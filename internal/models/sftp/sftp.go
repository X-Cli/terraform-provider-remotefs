package sftp

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"codeberg.org/X_Cli/sshhostkey"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type DNSResolverSpec struct {
	Address  types.String `tfsdk:"address"`
	Port     types.Int32  `tfsdk:"port"`
	Protocol types.String `tfsdk:"protocol"`
}

type DNSSpec struct {
	DNSResolvers []DNSResolverSpec `tfsdk:"resolvers"`
	CAFile       types.String      `tfsdk:"ca_file"`
	CAFilePath   types.String      `tfsdk:"ca_file_path"`
}

type ConnSpec struct {
	Address              types.String `tfsdk:"address"`
	Port                 types.Int32  `tfsdk:"port"`
	Username             types.String `tfsdk:"username"`
	Password             types.String `tfsdk:"password"`
	PrivateKey           types.String `tfsdk:"private_key"`
	PrivateKeyPassphrase types.String `tfsdk:"private_key_passphrase"`
	PrivateKeyPath       types.String `tfsdk:"private_key_path"`
	UseAgent             types.Bool   `tfsdk:"use_agent"`
	AgentSockPath        types.String `tfsdk:"agent_sock_path"`
	UseKnownHosts        types.Bool   `tfsdk:"use_known_hosts"`
	KnownHostsFiles      types.List   `tfsdk:"known_hosts_files"`
	KnownHostsEntries    types.List   `tfsdk:"known_hosts_entries"`
	UseSSHFP             []DNSSpec    `tfsdk:"use_sshfp"`
}

var (
	dnsProtocolMap = map[string]sshhostkey.DNSProtocol{
		"dns": sshhostkey.DNSOverUDPOrTCP,
		"dot": sshhostkey.DNSOverTLS,
		"doh": sshhostkey.DNSOverHTTPS,
	}
	ErrUnknownProtocol    = errors.New("specified protocol does not match any supported protocol")
	ErrInvalidCertificate = errors.New("expected PEM encoded certificate")
	ErrMissingAgentSocket = errors.New("agent socket not configured")
	ErrMissingAuthnMethod = errors.New("found no supported authentication method")
)

func (cs *ConnSpec) buildSSHVerifFunc(ctx context.Context) (ssh.HostKeyCallback, diag.Diagnostics) {
	var diags diag.Diagnostics
	var sshVerifBuidler sshhostkey.Builder
	if cs.UseKnownHosts.ValueBool() {
		if err := sshVerifBuidler.WithMyKnownHostsFile(); err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to configure verification with your known_hosts file", err.Error()),
			}
		}
	}
	if len(cs.KnownHostsFiles.Elements()) > 0 {
		var tfFiles []types.String
		var files []string
		diags.Append(cs.KnownHostsFiles.ElementsAs(ctx, &tfFiles, false)...)
		if diags.HasError() {
			return nil, diags
		}
		for _, tfFile := range tfFiles {
			files = append(files, tfFile.ValueString())
		}
		if err := sshVerifBuidler.WithThisKnownHostsFile(files...); err != nil {
			diags.Append(
				diag.NewErrorDiagnostic("failed to configure verification with the provided list of known_hosts files", err.Error()),
			)
			return nil, diags
		}
	}
	if len(cs.KnownHostsEntries.Elements()) > 0 {
		var tfEntries []types.String
		var entries []string
		diags.Append(cs.KnownHostsEntries.ElementsAs(ctx, &tfEntries, false)...)
		if diags.HasError() {
			return nil, diags
		}
		for _, tfEntry := range tfEntries {
			entries = append(entries, tfEntry.ValueString())
		}
		if err := sshVerifBuidler.WithThisKnownHostEntry(entries...); err != nil {
			diags.Append(
				diag.NewErrorDiagnostic("failed to configure known hosts entries", err.Error()),
			)
			return nil, diags
		}
	}
	for _, dnsConf := range cs.UseSSHFP {
		for _, dnsResv := range dnsConf.DNSResolvers {
			addr := net.JoinHostPort(dnsResv.Address.ValueString(), strconv.Itoa(int(dnsResv.Port.ValueInt32())))
			proto, found := dnsProtocolMap[strings.ToLower(dnsResv.Protocol.ValueString())]
			if !found {
				diags.Append(
					diag.NewErrorDiagnostic("unknown protocol", ErrUnknownProtocol.Error()),
				)
				return nil, diags
			}
			if err := sshVerifBuidler.WithThisDNSResolver(addr, proto); err != nil {
				diags.Append(
					diag.NewErrorDiagnostic("failed to set new DNS resolver", err.Error()),
				)
			}
		}
		if caFile := dnsConf.CAFile.ValueString(); caFile != "" {
			blk, _ := pem.Decode([]byte(caFile))
			if blk == nil || blk.Type != "CERTIFICATE" {
				diags.Append(
					diag.NewErrorDiagnostic("invalid certificate", ErrInvalidCertificate.Error()),
				)
				return nil, diags
			}
			if err := sshVerifBuidler.WithThisCertificateAuthority(blk.Bytes); err != nil {
				diags.Append(
					diag.NewErrorDiagnostic("failed to configure this certificate authority", err.Error()),
				)
				return nil, diags
			}
		} else if caFilePath := dnsConf.CAFilePath.ValueString(); caFilePath != "" {
			if err := sshVerifBuidler.WithThisCACertificateFile(caFilePath); err != nil {
				diags.Append(
					diag.NewErrorDiagnostic("failed to configure this certificate authority", err.Error()),
				)
				return nil, diags
			}
		}
	}
	fn, err := sshVerifBuidler.Build()
	if err != nil {
		diags.Append(
			diag.NewErrorDiagnostic("failed to build the SSH host key verification function", err.Error()),
		)
		return nil, diags
	}
	return fn, diags
}

func (cs *ConnSpec) getSSHAuthn() (ssh.AuthMethod, error) {
	if passwd := cs.Password.ValueString(); passwd != "" {
		return ssh.Password(cs.Password.ValueString()), nil
	}

	var privKeyBytes []byte
	passphrase := cs.PrivateKeyPassphrase.ValueString()
	if privKey := cs.PrivateKey.ValueString(); privKey != "" {
		privKeyBytes = []byte(privKey)
	} else if privKeyPath := cs.PrivateKeyPath.ValueString(); privKeyPath != "" {
		f, err := os.Open(privKeyPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		privKeyBytes, err = io.ReadAll(io.LimitReader(f, 4096))
		if err != nil {
			return nil, err
		}
	}
	if privKeyBytes != nil {
		var signer ssh.Signer
		var err error
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privKeyBytes, []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(privKeyBytes)
		}
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(signer), nil
	}
	if cs.UseAgent.ValueBool() {
		sshAgentSockPath := cs.AgentSockPath.ValueString()
		if sshAgentSockPath == "" {
			sshAgentSockPath = os.Getenv("SSH_AUTH_SOCK")
		}
		if sshAgentSockPath == "" {
			return nil, ErrMissingAgentSocket
		}
		agentConn, err := net.Dial("unix", sshAgentSockPath)
		if err != nil {
			return nil, err
		}
		sshAgent := agent.NewClient(agentConn)
		return ssh.PublicKeysCallback(sshAgent.Signers), nil
	}
	return nil, ErrMissingAuthnMethod
}

func (cs *ConnSpec) InitializeClient(ctx context.Context) (*sftp.Client, diag.Diagnostics) {
	sshVerifFun, diags := cs.buildSSHVerifFunc(ctx)
	if diags.HasError() {
		return nil, diags
	}
	authMethod, err := cs.getSSHAuthn()
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to initialize authentication methods", err.Error()),
		}
	}
	sshConf := &ssh.ClientConfig{
		User:            cs.Username.ValueString(),
		HostKeyCallback: sshVerifFun,
		Auth:            []ssh.AuthMethod{authMethod},
	}

	sshPort := int(cs.Port.ValueInt32())
	if sshPort == 0 {
		sshPort = 22
	}
	sshClnt, err := ssh.Dial("tcp", net.JoinHostPort(cs.Address.ValueString(), strconv.Itoa(sshPort)), sshConf)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to dial to the SSH server", err.Error()),
		}
	}

	sftpClnt, err := sftp.NewClient(sshClnt)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to initialize SFTP subsystem", err.Error()),
		}
	}
	return sftpClnt, nil
}
