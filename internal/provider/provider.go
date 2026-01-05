// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package provider implements the remotefs provider to interact with a remote filesystems over diverse network protocols.
// Currently, only WebDav is implemented.
package provider

import (
	"context"
	"fmt"

	sftp_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/sftp"
	webdav_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/X-Cli/terraform-provider-remotefs/internal/provider/config"
	"github.com/X-Cli/terraform-provider-remotefs/internal/resources/directory"
	resource_file "github.com/X-Cli/terraform-provider-remotefs/internal/resources/file"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/cafile"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/cert"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/files"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/knownhosts"
	sftp_validator "github.com/X-Cli/terraform-provider-remotefs/internal/validators/sftp"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/sshfp"
	url_validator "github.com/X-Cli/terraform-provider-remotefs/internal/validators/url"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/webdav"
	webdav_client "github.com/emersion/go-webdav"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pkg/sftp"
)

const (
	TFVersionConstraint = ">= 1.11.0"
)

var (
	providerVersion string = "dev"
)

type providerConfig struct {
	WebDav *webdav_model.ConnSpec `tfsdk:"webdav"`
	SFTP   *sftp_model.ConnSpec   `tfsdk:"sftp"`
}

type Provider struct {
	config       providerConfig
	webDavClient *webdav_client.Client
	sftpClient   *sftp.Client
}

var (
	_ provider.Provider = &Provider{}
)

func New() provider.Provider {
	return &Provider{}
}

func (p *Provider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "remotefs"
	resp.Version = providerVersion
}

func (p *Provider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `This provider manages directories and files on remote filesystems. Currently, only WebDAV is supported but others will follow (most notably SSH).`,
		Attributes: map[string]schema.Attribute{
			"webdav": schema.SingleNestedAttribute{
				Description: `webdav specifies the connection information required to access the managed resource over WebDAV.

If the managed resource is accessed over WebDAV and this configuration value is not specified, the resource level connection info must be specified instead.

At most one connection type must be specified.

If the connection information is provided both at the provider level and at the resource level, the resource level information is preferred and used.
`,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"base_url": schema.StringAttribute{
						Description: `The URL of the root directory exposed over WebDAV.

The URL use the HTTP or the HTTPS scheme. If the HTTPS scheme is used, either the ca_file or the ca_file_path attributes must be specifie.

The specified URL serves as a prefix for the path of all managed resources.
`,
						Required: true,
						Validators: []validator.String{
							&url_validator.URLValidator{},
						},
					},
					"ca_file": schema.StringAttribute{
						Description: `A series of certificate authoritiy certificates to use to validate the certificate of the WebDAV server.

The content must be a list of PEM-encoded X.509 certificates.
`,
						Optional: true,
						Validators: []validator.String{
							&cafile.CAFileValidator{},
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("ca_file_path"),
							),
						},
					},
					"ca_file_path": schema.StringAttribute{
						Description: `A file containing a series of certificate authority certificates to use to validate the certificate of the WebDAV server.

This file content must be a list of PEM-encoded X.509 certificates, similar to the content of the /etc/ssl/certs/ca-certificates.crt file that can be found on some OSes.
`,
						Optional: true,
						Validators: []validator.String{
							&cafile.CAFilePathValidator{},
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("ca_file"),
							),
						},
					},
					"authentication_method": schema.StringAttribute{
						Description: `The type of authentication to use with this WebDAV server.

If this attribute is not specified, no authentication is attempted. Acceptable values are "basic" and "cert".

"basic" means that a username and a password must be provided and authentication will be performed using the HTTP Basic authentication scheme.

"cert" means that the connection to the WebDAV server is authenticated using mTLS (client certificate). With the "cert" authentication method, the private key must be specified inline using the "private_key" attribute or via a local file using the "private_key_path" attribute. The certificate associated to that private key must also be specified, either inline using the "certificate" attribute or as a local file using the "certificate_path" attribute.
`,
						Optional: true,
						Validators: []validator.String{
							stringvalidator.OneOf("basic", "cert"),
						},
					},
					"username": schema.StringAttribute{
						Description: `The username to use when authenticating with the HTTP Basic authentication scheme.`,
						Optional:    true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_passphrase"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
								path.MatchRelative().AtParent().AtName("certificate"),
								path.MatchRelative().AtParent().AtName("certificate_path"),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
						},
					},
					"password": schema.StringAttribute{
						Description: `The password to use when authenticating with the HTTP Basic authentication scheme. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
						Optional:    true,
						Sensitive:   true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_passphrase"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
								path.MatchRelative().AtParent().AtName("certificate"),
								path.MatchRelative().AtParent().AtName("certificate_path"),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
						},
					},
					"private_key": schema.StringAttribute{
						Description: `The private key to use when authenticating using mTLS. The key must be encoded with the PKCS#8 format. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
						Optional:    true,
						Sensitive:   true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("certificate")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("certificate_path")),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file_path")),
							),
						},
					},
					"private_key_passphrase": schema.StringAttribute{
						Description: `The passphrase used to encrypt the specified private key. This attribute is optional. If it is not specified, the private key is assumed to be stored unencrypted. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
						Optional:    true,
						Sensitive:   true,
						Validators: []validator.String{
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key_path")),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("certificate")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("certificate_path")),
							),
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("password"),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file_path")),
							),
						},
					},
					"private_key_path": schema.StringAttribute{
						Description: `The path to a local file containing the private key to use when authenticating using mTLS.`,
						Optional:    true,
						Validators: []validator.String{
							&files.FileValidator{},
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("certificate")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("certificate_path")),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file_path")),
							),
						},
					},
					"certificate": schema.StringAttribute{
						Description: `The certificate to use to authenticate using mTLS.`,
						Optional:    true,
						Validators: []validator.String{
							&cert.CertValidator{},
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("certificate_path"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key_path")),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file_path")),
							),
						},
					},
					"certificate_path": schema.StringAttribute{
						Description: `The path to a local file containing the certificate to use to authenticate using mTLS.`,
						Optional:    true,
						Validators: []validator.String{
							&cert.CertFileValidator{},
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("certificate"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key_path")),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file")),
								stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file_path")),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("authentication_method"),
							),
						},
					},
				},
				Validators: []validator.Object{
					&webdav.Validator{},
					objectvalidator.ConflictsWith(
						path.MatchRelative().AtParent().AtName("sftp"),
					),
				},
			},
			"sftp": schema.SingleNestedAttribute{
				Description: `sftp specifies the connection information required to access the managed resource over SFTP.

If the managed resource is accessed over SFTP and this configuration value is not specified, the resource level connection info must be specified instead.

At most one connection type must be specified.

If the connection information is provided both at the provider level and at the resource level, the resource level information is preferred and used.
`,
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"address": schema.StringAttribute{
						Description: `address specifies the domain name or IP address of the host to connect to over SFTP.

If a domain name is specified and SSHFP is configured for the SSH host key verification, this domain name is queried for SSHFP records.
`,
						Required: true,
					},
					"port": schema.Int32Attribute{
						Description: `port specifies the port number to connect to.

If this attribute is left unspecified, the provider will connect to port 22.
`,
						Optional: true,
						Validators: []validator.Int32{
							int32validator.Between(1, 65535),
						},
					},
					"username": schema.StringAttribute{
						Description: `username specifies the name of the user to login as.
`,
						Required: true,
					},
					"password": schema.StringAttribute{
						Description: `password specifies the password used to authenticate to the SFTP server.

Exactly one of the password, private_key, private_key_path or use_agent attributes must be specified.
`,
						Optional:  true,
						Sensitive: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
								path.MatchRelative().AtParent().AtName("private_key_passphrase"),
								path.MatchRelative().AtParent().AtName("use_agent"),
								path.MatchRelative().AtParent().AtName("agent_sock_path"),
							),
							stringvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
								path.MatchRelative().AtParent().AtName("use_agent"),
							),
						},
					},
					"private_key": schema.StringAttribute{
						Description: `private_key specifies the private key to use to authenticate to the SFTP server.

The private key may be encrypted. If so, the private_key_passphrase attribute must be specified.

Exactly one of the password, private_key, private_key_path or use_agent attributes must be specified.
`,
						Optional:  true,
						Sensitive: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
								path.MatchRelative().AtParent().AtName("use_agent"),
								path.MatchRelative().AtParent().AtName("agent_sock_path"),
							),
							stringvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
								path.MatchRelative().AtParent().AtName("use_agent"),
							),
						},
					},
					"private_key_passphrase": schema.StringAttribute{
						Description: `private_key_passphrase specifies the passphrase to use to decrypt the private key specified with the private_key or private_key_path attributes.`,
						Optional:    true,
						Sensitive:   true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("use_agent"),
								path.MatchRelative().AtParent().AtName("agent_sock_path"),
							),
							stringvalidator.Any(
								stringvalidator.AlsoRequires(
									path.MatchRelative().AtParent().AtName("private_key"),
								),
								stringvalidator.AlsoRequires(
									path.MatchRelative().AtParent().AtName("private_key_path"),
								),
							),
						},
					},
					"private_key_path": schema.StringAttribute{
						Description: `private_key_path specifies the path of a file containing the private key to use to authenticate to the SFP server.

The private key may be encrypted. If so, the private_key_passphrase attribute must be specified.

Exactly one of the password, private_key, private_key_path or use_agent attributes must be specified.
`,
						Optional: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("use_agent"),
								path.MatchRelative().AtParent().AtName("agent_sock_path"),
							),
							stringvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("use_agent"),
							),
						},
					},
					"use_agent": schema.BoolAttribute{
						Description: `use_agent specifies that a SSH agent should be used to authenticate to the SFTP server.

Exactly one of the password, private_key, private_key_path or use_agent attributes must be specified.
`,
						Optional: true,
						Validators: []validator.Bool{
							boolvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_passphrase"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
							),
							boolvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
							),
						},
					},
					"agent_sock_path": schema.StringAttribute{
						Description: `agent_sock_path enables specifying the path to the SSH agent socket.

If this attribute is not specified and use_agent is set, the SSH_AUTH_SOCK environment variable is used to determine the socket path.
`,
						Optional: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("password"),
								path.MatchRelative().AtParent().AtName("private_key"),
								path.MatchRelative().AtParent().AtName("private_key_passphrase"),
								path.MatchRelative().AtParent().AtName("private_key_path"),
							),
							stringvalidator.AlsoRequires(
								path.MatchRelative().AtParent().AtName("use_agent"),
							),
						},
					},
					"use_known_hosts": schema.BoolAttribute{
						Description: `use_known_hosts specifies that the $HOME/.ssh/known_hosts file should be used to verify the SSH server host key.

At least one of use_known_hosts, known_hosts_files, known_hosts_entries or use_sshfp must be specified.

Not verifying the SSH host key is not an option for security reasons. If you don't know the expected SSH host key, please find it out in a secure manner. For a newly provisionned virtual machine, you may want to take a peek at the X-Cli/ssh2vsock provider to perform a secure ssh-keyscan.
`,
						Optional: true,
						Validators: []validator.Bool{
							boolvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("known_hosts_files"),
								path.MatchRelative().AtParent().AtName("known_hosts_entries"),
								path.MatchRelative().AtParent().AtName("use_sshfp"),
							),
							&knownhosts.FileValidator{},
						},
					},
					"known_hosts_files": schema.ListAttribute{
						Description: `known_hosts_file specifies a list of pathes to files whose content are similar to $HOME/.ssh/known_hosts.

This enables you to use known_hosts files stored at a non-standard location or different known_hosts file per client/provider.

At least one of use_known_hosts, known_hosts_files, known_hosts_entries or use_sshfp must be specified.

Not verifying the SSH host key is not an option for security reasons. If you don't know the expected SSH host key, please find it out in a secure manner. For a newly provisionned virtual machine, you may want to take a peek at the X-Cli/ssh2vsock provider to perform a secure ssh-keyscan.
`,
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("use_known_hosts"),
								path.MatchRelative().AtParent().AtName("known_hosts_entries"),
								path.MatchRelative().AtParent().AtName("use_sshfp"),
							),
							&knownhosts.FileValidator{},
						},
					},
					"known_hosts_entries": schema.ListAttribute{
						Description: `known_hosts_entries specifies a list of strings whose content is similar to a line in a known_hosts file.

This attribute can be used, for instance, to specify the host keys of a newly provisionned virtual machine whose public key was discovered using the X-Cli/ssh2vsock provider, or some other way.

At least one of use_known_hosts, known_hosts_files, known_hosts_entries or use_sshfp must be specified.

Not verifying the SSH host key is not an option for security reasons. If you don't know the expected SSH host key, please find it out in a secure manner. For a newly provisionned virtual machine, you may want to take a peek at the X-Cli/ssh2vsock provider to perform a secure ssh-keyscan.
`,
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("use_known_hosts"),
								path.MatchRelative().AtParent().AtName("known_hosts_files"),
								path.MatchRelative().AtParent().AtName("use_sshfp"),
							),
							&knownhosts.EntryValidator{},
						},
					},
					"use_sshfp": schema.ListAttribute{
						Description: `use_sshfp specifies ways to verify the SSH host key by querying the DNS for SSHFP records.

Resolvers are designated by their IP address, their port number and the protocol to use to query them.

Supported protocols are "dns" (classic DNS protocol), "dot" (for DNS over TLS) and "doh" (for DNS over HTTPS).

DNS answers MUST have been verified with DNSSEC and the AD bit (authenticated data) is expected, for security reasons.

Unless you specify a local DNS resolver or a DNS resolver reached over a protected channel like a Wireguard tunnel, please consider using a secure DNS protocol like DoT or DoH. Failing to do so means you cannot trust the AD bit and a MITM attack could be perform against your connection.

For resolvers queried over a secure protocol (DoT or DoH), a list of certificate authorities MUST be specified to verify the server X.509 certificate. If you are using a public DNS resolver, it is likely that the certificates specified in /etc/ssl/certs/ca-certificates.crt are sufficient.

At least one of use_known_hosts, known_hosts_files, known_hosts_entries or use_sshfp must be specified.

Not verifying the SSH host key is not an option for security reasons. If you don't know the expected SSH host key, please find it out in a secure manner. For a newly provisionned virtual machine, you may want to take a peek at the X-Cli/ssh2vsock provider to perform a secure ssh-keyscan. The SSHFP record can then be pushed over RFC2136 using the hashicorp/dns provider.
`,
						Optional: true,
						ElementType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"resolvers": types.ListType{
									ElemType: types.ObjectType{
										AttrTypes: map[string]attr.Type{
											"address":  types.StringType,
											"port":     types.Int32Type,
											"protocol": types.StringType,
										},
									},
								},
								"ca_cert":      types.StringType,
								"ca_cert_path": types.StringType,
							},
						},
						Validators: []validator.List{
							listvalidator.AtLeastOneOf(
								path.MatchRelative().AtParent().AtName("use_known_hosts"),
								path.MatchRelative().AtParent().AtName("known_hosts_files"),
								path.MatchRelative().AtParent().AtName("known_hosts_entries"),
							),
							&sshfp.Validator{},
						},
					},
				},
				Validators: []validator.Object{
					&sftp_validator.Validator{},
					objectvalidator.ConflictsWith(
						path.MatchRelative().AtParent().AtName("webdav"),
					),
				},
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	versionConstraint, err := version.NewConstraint(TFVersionConstraint)
	if err != nil {
		resp.Diagnostics.AddError("failed to parse Terraform version constraint", fmt.Sprintf("failed to parse Terraform version constraint: %s", err.Error()))
		return
	}
	if tfVersion, err := version.NewVersion(req.TerraformVersion); err != nil {
		resp.Diagnostics.AddError("failed to parse Terraform version", fmt.Sprintf("failed to parse Terraform version: %s", err.Error()))
		return
	} else if !versionConstraint.Check(tfVersion) {
		resp.Diagnostics.AddError("invalid version", fmt.Sprintf("insufficient version %q. This provider has this Terraform version constraint: %q", req.TerraformVersion, TFVersionConstraint))
		return
	}

	var provConfig providerConfig
	var provData config.ProviderData

	resp.Diagnostics.Append(req.Config.Get(ctx, &provConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p.config = provConfig

	if provConfig.WebDav != nil {
		wdc, diags := provConfig.WebDav.InitializeClient()
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		p.webDavClient = wdc
		provData.WebDavClient = wdc
		provData.WebDavConnSpec = *provConfig.WebDav
	} else if provConfig.SFTP != nil {
		sftpClnt, diags := provConfig.SFTP.InitializeClient(ctx)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		p.sftpClient = sftpClnt
		provData.SFTPClient = sftpClnt
		provData.SFTPConnSpec = *provConfig.SFTP
	}
	resp.ResourceData = provData
}

func (p *Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func (p *Provider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resource_file.New,
		directory.New,
	}
}
