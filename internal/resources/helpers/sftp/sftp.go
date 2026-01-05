// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sftp

import (
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/files"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/knownhosts"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/sshfp"
	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var ConnSpec = map[string]schema.Attribute{
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
		WriteOnly: true,
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
		WriteOnly: true,
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
		WriteOnly:   true,
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
			&files.FileValidator{},
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
				"ca_file":      types.StringType,
				"ca_file_path": types.StringType,
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
}
