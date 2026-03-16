// Copyright Florian Maury 2025, 2026
// SPDX-License-Identifier: BSD-2-Clause

// Package webdav specifies the map used to specify the common schema of the webdav attribute for the remotefs_directory and remotefs_file resource types
package webdav

import (
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/cert"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/files"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/url"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var ConnSpec = map[string]schema.Attribute{
	"base_url": schema.StringAttribute{
		Description: `The URL of the root directory exposed over WebDAV.

The URL use the HTTP or the HTTPS scheme. If the HTTPS scheme is used, either the ca_file or the ca_file_path attributes must be specifie.

The specified URL serves as a prefix for the path of all managed resources.
`,
		Required: true,
		Validators: []validator.String{
			&url.URLValidator{},
		},
	},
	"ca_file": schema.StringAttribute{
		Description: `A series of certificate authoritiy certificates to use to validate the certificate of the WebDAV server.

The content must be a list of PEM-encoded X.509 certificates.
`,
		Optional: true,
		Validators: []validator.String{
			&cert.CertValidator{},
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
			&cert.CertFileValidator{},
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
		Required:    false,
		Optional:    true,
		Validators: []validator.String{
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("private_key"),
				path.MatchRelative().AtParent().AtName("private_key_path"),
				path.MatchRelative().AtParent().AtName("private_key_passphrase"),
				path.MatchRelative().AtParent().AtName("certificate"),
				path.MatchRelative().AtParent().AtName("certificate_path"),
			),
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("authentication_method"),
				path.MatchRelative().AtParent().AtName("password"),
			),
		},
	},
	"password": schema.StringAttribute{
		Description: `The password to use when authenticating with the HTTP Basic authentication scheme. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
		Optional:    true,
		Sensitive:   true,
		WriteOnly:   true,
		Validators: []validator.String{
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("private_key"),
				path.MatchRelative().AtParent().AtName("private_key_path"),
				path.MatchRelative().AtParent().AtName("private_key_passphrase"),
				path.MatchRelative().AtParent().AtName("certificate"),
				path.MatchRelative().AtParent().AtName("certificate_path"),
			),
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("authentication_method"),
				path.MatchRelative().AtParent().AtName("username"),
			),
		},
	},
	"private_key": schema.StringAttribute{
		Description: `The private key to use when authenticating using mTLS. The key must be encoded with the PKCS#8 format. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
		Optional:    true,
		Sensitive:   true,
		WriteOnly:   true,
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
		WriteOnly:   true,
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
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("authentication_method"),
			),
			stringvalidator.Any(
				stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file")),
				stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_file_path")),
			),
		},
	},
}
