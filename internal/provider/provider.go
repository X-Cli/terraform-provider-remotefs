// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package provider implements the remotefs provider to interact with a remote filesystems over diverse network protocols.
// Currently, only WebDav is implemented.
package provider

import (
	"context"
	"fmt"

	webdav_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/X-Cli/terraform-provider-remotefs/internal/provider/config"
	"github.com/X-Cli/terraform-provider-remotefs/internal/resources/directory"
	resource_file "github.com/X-Cli/terraform-provider-remotefs/internal/resources/file"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/cafile"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/cert"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/files"
	url_validator "github.com/X-Cli/terraform-provider-remotefs/internal/validators/url"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/webdav"
	webdav_client "github.com/emersion/go-webdav"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

const (
	TFVersionConstraint = ">= 1.11.0"
)

var (
	providerVersion string = "dev"
)

type providerConfig struct {
	WebDav *webdav_model.ConnSpec `tfsdk:"webdav"`
}

type Provider struct {
	config       providerConfig
	webDavClient *webdav_client.Client
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

At most one connection type must be specified. Currently, only WebDAV is supported.

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
						},
					},
					"ca_file_path": schema.StringAttribute{
						Description: `A file containing a series of certificate authority certificates to use to validate the certificate of the WebDAV server.

This file content must be a list of PEM-encoded X.509 certificates, similar to the content of the /etc/ssl/certs/ca-certificates.crt file that can be found on some OSes.
`,
						Optional: true,
						Validators: []validator.String{
							&cafile.CAFilePathValidator{},
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
					},
					"password": schema.StringAttribute{
						Description: `The password to use when authenticating with the HTTP Basic authentication scheme. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
						Optional:    true,
						Sensitive:   true,
					},
					"private_key": schema.StringAttribute{
						Description: `The private key to use when authenticating using mTLS. The key must be encoded with the PKCS#8 format. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
						Optional:    true,
						Sensitive:   true,
					},
					"private_key_passphrase": schema.StringAttribute{
						Description: `The passphrase used to encrypt the specified private key. This attribute is optional. If it is not specified, the private key is assumed to be stored unencrypted. This attribute is write-only, so it can be set with an ephemeral value that will not be stored in state.`,
						Optional:    true,
						Sensitive:   true,
					},
					"private_key_path": schema.StringAttribute{
						Description: `The path to a local file containing the private key to use when authenticating using mTLS.`,
						Optional:    true,
						Validators: []validator.String{
							&files.FileValidator{},
						},
					},
					"certificate": schema.StringAttribute{
						Description: `The certificate to use to authenticate using mTLS.`,
						Optional:    true,
						Validators: []validator.String{
							&cert.CertValidator{},
						},
					},
					"certificate_path": schema.StringAttribute{
						Description: `The path to a local file containing the certificate to use to authenticate using mTLS.`,
						Optional:    true,
						Validators: []validator.String{
							&cert.CertFileValidator{},
						},
					},
				},
				Validators: []validator.Object{
					&webdav.Validator{},
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
		provData.ConnSpec = *provConfig.WebDav
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
