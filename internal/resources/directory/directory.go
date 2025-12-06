// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package directory implements the remotefs_directory resource type
package directory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	webdav_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/X-Cli/terraform-provider-remotefs/internal/provider/config"
	"github.com/X-Cli/terraform-provider-remotefs/internal/resources/helpers/owner"
	"github.com/X-Cli/terraform-provider-remotefs/internal/resources/helpers/webdav"
	webdav_validator "github.com/X-Cli/terraform-provider-remotefs/internal/validators/webdav"
	webdav_client "github.com/emersion/go-webdav"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type resourceData struct {
	WebDav      *webdav_model.ConnSpec `tfsdk:"webdav"`
	Path        types.String           `tfsdk:"path"`
	Permissions types.String           `tfsdk:"permissions"`
	Owner       *owner.Owner           `tfsdk:"owner"`
	Group       *owner.Group           `tfsdk:"group"`
}

type directoryIdentity struct {
	URL types.String `tfsdk:"url"`
}

func newIdentityFromWebDav(rs resourceData, providerData config.ProviderData) (*directoryIdentity, error) {
	var urlToParse string
	if rs.WebDav != nil {
		urlToParse = rs.WebDav.BaseURL.ValueString()
	} else {
		urlToParse = providerData.ConnSpec.BaseURL.ValueString()
	}
	parsedBaseURL, err := url.Parse(urlToParse)
	if err != nil {
		return nil, err
	}

	parsedBaseURL.Fragment = ""
	parsedBaseURL.RawQuery = ""
	parsedBaseURL.User = nil
	parsedBaseURL.Path = rs.Path.ValueString()

	id := directoryIdentity{
		URL: basetypes.NewStringValue(parsedBaseURL.String()),
	}
	return &id, nil
}

func newIdentityFromImportID(importID string) (*directoryIdentity, error) {
	parsedURL, err := url.Parse(importID)
	if err != nil {
		return nil, err
	}
	parsedURL.Fragment = ""
	parsedURL.RawQuery = ""
	parsedURL.User = nil

	id := directoryIdentity{
		URL: basetypes.NewStringValue(parsedURL.String()),
	}
	return &id, nil
}

type Directory struct {
	providerData config.ProviderData
	webDavClient *webdav_client.Client
}

var (
	_ resource.Resource                = &Directory{}
	_ resource.ResourceWithConfigure   = &Directory{}
	_ resource.ResourceWithIdentity    = &Directory{}
	_ resource.ResourceWithImportState = &Directory{}
)

func New() resource.Resource {
	return &Directory{}
}

func (d *Directory) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_directory", req.ProviderTypeName)
}

func (d *Directory) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `The directory resource manages a directory on a remote filesystem.

At the moment, only WebDAV is supported as a transport protocol but others will follow eventually.
`,
		Attributes: map[string]schema.Attribute{
			"webdav": schema.SingleNestedAttribute{
				Attributes: webdav.ConnSpec,
				Description: `webdav specifies the connection information required to access the managed resource.

If the managed resource is accessed over WebDAV and this configuration value is not specified, the value defined at the provider level is used instead.

Exactly one connection type must be specified (currently only WebDAV is supported).

If the connection information is provided both at the provider level and at the resource level, the resource level information is preferred and used.
`,
				Optional: true,
				Validators: []validator.Object{
					&webdav_validator.Validator{},
				},
			},
			"path": schema.StringAttribute{
				Description: `The path to the managed resource.

With WebDAV, this path is concatenated to the base URL specified as part of the connection information.
`,
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"permissions": schema.StringAttribute{
				Description: `An octal value representing the UNIX-like permissions to the mananged resource. The format can be 777, 0777 or 0o777.

This value is ignored when managing a WebDAV resource.
`,
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile("^(?:^(?:0o?)?[0-7]{3})?$"), "mode must be expressed as an octal value: 777, 0777 or 0o777"),
				},
			},
			"owner": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Description: `The username of the owner of the managed resource.

This value is ignored when managing a WebDAV resource.

This value conflicts with the uid property of this object.
`,
						Optional: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("uid"),
							),
						},
					},
					"uid": schema.Int64Attribute{
						Description: `The UID of the owner of the managed resource.
	
This value is ignored when managing a WebDAV resource.

This value conflicts with the name property of this object.
`,
						Optional: true,
						Validators: []validator.Int64{
							int64validator.AtLeast(0),
						},
					},
				},
				Description: `An object to specify the owner of the managed resource.

This value is ignored when managing a WebDAV resource.

Only one of the name and uid properties can be set at the same time.
`,
				Optional: true,
			},
			"group": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Description: `The name of the primary group of the managed resource.

This value is ignored when managing a WebDAV resource.

This value conflicts with the gid property of this object.
`,
						Optional: true,
						Validators: []validator.String{
							stringvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("gid"),
							),
						},
					},
					"gid": schema.Int64Attribute{
						Description: `The GID of the primary group of the managed resource.
	
This value is ignored when managing a WebDAV resource.

This value conflicts with the name property of this object.
`,
						Optional: true,
						Validators: []validator.Int64{
							int64validator.AtLeast(0),
						},
					},
				},
				Description: `An object to specify the primary group of the managed resource.

This value is ignored when managing a WebDAV resource.

Only one of the name and gid properties can be set at the same time.
`,
				Optional: true,
			},
		},
	}
}

func (d *Directory) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		d.providerData = req.ProviderData.(config.ProviderData)
	}
}

func (d *Directory) getClients(resourceData resourceData) (*webdav_client.Client, diag.Diagnostics) {
	var wdc *webdav_client.Client
	if resourceData.WebDav != nil {
		var diags diag.Diagnostics
		wdc, diags = resourceData.WebDav.InitializeClient()
		if diags.HasError() {
			return nil, diags
		}
	} else if d.providerData.WebDavClient != nil {
		wdc = d.providerData.WebDavClient
	}
	return wdc, nil
}

func (d *Directory) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, diags := d.getClients(resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var identity *directoryIdentity

	if wdc != nil {
		var err error
		if err := wdc.Mkdir(ctx, resourceData.Path.ValueString()); err != nil {
			resp.Diagnostics.AddError("failed to create directory", fmt.Sprintf("failed to create directory: %s", err.Error()))
			return
		}
		if identity, err = newIdentityFromWebDav(resourceData, d.providerData); err != nil {
			resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
			return
		}
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceData)...)
}

func (d *Directory) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.State.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, diags := d.getClients(resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var identity *directoryIdentity

	if wdc != nil {
		fi, err := wdc.Stat(ctx, resourceData.Path.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to stat directory", fmt.Sprintf("failed to state directory: %s", err.Error()))
			return
		}
		if !fi.IsDir {
			resp.Diagnostics.AddError("remote file is not a directory", "remote file is not a directory")
			return
		}

		identity, err = newIdentityFromWebDav(resourceData, d.providerData)
		if err != nil {
			resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
			return
		}
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceData)...)
}

func (d *Directory) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.AddWarning("unimplemented", "unimplemented because do not matter with webdav")

	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceData)...)
}

func (d *Directory) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.State.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, diags := d.getClients(resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if wdc != nil {
		if err := wdc.RemoveAll(ctx, resourceData.Path.ValueString()); err != nil {
			resp.Diagnostics.AddError("failed to delete directory", fmt.Sprintf("failed to delete directory: %s", err.Error()))
			return
		}
	}
}

func (d *Directory) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"url": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func (d *Directory) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var identity directoryIdentity
	var err error
	if req.ID != "" {
		newID, err := newIdentityFromImportID(req.ID)
		if err != nil {
			resp.Diagnostics.AddError("failed to compute identity from Import ID", fmt.Sprintf("failed to compute identity from Import ID: %s", err.Error()))
			return
		}
		identity = *newID
	} else {
		resp.Diagnostics.Append(req.Identity.Get(ctx, &identity)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	parsedURL, err := url.Parse(identity.URL.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("failed to parse identity URL", fmt.Sprintf("failed to parse identity URL: %s", err.Error()))
		return
	}

	rs := resourceData{
		Path: basetypes.NewStringValue(parsedURL.Path),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &rs)...)
}
