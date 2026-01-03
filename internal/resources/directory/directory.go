// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package directory implements the remotefs_directory resource type
package directory

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"

	sftp_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/sftp"
	webdav_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/X-Cli/terraform-provider-remotefs/internal/provider/config"
	"github.com/X-Cli/terraform-provider-remotefs/internal/resources/helpers/owner"
	sftp_helper "github.com/X-Cli/terraform-provider-remotefs/internal/resources/helpers/sftp"
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
	"github.com/pkg/sftp"
)

type resourceData struct {
	WebDav      *webdav_model.ConnSpec `tfsdk:"webdav"`
	SFTP        *sftp_model.ConnSpec   `tfsdk:"sftp"`
	Path        types.String           `tfsdk:"path"`
	Permissions types.String           `tfsdk:"permissions"`
	Owner       types.Object           `tfsdk:"owner"`
	Group       types.Object           `tfsdk:"group"`
}

type directoryIdentity struct {
	URL types.String `tfsdk:"url"`
}

func newIdentityFromWebDav(rs resourceData, providerData config.ProviderData) (*directoryIdentity, error) {
	var urlToParse string
	if rs.WebDav != nil {
		urlToParse = rs.WebDav.BaseURL.ValueString()
	} else {
		urlToParse = providerData.WebDavConnSpec.BaseURL.ValueString()
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
			"sftp": schema.SingleNestedAttribute{
				Attributes: sftp_helper.ConnSpec,
				Description: `sftp specifies the connection information required to access the managed resource over SFTP.
	
If this configuration value not the webdav value are not specified, the value defined at the provider level is used instead.

Exactly one connection type must be specified.

If the connection information is provided both at the provider level and at the resource level, the resource level information is preferred and used.`,
				Optional:   true,
				Validators: []validator.Object{
					// TODO validator
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
				Computed: true,
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
						Computed: true,
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
						Computed: true,
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
				Computed: true,
			},
			"group": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Description: `The name of the primary group of the managed resource.

This value is ignored when managing a WebDAV resource.

This value conflicts with the gid property of this object.
`,
						Optional: true,
						Computed: true,
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
						Computed: true,
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
				Computed: true,
			},
		},
	}
}

func (d *Directory) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		d.providerData = req.ProviderData.(config.ProviderData) //nolint:forcetypeassert
	}
}

func (d *Directory) getClients(ctx context.Context, resourceData resourceData) (*webdav_client.Client, *sftp.Client, diag.Diagnostics) {
	var wdc *webdav_client.Client
	var sftpc *sftp.Client
	if resourceData.WebDav != nil {
		var diags diag.Diagnostics
		wdc, diags = resourceData.WebDav.InitializeClient()
		if diags.HasError() {
			return nil, nil, diags
		}
	} else if d.providerData.WebDavClient != nil {
		wdc = d.providerData.WebDavClient
	}
	if resourceData.SFTP != nil {
		var diags diag.Diagnostics
		sftpc, diags = resourceData.SFTP.InitializeClient(ctx)
		if diags.HasError() {
			return nil, nil, diags
		}
	} else if d.providerData.SFTPClient != nil {
		sftpc = d.providerData.SFTPClient
	}

	return wdc, sftpc, nil
}

func (d *Directory) setOwnershipAndPermissionsViaSFTP(ctx context.Context, sftpc *sftp.Client, rd resourceData) (diags diag.Diagnostics) {
	mode, err := strconv.ParseInt(rd.Permissions.ValueString(), 0, 32)
	if err != nil {
		diags.AddError("failed to parse file permissions", fmt.Sprintf("failed to parse file permissions: %s", err.Error()))
		return
	}
	if err := sftpc.Chmod(rd.Path.ValueString(), os.FileMode(mode)); err != nil {
		diags.AddError("failed to chmod file", fmt.Sprintf("failed to chmod file: %s", err.Error()))
		return
	}

	var uid int64 = -1
	var gid int64 = -1
	if !rd.Owner.IsNull() && !rd.Owner.IsUnknown() {
		var ownerValue owner.Owner
		diags.Append(rd.Owner.As(ctx, &ownerValue, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		if ownerValue.Name.ValueString() != "" {
			diags.AddError("cannot set owner by name with SFTP", "cannot set owner by name with SFTP")
			return
		}
		uid = ownerValue.UID.ValueInt64()
	}
	if !rd.Group.IsNull() && !rd.Group.IsUnknown() {
		var groupValue owner.Group
		diags.Append(rd.Group.As(ctx, &groupValue, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		if groupValue.Name.ValueString() != "" {
			diags.AddError("cannot set group by name with SFTP", "cannot set group by name with SFTP")
			return
		}
		gid = groupValue.GID.ValueInt64()
	}
	if uid != -1 && gid != -1 {
		if err := sftpc.Chown(rd.Path.ValueString(), int(uid), int(gid)); err != nil {
			diags.AddError("failed to chown file", fmt.Sprintf("failed to chown file: %s", err.Error()))
			return
		}
	}
	return
}

func (d *Directory) getOwnershipAndPermissionsViaSFTP(ctx context.Context, sftpc *sftp.Client, rd resourceData) (permissions types.String, ownerObj, groupObj types.Object, diags diag.Diagnostics) {
	fi, err := sftpc.Stat(rd.Path.ValueString())
	if err != nil {
		diags.AddError("failed to stat directory", fmt.Sprintf("failed to stat directory: %s", err.Error()))
		return
	}
	mode := fmt.Sprintf("%O", fi.Mode())
	permissions = basetypes.NewStringValue(mode)

	fs, ok := fi.Sys().(*sftp.FileStat)
	if !ok {
		diags.AddError("invalid system file stat type", "invalid system file stat type")
		return
	}
	ownerValue := owner.Owner{
		UID:  basetypes.NewInt64Value(int64(fs.UID)),
		Name: basetypes.NewStringNull(),
	}
	groupValue := owner.Group{
		GID:  basetypes.NewInt64Value(int64(fs.GID)),
		Name: basetypes.NewStringNull(),
	}

	var objDiag diag.Diagnostics
	ownerObj, objDiag = basetypes.NewObjectValueFrom(ctx, owner.Owner{}.AttributeTypes(), ownerValue)
	diags.Append(objDiag...)
	if diags.HasError() {
		return
	}
	groupObj, objDiag = basetypes.NewObjectValueFrom(ctx, owner.Group{}.AttributeTypes(), groupValue)
	diags.Append(objDiag...)
	if diags.HasError() {
		return
	}
	return
}

func (d *Directory) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, sftpc, diags := d.getClients(ctx, resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	permissions := basetypes.NewStringNull()
	ownerObj := basetypes.NewObjectNull(owner.Owner{}.AttributeTypes())
	groupObj := basetypes.NewObjectNull(owner.Group{}.AttributeTypes())
	if wdc != nil {
		if err := wdc.Mkdir(ctx, resourceData.Path.ValueString()); err != nil {
			resp.Diagnostics.AddError("failed to create directory", fmt.Sprintf("failed to create directory: %s", err.Error()))
			return
		}
	} else if sftpc != nil {
		if err := sftpc.Mkdir(resourceData.Path.ValueString()); err != nil {
			resp.Diagnostics.AddError("failed to create directory", fmt.Sprintf("failed to create directory: %s", err.Error()))
			return
		}
		permissions, ownerObj, groupObj, diags = d.getOwnershipAndPermissionsViaSFTP(ctx, sftpc, resourceData)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	identity, err := newIdentityFromWebDav(resourceData, d.providerData)
	if err != nil {
		resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
		return
	}
	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceData.Permissions = permissions
	resourceData.Owner = ownerObj
	resourceData.Group = groupObj
	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceData)...)
}

func (d *Directory) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.State.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, sftpc, diags := d.getClients(ctx, resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	permissions := basetypes.NewStringNull()
	ownerObj := basetypes.NewObjectNull(owner.Owner{}.AttributeTypes())
	groupObj := basetypes.NewObjectNull(owner.Group{}.AttributeTypes())
	if wdc != nil {
		fi, err := wdc.Stat(ctx, resourceData.Path.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to stat directory", fmt.Sprintf("failed to stat directory: %s", err.Error()))
			return
		}
		if !fi.IsDir {
			resp.Diagnostics.AddError("remote file is not a directory", "remote file is not a directory")
			return
		}
	} else if sftpc != nil {
		fi, err := sftpc.Stat(resourceData.Path.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to stat directory", fmt.Sprintf("failed to stat directory: %s", err.Error()))
			return
		}
		if !fi.IsDir() {
			resp.Diagnostics.AddError("remote file is not a directory", "remote file is not a directory")
			return
		}
		permissions, ownerObj, groupObj, diags = d.getOwnershipAndPermissionsViaSFTP(ctx, sftpc, resourceData)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	identity, err := newIdentityFromWebDav(resourceData, d.providerData)
	if err != nil {
		resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
		return
	}
	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceData.Permissions = permissions
	resourceData.Owner = ownerObj
	resourceData.Group = groupObj
	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceData)...)
}

func (d *Directory) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, sftpc, diags := d.getClients(ctx, resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	permissions := basetypes.NewStringNull()
	ownerObj := basetypes.NewObjectNull(owner.Owner{}.AttributeTypes())
	groupObj := basetypes.NewObjectNull(owner.Group{}.AttributeTypes())
	if wdc != nil {
		resp.Diagnostics.AddWarning("unimplemented", "unimplemented because do not matter with webdav")
	} else if sftpc != nil {
		resp.Diagnostics.Append(d.setOwnershipAndPermissionsViaSFTP(ctx, sftpc, resourceData)...)
		if resp.Diagnostics.HasError() {
			return
		}
		permissions, ownerObj, groupObj, diags = d.getOwnershipAndPermissionsViaSFTP(ctx, sftpc, resourceData)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	identity, err := newIdentityFromWebDav(resourceData, d.providerData)
	if err != nil {
		resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
		return
	}
	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceData.Permissions = permissions
	resourceData.Owner = ownerObj
	resourceData.Group = groupObj
	resp.Diagnostics.Append(resp.State.Set(ctx, &resourceData)...)
}

func (d *Directory) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var resourceData resourceData
	resp.Diagnostics.Append(req.State.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, sftpc, diags := d.getClients(ctx, resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if wdc != nil {
		if err := wdc.RemoveAll(ctx, resourceData.Path.ValueString()); err != nil {
			resp.Diagnostics.AddError("failed to delete directory", fmt.Sprintf("failed to delete directory: %s", err.Error()))
			return
		}
	} else if sftpc != nil {
		if err := sftpc.RemoveAll(resourceData.Path.ValueString()); err != nil {
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
		Path:        basetypes.NewStringValue(parsedURL.Path),
		Permissions: basetypes.NewStringNull(),
		Owner:       basetypes.NewObjectNull(owner.Owner{}.AttributeTypes()),
		Group:       basetypes.NewObjectNull(owner.Group{}.AttributeTypes()),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &rs)...)
}
