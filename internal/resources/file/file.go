// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package file implements the remotefs_file resource type
package file

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"

	provider_config "github.com/X-Cli/terraform-provider-remotefs/internal/provider/config"
	resource_config "github.com/X-Cli/terraform-provider-remotefs/internal/resources/file/config"
	webdav_resource "github.com/X-Cli/terraform-provider-remotefs/internal/resources/helpers/webdav"
	webdav_validator "github.com/X-Cli/terraform-provider-remotefs/internal/validators/webdav"
	webdav_client "github.com/emersion/go-webdav"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/argon2"
)

// Using values from RFC9106.
const (
	Argon2Time   uint32 = 3
	Argon2Mem    uint32 = 32 * 1024
	Argon2Thread uint8  = 4
)

const (
	contentHashKey string = "content_hash"
)

func hashWithArgon2ID(hash, salt string) (string, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %w", err)
	}
	fp := hex.EncodeToString(argon2.IDKey([]byte(hash), saltBytes, Argon2Time, Argon2Mem, Argon2Thread, 32))
	return fmt.Sprintf("$argon2id$%s$%s", salt, fp), nil
}

type privateData struct {
	ContentHash string `json:"content_hash"`
}

type File struct {
	providerData provider_config.ProviderData
}

type fileIdentity struct {
	URL      types.String `tfsdk:"url"`
	HashSalt types.String `tfsdk:"hash_salt"`
}

func newFileIdentityFromWebDav(rs resource_config.ResourceData, providerData provider_config.ProviderData, hashSalt string) (*fileIdentity, error) {
	var urlToParse string
	if rs.WebDav != nil {
		urlToParse = rs.WebDav.BaseURL.ValueString()
	} else {
		urlToParse = providerData.ConnSpec.BaseURL.ValueString()
	}
	parsedURL, err := url.Parse(urlToParse)
	if err != nil {
		return nil, err
	}
	parsedURL.RawFragment = ""
	parsedURL.RawQuery = ""
	parsedURL.User = nil
	parsedURL.RawPath = rs.Path.ValueString()

	return &fileIdentity{
		URL:      basetypes.NewStringValue(parsedURL.String()),
		HashSalt: basetypes.NewStringValue(hashSalt),
	}, nil
}

func newFileIdentityFromImportID(id string) (*fileIdentity, error) {
	parsedURL, err := url.Parse(id)
	if err != nil {
		return nil, err
	}

	parsedURL.RawFragment = ""
	parsedURL.RawQuery = ""
	parsedURL.User = nil

	return &fileIdentity{
		URL: basetypes.NewStringValue(parsedURL.String()),
	}, nil
}

var (
	_ resource.Resource                = &File{}
	_ resource.ResourceWithConfigure   = &File{}
	_ resource.ResourceWithIdentity    = &File{}
	_ resource.ResourceWithImportState = &File{}
	_ resource.ResourceWithModifyPlan  = &File{}
)

func New() resource.Resource {
	return &File{}
}

func (f *File) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_file", req.ProviderTypeName)
}

func (f *File) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `The file resource manages a file on a remote filesystem.

At the moment, only WebDAV is supported as a transport protocol but others will follow eventually.
`,
		Attributes: map[string]schema.Attribute{
			"webdav": schema.SingleNestedAttribute{
				Attributes: webdav_resource.ConnSpec,
				Description: `webdav specifies the connection information required to access the managed resource.

If this configuration value is not specified, the value defined at the provider level is used instead.

Exactly one connection type must be specified (currently only WebDAV is supported).

If the connection information is provided both at the provider level and at the resource level, the resource level information is preferred and used.`,
				Optional: true,
				Validators: []validator.Object{
					&webdav_validator.Validator{},
				},
			},
			"keepers": schema.MapAttribute{
				Description: "Arbitrary map of values that, when changed, will trigger recreation of resource. This is the same thing as hashicorp/random random_id keepers.",
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.RequiresReplace(),
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
			"inline_content": schema.StringAttribute{
				Description: `The managed file content itself.
	
When this attribute is not null, if the content of the managed file is identical to this attribute value, nothing is done. If the managed resource file content differs from this attribute value, the resource is replaced (the managed file is destroyed and recreated with this attribute value).

Setting this attribute to an empty string does count as a valid value and corresponds to an empty managed file.

This attribute is write-only, which means that the specified content is not stored in state, and ephemeral values can be used to set it. As such, setting this property to a sensitive value like a password can be done securely. If you do specify a password, please consider specifying the hash_salt property as well so that the hash algorithm used to compare the managed file content and this property value is appropriate and secure (Argon2ID of the SHA-512 of the file, instead of just SHA-512 of the file).

This attribute conflicts with the file_content attribute.
`,
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("file_content")),
				},
			},
			"file_content": schema.StringAttribute{
				Description: `The absolute path to a local file whose content is used to set the content of the managed file.

When this attribute is specified, the content of the local file is compared with the content of the managed file. If the content differs, the resource is replaced (the managed file is destroyed and recreated with the content of the local file specified with this attribute).

If the content of the local file and the content of the managed file are identical, then the state is just updated to the new value of that attribute and the managed file is left unchanged and untouched.

The content comparison is performed using a hash function. If the file content is sensitive, like a password, please consider specifying the hash_salt property as well so that the hash algorithm used to compare the managed file content and this property value is appropriate and secure (Argon2ID of the SHA-512 of the file, instead of just SHA-512 of the file).
`,
				Optional: true,
			},
			"hash_salt": schema.StringAttribute{
				Description: `A salt value to use when hashing the file content.

This attribute ought to be set if the content of the managed file is sensitive, like a password.

When this attribute is set, the file content hash is computed using the Argon2ID algorithm to reduce the risk of the sensitive value being recovered by a bruteforce attack on the hash property.
`,
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile("^[0-9a-fA-F]{32}$"), "Salt must be a hex-encoded 128 bits random value (32 bytes string)"),
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

func (f *File) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		f.providerData = req.ProviderData.(provider_config.ProviderData) //nolint:forcetypeassert
	}
}

func (f *File) getClients(resourceData resource_config.ResourceData) (*webdav_client.Client, diag.Diagnostics) {
	var wdc *webdav_client.Client
	if resourceData.WebDav != nil {
		var diags diag.Diagnostics
		wdc, diags = resourceData.WebDav.InitializeClient()
		if diags.HasError() {
			return nil, diags
		}
	} else if f.providerData.WebDavClient != nil {
		wdc = f.providerData.WebDavClient
	}
	return wdc, nil
}

func (f *File) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plannedResourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plannedResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var configuredResourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.Config.Get(ctx, &configuredResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mergedResourceData := plannedResourceData.Merge(configuredResourceData)

	wdc, diags := f.getClients(mergedResourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var identity *fileIdentity

	if wdc != nil {
		if plannedResourceData.Permissions.ValueString() != "" {
			resp.Diagnostics.AddWarning("ignored attribute", "ignored attribute: permissions attribute is not used with the WebDav connection type")
		}
		if plannedResourceData.Owner != nil {
			resp.Diagnostics.AddWarning("ignored attribute", "ignored attribute: owner attribute is not used with the WebDav connection type")
		}
		if plannedResourceData.Group != nil {
			resp.Diagnostics.AddWarning("ignored attribute", "ignored attribute: group attribute is not used with the WebDav connection type")
		}

		wc, err := wdc.Create(ctx, plannedResourceData.Path.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to create file", fmt.Sprintf("failed to create file: %s", err.Error()))
			return
		}
		defer wc.Close()

		contentHash := sha512.New()

		if !configuredResourceData.InlineContent.IsNull() {
			contentByte := []byte(configuredResourceData.InlineContent.ValueString())
			if n, err := wc.Write(contentByte); err != nil {
				resp.Diagnostics.AddError("failed to write to new file", fmt.Sprintf("failed to write to new file: %s", err.Error()))
				return
			} else if len(contentByte) > n {
				resp.Diagnostics.AddError("truncated write to new file", fmt.Sprintf("truncated write to new file: %d/%d", n, len(contentByte)))
				return
			}

			if n, err := contentHash.Write(contentByte); err != nil {
				resp.Diagnostics.AddError("failed to write to file hash", fmt.Sprintf("failed to write to file hash: %s", err.Error()))
				return
			} else if len(contentByte) > n {
				resp.Diagnostics.AddError("truncated write to file hash", fmt.Sprintf("truncated write to file hash: %d/%d", n, len(contentByte)))
				return
			}
		} else if !plannedResourceData.ContentFilePath.IsNull() {
			f, err := os.Open(plannedResourceData.ContentFilePath.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("failed to open file", fmt.Sprintf("failed to open file: %s", err.Error()))
				return
			}
			defer f.Close()
			for {
				var buf [4096]byte
				nr, err := f.Read(buf[:])
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					resp.Diagnostics.AddError("failed to read from file", fmt.Sprintf("failed to read from file: %s", err.Error()))
					return
				}

				if nw, err := wc.Write(buf[:nr]); err != nil {
					resp.Diagnostics.AddError("failed to write content to the server", fmt.Sprintf("failed to write content to the server: %s", err.Error()))
					return
				} else if nw < nr {
					resp.Diagnostics.AddError("truncated write content to the server", fmt.Sprintf("truncated write content to the server: %d/%d", nw, nr))
					return
				}

				if nw, err := contentHash.Write(buf[:nr]); err != nil {
					resp.Diagnostics.AddError("failed to hash content", fmt.Sprintf("failed to hash content: %s", err.Error()))
					return
				} else if nw < nr {
					resp.Diagnostics.AddError("truncated hashed content", fmt.Sprintf("truncated hashed content: %d/%d", nw, nr))
					return
				}
			}
		}

		computedHash := hex.EncodeToString(contentHash.Sum(nil))
		if hashSalt := plannedResourceData.HashSalt.ValueString(); hashSalt != "" {
			computedHash, err = hashWithArgon2ID(computedHash, hashSalt)
			if err != nil {
				resp.Diagnostics.AddError("failed to hash with Argon2", fmt.Sprintf("failed to hash with Argon2: %s", err.Error()))
				return
			}
		}

		privDataBytes, err := json.Marshal(privateData{ContentHash: computedHash})
		if err != nil {
			resp.Diagnostics.AddError("failed to marshal private data", fmt.Sprintf("failed to marshal private data: %s", err.Error()))
		}
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, contentHashKey, privDataBytes)...)
		if resp.Diagnostics.HasError() {
			return
		}

		identity, err = newFileIdentityFromWebDav(plannedResourceData, f.providerData, plannedResourceData.HashSalt.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
			return
		}
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plannedResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (f *File) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var resourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.State.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, diags := f.getClients(resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var identity *fileIdentity

	if wdc != nil {
		rc, err := wdc.Open(ctx, resourceData.Path.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to open file", fmt.Sprintf("failed to open file: %s", err.Error()))
			return
		}
		defer rc.Close()

		contentHash := sha512.New()
		if _, err := io.Copy(contentHash, rc); err != nil {
			resp.Diagnostics.AddError("failed to read file", fmt.Sprintf("failed to read file: %s", err.Error()))
			return
		}
		computedHash := hex.EncodeToString(contentHash.Sum(nil))
		if hashSalt := resourceData.HashSalt.ValueString(); hashSalt != "" {
			computedHash, err = hashWithArgon2ID(computedHash, hashSalt)
			if err != nil {
				resp.Diagnostics.AddError("failed to hash with Argon2", fmt.Sprintf("failed to hash with Argon2: %s", err.Error()))
				return
			}
		}

		privDataBytes, err := json.Marshal(privateData{ContentHash: computedHash})
		if err != nil {
			resp.Diagnostics.AddError("failed to marshal private data", fmt.Sprintf("failed to marshal private data: %s", err.Error()))
		}
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, contentHashKey, privDataBytes)...)
		if resp.Diagnostics.HasError() {
			return
		}

		identity, err = newFileIdentityFromWebDav(resourceData, f.providerData, resourceData.HashSalt.ValueString())
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
	if resp.Diagnostics.HasError() {
		return
	}
}

func (f *File) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plannedResourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plannedResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configuredResourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.Config.Get(ctx, &configuredResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mergedResourceData := plannedResourceData.Merge(configuredResourceData)

	wdc, diags := f.getClients(mergedResourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var identity *fileIdentity
	if wdc != nil {
		if plannedResourceData.Permissions.ValueString() != "" {
			resp.Diagnostics.AddWarning("ignored attribute", "ignored attribute: permissions attribute is not used with the WebDav connection type")
		}
		if plannedResourceData.Owner != nil {
			resp.Diagnostics.AddWarning("ignored attribute", "ignored attribute: owner attribute is not used with the WebDav connection type")
		}
		if plannedResourceData.Group != nil {
			resp.Diagnostics.AddWarning("ignored attribute", "ignored attribute: group attribute is not used with the WebDav connection type")
		}

		var err error
		identity, err = newFileIdentityFromWebDav(plannedResourceData, f.providerData, plannedResourceData.HashSalt.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to generate identity", fmt.Sprintf("failed to generate identity: %s", err.Error()))
			return
		}
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, identity)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plannedResourceData)...)
}

func (f *File) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var resourceData resource_config.ResourceData

	resp.Diagnostics.Append(req.State.Get(ctx, &resourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wdc, diags := f.getClients(resourceData)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if wdc != nil {
		if err := wdc.RemoveAll(ctx, resourceData.Path.ValueString()); err != nil {
			resp.Diagnostics.AddError("failed to delete file", fmt.Sprintf("failed to delete file: %s", err.Error()))
			return
		}
	}
}

func (f *File) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"url": identityschema.StringAttribute{
				RequiredForImport: true,
			},
			"hash_salt": identityschema.StringAttribute{
				OptionalForImport: true,
			},
		},
	}
}

func (f *File) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var fi fileIdentity
	if req.ID != "" {
		newID, err := newFileIdentityFromImportID(req.ID)
		if err != nil {
			resp.Diagnostics.AddError("failed to parse import ID", fmt.Sprintf("failed to parse import ID: %s", err.Error()))
			return
		}
		fi = *newID
	} else {
		resp.Diagnostics.Append(req.Identity.Get(ctx, &fi)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	parsedURL, err := url.Parse(fi.URL.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("failed to parse Import ID", fmt.Sprintf("failed to parse Import ID: %s", err.Error()))
		return
	}
	var rs resource_config.ResourceData
	rs.Path = basetypes.NewStringValue(parsedURL.Path)
	rs.Keepers = basetypes.NewMapNull(types.StringType)
	rs.HashSalt = fi.HashSalt

	resp.Diagnostics.Append(resp.State.Set(ctx, &rs)...)
}

func (f *File) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		// Planning destruction
		return
	}

	var configuredResourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.Config.Get(ctx, &configuredResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !configuredResourceData.Keepers.IsNull() {
		// Keepers are used to control replacement, so we don't not interfere
		return
	}

	var plannedResourceData resource_config.ResourceData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plannedResourceData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var mayRequireReplacement path.Paths

	newHash := basetypes.NewStringNull()
	if !configuredResourceData.InlineContent.IsNull() {
		// If the value is unknown, we cannot decide if a replacement is required or not, but if the value is known, then this attribute MAY be a reason to require a replacement.
		if !configuredResourceData.InlineContent.IsUnknown() {
			mayRequireReplacement.Append(path.Root("inline_content"))
		}
		if content := configuredResourceData.InlineContent.ValueString(); content != "" {
			h := sha512.New()
			bytesToWrite := []byte(content)
			if n, err := h.Write(bytesToWrite); err != nil {
				resp.Diagnostics.AddError("failed to write to hash", fmt.Sprintf("failed to write to hash: %s", err.Error()))
				return
			} else if n < len(bytesToWrite) {
				resp.Diagnostics.AddError("truncated write to hash", fmt.Sprintf("truncated write to hash: %d/%d", n, len(bytesToWrite)))
				return
			}
			newHash = basetypes.NewStringValue(hex.EncodeToString(h.Sum(nil)))
		}
	} else if !plannedResourceData.ContentFilePath.IsNull() {
		// If the value is unknown, we cannot decide if a replacement is required or not, but if the value is known, then this attribute MAY be a reason to require a replacement.
		if !plannedResourceData.ContentFilePath.IsUnknown() {
			mayRequireReplacement.Append(path.Root("file_content"))
		}
		if filePath := plannedResourceData.ContentFilePath.ValueString(); filePath != "" {
			// Testing if the content changed; if the file was just moved, then there is nothing to do
			f, err := os.Open(filePath)
			if err != nil {
				resp.Diagnostics.AddError("failed to open file", fmt.Sprintf("failed to open file: %s", err.Error()))
				return
			}
			defer f.Close()

			h := sha512.New()
			if _, err := io.Copy(h, f); err != nil {
				resp.Diagnostics.AddError("failed to open file", fmt.Sprintf("failed to open file: %s", err.Error()))
				return
			}
			newHash = basetypes.NewStringValue(hex.EncodeToString(h.Sum(nil)))
		}
	}

	if !newHash.IsNull() {
		// Not knowning the hash salt means we cannot compare the hashes, so we have to assume that it will trigger a replacement
		if plannedResourceData.HashSalt.IsUnknown() {
			resp.RequiresReplace.Append(path.Root("hash_salt"))
			return
		}
		if salt := plannedResourceData.HashSalt.ValueString(); salt != "" {
			argonHash, err := hashWithArgon2ID(newHash.ValueString(), salt)
			if err != nil {
				resp.Diagnostics.AddError("failed to hash with Argon2", fmt.Sprintf("failed to hash with Argon2: %s", err.Error()))
				return
			}
			newHash = basetypes.NewStringValue(argonHash)
		}

		privDataBytes, diags := req.Private.GetKey(ctx, contentHashKey)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		var previousHash string
		if privDataBytes != nil {
			var privData privateData
			if err := json.Unmarshal(privDataBytes, &privData); err != nil {
				resp.Diagnostics.AddError("failed to unmarshal private data", fmt.Sprintf("failed to unmarshal private data: %s", err.Error()))
				return
			}
			previousHash = privData.ContentHash
		}

		if previousHash != newHash.ValueString() {
			resp.RequiresReplace.Append(mayRequireReplacement...)
		}
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plannedResourceData)...)
	}
}
