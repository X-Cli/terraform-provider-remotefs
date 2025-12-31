package sftp

import (
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
		Description: ``,
		Required:    true,
	},
	"port": schema.Int32Attribute{
		Description: ``,
		Optional:    true,
		Validators: []validator.Int32{
			int32validator.Between(1, 65535),
		},
	},
	"username": schema.StringAttribute{
		Description: ``,
		Required:    true,
	},
	"password": schema.StringAttribute{
		Description: ``,
		Optional:    true,
		Sensitive:   true,
		WriteOnly:   true,
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
		Description: ``,
		Optional:    true,
		Sensitive:   true,
		WriteOnly:   true,
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
		Description: ``,
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
		Description: ``,
		Optional:    true,
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
		Description: ``,
		Optional:    true,
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
		Description: ``,
		Optional:    true,
		Validators: []validator.String{
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("password"),
				path.MatchRelative().AtParent().AtName("private_key"),
				path.MatchRelative().AtParent().AtName("private_key_passphrase"),
				path.MatchRelative().AtParent().AtName("private_key_path"),
			),
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("use_agent"),
				// TODO check path exists
			),
		},
	},
	"use_known_hosts": schema.BoolAttribute{
		Description: ``,
		Optional:    true,
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
		Description: ``,
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
		Description: ``,
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
		Description: ``,
		Optional:    true,
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
