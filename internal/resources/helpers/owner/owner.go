// Copyright Florian Maury 2025, 2026
// SPDX-License-Identifier: BSD-2-Clause

// Package owner specified the owner/group parts of the resource data
// Theses structure are common to remotefs_directory and remotefs_file resource types
package owner

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type Owner struct {
	Name types.String `tfsdk:"name"`
	UID  types.Int64  `tfsdk:"uid"`
}

func (o Owner) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
		"uid":  types.Int64Type,
	}
}

type Group struct {
	Name types.String `tfsdk:"name"`
	GID  types.Int64  `tfsdk:"gid"`
}

func (g Group) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
		"gid":  types.Int64Type,
	}
}
