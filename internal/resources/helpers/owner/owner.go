// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package owner specified the owner/group parts of the resource data
// Theses structure are common to remotefs_directory and remotefs_file resource types
package owner

import "github.com/hashicorp/terraform-plugin-framework/types"

type Owner struct {
	Name types.String `tfsdk:"name"`
	UID  types.Int64  `tfsdk:"uid"`
}

type Group struct {
	Name types.String `tfsdk:"name"`
	GIF  types.Int64  `tfsdk:"gid"`
}
