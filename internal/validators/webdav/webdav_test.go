// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package webdav

import (
	"testing"

	"github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestValidatesHTTPBasic(t *testing.T) {
	ctx := t.Context()

	connSpec := webdav.ConnSpec{
		BaseURL:     basetypes.NewStringValue("https://127.0.0.1/"),
		CaFilePath:  basetypes.NewStringValue("/etc/ssl/certs/ca-certificates.crt"),
		AuthnMethod: basetypes.NewStringValue("basic"),
		Username:    basetypes.NewStringValue("titi"),
		Password:    basetypes.NewStringValue("toto"),
	}

	v, diags := basetypes.NewObjectValueFrom(
		ctx,
		map[string]attr.Type{
			"base_url":               types.StringType,
			"ca_file":                types.StringType,
			"ca_file_path":           types.StringType,
			"authentication_method":  types.StringType,
			"username":               types.StringType,
			"password":               types.StringType,
			"private_key":            types.StringType,
			"private_key_passphrase": types.StringType,
			"private_key_path":       types.StringType,
			"certificate":            types.StringType,
			"certificate_path":       types.StringType,
		},
		connSpec,
	)
	if diags.HasError() {
		t.Fatalf("failed to initialized object: %v", diags)
	}

	var resp validator.ObjectResponse

	valid := &Validator{}
	valid.ValidateObject(ctx, validator.ObjectRequest{
		Path:        path.Path{},
		ConfigValue: v,
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("failed to validate object: :%v", resp.Diagnostics)
	}
}
