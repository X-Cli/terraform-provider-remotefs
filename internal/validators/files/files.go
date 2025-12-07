// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package files

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type FileValidator struct{}

var (
	_ validator.String = &FileValidator{}
)

func (v *FileValidator) Description(ctx context.Context) string {
	return "File validator checking read permission on file"
}

func (v *FileValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *FileValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	filename := req.ConfigValue.ValueString()
	if filename == "" {
		return
	}

	f, err := os.Open(filename)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to open file", fmt.Sprintf("failed to open file: %s", err.Error()))
		return
	}
	_ = f.Close()
}
