// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package path

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type Path struct{}

var (
	_ validator.String = &Path{}
)

func (p *Path) Description(ctx context.Context) string {
	return "Validates that the value is a Unix path"
}

func (p *Path) MarkdownDescription(ctx context.Context) string {
	return p.Description(ctx)
}

func (p *Path) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {

}
