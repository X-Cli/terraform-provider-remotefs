// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package url provides a validator to check URL syntax
package url

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type URLValidator struct{}

var (
	_ validator.String = &URLValidator{}
)

func (v *URLValidator) Description(ctx context.Context) string {
	return "Validates that the specified string is a URL"
}

func (v *URLValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *URLValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue.ValueString()
	if value == "" {
		return
	}

	if _, err := url.Parse(value); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "invalid URL", fmt.Sprintf("invalid URL: %s", err.Error()))
	}
}
