// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package webdav provides a validator for the webdav configuration option of this provider
package webdav

import (
	"context"
	"fmt"
	"net/url"

	"github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type Validator struct{}

var (
	_ validator.Object = &Validator{}
)

func (v *Validator) Description(ctx context.Context) string {
	return "Validates WebDav Configuration Coherence"
}

func (v *Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *Validator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	var connSpec webdav.ConnSpec
	resp.Diagnostics.Append(req.ConfigValue.As(ctx, &connSpec, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true, UnhandledUnknownAsEmpty: true})...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check HTTP scheme in URL and CAfile specification
	urlScheme, err := url.Parse(connSpec.BaseURL.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to parse URL", fmt.Sprintf("failed to parse URL: %s", err.Error()))
		return
	}
	if urlScheme.Scheme == "https" && connSpec.CaFile.ValueString() == "" && connSpec.CaFilePath.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "missing root certificates", "missing root certificates for a URL using the HTTPS scheme")
		return
	}

	switch connSpec.AuthnMethod.ValueString() {
	case "":
		fallthrough
	case "none":
		// Doing nothing
	case "cert":
		if connSpec.Username.ValueString() != "" || connSpec.Password.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: username and password must not be specified when using a certificate based authentication scheme")
		}
		if (connSpec.PrivateKey.ValueString() == "" && connSpec.PrivateKeyPath.ValueString() == "") || (connSpec.PrivateKey.ValueString() != "" && connSpec.PrivateKeyPath.ValueString() != "") {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: exactly one of a private key or a private key path must be specified when using a certificate based authentication scheme")
		}
		if (connSpec.Certificate.ValueString() == "" && connSpec.CertificatePath.ValueString() == "") || (connSpec.Certificate.ValueString() != "" && connSpec.CertificatePath.ValueString() != "") {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: exactly one of a certificate or a certificate path must be specified when using a certificate based authentication scheme")
		}

		cert, diags := connSpec.GetClientCert()
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		_, diags = connSpec.GetClientPrivateKey(cert.PublicKeyAlgorithm)
		resp.Diagnostics.Append(diags...)
	case "basic":
		if connSpec.PrivateKey.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: private key cannot be set when using a password based authentication scheme")
		}
		if connSpec.PrivateKeyPassPhrase.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: private key passphrase cannot be set when using a password based authentication scheme")
		}
		if connSpec.PrivateKeyPath.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: private key path cannot be set when using a password based authentication scheme")
		}
		if connSpec.Username.ValueString() == "" || connSpec.Password.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(req.Path, "invalid authentication configuration", "invalid authentication configuration: username and password must be specified when using a password based authentication scheme")
		}
	default:
		resp.Diagnostics.AddAttributeError(req.Path, "unexpected error: invalid authentication value", fmt.Sprintf("unexpected error: invalid authentication value: %s", connSpec.AuthnMethod.ValueString()))
	}
}
