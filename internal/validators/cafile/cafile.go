// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package cafile provides validators for files containing a list of root CA certificates
package cafile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/edsrzf/mmap-go"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type CAFileValidator struct{}
type CAFilePathValidator struct{}

var (
	_ validator.String = &CAFileValidator{}
	_ validator.String = &CAFilePathValidator{}
)

func validateCAFile(path path.Path, content []byte) diag.Diagnostics {
	rest := bytes.Trim(content, " \n")

	for len(rest) > 0 {
		var pemBlock *pem.Block
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			return diag.Diagnostics{diag.NewAttributeErrorDiagnostic(path, "invalid PEM block", fmt.Sprintf("invalid PEM block starting with %s", string(rest)[:100]))}
		}

		if _, err := x509.ParseCertificate(pemBlock.Bytes); err != nil {
			return diag.Diagnostics{diag.NewAttributeErrorDiagnostic(path, "invalid certificate", fmt.Sprintf("invalid certificate: %s", err.Error()))}
		}
	}
	return nil
}

func (v *CAFileValidator) Description(ctx context.Context) string {
	return "Validates that the specified string is a list of X.509 root certificates"
}

func (v *CAFileValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *CAFileValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue.ValueString()
	if value == "" {
		return
	}
	resp.Diagnostics.Append(validateCAFile(req.Path, []byte(value))...)
}

func (v *CAFilePathValidator) Description(ctx context.Context) string {
	return "Validates that the specified string is a list of X.509 root certificates"
}

func (v *CAFilePathValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *CAFilePathValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	filename := req.ConfigValue.ValueString()
	if filename == "" {
		return
	}
	f, err := os.Open(filename)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "no such CA file", fmt.Sprintf("no such CA file: %s", err.Error()))
		return
	}
	defer f.Close()
	mem, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to mmap file", fmt.Sprintf("failed to mmap file: %s", err.Error()))
		return
	}

	resp.Diagnostics.Append(validateCAFile(req.Path, mem)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := mem.Unmap(); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to unmap file", fmt.Sprintf("failed to unmap file: %s", err.Error()))
		return
	}
}
