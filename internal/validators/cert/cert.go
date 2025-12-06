// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package cert

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

type CertValidator struct{}
type CertFileValidator struct{}

var (
	_ validator.String = &CertValidator{}
	_ validator.String = &CertFileValidator{}
)

func validateCert(path path.Path, content []byte) diag.Diagnostics {
	rest := bytes.Trim(content, " \n")

	var blk *pem.Block
	var certContent []byte
	blk, rest = pem.Decode(rest)
	if blk == nil {
		certContent = rest
	} else {
		if len(rest) > 0 {
			return diag.Diagnostics{diag.NewAttributeErrorDiagnostic(path, "trailing bytes after certificate", fmt.Sprintf("trailing bytes after certificate: %s", string(rest)[:100]))}
		}
		certContent = blk.Bytes
	}
	if _, err := x509.ParseCertificate(certContent); err != nil {
		return diag.Diagnostics{diag.NewAttributeErrorDiagnostic(path, "invalid certificate", fmt.Sprintf("invalid certificate: %s", err.Error()))}
	}
	return nil
}

func (v *CertValidator) Description(ctx context.Context) string {
	return "Validates that the provided string contains a certificate in PEM or DER format"
}

func (v *CertValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *CertValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue.ValueString()
	if value == "" {
		return
	}
	resp.Diagnostics.Append(validateCert(req.Path, []byte(value))...)
}

func (v *CertFileValidator) Description(ctx context.Context) string {
	return "Validates that the provided string points to a file containing a certificate in PEM or DER format"
}

func (v *CertFileValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *CertFileValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue.ValueString()
	if value == "" {
		return
	}
	f, err := os.Open(value)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "could not open file", fmt.Sprintf("could not open file: %s", err.Error()))
		return
	}
	mem, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to mmap file", fmt.Sprintf("failed to mmap file: %s", err.Error()))
		return
	}
	resp.Diagnostics.Append(validateCert(req.Path, mem)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := mem.Unmap(); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to unmap file", fmt.Sprintf("failed to unmap file: %s", err.Error()))
		return
	}
	if err := f.Close(); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "could not close file", fmt.Sprintf("could not close file: %s", err.Error()))
		return
	}
}
