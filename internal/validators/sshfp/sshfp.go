// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package sshfp validates a sshfp config consisting of a list of DNS resolvers and how to secure the communication with them
package sshfp

import (
	"context"
	"fmt"
	"net"

	sftp_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/sftp"
	"github.com/X-Cli/terraform-provider-remotefs/internal/validators/cafile"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type Validator struct{}

func (v *Validator) Description(ctx context.Context) string {
	return "Validates a use_sshfp config"
}

func (v *Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *Validator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	var dnsSpecs []sftp_model.DNSSpec
	resp.Diagnostics.Append(req.ConfigValue.ElementsAs(ctx, &dnsSpecs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, spec := range dnsSpecs {
		if spec.CAFile.ValueString() != "" {
			var certValidator cafile.CAFileValidator
			var certResp validator.StringResponse
			certReq := validator.StringRequest{
				Path:        req.Path,
				ConfigValue: spec.CAFile,
			}
			certValidator.ValidateString(ctx, certReq, &certResp)
			if certResp.Diagnostics.HasError() {
				resp.Diagnostics.Append(certResp.Diagnostics...)
				return
			}
		} else if caFilePath := spec.CAFilePath.ValueString(); caFilePath != "" {
			var certValidator cafile.CAFilePathValidator
			var certResp validator.StringResponse
			certReq := validator.StringRequest{
				Path:        req.Path,
				ConfigValue: spec.CAFilePath,
			}
			certValidator.ValidateString(ctx, certReq, &certResp)
			if certResp.Diagnostics.HasError() {
				resp.Diagnostics.Append(certResp.Diagnostics...)
				return
			}
		}
		for _, resv := range spec.DNSResolvers {
			ipAddr := net.ParseIP(resv.Address.ValueString())
			if ipAddr == nil {
				resp.Diagnostics.AddAttributeError(req.Path, "invalid IP address", fmt.Sprintf("invalid IP address: %q", resv.Address.ValueString()))
				return
			}
			if port := resv.Port.ValueInt32(); port < 1 || port > 65535 {
				resp.Diagnostics.AddAttributeError(req.Path, "invalid port number", "invalid port number: out of range [1;65535]")
				return
			}
			switch resv.Protocol.ValueString() {
			case "dns":
			case "dot":
			case "doh":
			default:
				resp.Diagnostics.AddAttributeError(req.Path, "invalid protocol", `invalid protocol: expected one of "dns", "dot" or "doh"`)
				return
			}
		}
	}
}
