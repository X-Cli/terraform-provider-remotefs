package knownhosts

import (
	"context"
	"os"
	"path"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
	ssh_known_hosts "golang.org/x/crypto/ssh/knownhosts"
)

type FileValidator struct{}

type EntryValidator struct{}

var (
	_ validator.Bool   = &FileValidator{}
	_ validator.String = &FileValidator{}
	_ validator.List   = &FileValidator{}
	_ validator.List   = &EntryValidator{}
	_ validator.String = &EntryValidator{}
)

func (v *FileValidator) Description(ctx context.Context) string {
	return "validates a known_hosts file"
}

func (v *FileValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *FileValidator) ValidateBool(ctx context.Context, req validator.BoolRequest, resp *validator.BoolResponse) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "missing home directory environment variable", "")
		return
	}

	sshKnownHostFile := path.Join(homeDir, ".ssh/known_hosts")

	var respStr validator.StringResponse
	v.ValidateString(ctx, validator.StringRequest{Path: req.Path, ConfigValue: basetypes.NewStringValue(sshKnownHostFile)}, &respStr)
	resp.Diagnostics.Append(resp.Diagnostics...)
}

func (v *FileValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	_, err := ssh_known_hosts.New(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to parse known_hosts file", err.Error())
		return
	}
}

func (v *FileValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	var files []types.String
	resp.Diagnostics.Append(req.ConfigValue.ElementsAs(ctx, &files, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, file := range files {
		var respStr validator.StringResponse
		v.ValidateString(ctx, validator.StringRequest{Path: req.Path, ConfigValue: file}, &respStr)
		resp.Diagnostics.Append(respStr.Diagnostics...)
	}
}

func (v *EntryValidator) Description(ctx context.Context) string {
	return "validates a known_hosts file entry"
}

func (v *EntryValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *EntryValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	var entries []types.String
	resp.Diagnostics.Append(req.ConfigValue.ElementsAs(ctx, &entries, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, entry := range entries {
		var respStr validator.StringResponse
		v.ValidateString(ctx, validator.StringRequest{Path: req.Path, ConfigValue: entry}, &respStr)
		resp.Diagnostics.Append(respStr.Diagnostics...)
	}
}

func (v *EntryValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	entry := req.ConfigValue.ValueString()
	if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(entry)); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "failed to parse known_hosts entry", err.Error())
	}
}
