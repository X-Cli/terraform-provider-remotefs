// Package sftp provides a validator for sftp connection object
package sftp

import (
	"context"
	"fmt"
	"io"
	"os"

	sftp_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/sftp"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
)

type Validator struct{}

var (
	_ validator.Object = &Validator{}
)

func (v *Validator) Description(ctx context.Context) string {
	return "Validates SFTP configuration"
}

func (v *Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *Validator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	var connSpec sftp_model.ConnSpec
	resp.Diagnostics.Append(req.ConfigValue.As(ctx, &connSpec, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}
	var privateKeyBytes []byte
	if privateKey := connSpec.PrivateKey.ValueString(); privateKey != "" {
		privateKeyBytes = []byte(privateKey)
	} else if privateKeyPath := connSpec.PrivateKeyPath.ValueString(); privateKeyPath != "" {
		f, err := os.Open(privateKeyPath)
		if err != nil {
			resp.Diagnostics.AddAttributeError(req.Path, "failed to open private key file", fmt.Sprintf("failed to open private key file: %s", err.Error()))
			return
		}
		defer f.Close()

		privateKeyBytes, err = io.ReadAll(io.LimitReader(f, 4096))
		if err != nil {
			resp.Diagnostics.AddAttributeError(req.Path, "failed to read private key", fmt.Sprintf("failed to read private key: %s", err.Error()))
			return
		}
	}
	if len(privateKeyBytes) > 0 {
		passphrase := connSpec.PrivateKeyPassphrase.ValueString()
		if passphrase != "" {
			if _, err := ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase)); err != nil {
				resp.Diagnostics.AddAttributeError(req.Path, "failed to parse private key with passphrase", fmt.Sprintf("failed to parse private key with passphrase: %s", err.Error()))
				return
			}
		} else if _, err := ssh.ParsePrivateKey(privateKeyBytes); err != nil {
			resp.Diagnostics.AddAttributeError(req.Path, "failed to parse private key", fmt.Sprintf("failed to parse private key: %s", err.Error()))
			return
		}
	}
}
