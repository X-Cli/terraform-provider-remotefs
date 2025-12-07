// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package config provides the structure for all data that may be passed by the provider to the resources.
package config

import (
	webdav_model "github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	webdav_client "github.com/emersion/go-webdav"
)

// ProviderData is the structure containing the data to be passed to the resources.
type ProviderData struct {
	ConnSpec     webdav_model.ConnSpec
	WebDavClient *webdav_client.Client
}
