// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package config specifies the data structure for the remotefs_file resource type
package config

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
	"github.com/X-Cli/terraform-provider-remotefs/internal/resources/helpers/owner"
)

type ResourceData struct {
	WebDav          *webdav.ConnSpec `tfsdk:"webdav"`
	Path            types.String     `tfsdk:"path"`
	InlineContent   types.String     `tfsdk:"inline_content"`
	ContentFilePath types.String     `tfsdk:"file_content"`
	ContentHash     types.String     `tfsdk:"hash"`
	HashSalt        types.String     `tfsdk:"hash_salt"`
	Permissions     types.String     `tfsdk:"permissions"`
	Owner           *owner.Owner     `tfsdk:"owner"`
	Group           *owner.Group     `tfsdk:"group"`
}

// Merge can be used to merge a planned resource data (the receiver) and a configured resource data
// This function is useful to have everything in one data structure, because planned resource data contains null values for write-only attributes and configured resource data does not contain everything either and it is just messy to carry around two data struct when one can perfectly do the job internally
func (rd ResourceData) Merge(configuredResourceData ResourceData) ResourceData {
	returnedRD := ResourceData{
		Path:            rd.Path,
		InlineContent:   configuredResourceData.InlineContent,
		ContentFilePath: rd.ContentFilePath,
		ContentHash:     rd.ContentHash,
		HashSalt:        rd.HashSalt,
		Permissions:     rd.Permissions,
		Owner:           rd.Owner,
		Group:           rd.Group,
	}

	if rd.WebDav != nil && configuredResourceData.WebDav != nil {
		returnedRD.WebDav = &webdav.ConnSpec{
			BaseURL:              rd.WebDav.BaseURL,
			CaFile:               rd.WebDav.CaFile,
			CaFilePath:           rd.WebDav.CaFilePath,
			AuthnMethod:          rd.WebDav.AuthnMethod,
			Username:             rd.WebDav.Username,
			Password:             configuredResourceData.WebDav.Password,
			PrivateKey:           configuredResourceData.WebDav.PrivateKey,
			PrivateKeyPassPhrase: configuredResourceData.WebDav.PrivateKeyPassPhrase,
			PrivateKeyPath:       rd.WebDav.PrivateKeyPath,
			Certificate:          rd.WebDav.Certificate,
			CertificatePath:      rd.WebDav.CertificatePath,
		}
	}

	return returnedRD
}
