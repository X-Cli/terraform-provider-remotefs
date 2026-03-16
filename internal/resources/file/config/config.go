// Copyright Florian Maury 2025, 2026
// SPDX-License-Identifier: BSD-2-Clause

// Package config specifies the data structure for the remotefs_file resource type.
package config

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/X-Cli/terraform-provider-remotefs/internal/models/sftp"
	"github.com/X-Cli/terraform-provider-remotefs/internal/models/webdav"
)

type ResourceData struct {
	WebDav          *webdav.ConnSpec `tfsdk:"webdav"`
	SFTP            *sftp.ConnSpec   `tfsdk:"sftp"`
	Keepers         types.Map        `tfsdk:"keepers"`
	Path            types.String     `tfsdk:"path"`
	InlineContent   types.String     `tfsdk:"inline_content"`
	ContentFilePath types.String     `tfsdk:"file_content"`
	HashSalt        types.String     `tfsdk:"hash_salt"`
	Permissions     types.String     `tfsdk:"permissions"`
	Owner           types.Object     `tfsdk:"owner"`
	Group           types.Object     `tfsdk:"group"`
}

// Merge can be used to merge a planned resource data (the receiver) and a configured resource data.
// This function is useful to have everything in one data structure, because planned resource data contains null values for write-only attributes and configured resource data does not contain everything either and it is just messy to carry around two data struct when one can perfectly do the job internally.
func (rd ResourceData) Merge(configuredResourceData ResourceData) ResourceData {
	returnedRD := ResourceData{
		Keepers:         rd.Keepers,
		Path:            rd.Path,
		InlineContent:   configuredResourceData.InlineContent,
		ContentFilePath: rd.ContentFilePath,
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
	if rd.SFTP != nil && configuredResourceData.WebDav != nil {
		returnedRD.SFTP = &sftp.ConnSpec{
			Address:              rd.SFTP.Address,
			Port:                 rd.SFTP.Port,
			Username:             rd.SFTP.Username,
			Password:             configuredResourceData.SFTP.Password,
			PrivateKey:           configuredResourceData.SFTP.PrivateKey,
			PrivateKeyPassphrase: configuredResourceData.SFTP.PrivateKeyPassphrase,
			PrivateKeyPath:       rd.SFTP.PrivateKeyPath,
			UseAgent:             rd.SFTP.UseAgent,
			AgentSockPath:        rd.SFTP.AgentSockPath,
			UseKnownHosts:        rd.SFTP.UseKnownHosts,
			KnownHostsFiles:      rd.SFTP.KnownHostsFiles,
			KnownHostsEntries:    rd.SFTP.KnownHostsEntries,
			UseSSHFP:             rd.SFTP.UseSSHFP,
		}
	}

	return returnedRD
}
