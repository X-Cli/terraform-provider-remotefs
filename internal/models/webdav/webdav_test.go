// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package webdav

import (
	"encoding/pem"
	"fmt"
	"testing"

	server "github.com/X-Cli/terraform-provider-remotefs/tests/webdav_server"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestNoAuth(t *testing.T) {
	t.Parallel()
	port, rootCACert, webdavFS, err := server.StartWebDavServer(t, nil, "", "")

	if err != nil {
		t.Fatalf("failed to initialize webdav server: %s", err.Error())
	}

	webdavFS.Mkdir(t.Context(), "test", 0o755)

	pemEncodedRootCAs := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCACert.Raw})

	cs := ConnSpec{
		BaseURL:              basetypes.NewStringValue(fmt.Sprintf("https://127.0.0.1:%d/", port)),
		CaFile:               basetypes.NewStringValue(string(pemEncodedRootCAs)),
		CaFilePath:           basetypes.NewStringValue(""),
		AuthnMethod:          basetypes.NewStringValue(""),
		Username:             basetypes.NewStringValue(""),
		Password:             basetypes.NewStringValue(""),
		PrivateKey:           basetypes.NewStringValue(""),
		PrivateKeyPassPhrase: basetypes.NewStringValue(""),
		PrivateKeyPath:       basetypes.NewStringValue(""),
		Certificate:          basetypes.NewStringValue(""),
		CertificatePath:      basetypes.NewStringValue(""),
	}

	wdc, diags := cs.InitializeClient()
	if diags.HasError() {
		t.Fatalf("failed to initialize WebDav client: %v", diags)
	}

	if fi, err := wdc.Stat(t.Context(), "test"); err != nil {
		t.Fatalf("failed to stat test directory: %s", err.Error())
	} else if !fi.IsDir {
		t.Fatal("failed to carry dir flag")
	}

	if err := wdc.Mkdir(t.Context(), "pouet"); err != nil {
		t.Fatalf("failed to create directory: %s", err.Error())
	}
	if fi, err := webdavFS.Stat(t.Context(), "pouet"); err != nil {
		t.Fatalf("failed to stat pouet directory created through webdav: %s", err.Error())
	} else if !fi.IsDir() {
		t.Fatalf("node created by webdav was not identified as a directory")
	}
}
