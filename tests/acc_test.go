// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/X-Cli/terraform-provider-remotefs/internal/provider"
	"github.com/X-Cli/terraform-provider-remotefs/tests/planchecks/comparevalues"
	server "github.com/X-Cli/terraform-provider-remotefs/tests/webdav_server"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/youmark/pkcs8"
)

func TestAccDirectory(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_directory" "test" {
				  path = "/test"
				}
			  `, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					if fi, err := davfs.Stat(t.Context(), "/test"); err != nil {
						return fmt.Errorf("failed to stat dir: %s", err.Error())
					} else if !fi.IsDir() {
						return fmt.Errorf("not a directory")
					}
					return nil
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFile(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h := sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
				  inline_content = "%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), string(fileContent[:])),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFileContentChanged(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var originalRandomContent [4096]byte
	var originalFileContent [8192]byte
	if _, err := rand.Read(originalRandomContent[:]); err != nil {
		t.Fatalf("failed to initialize original buffer content: %s", err.Error())
	}
	hex.Encode(originalFileContent[:], originalRandomContent[:])
	h := sha512.New()
	h.Write(originalFileContent[:])
	expectedOrigHash := hex.EncodeToString(h.Sum(nil))

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h = sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
					inline_content = "%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), string(originalFileContent[:])),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], originalFileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedOrigHash)),
				},
			},
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
					inline_content = "%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), string(fileContent[:])),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestImportDirectoryByID(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	if err := davfs.Mkdir(t.Context(), "/test", 0600); err != nil {
		t.Fatalf("failed to create directory: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_directory" "test" {
          path = "/test"
				}

				import {
          to = remotefs_directory.test
					id = "https://127.0.0.1/test/"
				}
			  `, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					if fi, err := davfs.Stat(t.Context(), "/test"); err != nil {
						return fmt.Errorf("failed to stat dir: %s", err.Error())
					} else if !fi.IsDir() {
						return fmt.Errorf("not a directory")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_directory.test", tfjsonpath.New("path"), knownvalue.StringExact("/test")),
				},
			},
		},
	})
}

func TestImportDirectoryByIdentity(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	if err := davfs.Mkdir(t.Context(), "/test", 0600); err != nil {
		t.Fatalf("failed to create directory: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_directory" "test" {
          path = "/test"
				}

				import {
          to = remotefs_directory.test
					identity = {
            url = "https://127.0.0.1/test/"
					}
				}
			  `, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					if fi, err := davfs.Stat(t.Context(), "/test"); err != nil {
						return fmt.Errorf("failed to stat dir: %s", err.Error())
					} else if !fi.IsDir() {
						return fmt.Errorf("not a directory")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_directory.test", tfjsonpath.New("path"), knownvalue.StringExact("/test")),
				},
			},
		},
	})
}

func TestAccFileImportByID(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h := sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	f, err := davfs.OpenFile(t.Context(), "/test", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %s", err.Error())
	}
	if n, err := f.Write(fileContent[:]); err != nil {
		t.Fatalf("failed to write file content: %s", err.Error())
	} else if n < len(fileContent) {
		t.Fatalf("truncated write: %d/%d", n, len(fileContent))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				import {
          to = remotefs_file.test
					id = "https://127.0.0.1/test"
				}
				resource "remotefs_file" "test" {
					path = "/test"
				}
				`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources imported by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFileImportByIdentity(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h := sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	f, err := davfs.OpenFile(t.Context(), "/test", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %s", err.Error())
	}
	if n, err := f.Write(fileContent[:]); err != nil {
		t.Fatalf("failed to write file content: %s", err.Error())
	} else if n < len(fileContent) {
		t.Fatalf("truncated write: %d/%d", n, len(fileContent))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				import {
          to = remotefs_file.test
					identity = {
            url = "https://127.0.0.1/test"
					}
				}
				resource "remotefs_file" "test" {
					path = "/test"
				}
				`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources imported by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFileImportByIdentityWithPasswordContent(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	fileContent := []byte("bonjour")
	f, err := davfs.OpenFile(t.Context(), "/test", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %s", err.Error())
	}
	if n, err := f.Write(fileContent[:]); err != nil {
		t.Fatalf("failed to write file content: %s", err.Error())
	} else if n < len(fileContent) {
		t.Fatalf("truncated write: %d/%d", n, len(fileContent))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				import {
          to = remotefs_file.test
					identity = {
            url = "https://127.0.0.1/test"
			  		hash_salt = "01234567890123450123456789012345"
					}
				}
				resource "remotefs_file" "test" {
					path = "/test"
					hash_salt = "01234567890123450123456789012345"
				}
				`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 7 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact("$argon2id$01234567890123450123456789012345$4e8a4d5d881ab1215f7e76e515764c0fde7e909e4141ca2b32a04a9c8173385e")),
				},
			},
		},
	})

	// Not found because after the test, resources imported by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFileNoModifOnSecondApply(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h := sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
				  inline_content = "%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), string(fileContent[:])),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccEmptyFile(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
				  inline_content = ""
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					if fi, err := davfs.Stat(t.Context(), "/test"); err != nil {
						return err
					} else if size := fi.Size(); size != 0 {
						return fmt.Errorf("expected empty file: got %d bytes", size)
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					// This is the SHA512 of an empty stirng
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")),
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFileImportByIdentityThenAddTheSameFile(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h := sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	f, err := davfs.OpenFile(t.Context(), "/test", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %s", err.Error())
	}
	if n, err := f.Write(fileContent[:]); err != nil {
		t.Fatalf("failed to write file content: %s", err.Error())
	} else if n < len(fileContent) {
		t.Fatalf("truncated write: %d/%d", n, len(fileContent))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				import {
          to = remotefs_file.test
					identity = {
            url = "https://127.0.0.1/test"
					}
				}
				resource "remotefs_file" "test" {
					path = "/test"
				}
				`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert})),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				import {
          to = remotefs_file.test
					identity = {
            url = "https://127.0.0.1/test"
					}
				}
				resource "remotefs_file" "test" {
					path = "/test"
					inline_content="%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), string(fileContent[:])),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources imported by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccFileFromLocalFile(t *testing.T) {
	port, rootCACert, davfs, err := server.StartWebDavServer(t, nil, "titi", "toto")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	var fileRandom [4096]byte
	var fileContent [8192]byte
	if _, err := rand.Read(fileRandom[:]); err != nil {
		t.Fatalf("failed to initialize buffer content: %s", err.Error())
	}
	hex.Encode(fileContent[:], fileRandom[:])
	h := sha512.New()
	h.Write(fileContent[:])
	expectedHash := hex.EncodeToString(h.Sum(nil))

	localFile := path.Join(t.TempDir(), "content.dat")
	if err := os.WriteFile(localFile, fileContent[:], 0644); err != nil {
		t.Fatalf("failed to write file %s: %s", localFile, err.Error())
	}
	localFile2 := path.Join(t.TempDir(), "content2.dat")
	if err := os.WriteFile(localFile2, fileContent[:], 0644); err != nil {
		t.Fatalf("failed to write file %s: %s", localFile2, err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
				  file_content = "%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), localFile),
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "basic"
						username = "titi"
						password = "toto"
					}
				}
				resource "remotefs_file" "test" {
				  path = "/test"
				  file_content = "%s"
				}
					`, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), localFile2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("remotefs_file.test", plancheck.ResourceActionUpdate),
						&comparevalues.ComparePlanValues{
							ResourceAddress: "remotefs_file.test",
							AttributePath:   tfjsonpath.New("file_content"),
							BeforeValue:     knownvalue.StringExact(localFile),
							AfterValue:      knownvalue.StringExact(localFile2),
						},
					},
				},
				Check: func(state *terraform.State) error {
					f, err := davfs.OpenFile(t.Context(), "/test", os.O_RDONLY, 0)
					if err != nil {
						return err
					}
					defer f.Close()

					var fileTotalContent [16384]byte
					n, err := f.Read(fileTotalContent[:])
					if err != nil && !errors.Is(err, io.EOF) {
						return err
					} else if n != 8192 {
						return fmt.Errorf("unexpected read size: %d", n)
					}

					if !bytes.Equal(fileTotalContent[:n], fileContent[:]) {
						return fmt.Errorf("mismatch content")
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("remotefs_file.test", tfjsonpath.New("hash"), knownvalue.StringExact(expectedHash)),
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}

func TestAccDirectoryAuthnCert(t *testing.T) {
	clientCAPrivKey, clientCACert, err := server.CreateCA(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "Client RootCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	if err != nil {
		t.Fatalf("failed to generate client CA: %s", err.Error())
	}

	eePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %s", err.Error())
	}
	eePubKey := eePrivKey.PublicKey

	eeCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}, clientCACert, &eePubKey, clientCAPrivKey)
	if err != nil {
		t.Fatalf("failed to create EE certificate: %s", err.Error())
	}

	p8PrivKey, err := pkcs8.ConvertPrivateKeyToPKCS8(eePrivKey, []byte("passphrase"))
	if err != nil {
		t.Fatalf("failed to format private key as a PKCS#8 container: %s", err.Error())
	}

	p8PEM := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: p8PrivKey})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: eeCert})

	port, rootCACert, davfs, err := server.StartWebDavServer(t, clientCACert, "", "")
	if err != nil {
		t.Fatalf("failed to startup DAV server: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"remotefs": func() (tfprotov6.ProviderServer, error) {
				return providerserver.NewProtocol6(provider.New())(), nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`provider "remotefs" {
					webdav = {
					base_url = "https://127.0.0.1:%d/"
						ca_file = <<EOT
%s
EOT
						authentication_method = "cert"
						private_key = <<EOT
%s
EOT
					  private_key_passphrase = "passphrase"
					  certificate = <<EOT
%s
EOT
					}
				}
				resource "remotefs_directory" "test" {
				  path = "/test"
				}
			  `, port, server.EncodeCACerts([]*x509.Certificate{rootCACert}), p8PEM, certPEM),
				Check: func(state *terraform.State) error {
					if fi, err := davfs.Stat(t.Context(), "/test"); err != nil {
						return fmt.Errorf("failed to stat dir: %s", err.Error())
					} else if !fi.IsDir() {
						return fmt.Errorf("not a directory")
					}
					return nil
				},
			},
		},
	})

	// Not found because after the test, resources created by the test are destroyed
	if _, err := davfs.Stat(t.Context(), "/test"); err == nil {
		t.Fatal("unexpected success; resource ought to be destroyed after the test")
	}
}
