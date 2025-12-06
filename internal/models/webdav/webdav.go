// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package webdav specifies the material to establish a WebDav connection
package webdav

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/emersion/go-webdav"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/youmark/pkcs8"
)

// ConnSpec is a structure containing the information that may be used to establish a WebDav connection
// HTTP and HTTPS connections are supported. Optional client authentication is supported via HTTP Basic and a client certificate authentication.
// In case of client certificate authentication, the private key may be encrypted using a passphrase.
// Server authentication is supported over HTTPS using a provided list of certificates. Said list must be encoded with PEM in the manner of /etc/ssl/certs/ca-certificates.crt
type ConnSpec struct {
	BaseURL              types.String `tfsdk:"base_url"`
	CaFile               types.String `tfsdk:"ca_file"`
	CaFilePath           types.String `tfsdk:"ca_file_path"`
	AuthnMethod          types.String `tfsdk:"authentication_method"`
	Username             types.String `tfsdk:"username"`
	Password             types.String `tfsdk:"password"`
	PrivateKey           types.String `tfsdk:"private_key"`
	PrivateKeyPassPhrase types.String `tfsdk:"private_key_passphrase"`
	PrivateKeyPath       types.String `tfsdk:"private_key_path"`
	Certificate          types.String `tfsdk:"certificate"`
	CertificatePath      types.String `tfsdk:"certificate_path"`
}

func (cs *ConnSpec) getRootCAs() (*x509.CertPool, diag.Diagnostics) {
	var certificateStrings []byte
	if certs := cs.CaFile.ValueString(); certs != "" {
		certificateStrings = []byte(certs)
	} else if certPath := cs.CaFilePath.ValueString(); certPath != "" {
		var err error
		f, err := os.Open(certPath)
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to read cert file content", fmt.Sprintf("failed to read cert file content: %s", err.Error())),
			}
		}
		defer f.Close()
		certificateStrings, err = io.ReadAll(io.LimitReader(f, 10*1024*1024))
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to read certificate file", fmt.Sprintf("failed to read certificate file: %s", err.Error())),
			}
		}
	} else {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("unhandled case: missing certificate", "unhandled case: missing certificate when using an HTTPS URL"),
		}
	}
	rootCAs, err := cs.parseRootCAs(certificateStrings)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to parse root CAs", fmt.Sprintf("failed to parse root CAs: %s", err.Error())),
		}
	}
	return rootCAs, nil
}

func (cs *ConnSpec) parseRootCAs(data []byte) (*x509.CertPool, error) {
	data = bytes.Trim(data, " \n")

	pool := x509.NewCertPool()
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// GetClientCert returns the specified client certificate
// This function handles the many ways a certificate can be specified (inline, from a file, in DER or PEM format, etc.)
func (cs *ConnSpec) GetClientCert() (*x509.Certificate, diag.Diagnostics) {
	var certBytes []byte
	if certContent := cs.Certificate.ValueString(); certContent != "" {
		certBytes = []byte(certContent)
	} else if filename := cs.CertificatePath.ValueString(); filename != "" {
		var err error
		f, err := os.Open(filename)
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to open cert file", fmt.Sprintf("failed to open cert file: %s", err.Error())),
			}
		}
		defer f.Close()
		certBytes, err = io.ReadAll(io.LimitReader(f, 10*1024*1024))
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to read cert file", fmt.Sprintf("failed to read cert file: %s", err.Error())),
			}
		}
	} else {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("unhandled case: certificate and certificate_path attribute are both empty", "unhandled case: certificate and certificate_path attribute are both empty"),
		}
	}

	if bytes.Equal(certBytes[:5], []byte("-----")) {
		blk, _ := pem.Decode(certBytes)
		if blk.Type != "CERTIFICATE" {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("unexpected PEM block type", fmt.Sprintf("unexpected PEM block type: %s", blk.Type)),
			}
		}
		certBytes = blk.Bytes
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to parse certificate", fmt.Sprintf("failed to parse certificate: %s", certBytes)),
		}
	}
	return cert, nil
}

// GetClientPrivateKey returns the specified private key
// This function handles the many was a private key can be specified (inline, from a file, encrypted or unencrypted).
// The private key however needs to be specified in the PKCS#8 format. Only RSA, ECDSA and ED25519 keys are supported.
func (cs *ConnSpec) GetClientPrivateKey(pubKeyAlgo x509.PublicKeyAlgorithm) (crypto.PrivateKey, diag.Diagnostics) {
	var privateKeyBytes []byte
	if privKey := cs.PrivateKey.ValueString(); privKey != "" {
		privateKeyBytes = []byte(privKey)
	} else if filename := cs.PrivateKeyPath.ValueString(); filename != "" {
		var err error
		f, err := os.Open(filename)
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to open private key file", fmt.Sprintf("failed to open private key file: %s", err.Error())),
			}
		}
		defer f.Close()
		privateKeyBytes, err = io.ReadAll(io.LimitReader(f, 10*1024*1024))
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("failed to read private key file", fmt.Sprintf("failed to read private key file: %s", err.Error())),
			}
		}
	} else {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("unhandled case: missing private key", "unhandled case: private key was not specified as a file nor as an inline value"),
		}
	}

	if bytes.Equal(privateKeyBytes[:5], []byte("-----")) {
		blk, _ := pem.Decode(privateKeyBytes)
		privateKeyBytes = blk.Bytes
	}

	var pkey crypto.PrivateKey
	switch pubKeyAlgo {
	case x509.RSA:
		var err error
		pkey, err = pkcs8.ParsePKCS8PrivateKeyRSA(privateKeyBytes, []byte(cs.PrivateKeyPassPhrase.ValueString()))
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("unhandled case: missing private key", "unhandled case: private key was not specified as a file nor as an inline value"),
			}
		}
	case x509.ECDSA:
		var err error
		pkey, err = pkcs8.ParsePKCS8PrivateKeyECDSA(privateKeyBytes, []byte(cs.PrivateKeyPassPhrase.ValueString()))
		if err != nil {
			return nil, diag.Diagnostics{
				diag.NewErrorDiagnostic("unhandled case: missing private key", "unhandled case: private key was not specified as a file nor as an inline value"),
			}
		}
	case x509.Ed25519:
		pkey = ed25519.PrivateKey(privateKeyBytes)
	case x509.DSA:
		// Only supported for parsing but we are to use it for authentication so this is actually an error case
		fallthrough
	case x509.UnknownPublicKeyAlgorithm:
		fallthrough
	default:
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("unhandled public key type", fmt.Sprintf("unhandled public key type: %v", pubKeyAlgo)),
		}

	}
	return pkey, nil
}
func (cs *ConnSpec) getTransport() (*http.Transport, diag.Diagnostics) {
	parsedURL, err := url.Parse(cs.BaseURL.ValueString())
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to parse provided WebDav URL", fmt.Sprintf("failed to parse provided WebDav URL: %s", err.Error())),
		}
	}

	switch parsedURL.Scheme {
	case "http":
		return &http.Transport{}, nil
	case "https":
		var certs []tls.Certificate
		if cs.AuthnMethod.ValueString() == "cert" {
			clientCert, diags := cs.GetClientCert()
			if diags.HasError() {
				return nil, diags
			}

			clientPrivateKey, diags := cs.GetClientPrivateKey(clientCert.PublicKeyAlgorithm)
			if diags.HasError() {
				return nil, diags
			}

			certs = append(certs, tls.Certificate{
				PrivateKey: clientPrivateKey,
				Certificate: [][]byte{
					clientCert.Raw,
				},
			})
		}

		rootCAs, diags := cs.getRootCAs()
		if diags.HasError() {
			return nil, diags
		}

		return &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: certs,
				RootCAs:      rootCAs,
			},
		}, nil
	default:
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("unhandled scheme", fmt.Sprintf("unhandled scheme: %s", parsedURL.Scheme)),
		}
	}
}

// InitializeClient returns a WebDav client, already handling transparently all of the optional authentication that needs to happen
func (cs *ConnSpec) InitializeClient() (*webdav.Client, diag.Diagnostics) {
	transport, diags := cs.getTransport()
	if diags.HasError() {
		return nil, diags
	}

	var hc webdav.HTTPClient = &http.Client{
		Transport: transport,
	}

	if cs.AuthnMethod.ValueString() == "basic" {
		hc = webdav.HTTPClientWithBasicAuth(hc, cs.Username.ValueString(), cs.Password.ValueString())
	}

	wdc, err := webdav.NewClient(hc, cs.BaseURL.ValueString())
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to initialize WebDav client", fmt.Sprintf("failed to initialize WebDav client: %s", err.Error())),
		}
	}
	return wdc, nil
}
