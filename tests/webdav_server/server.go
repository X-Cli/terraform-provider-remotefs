// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package server contains utilities to serve a WebDAV service to check the provider with
package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

var (
	reHTTPBasic = regexp.MustCompile(`^(?i:Basic) ([a-zA-Z0-9\+/]+)$`)
)

type authHandler struct {
	token string
	next  http.Handler
}

func (ah *authHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	authnHdr := req.Header.Get("authorization")
	if authnHdr != "" {
		presentedToken := reHTTPBasic.FindStringSubmatch(authnHdr)
		if len(presentedToken) != 2 || presentedToken[1] != ah.token {
			resp.WriteHeader(401)
			if _, err := resp.Write(fmt.Appendf(nil, "failed to authenticate: expected %q, found %q", ah.token, presentedToken)); err != nil {
				log.Printf("failed to send error body to HTTP client: %s", err.Error())
			}
			return
		}
	}
	ah.next.ServeHTTP(resp, req)
}

func CreateCA(tmpl *x509.Certificate) (pkey crypto.PrivateKey, cert *x509.Certificate, err error) {
	rootCAPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	rootCAPublicKey := rootCAPrivateKey.PublicKey

	rootCACertBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootCAPublicKey, rootCAPrivateKey)
	if err != nil {
		return
	}

	rootCACert, err := x509.ParseCertificate(rootCACertBytes)
	if err != nil {
		return
	}

	return rootCAPrivateKey, rootCACert, nil
}

func StartWebDavServer(t *testing.T, clientRootCA *x509.Certificate, username, password string) (port int, rootCACert *x509.Certificate, webdavFS webdav.FileSystem, err error) {
	rootCAPrivKey, rootCACert, err := CreateCA(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "RootCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	if err != nil {
		return
	}

	eePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	eePubKey := eePrivKey.PublicKey

	eeCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}, rootCACert, &eePubKey, rootCAPrivKey)
	if err != nil {
		return
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{
					eeCert,
				},
				PrivateKey: eePrivKey,
			},
		},
	}
	if clientRootCA != nil {
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(clientRootCA)
		tlsConf.ClientCAs = clientCAs
	}

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}

	_, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return
	}

	portI64, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		return
	}

	port = int(portI64)

	webdavFS = webdav.NewMemFS()

	var davHandler http.Handler = &webdav.Handler{
		Prefix:     "/",
		FileSystem: webdavFS,
		LockSystem: webdav.NewMemLS(),
	}

	if username != "" && password != "" {
		token := base64.RawStdEncoding.EncodeToString(fmt.Appendf(nil, "%s:%s", username, password))
		davHandler = &authHandler{
			token: token,
			next:  davHandler,
		}
	}
	srv := &http.Server{
		Handler:   davHandler,
		TLSConfig: tlsConf,
	}
	go func() {
		err := srv.ServeTLS(l, "", "")
		if !errors.Is(err, http.ErrServerClosed) {
			t.Logf("unexpected error while stoppping the HTTP server: %s", err.Error())
		}
	}()
	go func() {
		<-t.Context().Done()
		if err := srv.Close(); err != nil {
			t.Logf("unexpected error while closing the HTTP server: %s", err.Error())
		}
	}()

	return
}

func EncodeCACerts(certs []*x509.Certificate) string {
	var entries []string
	for _, cert := range certs {
		entries = append(entries, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
	}
	return strings.Join(entries, "\n")
}
