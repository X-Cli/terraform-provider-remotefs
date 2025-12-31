// Package certificates provides some helper functions to parse certificates
package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

func GetRootCAs(caFile, caFilePath string) (*x509.CertPool, error) {
	var certificateStrings []byte
	if caFile != "" {
		certificateStrings = []byte(caFile)
	} else if caFilePath != "" {
		var err error
		f, err := os.Open(caFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read cert file content: %w", err)
		}
		defer f.Close()
		certificateStrings, err = io.ReadAll(io.LimitReader(f, 10*1024*1024))
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %w", err)
		}
	} else {
		return nil, errors.New("unhandled case: missing certificate when using an HTTPS URL")
	}
	rootCAs, err := parseRootCAs(certificateStrings)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root CAs: %w", err)
	}
	return rootCAs, nil
}

func parseRootCAs(data []byte) (*x509.CertPool, error) {
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
