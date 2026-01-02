// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

// Package sftpserver implements a "fake" SFTP server to use during the tests
package sftpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func StartSFTPServer(ctx context.Context) (pubKey ssh.PublicKey, port int, sftpFS sftp.Handlers, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	pubKey, err = ssh.NewPublicKey(privKey.Public())
	if err != nil {
		return
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}

	_, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return
	}
	portI64, err := strconv.ParseInt(portStr, 0, 32)
	if err != nil {
		return
	}
	port = int(portI64)

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return
	}
	srvConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "titi" && bytes.Equal(password, []byte("toto")) {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to authenticate user %q", conn.User())
		},
	}
	srvConfig.AddHostKey(signer)

	sftpFS = sftp.InMemHandler()

	go func() {
		<-ctx.Done()
		if err := l.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to close listener: %s", err.Error())
		}
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				_, sshSrvChannels, reqs, err := ssh.NewServerConn(conn, srvConfig)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to create new server connection: %s", err.Error())
					return
				}

				go ssh.DiscardRequests(reqs)

				for sshSrvChan := range sshSrvChannels {
					go func(c ssh.NewChannel) {
						if c.ChannelType() != "session" {
							fmt.Fprintf(os.Stderr, "unknown channel type: %s\n", c.ChannelType())
							if err := c.Reject(ssh.UnknownChannelType, "unimplemented"); err != nil {
								fmt.Fprintf(os.Stderr, "failed to reject unknown channel type: %s", err.Error())
							}
							return
						}

						subChan, sftpReq, err := c.Accept()
						if err != nil {
							fmt.Fprintf(os.Stderr, "failed to accept request: %s\n", err.Error())
							return
						}

						go func(reqs <-chan *ssh.Request) {
							for req := range reqs {
								ok := req.Type == "subsystem" && bytes.Equal(req.Payload[4:], []byte("sftp"))
								if err := req.Reply(ok, nil); err != nil {
									fmt.Fprintf(os.Stderr, "failed to reply to the request: %s\n", err.Error())
									return
								}
							}
						}(sftpReq)

						sftpSrv := sftp.NewRequestServer(subChan, sftpFS)
						go func() {
							<-ctx.Done()
							_ = sftpSrv.Close()
						}()
						go func() {
							if err := sftpSrv.Serve(); err != nil && !errors.Is(err, io.EOF) {
								fmt.Fprintf(os.Stderr, "failed to serve: %s", err.Error())
								return
							}
						}()
					}(sshSrvChan)
				}
			}(conn)
		}
	}()

	return
}
