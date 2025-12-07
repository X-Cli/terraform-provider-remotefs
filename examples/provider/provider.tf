# Empty provider. Configuration is done at the resource level

provider "remotefs" {}

# WebDAV connection information is specified at the provider level and shared by all resources not overriding these values. The address is an HTTP address and no client authentication is done.
provider "remotefs" {
  webdav = {
    base_url = "http://127.0.0.1/"
  }
}

# WebDAV connection information is specified at the provider level and shared by all resources not overriding these values. The address is an HTTPS address. The server uses a certificate emitted by a public certificate authority. No client authentication is done.
provider "remotefs" {
  webdav = {
    base_url     = "https://dav.broken-by-design.fr/"
    ca_cert_file = "/etc/ssl/certs/ca-certificates.crt"
  }
}


# WebDAV connection information is specified at the provider level and shared by all resources not overriding these values. The address is an HTTPS address. The server uses a certificate emitted by a public certificate authority. Client is authenticated using HTTP Basic.
provider "remotefs" {
  webdav = {
    base_url              = "https://dav.broken-by-design.fr/"
    ca_cert_file          = "/etc/ssl/certs/ca-certificates.crt"
    authentication_method = "basic"
    username              = "fmaury"
    password              = "tititoto"
  }
}

# WebDAV connection information is specified at the provider level and shared by all resources not overriding these values. The address is an HTTPS address. The server uses a certificate emitted by a public certificate authority. Client is authenticated using mTLS with the info provided as local files
provider "remotefs" {
  webdav = {
    base_url               = "https://dav.broken-by-design.fr/"
    ca_cert_file           = "/etc/ssl/certs/ca-certificates.crt"
    authentication_method  = "cert"
    private_key_path       = "./pkey.p8"
    private_key_passphrase = "tititoto"
    certificate_path       = "./cert.pem"
  }
}


# WebDAV connection information is specified at the provider level and shared by all resources not overriding these values. The address is an HTTPS address. The server uses a certificate emitted by a public certificate authority. Client is authenticated using mTLS, with the info provided as inline values

provider "remotefs" {
  base_url               = "https://dav.broken-by-design.fr/"
  ca_cert_file           = "/etc/ssl/certs/ca-certificates.crt"
  authentication_method  = "cert"
  private_key            = <<EOT
----- BEGIN ECDSA PRIVATE KEY -----
...
----- END ECDSA PRIVATE KEY -----
EOT
  private_key_passphrase = "tititoto"
  certificate            = <<EOT
----- BEGIN CERTIFICATE -----
...
----- END CERTIFICATE -----
EOT
}
