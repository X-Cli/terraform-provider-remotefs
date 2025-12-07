# Create a file "/example.txt" containing "toto" as content. All connection information are specified at the provider level.
resource "remotefs_file" "example" {
  path           = "/example.txt"
  inline_content = "toto"
}

# Copy the content the local file "local.txt" to the remote file "example.txt". All connection information are specified at the provider level.
resource "remotefs_file" "example" {
  path         = "/example.txt"
  file_content = "local.txt"
}

# Create a file containing a random identifier
resource "random_pet" "identifier" {
  length = 4
}

resource "remotefs_file" "remote_id" {
  path = "/my-id"
  inline_content = random_pet.identifier.id
}

# Create a file containing a random secret on two different servers: a shared secret
variable "secret_version" {
  description = "Increment value when the secrets need to be rolled"
  type        = number
  default     = 0
}

variable "private_key_passphrase" {
  description = "Private Key Passphrase"
  type        = string
  sensitive   = true
  ephemeral   = true
}

resource "random_bytes" "salt" {
  length = 16
}

ephemeral "random_password" "shared_secret" {
  length = 16
}

resource "remotefs_file" "shared_secret_srv1" {
  keepers = {
    secret_version = var.secret_version
  }
  path           = "/shared_secret.txt"
  inline_content = ephemeral.random_password.shared_secret.result
  hash_salt      = random_bytes.salt.hex
  webdav = {
    base_url               = "https://dav1.broken-by-design.fr/"
    ca_file_path           = "/etc/ssl/certs/ca-certificates.crt"
    authentication_method  = "cert"
    private_key_file       = "./terraform.key"
    private_key_passphrase = var.private_key_passphrase
    certificate_file       = "./terraform.crt"
  }
}

resource "remotefs_file" "shared_secret_srv2" {
  keepers = {
    secret_version = var.secret_version
  }
  path           = "/shared_secret.txt"
  inline_content = ephemeral.random_password.shared_secret.result
  hash_salt      = random_bytes.salt.hex
  webdav = {
    base_url               = "https://dav2.broken-by-design.fr/"
    ca_file_path           = "/etc/ssl/certs/ca-certificates.crt"
    authentication_method  = "cert"
    private_key_file       = "./terraform.key"
    private_key_passphrase = var.private_key_passphrase
    certificate_file       = "./terraform.crt"
  }
}
