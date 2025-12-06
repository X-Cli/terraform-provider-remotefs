# Create a directory /example. All connection information is specified in the provider configuration
resource "remotefs_directory" "example" {
  path = "/example"
}

# Create a directory /example over WebDAV
resource "remotefs_directory" "example" {
  path = "/example"
  webdav = {
    base_url = "http://127.0.0.1/dav/"
  }
}

