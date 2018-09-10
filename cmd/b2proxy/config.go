package main

import (
	"fmt"
	"net"
	"time"
)

type Config struct {
	// AllowedOrigins is the set of origins
	// that are allowed in the HTTP 'Host' header.
	// The default is []string{"*"}, which
	// allows all origins.
	// (Optional; default is ["*"])
	AllowedOrigins []string `json:"allowed_origins,omitempty"`

	// LocalAddress is the address that
	// the server binds to. The format can
	// be "host:port" or simply ":port," in
	// which case the server will bind to
	// the wildcard address.
	//
	// If LocalAddress binds to any non-local
	// address, the server must have a valid
	// TLS configuration (see CertFile, PemFile)
	// (Optional; default is localhost:8443)
	LocalAddress string `json:"addr,omitempty"`

	// RefreshInterval is the interval
	// at which file metadata is re-loaded
	// in the server.
	// (Optional; default is 1 minute)
	RefreshInterval time.Duration `json:"refresh_interval,omitempty"`

	// CertFile is the file containing the
	// certificate to be presented in a TLS configuration.
	// (Optional)
	CertFile string `json:"tls_cert,omitempty"`

	// PemFile is the file containing the
	// secret key corresponding to the certificate
	// identified in CertFile. (If one of CertFile
	// or PemFile is present in the configuration,
	// the other must be present as well.)
	// (Optional)
	PemFile string `json:"tls_pem,omitempty"`

	// B2Key is the key that the server uses
	// to authenticate with B2. (Mandatory)
	B2Key string `json:"b2_key"`

	// B2KeyID is the ID of the key
	// present in the B2Key field. (Mandatory)
	B2KeyID string `json:"b2_key_id"`

	// Bucket is the name of the bucket
	// out of which content will be served.
	// Either Bucket or BucketID must be present.
	// If both Bucket and BucketID are present,
	// they must be consistent with one another.
	// If Bucket but not BucketID is present,
	// the server will automatically determine
	// BucketID, which requires that the key
	// presented in B2Key have the "listBuckets"
	// capability. (Sorry; this is due to the
	// fact that the B2 API does not expose a
	// way to turn a bucket name into a bucket ID
	// without listing every bucket.)
	Bucket   string `json:"bucket,omitempty"`
	BucketID string `json:"bucket_id,omitempty"`

	// RewriteRoot causes requests to '/'
	// to be rewritten to the given path,
	// e.g. '/index.html'
	// (This option is useful if you
	// are serving a static webpage
	// out of a bucket.)
	// The default behavior of GET-ing
	// '/' is to return a plain-text
	// list of all the files that
	// the server has indexed.
	RewriteRoot string `json:"rewrite_root,omitempty"`

	// computed after-the-fact
	host   string
	port   string
	useTLS bool
}

var DefaultConfig = Config{
	AllowedOrigins:  []string{"*"},
	LocalAddress:    "localhost:8443",
	RefreshInterval: 1 * time.Minute,
}

func (c *Config) Validate() error {
	if c.B2Key == "" || c.B2KeyID == "" ||
		c.Bucket == "" {
		return fmt.Errorf("config needs all of b2_key, b2_key_id, and bucket")
	}

	c.useTLS = true

	var err error
	c.host, c.port, err = net.SplitHostPort(c.LocalAddress)
	if err != nil {
		return err
	}

	if (c.CertFile == "") != (c.PemFile == "") {
		return fmt.Errorf("need both a cert file and private key file for TLS")
	}

	// For now, require HTTPS on everything that isn't localhost
	if c.CertFile == "" {
		if c.port == "443" || c.port == "https" {
			return fmt.Errorf("won't serve non-HTTPS on %s:%s", c.host, c.port)
		}
		if c.host != "localhost" && c.host != "127.0.0.1" && c.host != "::1" {
			return fmt.Errorf("not serving plain HTTP for host %s", c.host)
		}
		c.AllowedOrigins = []string{"localhost", "127.0.0.1", "::1"}
		c.useTLS = false
	}

	return nil
}
