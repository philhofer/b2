package main

import (
	"fmt"
	"net"
	"time"
)

type Config struct {
	AllowedOrigins  []string      `json:"allowed_origins"`
	LocalAddress    string        `json:"addr"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	CertFile        string        `json:"tls_cert"`
	PemFile         string        `json:"tls_pem"`
	B2Key           string        `json:"b2_key"`
	B2KeyID         string        `json:"b2_key_id"`
	Bucket          string        `json:"bucket"`

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
