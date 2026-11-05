package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
)

// OTLP exporter configuration keys, shared by the agent and the controller.
// They configure only the connection to the OpenTelemetry Collector and are
// independent of the controller-agent tls_* keys.
const (
	keyOtelCollectorAddr            = "otel_collector_addr"
	keyOtelCollectorTLSEnabled      = "otel_collector_tls_enabled"
	keyOtelCollectorTLSCAFile       = "otel_collector_tls_ca_file"
	keyOtelCollectorTLSServerName   = "otel_collector_tls_server_name"
	keyOtelCollectorBearerTokenFile = "otel_collector_bearer_token_file"
)

// maxBearerTokenFileBytes bounds the size of otel_collector_bearer_token_file.
// A bearer token is a short string; a larger file is a misconfiguration (for
// example the path of a certificate bundle), so it is rejected rather than
// read in full.
const maxBearerTokenFileBytes = 16 << 10

// OTLPExporterConfig describes the connection of the OTLP/gRPC metric
// exporter to the OpenTelemetry Collector. The agent's metrics and the
// controller's analyzer metrics are exported through it.
//
// The zero value of every field except Endpoint is the pre-existing
// behavior: plaintext gRPC without authentication. With TLSEnabled, the
// exporter verifies the Collector's certificate chain and host name and never
// falls back to plaintext; a failed handshake fails the export.
//
// The struct holds the path of the bearer token, never the token itself, so
// printing or logging a configuration cannot reveal the secret.
type OTLPExporterConfig struct {
	// Endpoint is the Collector as host:port, without a URL scheme.
	Endpoint string
	// TLSEnabled turns on TLS with certificate and host name verification.
	TLSEnabled bool
	// CAFile is a PEM bundle of the CAs trusted to sign the Collector's
	// certificate. Empty uses the system roots.
	CAFile string
	// ServerName is the name verified against the Collector's certificate
	// and sent as SNI. Empty uses the host of Endpoint; set it when Endpoint
	// is an IP address or a name the certificate does not carry.
	ServerName string
	// BearerTokenFile is a file holding the bearer token sent in the
	// "authorization" metadata of every export. Empty sends no token. It
	// requires TLSEnabled.
	BearerTokenFile string
}

// Validate checks the settings and the files they name. It performs the same
// checks as Credentials, so a configuration that passes Validate at startup
// yields an exporter, unless the files change in between.
func (c OTLPExporterConfig) Validate() error {
	_, _, err := c.Credentials()
	return err
}

// Credentials loads what the exporter needs to connect: the TLS client
// configuration, which is nil for plaintext, and the bearer token, which is
// "" when no token file is configured. It rejects a URL scheme in the
// endpoint, TLS-only settings without TLS (in particular a bearer token,
// which is never sent over plaintext), an unreadable or unparsable CA bundle,
// and an unreadable, empty or malformed token file. Errors name the
// configuration key and the file but never include the token.
func (c OTLPExporterConfig) Credentials() (*tls.Config, string, error) {
	if err := validateOTLPEndpoint(c.Endpoint); err != nil {
		return nil, "", err
	}
	if !c.TLSEnabled {
		return nil, "", c.rejectTLSOnlySettings()
	}

	tlsCfg := &tls.Config{
		ServerName: c.ServerName,
		MinVersion: tls.VersionTLS12,
	}
	if c.CAFile != "" {
		pool, err := loadCACertPool(keyOtelCollectorTLSCAFile, c.CAFile)
		if err != nil {
			return nil, "", err
		}
		tlsCfg.RootCAs = pool
	}

	if c.BearerTokenFile == "" {
		return tlsCfg, "", nil
	}
	token, err := readBearerTokenFile(c.BearerTokenFile)
	if err != nil {
		return nil, "", err
	}
	return tlsCfg, token, nil
}

// rejectTLSOnlySettings returns an error naming the first setting that has
// no effect without TLS. Accepting them silently would let an operator
// believe the connection is encrypted or authenticated when it is not.
func (c OTLPExporterConfig) rejectTLSOnlySettings() error {
	if c.BearerTokenFile != "" {
		return fmt.Errorf("%s requires %s: true; the bearer token is never sent over plaintext",
			keyOtelCollectorBearerTokenFile, keyOtelCollectorTLSEnabled)
	}
	for _, s := range []struct{ key, value string }{
		{keyOtelCollectorTLSCAFile, c.CAFile},
		{keyOtelCollectorTLSServerName, c.ServerName},
	} {
		if s.value != "" {
			return fmt.Errorf("%s is set but %s is false; enable TLS or remove the setting",
				s.key, keyOtelCollectorTLSEnabled)
		}
	}
	return nil
}

// readBearerTokenFile reads a bearer token from path. Surrounding whitespace,
// such as a trailing newline, is removed. The token must be non-empty
// printable ASCII without spaces (the characters an HTTP/2 header value can
// carry unambiguously); the file holds the token only, without the "Bearer"
// scheme. Errors name the file but never include its contents.
func readBearerTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", keyOtelCollectorBearerTokenFile, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBearerTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", keyOtelCollectorBearerTokenFile, path, err)
	}
	if len(data) > maxBearerTokenFileBytes {
		return "", fmt.Errorf("%s %q: file is larger than %d bytes",
			keyOtelCollectorBearerTokenFile, path, maxBearerTokenFileBytes)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%s %q: file is empty", keyOtelCollectorBearerTokenFile, path)
	}
	for i := 0; i < len(token); i++ {
		if c := token[i]; c < 0x21 || c > 0x7e {
			return "", fmt.Errorf("%s %q: token contains whitespace, control or non-ASCII characters; store only the token, without the \"Bearer\" scheme",
				keyOtelCollectorBearerTokenFile, path)
		}
	}
	return token, nil
}

// validateOTLPEndpoint rejects collector addresses carrying a URL scheme.
// The OTLP gRPC exporter is configured with WithEndpoint, which expects a
// bare host:port; a value such as "grpc://host:4317" is accepted at startup
// but every export then fails ("too many colons in address"), leaving the
// process running with no metrics. Failing fast at config load surfaces the
// mistake immediately. TLS is selected by otel_collector_tls_enabled, not by
// an "https://" scheme.
func validateOTLPEndpoint(addr string) error {
	if strings.Contains(addr, "://") {
		return fmt.Errorf("%s must be host:port without a URL scheme (use %s for TLS), got: %q",
			keyOtelCollectorAddr, keyOtelCollectorTLSEnabled, addr)
	}
	return nil
}
