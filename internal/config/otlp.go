package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	keyOtelCollectorBearerTokenFile = "otel_collector_bearer_token_file" //nolint:gosec // G101: a config key name, not a credential
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
// which is never sent over plaintext), an authorization header in the
// OpenTelemetry environment variables that would be sent over plaintext or
// next to the token file's token, an unreadable or unparsable CA bundle, and
// a relative, unreadable, empty or malformed token file. Errors name the
// configuration key and the file but never include the token.
func (c OTLPExporterConfig) Credentials() (*tls.Config, string, error) {
	if err := validateOTLPEndpoint(c.Endpoint); err != nil {
		return nil, "", err
	}
	if err := c.rejectEnvAuthorizationHeader(); err != nil {
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

// otlpHeaderEnvVars are the OpenTelemetry SDK environment variables whose
// headers the exporter attaches to every export request, in addition to the
// settings of OTLPExporterConfig.
var otlpHeaderEnvVars = []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_METRICS_HEADERS"}

// rejectEnvAuthorizationHeader refuses an authorization header set through
// otlpHeaderEnvVars when it would be sent over plaintext, or next to the
// token of otel_collector_bearer_token_file (the request would carry two
// authorization values). The exporter honors those variables, so without
// this check a credential set there would bypass the rule that no token is
// sent over plaintext. Other headers, such as a tenant ID, are left alone,
// and so is an authorization header over TLS without a token file.
func (c OTLPExporterConfig) rejectEnvAuthorizationHeader() error {
	name, ok := envAuthorizationHeader()
	switch {
	case !ok:
		return nil
	case !c.TLSEnabled:
		return fmt.Errorf("%s sets an authorization header, which would be sent over plaintext; set %s: true, and preferably move the token to %s",
			name, keyOtelCollectorTLSEnabled, keyOtelCollectorBearerTokenFile)
	case c.BearerTokenFile != "":
		return fmt.Errorf("%s sets an authorization header in addition to %s; remove one of them",
			name, keyOtelCollectorBearerTokenFile)
	default:
		return nil
	}
}

// envAuthorizationHeader returns the first of otlpHeaderEnvVars that sets an
// authorization header. It splits the value as the OpenTelemetry SDK does,
// into comma-separated key=value pairs with space-trimmed keys, and compares
// keys case-insensitively because gRPC lower-cases metadata keys.
func envAuthorizationHeader() (string, bool) {
	for _, name := range otlpHeaderEnvVars {
		for _, pair := range strings.Split(os.Getenv(name), ",") {
			key, _, found := strings.Cut(pair, "=")
			if found && strings.EqualFold(strings.TrimSpace(key), "authorization") {
				return name, true
			}
		}
	}
	return "", false
}

// readBearerTokenFile reads a bearer token from path. Surrounding whitespace,
// such as a trailing newline, is removed. The token must be non-empty
// printable ASCII without spaces (the characters an HTTP/2 header value can
// carry unambiguously); the file holds the token only, without the "Bearer"
// scheme. Errors name the file but never include its contents.
//
// path must be absolute. A relative value is rejected without being echoed:
// it is most likely the token itself, put in the path key by mistake, and
// echoing it would print the secret.
func readBearerTokenFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path (the value is not shown, in case it is the token itself)",
			keyOtelCollectorBearerTokenFile)
	}
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
