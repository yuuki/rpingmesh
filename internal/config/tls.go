package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// TLS modes for controller-agent gRPC communication.
//
//   - TLSModeDisabled (the default) preserves the original plaintext gRPC
//     behavior for backward compatibility.
//   - TLSModeTLS authenticates the server only (the client verifies the
//     controller's certificate but presents none of its own).
//   - TLSModeMTLS additionally requires and verifies a client certificate,
//     mutually authenticating both ends.
const (
	TLSModeDisabled = "disabled"
	TLSModeTLS      = "tls"
	TLSModeMTLS     = "mtls"
)

// TLSClientConfig carries the TLS settings a gRPC client (the agent, dialing
// the controller) needs to build its transport credentials. A nil
// *TLSClientConfig, or one with Mode == TLSModeDisabled (or the empty
// string), means "use insecure/plaintext credentials" -- the pre-existing
// default behavior.
type TLSClientConfig struct {
	Mode       string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// tlsRole distinguishes which certificate files validateTLSFiles requires
// for a given mode: TLSModeTLS has different requirements on the server
// side (must present a certificate/key) than on the client side (only needs
// a CA to verify the server), while TLSModeMTLS requires all three files on
// both sides.
type tlsRole int

const (
	tlsRoleServer tlsRole = iota
	tlsRoleClient
)

// String names the role as it appears in error messages.
func (r tlsRole) String() string {
	if r == tlsRoleServer {
		return "server"
	}
	return "client"
}

// errUnknownTLSMode is the error every entry point returns for a tls_mode
// outside the accepted set.
func errUnknownTLSMode(mode string) error {
	return fmt.Errorf("tls_mode must be one of %q, %q, or %q, got %q", TLSModeDisabled, TLSModeTLS, TLSModeMTLS, mode)
}

// validateTLSFiles fails fast at config-load time if the certificate files
// required by mode (for the given role) are missing or unreadable, rather
// than deferring the failure to the first TLS handshake attempt.
func validateTLSFiles(role tlsRole, mode, certFile, keyFile, caFile string) error {
	switch mode {
	case TLSModeDisabled, "":
		return nil
	case TLSModeTLS:
		if role == tlsRoleServer {
			if err := requireTLSFile("tls_cert_file", certFile); err != nil {
				return err
			}
			return requireTLSFile("tls_key_file", keyFile)
		}
		// Client role: no certificate of its own to present, only a CA to
		// verify the server's certificate against.
		return requireTLSFile("tls_ca_file", caFile)
	case TLSModeMTLS:
		// Both roles need all three files: the server verifies the client's
		// certificate against the CA (and vice versa), and both present a
		// certificate/key of their own.
		if err := requireTLSFile("tls_ca_file", caFile); err != nil {
			return err
		}
		if err := requireTLSFile("tls_cert_file", certFile); err != nil {
			return err
		}
		return requireTLSFile("tls_key_file", keyFile)
	default:
		return errUnknownTLSMode(mode)
	}
}

// requireTLSFile returns an error if path is empty or does not name a file
// that can be stat'd, naming field in the error so the operator knows which
// config key to fix.
func requireTLSFile(field, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s is required for the configured tls_mode", field)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s %q: %w", field, path, err)
	}
	return nil
}

// ServerTLSConfig builds the *tls.Config a gRPC server should use for the
// given mode. It returns (nil, nil) for TLSModeDisabled (and the empty
// string), signaling the caller to fall back to grpc.NewServer's default of
// no transport security.
func ServerTLSConfig(mode, certFile, keyFile, caFile string) (*tls.Config, error) {
	switch mode {
	case TLSModeDisabled, "":
		return nil, nil
	case TLSModeTLS:
		cert, err := loadKeyPair(tlsRoleServer, certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	case TLSModeMTLS:
		cert, err := loadKeyPair(tlsRoleServer, certFile, keyFile)
		if err != nil {
			return nil, err
		}
		caPool, err := loadCACertPool(caFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}, nil
	default:
		return nil, errUnknownTLSMode(mode)
	}
}

// ClientTLSConfig builds the *tls.Config a gRPC client should use for the
// given mode. It returns (nil, nil) for TLSModeDisabled (and the empty
// string), signaling the caller to fall back to insecure credentials.
// serverName overrides the name used for both SNI and certificate
// verification; leave it empty to let the TLS stack derive it from the dial
// target, which is the common case when controller_addr is a DNS name
// matching the server certificate. InsecureSkipVerify is deliberately never
// set here: use tls_server_name to handle IP-literal controller_addr values
// instead of disabling verification.
func ClientTLSConfig(mode, certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	switch mode {
	case TLSModeDisabled, "":
		return nil, nil
	case TLSModeTLS:
		caPool, err := loadCACertPool(caFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			RootCAs:    caPool,
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}, nil
	case TLSModeMTLS:
		cert, err := loadKeyPair(tlsRoleClient, certFile, keyFile)
		if err != nil {
			return nil, err
		}
		caPool, err := loadCACertPool(caFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
			ServerName:   serverName,
			MinVersion:   tls.VersionTLS12,
		}, nil
	default:
		return nil, errUnknownTLSMode(mode)
	}
}

// loadKeyPair loads the PEM certificate/key pair a role presents, naming the
// role in the error so an operator can tell which binary's files are wrong.
func loadKeyPair(role tlsRole, certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load %s certificate/key: %w", role, err)
	}
	return cert, nil
}

// loadCACertPool reads and parses a PEM-encoded CA bundle from caFile.
func loadCACertPool(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read tls_ca_file %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("failed to parse any PEM certificates from tls_ca_file %q", caFile)
	}
	return pool, nil
}
