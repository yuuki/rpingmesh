package config

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/yuuki/rpingmesh/rebuild/internal/testutil/tlscerts"
)

// testCertSet holds file paths to a freshly generated, in-memory CA plus a
// server and client leaf certificate signed by it -- everything
// ServerTLSConfig/ClientTLSConfig need to build a real *tls.Config in tests,
// without depending on committed fixture certificates that could expire.
type testCertSet struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
}

func newTestCertSet(t *testing.T) testCertSet {
	t.Helper()
	dir := t.TempDir()

	ca, err := tlscerts.NewCA()
	if err != nil {
		t.Fatalf("tlscerts.NewCA: %v", err)
	}
	caFile := writeFile(t, dir, "ca.pem", ca.CAPEM())

	serverCertPEM, serverKeyPEM, err := ca.IssueLeaf(tlscerts.LeafOptions{
		CommonName:  "controller",
		DNSNames:    []string{"localhost"},
		IPs:         []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("IssueLeaf(server): %v", err)
	}
	clientCertPEM, clientKeyPEM, err := ca.IssueLeaf(tlscerts.LeafOptions{
		CommonName:  "agent",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("IssueLeaf(client): %v", err)
	}

	return testCertSet{
		caFile:         caFile,
		serverCertFile: writeFile(t, dir, "server-cert.pem", serverCertPEM),
		serverKeyFile:  writeFile(t, dir, "server-key.pem", serverKeyPEM),
		clientCertFile: writeFile(t, dir, "client-cert.pem", clientCertPEM),
		clientKeyFile:  writeFile(t, dir, "client-key.pem", clientKeyPEM),
	}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}

// --- ServerTLSConfig ---

func TestServerTLSConfig_Disabled(t *testing.T) {
	cfg, err := ServerTLSConfig(TLSModeDisabled, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("cfg = %+v, want nil for disabled mode", cfg)
	}
}

func TestServerTLSConfig_TLS_LoadsCertificate(t *testing.T) {
	certs := newTestCertSet(t)

	cfg, err := ServerTLSConfig(TLSModeTLS, certs.serverCertFile, certs.serverKeyFile, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert for tls mode", cfg.ClientAuth)
	}
}

func TestServerTLSConfig_TLS_MissingCertFile(t *testing.T) {
	certs := newTestCertSet(t)

	if _, err := ServerTLSConfig(TLSModeTLS, filepath.Join(t.TempDir(), "missing.pem"), certs.serverKeyFile, ""); err == nil {
		t.Fatal("expected an error for a missing server certificate file, got nil")
	}
}

func TestServerTLSConfig_MTLS_SetsClientCAsAndRequiresClientCert(t *testing.T) {
	certs := newTestCertSet(t)

	cfg, err := ServerTLSConfig(TLSModeMTLS, certs.serverCertFile, certs.serverKeyFile, certs.caFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs = nil, want a populated CertPool for mtls mode")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert for mtls mode", cfg.ClientAuth)
	}
}

func TestServerTLSConfig_MTLS_MissingCAFile(t *testing.T) {
	certs := newTestCertSet(t)

	if _, err := ServerTLSConfig(TLSModeMTLS, certs.serverCertFile, certs.serverKeyFile, filepath.Join(t.TempDir(), "missing-ca.pem")); err == nil {
		t.Fatal("expected an error for a missing CA file, got nil")
	}
}

func TestServerTLSConfig_UnknownMode(t *testing.T) {
	if _, err := ServerTLSConfig("bogus", "", "", ""); err == nil {
		t.Fatal("expected an error for an unknown tls_mode, got nil")
	}
}

// --- ClientTLSConfig ---

func TestClientTLSConfig_Disabled(t *testing.T) {
	cfg, err := ClientTLSConfig(TLSModeDisabled, "", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("cfg = %+v, want nil for disabled mode", cfg)
	}
}

func TestClientTLSConfig_TLS_SetsRootCAs(t *testing.T) {
	certs := newTestCertSet(t)

	cfg, err := ClientTLSConfig(TLSModeTLS, "", "", certs.caFile, "controller.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs = nil, want a populated CertPool for tls mode")
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("Certificates = %d, want 0 (client presents no cert in tls mode)", len(cfg.Certificates))
	}
	if cfg.ServerName != "controller.example" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "controller.example")
	}
}

func TestClientTLSConfig_TLS_MissingCAFile(t *testing.T) {
	if _, err := ClientTLSConfig(TLSModeTLS, "", "", filepath.Join(t.TempDir(), "missing-ca.pem"), ""); err == nil {
		t.Fatal("expected an error for a missing CA file, got nil")
	}
}

func TestClientTLSConfig_MTLS_SetsCertificateAndRootCAs(t *testing.T) {
	certs := newTestCertSet(t)

	cfg, err := ClientTLSConfig(TLSModeMTLS, certs.clientCertFile, certs.clientKeyFile, certs.caFile, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs = nil, want a populated CertPool for mtls mode")
	}
}

func TestClientTLSConfig_MTLS_MissingClientCert(t *testing.T) {
	certs := newTestCertSet(t)

	if _, err := ClientTLSConfig(TLSModeMTLS, filepath.Join(t.TempDir(), "missing.pem"), certs.clientKeyFile, certs.caFile, ""); err == nil {
		t.Fatal("expected an error for a missing client certificate file, got nil")
	}
}

func TestClientTLSConfig_UnknownMode(t *testing.T) {
	if _, err := ClientTLSConfig("bogus", "", "", "", ""); err == nil {
		t.Fatal("expected an error for an unknown tls_mode, got nil")
	}
}
