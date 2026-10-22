package config

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/yuuki/rpingmesh/internal/testutil/tlscerts"
)

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
	certs := tlscerts.WriteFileSet(t)

	cfg, err := ServerTLSConfig(TLSModeTLS, certs.ServerCertFile, certs.ServerKeyFile, "")
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
	certs := tlscerts.WriteFileSet(t)

	if _, err := ServerTLSConfig(TLSModeTLS, filepath.Join(t.TempDir(), "missing.pem"), certs.ServerKeyFile, ""); err == nil {
		t.Fatal("expected an error for a missing server certificate file, got nil")
	}
}

func TestServerTLSConfig_MTLS_SetsClientCAsAndRequiresClientCert(t *testing.T) {
	certs := tlscerts.WriteFileSet(t)

	cfg, err := ServerTLSConfig(TLSModeMTLS, certs.ServerCertFile, certs.ServerKeyFile, certs.CAFile)
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
	certs := tlscerts.WriteFileSet(t)

	if _, err := ServerTLSConfig(TLSModeMTLS, certs.ServerCertFile, certs.ServerKeyFile, filepath.Join(t.TempDir(), "missing-ca.pem")); err == nil {
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
	certs := tlscerts.WriteFileSet(t)

	cfg, err := ClientTLSConfig(TLSModeTLS, "", "", certs.CAFile, "controller.example")
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
	certs := tlscerts.WriteFileSet(t)

	cfg, err := ClientTLSConfig(TLSModeMTLS, certs.ClientCertFile, certs.ClientKeyFile, certs.CAFile, "")
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
	certs := tlscerts.WriteFileSet(t)

	if _, err := ClientTLSConfig(TLSModeMTLS, filepath.Join(t.TempDir(), "missing.pem"), certs.ClientKeyFile, certs.CAFile, ""); err == nil {
		t.Fatal("expected an error for a missing client certificate file, got nil")
	}
}

func TestClientTLSConfig_UnknownMode(t *testing.T) {
	if _, err := ClientTLSConfig("bogus", "", "", "", ""); err == nil {
		t.Fatal("expected an error for an unknown tls_mode, got nil")
	}
}
