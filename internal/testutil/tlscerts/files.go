package tlscerts

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// FileSet holds the paths of a freshly generated CA plus a server and a
// client leaf certificate signed by it, written to a test temp directory.
// They can be passed to config.ServerTLSConfig/ClientTLSConfig (and so to
// tls.LoadX509KeyPair) exactly as an operator's tls_cert_file, tls_key_file
// and tls_ca_file values would be.
type FileSet struct {
	CAFile         string
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string
}

// WriteFileSet generates a CA, a server leaf (CN "controller", SANs
// "localhost" and 127.0.0.1, server auth) and a client leaf (CN "agent",
// client auth), writes them under t.TempDir() and returns their paths. It
// fails the test on any error.
func WriteFileSet(t testing.TB) FileSet {
	t.Helper()
	dir := t.TempDir()

	ca, err := NewCA()
	if err != nil {
		t.Fatalf("tlscerts.NewCA: %v", err)
	}

	serverCertPEM, serverKeyPEM, err := ca.IssueLeaf(LeafOptions{
		CommonName:  "controller",
		DNSNames:    []string{"localhost"},
		IPs:         []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("IssueLeaf(server): %v", err)
	}
	clientCertPEM, clientKeyPEM, err := ca.IssueLeaf(LeafOptions{
		CommonName:  "agent",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("IssueLeaf(client): %v", err)
	}

	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return path
	}
	return FileSet{
		CAFile:         write("ca.pem", ca.CAPEM()),
		ServerCertFile: write("server-cert.pem", serverCertPEM),
		ServerKeyFile:  write("server-key.pem", serverKeyPEM),
		ClientCertFile: write("client-cert.pem", clientCertPEM),
		ClientKeyFile:  write("client-key.pem", clientKeyPEM),
	}
}
