// Package tlscerts generates short-lived, in-memory self-signed
// certificates for TLS/mTLS tests. Tests that exercise
// internal/config.ServerTLSConfig/ClientTLSConfig and the controller/agent
// gRPC TLS paths need real certificate files, but committing fixture
// certificates would eventually expire and break CI; generating a fresh CA
// and leaf certificates on every test run avoids that entirely.
package tlscerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// validity is deliberately generous (well beyond any single test run) since
// these certificates are generated fresh in-process and never persisted.
const validity = 24 * time.Hour

// CA is an in-memory self-signed certificate authority used to mint leaf
// certificates for TLS/mTLS tests.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewCA generates a fresh self-signed CA certificate and key pair.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rpingmesh-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// CAPEM returns the PEM-encoded CA certificate, suitable for writing to a
// tls_ca_file.
func (ca *CA) CAPEM() []byte {
	return ca.certPEM
}

// LeafOptions configures IssueLeaf.
type LeafOptions struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	// ExtKeyUsage selects server-auth, client-auth, or both, matching how
	// the certificate will be used in the test.
	ExtKeyUsage []x509.ExtKeyUsage
}

// IssueLeaf mints a leaf certificate signed by ca, returning PEM-encoded
// certificate and private key bytes ready to write to tls_cert_file /
// tls_key_file.
func (ca *CA) IssueLeaf(opts LeafOptions) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: opts.CommonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  opts.ExtKeyUsage,
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
