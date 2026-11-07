// Package otlptest runs an in-process OTLP/gRPC metrics receiver for tests of
// the metric exporter. It serves plaintext or TLS and can require a bearer
// token, and it records the Export requests it acknowledged, so a test
// verifies that a request was received and accepted rather than only that an
// exporter could be built.
package otlptest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"

	"github.com/yuuki/rpingmesh/internal/testutil/tlscerts"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Options configures a Collector.
type Options struct {
	// TLS, when non-nil, makes the collector serve TLS with this
	// certificate. Nil serves plaintext gRPC.
	TLS *tls.Certificate
	// BearerToken, when non-empty, makes the collector reject with
	// codes.Unauthenticated every request whose "authorization" metadata is
	// not exactly "Bearer <BearerToken>".
	BearerToken string
}

// Request is one Export request the collector accepted.
type Request struct {
	// Authorization holds the request's "authorization" metadata values.
	Authorization []string
	// Metrics is the request payload.
	Metrics *collectormetricspb.ExportMetricsServiceRequest
}

// ServiceNames returns the service.name of every resource in the request.
func (r Request) ServiceNames() []string {
	var names []string
	for _, rm := range r.Metrics.GetResourceMetrics() {
		for _, kv := range rm.GetResource().GetAttributes() {
			if kv.GetKey() == "service.name" {
				names = append(names, kv.GetValue().GetStringValue())
			}
		}
	}
	return names
}

// Collector is a running OTLP/gRPC metrics receiver.
type Collector struct {
	collectormetricspb.UnimplementedMetricsServiceServer

	addr  string
	token string

	mu       sync.Mutex
	accepted []Request
	rejected int
}

// Start starts a collector on a loopback port. It is stopped when the test
// ends.
func Start(t testing.TB, opts Options) *Collector {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; binding a loopback socket does not block
	if err != nil {
		t.Fatalf("otlptest: listen: %v", err)
	}
	var serverOpts []grpc.ServerOption
	if opts.TLS != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{*opts.TLS},
			MinVersion:   tls.VersionTLS12,
		})))
	}
	srv := grpc.NewServer(serverOpts...)
	c := &Collector{addr: lis.Addr().String(), token: opts.BearerToken}
	collectormetricspb.RegisterMetricsServiceServer(srv, c)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return c
}

// Addr returns the collector's address as 127.0.0.1:port.
func (c *Collector) Addr() string {
	return c.addr
}

// Export implements the OTLP MetricsService.
func (c *Collector) Export(ctx context.Context, req *collectormetricspb.ExportMetricsServiceRequest) (*collectormetricspb.ExportMetricsServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && (len(auth) != 1 || auth[0] != "Bearer "+c.token) {
		c.rejected++
		return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
	}
	c.accepted = append(c.accepted, Request{Authorization: auth, Metrics: req})
	return &collectormetricspb.ExportMetricsServiceResponse{}, nil
}

// Accepted returns the requests accepted so far.
func (c *Collector) Accepted() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Request(nil), c.accepted...)
}

// Rejected returns the number of requests rejected for their bearer token.
func (c *Collector) Rejected() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rejected
}

// ServerCertificate issues a server certificate signed by ca for dnsNames,
// with no IP SANs, so a client dialing 127.0.0.1 must verify one of dnsNames
// through its TLS server name.
func ServerCertificate(t testing.TB, ca *tlscerts.CA, dnsNames ...string) *tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueLeaf(tlscerts.LeafOptions{
		CommonName:  dnsNames[0],
		DNSNames:    dnsNames,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("otlptest: issue server certificate: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("otlptest: load server certificate: %v", err)
	}
	return &cert
}
