package controller

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/internal/testutil/tlscerts"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// This file exercises the controller-agent gRPC mTLS path (P1-B) end to
// end: a real ControllerService served over a real TCP listener with TLS
// transport credentials, dialed by the actual GRPCControllerClient used by
// agents. It deliberately avoids rqlite and docker: the registry is the
// same in-memory fakeRegistry used by service_test.go, and certificates are
// generated fresh in-process via internal/testutil/tlscerts, so this test
// runs anywhere "go test" does.

// mtlsFixture bundles a freshly generated CA plus server and client leaf
// certificates, written to temp files so they can be passed to
// config.ServerTLSConfig/ClientTLSConfig (and, transitively,
// tls.LoadX509KeyPair) exactly as an operator's tls_cert_file/tls_key_file/
// tls_ca_file config values would be.
type mtlsFixture struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
}

func newMTLSFixture(t *testing.T) mtlsFixture {
	t.Helper()
	dir := t.TempDir()

	ca, err := tlscerts.NewCA()
	if err != nil {
		t.Fatalf("tlscerts.NewCA: %v", err)
	}

	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	serverCertPEM, serverKeyPEM, err := ca.IssueLeaf(tlscerts.LeafOptions{
		CommonName:  "controller",
		DNSNames:    []string{"localhost"},
		IPs:         []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("issue server leaf certificate: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := ca.IssueLeaf(tlscerts.LeafOptions{
		CommonName:  "agent",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("issue client leaf certificate: %v", err)
	}

	return mtlsFixture{
		caFile:         write("ca.pem", ca.CAPEM()),
		serverCertFile: write("server-cert.pem", serverCertPEM),
		serverKeyFile:  write("server-key.pem", serverKeyPEM),
		clientCertFile: write("client-cert.pem", clientCertPEM),
		clientKeyFile:  write("client-key.pem", clientKeyPEM),
	}
}

// startMTLSController starts a real ControllerService -- backed by the
// in-memory fakeRegistry from service_test.go, not rqlite -- on a real TCP
// listener with mTLS server credentials built from fixture via the same
// config.ServerTLSConfig helper cmd/controller/main.go uses. It returns the
// listener address; the server is stopped via t.Cleanup.
func startMTLSController(t *testing.T, fixture mtlsFixture) string {
	t.Helper()

	svc := newTestService(&fakeRegistry{})

	tlsConfig, err := config.ServerTLSConfig(config.TLSModeMTLS, fixture.serverCertFile, fixture.serverKeyFile, fixture.caFile)
	if err != nil {
		t.Fatalf("config.ServerTLSConfig: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	controller_agent.RegisterControllerServiceServer(grpcServer, svc)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go grpcServer.Serve(lis)
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String()
}

// TestMTLS_ClientWithCertificate_Succeeds verifies that an agent-side
// GRPCControllerClient configured with tls_mode=mtls and a certificate
// signed by the same CA the controller trusts can complete
// RegisterAgent/GetPinglist over a real TCP + TLS connection.
func TestMTLS_ClientWithCertificate_Succeeds(t *testing.T) {
	fixture := newMTLSFixture(t)
	addr := startMTLSController(t, fixture)

	client, err := controller_client.NewGRPCControllerClient(addr, &config.TLSClientConfig{
		Mode:     config.TLSModeMTLS,
		CertFile: fixture.clientCertFile,
		KeyFile:  fixture.clientKeyFile,
		CAFile:   fixture.caFile,
		// The dial target is an IP:port (net.Listen("tcp", "127.0.0.1:0")),
		// so the authority gRPC would otherwise derive for verification is
		// "127.0.0.1" -- not a name the server certificate carries. Setting
		// ServerName explicitly to a SAN the certificate does carry is
		// exactly the tls_server_name escape hatch described in the README.
		ServerName: "localhost",
	})
	if err != nil {
		t.Fatalf("NewGRPCControllerClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.RegisterAgent(ctx, &controller_agent.AgentRegistrationRequest{
		AgentId: "mtls-agent-1",
		TorId:   "tor-1",
		Rnics: []*controller_agent.RnicInfo{
			{Gid: "fe80::1", Qpn: 100, IpAddress: "10.0.0.1", DeviceName: "mlx5_0"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterAgent over mtls: %v", err)
	}
	if !resp.GetSuccess() {
		t.Fatalf("RegisterAgent rejected: %s", resp.GetMessage())
	}

	if _, err := client.GetPinglist(ctx, "mtls-agent-1", "tor-1", "fe80::1", controller_agent.PinglistType_TOR_MESH); err != nil {
		t.Fatalf("GetPinglist over mtls: %v", err)
	}
}

// TestMTLS_ClientWithoutCertificate_Rejected verifies that a client dialing
// the same mtls-configured controller without presenting a client
// certificate (tls_mode=tls: it verifies the server but presents none of
// its own) is rejected, proving the server's
// tls.RequireAndVerifyClientCert is actually enforced rather than silently
// accepting anonymous connections.
func TestMTLS_ClientWithoutCertificate_Rejected(t *testing.T) {
	fixture := newMTLSFixture(t)
	addr := startMTLSController(t, fixture)

	client, err := controller_client.NewGRPCControllerClient(addr, &config.TLSClientConfig{
		Mode:       config.TLSModeTLS, // verifies the server; presents no client certificate
		CAFile:     fixture.caFile,
		ServerName: "localhost",
	})
	if err != nil {
		t.Fatalf("NewGRPCControllerClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.RegisterAgent(ctx, &controller_agent.AgentRegistrationRequest{
		AgentId: "no-cert-agent",
		TorId:   "tor-1",
	})
	if err == nil {
		t.Fatal("expected RegisterAgent to fail for a client presenting no certificate against an mtls controller, got nil")
	}
	t.Logf("client without a certificate was correctly rejected: %v", err)
}

// TestMTLS_PlaintextClient_Rejected verifies that a plaintext (tls_mode
// disabled) client cannot talk to an mtls-configured controller: dialing
// with insecure credentials against a TLS listener must fail, not silently
// downgrade.
func TestMTLS_PlaintextClient_Rejected(t *testing.T) {
	fixture := newMTLSFixture(t)
	addr := startMTLSController(t, fixture)

	client, err := controller_client.NewGRPCControllerClient(addr, nil) // nil => insecure/plaintext
	if err != nil {
		t.Fatalf("NewGRPCControllerClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.RegisterAgent(ctx, &controller_agent.AgentRegistrationRequest{
		AgentId: "plaintext-agent",
		TorId:   "tor-1",
	})
	if err == nil {
		t.Fatal("expected RegisterAgent to fail for a plaintext client against an mtls controller, got nil")
	}
	t.Logf("plaintext client was correctly rejected: %v", err)
}
