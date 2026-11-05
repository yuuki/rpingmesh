package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/testutil/otlptest"
	"github.com/yuuki/rpingmesh/internal/testutil/tlscerts"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// testCollectorName is the only name in the test collector's
	// certificate. The collector listens on 127.0.0.1, so a client must set
	// it as the TLS server name to pass verification.
	testCollectorName = "collector.test"
	testBearerToken   = "otlp-test-token-0123456789"
)

// tlsFixture holds a collector certificate and the CA bundles a client may
// be configured with.
type tlsFixture struct {
	cert            *tls.Certificate
	caFile          string // the CA that signed cert
	untrustedCAFile string // an unrelated CA
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()
	ca, err := tlscerts.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	other, err := tlscerts.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return tlsFixture{
		cert:            otlptest.ServerCertificate(t, ca, testCollectorName),
		caFile:          writeTestFile(t, "ca.pem", string(ca.CAPEM()), 0o644),
		untrustedCAFile: writeTestFile(t, "untrusted-ca.pem", string(other.CAPEM()), 0o644),
	}
}

// tlsConfig returns an exporter configuration that trusts the fixture's CA
// and verifies the collector as testCollectorName.
func (f tlsFixture) tlsConfig(addr string) config.OTLPExporterConfig {
	return config.OTLPExporterConfig{
		Endpoint:   addr,
		TLSEnabled: true,
		CAFile:     f.caFile,
		ServerName: testCollectorName,
	}
}

func writeTestFile(t *testing.T, name, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// testResourceMetrics is one export batch with a single counter point.
func testResourceMetrics() *metricdata.ResourceMetrics {
	return &metricdata.ResourceMetrics{
		Resource: resource.NewSchemaless(attribute.String("service.name", "otlp-exporter-test")),
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Scope: instrumentation.Scope{Name: "otlp-exporter-test"},
			Metrics: []metricdata.Metrics{{
				Name: "test.exports",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints:  []metricdata.DataPoint[int64]{{Value: 1}},
				},
			}},
		}},
	}
}

// exportOnce sends one Export request through an exporter built from cfg.
// Retries are disabled so a refused connection or a rejected request fails
// at once instead of backing off until the deadline.
func exportOnce(t *testing.T, cfg config.OTLPExporterConfig) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp, err := newOTLPExporter(ctx, cfg, otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{Enabled: false}))
	if err != nil {
		t.Fatalf("newOTLPExporter: %v", err)
	}
	defer func() { _ = exp.Shutdown(context.Background()) }()
	return exp.Export(ctx, testResourceMetrics())
}

// TestOTLPExport_PlaintextWithoutAuth pins the pre-existing default: without
// TLS or token settings the exporter speaks plaintext gRPC, its request is
// accepted, and it carries no authorization metadata.
func TestOTLPExport_PlaintextWithoutAuth(t *testing.T) {
	collector := otlptest.Start(t, otlptest.Options{})

	if err := exportOnce(t, config.OTLPExporterConfig{Endpoint: collector.Addr()}); err != nil {
		t.Fatalf("Export over plaintext: %v", err)
	}
	reqs := collector.Accepted()
	if len(reqs) != 1 {
		t.Fatalf("collector accepted %d requests, want 1", len(reqs))
	}
	if len(reqs[0].Authorization) != 0 {
		t.Errorf("authorization metadata = %q, want none", reqs[0].Authorization)
	}
}

// TestOTLPExport_TLSWithCustomCAAndServerName verifies a TLS export to a
// collector whose certificate is signed by a private CA and names a host
// other than the address dialed.
func TestOTLPExport_TLSWithCustomCAAndServerName(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{TLS: fx.cert})

	if err := exportOnce(t, fx.tlsConfig(collector.Addr())); err != nil {
		t.Fatalf("Export over TLS: %v", err)
	}
	if n := len(collector.Accepted()); n != 1 {
		t.Fatalf("collector accepted %d requests, want 1", n)
	}
}

// TestOTLPExport_TLSRejectsUnverifiedCollector verifies that the exporter
// refuses a collector whose certificate chain or host name does not verify:
// no request reaches the collector.
func TestOTLPExport_TLSRejectsUnverifiedCollector(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{TLS: fx.cert})

	tests := []struct {
		name    string
		mutate  func(*config.OTLPExporterConfig)
		wantErr string
	}{
		{
			name:    "untrusted CA",
			mutate:  func(c *config.OTLPExporterConfig) { c.CAFile = fx.untrustedCAFile },
			wantErr: "certificate signed by unknown authority",
		},
		{
			// Without a CA file the system roots apply, and they do not
			// contain the test CA.
			name:    "system roots",
			mutate:  func(c *config.OTLPExporterConfig) { c.CAFile = "" },
			wantErr: "x509:",
		},
		{
			name:    "server name mismatch",
			mutate:  func(c *config.OTLPExporterConfig) { c.ServerName = "other.test" },
			wantErr: "not other.test",
		},
		{
			// The host of the endpoint, 127.0.0.1, is not in the
			// certificate.
			name:    "endpoint host without server name",
			mutate:  func(c *config.OTLPExporterConfig) { c.ServerName = "" },
			wantErr: "doesn't contain any IP SANs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fx.tlsConfig(collector.Addr())
			tt.mutate(&cfg)
			err := exportOnce(t, cfg)
			if err == nil {
				t.Fatal("Export succeeded, want a TLS verification error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
	if n := len(collector.Accepted()); n != 0 {
		t.Errorf("collector accepted %d requests, want 0", n)
	}
}

// TestOTLPExport_TLSNeverFallsBackToPlaintext verifies that a TLS exporter
// does not reach a plaintext collector, even when the OTLP environment
// variables ask for an insecure connection.
func TestOTLPExport_TLSNeverFallsBackToPlaintext(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{})
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_INSECURE", "true")

	err := exportOnce(t, fx.tlsConfig(collector.Addr()))
	if err == nil || !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("TLS export to a plaintext collector: %v, want a TLS handshake error", err)
	}
	if n := len(collector.Accepted()); n != 0 {
		t.Errorf("plaintext collector accepted %d requests, want 0", n)
	}
}

// TestOTLPExport_BearerToken verifies against a collector that requires a
// bearer token that the configured token is accepted, and that a missing or
// wrong token is rejected, without the tokens appearing in the errors.
func TestOTLPExport_BearerToken(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{TLS: fx.cert, BearerToken: testBearerToken})
	const wrongToken = "wrong-token-9876543210"

	tests := []struct {
		name      string
		tokenFile string
		wantCode  codes.Code
	}{
		// The trailing newline of a token file written by echo is ignored.
		{"correct token", writeTestFile(t, "token", testBearerToken+"\n", 0o600), codes.OK},
		{"no token", "", codes.Unauthenticated},
		{"wrong token", writeTestFile(t, "token", wrongToken, 0o600), codes.Unauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fx.tlsConfig(collector.Addr())
			cfg.BearerTokenFile = tt.tokenFile
			err := exportOnce(t, cfg)
			if got := status.Code(err); got != tt.wantCode {
				t.Fatalf("Export: code %v (%v), want %v", got, err, tt.wantCode)
			}
			if err != nil {
				for _, secret := range []string{testBearerToken, wrongToken} {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("error %q reveals a token", err)
					}
				}
			}
		})
	}

	reqs := collector.Accepted()
	if len(reqs) != 1 {
		t.Fatalf("collector accepted %d requests, want 1", len(reqs))
	}
	if want := []string{"Bearer " + testBearerToken}; !slices.Equal(reqs[0].Authorization, want) {
		t.Errorf("authorization metadata = %q, want %q", reqs[0].Authorization, want)
	}
	if got := collector.Rejected(); got != 2 {
		t.Errorf("collector rejected %d requests, want 2", got)
	}
}

// TestOTLPExporterOptions_RejectsTokenWithoutTLS verifies both guards against
// sending the token over plaintext: the configuration is refused, and the
// credentials themselves make a plaintext client fail to build.
func TestOTLPExporterOptions_RejectsTokenWithoutTLS(t *testing.T) {
	cfg := config.OTLPExporterConfig{
		Endpoint:        "127.0.0.1:1",
		BearerTokenFile: writeTestFile(t, "token", testBearerToken, 0o600),
	}
	_, err := otlpExporterOptions(cfg)
	if err == nil || !strings.Contains(err.Error(), "otel_collector_tls_enabled") {
		t.Fatalf("otlpExporterOptions = %v, want an error naming otel_collector_tls_enabled", err)
	}
	if strings.Contains(err.Error(), testBearerToken) {
		t.Errorf("error %q reveals the token", err)
	}

	_, err = otlpmetricgrpc.New(context.Background(),
		otlpmetricgrpc.WithEndpoint("127.0.0.1:1"),
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithDialOption(grpc.WithPerRPCCredentials(bearerTokenCredentials{token: testBearerToken})))
	if err == nil || !strings.Contains(err.Error(), "transport level security") {
		t.Errorf("plaintext exporter with bearer credentials: %v, want a transport security error", err)
	}
}

// TestNewMeterProvider_InvalidSettingsFail verifies that invalid TLS or token
// settings fail provider construction instead of yielding a plaintext or
// unauthenticated exporter.
func TestNewMeterProvider_InvalidSettingsFail(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.OTLPExporterConfig
		wantErr string
	}{
		{
			name: "CA file is not PEM",
			cfg: config.OTLPExporterConfig{
				Endpoint: "127.0.0.1:1", TLSEnabled: true,
				CAFile: writeTestFile(t, "ca.pem", "not a certificate", 0o644),
			},
			wantErr: "failed to parse any PEM certificates from otel_collector_tls_ca_file",
		},
		{
			name: "token file missing",
			cfg: config.OTLPExporterConfig{
				Endpoint: "127.0.0.1:1", TLSEnabled: true,
				BearerTokenFile: filepath.Join(t.TempDir(), "missing-token"),
			},
			wantErr: "no such file or directory",
		},
		{
			name: "token without TLS",
			cfg: config.OTLPExporterConfig{
				Endpoint:        "127.0.0.1:1",
				BearerTokenFile: writeTestFile(t, "token", testBearerToken, 0o600),
			},
			wantErr: "otel_collector_bearer_token_file requires otel_collector_tls_enabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewMeterProvider(context.Background(), tt.cfg, "rpingmesh-test")
			if err == nil {
				_ = provider.Shutdown(context.Background())
				t.Fatal("NewMeterProvider succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestOTLPExport_EnvAuthorizationHeaderNotSentOverPlaintext verifies that an
// authorization header set through OTEL_EXPORTER_OTLP_HEADERS, which the
// exporter would otherwise attach to every request, does not reach a
// plaintext collector: building the exporter fails.
func TestOTLPExport_EnvAuthorizationHeaderNotSentOverPlaintext(t *testing.T) {
	collector := otlptest.Start(t, otlptest.Options{})
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%20"+testBearerToken)

	_, err := NewMeterProvider(context.Background(), config.OTLPExporterConfig{Endpoint: collector.Addr()}, "rpingmesh-test")
	if err == nil || !strings.Contains(err.Error(), "would be sent over plaintext") {
		t.Fatalf("NewMeterProvider = %v, want an error about plaintext", err)
	}
	if strings.Contains(err.Error(), testBearerToken) {
		t.Errorf("error %q reveals the token", err)
	}
	if n := len(collector.Accepted()); n != 0 {
		t.Errorf("collector accepted %d requests, want 0", n)
	}
}

// captureLogs redirects the global zerolog logger, from which the telemetry
// loggers derive, to a buffer until the test ends.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

// TestOTLPExport_TokenNeverLogged exports through both the agent's and the
// analyzer's paths, with a token file other users can read and with a
// private one, and checks the logs: the token never appears, the
// world-readable file draws a warning naming the file, the private one none.
func TestOTLPExport_TokenNeverLogged(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{TLS: fx.cert, BearerToken: testBearerToken})

	for _, tc := range []struct {
		name     string
		perm     os.FileMode
		wantWarn bool
	}{
		{"world-readable", 0o644, true},
		{"private", 0o600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			cfg := fx.tlsConfig(collector.Addr())
			cfg.BearerTokenFile = writeTestFile(t, "token", testBearerToken+"\n", tc.perm)
			// os.WriteFile applies the umask; set the mode explicitly.
			if err := os.Chmod(cfg.BearerTokenFile, tc.perm); err != nil {
				t.Fatal(err)
			}

			mc, err := NewMetricsCollector(context.Background(), cfg)
			if err != nil {
				t.Fatalf("NewMetricsCollector: %v", err)
			}
			flushOne(t, mc.meterProvider)
			if err := mc.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
			provider, err := NewMeterProvider(context.Background(), cfg, "rpingmesh-analyzer")
			if err != nil {
				t.Fatalf("NewMeterProvider: %v", err)
			}
			flushOne(t, provider)
			if err := provider.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}

			out := logs.String()
			if strings.Contains(out, testBearerToken) {
				t.Errorf("logs reveal the token:\n%s", out)
			}
			if !strings.Contains(out, `"collector_bearer_auth":true`) {
				t.Errorf("logs do not report bearer authentication:\n%s", out)
			}
			warned := strings.Contains(out, "accessible to other users")
			if warned != tc.wantWarn {
				t.Errorf("permission warning logged = %v, want %v:\n%s", warned, tc.wantWarn, out)
			}
			if warned && !strings.Contains(out, cfg.BearerTokenFile) {
				t.Errorf("permission warning does not name the file:\n%s", out)
			}
		})
	}
}

// TestBearerTokenCredentials verifies the metadata the credentials attach,
// that they require transport security, and that formatting them does not
// reveal the token.
func TestBearerTokenCredentials(t *testing.T) {
	creds := bearerTokenCredentials{token: testBearerToken}
	md, err := creds.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	if got, want := md["authorization"], "Bearer "+testBearerToken; got != want {
		t.Errorf("authorization = %q, want %q", got, want)
	}
	if !creds.RequireTransportSecurity() {
		t.Error("RequireTransportSecurity() = false, want true")
	}
	if s := fmt.Sprintf("%v %+v %#v %s", creds, creds, creds, creds); strings.Contains(s, testBearerToken) {
		t.Errorf("formatted credentials %q reveal the token", s)
	}
}

// flushOne records one counter point on provider and flushes it.
func flushOne(t *testing.T, provider *sdkmetric.MeterProvider) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	counter, err := provider.Meter("otlp-exporter-test").Int64Counter("test.exports")
	if err != nil {
		t.Fatalf("Int64Counter: %v", err)
	}
	counter.Add(ctx, 1)
	if err := provider.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
}

// checkAuthenticatedExport asserts that the collector accepted at least one
// request, carrying the bearer token and the given service.name.
func checkAuthenticatedExport(t *testing.T, collector *otlptest.Collector, serviceName string) {
	t.Helper()
	reqs := collector.Accepted()
	if len(reqs) == 0 {
		t.Fatal("collector accepted no requests")
	}
	if want := []string{"Bearer " + testBearerToken}; !slices.Equal(reqs[0].Authorization, want) {
		t.Errorf("authorization metadata = %q, want %q", reqs[0].Authorization, want)
	}
	if got := reqs[0].ServiceNames(); !slices.Equal(got, []string{serviceName}) {
		t.Errorf("service.name = %q, want %q", got, serviceName)
	}
}

// TestNewMeterProvider_TLSBearerExport covers the controller analyzer's path
// (NewMeterProvider with service.name=rpingmesh-analyzer) to a collector that
// requires TLS and a bearer token.
func TestNewMeterProvider_TLSBearerExport(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{TLS: fx.cert, BearerToken: testBearerToken})
	cfg := fx.tlsConfig(collector.Addr())
	cfg.BearerTokenFile = writeTestFile(t, "token", testBearerToken, 0o400)

	provider, err := NewMeterProvider(context.Background(), cfg, "rpingmesh-analyzer")
	if err != nil {
		t.Fatalf("NewMeterProvider: %v", err)
	}
	defer func() { _ = provider.Shutdown(context.Background()) }()

	flushOne(t, provider)
	checkAuthenticatedExport(t, collector, "rpingmesh-analyzer")
}

// TestNewMetricsCollector_TLSBearerExport covers the agent's path
// (NewMetricsCollector) to a collector that requires TLS and a bearer token.
func TestNewMetricsCollector_TLSBearerExport(t *testing.T) {
	fx := newTLSFixture(t)
	collector := otlptest.Start(t, otlptest.Options{TLS: fx.cert, BearerToken: testBearerToken})
	cfg := fx.tlsConfig(collector.Addr())
	cfg.BearerTokenFile = writeTestFile(t, "token", testBearerToken, 0o400)

	mc, err := NewMetricsCollector(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}
	defer func() { _ = mc.Shutdown(context.Background()) }()

	flushOne(t, mc.meterProvider)
	checkAuthenticatedExport(t, collector, defaultServiceName)
}
