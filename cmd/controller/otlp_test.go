package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/controller"
	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/internal/testutil/otlptest"
	"github.com/yuuki/rpingmesh/internal/testutil/tlscerts"
)

// TestSetupAnalyzer_ExportsOverTLSWithBearerToken verifies that the
// analyzer's meter provider, built from the controller configuration, exports
// to a collector that requires TLS and a bearer token. The collector listens
// on 127.0.0.1 with a certificate for another name, signed by a private CA.
// The controller's logs must not contain the token.
func TestSetupAnalyzer_ExportsOverTLSWithBearerToken(t *testing.T) {
	const (
		collectorName = "collector.test"
		token         = "analyzer-test-token"
	)
	ca, err := tlscerts.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	collector := otlptest.Start(t, otlptest.Options{
		TLS:         otlptest.ServerCertificate(t, ca, collectorName),
		BearerToken: token,
	})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(caFile, ca.CAPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	cfg := &config.ControllerConfig{
		AnalyzerEnabled:                 true,
		AnalyzerWindowRetention:         config.DefaultAnalyzerWindowRetention,
		AnalyzerMetricsCardinalityLimit: config.DefaultAnalyzerMetricsCardinalityLimit,
		OtelCollectorAddr:               collector.Addr(),
		OtelCollectorTLSEnabled:         true,
		OtelCollectorTLSCAFile:          caFile,
		OtelCollectorTLSServerName:      collectorName,
		OtelCollectorBearerTokenFile:    tokenFile,
	}
	svc := controller.NewControllerService(nil, pinglist.ECMPConfig{
		PathsAssumed:        config.DefaultEcmpPathsAssumed,
		CoverageProbability: config.DefaultEcmpCoverageProbability,
		MaxFlowLabels:       config.DefaultEcmpMaxFlowLabels,
	}, config.DefaultInterTorSampleSize, config.DefaultUnspecifiedMeshMaxTargets)

	var logs bytes.Buffer
	prevLogger := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = prevLogger })

	provider := setupAnalyzer(cfg, svc)
	if provider == nil {
		t.Fatal("setupAnalyzer returned no meter provider")
	}
	defer shutdownMeterProvider(provider)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The analyzer records nothing without agent reports; one point on the
	// same provider makes the flush carry data.
	counter, err := provider.Meter("otlp-test").Int64Counter("test.exports")
	if err != nil {
		t.Fatalf("Int64Counter: %v", err)
	}
	counter.Add(ctx, 1)
	if err := provider.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	reqs := collector.Accepted()
	if len(reqs) == 0 {
		t.Fatal("collector accepted no requests")
	}
	if want := []string{"Bearer " + token}; !slices.Equal(reqs[0].Authorization, want) {
		t.Errorf("authorization metadata = %q, want %q", reqs[0].Authorization, want)
	}
	if got := reqs[0].ServiceNames(); !slices.Equal(got, []string{analyzerServiceName}) {
		t.Errorf("service.name = %q, want %q", got, analyzerServiceName)
	}
	out := logs.String()
	if !strings.Contains(out, `"otelCollectorBearerAuth":true`) {
		t.Errorf("analyzer startup log does not report bearer authentication:\n%s", out)
	}
	if strings.Contains(out, token) {
		t.Errorf("logs reveal the token:\n%s", out)
	}
}
