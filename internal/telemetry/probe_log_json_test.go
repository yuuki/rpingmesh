package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/yuuki/rpingmesh/internal/logging"
	"github.com/yuuki/rpingmesh/internal/probe"
)

// probeLogFixture is the journal fixture scripts/topology/rtt_tor_check.py is
// tested against (scripts/topology/test_rtt_tor_check.py).
var probeLogFixture = filepath.Join("..", "..", "scripts", "topology", "testdata", "agent-journal.jsonl")

// rttToolFields are the fields rtt_tor_check.py reads from a
// "Probe result recorded" record.
var rttToolFields = []string{"message", "source_gid", "target_gid", "t2", "t3", "t4", "t5", "success"}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestProbeResultLogJSONMatchesRTTTool checks that, with log_format=json, the
// "Probe result recorded" debug line is a single JSON object carrying the
// fields rtt_tor_check.py reads, and that the Python tool's fixture has
// exactly the same shape, so the two cannot drift apart silently.
func TestProbeResultLogJSONMatchesRTTTool(t *testing.T) {
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	defer provider.Shutdown(context.Background())
	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}
	var buf bytes.Buffer
	logger, err := logging.New(logging.FormatJSON, &buf)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	mc.logger = logger.With().Str("component", "telemetry").Logger()

	src, _ := probe.ParseGID("fe80::1")
	dst, _ := probe.ParseGID("fe80::2")
	mc.RecordProbeResult(&probe.ProbeResult{
		SourceGID: src, TargetGID: dst, TargetTorID: "leaf-b",
		T1: 1, T2: 100, T3: 1000, T4: 1300, T5: 2400, T6: 2500,
		Success: true,
	}, &probe.RTTResult{NetworkRTT: 2000, Valid: true}, "leaf-a")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String())
	}
	var live map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &live); err != nil {
		t.Fatalf("probe log line is not JSON: %v (%q)", err, lines[0])
	}
	for _, k := range rttToolFields {
		if _, ok := live[k]; !ok {
			t.Errorf("probe log line lacks %q: %s", k, lines[0])
		}
	}
	if live["message"] != "Probe result recorded" || live["success"] != true || live["t5"] != float64(2400) {
		t.Errorf("unexpected probe log record: %s", lines[0])
	}

	f, err := os.Open(probeLogFixture)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	want := strings.Join(sortedKeys(live), ",")
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if !strings.Contains(sc.Text(), "Probe result recorded") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("fixture line is not JSON: %v (%q)", err, sc.Text())
		}
		if got := strings.Join(sortedKeys(rec), ","); got != want {
			t.Errorf("fixture record keys = %s, live agent emits %s", got, want)
		}
		n++
	}
	if n == 0 {
		t.Fatal("fixture has no Probe result recorded lines")
	}
	t.Logf("live: %s", lines[0])
}
