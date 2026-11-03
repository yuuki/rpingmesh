package agent

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func TestAckDropLog_RateLimitsAndCounts(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	now := time.Unix(1000, 0)
	d := &ackDropLog{now: func() time.Time { return now }}

	d.record(logger, false) // first drop logs at once
	for i := 0; i < 50; i++ {
		d.record(logger, i%2 == 0)
	}
	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Fatalf("log lines = %d, want 1 within the interval:\n%s", got, buf.String())
	}

	now = now.Add(ackDropLogInterval)
	d.record(logger, true)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log lines = %d, want 2 after the interval", len(lines))
	}
	// 50 drops since the first summary plus this one: 25 unknown, 26 foreign.
	if !strings.Contains(lines[1], `"unknown_seq":25`) || !strings.Contains(lines[1], `"unexpected_source":26`) {
		t.Fatalf("summary = %s", lines[1])
	}
}

func TestClusterMonitor_CapTargets(t *testing.T) {
	m := newTestClusterMonitor(nil, newTestProber())
	targets := make([]*controller_agent.PingTarget, MaxPinglistTargets+10)
	if got := len(m.capTargets(targets, controller_agent.PinglistType_TOR_MESH)); got != MaxPinglistTargets {
		t.Fatalf("kept %d targets, want %d", got, MaxPinglistTargets)
	}
	small := targets[:3]
	if got := len(m.capTargets(small, controller_agent.PinglistType_INTER_TOR)); got != 3 {
		t.Fatalf("kept %d targets, want 3", got)
	}
}
