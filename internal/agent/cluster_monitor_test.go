package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// pinglistResponse is a single canned GetPinglist result used by
// mockControllerClient.
type pinglistResponse struct {
	targets []*controller_agent.PingTarget
	err     error
}

// mockControllerClient is a test double for the ControllerClient interface.
// It lets tests script a per-pinglist-type sequence of results so that
// ClusterMonitor's fetch/cache/combine behavior can be tested without a
// real gRPC connection to a controller.
type mockControllerClient struct {
	mu        sync.Mutex
	responses map[controller_agent.PinglistType][]pinglistResponse
	callIndex map[controller_agent.PinglistType]int
	calls     map[controller_agent.PinglistType]int
}

func newMockControllerClient() *mockControllerClient {
	return &mockControllerClient{
		responses: make(map[controller_agent.PinglistType][]pinglistResponse),
		callIndex: make(map[controller_agent.PinglistType]int),
		calls:     make(map[controller_agent.PinglistType]int),
	}
}

// enqueue appends a scripted response for the given pinglist type. Calls to
// GetPinglist for that type consume the queue in order; once exhausted, the
// last enqueued response is returned for all further calls.
func (m *mockControllerClient) enqueue(ptype controller_agent.PinglistType, targets []*controller_agent.PingTarget, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[ptype] = append(m.responses[ptype], pinglistResponse{targets: targets, err: err})
}

// GetPinglist implements the ControllerClient interface.
func (m *mockControllerClient) GetPinglist(
	_ context.Context,
	_, _, _ string,
	ptype controller_agent.PinglistType,
) ([]*controller_agent.PingTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls[ptype]++
	queue := m.responses[ptype]
	if len(queue) == 0 {
		return nil, nil
	}

	idx := m.callIndex[ptype]
	if idx >= len(queue) {
		idx = len(queue) - 1
	} else {
		m.callIndex[ptype] = idx + 1
	}
	resp := queue[idx]
	return resp.targets, resp.err
}

// newTestProber builds a Prober suitable for ClusterMonitor tests. It
// bypasses NewProber (which requires a real RDMA device) since only the
// unexported targets field, set via UpdateTargets, is exercised here.
func newTestProber() *Prober {
	return &Prober{logger: zerolog.Nop()}
}

// newTestClusterMonitor builds a ClusterMonitor wired to the given mock
// client and prober, with logging silenced.
func newTestClusterMonitor(client ControllerClient, prober *Prober) *ClusterMonitor {
	m := NewClusterMonitor(client, prober, "agent-1", "tor-1", "gid-requester", 1)
	m.logger = zerolog.Nop()
	return m
}

func targetWithGID(gid string) *controller_agent.PingTarget {
	return &controller_agent.PingTarget{TargetGid: gid}
}

func gidsOf(targets []*controller_agent.PingTarget) []string {
	gids := make([]string, len(targets))
	for i, target := range targets {
		gids[i] = target.GetTargetGid()
	}
	return gids
}

func TestClusterMonitor_FetchPinglists_Success(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("tor-a")}, nil)
	client.enqueue(controller_agent.PinglistType_INTER_TOR, []*controller_agent.PingTarget{targetWithGID("inter-a")}, nil)

	monitor := newTestClusterMonitor(client, newTestProber())

	combined := monitor.fetchPinglists(context.Background())

	if got := gidsOf(combined); len(got) != 2 || got[0] != "tor-a" || got[1] != "inter-a" {
		t.Fatalf("unexpected combined targets: %v", got)
	}
}

func TestClusterMonitor_FetchPinglists_PartialFailure_ReusesCache(t *testing.T) {
	client := newMockControllerClient()
	// First cycle: both pinglist types succeed, populating the per-type cache.
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("tor-a")}, nil)
	client.enqueue(controller_agent.PinglistType_INTER_TOR, []*controller_agent.PingTarget{targetWithGID("inter-a")}, nil)
	// Second cycle: TOR_MESH succeeds with a refreshed target, INTER_TOR fails.
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("tor-b")}, nil)
	client.enqueue(controller_agent.PinglistType_INTER_TOR, nil, errors.New("controller unreachable"))

	monitor := newTestClusterMonitor(client, newTestProber())

	if first := monitor.fetchPinglists(context.Background()); len(first) != 2 {
		t.Fatalf("expected 2 targets on first fetch, got %d", len(first))
	}

	second := monitor.fetchPinglists(context.Background())
	got := gidsOf(second)
	if len(got) != 2 {
		t.Fatalf("expected 2 targets on second fetch (cached INTER_TOR reused), got %d (%v)", len(got), got)
	}

	present := map[string]bool{got[0]: true, got[1]: true}
	if !present["tor-b"] {
		t.Errorf("expected refreshed TOR_MESH target 'tor-b' in combined result, got %v", got)
	}
	if !present["inter-a"] {
		t.Errorf("expected cached INTER_TOR target 'inter-a' to be reused after fetch failure, got %v", got)
	}
}

func TestClusterMonitor_FetchPinglists_BothFail_ReusesCache(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("tor-a")}, nil)
	client.enqueue(controller_agent.PinglistType_INTER_TOR, []*controller_agent.PingTarget{targetWithGID("inter-a")}, nil)
	client.enqueue(controller_agent.PinglistType_TOR_MESH, nil, errors.New("timeout"))
	client.enqueue(controller_agent.PinglistType_INTER_TOR, nil, errors.New("timeout"))

	monitor := newTestClusterMonitor(client, newTestProber())

	first := gidsOf(monitor.fetchPinglists(context.Background()))
	second := gidsOf(monitor.fetchPinglists(context.Background()))

	if len(second) != len(first) {
		t.Fatalf("expected cached targets to be preserved when both fetches fail: first=%v second=%v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("target %d changed after both-fail cycle: got %s, want %s", i, second[i], first[i])
		}
	}
}

// TestClusterMonitor_FetchPinglists_BackfillsInterTorType verifies that when an
// older controller returns inter-ToR targets without stamping pinglist_type
// (proto3 default TOR_MESH), the monitor backfills INTER_TOR -- which the agent
// knows from having issued an INTER_TOR request -- while leaving ToR-mesh
// targets and any explicitly-stamped value untouched. Without this, the prober
// would rate-limit those targets as ToR-mesh and ignore the inter-ToR rate.
func TestClusterMonitor_FetchPinglists_BackfillsInterTorType(t *testing.T) {
	client := newMockControllerClient()
	// ToR-mesh target: unstamped (default TOR_MESH), must stay TOR_MESH.
	client.enqueue(controller_agent.PinglistType_TOR_MESH,
		[]*controller_agent.PingTarget{targetWithGID("tor-a")}, nil)
	// Inter-ToR list as an OLD controller would send it: one unstamped target
	// (default TOR_MESH) plus one a newer controller stamped INTER_TOR.
	explicit := targetWithGID("inter-explicit")
	explicit.PinglistType = controller_agent.PinglistType_INTER_TOR
	client.enqueue(controller_agent.PinglistType_INTER_TOR,
		[]*controller_agent.PingTarget{targetWithGID("inter-unstamped"), explicit}, nil)

	monitor := newTestClusterMonitor(client, newTestProber())
	combined := monitor.fetchPinglists(context.Background())

	byGID := make(map[string]controller_agent.PinglistType, len(combined))
	for _, tgt := range combined {
		byGID[tgt.GetTargetGid()] = tgt.GetPinglistType()
	}

	if got := byGID["tor-a"]; got != controller_agent.PinglistType_TOR_MESH {
		t.Errorf("ToR-mesh target type = %v, want TOR_MESH (unchanged)", got)
	}
	if got := byGID["inter-unstamped"]; got != controller_agent.PinglistType_INTER_TOR {
		t.Errorf("unstamped inter-ToR target type = %v, want INTER_TOR (backfilled)", got)
	}
	if got := byGID["inter-explicit"]; got != controller_agent.PinglistType_INTER_TOR {
		t.Errorf("explicitly-stamped inter-ToR target type = %v, want INTER_TOR (preserved)", got)
	}
}

func TestClusterMonitor_UpdateTargets_PushesToProber(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("tor-a")}, nil)
	client.enqueue(controller_agent.PinglistType_INTER_TOR, nil, nil)

	prober := newTestProber()
	monitor := newTestClusterMonitor(client, prober)

	monitor.updateTargets(context.Background())

	if len(prober.targets) != 1 || prober.targets[0].GetTargetGid() != "tor-a" {
		t.Errorf("expected prober targets to be updated with fetched pinglist, got %v", gidsOf(prober.targets))
	}
}

func TestClusterMonitor_Stop_ReturnsQuickly(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH, nil, nil)
	client.enqueue(controller_agent.PinglistType_INTER_TOR, nil, nil)

	// A long update interval ensures this test only passes if Stop wakes
	// the monitor loop via stopCh rather than waiting for the next tick.
	monitor := NewClusterMonitor(client, newTestProber(), "agent-1", "tor-1", "gid-requester", 3600)
	monitor.logger = zerolog.Nop()

	if err := monitor.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		monitor.Stop()
		close(done)
	}()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Stop took too long: %v", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s; monitor loop likely blocked on the ticker instead of stopCh")
	}
}

// callCount returns how many times GetPinglist was called for ptype.
func (m *mockControllerClient) callCount(ptype controller_agent.PinglistType) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[ptype]
}

// waitForCalls polls until GetPinglist(ptype) has been called at least want
// times, failing the test after timeout.
func waitForCalls(t *testing.T, client *mockControllerClient, ptype controller_agent.PinglistType, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for client.callCount(ptype) < want {
		if time.Now().After(deadline) {
			t.Fatalf("GetPinglist(%v) called %d times, want >= %d within %v",
				ptype, client.callCount(ptype), want, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEarlyRefreshBackoff(t *testing.T) {
	b := newEarlyRefreshBackoff(30*time.Second, 300*time.Second)
	if got := b.delay(); got != 30*time.Second {
		t.Fatalf("initial delay = %v, want 30s", got)
	}
	for _, want := range []time.Duration{60, 120, 240, 300, 300} {
		b.observe(false)
		if got := b.delay(); got != want*time.Second {
			t.Fatalf("delay after unchanged refresh = %v, want %v", got, want*time.Second)
		}
	}
	b.observe(true)
	if got := b.delay(); got != 30*time.Second {
		t.Errorf("delay after changed refresh = %v, want reset to 30s", got)
	}

	// A base above the cap (e.g. a short update interval) clamps to the cap.
	if got := newEarlyRefreshBackoff(30*time.Second, time.Second).delay(); got != time.Second {
		t.Errorf("clamped delay = %v, want 1s", got)
	}
}

func TestQPNChanged(t *testing.T) {
	prev := map[string]uint32{"g1": 10, "g2": 20}
	cases := []struct {
		name string
		cur  map[string]uint32
		want bool
	}{
		{"identical", map[string]uint32{"g1": 10, "g2": 20}, false},
		{"membership only (inter-ToR resample)", map[string]uint32{"g1": 10, "g3": 30}, false},
		{"empty", map[string]uint32{}, false},
		{"qpn replaced", map[string]uint32{"g1": 10, "g2": 21}, true},
	}
	for _, tc := range cases {
		if got := qpnChanged(prev, tc.cur); got != tc.want {
			t.Errorf("%s: qpnChanged = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestClusterMonitor_RefreshHint_TriggersEarlyRefresh verifies that a
// prober refresh hint causes a pinglist fetch long before the next tick.
func TestClusterMonitor_RefreshHint_TriggersEarlyRefresh(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH,
		[]*controller_agent.PingTarget{{TargetGid: "g1", TargetQpn: 10}}, nil)
	client.enqueue(controller_agent.PinglistType_TOR_MESH,
		[]*controller_agent.PingTarget{{TargetGid: "g1", TargetQpn: 11}}, nil)

	prober := newTestProber()
	prober.refreshHint = make(chan struct{}, 1)
	monitor := NewClusterMonitor(client, prober, "agent-1", "tor-1", "gid-requester", 3600)
	monitor.logger = zerolog.Nop()
	monitor.minEarlyRefresh = 10 * time.Millisecond

	if err := monitor.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer monitor.Stop()

	waitForCalls(t, client, controller_agent.PinglistType_TOR_MESH, 1, 2*time.Second)
	time.Sleep(20 * time.Millisecond) // let the base delay elapse
	prober.refreshHint <- struct{}{}
	waitForCalls(t, client, controller_agent.PinglistType_TOR_MESH, 2, 2*time.Second)

	prober.targetsMu.RLock()
	defer prober.targetsMu.RUnlock()
	if len(prober.targets) != 1 || prober.targets[0].GetTargetQpn() != 11 {
		t.Errorf("prober targets after early refresh = %v, want the refreshed QPN 11", prober.targets)
	}
}

// TestClusterMonitor_RefreshHint_RateLimited verifies that a hint arriving
// before the backoff delay has elapsed since the last fetch is dropped.
func TestClusterMonitor_RefreshHint_RateLimited(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("g1")}, nil)

	prober := newTestProber()
	prober.refreshHint = make(chan struct{}, 1)
	monitor := NewClusterMonitor(client, prober, "agent-1", "tor-1", "gid-requester", 3600)
	monitor.logger = zerolog.Nop()
	monitor.minEarlyRefresh = time.Hour

	if err := monitor.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer monitor.Stop()

	waitForCalls(t, client, controller_agent.PinglistType_TOR_MESH, 1, 2*time.Second)
	prober.refreshHint <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	if got := client.callCount(controller_agent.PinglistType_TOR_MESH); got != 1 {
		t.Errorf("GetPinglist called %d times, want 1 (hint within backoff delay must be dropped)", got)
	}
}

// TestClusterMonitor_EmptyPinglist_RetriesEarly verifies that an agent whose
// first fetch returns no targets (e.g. it registered before its peers)
// retries without waiting for the update interval.
func TestClusterMonitor_EmptyPinglist_RetriesEarly(t *testing.T) {
	client := newMockControllerClient()
	client.enqueue(controller_agent.PinglistType_TOR_MESH, nil, nil)
	client.enqueue(controller_agent.PinglistType_TOR_MESH, []*controller_agent.PingTarget{targetWithGID("g1")}, nil)

	prober := newTestProber()
	monitor := NewClusterMonitor(client, prober, "agent-1", "tor-1", "gid-requester", 3600)
	monitor.logger = zerolog.Nop()
	monitor.minEarlyRefresh = 10 * time.Millisecond

	if err := monitor.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer monitor.Stop()

	waitForCalls(t, client, controller_agent.PinglistType_TOR_MESH, 2, 2*time.Second)

	// Once the pinglist is non-empty, no further early retries happen.
	time.Sleep(100 * time.Millisecond)
	if got := client.callCount(controller_agent.PinglistType_TOR_MESH); got != 2 {
		t.Errorf("GetPinglist called %d times, want 2 (no retry once targets exist)", got)
	}
}
