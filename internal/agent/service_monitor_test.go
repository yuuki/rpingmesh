package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeEventSource stands in for the eBPF tracer: Emit delivers an event to
// the handler Start installed.
type fakeEventSource struct {
	mu      sync.Mutex
	handle  func(servicetrace.Event)
	closed  bool
	stats   servicetrace.Stats
	started int
}

func (f *fakeEventSource) Start(_ context.Context, handle func(servicetrace.Event)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handle = handle
	f.started++
}

func (f *fakeEventSource) Stats() servicetrace.Stats { return f.stats }

func (f *fakeEventSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeEventSource) Emit(ev servicetrace.Event) {
	f.mu.Lock()
	h := f.handle
	f.mu.Unlock()
	if h != nil {
		h(ev)
	}
}

// fakeResolver answers GetTargetRnicInfo from a map and records the calls.
type fakeResolver struct {
	mu      sync.Mutex
	targets map[string]*controller_agent.PingTarget
	err     error
	calls   [][]string
	gids    []string
}

func (f *fakeResolver) GetTargetRnicInfo(_ context.Context, _, requesterGID string, gids []string) ([]*controller_agent.PingTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{requesterGID}, gids...))
	if f.err != nil {
		return nil, f.err
	}
	var out []*controller_agent.PingTarget
	for _, gid := range gids {
		if t := f.targets[gid]; t != nil {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeServiceProber records every UpdateServiceTargets call.
type fakeServiceProber struct {
	mu       sync.Mutex
	updates  [][]*controller_agent.PingTarget
	services map[*controller_agent.PingTarget][]string
}

func (f *fakeServiceProber) UpdateServiceTargets(targets []*controller_agent.PingTarget, services map[*controller_agent.PingTarget][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, targets)
	f.services = services
}

func (f *fakeServiceProber) last() ([]*controller_agent.PingTarget, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.updates) == 0 {
		return nil, 0
	}
	return f.updates[len(f.updates)-1], len(f.updates)
}

const (
	testUverbsDev = uint32(0xe7000c0) // 231:192
	localGIDStr   = "0000:0000:0000:0000:0000:ffff:0a00:0001"
)

var (
	localGID, _  = probe.ParseGID(localGIDStr)
	remoteGID, _ = probe.ParseGID("0000:0000:0000:0000:0000:ffff:0a00:0002")
	remoteGIDStr = probe.FormatGID(remoteGID)
)

// newTestServiceMonitor builds a monitor for one device "mlx5_0" whose uverbs
// node is 231:192 in a fake sysfs, with a short debounce.
func newTestServiceMonitor(t *testing.T, resolver *fakeResolver, source *fakeEventSource, prober *fakeServiceProber) *ServiceMonitor {
	t.Helper()
	root := t.TempDir()
	for path, content := range map[string]string{
		"class/infiniband_verbs/uverbs0/dev":        "231:192\n",
		"class/infiniband_verbs/uverbs0/ibdev":      "mlx5_0\n",
		"class/infiniband/mlx5_0/ports/1/gids/3":    localGIDStr + "\n",
		"class/infiniband/mlx5_0/ports/1/gids/1":    "0000:0000:0000:0000:0000:ffff:c0a8:0001\n",
		"class/infiniband_verbs/uverbs1/dev":        "231:193\n",
		"class/infiniband_verbs/uverbs1/ibdev":      "mlx5_9\n",
		"class/infiniband/mlx5_9/ports/1/gids/3":    "0000:0000:0000:0000:0000:ffff:0a00:0009\n",
		"class/infiniband_verbs/abi_version/ignore": "",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := NewServiceMonitor(resolver, source, "agent-a", []ServiceDevice{{
		Name: "mlx5_0", GID: localGIDStr, IPAddr: "10.0.0.1", Port: 1, GIDIndex: 3, Prober: prober,
	}}, 300)
	m.sysfsRoot = root
	// A fake /proc in which the traced process (pid 7) exists.
	m.procRoot = filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(m.procRoot, "7"), 0o755); err != nil {
		t.Fatal(err)
	}
	m.debounce = 10 * time.Millisecond
	m.logger = zerolog.Nop()
	return m
}

func createRC(ctx uint64, dev, handle, qpn uint32) servicetrace.Event {
	return servicetrace.Event{Kind: servicetrace.KindQPCreate, Context: ctx, Dev: dev, QPHandle: handle, QPNum: qpn, QPType: servicetrace.QPTypeRC, PID: 7, Comm: "app"}
}

func connectTo(ctx uint64, handle, destQPN, flowLabel uint32, dgid [16]byte, sgidIndex uint8) servicetrace.Event {
	return servicetrace.Event{
		Kind: servicetrace.KindQPModify, Context: ctx, QPHandle: handle,
		AttrMask: servicetrace.AttrMaskState | servicetrace.AttrMaskAV | servicetrace.AttrMaskDestQPN,
		QPState:  servicetrace.QPStateRTR, DGID: dgid, DestQPNum: destQPN, FlowLabel: flowLabel, SGIDIndex: sgidIndex, DestPortNum: 1,
	}
}

func waitForUpdate(t *testing.T, prober *fakeServiceProber, after int) []*controller_agent.PingTarget {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		targets, n := prober.last()
		if n > after {
			return targets
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no service target update after %d updates", after)
	return nil
}

// TestServiceMonitor_ConnectionBecomesTarget drives the monitor end to end:
// a traced RC connection is resolved through the controller and pushed to the
// device's prober as a SERVICE_TRACING target carrying the flow's effective
// label; destroying the QP clears it.
func TestServiceMonitor_ConnectionBecomesTarget(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{
		remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77, TargetTorId: "tor-b", TargetHostname: "host-b"},
	}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()
	if source.started != 1 {
		t.Fatalf("tracer started %d times, want 1", source.started)
	}

	source.Emit(createRC(0x1000, testUverbsDev, 1, 0x100))
	source.Emit(connectTo(0x1000, 1, 0x200, 0, remoteGID, 3))
	// A second QP to the same remote with an explicit label: a second flow.
	source.Emit(createRC(0x1000, testUverbsDev, 2, 0x101))
	source.Emit(connectTo(0x1000, 2, 0x201, 0xabc, remoteGID, 3))

	targets := waitForUpdate(t, prober, 0)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %v", len(targets), targets)
	}
	wantLabels := map[uint32]bool{servicetrace.CalcFlowLabel(0x100, 0x200): true, 0xabc: true}
	for _, tg := range targets {
		if tg.GetTargetGid() != remoteGIDStr || tg.GetTargetQpn() != 77 || tg.GetTargetTorId() != "tor-b" {
			t.Errorf("unexpected target identity: %v", tg)
		}
		if tg.GetPinglistType() != controller_agent.PinglistType_SERVICE_TRACING || tg.GetFlowLabelCount() != 1 || tg.GetSampled() {
			t.Errorf("unexpected target shape: %v", tg)
		}
		if !wantLabels[tg.GetFlowLabel()] {
			t.Errorf("unexpected flow label %#x", tg.GetFlowLabel())
		}
		delete(wantLabels, tg.GetFlowLabel())
	}
	if resolver.callCount() != 1 {
		t.Errorf("resolver called %d times, want 1 (both flows share one remote)", resolver.callCount())
	}
	if calls := resolver.calls; calls[0][0] != localGIDStr || calls[0][1] != remoteGIDStr {
		t.Errorf("resolver request = %v", calls[0])
	}

	stats := m.Stats()
	if !stats.Active || len(stats.Devices) != 1 || stats.Devices[0].Connections != 2 ||
		stats.Devices[0].FlowsProbed != 2 || stats.Devices[0].FlowsUnresolved != 0 || stats.Connects != 2 {
		t.Errorf("stats = %+v", stats)
	}

	// Destroying one QP leaves one flow; closing the context leaves none.
	_, n := prober.last()
	source.Emit(servicetrace.Event{Kind: servicetrace.KindQPDestroy, Context: 0x1000, QPHandle: 2})
	targets = waitForUpdate(t, prober, n)
	if len(targets) != 1 || targets[0].GetFlowLabel() != servicetrace.CalcFlowLabel(0x100, 0x200) {
		t.Fatalf("after destroy: %v", targets)
	}
	_, n = prober.last()
	source.Emit(servicetrace.Event{Kind: servicetrace.KindContextClose, Context: 0x1000})
	if targets = waitForUpdate(t, prober, n); len(targets) != 0 {
		t.Fatalf("after context close: %v", targets)
	}

	m.Stop()
	if !source.closed {
		t.Error("Stop must close the tracer")
	}
	if st := m.Stats(); st.Active {
		t.Error("Stats must report inactive after Stop")
	}
}

// TestServiceMonitor_UnresolvedRetriedOnRefresh verifies that a remote the
// controller does not know yields no target, is counted as unresolved, and is
// asked again on a full refresh.
func TestServiceMonitor_UnresolvedRetriedOnRefresh(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)
	m.loadDeviceNumbers()
	ctx := context.Background()

	m.handleEvent(createRC(0x1000, testUverbsDev, 1, 0x100))
	m.handleEvent(connectTo(0x1000, 1, 0x200, 0, remoteGID, 3))
	m.rebuild(ctx, false)
	if targets, _ := prober.last(); len(targets) != 0 {
		t.Fatalf("unresolved remote produced targets: %v", targets)
	}
	if st := m.Stats(); st.Devices[0].FlowsUnresolved != 1 || st.Devices[0].FlowsProbed != 0 {
		t.Errorf("stats = %+v", st.Devices[0])
	}

	// A debounced rebuild within the retry window does not ask again.
	m.rebuild(ctx, false)
	if resolver.callCount() != 1 {
		t.Fatalf("resolver called %d times, want 1 (negative answer cached)", resolver.callCount())
	}

	// The peer's agent registers; a full refresh asks again and succeeds.
	resolver.mu.Lock()
	resolver.targets[remoteGIDStr] = &controller_agent.PingTarget{TargetGid: remoteGIDStr, TargetQpn: 5}
	resolver.mu.Unlock()
	m.rebuild(ctx, true)
	targets, _ := prober.last()
	if len(targets) != 1 || targets[0].GetTargetQpn() != 5 {
		t.Fatalf("after refresh: %v", targets)
	}

	// Once the negative answer is older than the retry window, even an
	// event-driven rebuild asks again.
	delete(resolver.targets, remoteGIDStr)
	m.rebuild(ctx, true)
	m.nowFn = func() time.Time { return time.Now().Add(2 * serviceUnresolvedRetry) }
	before := resolver.callCount()
	m.rebuild(ctx, false)
	if resolver.callCount() != before+1 {
		t.Errorf("stale negative answer was not retried")
	}
}

// TestServiceMonitor_UnresolvedRetryTimer verifies that an unresolved remote
// is asked for again after the retry period without any new connection
// event, once the peer's agent has registered.
func TestServiceMonitor_UnresolvedRetryTimer(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)
	m.unresolvedRetry = 30 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	source.Emit(createRC(0x1000, testUverbsDev, 1, 0x100))
	source.Emit(connectTo(0x1000, 1, 0x200, 0, remoteGID, 3))
	targets := waitForUpdate(t, prober, 0)
	if len(targets) != 0 {
		t.Fatalf("unresolved remote produced targets: %v", targets)
	}
	_, n := prober.last()

	// The peer registers; nothing else happens on this host.
	resolver.mu.Lock()
	resolver.targets[remoteGIDStr] = &controller_agent.PingTarget{TargetGid: remoteGIDStr, TargetQpn: 5}
	resolver.mu.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if targets, m := prober.last(); m > n && len(targets) == 1 && targets[0].GetTargetQpn() == 5 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the retry timer did not resolve the remote; resolver calls: %v", resolver.calls)
}

// TestServiceMonitor_ReapsExitedProcesses verifies that the connections of a
// process whose close event was lost are dropped once the process is gone.
func TestServiceMonitor_ReapsExitedProcesses(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{
		remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77},
	}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)
	m.loadDeviceNumbers()
	ctx := context.Background()

	m.handleEvent(createRC(0x1000, testUverbsDev, 1, 0x100))
	m.handleEvent(connectTo(0x1000, 1, 0x200, 0, remoteGID, 3))
	m.rebuild(ctx, false)
	if targets, _ := prober.last(); len(targets) != 1 {
		t.Fatalf("initial: %v", targets)
	}

	// The process exits but its context-close event is lost.
	if err := os.Remove(filepath.Join(m.procRoot, "7")); err != nil {
		t.Fatal(err)
	}
	source.stats.RingBufferDropped = 1
	m.rebuild(ctx, false)
	if targets, _ := prober.last(); len(targets) != 0 {
		t.Fatalf("after the process exited: %v", targets)
	}
	if st := m.Stats(); st.ContextCloses != 1 || st.Devices[0].Connections != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// TestServiceMonitor_ResolverErrors verifies that a failing controller keeps
// the previous targets and that an Unimplemented answer is reported once.
func TestServiceMonitor_ResolverErrors(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{
		remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77},
	}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)
	m.loadDeviceNumbers()
	ctx := context.Background()

	m.handleEvent(createRC(0x1000, testUverbsDev, 1, 0x100))
	m.handleEvent(connectTo(0x1000, 1, 0x200, 0, remoteGID, 3))
	m.rebuild(ctx, false)
	if targets, _ := prober.last(); len(targets) != 1 {
		t.Fatalf("initial resolution: %v", targets)
	}

	resolver.mu.Lock()
	resolver.err = errors.New("controller unreachable")
	resolver.mu.Unlock()
	m.rebuild(ctx, true)
	if targets, _ := prober.last(); len(targets) != 1 {
		t.Fatalf("a failed refresh must keep the previous targets, got %v", targets)
	}

	resolver.mu.Lock()
	resolver.err = status.Error(codes.Unimplemented, "unknown method")
	resolver.mu.Unlock()
	m.rebuild(ctx, true)
	m.rebuild(ctx, true)
	if !m.unimplementedWarned {
		t.Error("an Unimplemented answer must be recorded")
	}
	if targets, _ := prober.last(); len(targets) != 1 {
		t.Fatalf("an Unimplemented answer must keep the cached targets, got %v", targets)
	}
}

// TestServiceMonitor_IgnoresOtherDevices verifies that connections on RDMA
// devices the agent does not probe from (an excluded device) are ignored.
func TestServiceMonitor_IgnoresOtherDevices(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{
		remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77},
	}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)
	ctx := context.Background()

	// uverbs1 (mlx5_9) is not a monitored device; 231:250 is no node at all.
	m.handleEvent(createRC(0x2000, servicetrace.MakeDev(231, 193), 1, 0x100))
	m.handleEvent(connectTo(0x2000, 1, 0x200, 0, remoteGID, 3))
	m.handleEvent(createRC(0x3000, servicetrace.MakeDev(231, 250), 1, 0x100))
	m.handleEvent(connectTo(0x3000, 1, 0x200, 0, remoteGID, 3))
	m.rebuild(ctx, false)
	if targets, _ := prober.last(); len(targets) != 0 {
		t.Fatalf("connections on other devices produced targets: %v", targets)
	}
	if resolver.callCount() != 0 {
		t.Errorf("resolver called %d times for other devices' connections", resolver.callCount())
	}
	if m.otherDeviceConns != 2 {
		t.Errorf("otherDeviceConns = %d, want 2", m.otherDeviceConns)
	}
}

// TestServiceMonitor_SourceGIDMismatchWarnsOnce verifies the source-GID
// check reads the flow's GID from sysfs and records each index once.
func TestServiceMonitor_SourceGIDMismatchWarnsOnce(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{
		remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77},
	}}
	source := &fakeEventSource{}
	prober := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, source, prober)
	m.loadDeviceNumbers()
	ctx := context.Background()

	// GID index 1 is another address (192.168.0.1): a different source.
	m.handleEvent(createRC(0x1000, testUverbsDev, 1, 0x100))
	m.handleEvent(connectTo(0x1000, 1, 0x200, 0, remoteGID, 1))
	m.rebuild(ctx, false)
	d := m.devices["mlx5_0"]
	if !d.warnedSGID[1] || d.warnedSGID[3] {
		t.Errorf("warnedSGID = %v, want only index 1", d.warnedSGID)
	}
	// The flow is still probed: the mismatch is a warning, not a filter.
	if targets, _ := prober.last(); len(targets) != 1 {
		t.Fatalf("mismatched source GID must still be probed, got %v", targets)
	}
}
