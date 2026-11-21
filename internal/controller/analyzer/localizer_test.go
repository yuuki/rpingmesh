package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// newTestLocalizer returns an analyzer with localization on and a clock the
// test controls, set to the start of window 0.
func newTestLocalizer(t *testing.T, loc LocalizationConfig, metrics *Metrics) (*Analyzer, *simClock) {
	t.Helper()
	cfg := testConfig()
	cfg.Localization = &loc
	az := New(cfg, metrics)
	clock := &simClock{ns: testBaseStartNs}
	az.loc.now = clock.now
	return az, clock
}

// windowEnd returns the end of test window w; windowClose the moment it
// closes.
func windowEnd(w int) uint64   { return testBaseStartNs + uint64(w+1)*testWindowNs }
func windowClose(w int) uint64 { return windowEnd(w) + testWindowNs + closeMarginNs }

// ingestWindow reports one window of observations, each agent's in a report
// of its own, a few seconds after the window ends.
func ingestWindow(az *Analyzer, clock *simClock, w int, window []obs) {
	clock.ns = windowEnd(w) + 5*uint64(time.Second)
	byAgent := map[string][]*controller_agent.PathSummary{}
	var agents []string
	for _, o := range window {
		if _, ok := byAgent[o.agent]; !ok {
			agents = append(agents, o.agent)
		}
		byAgent[o.agent] = append(byAgent[o.agent], o.summary(w))
	}
	for _, agent := range agents {
		az.Ingest(context.Background(), &controller_agent.ProbeAnalysisReport{AgentId: agent, Summaries: byAgent[agent]})
	}
}

// lossyTor0 is a window in which every path of tor-0 loses 5% of its probes.
func lossyTor0() []obs {
	return meshWindow(3, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if st == 0 || dt == 0 {
			return 50
		}
		return 0
	})
}

// TestAnalyzer_LocalizationIsOptIn verifies that an analyzer built without
// localization settings has no localizer, and that RunLocalization then
// returns at once.
func TestAnalyzer_LocalizationIsOptIn(t *testing.T) {
	az := New(testConfig(), nil)
	if az.loc != nil {
		t.Fatal("localization is on without Config.Localization")
	}
	done := make(chan struct{})
	go func() {
		az.RunLocalization(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunLocalization did not return at once with localization off")
	}
}

// TestLocalizer_Phase1IsUnchanged verifies that enabling localization does
// not change what Ingest returns or retains.
func TestLocalizer_Phase1IsUnchanged(t *testing.T) {
	plain := New(testConfig(), nil)
	withLoc, clock := newTestLocalizer(t, LocalizationConfig{}, nil)
	clock.ns = windowEnd(0)

	for w := 0; w < 3; w++ {
		for _, window := range [][]obs{lossyTor0()} {
			for _, o := range window {
				a := plain.Ingest(context.Background(), report(o.summary(w)))
				b := withLoc.Ingest(context.Background(), report(o.summary(w)))
				if a != b {
					t.Fatalf("window %d: Ingest returned %d without localization, %d with", w, a, b)
				}
			}
		}
	}
	if plain.RetainedWindows() != withLoc.RetainedWindows() || plain.RetainedSummaries() != withLoc.RetainedSummaries() {
		t.Errorf("ring: %d windows, %d summaries without localization; %d, %d with",
			plain.RetainedWindows(), plain.RetainedSummaries(), withLoc.RetainedWindows(), withLoc.RetainedSummaries())
	}
}

// TestLocalizer_EvaluatesClosedWindowsOnce verifies when an evaluation
// runs: not before a window has closed, once when it has, and again only
// when the evidence changed.
func TestLocalizer_EvaluatesClosedWindowsOnce(t *testing.T) {
	az, clock := newTestLocalizer(t, LocalizationConfig{}, nil)
	ctx := context.Background()

	if az.loc.evaluate(ctx) {
		t.Error("evaluated without any evidence")
	}
	ingestWindow(az, clock, 0, lossyTor0())
	if az.loc.evaluate(ctx) {
		t.Error("evaluated a window that has just ended")
	}
	// One nanosecond before the window closes: its reports may still come.
	clock.ns = windowClose(0) - 1
	if az.loc.evaluate(ctx) {
		t.Error("evaluated a window before its grace period ended")
	}
	clock.ns = windowClose(0)
	if !az.loc.evaluate(ctx) {
		t.Fatal("did not evaluate a closed window")
	}
	if az.loc.evaluate(ctx) {
		t.Error("evaluated the same evidence twice")
	}
	requireNone(t, az.loc.currentFindings()) // one window is not persistent

	ingestWindow(az, clock, 1, lossyTor0())
	clock.ns = windowClose(1)
	if !az.loc.evaluate(ctx) {
		t.Fatal("did not evaluate after a second window closed")
	}
	requireLocalized(t, az.loc.currentFindings(), KindLoss, "tor/tor-0")

	// A summary that arrives late for a closed window of the span is new
	// evidence.
	late := obs{agent: "late", src: "late-a", srcTor: "tor-9", dst: "late-b", dstTor: "tor-9", total: 100}
	az.Ingest(ctx, report(late.summary(1)))
	if !az.loc.evaluate(ctx) {
		t.Error("did not evaluate after a late summary for a window of the span")
	}
	if az.loc.evaluate(ctx) {
		t.Error("evaluated again without new evidence")
	}
}

// TestLocalizer_SpanSlides verifies that the evidence span is the most
// recent windows only: a fault that ended leaves the findings once its
// windows have left the span, and evidence that stops arriving goes stale.
func TestLocalizer_SpanSlides(t *testing.T) {
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2}, nil)
	ctx := context.Background()
	healthy := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })

	ingestWindow(az, clock, 0, lossyTor0())
	ingestWindow(az, clock, 1, lossyTor0())
	clock.ns = windowClose(1)
	az.loc.evaluate(ctx)
	requireLocalized(t, az.loc.currentFindings(), KindLoss, "tor/tor-0")

	// Window 2 is healthy: the span is windows 1 and 2, and one window of
	// loss is no longer persistent.
	ingestWindow(az, clock, 2, healthy)
	clock.ns = windowClose(2)
	az.loc.evaluate(ctx)
	requireNone(t, az.loc.currentFindings())

	// Loss again in windows 3 and 4, then the agents stop reporting.
	ingestWindow(az, clock, 3, lossyTor0())
	ingestWindow(az, clock, 4, lossyTor0())
	clock.ns = windowClose(4)
	az.loc.evaluate(ctx)
	requireLocalized(t, az.loc.currentFindings(), KindLoss, "tor/tor-0")

	clock.ns = windowClose(4) + 10*testWindowNs
	if !az.loc.evaluate(ctx) {
		t.Fatal("did not evaluate when the evidence went stale")
	}
	requireNone(t, az.loc.currentFindings())
	if got := len(az.loc.store.windows); got != 0 {
		t.Errorf("%d windows retained after the evidence went stale, want 0", got)
	}
}

// TestLocalizer_WithDefaults verifies that out-of-range settings are
// replaced by the defaults instead of being used.
func TestLocalizer_WithDefaults(t *testing.T) {
	want := LocalizationConfig{
		Windows:           DefaultLocalizationWindows,
		BaselineLossRatio: DefaultLocalizationBaselineLossRatio,
		MinConfidence:     DefaultLocalizationMinConfidence,
		MaxPathsPerWindow: DefaultLocalizationMaxPathsPerWindow,
	}
	for _, cfg := range []LocalizationConfig{
		{},
		{Windows: -1, BaselineLossRatio: -0.1, MinConfidence: 0.2, MaxPathsPerWindow: -5},
		{Windows: MaxLocalizationWindows + 1, BaselineLossRatio: 1, MinConfidence: 1},
	} {
		if got := cfg.withDefaults(); got != want {
			t.Errorf("%+v.withDefaults() = %+v, want %+v", cfg, got, want)
		}
	}
	kept := LocalizationConfig{Windows: 64, BaselineLossRatio: 0.5, MinConfidence: 0.5, MaxPathsPerWindow: 1}
	if got := kept.withDefaults(); got != kept {
		t.Errorf("valid settings changed: %+v -> %+v", kept, got)
	}
}

// TestEvidenceStore_KeepsOnlyAttributableClusterPaths verifies which
// summaries become evidence.
func TestEvidenceStore_KeepsOnlyAttributableClusterPaths(t *testing.T) {
	store := newEvidenceStore(4, 100, simRTTThresholdNs)
	nowNs := windowEnd(0)
	ok := obs{agent: "host-a", src: "a", srcTor: "tor-1", dst: "b", dstTor: "tor-2", total: 100, failed: 3, p99: 600_000}

	rejected := []obs{
		{agent: "host-a", src: "", srcTor: "tor-1", dst: "b", dstTor: "tor-2", total: 100},                        // no source GID
		{agent: "host-a", src: "a", srcTor: "tor-1", dst: "", dstTor: "tor-2", total: 100},                        // no target GID
		{agent: "host-a", src: "a", srcTor: "tor-1", dst: "a", dstTor: "tor-1", total: 100},                       // a path to itself
		{agent: "host-a", src: "a", srcTor: "", dst: "b", dstTor: "tor-2", total: 100},                            // no source ToR
		{agent: "host-a", src: "a", srcTor: "tor-1", dst: "b", dstTor: "unspecified", total: 100},                 // no target ToR
		{agent: "host-a", src: "a", srcTor: "tor-1", dst: "b", dstTor: "tor-2", total: 0},                         // no probes
		{agent: "host-a", src: "a", srcTor: "tor-1", dst: "c", dstTor: "tor-2", total: 100, serviceTracing: true}, // service network
	}
	for _, o := range rejected {
		store.observe(o.agent, o.summary(0), nowNs)
	}
	if len(store.windows) != 0 {
		t.Fatalf("%d windows after rejected summaries only, want 0", len(store.windows))
	}
	if store.stats.unattributable != 5 {
		t.Errorf("unattributable = %d, want 5", store.stats.unattributable)
	}

	store.observe(ok.agent, ok.summary(0), nowNs)
	// The same path again in the same window (a flush at shutdown followed
	// by a restart): the counts add up.
	store.observe(ok.agent, ok.summary(0), nowNs)
	// More failures than probes is clamped.
	bad := ok
	bad.total, bad.failed, bad.p99 = 10, 50, 0
	bad.dst = "c"
	store.observe(bad.agent, bad.summary(0), nowNs)

	w := store.windows[0]
	if len(w.pathKeys) != 2 || len(w.rnics) != 3 {
		t.Fatalf("window holds %d paths and %d RNICs, want 2 and 3", len(w.pathKeys), len(w.rnics))
	}
	got := *w.path(pathKey{src: w.rnicIdx["a"], dst: w.rnicIdx["b"]})
	if got.probes != 200 || got.failed != 6 || !got.rttValid || !got.rttBad {
		t.Errorf("path a->b = %+v, want 200 probes, 6 failed, an RTT violation", got)
	}
	got = *w.path(pathKey{src: w.rnicIdx["a"], dst: w.rnicIdx["c"]})
	if got.probes != 10 || got.failed != 10 || got.rttValid {
		t.Errorf("path a->c = %+v, want 10 probes, 10 failed (clamped), no RTT", got)
	}
	if rec := store.agents["a"]; rec.agentID != "host-a" {
		t.Errorf("agent of a = %q, want host-a", rec.agentID)
	}
	if _, known := store.agents["b"]; known {
		t.Error("b has an agent, but only reported as a target")
	}
}

// TestEvidenceStore_SourceStatesItsToR verifies that the ToR an RNIC's own
// agent reports wins over the one a prober copied from its pinglist.
func TestEvidenceStore_SourceStatesItsToR(t *testing.T) {
	store := newEvidenceStore(4, 100, 0)
	nowNs := windowEnd(0)
	// b is first seen as a target under an outdated ToR, then reports
	// itself, then is seen as a target again.
	for _, o := range []obs{
		{agent: "host-a", src: "a", srcTor: "tor-1", dst: "b", dstTor: "tor-old", total: 10},
		{agent: "host-b", src: "b", srcTor: "tor-new", dst: "a", dstTor: "tor-1", total: 10},
		{agent: "host-c", src: "c", srcTor: "tor-1", dst: "b", dstTor: "tor-old", total: 10},
	} {
		store.observe(o.agent, o.summary(0), nowNs)
	}
	w := store.windows[0]
	if got := w.tors[w.rnics[w.rnicIdx["b"]].tor]; got != "tor-new" {
		t.Errorf("ToR of b = %q, want tor-new (stated by its own agent)", got)
	}
}

// TestEvidenceStore_IsBounded verifies every bound of the store: the paths
// per window, the RNIC table of a full window, the number of windows, and
// the age and clock skew of a window.
func TestEvidenceStore_IsBounded(t *testing.T) {
	const maxPaths = 5
	store := newEvidenceStore(2, maxPaths, 0)
	nowNs := windowEnd(0)
	path := func(i int) obs {
		return obs{agent: "host", src: fmt.Sprintf("s%d", i), srcTor: "tor-1", dst: fmt.Sprintf("d%d", i), dstTor: "tor-2", total: 10}
	}

	dropped := 0
	for i := 0; i < 100; i++ {
		if store.observe("host", path(i).summary(0), nowNs) {
			dropped++
		}
	}
	w := store.windows[0]
	if len(w.pathKeys) != maxPaths || dropped != 100-maxPaths || store.stats.dropped != uint64(dropped) {
		t.Errorf("%d paths kept, %d dropped (stats %d); want %d kept, %d dropped",
			len(w.pathKeys), dropped, store.stats.dropped, maxPaths, 100-maxPaths)
	}
	// A full window refuses new paths without growing its RNIC table.
	if len(w.rnics) != 2*maxPaths {
		t.Errorf("RNIC table holds %d RNICs, want %d: a refused path must not intern its RNICs", len(w.rnics), 2*maxPaths)
	}
	// A path already kept is still updated.
	if store.observe("host", path(0).summary(0), nowNs) {
		t.Error("an update of a kept path was refused")
	}
	if got := w.path(pathKey{src: w.rnicIdx["s0"], dst: w.rnicIdx["d0"]}).probes; got != 20 {
		t.Errorf("probes of the updated path = %d, want 20", got)
	}

	// Windows: a span of 2 retains at most 2+extraRetainedWindows.
	limit := 2 + extraRetainedWindows
	for wi := 1; wi < 40; wi++ {
		store.observe("host", path(0).summary(wi), windowEnd(wi))
		if len(store.windows) > limit {
			t.Fatalf("%d windows retained after window %d, want at most %d", len(store.windows), wi, limit)
		}
	}
	for i := 1; i < len(store.windows); i++ {
		if store.windows[i-1].startNs >= store.windows[i].startNs {
			t.Fatal("windows are not sorted by start")
		}
	}

	// A window older than the span and its slack, one that starts more than
	// a window ahead of the controller's clock, and one without a duration
	// are not kept.
	before := len(store.windows)
	outOfRange := store.stats.outOfRange
	nowNs = windowEnd(39)
	store.observe("host", path(0).summary(39-limit-1), nowNs)
	store.observe("host", path(0).summary(42), nowNs)
	noDuration := path(0).summary(39)
	noDuration.WindowDurationMs = 0
	store.observe("host", noDuration, nowNs)
	if len(store.windows) != before || store.stats.outOfRange != outOfRange+3 {
		t.Errorf("%d windows (were %d), %d out of range (were %d); want no new window and 3 more out of range",
			len(store.windows), before, store.stats.outOfRange, outOfRange)
	}
}

// TestEvidenceStore_AgentsExpire verifies that the RNIC-to-agent table
// outlives the evidence span, so that a silent host is still one host, and
// that it does not grow without bound.
func TestEvidenceStore_AgentsExpire(t *testing.T) {
	store := newEvidenceStore(2, 100, 0)
	o := obs{agent: "host-a", src: "a", srcTor: "tor-1", dst: "b", dstTor: "tor-2", total: 10}
	store.observe(o.agent, o.summary(0), windowEnd(0))

	store.prune(windowEnd(0) + agentTTLNs)
	if _, known := store.agents["a"]; !known {
		t.Error("the agent of a expired before its TTL")
	}
	if len(store.windows) != 0 {
		t.Error("the window of the span was kept past its range")
	}
	store.prune(windowEnd(0) + agentTTLNs + 1)
	if _, known := store.agents["a"]; known {
		t.Error("the agent of a did not expire after its TTL")
	}
}

// TestLocalizer_LogsFindingTransitions verifies the finding logs: one line
// when a finding appears, none while it lasts, one when it clears, and the
// identities that never reach a metric.
func TestLocalizer_LogsFindingTransitions(t *testing.T) {
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2}, nil)
	var logs bytes.Buffer
	az.loc.logger = zerolog.New(&logs)
	ctx := context.Background()

	// gid-1-2 loses 20% on every path.
	window := meshWindow(3, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if (st == 1 && sr == 2) || (dt == 1 && dr == 2) {
			return 200
		}
		return 0
	})
	healthy := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })
	for w := 0; w < 3; w++ {
		ingestWindow(az, clock, w, window)
		clock.ns = windowClose(w)
		az.loc.evaluate(ctx)
	}
	for w := 3; w < 5; w++ {
		ingestWindow(az, clock, w, healthy)
		clock.ns = windowClose(w)
		az.loc.evaluate(ctx)
	}

	var appeared, cleared []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		switch ev["message"] {
		case "Fault localization finding":
			appeared = append(appeared, ev)
		case "Fault localization finding cleared":
			cleared = append(cleared, ev)
		}
	}
	if len(appeared) != 1 || len(cleared) != 1 {
		t.Fatalf("%d findings logged, %d cleared; want 1 and 1:\n%s", len(appeared), len(cleared), logs.String())
	}
	ev := appeared[0]
	for key, want := range map[string]any{
		"level": "warn", "kind": KindLoss, "state": StateLocalized, "component": ComponentRNIC,
		"tor": "tor-1", "gid": "gid-1-2", "agent_id": "host-1-2",
	} {
		if ev[key] != want {
			t.Errorf("finding log: %s = %v, want %v", key, ev[key], want)
		}
	}
	for _, key := range []string{"confidence", "excess_ratio", "evidence_nats", "paths", "failed_paths", "trials", "events", "windows"} {
		if _, ok := ev[key]; !ok {
			t.Errorf("finding log has no %s field", key)
		}
	}
	if cleared[0]["level"] != "info" || cleared[0]["gid"] != "gid-1-2" {
		t.Errorf("cleared log = %v, want level info for gid-1-2", cleared[0])
	}
}

// TestLocalizer_LogsCandidatesAndMembers verifies the log fields of an
// ambiguous finding (its candidates) and of a folded one (its members).
func TestLocalizer_LogsCandidatesAndMembers(t *testing.T) {
	render := func(f Finding) map[string]any {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		logFindingFields(logger.Warn(), f).Msg("x")
		var ev map[string]any
		if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
			t.Fatalf("log line is not JSON: %q", buf.String())
		}
		return ev
	}

	ambiguous := Finding{Signal: KindLoss, State: StateAmbiguous, Suspects: []Suspect{
		{Component: Component{Kind: ComponentTorUplink, Tor: "tor-1"}, Confidence: 0.5},
		{Component: Component{Kind: ComponentTor, Tor: "tor-1"}, Confidence: 0.5},
	}}
	ev := render(ambiguous)
	candidates, ok := ev["candidates"].([]any)
	if !ok || len(candidates) != 2 {
		t.Fatalf("candidates = %v, want two", ev["candidates"])
	}
	second := candidates[1].(map[string]any)
	if second["component"] != ComponentTor || second["tor"] != "tor-1" || second["confidence"] != 0.5 {
		t.Errorf("second candidate = %v", second)
	}
	if ev["candidates_truncated"] != false {
		t.Errorf("candidates_truncated = %v, want false", ev["candidates_truncated"])
	}

	folded := Finding{Signal: KindRTT, State: StateNotLocalizable,
		Suspects: []Suspect{{Component: Component{Kind: ComponentRail, Rail: "rail0"}, Confidence: 1}},
		Members:  []string{"tor-1", "tor-2"}, MemberCount: 7}
	ev = render(folded)
	if ev["component"] != ComponentRail || ev["rail"] != "rail0" || ev["member_count"] != float64(7) {
		t.Errorf("folded finding log = %v", ev)
	}
	if members, ok := ev["members"].([]any); !ok || len(members) != 2 {
		t.Errorf("members = %v, want two", ev["members"])
	}
	if _, has := ev["candidates"]; has {
		t.Error("a finding with one suspect logs candidates")
	}
}

// TestLocalizer_ConcurrentIngestAndEvaluate runs reports and evaluations
// at the same time, as the gRPC handlers and the localization loop do. Run
// with the race detector, it verifies the locking.
func TestLocalizer_ConcurrentIngestAndEvaluate(t *testing.T) {
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2}, nil)
	// A fixed clock, late enough that windows 0 and 1 are closed while
	// their reports still arrive (late reports).
	clock.ns = windowClose(1)
	window := lossyTor0()

	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < len(window); i += 4 {
				for w := 0; w < 2; w++ {
					az.Ingest(context.Background(), report(window[i].summary(w)))
				}
			}
		}(worker)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			az.loc.evaluate(context.Background())
			_ = az.loc.currentFindings()
		}
	}()
	wg.Wait()

	az.loc.evaluate(context.Background())
	requireLocalized(t, az.loc.currentFindings(), KindLoss, "tor/tor-0")
}

// TestAnalyzer_RunLocalizationStops verifies that the localization loop
// ends when its context is cancelled.
func TestAnalyzer_RunLocalizationStops(t *testing.T) {
	az, _ := newTestLocalizer(t, LocalizationConfig{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		az.RunLocalization(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunLocalization did not stop when its context was cancelled")
	}
}

// TestLocalizer_WarnsAboutWeakEvidence verifies the two warnings about
// evidence that is weaker than it could be: ToRs that report but are not in
// the topology file, and paths dropped at the cap. Each is logged when its
// extent changes, not on every evaluation.
func TestLocalizer_WarnsAboutWeakEvidence(t *testing.T) {
	topo, err := ParseTopology([]byte("version: 1\ntors: {tor-0: {rail: rail0}, tor-typo: {rail: rail0}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	// The mesh has 132 paths; the cap leaves 32 of them out of each window.
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2, Topology: topo, MaxPathsPerWindow: 100}, nil)
	var logs bytes.Buffer
	az.loc.logger = zerolog.New(&logs)
	healthy := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })

	count := func(message string) (n int, last map[string]any) {
		for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			var ev map[string]any
			if json.Unmarshal([]byte(line), &ev) == nil && strings.HasPrefix(ev["message"].(string), message) {
				n++
				last = ev
			}
		}
		return n, last
	}
	for w := 0; w < 3; w++ {
		ingestWindow(az, clock, w, healthy)
		clock.ns = windowClose(w)
		az.loc.evaluate(context.Background())
	}

	// tor-1 and tor-2 report and are not listed: one warning, although
	// three evaluations saw them.
	n, ev := count("ToRs report paths but have no rail or spine group")
	if n != 1 {
		t.Fatalf("%d warnings about unlisted ToRs, want 1:\n%s", n, logs.String())
	}
	if tors := fmt.Sprint(ev["tors"]); tors != "[tor-1 tor-2]" || ev["tor_count"] != float64(2) {
		t.Errorf("unlisted ToRs warning = %v", ev)
	}
	// Each window dropped 32 paths before it was evaluated: one warning per
	// evaluation that saw new drops.
	n, ev = count("Path summaries were left out of the localization evidence")
	if n != 3 || ev["dropped_paths"] != float64(32) || ev["max_paths_per_window"] != float64(100) {
		t.Errorf("%d warnings about dropped paths, last %v; want 3 of 32 paths each", n, ev)
	}

	// Without a topology file, no ToR is "unlisted".
	az, clock = newTestLocalizer(t, LocalizationConfig{Windows: 2}, nil)
	logs.Reset()
	az.loc.logger = zerolog.New(&logs)
	ingestWindow(az, clock, 0, healthy)
	clock.ns = windowClose(0)
	az.loc.evaluate(context.Background())
	if strings.Contains(logs.String(), `"level":"warn"`) {
		t.Errorf("warnings without a topology file and below the cap:\n%s", logs.String())
	}
}

// TestLocalizer_MixedWindowLengths verifies what happens when one agent
// reports windows of another length than the rest (a misconfigured
// analysis_window_sec): its windows are not pooled with the others, they do
// not push the others' evidence out of the store although there are many
// more of them, and the finding on the fleet's evidence is unchanged.
func TestLocalizer_MixedWindowLengths(t *testing.T) {
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2}, nil)
	var logs bytes.Buffer
	az.loc.logger = zerolog.New(&logs)
	ctx := context.Background()

	// The odd agent reports 10 s windows, three per window of the fleet,
	// each with one path between two ToRs of its own, a few seconds after
	// each of them ends.
	const oddMs = 10_000
	odd := func(i int) *controller_agent.PathSummary {
		return &controller_agent.PathSummary{
			SourceGid: "odd-a", SourceTorId: "tor-odd-1", TargetGid: "odd-b", TargetTorId: "tor-odd-2",
			ProbeTotal: 10, ProbeFailed: 10,
			WindowStartUnixNs: testBaseStartNs + uint64(i)*oddMs*1_000_000,
			WindowDurationMs:  oddMs,
		}
	}
	for w := 0; w < 3; w++ {
		for i := 3 * w; i < 3*(w+1); i++ {
			clock.ns = testBaseStartNs + uint64(i+1)*oddMs*1_000_000 + 2*uint64(time.Second)
			az.Ingest(ctx, &controller_agent.ProbeAnalysisReport{AgentId: "odd", Summaries: []*controller_agent.PathSummary{odd(i)}})
		}
		ingestWindow(az, clock, w, lossyTor0())
		// The odd agent keeps reporting while the fleet's window waits for
		// its grace period.
		for i := 3 * (w + 1); i < 3*(w+1)+4; i++ {
			clock.ns = testBaseStartNs + uint64(i+1)*oddMs*1_000_000 + 2*uint64(time.Second)
			az.Ingest(ctx, &controller_agent.ProbeAnalysisReport{AgentId: "odd", Summaries: []*controller_agent.PathSummary{odd(i)}})
		}
		clock.ns = windowClose(w)
		az.loc.evaluate(ctx)
	}

	requireLocalized(t, az.loc.currentFindings(), KindLoss, "tor/tor-0")
	store := az.loc.store
	if store.windowNs != testWindowNs {
		t.Errorf("window length in use = %d ns, want the fleet's %d ns", store.windowNs, testWindowNs)
	}
	if got := len(store.windows); got > 2+extraRetainedWindows {
		t.Errorf("%d windows retained, want at most %d", got, 2+extraRetainedWindows)
	}
	fleet := 0
	for _, w := range store.windows {
		if w.durNs == testWindowNs {
			fleet++
			if len(w.pathKeys) != len(lossyTor0()) {
				t.Errorf("fleet window at %d holds %d paths, want %d", w.startNs, len(w.pathKeys), len(lossyTor0()))
			}
		}
	}
	if fleet != 3 {
		t.Errorf("%d windows of the fleet's length retained, want all 3", fleet)
	}
	if n := strings.Count(logs.String(), "Agents report windows of different lengths"); n != 1 {
		t.Errorf("%d warnings about mixed window lengths, want 1:\n%s", n, logs.String())
	}
}

// TestEvidenceStore_WindowLengthFollowsTheMajority verifies that the window
// length in use is the one with the most paths, whichever arrived first.
func TestEvidenceStore_WindowLengthFollowsTheMajority(t *testing.T) {
	store := newEvidenceStore(2, 1000, 0)
	nowNs := windowEnd(0)
	short := obs{agent: "odd", src: "odd-a", srcTor: "tor-1", dst: "odd-b", dstTor: "tor-2", total: 10}.summary(0)
	short.WindowDurationMs = 10_000
	store.observe("odd", short, nowNs)
	if store.windowNs != 10*uint64(time.Second) {
		t.Fatalf("window length = %d ns, want that of the first summary", store.windowNs)
	}
	for _, o := range lossyTor0() {
		store.observe(o.agent, o.summary(0), nowNs)
	}
	store.prune(nowNs)
	if store.windowNs != testWindowNs {
		t.Errorf("window length = %d ns, want the majority's %d ns", store.windowNs, testWindowNs)
	}
	windows, otherPaths := store.span(windowClose(0))
	if len(windows) != 1 || windows[0].durNs != testWindowNs || otherPaths != 1 {
		t.Errorf("span = %d windows, %d paths of other lengths; want the fleet's window and 1 path left out", len(windows), otherPaths)
	}
}

// TestEvidenceStore_RefusesUnalignedWindows verifies that a window that does
// not start on a multiple of its length is refused. Agents align their
// windows, so such a window comes from no agent, and it must neither open a
// window of its own nor take the place of an agents' window in the store.
func TestEvidenceStore_RefusesUnalignedWindows(t *testing.T) {
	store := newEvidenceStore(4, 1000, 0)
	nowNs := windowEnd(9)
	o := obs{agent: "host-a", src: "a", srcTor: "tor-0", dst: "b", dstTor: "tor-1", total: 100, failed: 5}
	for w := 0; w < 10; w++ {
		store.observe(o.agent, o.summary(w), nowNs)
	}
	if len(store.windows) != 10 || store.stats.outOfRange != 0 {
		t.Fatalf("aligned windows: %d retained, %d out of range; want 10 and 0", len(store.windows), store.stats.outOfRange)
	}
	for i := 1; i <= 10; i++ {
		s := o.summary(9)
		s.WindowStartUnixNs += uint64(i) * uint64(time.Millisecond)
		store.observe("host-b", s, nowNs)
	}
	if store.stats.outOfRange != 10 {
		t.Errorf("out of range: %d, want the 10 unaligned summaries", store.stats.outOfRange)
	}
	for w, win := range store.windows {
		if want := testBaseStartNs + uint64(w)*testWindowNs; win.startNs != want {
			t.Errorf("retained window %d starts at %d, want the agents' window at %d", w, win.startNs, want)
		}
	}
}

// TestLocalizer_SpanHoldsAtMostItsWindows verifies, for the longest spans
// the settings allow, that an evaluation takes no more windows than the span
// is configured to hold and does not fail, when summaries arrive for windows
// that start half a window apart: every second one is unaligned.
func TestLocalizer_SpanHoldsAtMostItsWindows(t *testing.T) {
	for _, windows := range []int{1, 58, 59, MaxLocalizationWindows} {
		t.Run(fmt.Sprintf("windows=%d", windows), func(t *testing.T) {
			az, clock := newTestLocalizer(t, LocalizationConfig{Windows: windows}, nil)
			n := 2 * (windows + extraRetainedWindows)
			clock.ns = testBaseStartNs + uint64(n/2+1)*testWindowNs
			for i := 0; i < n; i++ {
				var sums []*controller_agent.PathSummary
				for d := 0; d < 4; d++ {
					s := obs{src: "a", srcTor: "tor-0", dst: fmt.Sprintf("b%d", d), dstTor: "tor-1", total: 30, failed: 10}.summary(0)
					s.WindowStartUnixNs = testBaseStartNs + uint64(i)*testWindowNs/2
					sums = append(sums, s)
				}
				az.Ingest(context.Background(), &controller_agent.ProbeAnalysisReport{AgentId: "host-a", Summaries: sums})
			}
			store := az.loc.store
			if len(store.windows) > windows+extraRetainedWindows {
				t.Fatalf("%d windows retained, want at most %d", len(store.windows), windows+extraRetainedWindows)
			}
			clock.ns += testWindowNs + closeMarginNs
			span, _ := store.span(clock.ns)
			if len(span) != windows {
				t.Fatalf("the span holds %d windows, want %d", len(span), windows)
			}
			if !az.loc.evaluate(context.Background()) {
				t.Fatal("did not evaluate")
			}
			checkFindingInvariants(t, az.loc.currentFindings(), DefaultLocalizationMinConfidence)
		})
	}
}

// TestBuildSpan_HoldsAtMostOneWindowPerMaskBit verifies that pooling takes
// the newest MaxLocalizationWindows windows when it is handed more: a path
// keeps one bit per window.
func TestBuildSpan_HoldsAtMostOneWindowPerMaskBit(t *testing.T) {
	const extra = 6
	var snaps []*windowSnapshot
	for w := 0; w < MaxLocalizationWindows+extra; w++ {
		store := newEvidenceStore(1, 1000, 0)
		// Only the windows that are cut off hold the path a -> old.
		dst := "new"
		if w < extra {
			dst = "old"
		}
		for d := 0; d < 3; d++ {
			o := obs{agent: "host-a", src: "a", srcTor: "tor-0", dst: fmt.Sprintf("%s%d", dst, d), dstTor: "tor-1", total: 30, failed: 30}
			store.observe(o.agent, o.summary(w), windowEnd(w))
		}
		snaps = append(snaps, store.snapshots(windowClose(w))...)
	}
	if len(snaps) != MaxLocalizationWindows+extra {
		t.Fatalf("%d snapshots, want %d", len(snaps), MaxLocalizationWindows+extra)
	}
	sp := buildSpan(snaps, nil)
	if sp.windows != MaxLocalizationWindows || len(sp.lossEvents) != MaxLocalizationWindows {
		t.Fatalf("the span holds %d windows (%d event lists), want %d", sp.windows, len(sp.lossEvents), MaxLocalizationWindows)
	}
	for _, r := range sp.rnics {
		if strings.HasPrefix(r.gid, "old") {
			t.Errorf("RNIC %s of a window that was cut off is in the span", r.gid)
		}
	}
	p := solverParams{baseline: DefaultLocalizationBaselineLossRatio, minConfidence: DefaultLocalizationMinConfidence, spanWindows: MaxLocalizationWindows}
	checkFindingInvariants(t, localize(sp, p, p), p.minConfidence)
}

// TestLocalizer_EvaluationSurvivesAPanic verifies that a panic during an
// evaluation does not escape the localizer's loop, that it is logged, and
// that the findings of the previous evaluation are withdrawn.
func TestLocalizer_EvaluationSurvivesAPanic(t *testing.T) {
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2}, nil)
	var logs bytes.Buffer
	az.loc.logger = zerolog.New(&logs)
	for w := 0; w < 2; w++ {
		ingestWindow(az, clock, w, lossyTor0())
	}
	clock.ns = windowClose(1)
	az.loc.evaluateRecovering(context.Background())
	if len(az.loc.currentFindings()) == 0 {
		t.Fatal("no finding to withdraw: the test needs one")
	}

	az.loc.now = func() time.Time { panic("defect in the inference") }
	az.loc.evaluateRecovering(context.Background())
	if got := az.loc.currentFindings(); len(got) != 0 {
		t.Errorf("findings after a failed evaluation:%s", describeFindings(got))
	}
	if !strings.Contains(logs.String(), "defect in the inference") || !strings.Contains(logs.String(), `"level":"error"`) {
		t.Errorf("the panic is not logged as an error: %s", logs.String())
	}

	// The next evaluation works again.
	az.loc.now = clock.now
	ingestWindow(az, clock, 2, lossyTor0())
	clock.ns = windowClose(2)
	az.loc.evaluateRecovering(context.Background())
	if len(az.loc.currentFindings()) == 0 {
		t.Error("no findings from the evaluation after the failed one")
	}
}
