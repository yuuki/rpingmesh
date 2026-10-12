package pinglist

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// railFabric models a rail-optimized cluster of four hosts with two RNICs
// each: mlx5_0 is on rail0 and mlx5_1 on rail1, every rail has two leaves, and
// rails are not routed to each other (so cross-rail probes always time out).
func railFabric() []*controller_agent.RnicInfo {
	rnic := func(gid, host, tor, plane string) *controller_agent.RnicInfo {
		return &controller_agent.RnicInfo{Gid: gid, HostName: host, TorId: tor, PlaneId: plane}
	}
	return []*controller_agent.RnicInfo{
		rnic("fe80::10", "host-1", "leaf-r0-a", "rail0"),
		rnic("fe80::11", "host-1", "leaf-r1-a", "rail1"),
		rnic("fe80::20", "host-2", "leaf-r0-a", "rail0"),
		rnic("fe80::21", "host-2", "leaf-r1-a", "rail1"),
		rnic("fe80::30", "host-3", "leaf-r0-b", "rail0"),
		rnic("fe80::31", "host-3", "leaf-r1-b", "rail1"),
		rnic("fe80::40", "host-4", "leaf-r0-b", "rail0"),
		rnic("fe80::41", "host-4", "leaf-r1-b", "rail1"),
	}
}

func planeOf(all []*controller_agent.RnicInfo) map[string]string {
	m := make(map[string]string, len(all))
	for _, r := range all {
		m[r.GetGid()] = r.GetPlaneId()
	}
	return m
}

func targetToRs(targets []*controller_agent.PingTarget) []string {
	seen := map[string]bool{}
	var tors []string
	for _, t := range targets {
		if !seen[t.GetTargetTorId()] {
			seen[t.GetTargetTorId()] = true
			tors = append(tors, t.GetTargetTorId())
		}
	}
	sort.Strings(tors)
	return tors
}

// captureLogs redirects the global logger into a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = old })
	return &buf
}

func TestInterTor_RestrictedToRegisteredPlane(t *testing.T) {
	all := railFabric()
	src := &fakeRnicSource{
		all:           all,
		hostnameByGID: map[string]string{"fe80::10": "host-1"},
		planeByGID:    map[string]string{"fe80::10": "rail0"},
	}
	targets, err := newTestGenerator(src).GenerateInterTorPinglist(context.Background(), "fe80::10", "leaf-r0-a", "")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if got, want := targetToRs(targets), []string{"leaf-r0-b"}; !equalStrings(got, want) {
		t.Errorf("sampled ToRs = %v, want %v (only rail0 leaves)", got, want)
	}
	planes := planeOf(all)
	for _, tgt := range targets {
		if planes[tgt.GetTargetGid()] != "rail0" {
			t.Errorf("target %s is on plane %q, want rail0", tgt.GetTargetGid(), planes[tgt.GetTargetGid()])
		}
	}
}

// TestInterTor_EmptyPlaneKeepsLegacyBehavior checks full backward
// compatibility: a requester without a plane samples every foreign ToR, of
// every plane, exactly as before plane support.
func TestInterTor_EmptyPlaneKeepsLegacyBehavior(t *testing.T) {
	src := &fakeRnicSource{
		all:           railFabric(),
		hostnameByGID: map[string]string{"fe80::10": "host-1"},
	}
	targets, err := newTestGenerator(src).GenerateInterTorPinglist(context.Background(), "fe80::10", "leaf-r0-a", "")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if got, want := targetToRs(targets), []string{"leaf-r0-b", "leaf-r1-a", "leaf-r1-b"}; !equalStrings(got, want) {
		t.Errorf("sampled ToRs = %v, want %v (no plane restriction)", got, want)
	}
}

// TestInterTor_PlanedRequesterSkipsPlanelessTargets checks a partially
// upgraded fleet: a requester with a plane does not sample RNICs registered
// without one (by an older agent), since nothing says they are reachable
// from its plane.
func TestInterTor_PlanedRequesterSkipsPlanelessTargets(t *testing.T) {
	all := railFabric()
	// host-4's agent is old: its RNICs registered without a plane.
	for _, r := range all {
		if r.GetHostName() == "host-4" {
			r.PlaneId = ""
		}
	}
	src := &fakeRnicSource{
		all:           all,
		hostnameByGID: map[string]string{"fe80::10": "host-1"},
		planeByGID:    map[string]string{"fe80::10": "rail0"},
	}
	targets, err := newTestGenerator(src).GenerateInterTorPinglist(context.Background(), "fe80::10", "leaf-r0-a", "")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if got, want := targetGIDs(targets), []string{"fe80::30"}; !equalStrings(got, want) {
		t.Errorf("targets = %v, want %v (plane-less fe80::40 excluded)", got, want)
	}
}

func TestResolveRequester_PlaneSources(t *testing.T) {
	cases := []struct {
		name         string
		planeByGID   map[string]string
		requestPlane string
		wantPlane    string
		wantSource   string
	}{
		{"registry wins over request", map[string]string{"fe80::10": "rail0"}, "rail1", "rail0", planeSourceRegistry},
		{"unregistered uses request", nil, " rail1 ", "rail1", planeSourceRequest},
		{"registered without plane uses request", map[string]string{"fe80::10": ""}, "rail1", "rail1", planeSourceRequest},
		{"no plane anywhere", map[string]string{"fe80::10": ""}, "", "", planeSourceNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gen := newTestGenerator(&fakeRnicSource{planeByGID: tc.planeByGID})
			rc := gen.resolveRequester(context.Background(), "fe80::10", tc.requestPlane)
			if rc.plane != tc.wantPlane || rc.planeSource != tc.wantSource {
				t.Errorf("plane = %q (%s), want %q (%s)", rc.plane, rc.planeSource, tc.wantPlane, tc.wantSource)
			}
		})
	}
}

// TestInterTor_RequestPlaneFallback checks that an unregistered requester is
// restricted by the plane carried in its request.
func TestInterTor_RequestPlaneFallback(t *testing.T) {
	all := railFabric()
	src := &fakeRnicSource{all: all}
	targets, err := newTestGenerator(src).GenerateInterTorPinglist(context.Background(), "fe80::11", "leaf-r1-a", "rail1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if got, want := targetToRs(targets), []string{"leaf-r1-b"}; !equalStrings(got, want) {
		t.Errorf("sampled ToRs = %v, want %v", got, want)
	}
}

// TestInterTor_LookupErrorUsesRequestPlane checks graceful degradation: a
// registry lookup failure still applies the requested plane.
func TestInterTor_LookupErrorUsesRequestPlane(t *testing.T) {
	src := &fakeRnicSource{all: railFabric(), resolveErr: errFakeRegistry}
	targets, err := newTestGenerator(src).GenerateInterTorPinglist(context.Background(), "fe80::10", "leaf-r0-a", "rail0")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if got, want := targetToRs(targets), []string{"leaf-r0-b"}; !equalStrings(got, want) {
		t.Errorf("sampled ToRs = %v, want %v", got, want)
	}
}

func untaggedRailFabric() []*controller_agent.RnicInfo {
	all := railFabric()
	for _, r := range all {
		r.TorId = ""
	}
	return all
}

func TestUnspecifiedMesh_RestrictedToPlane(t *testing.T) {
	src := &fakeRnicSource{
		all:           untaggedRailFabric(),
		hostnameByGID: map[string]string{"fe80::10": "host-1"},
		planeByGID:    map[string]string{"fe80::10": "rail0"},
	}
	targets, err := newTestGenerator(src).GenerateTorMeshPinglist(context.Background(), "fe80::10", "", "")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if got, want := targetGIDs(targets), []string{"fe80::20", "fe80::30", "fe80::40"}; !equalStrings(got, want) {
		t.Errorf("untagged mesh = %v, want %v (same plane, other hosts)", got, want)
	}
}

// TestUnspecifiedMesh_CapAppliesAfterPlaneFilter checks that the cap keeps
// only same-plane targets instead of spending slots on unreachable ones.
func TestUnspecifiedMesh_CapAppliesAfterPlaneFilter(t *testing.T) {
	src := &fakeRnicSource{
		all:           untaggedRailFabric(),
		hostnameByGID: map[string]string{"fe80::11": "host-1"},
		planeByGID:    map[string]string{"fe80::11": "rail1"},
	}
	gen := NewPinglistGenerator(src, ECMPConfig{PathsAssumed: 16, CoverageProbability: 0.9, MaxFlowLabels: 64},
		DefaultInterTorSampleSize, 2)
	for i := 0; i < 20; i++ {
		targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::11", "", "")
		if err != nil {
			t.Fatalf("GenerateTorMeshPinglist: %v", err)
		}
		if len(targets) != 2 {
			t.Fatalf("got %d targets, want 2 (cap)", len(targets))
		}
		for _, tgt := range targets {
			if !strings.HasSuffix(tgt.GetTargetGid(), "1") {
				t.Fatalf("target %s is not on rail1", tgt.GetTargetGid())
			}
		}
	}
}

func TestUnspecifiedMesh_EmptyPlaneKeepsLegacyBehavior(t *testing.T) {
	src := &fakeRnicSource{
		all:           untaggedRailFabric(),
		hostnameByGID: map[string]string{"fe80::10": "host-1"},
	}
	targets, err := newTestGenerator(src).GenerateTorMeshPinglist(context.Background(), "fe80::10", "", "")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if len(targets) != 6 {
		t.Errorf("got %d targets, want 6 (every other host's RNICs, any plane)", len(targets))
	}
}

// TestNamedTorMesh_NotPlaneFilteredButWarnsOnMix checks that a named
// ToR-mesh is generated as before even when its RNICs disagree on the plane,
// and that the disagreement is logged.
func TestNamedTorMesh_NotPlaneFilteredButWarnsOnMix(t *testing.T) {
	logs := captureLogs(t)
	src := &fakeRnicSource{
		all: []*controller_agent.RnicInfo{
			{Gid: "fe80::10", HostName: "host-1", TorId: "leaf-a", PlaneId: "rail0"},
			{Gid: "fe80::20", HostName: "host-2", TorId: "leaf-a", PlaneId: "rail1"},
			{Gid: "fe80::30", HostName: "host-3", TorId: "leaf-a", PlaneId: ""},
		},
		hostnameByGID: map[string]string{"fe80::10": "host-1"},
		planeByGID:    map[string]string{"fe80::10": "rail0"},
	}
	targets, err := newTestGenerator(src).GenerateTorMeshPinglist(context.Background(), "fe80::10", "leaf-a", "")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if got, want := targetGIDs(targets), []string{"fe80::20", "fe80::30"}; !equalStrings(got, want) {
		t.Errorf("ToR-mesh = %v, want %v (no plane filter)", got, want)
	}
	out := logs.String()
	if !strings.Contains(out, "RNICs of one ToR report different planes") ||
		!strings.Contains(out, `"planeIDs":["rail0","rail1"]`) {
		t.Errorf("missing mixed-plane warning; logs:\n%s", out)
	}
}

func TestNamedTorMesh_NoWarningForSinglePlane(t *testing.T) {
	logs := captureLogs(t)
	src := &fakeRnicSource{
		all: []*controller_agent.RnicInfo{
			{Gid: "fe80::10", HostName: "host-1", TorId: "leaf-a", PlaneId: "rail0"},
			{Gid: "fe80::20", HostName: "host-2", TorId: "leaf-a", PlaneId: "rail0"},
			{Gid: "fe80::30", HostName: "host-3", TorId: "leaf-a", PlaneId: ""}, // old agent
		},
	}
	if _, err := newTestGenerator(src).GenerateTorMeshPinglist(context.Background(), "fe80::10", "leaf-a", ""); err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if strings.Contains(logs.String(), "different planes") {
		t.Errorf("unexpected mixed-plane warning; logs:\n%s", logs.String())
	}
}

// TestPinglistLogsIncludePlane checks that generated-pinglist logs carry the
// requester's plane and where it came from.
func TestPinglistLogsIncludePlane(t *testing.T) {
	logs := captureLogs(t)
	src := &fakeRnicSource{all: railFabric(), planeByGID: map[string]string{"fe80::10": "rail0"}}
	if _, err := newTestGenerator(src).GenerateInterTorPinglist(context.Background(), "fe80::10", "leaf-r0-a", ""); err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if !strings.Contains(logs.String(), `"planeID":"rail0","planeSource":"registry"`) {
		t.Errorf("inter-ToR log lacks plane fields:\n%s", logs.String())
	}
}
