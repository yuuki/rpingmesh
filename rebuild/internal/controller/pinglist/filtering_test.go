package pinglist

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// targetGIDs returns the sorted TargetGid values of the given targets so tests
// can assert on the exact set of RNICs a pinglist paired the requester with,
// independent of ordering.
func targetGIDs(targets []*controller_agent.PingTarget) []string {
	gids := make([]string, 0, len(targets))
	for _, t := range targets {
		gids = append(gids, t.GetTargetGid())
	}
	sort.Strings(gids)
	return gids
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestTorMesh_SameHostExclusion verifies issue #39: when the requester is
// registered, every RNIC on its own host (not just its own GID) is excluded
// from the ToR-mesh pinglist, while RNICs on other hosts in the same ToR are
// kept. Same-host probes can hairpin without reaching the fabric, so their RTTs
// would skew ToR-level aggregates.
func TestTorMesh_SameHostExclusion(t *testing.T) {
	src := &fakeRnicSource{
		torMesh: []*controller_agent.RnicInfo{
			{Gid: "fe80::1", HostName: "host-a", TorId: "tor-1"}, // requester (self)
			{Gid: "fe80::2", HostName: "host-a", TorId: "tor-1"}, // same host, other rail
			{Gid: "fe80::3", HostName: "host-b", TorId: "tor-1"}, // different host
			{Gid: "fe80::4", HostName: "host-b", TorId: "tor-1"}, // different host
		},
		hostnameByGID: map[string]string{"fe80::1": "host-a"},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	got := targetGIDs(targets)
	want := []string{"fe80::3", "fe80::4"}
	if !equalStrings(got, want) {
		t.Errorf("targets = %v, want %v (self and same-host RNIC excluded)", got, want)
	}
}

// TestTorMesh_UnregisteredRequesterFallsBackToGID verifies that when the
// requester is not registered (hostname unknown), the generator falls back to
// GID self-exclusion only: it can no longer identify same-host RNICs, so a
// sibling NIC on the same host is (unavoidably) kept, but the request still
// succeeds rather than failing.
func TestTorMesh_UnregisteredRequesterFallsBackToGID(t *testing.T) {
	src := &fakeRnicSource{
		torMesh: []*controller_agent.RnicInfo{
			{Gid: "fe80::1", HostName: "host-a", TorId: "tor-1"}, // requester (self)
			{Gid: "fe80::2", HostName: "host-a", TorId: "tor-1"}, // same host, but unknowable
			{Gid: "fe80::3", HostName: "host-b", TorId: "tor-1"},
		},
		// hostnameByGID is empty: the requester is not registered.
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	got := targetGIDs(targets)
	want := []string{"fe80::2", "fe80::3"} // only the requester's own GID is excluded
	if !equalStrings(got, want) {
		t.Errorf("targets = %v, want %v (only self excluded on fallback)", got, want)
	}
}

// TestTorMesh_ResolveErrorDegradesGracefully verifies that a hostname-lookup
// failure does not fail the pinglist request: it degrades to GID self-exclusion
// (same as the unregistered case) so the requester still receives a pinglist.
func TestTorMesh_ResolveErrorDegradesGracefully(t *testing.T) {
	src := &fakeRnicSource{
		torMesh: []*controller_agent.RnicInfo{
			{Gid: "fe80::1", HostName: "host-a", TorId: "tor-1"}, // requester (self)
			{Gid: "fe80::2", HostName: "host-a", TorId: "tor-1"},
			{Gid: "fe80::3", HostName: "host-b", TorId: "tor-1"},
		},
		resolveErr: errors.New("rqlite unreachable"),
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist must not fail on a hostname-lookup error: %v", err)
	}
	got := targetGIDs(targets)
	want := []string{"fe80::2", "fe80::3"} // self excluded via GID fallback
	if !equalStrings(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

// TestTorMesh_CrossFamilyExclusion verifies issue #41 in both directions: a
// native-IPv6 requester never probes an IPv4-mapped target and vice versa,
// while same-family targets are preserved. A cross-family probe fails at
// ibv_create_ah() before reaching the wire.
func TestTorMesh_CrossFamilyExclusion(t *testing.T) {
	cases := []struct {
		name         string
		requesterGID string
		torMesh      []*controller_agent.RnicInfo
		want         []string
	}{
		{
			name:         "ipv6_requester_skips_ipv4_mapped",
			requesterGID: "fe80::1",
			torMesh: []*controller_agent.RnicInfo{
				{Gid: "fe80::2", HostName: "host-b", TorId: "tor-1"},         // same family (ipv6) -> kept
				{Gid: "::ffff:10.0.0.2", HostName: "host-c", TorId: "tor-1"}, // cross family -> skipped
				{Gid: "fe80::3", HostName: "host-d", TorId: "tor-1"},         // same family -> kept
			},
			want: []string{"fe80::2", "fe80::3"},
		},
		{
			name:         "ipv4_mapped_requester_skips_ipv6",
			requesterGID: "::ffff:10.0.0.1",
			torMesh: []*controller_agent.RnicInfo{
				{Gid: "fe80::2", HostName: "host-b", TorId: "tor-1"},         // cross family -> skipped
				{Gid: "::ffff:10.0.0.3", HostName: "host-c", TorId: "tor-1"}, // same family -> kept
				{Gid: "::ffff:10.0.0.4", HostName: "host-d", TorId: "tor-1"}, // same family -> kept
			},
			want: []string{"::ffff:10.0.0.3", "::ffff:10.0.0.4"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeRnicSource{torMesh: tc.torMesh}
			gen := newTestGenerator(src)

			targets, err := gen.GenerateTorMeshPinglist(context.Background(), tc.requesterGID, "tor-1")
			if err != nil {
				t.Fatalf("GenerateTorMeshPinglist: %v", err)
			}
			got := targetGIDs(targets)
			if !equalStrings(got, tc.want) {
				t.Errorf("targets = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTorMesh_UnparseableGIDHandling verifies the deliberate "unknown is its
// own family" rule: an unparseable requester GID pairs only with equally
// unparseable targets (preserving prior behavior for such GIDs), and never with
// a parseable one; conversely a parseable requester never pairs with an
// unparseable target. Production GIDs always parse, so this is defensive.
func TestTorMesh_UnparseableGIDHandling(t *testing.T) {
	t.Run("unparseable_requester_pairs_only_with_unparseable", func(t *testing.T) {
		src := &fakeRnicSource{
			torMesh: []*controller_agent.RnicInfo{
				{Gid: "fe80::2", HostName: "host-b", TorId: "tor-1"},   // parseable -> skipped
				{Gid: "also-junk", HostName: "host-c", TorId: "tor-1"}, // unparseable -> kept
			},
		}
		gen := newTestGenerator(src)

		targets, err := gen.GenerateTorMeshPinglist(context.Background(), "junk-gid", "tor-1")
		if err != nil {
			t.Fatalf("GenerateTorMeshPinglist: %v", err)
		}
		got := targetGIDs(targets)
		want := []string{"also-junk"}
		if !equalStrings(got, want) {
			t.Errorf("targets = %v, want %v", got, want)
		}
	})

	t.Run("parseable_requester_skips_unparseable_target", func(t *testing.T) {
		src := &fakeRnicSource{
			torMesh: []*controller_agent.RnicInfo{
				{Gid: "fe80::2", HostName: "host-b", TorId: "tor-1"}, // same family -> kept
				{Gid: "junk", HostName: "host-c", TorId: "tor-1"},    // unparseable -> skipped
			},
		}
		gen := newTestGenerator(src)

		targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
		if err != nil {
			t.Fatalf("GenerateTorMeshPinglist: %v", err)
		}
		got := targetGIDs(targets)
		want := []string{"fe80::2"}
		if !equalStrings(got, want) {
			t.Errorf("targets = %v, want %v", got, want)
		}
	})
}

// TestInterTor_SameHostExcludedBeforeSampling verifies issue #39 for
// rail-optimized fabrics (a host's NICs register under different ToR IDs) AND
// that coverage is preserved: even though the same-host RNIC in tor-2 is
// listed first, filtering happens before per-ToR sampling, so tor-2 is still
// represented by its valid different-host RNIC instead of being dropped.
func TestInterTor_SameHostExcludedBeforeSampling(t *testing.T) {
	src := &fakeRnicSource{
		interTor: []*controller_agent.RnicInfo{
			// tor-2: the requester's own host appears first; it must be
			// filtered out, but tor-2 must still be covered by fe80::b2.
			{Gid: "fe80::a2", HostName: "host-a", TorId: "tor-2"},
			{Gid: "fe80::b2", HostName: "host-b", TorId: "tor-2"},
			// tor-3: only a valid different-host RNIC.
			{Gid: "fe80::c3", HostName: "host-c", TorId: "tor-3"},
		},
		hostnameByGID: map[string]string{"fe80::1": "host-a"},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	got := targetGIDs(targets)
	want := []string{"fe80::b2", "fe80::c3"} // tor-2 covered by fe80::b2, not the same-host fe80::a2
	if !equalStrings(got, want) {
		t.Errorf("targets = %v, want %v (same-host excluded, ToR coverage preserved)", got, want)
	}
}

// TestInterTor_CrossFamilyExcludedBeforeSampling verifies issue #41 for the
// inter-ToR list: a foreign ToR whose first candidate is cross-family is still
// covered by a same-family RNIC rather than being dropped from coverage.
func TestInterTor_CrossFamilyExcludedBeforeSampling(t *testing.T) {
	src := &fakeRnicSource{
		interTor: []*controller_agent.RnicInfo{
			{Gid: "::ffff:10.0.2.1", HostName: "host-x", TorId: "tor-2"}, // cross family -> skipped
			{Gid: "fe80::b2", HostName: "host-y", TorId: "tor-2"},        // same family -> represents tor-2
			{Gid: "fe80::c3", HostName: "host-z", TorId: "tor-3"},
		},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	got := targetGIDs(targets)
	want := []string{"fe80::b2", "fe80::c3"}
	if !equalStrings(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

// TestInterTor_SamplesOnePerToRUpToSize verifies that the generator still caps
// the inter-ToR pinglist at interTorSampleSize distinct ToRs, one representative
// each, after filtering.
func TestInterTor_SamplesOnePerToRUpToSize(t *testing.T) {
	src := &fakeRnicSource{
		interTor: []*controller_agent.RnicInfo{
			{Gid: "fe80::a", HostName: "host-a", TorId: "tor-2"},
			{Gid: "fe80::b", HostName: "host-b", TorId: "tor-2"}, // second RNIC in tor-2 -> not sampled
			{Gid: "fe80::c", HostName: "host-c", TorId: "tor-3"},
			{Gid: "fe80::d", HostName: "host-d", TorId: "tor-4"},
		},
	}
	// Cap at 2 distinct ToRs.
	gen := NewPinglistGenerator(src, ECMPConfig{PathsAssumed: 16, CoverageProbability: 0.9, MaxFlowLabels: 64}, 2)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (capped at interTorSampleSize)", len(targets))
	}
	// Exactly one representative per distinct ToR.
	seen := map[string]bool{}
	for _, tgt := range targets {
		if seen[tgt.GetTargetTorId()] {
			t.Errorf("ToR %s represented more than once", tgt.GetTargetTorId())
		}
		seen[tgt.GetTargetTorId()] = true
	}
}
