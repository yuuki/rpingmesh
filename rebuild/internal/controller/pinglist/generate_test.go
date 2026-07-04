package pinglist

import (
	"context"
	"errors"
	"testing"

	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// erroringRnicSource is an RnicSource whose methods always fail, so
// GenerateTorMeshPinglist/GenerateInterTorPinglist's error-propagation paths
// can be exercised without a real registry.
type erroringRnicSource struct{}

var errFakeRegistry = errors.New("fake registry failure")

func (erroringRnicSource) GetRNICsByToR(_ context.Context, _ string) ([]*controller_agent.RnicInfo, error) {
	return nil, errFakeRegistry
}

func (erroringRnicSource) GetSampleRNICsFromOtherToRs(_ context.Context, _ string) ([]*controller_agent.RnicInfo, error) {
	return nil, errFakeRegistry
}

func newTestGenerator(src RnicSource) *PinglistGenerator {
	return NewPinglistGenerator(src, ECMPConfig{
		PathsAssumed:        16,
		CoverageProbability: 0.9,
		MaxFlowLabels:       64,
	})
}

// TestGenerateTorMeshPinglist_Error verifies that a registry error is
// propagated unchanged and no targets are returned.
func TestGenerateTorMeshPinglist_Error(t *testing.T) {
	gen := newTestGenerator(erroringRnicSource{})

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
	if !errors.Is(err, errFakeRegistry) {
		t.Fatalf("GenerateTorMeshPinglist error = %v, want %v", err, errFakeRegistry)
	}
	if targets != nil {
		t.Errorf("GenerateTorMeshPinglist targets = %v, want nil on error", targets)
	}
}

// TestGenerateTorMeshPinglist_EmptyToR verifies that a ToR with no RNICs (or
// only the requester itself) yields an empty, non-nil target slice rather
// than an error.
func TestGenerateTorMeshPinglist_EmptyToR(t *testing.T) {
	cases := []struct {
		name string
		src  *fakeRnicSource
	}{
		{"no_rnics", &fakeRnicSource{torMesh: nil}},
		{"only_requester", &fakeRnicSource{torMesh: []*controller_agent.RnicInfo{
			{Gid: "fe80::1"},
		}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gen := newTestGenerator(tc.src)

			targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
			if err != nil {
				t.Fatalf("GenerateTorMeshPinglist: %v", err)
			}
			if len(targets) != 0 {
				t.Errorf("got %d targets, want 0", len(targets))
			}
		})
	}
}

// TestGenerateInterTorPinglist_Success verifies that sampled RNICs from other
// ToRs are converted into PingTargets carrying the ECMP seed/count, mirroring
// GenerateTorMeshPinglist's contract but without excluding the requester
// (GetSampleRNICsFromOtherToRs already excludes the requester's own ToR).
func TestGenerateInterTorPinglist_Success(t *testing.T) {
	src := &fakeRnicSource{
		interTor: []*controller_agent.RnicInfo{
			{Gid: "fe80::10", Qpn: 200, TorId: "tor-2"},
			{Gid: "fe80::11", Qpn: 201, TorId: "tor-3"},
		},
	}
	wantCount := ComputeFlowLabelCount(16, 0.9, 64)
	gen := newTestGenerator(src)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}

	for _, tgt := range targets {
		if tgt.GetFlowLabelCount() != wantCount {
			t.Errorf("target %s: FlowLabelCount = %d, want %d",
				tgt.GetTargetGid(), tgt.GetFlowLabelCount(), wantCount)
		}
		if tgt.GetFlowLabel() != tgt.GetFlowLabelSeed()&0xFFFFF {
			t.Errorf("target %s: FlowLabel %#x != seed&0xFFFFF %#x",
				tgt.GetTargetGid(), tgt.GetFlowLabel(), tgt.GetFlowLabelSeed()&0xFFFFF)
		}
	}
}

// TestGenerateInterTorPinglist_Empty verifies that no sampled RNICs (e.g. a
// single-ToR cluster where every other ToR is empty) yields an empty,
// non-nil target slice.
func TestGenerateInterTorPinglist_Empty(t *testing.T) {
	src := &fakeRnicSource{interTor: nil}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("got %d targets, want 0", len(targets))
	}
}

// TestGenerateInterTorPinglist_Error verifies that a registry error is
// propagated unchanged and no targets are returned.
func TestGenerateInterTorPinglist_Error(t *testing.T) {
	gen := newTestGenerator(erroringRnicSource{})

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "tor-1")
	if !errors.Is(err, errFakeRegistry) {
		t.Fatalf("GenerateInterTorPinglist error = %v, want %v", err, errFakeRegistry)
	}
	if targets != nil {
		t.Errorf("GenerateInterTorPinglist targets = %v, want nil on error", targets)
	}
}
