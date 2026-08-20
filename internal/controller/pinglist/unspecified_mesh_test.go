package pinglist

import (
	"context"
	"fmt"
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func mixedClusterRnics() []*controller_agent.RnicInfo {
	return []*controller_agent.RnicInfo{
		{Gid: "fe80::1", HostName: "host-a", TorId: ""},
		{Gid: "fe80::2", HostName: "host-b", TorId: ""},
		{Gid: "fe80::3", HostName: "host-c", TorId: ""},
		{Gid: "fe80::4", HostName: "host-d", TorId: ""},
		{Gid: "fe80::5", HostName: "host-e", TorId: ""},
		{Gid: "fe80::a", HostName: "host-x", TorId: "tor-1"},
		{Gid: "fe80::b", HostName: "host-y", TorId: "tor-1"},
		{Gid: "fe80::c", HostName: "host-z", TorId: "tor-2"},
	}
}

func TestTorMesh_EmptyToRExcludesNamed(t *testing.T) {
	src := &fakeRnicSource{
		all:           mixedClusterRnics(),
		hostnameByGID: map[string]string{"fe80::1": "host-a"},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	got := targetGIDs(targets)
	want := []string{"fe80::2", "fe80::3", "fe80::4", "fe80::5"}
	if !equalStrings(got, want) {
		t.Errorf("untagged ToR-mesh = %v, want %v (self/same-host excluded, named ToRs omitted)", got, want)
	}
}

func TestTorMesh_EmptyToRRespectsCap(t *testing.T) {
	src := &fakeRnicSource{
		all:           mixedClusterRnics(),
		hostnameByGID: map[string]string{"fe80::1": "host-a"},
	}
	gen := NewPinglistGenerator(src, ECMPConfig{
		PathsAssumed: 16, CoverageProbability: 0.9, MaxFlowLabels: 64,
	}, DefaultInterTorSampleSize, 2)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (unspecified mesh cap)", len(targets))
	}
	seen := map[string]bool{}
	for _, tgt := range targets {
		if tgt.GetTargetTorId() != "" {
			t.Errorf("target %s: TorId = %q, want empty", tgt.GetTargetGid(), tgt.GetTargetTorId())
		}
		if tgt.GetTargetGid() == "fe80::1" {
			t.Error("requester included in its own untagged mesh")
		}
		if seen[tgt.GetTargetGid()] {
			t.Errorf("duplicate target %s", tgt.GetTargetGid())
		}
		seen[tgt.GetTargetGid()] = true
	}
}

func TestTorMesh_NamedToRNotCapped(t *testing.T) {
	rnics := []*controller_agent.RnicInfo{
		{Gid: "fe80::1", HostName: "host-0", TorId: "tor-1"},
	}
	for i := 2; i <= 40; i++ {
		rnics = append(rnics, &controller_agent.RnicInfo{
			Gid:      fmt.Sprintf("fe80::%x", i),
			HostName: fmt.Sprintf("host-%d", i),
			TorId:    "tor-1",
		})
	}
	src := &fakeRnicSource{
		all:           rnics,
		hostnameByGID: map[string]string{"fe80::1": "host-0"},
	}
	gen := NewPinglistGenerator(src, ECMPConfig{
		PathsAssumed: 16, CoverageProbability: 0.9, MaxFlowLabels: 64,
	}, DefaultInterTorSampleSize, 2)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if len(targets) != 39 {
		t.Errorf("named ToR-mesh = %d targets, want 39 (cap must not apply)", len(targets))
	}
}

func TestInterTor_EmptyRequesterOmitsUntagged(t *testing.T) {
	src := &fakeRnicSource{
		all:           mixedClusterRnics(),
		hostnameByGID: map[string]string{"fe80::1": "host-a"},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::1", "")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	for _, tgt := range targets {
		if tgt.GetTargetTorId() == "" {
			t.Errorf("inter-ToR for untagged requester included untagged target %s", tgt.GetTargetGid())
		}
	}
	got := targetGIDs(targets)
	want := []string{"fe80::a", "fe80::c"}
	if !equalStrings(got, want) {
		t.Errorf("inter-ToR for untagged requester = %v, want %v (one representative each from tor-1 and tor-2)", got, want)
	}
}

func TestInterTor_NamedRequesterMaySampleUntagged(t *testing.T) {
	src := &fakeRnicSource{
		all:           mixedClusterRnics(),
		hostnameByGID: map[string]string{"fe80::a": "host-x"},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateInterTorPinglist(context.Background(), "fe80::a", "tor-1")
	if err != nil {
		t.Fatalf("GenerateInterTorPinglist: %v", err)
	}
	var sawEmpty, sawTor2 bool
	for _, tgt := range targets {
		switch tgt.GetTargetTorId() {
		case "":
			sawEmpty = true
		case "tor-2":
			sawTor2 = true
		case "tor-1":
			t.Errorf("inter-ToR included requester ToR target %s", tgt.GetTargetGid())
		}
	}
	if !sawEmpty {
		t.Error("named requester inter-ToR did not include an untagged representative")
	}
	if !sawTor2 {
		t.Error("named requester inter-ToR did not include tor-2")
	}
}
