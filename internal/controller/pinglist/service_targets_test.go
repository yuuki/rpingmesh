package pinglist

import (
	"context"
	"errors"
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// TestGenerateServiceTargets_Filters verifies that the destination GIDs of
// traced flows resolve to SERVICE_TRACING targets, that unregistered GIDs,
// the requester itself, its host mates and duplicates are dropped, and that
// the targets carry no flow-label set (the agent stamps the flow's own).
func TestGenerateServiceTargets_Filters(t *testing.T) {
	src := &fakeRnicSource{
		hostnameByGID: map[string]string{
			"fe80::1": "host-a", // requester
			"fe80::2": "host-a", // same host
			"fe80::3": "host-b",
			"fe80::4": "host-c",
		},
	}
	gen := newTestGenerator(src)

	targets, err := gen.GenerateServiceTargets(context.Background(), "fe80::1", []string{
		"fe80::3", "fe80::1", "fe80::2", "fe80::9", " fe80::3 ", "", "fe80::4",
	})
	if err != nil {
		t.Fatalf("GenerateServiceTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %v", len(targets), targets)
	}
	for i, want := range []string{"fe80::3", "fe80::4"} {
		tg := targets[i]
		if tg.GetTargetGid() != want {
			t.Errorf("target %d GID = %q, want %q", i, tg.GetTargetGid(), want)
		}
		if tg.GetPinglistType() != controller_agent.PinglistType_SERVICE_TRACING {
			t.Errorf("target %d type = %v, want SERVICE_TRACING", i, tg.GetPinglistType())
		}
		if tg.GetFlowLabelCount() != 1 || tg.GetFlowLabel() != 0 || tg.GetFlowLabelSeed() != 0 {
			t.Errorf("target %d carries a flow-label set: label=%d seed=%d count=%d",
				i, tg.GetFlowLabel(), tg.GetFlowLabelSeed(), tg.GetFlowLabelCount())
		}
		if tg.GetSampled() {
			t.Errorf("target %d is marked sampled", i)
		}
	}
}

// TestGenerateServiceTargets_UnregisteredRequester verifies that a requester
// the registry does not know still gets its targets, with only GID-based
// self-exclusion.
func TestGenerateServiceTargets_UnregisteredRequester(t *testing.T) {
	src := &fakeRnicSource{hostnameByGID: map[string]string{"fe80::3": "host-b"}}
	gen := newTestGenerator(src)
	targets, err := gen.GenerateServiceTargets(context.Background(), "fe80::1", []string{"fe80::1", "fe80::3"})
	if err != nil {
		t.Fatalf("GenerateServiceTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].GetTargetGid() != "fe80::3" {
		t.Fatalf("got %v, want only fe80::3", targets)
	}
}

// TestGenerateServiceTargets_CrossFamily verifies that a GID of another
// address family than the requester is dropped, like in the pinglists.
func TestGenerateServiceTargets_CrossFamily(t *testing.T) {
	src := &fakeRnicSource{hostnameByGID: map[string]string{"::ffff:10.0.0.2": "host-b"}}
	gen := newTestGenerator(src)
	targets, err := gen.GenerateServiceTargets(context.Background(), "fe80::1", []string{"::ffff:10.0.0.2"})
	if err != nil {
		t.Fatalf("GenerateServiceTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("got %v, want no cross-family target", targets)
	}
}

// TestGenerateServiceTargets_Empty verifies that no GIDs yield an empty,
// non-nil list.
func TestGenerateServiceTargets_Empty(t *testing.T) {
	gen := newTestGenerator(&fakeRnicSource{})
	targets, err := gen.GenerateServiceTargets(context.Background(), "fe80::1", nil)
	if err != nil {
		t.Fatalf("GenerateServiceTargets: %v", err)
	}
	if targets == nil || len(targets) != 0 {
		t.Fatalf("got %v, want an empty list", targets)
	}
}

// TestGenerateServiceTargets_RegistryError verifies that a lookup failure is
// propagated: the agent then keeps its previous targets.
func TestGenerateServiceTargets_RegistryError(t *testing.T) {
	src := &fakeRnicSource{resolveErr: errFakeRegistry}
	gen := newTestGenerator(src)
	if _, err := gen.GenerateServiceTargets(context.Background(), "fe80::1", []string{"fe80::3"}); !errors.Is(err, errFakeRegistry) {
		t.Fatalf("error = %v, want %v", err, errFakeRegistry)
	}
}
