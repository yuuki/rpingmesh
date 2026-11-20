package analyzer

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/yuuki/rpingmesh/internal/probe"
)

// FuzzParseTopology feeds arbitrary bytes to the topology parser. The file
// is operator input read at startup; whatever the parser accepts must
// satisfy the invariants the localizer and the metric attributes rely on.
func FuzzParseTopology(f *testing.F) {
	for _, seed := range []string{
		validTopologyYAML,
		"version: 1\ntors: {leaf-1: {rail: rail0, spine_group: pod-a}}\n",
		`{"version": 1, "tors": {"leaf-1": {"rail": "rail0"}}}`,
		"version: 1\ntors:\n  a: &x {rail: r, spine_group: g}\n  b: *x\n",
		"version: 1\ntors: {1: {rail: 2}, true: {spine_group: null}}\n",
		"version: 1\ntors:\n  leaf-1: {rail: rail0, spine_group: pod-a}\n  leaf-2: {rail: rail1, spine_group: pod-a}\n",
		"",
		"version: 2\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		topo, err := ParseTopology(data)
		if err != nil {
			if topo != nil {
				t.Fatal("ParseTopology returned a topology with an error")
			}
			return
		}
		if n := topo.Tors(); n < 1 || n > MaxTopologyTors {
			t.Fatalf("accepted %d ToRs", n)
		}
		checkName := func(what, name string) {
			if len(name) > maxTopologyNameLen || !utf8.ValidString(name) || name != strings.TrimSpace(name) {
				t.Fatalf("accepted %s %q", what, name)
			}
			for _, r := range name {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("accepted %s %q with a control character", what, name)
				}
			}
		}
		rails := make(map[string]struct{})
		groupRail := make(map[string]string)
		for id, facts := range topo.tors {
			if id == "" || probe.IsReservedTorID(id) {
				t.Fatalf("accepted ToR ID %q", id)
			}
			checkName("ToR ID", id)
			checkName("rail", facts.Rail)
			checkName("spine group", facts.SpineGroup)
			if facts.Rail != "" {
				rails[facts.Rail] = struct{}{}
			}
			if facts.SpineGroup != "" {
				// A spine group belongs to one rail.
				if rail, seen := groupRail[facts.SpineGroup]; seen && rail != facts.Rail {
					t.Fatalf("spine group %q spans rails %q and %q", facts.SpineGroup, rail, facts.Rail)
				}
				groupRail[facts.SpineGroup] = facts.Rail
			}
			got, known := topo.Lookup(id)
			if got != facts || known != (facts.Rail != "" || facts.SpineGroup != "") {
				t.Fatalf("Lookup(%q) = %+v, %v; stored %+v", id, got, known, facts)
			}
		}
		if topo.Rails() != len(rails) || topo.SpineGroups() != len(groupRail) {
			t.Fatalf("counts: Rails() = %d (want %d), SpineGroups() = %d (want %d)",
				topo.Rails(), len(rails), topo.SpineGroups(), len(groupRail))
		}
	})
}
