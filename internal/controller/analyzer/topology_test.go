package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validTopologyYAML = `
# Two rails, each with two spine groups.
version: 1
tors:
  leaf-a1-r0: {rail: rail0, spine_group: pod-a-r0}
  leaf-a2-r0: {rail: rail0, spine_group: pod-a-r0}
  leaf-b1-r0: {rail: rail0, spine_group: pod-b-r0}
  leaf-a1-r1:
    rail: rail1
    spine_group: pod-a-r1
  leaf-c1-r1: {rail: rail1}          # under the rail's spines directly
  leaf-d1: {spine_group: pod-d}      # a spine group without a rail
  leaf-e1: {}                        # listed, nothing stated
  leaf-f1:
  leaf-g1: &pod-g {rail: rail1, spine_group: pod-g-r1}
  leaf-g2: *pod-g                    # the same facts, by alias
  "10": {rail: 1}                    # names are text, also when they look like numbers
`

func TestParseTopology_Valid(t *testing.T) {
	topo, err := ParseTopology([]byte(validTopologyYAML))
	if err != nil {
		t.Fatalf("ParseTopology: %v", err)
	}
	if got := topo.Tors(); got != 11 {
		t.Errorf("Tors() = %d, want 11", got)
	}
	if got := topo.SpineGroups(); got != 5 {
		t.Errorf("SpineGroups() = %d, want 5", got)
	}
	if got := topo.Rails(); got != 3 {
		t.Errorf("Rails() = %d, want 3", got)
	}

	for _, tc := range []struct {
		tor   string
		want  TorFacts
		known bool
	}{
		{"leaf-a1-r0", TorFacts{Rail: "rail0", SpineGroup: "pod-a-r0"}, true},
		{"leaf-a1-r1", TorFacts{Rail: "rail1", SpineGroup: "pod-a-r1"}, true},
		{"leaf-c1-r1", TorFacts{Rail: "rail1"}, true},
		{"leaf-d1", TorFacts{SpineGroup: "pod-d"}, true},
		// Listed without facts and not listed are the same: nothing is known.
		{"leaf-e1", TorFacts{}, false},
		{"leaf-f1", TorFacts{}, false},
		{"leaf-unknown", TorFacts{}, false},
		{"leaf-g1", TorFacts{Rail: "rail1", SpineGroup: "pod-g-r1"}, true},
		{"leaf-g2", TorFacts{Rail: "rail1", SpineGroup: "pod-g-r1"}, true},
		{"10", TorFacts{Rail: "1"}, true},
	} {
		got, known := topo.Lookup(tc.tor)
		if got != tc.want || known != tc.known {
			t.Errorf("Lookup(%q) = %+v, %v; want %+v, %v", tc.tor, got, known, tc.want, tc.known)
		}
	}
}

// TestParseTopology_JSON verifies that a JSON document, which generated
// tooling may prefer to write, is accepted: YAML is a superset of JSON.
func TestParseTopology_JSON(t *testing.T) {
	topo, err := ParseTopology([]byte(`{"version": 1, "tors": {"leaf-1": {"rail": "rail0"}}}`))
	if err != nil {
		t.Fatalf("ParseTopology: %v", err)
	}
	if facts, known := topo.Lookup("leaf-1"); !known || facts.Rail != "rail0" {
		t.Errorf("Lookup(leaf-1) = %+v, %v", facts, known)
	}
}

func TestParseTopology_Rejects(t *testing.T) {
	long := strings.Repeat("x", maxTopologyNameLen+1)
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"empty file", "", "file is empty"},
		{"comment only", "# nothing\n", "file is empty"},
		{"not a mapping", "- a\n- b\n", "must be a mapping"},
		{"syntax error", "version: 1\ntors: {leaf-1: {rail: rail0}", "invalid YAML"},
		{"missing version", "tors: {leaf-1: {rail: rail0}}\n", "version is required"},
		{"unknown version", "version: 2\ntors: {leaf-1: {rail: rail0}}\n", `unsupported version "2"`},
		{"version zero", "version: 0\ntors: {leaf-1: {rail: rail0}}\n", `unsupported version "0"`},
		{"version as text", "version: \"1\"\ntors: {leaf-1: {rail: rail0}}\n", `unsupported version "1"`},
		{"version set twice", "version: 1\nversion: 1\ntors: {leaf-1: {rail: rail0}}\n", `key "version" is set twice`},
		{"no tors", "version: 1\n", "at least one ToR"},
		{"empty tors", "version: 1\ntors: {}\n", "at least one ToR"},
		{"null tors", "version: 1\ntors:\n", "at least one ToR"},
		{"tors as a list", "version: 1\ntors: [leaf-1]\n", "tors must be a mapping"},
		{"unknown top-level key", "version: 1\nrails: {}\ntors: {leaf-1: {rail: rail0}}\n", `line 2: unknown key "rails"`},
		{"unknown ToR key", "version: 1\ntors: {leaf-1: {rial: rail0}}\n", `unknown key "rial" of ToR "leaf-1"`},
		{"ToR key set twice", "version: 1\ntors: {leaf-1: {rail: rail0, rail: rail1}}\n", `key "rail" of ToR "leaf-1" is set twice`},
		{"duplicate ToR", "version: 1\ntors:\n  leaf-1: {rail: rail0}\n  leaf-1: {rail: rail1}\n", `line 4: ToR "leaf-1" is listed twice`},
		{"merge key", "version: 1\ntors:\n  a: &x {rail: r}\n  <<: *x\n", "a ToR ID must be a string"},
		{"null ToR ID", "version: 1\ntors: {~: {rail: rail0}}\n", "a ToR ID must be a string"},
		{"ToR ID that is a mapping", "version: 1\ntors: {? {a: b} : {rail: rail0}}\n", "a ToR ID must be a string"},
		{"rail that is a list", "version: 1\ntors: {leaf-1: {rail: [rail0]}}\n", `rail of ToR "leaf-1" must be a string`},
		{"two documents", "version: 1\ntors: {leaf-1: {rail: rail0}}\n---\nversion: 1\n", "more than one YAML document"},
		{"empty ToR ID", "version: 1\ntors: {\"\": {rail: rail0}}\n", "must not be empty"},
		{"reserved ToR ID", "version: 1\ntors: {unspecified: {rail: rail0}}\n", "reserved"},
		{"ToR ID with whitespace", "version: 1\ntors: {\" leaf-1\": {rail: rail0}}\n", "leading or trailing whitespace"},
		{"rail with whitespace", "version: 1\ntors: {leaf-1: {rail: \"rail0 \"}}\n", "leading or trailing whitespace"},
		{"ToR ID with control character", "version: 1\ntors: {\"leaf\\t1\": {rail: rail0}}\n", "control character"},
		{"spine group with NUL", "version: 1\ntors: {leaf-1: {spine_group: \"a\\0b\"}}\n", "control character"},
		{"ToR ID too long", "version: 1\ntors: {" + long + ": {rail: rail0}}\n", "too long"},
		{"rail too long", "version: 1\ntors: {leaf-1: {rail: " + long + "}}\n", "too long"},
		{"spine group too long", "version: 1\ntors: {leaf-1: {spine_group: " + long + "}}\n", "too long"},
		{
			"spine group spans rails",
			"version: 1\ntors:\n  leaf-1: {rail: rail0, spine_group: pod-a}\n  leaf-2: {rail: rail1, spine_group: pod-a}\n",
			`spine_group "pod-a" spans rails`,
		},
		{
			"spine group with and without a rail",
			"version: 1\ntors:\n  leaf-1: {rail: rail0, spine_group: pod-a}\n  leaf-2: {spine_group: pod-a}\n",
			`spine_group "pod-a" spans rails`,
		},
		{"facts of the wrong type", "version: 1\ntors: {leaf-1: [rail0]}\n", `facts of ToR "leaf-1" must be a mapping`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			topo, err := ParseTopology([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("ParseTopology accepted the file (%d ToRs), want an error containing %q", topo.Tors(), tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestParseTopology_Bounds verifies the caps on the file size and on the
// number of ToRs.
func TestParseTopology_Bounds(t *testing.T) {
	big := make([]byte, MaxTopologyFileBytes+1)
	for i := range big {
		big[i] = '#'
	}
	if _, err := ParseTopology(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: got error %v, want one about the size", err)
	}

	var b strings.Builder
	b.WriteString("version: 1\ntors:\n")
	for i := 0; i < MaxTopologyTors; i++ {
		fmt.Fprintf(&b, "  t%d: {rail: r}\n", i)
	}
	// A file at the cap is read (in linear time: this takes well under a
	// second), one ToR more is refused.
	topo, err := ParseTopology([]byte(b.String()))
	if err != nil {
		t.Fatalf("file at the ToR cap: %v", err)
	}
	if topo.Tors() != MaxTopologyTors {
		t.Errorf("Tors() = %d, want %d", topo.Tors(), MaxTopologyTors)
	}
	b.WriteString("  one-more: {rail: r}\n")
	if _, err := ParseTopology([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "ToRs (max") {
		t.Errorf("too many ToRs: got error %v, want one about the ToR count", err)
	}
}

// TestTopology_NilStatesNothing verifies that a nil topology (no file) is
// usable and knows no ToR.
func TestTopology_NilStatesNothing(t *testing.T) {
	var topo *Topology
	if facts, known := topo.Lookup("leaf-1"); known || facts != (TorFacts{}) {
		t.Errorf("nil Lookup = %+v, %v; want zero, false", facts, known)
	}
	if topo.Tors() != 0 || topo.SpineGroups() != 0 || topo.Rails() != 0 {
		t.Error("nil topology reports facts")
	}
}

func TestLoadTopologyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "topology.yaml")
	if err := os.WriteFile(path, []byte(validTopologyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	topo, err := LoadTopologyFile(path)
	if err != nil {
		t.Fatalf("LoadTopologyFile: %v", err)
	}
	if topo.Tors() != 11 {
		t.Errorf("Tors() = %d, want 11", topo.Tors())
	}

	if _, err := LoadTopologyFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file: got nil error")
	}

	// A parse error names the file.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTopologyFile(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("invalid file: got error %v, want one naming %s", err, bad)
	}

	// A file over the size cap is refused without being parsed.
	huge := filepath.Join(dir, "huge.yaml")
	if err := os.WriteFile(huge, make([]byte, MaxTopologyFileBytes+2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTopologyFile(huge); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: got error %v, want one about the size", err)
	}
}

// TestParseTopology_ShippedFiles verifies the topology files in the
// repository: the commented example in configs/ and the file
// scripts/topology/build_device_tor_map.py writes (its Python test compares
// the script's output with the same file).
func TestParseTopology_ShippedFiles(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	topo, err := LoadTopologyFile(filepath.Join(root, "configs", "topology.yaml"))
	if err != nil {
		t.Fatalf("configs/topology.yaml: %v", err)
	}
	if topo.Tors() != 8 || topo.SpineGroups() != 2 || topo.Rails() != 2 {
		t.Errorf("configs/topology.yaml: %d ToRs, %d spine groups, %d rails; want 8, 2, 2",
			topo.Tors(), topo.SpineGroups(), topo.Rails())
	}
	if facts, _ := topo.Lookup("leaf-b2-r0"); facts != (TorFacts{Rail: "rail0", SpineGroup: "pod-b-r0"}) {
		t.Errorf("configs/topology.yaml: leaf-b2-r0 = %+v", facts)
	}

	topo, err = LoadTopologyFile(filepath.Join(root, "scripts", "topology", "testdata", "topology.yaml"))
	if err != nil {
		t.Fatalf("scripts/topology/testdata/topology.yaml: %v", err)
	}
	for tor, rail := range map[string]string{"su1-mlx5_0": "mlx5_0", "su1-mlx5_1": "mlx5_1"} {
		if facts, known := topo.Lookup(tor); !known || facts != (TorFacts{Rail: rail}) {
			t.Errorf("generated topology: %s = %+v, %v; want rail %s", tor, facts, known, rail)
		}
	}
	if topo.Tors() != 2 {
		t.Errorf("generated topology lists %d ToRs, want 2", topo.Tors())
	}
}
