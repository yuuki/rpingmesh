package analyzer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/yuuki/rpingmesh/internal/probe"
)

// Bounds of a topology file. They keep a mistyped path (a log file, a
// database dump) or a generated file gone wrong from exhausting the
// controller's memory at startup.
const (
	// TopologyVersion is the only schema version this controller reads.
	TopologyVersion = 1
	// MaxTopologyFileBytes caps the size of a topology file.
	MaxTopologyFileBytes = 8 << 20
	// MaxTopologyTors caps the ToRs one topology file may describe.
	MaxTopologyTors = 100_000
	// maxTopologyNameLen caps a ToR ID, rail or spine group name. It equals
	// the bound the controller applies to a registered tor_id.
	maxTopologyNameLen = 255
)

// TorFacts are the facts a topology file states about one ToR switch. Both
// are optional: an empty value means "not stated", never "none".
type TorFacts struct {
	// Rail names the rail (plane) the ToR belongs to: the set of ToRs that
	// reach each other through one upper tier.
	Rail string
	// SpineGroup names the set of spine switches the ToR's uplinks connect
	// to. Every ToR of one spine group shares the same spines, so two ToRs
	// of one group are connected through exactly one of them.
	SpineGroup string
}

// Topology holds the fabric facts the localizer cannot learn from probe
// summaries: which ToRs share a spine group and a rail. A summary names the
// ToR of each end of a path, but nothing above it, and agents cannot discover
// spine switches. A nil *Topology is valid and states no facts.
//
// A Topology is immutable after ParseTopology returns, so it needs no
// locking.
type Topology struct {
	tors map[string]TorFacts
	// groupRail is the rail of each spine group ("" when its ToRs state
	// none). ParseTopology guarantees that it is the same for every ToR of
	// the group.
	groupRail map[string]string
	rails     int
}

// LoadTopologyFile reads and parses the topology file at path.
func LoadTopologyFile(path string) (*Topology, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open topology file: %w", err)
	}
	defer f.Close()

	// Read one byte past the cap so an oversized file is told apart from a
	// file of exactly the cap.
	data, err := io.ReadAll(io.LimitReader(f, MaxTopologyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read topology file %s: %w", path, err)
	}
	topo, err := ParseTopology(data)
	if err != nil {
		return nil, fmt.Errorf("topology file %s: %w", path, err)
	}
	return topo, nil
}

// ParseTopology parses and validates a topology file (schema version 1):
//
//	version: 1
//	tors:
//	  <tor_id>:
//	    rail: <name>          # optional
//	    spine_group: <name>   # optional
//
// It rejects a file it cannot interpret in full (an unknown key, an unknown
// version, a ToR listed twice, a spine group whose ToRs name different
// rails) instead of using the part it understands: a fact dropped silently
// would make the localizer name the wrong tier.
//
// The document is walked as a node tree instead of being decoded into a
// struct. The YAML library's own duplicate-key check compares every pair of
// keys, which would take minutes on a file of MaxTopologyTors ToRs; here a
// file is read in time linear in its size, and every error names its line.
func ParseTopology(data []byte) (*Topology, error) {
	if len(data) > MaxTopologyFileBytes {
		return nil, fmt.Errorf("file is larger than %d bytes", MaxTopologyFileBytes)
	}

	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("file is empty")
		}
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("file holds more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("file is empty")
	}
	root := resolveAlias(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: the document must be a mapping with the keys version and tors", root.Line)
	}

	var version, tors *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		var slot **yaml.Node
		switch {
		case key.Kind == yaml.ScalarNode && key.Value == "version":
			slot = &version
		case key.Kind == yaml.ScalarNode && key.Value == "tors":
			slot = &tors
		default:
			return nil, fmt.Errorf("line %d: unknown key %q (known keys: version, tors)", key.Line, key.Value)
		}
		if *slot != nil {
			return nil, fmt.Errorf("line %d: key %q is set twice", key.Line, key.Value)
		}
		*slot = resolveAlias(value)
	}

	if version == nil {
		return nil, fmt.Errorf("version is required (this controller reads version %d)", TopologyVersion)
	}
	if version.Kind != yaml.ScalarNode || version.Tag != "!!int" || version.Value != strconv.Itoa(TopologyVersion) {
		return nil, fmt.Errorf("line %d: unsupported version %q (this controller reads version %d)",
			version.Line, version.Value, TopologyVersion)
	}
	if tors == nil || isNullNode(tors) {
		return nil, errors.New("tors must list at least one ToR")
	}
	if tors.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: tors must be a mapping of ToR IDs", tors.Line)
	}
	count := len(tors.Content) / 2
	if count == 0 {
		return nil, errors.New("tors must list at least one ToR")
	}
	if count > MaxTopologyTors {
		return nil, fmt.Errorf("tors lists %d ToRs (max %d)", count, MaxTopologyTors)
	}

	topo := &Topology{
		tors:      make(map[string]TorFacts, count),
		groupRail: make(map[string]string),
	}
	groupFirstTor := make(map[string]string)
	rails := make(map[string]struct{})
	for i := 0; i+1 < len(tors.Content); i += 2 {
		key := tors.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag == "!!null" || key.Tag == "!!merge" {
			return nil, fmt.Errorf("line %d: a ToR ID must be a string", key.Line)
		}
		id := key.Value
		if id == "" {
			return nil, fmt.Errorf("line %d: a ToR ID must not be empty", key.Line)
		}
		if err := checkTopologyName("ToR ID", id); err != nil {
			return nil, fmt.Errorf("line %d: %w", key.Line, err)
		}
		if probe.IsReservedTorID(id) {
			return nil, fmt.Errorf("line %d: ToR ID %q is reserved for RNICs without a ToR", key.Line, id)
		}
		if _, dup := topo.tors[id]; dup {
			return nil, fmt.Errorf("line %d: ToR %q is listed twice", key.Line, id)
		}
		facts, err := parseTorFacts(id, tors.Content[i+1])
		if err != nil {
			return nil, err
		}
		if group := facts.SpineGroup; group != "" {
			if first, seen := groupFirstTor[group]; !seen {
				groupFirstTor[group] = id
				topo.groupRail[group] = facts.Rail
			} else if topo.groupRail[group] != facts.Rail {
				return nil, fmt.Errorf("line %d: spine_group %q spans rails: ToR %q states rail %q, ToR %q states rail %q",
					key.Line, group, first, topo.groupRail[group], id, facts.Rail)
			}
		}
		if facts.Rail != "" {
			rails[facts.Rail] = struct{}{}
		}
		topo.tors[id] = facts
	}
	topo.rails = len(rails)
	return topo, nil
}

// parseTorFacts reads the facts of one ToR: a mapping with the optional keys
// rail and spine_group, or nothing (the ToR is listed, nothing is stated).
func parseTorFacts(id string, node *yaml.Node) (TorFacts, error) {
	node = resolveAlias(node)
	if isNullNode(node) {
		return TorFacts{}, nil
	}
	if node.Kind != yaml.MappingNode {
		return TorFacts{}, fmt.Errorf("line %d: the facts of ToR %q must be a mapping with the keys rail and spine_group", node.Line, id)
	}
	var facts TorFacts
	var seenRail, seenGroup bool
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], resolveAlias(node.Content[i+1])
		var dst *string
		var seen *bool
		switch {
		case key.Kind == yaml.ScalarNode && key.Value == "rail":
			dst, seen = &facts.Rail, &seenRail
		case key.Kind == yaml.ScalarNode && key.Value == "spine_group":
			dst, seen = &facts.SpineGroup, &seenGroup
		default:
			return TorFacts{}, fmt.Errorf("line %d: unknown key %q of ToR %q (known keys: rail, spine_group)", key.Line, key.Value, id)
		}
		if *seen {
			return TorFacts{}, fmt.Errorf("line %d: key %q of ToR %q is set twice", key.Line, key.Value, id)
		}
		*seen = true
		if isNullNode(value) {
			continue
		}
		if value.Kind != yaml.ScalarNode {
			return TorFacts{}, fmt.Errorf("line %d: %s of ToR %q must be a string", value.Line, key.Value, id)
		}
		// The text of the scalar is the name, also for a value YAML would
		// read as a number or a boolean (rail: 0).
		if err := checkTopologyName(fmt.Sprintf("%s of ToR %q", key.Value, id), value.Value); err != nil {
			return TorFacts{}, fmt.Errorf("line %d: %w", value.Line, err)
		}
		*dst = value.Value
	}
	return facts, nil
}

// resolveAlias follows a YAML alias to the node it names, so one set of
// facts can be anchored and reused by the ToRs that share it.
func resolveAlias(node *yaml.Node) *yaml.Node {
	for i := 0; i < 8 && node.Kind == yaml.AliasNode && node.Alias != nil; i++ {
		node = node.Alias
	}
	return node
}

// isNullNode reports whether node is a YAML null (an empty value or ~).
func isNullNode(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

// checkTopologyName checks one name of a topology file: canonical (no
// surrounding whitespace, as tor_id values are trimmed before they are
// compared), bounded, valid UTF-8 and free of control characters. Names
// become metric attribute values and log fields.
func checkTopologyName(what, name string) error {
	if len(name) > maxTopologyNameLen {
		return fmt.Errorf("%s is too long (%d bytes, max %d)", what, len(name), maxTopologyNameLen)
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("%s %q has leading or trailing whitespace", what, name)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%s is not valid UTF-8", what)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s %q holds a control character", what, name)
		}
	}
	return nil
}

// Lookup returns the facts stated for torID. ok is false when the ToR is not
// listed or is listed without a rail and a spine group: nothing is known
// about the tiers above it.
func (t *Topology) Lookup(torID string) (facts TorFacts, ok bool) {
	if t == nil {
		return TorFacts{}, false
	}
	facts = t.tors[torID]
	return facts, facts.Rail != "" || facts.SpineGroup != ""
}

// Tors returns the number of ToRs the topology lists.
func (t *Topology) Tors() int {
	if t == nil {
		return 0
	}
	return len(t.tors)
}

// SpineGroups returns the number of distinct spine groups the topology names.
func (t *Topology) SpineGroups() int {
	if t == nil {
		return 0
	}
	return len(t.groupRail)
}

// Rails returns the number of distinct rails the topology names.
func (t *Topology) Rails() int {
	if t == nil {
		return 0
	}
	return t.rails
}
