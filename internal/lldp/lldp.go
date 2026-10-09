// Package lldp discovers the switch each RDMA device is cabled to from the
// host's LLDP agent (lldpd), so the agent can derive per-device ToR IDs
// without a hand-maintained device_tor_ids map.
//
// Discovery is read-only: it runs `lldpcli -f json0 show neighbors` and maps
// each RDMA device to its RoCE netdev through sysfs. It never configures
// lldpd, the NIC, or the switch.
package lldp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ToR ID fields accepted by lldp_tor_id_field.
const (
	// FieldSystemName uses the neighbor's LLDP System Name TLV (the switch
	// hostname), which is the most readable ToR label.
	FieldSystemName = "system_name"
	// FieldChassisID uses the neighbor's Chassis ID TLV (usually the switch
	// base MAC), for switches that do not advertise a system name.
	FieldChassisID = "chassis_id"
)

// DefaultCLIPath is the lldpd client used when lldpcli_path is empty.
const DefaultCLIPath = "lldpcli"

// DefaultSysfsRoot is where RDMA device → netdev links are looked up.
const DefaultSysfsRoot = "/sys"

// DefaultQueryTimeout bounds a single neighbor query, so an lldpcli stuck on
// an unresponsive lldpd socket cannot stall agent startup.
const DefaultQueryTimeout = 10 * time.Second

// Neighbor is the LLDP neighbor seen on one local interface.
type Neighbor struct {
	Interface  string
	SystemName string
	ChassisID  string
	PortID     string
	PortDescr  string
}

// TorID returns the neighbor attribute selected by field, trimmed. It is empty
// when the neighbor does not advertise that attribute.
func (n Neighbor) TorID(field string) string {
	switch field {
	case FieldChassisID:
		return strings.TrimSpace(n.ChassisID)
	default:
		return strings.TrimSpace(n.SystemName)
	}
}

// ValidField reports whether field is an accepted lldp_tor_id_field value.
func ValidField(field string) bool {
	return field == FieldSystemName || field == FieldChassisID
}

// Querier returns the current LLDP neighbors keyed by local interface name.
type Querier interface {
	Neighbors(ctx context.Context) (map[string]Neighbor, error)
}

// CLIQuerier queries lldpd through lldpcli. The agent needs access to the
// lldpd control socket (root, or membership in lldpd's group).
type CLIQuerier struct {
	Path string
}

// Neighbors runs `lldpcli -f json0 show neighbors` and parses its output.
func (q CLIQuerier) Neighbors(ctx context.Context) (map[string]Neighbor, error) {
	path := q.Path
	if path == "" {
		path = DefaultCLIPath
	}
	cmd := exec.CommandContext(ctx, path, "-f", "json0", "show", "neighbors")
	// Return soon after ctx expires even if a child of lldpcli keeps the
	// output pipe open after lldpcli itself is killed.
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s show neighbors: %w: %s", path, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("%s show neighbors: %w", path, err)
	}
	return ParseJSON0(out)
}

// json0 is lldpcli's "-f json0" output, in which every node is a list and
// every leaf value is an object with a "value" key. Unlike "-f json", its
// shape does not depend on how many interfaces or values are present.
type json0Doc struct {
	LLDP []struct {
		Interface []struct {
			Name    string `json:"name"`
			Chassis []struct {
				ID   []json0Value `json:"id"`
				Name []json0Value `json:"name"`
			} `json:"chassis"`
			Port []struct {
				ID    []json0Value `json:"id"`
				Descr []json0Value `json:"descr"`
			} `json:"port"`
		} `json:"interface"`
	} `json:"lldp"`
}

type json0Value struct {
	Value string `json:"value"`
}

func first(vs []json0Value) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0].Value
}

// ParseJSON0 parses `lldpcli -f json0 show neighbors` output into neighbors
// keyed by local interface name. When an interface reports several neighbors
// the first one wins. Output without neighbors yields an empty map.
func ParseJSON0(data []byte) (map[string]Neighbor, error) {
	var doc json0Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse lldpcli json0 output: %w", err)
	}
	out := make(map[string]Neighbor)
	for _, l := range doc.LLDP {
		for _, iface := range l.Interface {
			if iface.Name == "" {
				continue
			}
			if _, seen := out[iface.Name]; seen {
				continue
			}
			n := Neighbor{Interface: iface.Name}
			if len(iface.Chassis) > 0 {
				n.SystemName = first(iface.Chassis[0].Name)
				n.ChassisID = first(iface.Chassis[0].ID)
			}
			if len(iface.Port) > 0 {
				n.PortID = first(iface.Port[0].ID)
				n.PortDescr = first(iface.Port[0].Descr)
			}
			out[iface.Name] = n
		}
	}
	return out, nil
}

// NetdevForRDMAPort returns the netdev behind an RDMA device's RoCE GID. It
// reads ports/<port>/gid_attrs/ndevs/<gidIndex>, the netdev the GID actually
// uses, and falls back to the device's only PCI netdev when that attribute is
// unavailable (e.g. older kernels or InfiniBand ports).
func NetdevForRDMAPort(sysfsRoot, device string, port, gidIndex uint8) (string, error) {
	if sysfsRoot == "" {
		sysfsRoot = DefaultSysfsRoot
	}
	devDir := filepath.Join(sysfsRoot, "class", "infiniband", device)
	ndevPath := filepath.Join(devDir, "ports", fmt.Sprint(port), "gid_attrs", "ndevs", fmt.Sprint(gidIndex))
	if b, err := os.ReadFile(ndevPath); err == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			return name, nil
		}
	}
	entries, err := os.ReadDir(filepath.Join(devDir, "device", "net"))
	if err != nil {
		return "", fmt.Errorf("no netdev for RDMA device %s port %d gid %d: %w", device, port, gidIndex, err)
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("no unambiguous netdev for RDMA device %s: %d candidates under device/net", device, len(entries))
	}
	return entries[0].Name(), nil
}

// Device is an RDMA device to resolve, with the netdev its LLDP neighbor is
// looked up on.
type Device struct {
	Name   string
	Netdev string
}

// Result is the outcome of resolving one device.
type Result struct {
	Device   Device
	Neighbor Neighbor
	// TorID is the selected neighbor attribute; empty when unresolved.
	TorID string
}

// DiscoverOptions controls Discover.
type DiscoverOptions struct {
	// Field selects the neighbor attribute used as the ToR ID.
	Field string
	// Timeout bounds how long Discover waits for every device to see a
	// neighbor. lldpd learns a neighbor only after the switch's next LLDP
	// frame (30 s by default), so right after boot a single query can miss.
	// Zero queries exactly once.
	Timeout time.Duration
	// PollInterval is the delay between queries while waiting.
	PollInterval time.Duration
	// QueryTimeout bounds each query (DefaultQueryTimeout when zero). A query
	// is also cut off at Timeout, so Discover returns within
	// max(Timeout, QueryTimeout) even if the LLDP agent hangs.
	QueryTimeout time.Duration
}

// Discover resolves each device's ToR ID from LLDP, re-querying until every
// device has one or opts.Timeout expires. It returns one Result per device in
// input order; unresolved devices (including those with an empty Netdev) have
// an empty TorID. The error is the last query error, returned only when no
// query ever succeeded.
func Discover(ctx context.Context, q Querier, devices []Device, opts DiscoverOptions) ([]Result, error) {
	results := make([]Result, len(devices))
	for i, d := range devices {
		results[i].Device = d
	}
	if len(devices) == 0 {
		return results, nil
	}
	poll := opts.PollInterval
	if poll <= 0 {
		poll = 2 * time.Second
	}
	queryTimeout := opts.QueryTimeout
	if queryTimeout <= 0 {
		queryTimeout = DefaultQueryTimeout
	}
	deadline := time.Now().Add(opts.Timeout)

	var lastErr error
	succeeded := false
	for {
		// Bound each query by queryTimeout and by the overall deadline. With
		// no time left (Timeout 0), the single query gets queryTimeout.
		budget := queryTimeout
		if remaining := time.Until(deadline); remaining > 0 && remaining < budget {
			budget = remaining
		}
		qctx, cancel := context.WithTimeout(ctx, budget)
		neighbors, err := q.Neighbors(qctx)
		cancel()
		if err != nil {
			lastErr = err
		} else {
			succeeded = true
			pending := 0
			for i := range results {
				// A device without a netdev can never resolve; do not wait for it.
				if results[i].TorID != "" || results[i].Device.Netdev == "" {
					continue
				}
				if n, ok := neighbors[results[i].Device.Netdev]; ok {
					results[i].Neighbor = n
					results[i].TorID = n.TorID(opts.Field)
				}
				if results[i].TorID == "" {
					pending++
				}
			}
			if pending == 0 {
				return results, nil
			}
		}
		if !time.Now().Add(poll).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			if !succeeded {
				return results, ctx.Err()
			}
			return results, nil
		case <-time.After(poll):
		}
	}
	if !succeeded {
		return results, lastErr
	}
	return results, nil
}
