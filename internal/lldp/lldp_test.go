package lldp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// json0Sample mirrors `lldpcli -f json0 show neighbors` with two interfaces:
// one with a full neighbor and one whose switch advertises no system name.
const json0Sample = `{
  "lldp": [{
    "interface": [
      {
        "name": "ens1f0np0", "via": "LLDP", "rid": "1", "age": "0 day, 00:10:00",
        "chassis": [{
          "id": [{"type": "mac", "value": "aa:bb:cc:00:00:01"}],
          "name": [{"value": "leaf-a1"}],
          "descr": [{"value": "switch OS"}]
        }],
        "port": [{
          "id": [{"type": "ifname", "value": "Ethernet12"}],
          "descr": [{"value": "host01 rail0"}]
        }]
      },
      {
        "name": "ens2f0np0", "via": "LLDP", "rid": "2",
        "chassis": [{"id": [{"type": "mac", "value": "aa:bb:cc:00:00:02"}]}],
        "port": [{"id": [{"type": "ifname", "value": "Ethernet3"}]}]
      }
    ]
  }]
}`

func TestParseJSON0(t *testing.T) {
	got, err := ParseJSON0([]byte(json0Sample))
	if err != nil {
		t.Fatalf("ParseJSON0: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d neighbors, want 2", len(got))
	}
	a := got["ens1f0np0"]
	if a.SystemName != "leaf-a1" || a.ChassisID != "aa:bb:cc:00:00:01" ||
		a.PortID != "Ethernet12" || a.PortDescr != "host01 rail0" {
		t.Errorf("unexpected neighbor: %+v", a)
	}
	b := got["ens2f0np0"]
	if b.SystemName != "" || b.ChassisID != "aa:bb:cc:00:00:02" {
		t.Errorf("unexpected neighbor: %+v", b)
	}
	if b.TorID(FieldSystemName) != "" || b.TorID(FieldChassisID) != "aa:bb:cc:00:00:02" {
		t.Errorf("TorID field selection wrong: %+v", b)
	}
}

func TestParseJSON0_NoNeighbors(t *testing.T) {
	for _, in := range []string{`{"lldp": [{}]}`, `{"lldp": []}`, `{}`} {
		got, err := ParseJSON0([]byte(in))
		if err != nil {
			t.Fatalf("ParseJSON0(%s): %v", in, err)
		}
		if len(got) != 0 {
			t.Errorf("ParseJSON0(%s) = %v, want empty", in, got)
		}
	}
	if _, err := ParseJSON0([]byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNetdevForRDMAPort(t *testing.T) {
	root := t.TempDir()
	ib := filepath.Join(root, "class", "infiniband")

	// GID attribute present: it wins over device/net.
	writeFile(t, filepath.Join(ib, "mlx5_0", "ports", "1", "gid_attrs", "ndevs", "3"), "ens1f0np0\n")
	writeFile(t, filepath.Join(ib, "mlx5_0", "device", "net", "other", "x"), "")
	if got, err := NetdevForRDMAPort(root, "mlx5_0", 1, 3); err != nil || got != "ens1f0np0" {
		t.Errorf("gid_attrs: got %q, %v", got, err)
	}

	// Fallback to the only PCI netdev.
	writeFile(t, filepath.Join(ib, "mlx5_1", "device", "net", "ens2f0np0", "x"), "")
	if got, err := NetdevForRDMAPort(root, "mlx5_1", 1, 0); err != nil || got != "ens2f0np0" {
		t.Errorf("device/net fallback: got %q, %v", got, err)
	}

	// Ambiguous fallback is an error.
	writeFile(t, filepath.Join(ib, "mlx5_2", "device", "net", "a", "x"), "")
	writeFile(t, filepath.Join(ib, "mlx5_2", "device", "net", "b", "x"), "")
	if _, err := NetdevForRDMAPort(root, "mlx5_2", 1, 0); err == nil {
		t.Error("expected error for ambiguous netdevs")
	}

	// Unknown device is an error.
	if _, err := NetdevForRDMAPort(root, "mlx5_9", 1, 0); err == nil {
		t.Error("expected error for unknown device")
	}
}

// fakeQuerier returns successive responses, repeating the last one.
type fakeQuerier struct {
	responses []map[string]Neighbor
	errs      []error
	calls     int
}

func (f *fakeQuerier) Neighbors(context.Context) (map[string]Neighbor, error) {
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	return f.responses[i], f.errs[i]
}

func TestDiscover_WaitsForLateNeighbor(t *testing.T) {
	q := &fakeQuerier{
		responses: []map[string]Neighbor{
			{"eth0": {SystemName: "leaf-a"}},
			{"eth0": {SystemName: "leaf-a"}, "eth1": {SystemName: " leaf-b "}},
		},
		errs: []error{nil, nil},
	}
	devs := []Device{{Name: "mlx5_0", Netdev: "eth0"}, {Name: "mlx5_1", Netdev: "eth1"}, {Name: "mlx5_2"}}
	res, err := Discover(context.Background(), q, devs, DiscoverOptions{
		Field: FieldSystemName, Timeout: time.Second, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if q.calls != 2 {
		t.Errorf("calls = %d, want 2 (device without netdev must not be waited for)", q.calls)
	}
	want := []string{"leaf-a", "leaf-b", ""}
	for i, w := range want {
		if res[i].TorID != w {
			t.Errorf("res[%d].TorID = %q, want %q", i, res[i].TorID, w)
		}
	}
}

func TestDiscover_TimeoutLeavesUnresolved(t *testing.T) {
	q := &fakeQuerier{
		responses: []map[string]Neighbor{{"eth0": {SystemName: "leaf-a"}}},
		errs:      []error{nil},
	}
	devs := []Device{{Name: "mlx5_0", Netdev: "eth0"}, {Name: "mlx5_1", Netdev: "eth1"}}
	res, err := Discover(context.Background(), q, devs, DiscoverOptions{
		Field: FieldSystemName, Timeout: 20 * time.Millisecond, PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res[0].TorID != "leaf-a" || res[1].TorID != "" {
		t.Errorf("unexpected results: %+v", res)
	}
	if q.calls < 2 {
		t.Errorf("calls = %d, want retries until timeout", q.calls)
	}
}

func TestDiscover_ZeroTimeoutQueriesOnce(t *testing.T) {
	q := &fakeQuerier{responses: []map[string]Neighbor{{}}, errs: []error{nil}}
	_, err := Discover(context.Background(), q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, DiscoverOptions{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if q.calls != 1 {
		t.Errorf("calls = %d, want 1", q.calls)
	}
}

func TestDiscover_QueryErrorReturned(t *testing.T) {
	boom := errors.New("socket permission denied")
	q := &fakeQuerier{responses: []map[string]Neighbor{nil}, errs: []error{boom}}
	res, err := Discover(context.Background(), q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, DiscoverOptions{
		Timeout: 10 * time.Millisecond, PollInterval: 2 * time.Millisecond,
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if res[0].TorID != "" {
		t.Errorf("unexpected TorID %q", res[0].TorID)
	}
}

func TestDiscover_ContextCancel(t *testing.T) {
	q := &fakeQuerier{responses: []map[string]Neighbor{{}}, errs: []error{nil}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := Discover(ctx, q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, DiscoverOptions{
		Timeout: time.Minute, PollInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("Discover did not stop on context cancellation")
	}
}

// hangingQuerier blocks until its context is done, like lldpcli stuck on an
// unresponsive lldpd socket.
type hangingQuerier struct{}

func (hangingQuerier) Neighbors(ctx context.Context) (map[string]Neighbor, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDiscover_HangingQueryIsBounded(t *testing.T) {
	for name, opts := range map[string]DiscoverOptions{
		"zero timeout":        {QueryTimeout: 50 * time.Millisecond},
		"timeout below query": {Timeout: 50 * time.Millisecond, QueryTimeout: time.Minute},
		"query below timeout": {Timeout: 150 * time.Millisecond, QueryTimeout: 30 * time.Millisecond, PollInterval: 10 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := Discover(context.Background(), hangingQuerier{}, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, opts)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want deadline exceeded", err)
			}
			if el := time.Since(start); el > time.Second {
				t.Errorf("Discover took %v; a hanging query must be cut off", el)
			}
		})
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lldpcli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIQuerier(t *testing.T) {
	path := writeScript(t, "cat <<'JSON'\n"+json0Sample+"\nJSON\n")
	got, err := CLIQuerier{Path: path}.Neighbors(context.Background())
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if got["ens1f0np0"].SystemName != "leaf-a1" {
		t.Errorf("unexpected neighbors: %+v", got)
	}

	fail := writeScript(t, "echo 'unable to connect to socket' >&2; exit 1\n")
	if _, err := (CLIQuerier{Path: fail}).Neighbors(context.Background()); err == nil {
		t.Error("expected an error from a failing lldpcli")
	}
}

func TestCLIQuerier_HangIsKilled(t *testing.T) {
	// The background sleep keeps stdout open after the shell is killed;
	// WaitDelay must still let Neighbors return.
	path := writeScript(t, "sleep 30 &\nsleep 30\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (CLIQuerier{Path: path}).Neighbors(ctx); err == nil {
		t.Error("expected an error from a hung lldpcli")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("Neighbors took %v after its context expired", el)
	}
}
