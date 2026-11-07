package lldp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"
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

// queryStep is one scripted answer of scriptedQuerier.
type queryStep struct {
	neighbors map[string]Neighbor
	err       error
	// then runs before the answer is returned, e.g. to cancel the caller.
	then func()
}

// scriptedQuerier answers query i with steps[i], repeating the last step,
// and records when each query ran, its deadline and its context's state.
type scriptedQuerier struct {
	steps     []queryStep
	at        []time.Time
	deadlines []time.Time
	ctxErrs   []error
}

func (q *scriptedQuerier) Neighbors(ctx context.Context) (map[string]Neighbor, error) {
	q.at = append(q.at, time.Now())
	deadline, _ := ctx.Deadline()
	q.deadlines = append(q.deadlines, deadline)
	q.ctxErrs = append(q.ctxErrs, ctx.Err())
	step := q.steps[min(len(q.at), len(q.steps))-1]
	if step.then != nil {
		step.then()
	}
	return step.neighbors, step.err
}

func TestDiscover_Characterization(t *testing.T) {
	t.Parallel()
	errA, errB := errors.New("lldpd socket refused"), errors.New("lldpd socket timed out")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eth := []Device{{Name: "mlx5_0", Netdev: "eth0"}, {Name: "mlx5_1", Netdev: "eth1"}, {Name: "mlx5_2", Netdev: "eth0"}}
	leafA, leafB := Neighbor{Interface: "eth0", SystemName: " leaf-a ", ChassisID: " aa:01 "}, Neighbor{Interface: "eth1", SystemName: "leaf-b", ChassisID: "aa:02"}
	resolved := func(d Device, n Neighbor, id string) Result { return Result{Device: d, Neighbor: n, TorID: id} }
	// Long enough for a retry even when the first query is scheduled late.
	short := DiscoverOptions{Timeout: 500 * time.Millisecond, PollInterval: 10 * time.Millisecond}
	for _, tt := range []struct {
		name    string
		ctx     context.Context
		devices []Device
		opts    DiscoverOptions
		steps   []queryStep
		want    []Result
		err     error
		calls   int // 0: at least two
	}{
		{name: "no devices", devices: nil, opts: short, steps: []queryStep{{err: errA}}, want: []Result{}, calls: -1},
		{
			name: "system name in input order", devices: eth, opts: short,
			steps: []queryStep{{neighbors: map[string]Neighbor{"eth0": leafA, "eth1": leafB}}},
			want:  []Result{resolved(eth[0], leafA, "leaf-a"), resolved(eth[1], leafB, "leaf-b"), resolved(eth[2], leafA, "leaf-a")}, calls: 1,
		},
		{
			name: "chassis id", devices: eth[:2], opts: DiscoverOptions{Field: FieldChassisID},
			steps: []queryStep{{neighbors: map[string]Neighbor{"eth0": leafA, "eth1": leafB}}},
			want:  []Result{resolved(eth[0], leafA, "aa:01"), resolved(eth[1], leafB, "aa:02")}, calls: 1,
		},
		{
			name: "a resolved device keeps its first neighbor", devices: eth[:2], opts: short,
			steps: []queryStep{
				{neighbors: map[string]Neighbor{"eth0": leafA}},
				{neighbors: map[string]Neighbor{"eth0": leafB, "eth1": leafB}},
			},
			want: []Result{resolved(eth[0], leafA, "leaf-a"), resolved(eth[1], leafB, "leaf-b")}, calls: 2,
		},
		{
			name: "a neighbor without the field keeps the device pending", devices: eth[:1], opts: short,
			steps: []queryStep{
				{neighbors: map[string]Neighbor{"eth0": {ChassisID: "aa:01"}}},
				{neighbors: map[string]Neighbor{"eth0": {ChassisID: "aa:09", SystemName: "leaf-x"}}},
			},
			want: []Result{resolved(eth[0], Neighbor{ChassisID: "aa:09", SystemName: "leaf-x"}, "leaf-x")}, calls: 2,
		},
		{
			name: "an unresolved device keeps the last neighbor seen", devices: eth[:1], opts: short,
			steps: []queryStep{{neighbors: map[string]Neighbor{"eth0": {ChassisID: "aa:01"}}}, {err: errA}, {}},
			want:  []Result{resolved(eth[0], Neighbor{ChassisID: "aa:01"}, "")},
		},
		{
			name: "devices without a netdev are not waited for", devices: []Device{{Name: "mlx5_0"}, {Name: "mlx5_1"}}, opts: DiscoverOptions{Timeout: time.Minute, PollInterval: 10 * time.Second},
			steps: []queryStep{{neighbors: map[string]Neighbor{"": leafA}}},
			want:  []Result{{Device: Device{Name: "mlx5_0"}}, {Device: Device{Name: "mlx5_1"}}}, calls: 1,
		},
		{
			name: "query errors repeat until the timeout", devices: []Device{{Name: "mlx5_0"}}, opts: short,
			steps: []queryStep{{err: errA}, {err: errB}},
			want:  []Result{{Device: Device{Name: "mlx5_0"}}}, err: errB,
		},
		{
			name: "an error after a success is not returned", devices: eth[:2], opts: short,
			steps: []queryStep{{neighbors: map[string]Neighbor{"eth0": leafA}}, {err: errA}},
			want:  []Result{resolved(eth[0], leafA, "leaf-a"), {Device: eth[1]}},
		},
		{
			name: "an error before a success is not returned", devices: eth[:1], opts: short,
			steps: []queryStep{{err: errA}, {neighbors: map[string]Neighbor{"eth0": leafA}}},
			want:  []Result{resolved(eth[0], leafA, "leaf-a")}, calls: 2,
		},
		{
			name: "zero timeout returns the only error", devices: eth[:1], opts: DiscoverOptions{PollInterval: time.Millisecond},
			steps: []queryStep{{err: errA}}, want: []Result{{Device: eth[0]}}, err: errA, calls: 1,
		},
		{
			name: "cancellation while waiting without a success", ctx: ctx, devices: eth[:1], opts: DiscoverOptions{Timeout: time.Minute, PollInterval: 10 * time.Second},
			steps: []queryStep{{err: errA, then: cancel}}, want: []Result{{Device: eth[0]}}, err: context.Canceled, calls: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := &scriptedQuerier{steps: tt.steps}
			c := tt.ctx
			if c == nil {
				c = context.Background()
			}
			res, err := Discover(c, q, tt.devices, tt.opts)
			if err != tt.err {
				t.Errorf("err = %v, want %v", err, tt.err)
			}
			if !reflect.DeepEqual(res, tt.want) {
				t.Errorf("results = %+v, want %+v", res, tt.want)
			}
			switch {
			case tt.calls < 0 && len(q.at) != 0:
				t.Errorf("queried %d times, want none", len(q.at))
			case tt.calls == 0 && len(q.at) < 2:
				t.Errorf("queried %d times, want retries", len(q.at))
			case tt.calls > 0 && len(q.at) != tt.calls:
				t.Errorf("queried %d times, want %d", len(q.at), tt.calls)
			}
		})
	}
}

func TestDiscover_CancellationAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := &scriptedQuerier{steps: []queryStep{{neighbors: map[string]Neighbor{}, then: cancel}}}
	start := time.Now()
	res, err := Discover(ctx, q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, DiscoverOptions{Timeout: time.Minute, PollInterval: 10 * time.Second})
	if err != nil || len(res) != 1 || res[0].TorID != "" || len(q.at) != 1 {
		t.Fatalf("Discover = %+v, %v after %d queries", res, err, len(q.at))
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("Discover took %v after cancellation", el)
	}
}

func TestDiscover_NoTimeLeftIgnoresCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	boom := errors.New("lldpcli killed")
	q := &scriptedQuerier{steps: []queryStep{{err: boom}}}
	if _, err := Discover(ctx, q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, DiscoverOptions{}); err != boom {
		t.Fatalf("err = %v, want the query error", err)
	}
	if len(q.ctxErrs) != 1 || !errors.Is(q.ctxErrs[0], context.Canceled) {
		t.Fatalf("query contexts = %v, want one derived from the cancelled caller", q.ctxErrs)
	}
}

func TestDiscover_QueryBudget(t *testing.T) {
	// The querier answers at once, so long budgets cost nothing. They keep
	// the lower bound clear of scheduling delays between computing the
	// budget and the query recording it.
	for _, tt := range []struct {
		name string
		opts DiscoverOptions
		want time.Duration
	}{
		{"default query timeout", DiscoverOptions{}, DefaultQueryTimeout},
		{"query timeout", DiscoverOptions{QueryTimeout: 5 * time.Second}, 5 * time.Second},
		{"negative query timeout", DiscoverOptions{QueryTimeout: -time.Second}, DefaultQueryTimeout},
		{"timeout below the default", DiscoverOptions{Timeout: 5 * time.Second, PollInterval: time.Minute}, 5 * time.Second},
		{"query timeout below the timeout", DiscoverOptions{Timeout: time.Minute, PollInterval: time.Minute, QueryTimeout: 3 * time.Second}, 3 * time.Second},
		{"negative timeout", DiscoverOptions{Timeout: -time.Second, QueryTimeout: 4 * time.Second}, 4 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A device without a netdev resolves on the first successful query.
			q := &scriptedQuerier{steps: []queryStep{{}}}
			if _, err := Discover(context.Background(), q, []Device{{Name: "mlx5_0"}}, tt.opts); err != nil {
				t.Fatal(err)
			}
			if got := q.deadlines[0].Sub(q.at[0]); got > tt.want || got < tt.want-time.Second {
				t.Fatalf("query budget = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscover_QueriesShareTheOverallDeadline(t *testing.T) {
	t.Parallel()
	const timeout = 300 * time.Millisecond
	q := &scriptedQuerier{steps: []queryStep{{}}}
	start := time.Now()
	_, err := Discover(context.Background(), q, []Device{{Name: "mlx5_0", Netdev: "eth0"}},
		DiscoverOptions{Timeout: timeout, PollInterval: 50 * time.Millisecond, QueryTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(q.at) < 2 {
		t.Fatalf("queried %d times, want retries", len(q.at))
	}
	// A query that starts before the overall deadline (no earlier than
	// start+timeout) is cut off there: its deadline is at or after that
	// point and at most timeout after the query began, far below
	// QueryTimeout. A retry that a late wakeup starts after the deadline
	// gets the whole QueryTimeout instead, so it is not checked.
	checked := 0
	for i, d := range q.deadlines {
		if !q.at[i].Before(start.Add(timeout)) {
			continue
		}
		checked++
		if d.Before(start.Add(timeout)) || d.After(q.at[i].Add(timeout)) {
			t.Fatalf("query %d at %v has deadline %v; want the overall deadline, near %v",
				i, q.at[i].Sub(start), d.Sub(start), timeout)
		}
	}
	if checked == 0 {
		t.Fatal("no query started before the overall deadline")
	}
}

func TestDiscover_StopsWhenTheNextPollMissesTheDeadline(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		opts  DiscoverOptions
		calls int
	}{
		// The first check passes unless the first query takes 400ms, the
		// second fails whatever the delays: exactly one poll.
		{"poll fits once", DiscoverOptions{Timeout: time.Second, PollInterval: 600 * time.Millisecond}, 2},
		// The deadline is set before the first query, so the first poll
		// would end past it.
		{"poll as long as the timeout", DiscoverOptions{Timeout: 50 * time.Millisecond, PollInterval: 50 * time.Millisecond}, 1},
		{"default poll exceeds the timeout", DiscoverOptions{Timeout: time.Second}, 1},
		{"negative poll uses the default", DiscoverOptions{Timeout: time.Second, PollInterval: -time.Millisecond}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := &scriptedQuerier{steps: []queryStep{{}}}
			if _, err := Discover(context.Background(), q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, tt.opts); err != nil {
				t.Fatal(err)
			}
			// Every poll is followed by a query, so the query count also
			// bounds how long Discover waited.
			if len(q.at) != tt.calls {
				t.Fatalf("queried %d times, want %d", len(q.at), tt.calls)
			}
		})
	}
}

func TestDiscover_DefaultPollInterval(t *testing.T) {
	t.Parallel()
	// With the 2s default, the first poll fits in 3s unless the first query
	// takes a second, and a second poll never does. A 1s default would
	// query three times, a 3s one once.
	q := &scriptedQuerier{steps: []queryStep{{}}}
	if _, err := Discover(context.Background(), q, []Device{{Name: "mlx5_0", Netdev: "eth0"}}, DiscoverOptions{Timeout: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if len(q.at) != 2 {
		t.Fatalf("queried %d times, want 2", len(q.at))
	}
	if gap := q.at[1].Sub(q.at[0]); gap < 2*time.Second || gap > 3*time.Second {
		t.Fatalf("poll interval = %v, want the 2s default", gap)
	}
}

// FuzzParseJSON0 checks that ParseJSON0 accepts only valid JSON (lldpcli
// output is external input) and keys every neighbor by its non-empty local
// interface name. Every field is valid UTF-8 even when the switch sent
// arbitrary bytes in a TLV (encoding/json replaces them with U+FFFD), so a
// ToR ID taken from LLDP can always travel in a protobuf string or an OTel
// attribute.
func FuzzParseJSON0(f *testing.F) {
	f.Add([]byte(json0Sample))
	f.Add([]byte(`{"lldp":[{}]}`))
	f.Add([]byte(`{"lldp":[{"interface":[{"name":"eth0"},{"name":"eth0","chassis":[{"name":[{"value":"x"}]}]}]}]}`))
	f.Add([]byte(`{"lldp":{"interface":"not a list"}}`))
	f.Add([]byte("{\"lldp\":[{\"interface\":[{\"name\":\"eth0\",\"chassis\":[{\"name\":[{\"value\":\"leaf-\xff\\udc80\"}]}]}]}]}"))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseJSON0(data)
		if err != nil {
			if got != nil {
				t.Fatalf("partial result %v with error %v", got, err)
			}
			return
		}
		if !json.Valid(data) {
			t.Fatalf("accepted invalid JSON %q", data)
		}
		for name, n := range got {
			if name == "" || n.Interface != name {
				t.Fatalf("neighbor %+v keyed by %q", n, name)
			}
			for _, v := range []string{n.Interface, n.SystemName, n.ChassisID, n.PortID, n.PortDescr} {
				if !utf8.ValidString(v) {
					t.Fatalf("neighbor %+v has a field that is not valid UTF-8", n)
				}
			}
		}
	})
}
