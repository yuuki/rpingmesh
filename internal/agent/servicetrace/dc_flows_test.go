package servicetrace

import (
	"sync"
	"testing"
	"time"
)

func TestDCFlowsMultipleRemotesAndExpiry(t *testing.T) {
	table, err := newDCFlowTable(2, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(100, 0)
	a, b, c := dcPrefix(t), dcPrefix(t), dcPrefix(t)
	b[63], c[63] = 2, 3
	observe := func(prefix []byte, seconds int) {
		t.Helper()
		if err := table.observeCommitted(1, 1, 0x12345, prefix, base.Add(time.Duration(seconds)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	observe(a, 0)
	observe(b, 1)
	flows := table.snapshot(base.Add(time.Second))
	if len(flows) != 2 || flows[0].Address.RemoteGID[15] != 1 || flows[1].Address.RemoteGID[15] != 2 {
		t.Fatalf("one DCI lost a remote: %+v", flows)
	}
	observe(a, 2) // refresh A, then capacity pressure must evict B
	observe(c, 3)
	flows = table.snapshot(base.Add(3 * time.Second))
	if len(flows) != 2 || flows[0].Address.RemoteGID[15] != 1 || flows[1].Address.RemoteGID[15] != 3 || !flows[0].FirstSeen.Equal(base) || !flows[0].LastSeen.Equal(base.Add(2*time.Second)) {
		t.Fatalf("bad refresh/eviction: %+v", flows)
	}
	flows[0].Address.RemoteGID[15] = 99 // snapshot must not alias internal storage
	flows = table.snapshot(base.Add(12 * time.Second))
	if len(flows) != 1 || flows[0].Address.RemoteGID[15] != 3 {
		t.Fatalf("wrong inactivity expiry: %+v", flows)
	}
	if err := table.observeCommitted(1, 1, 0x12345, a, base.Add(11*time.Second)); err == nil {
		t.Fatal("accepted out-of-order event")
	}
	if len(table.snapshot(base.Add(13*time.Second))) != 0 {
		t.Fatal("last flow did not expire at timeout boundary")
	}
}

func TestDCFlowsIdentityAndTeardown(t *testing.T) {
	table, _ := newDCFlowTable(10, time.Minute)
	now := time.Unix(100, 0)
	a, b := dcPrefix(t), dcPrefix(t)
	b[31]++ // same DCI/DCT/GID, different AV UDP port
	for _, item := range []struct {
		dci    uint64
		port   uint8
		prefix []byte
	}{{1, 1, a}, {1, 1, b}, {1, 2, a}, {2, 1, a}} {
		if err := table.observeCommitted(item.dci, item.port, 0x12345, item.prefix, now); err != nil {
			t.Fatal(err)
		}
	}
	if flows := table.snapshot(now); len(flows) != 4 {
		t.Fatalf("merged different source ports, RNIC ports, or DCI lifetimes: %+v", flows)
	}
	table.forgetDCI(1)
	flows := table.snapshot(now)
	if len(flows) != 1 || flows[0].DCI != 2 {
		t.Fatalf("teardown affected another DCI lifetime: %+v", flows)
	}
	table.reset()
	if len(table.snapshot(now)) != 0 {
		t.Fatal("capture loss retained stale flows")
	}
}

func TestDCFlowsInvalidObservation(t *testing.T) {
	for _, args := range []struct {
		capacity int
		ttl      time.Duration
	}{{0, time.Second}, {-1, time.Second}, {1, 0}, {1, -time.Second}} {
		if _, err := newDCFlowTable(args.capacity, args.ttl); err == nil {
			t.Fatal("accepted invalid bounds")
		}
	}
	table, _ := newDCFlowTable(1, time.Minute)
	now := time.Unix(100, 0)
	for _, err := range []error{
		table.observeCommitted(0, 1, 0x12345, dcPrefix(t), now),
		table.observeCommitted(1, 0, 0x12345, dcPrefix(t), now),
		table.observeCommitted(1, 1, 0x12345, dcPrefix(t), time.Time{}),
		table.observeCommitted(1, 1, 0x12345, nil, now),
	} {
		if err == nil {
			t.Fatal("accepted invalid observation")
		}
	}
	if len(table.snapshot(now)) != 0 {
		t.Fatal("invalid observation published a flow")
	}
}

func TestDCFlowsConcurrentAccess(t *testing.T) {
	table, _ := newDCFlowTable(2, time.Minute)
	now := time.Unix(100, 0)
	prefix := dcPrefix(t)
	var wg sync.WaitGroup
	for id := uint64(1); id <= 4; id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if err := table.observeCommitted(id, 1, 0x12345, prefix, now); err != nil {
					t.Error(err)
				}
				if len(table.snapshot(now)) > 2 {
					t.Error("exceeded capacity")
				}
				table.forgetDCI(id)
				table.reset()
			}
		}()
	}
	wg.Wait()
}
