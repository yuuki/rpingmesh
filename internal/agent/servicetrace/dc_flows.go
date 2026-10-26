package servicetrace

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

type dcFlowKey struct {
	// DCI is a nonzero, capture-session-wide lifetime token assigned by the
	// adapter. It must change on process/QP reuse; a PID, QPN or pointer alone
	// is not sufficient. The adapter owns the token -> device/owner mapping.
	DCI     uint64
	Port    uint8
	Address mlx5DCAddress
}

type dcFlow struct {
	dcFlowKey
	FirstSeen time.Time
	LastSeen  time.Time
}

// dcFlowTable retains submitted address vectors, not persistent connections.
// It is intentionally not wired into Table or the service monitor until a
// build-validated submission adapter and hardware port validation exist.
type dcFlowTable struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	clock    time.Time
	flows    map[dcFlowKey]*list.Element
	active   list.List // least recently observed first
}

func newDCFlowTable(capacity int, ttl time.Duration) (*dcFlowTable, error) {
	if capacity <= 0 || ttl <= 0 {
		return nil, fmt.Errorf("DC flow capacity and inactivity timeout must be positive")
	}
	return &dcFlowTable{capacity: capacity, ttl: ttl, flows: make(map[dcFlowKey]*list.Element)}, nil
}

// observeCommitted must only be called for an adapter-confirmed submission,
// never on AH creation, a DC setter, an aborted/failed batch, or a completion
// with an unknown submitted prefix. now is the observation time from the same
// monotonic clock used by snapshot, not a hardware timestamp. Older events
// are rejected; a live adapter must order events and filter destroyed tokens.
func (t *dcFlowTable) observeCommitted(dci uint64, port uint8, qpn uint32, prefix []byte, now time.Time) error {
	if dci == 0 || port == 0 || now.IsZero() {
		return fmt.Errorf("DC observation needs a lifetime token, port and timestamp")
	}
	address, err := decodeMLX5DCAddress(prefix, qpn)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Before(t.clock) {
		return fmt.Errorf("DC observation timestamp precedes table clock")
	}
	t.expire(now)
	key := dcFlowKey{DCI: dci, Port: port, Address: address}
	if e := t.flows[key]; e != nil {
		e.Value.(*dcFlow).LastSeen = now
		t.active.MoveToBack(e)
		return nil
	}
	if len(t.flows) == t.capacity {
		t.remove(t.active.Front())
	}
	flow := &dcFlow{dcFlowKey: key, FirstSeen: now, LastSeen: now}
	t.flows[key] = t.active.PushBack(flow)
	return nil
}

func (t *dcFlowTable) remove(e *list.Element) {
	delete(t.flows, e.Value.(*dcFlow).dcFlowKey)
	t.active.Remove(e)
}

// expire uses a nondecreasing clock, even if a snapshot caller supplies an
// older time. The list order and TTL are based on last observation time.
func (t *dcFlowTable) expire(now time.Time) {
	if now.After(t.clock) {
		t.clock = now
	}
	for e := t.active.Front(); e != nil; e = t.active.Front() {
		if t.clock.Sub(e.Value.(*dcFlow).LastSeen) < t.ttl {
			break
		}
		t.remove(e)
	}
}

func (t *dcFlowTable) snapshot(now time.Time) []dcFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expire(now)
	result := make([]dcFlow, 0, len(t.flows))
	for e := t.active.Front(); e != nil; e = e.Next() {
		result = append(result, *e.Value.(*dcFlow))
	}
	return result
}

// forgetDCI is called on QP destruction or owner exit. Before calling it the
// adapter must invalidate the token so buffered sends cannot resurrect it.
func (t *dcFlowTable) forgetDCI(dci uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, e := range t.flows {
		if key.DCI == dci {
			t.remove(e)
		}
	}
}

// reset drops all flows when capture is lost or the adapter restarts. A fresh
// capture session must use fresh tokens and discard old buffered observations.
func (t *dcFlowTable) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.flows)
	t.active.Init()
}
