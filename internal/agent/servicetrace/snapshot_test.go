package servicetrace

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
)

func nlAttr(kind uint16, value []byte) []byte {
	out := make([]byte, (4+len(value)+3)&^3)
	binary.NativeEndian.PutUint16(out, uint16(4+len(value)))
	binary.NativeEndian.PutUint16(out[2:], kind)
	copy(out[4:], value)
	return out
}

func nlU32(value uint32) []byte {
	out := make([]byte, 4)
	binary.NativeEndian.PutUint32(out, value)
	return out
}

func nlJoin(attrs ...[]byte) []byte {
	var out []byte
	for _, a := range attrs {
		out = append(out, a...)
	}
	return out
}

func qpEntryAttr(qpn, pid uint32, remote bool) []byte {
	// Numeric attribute IDs below are the Linux UAPI, intentionally
	// independent of the decoder's named constants.
	out := nlJoin(nlAttr(21, nlU32(qpn)), nlAttr(26, []byte{2}), nlAttr(27, []byte{3}), nlAttr(28, nlU32(pid)))
	if remote {
		out = append(out, nlAttr(22, nlU32(0x200))...)
	}
	return nlAttr(20|0x8000, out)
}

func TestSnapshotQPsRequestsMonitoredDevices(t *testing.T) {
	ctx := context.Background()
	var calls int
	dump := func(_ context.Context, cmd uint16, attrs []byte) ([][]byte, error) {
		calls++
		switch calls {
		case 1:
			if cmd != 5121 || len(attrs) != 0 {
				t.Fatalf("device request = %d %x", cmd, attrs)
			}
			return [][]byte{
				nlJoin(nlAttr(1, nlU32(123)), nlAttr(2, []byte("mlx5_0\x00"))),
				nlJoin(nlAttr(1, nlU32(124)), nlAttr(2, []byte("mlx5_1\x00"))),
			}, nil
		case 2:
			if cmd != 5130 || !reflect.DeepEqual(attrs, nlAttr(1, nlU32(123))) {
				t.Fatalf("QP request = %d %x", cmd, attrs)
			}
			return [][]byte{nlAttr(19|0x8000, nlJoin(qpEntryAttr(0x100, 42, true), qpEntryAttr(0x101, 43, false)))}, nil
		default:
			t.Fatal("queried an unmonitored device")
			return nil, nil
		}
	}
	got, err := snapshotQPs(ctx, map[uint32]string{devA: "mlx5_0"}, dump)
	want := []QPResource{
		{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, PID: 42},
		{Dev: devA, LocalQPN: 0x101, QPType: QPTypeRC, QPState: QPStateRTS, PID: 43},
	}
	if err != nil || !reflect.DeepEqual(got, want) || calls != 2 {
		t.Fatalf("snapshot = %+v, %v, calls=%d", got, err, calls)
	}
}

func TestDecodeQPResourcesRejectsMalformedDump(t *testing.T) {
	for name, msg := range map[string][]byte{
		"short_header":   {1, 2, 3},
		"short_length":   {3, 0, 19, 0},
		"overrun":        {100, 0, 19, 0},
		"missing_table":  nlAttr(1, nlU32(1)),
		"short_entry":    nlAttr(19, []byte{1}),
		"entry_overrun":  nlAttr(19, []byte{100, 0, 20, 0}),
		"missing_fields": nlAttr(19, nlAttr(20, nlAttr(21, nlU32(1)))),
		"short_pid":      nlAttr(19, nlAttr(20, nlJoin(nlAttr(21, nlU32(1)), nlAttr(26, []byte{2}), nlAttr(27, []byte{3}), nlAttr(28, []byte{42})))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeQPResources(msg, devA); err == nil {
				t.Fatal("accepted malformed dump")
			}
		})
	}
}

func TestDecodeQPResourcesIgnoresUnknownAttributes(t *testing.T) {
	msg := nlJoin(nlAttr(999, []byte{1}), nlAttr(19, nlJoin(nlAttr(1000, []byte{2}), qpEntryAttr(12, 42, false))))
	got, err := decodeQPResources(msg, devA)
	if err != nil || len(got) != 1 || got[0].LocalQPN != 12 {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	// Kernel resources carry KERN_NAME; a user QP whose creator task
	// exited can omit PID while the QP remains alive in another thread.
	msg = nlAttr(19, nlAttr(20, nlJoin(nlAttr(21, nlU32(1)), nlAttr(26, []byte{2}), nlAttr(27, []byte{3}), nlAttr(29, []byte("kernel\x00")))))
	got, err = decodeQPResources(msg, devA)
	if err != nil || len(got) != 1 || got[0].PID != 0 || !got[0].Kernel {
		t.Fatalf("kernel QP decode = %+v, %v", got, err)
	}
	msg = nlAttr(19, nlAttr(20, nlJoin(nlAttr(21, nlU32(1)), nlAttr(26, []byte{2}), nlAttr(27, []byte{3}))))
	got, err = decodeQPResources(msg, devA)
	if err != nil || len(got) != 1 || got[0].PID != 0 || got[0].Kernel {
		t.Fatalf("user QP after creator exit = %+v, %v", got, err)
	}
}

func TestSnapshotQPsDiscardsPartialDump(t *testing.T) {
	failure := errors.New("interrupted")
	calls := 0
	got, err := snapshotQPs(context.Background(), map[uint32]string{devA: "mlx5_0", devB: "mlx5_1"}, func(_ context.Context, _ uint16, _ []byte) ([][]byte, error) {
		calls++
		switch calls {
		case 1:
			return [][]byte{nlJoin(nlAttr(1, nlU32(1)), nlAttr(2, []byte("mlx5_0\x00"))), nlJoin(nlAttr(1, nlU32(2)), nlAttr(2, []byte("mlx5_1\x00")))}, nil
		case 2:
			return [][]byte{nlAttr(19, qpEntryAttr(12, 42, true))}, nil
		default:
			return nil, failure
		}
	})
	if !errors.Is(err, failure) || got != nil {
		t.Fatalf("partial dump escaped: %+v, %v", got, err)
	}
}

// A driver query can block inside a syscall without observing context.
// The caller must still return, and refreshes must not pile up workers.
func TestSnapshotDeadlineWithStalledCollector(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	workerDone := make(chan struct{})
	defer func() {
		close(release)
		<-workerDone
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	devices := map[uint32]string{devA: "mlx5_0"}
	returned := make(chan error, 1)
	go func() {
		_, err := boundedQPSnapshot(ctx, devices, func(_ context.Context, owned map[uint32]string) ([]QPResource, error) {
			close(started)
			<-release
			if owned[devA] != "mlx5_0" {
				t.Error("worker retained the caller's mutable device map")
			}
			close(workerDone)
			return []QPResource{{Dev: devA}}, nil
		})
		returned <- err
	}()
	<-started
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled snapshot = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled collector blocked its caller")
	}
	devices[devA] = "changed"
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	_, err := boundedQPSnapshot(ctx2, devices, func(context.Context, map[uint32]string) ([]QPResource, error) {
		t.Error("a second collector started while the first was stalled")
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second snapshot = %v", err)
	}
}
