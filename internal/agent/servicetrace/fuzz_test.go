package servicetrace

import (
	"bytes"
	"testing"
)

// Fuzz targets for the decoders of kernel-supplied binary input: tracer
// events (struct qp_event, shared with bpf/uverbs_trace.bpf.c), RDMA netlink
// QP dumps and mlx5 raw QP dumps. Each checks a property of what the decoder
// accepts, not only that it does not panic. FuzzDecodeMLX5DCAddress lives in
// mlx5_dc_test.go.

// FuzzDecodeEvent checks that DecodeEvent rejects records of the wrong size
// with an empty Event, and that re-encoding an accepted event reproduces
// every byte of the 112-byte record that carries a field (padding and the
// bytes after comm's terminator excepted).
func FuzzDecodeEvent(f *testing.F) {
	connect := Event{
		TimestampNS: 0x0102030405060708, Context: 0xffff9a1b2c3d4e50, CgroupID: 4242,
		PID: 1234, TID: 1235, Kind: KindQPModify, Source: SourceIoctlWrite,
		Dev: MakeDev(231, 192), QPHandle: 7, QPNum: 0x1a2b, QPType: QPTypeRC,
		AttrMask: AttrMaskState | AttrMaskAV | AttrMaskDestQPN, DestQPNum: 0x3c4d,
		FlowLabel: 0xabcde, QPState: QPStateRTR, SGIDIndex: 3, PortNum: 1,
		HopLimit: 64, TrafficClass: 96, SL: 3, IsGlobal: 1, DestPortNum: 1,
		Comm: "nccl-worker",
	}
	f.Add(rawEvent(connect))
	f.Add(rawEvent(Event{Kind: KindQPCreate, QPType: QPTypeUD, Comm: "sixteen-char-com"}))
	f.Add(rawEvent(Event{Kind: KindContextClose, Source: SourceWrite}))
	kernel := append(rawEvent(Event{Kind: KindQPCreate, Source: SourceKernel, QPNum: 9, QPType: QPTypeRC, PID: 1}), make([]byte, 64)...)
	copy(kernel[eventSize:], "mlx5_0")
	f.Add(kernel)
	f.Add(make([]byte, eventSize-1))
	f.Add(append(rawEvent(connect), 0xff)) // trailing bytes after a uverbs event

	f.Fuzz(func(t *testing.T, raw []byte) {
		ev, err := DecodeEvent(raw)
		if err != nil {
			if ev != (Event{}) {
				t.Fatalf("DecodeEvent returned %+v with error %v", ev, err)
			}
			return
		}
		if len(raw) < eventSize {
			t.Fatalf("accepted a %d-byte record", len(raw))
		}
		if ev.IsConnect() && ev.IsReset() {
			t.Fatalf("event is both a connect and a reset: %+v", ev)
		}

		want := bytes.Clone(raw[:eventSize])
		clear(want[68:72]) // padding before dgid
		if i := bytes.IndexByte(want[96:112], 0); i >= 0 {
			clear(want[96+i : 112]) // comm ends at its first NUL
		}
		if ev.Source == SourceKernel {
			if len(raw) != eventSize+64 {
				t.Fatalf("accepted a %d-byte kernel event", len(raw))
			}
			if ev.DeviceName == "" || !bytes.HasPrefix(raw[eventSize:], append([]byte(ev.DeviceName), 0)) {
				t.Fatalf("device name %q is not the NUL-terminated prefix of the extension", ev.DeviceName)
			}
			// A kernel workqueue is not a service owner: its identity is dropped.
			if ev.PID != 0 || ev.TID != 0 || ev.CgroupID != 0 || ev.Comm != "" {
				t.Fatalf("kernel event kept a process identity: %+v", ev)
			}
			clear(want[16:32])
			clear(want[96:112])
		} else if ev.DeviceName != "" {
			t.Fatalf("uverbs event has a device name %q", ev.DeviceName)
		}
		if got := rawEvent(ev); !bytes.Equal(got, want) {
			t.Fatalf("re-encoded event differs:\n got %x\nwant %x", got, want)
		}
	})
}

// FuzzDecodeQPResources checks that a netlink QP dump either fails as a
// whole or yields QPs that carry only what the dump says, and that the
// number of QPs is bounded by the input size (each RES_QP_ENTRY needs at
// least its own header plus the QPN, type and state attributes: 28 bytes).
func FuzzDecodeQPResources(f *testing.F) {
	f.Add(nlAttr(19|0x8000, nlJoin(qpEntryAttr(0x100, 42, true), qpEntryAttr(0x101, 0, false))))
	f.Add(nlJoin(nlAttr(1, nlU32(3)), nlAttr(19|0x8000, qpEntryAttr(0x102, 7, false))))
	f.Add(nlAttr(19|0x8000, nil))
	f.Add([]byte{})
	f.Add([]byte{4, 0})

	f.Fuzz(func(t *testing.T, msg []byte) {
		qps, err := decodeQPResources(msg, devA)
		if err != nil {
			if qps != nil {
				t.Fatalf("partial result %v with error %v", qps, err)
			}
			return
		}
		if 4+28*len(qps) > len(msg) {
			t.Fatalf("decoded %d QPs from %d bytes", len(qps), len(msg))
		}
		for _, qp := range qps {
			if qp.Dev != devA || qp.QPType > 0xff || qp.OwnerTGID != 0 || qp.Recovered != nil {
				t.Fatalf("decoded QP carries data the dump has no attribute for: %+v", qp)
			}
		}
	})
}

// FuzzDecodeMlx5QP checks that a raw mlx5 QP dump is accepted only as a
// recovery of the very QP that was asked for, with a usable address vector
// whose RoCEv2 source port the prober can reproduce.
func FuzzDecodeMlx5QP(f *testing.F) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42, OwnerTGID: 42}
	f.Add(mlx5QPFixture(qp, 0))
	f.Add(mlx5QPFixture(qp, 0xabcde))
	f.Add(mlx5QPFixture(qp, 1)[:64])

	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := decodeMlx5QP(raw, qp)
		if err != nil {
			if c != (Connection{}) {
				t.Fatalf("partial connection %+v with error %v", c, err)
			}
			return
		}
		if !c.FromSnapshot || c.Kernel || c.Dev != qp.Dev || c.LocalQPN != qp.LocalQPN ||
			c.RemoteQPN != qp.RemoteQPN || c.QPType != qp.QPType || c.PID != qp.OwnerTGID ||
			uint32(c.Port) != qp.Port {
			t.Fatalf("recovered connection does not describe the queried QP: %+v", c)
		}
		if c.RemoteGID == ([16]byte{}) || c.FlowLabel > FlowLabelMask || c.SL > 0xf {
			t.Fatalf("recovered connection has an unusable address vector: %+v", c)
		}
	})
}

// FuzzEffectiveFlowLabel checks the flow-label arithmetic shared with the
// kernel (rdma_get_udp_sport): a 20-bit label, the application's label when
// it set one, the symmetric QPN-derived label otherwise, and a UDP source
// port in the RoCEv2 range.
func FuzzEffectiveFlowLabel(f *testing.F) {
	f.Add(uint32(0), uint32(0x1a2b), uint32(0x3c4d))
	f.Add(uint32(0xabcde), uint32(1), uint32(2))
	f.Add(uint32(0xfff00000), uint32(0xffffff), uint32(0xffffff))

	f.Fuzz(func(t *testing.T, label, local, remote uint32) {
		fl := EffectiveFlowLabel(label, local, remote)
		if fl > FlowLabelMask {
			t.Fatalf("EffectiveFlowLabel = %#x, wider than 20 bits", fl)
		}
		if set := label & FlowLabelMask; set != 0 && fl != set {
			t.Fatalf("EffectiveFlowLabel = %#x, want the application's %#x", fl, set)
		}
		if CalcFlowLabel(local, remote) != CalcFlowLabel(remote, local) {
			t.Fatalf("CalcFlowLabel(%#x, %#x) is not symmetric", local, remote)
		}
		if port := UDPSourcePort(fl); port < udpEncapPortMin {
			t.Fatalf("UDPSourcePort(%#x) = %#x, below the RoCEv2 range", fl, port)
		}
	})
}

// BenchmarkDecodeEvent measures the per-event cost of the tracer's ring
// buffer reader.
func BenchmarkDecodeEvent(b *testing.B) {
	raw := rawEvent(Event{
		Kind: KindQPModify, Source: SourceWrite, QPType: QPTypeRC, QPState: QPStateRTR,
		AttrMask: AttrMaskState | AttrMaskAV, FlowLabel: 0xabcde, Comm: "nccl-worker",
	})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeEvent(raw); err != nil {
			b.Fatal(err)
		}
	}
}
