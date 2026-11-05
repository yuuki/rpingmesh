package servicetrace

import (
	"encoding/binary"
	"slices"
	"testing"
)

// These synthetic fixtures follow Linux mlx5_ifc.h's PRM query_qp_out,
// qpc and ads layouts. They are not captures from a physical NIC.
func mlx5QPFixture(qp QPResource, flowLabel uint32) []byte {
	payload := make([]byte, 272) // query_qp_out: qpc at byte 24, size 232
	qpc := payload[24:256]
	qpc[0] = qp.QPState << 4
	qpc[1] = 0 // MLX5_QP_ST_RC
	binary.BigEndian.PutUint32(qpc[20:], qp.RemoteQPN)
	path := qpc[24:68]
	path[9], path[11] = 3, 64
	binary.BigEndian.PutUint32(path[12:], 0xa5<<20|flowLabel)
	path[26], path[27], path[31] = 0xff, 0xff, 7
	binary.BigEndian.PutUint16(path[34:], UDPSourcePort(EffectiveFlowLabel(flowLabel, qp.LocalQPN, qp.RemoteQPN)))
	path[36], path[37] = 5, byte(qp.Port)
	segment := func(kind uint16, data []byte) []byte {
		out := make([]byte, 4+len(data))
		binary.BigEndian.PutUint16(out, uint16(len(out)/4))
		binary.BigEndian.PutUint16(out[2:], kind)
		copy(out[4:], data)
		return out
	}
	info := segment(0xfffe, make([]byte, 12))
	command := make([]byte, 16)
	binary.BigEndian.PutUint16(command, 0x1234) // firmware-selected PRM_QUERY_QP ID
	binary.BigEndian.PutUint32(command[4:], qp.LocalQPN)
	binary.BigEndian.PutUint16(command[12:], 1)
	resource := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint32(resource[4:], qp.LocalQPN)
	copy(resource[12:], payload)
	return nlJoin(info, segment(0xfffa, command), segment(0x1234, resource), segment(0xfffb, nil))
}

func TestDecodeMlx5QP(t *testing.T) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42, OwnerTGID: 42}
	for _, label := range []uint32{0, 0xabcde} {
		c, err := decodeMlx5QP(mlx5QPFixture(qp, label), qp)
		if err != nil {
			t.Fatal(err)
		}
		if !c.FromSnapshot || c.Context != 0 || c.Handle != 0 || c.LocalQPN != qp.LocalQPN || c.RemoteQPN != qp.RemoteQPN || c.RemoteGID[15] != 7 || c.FlowLabel != label || c.SGIDIndex != 3 || c.Port != 1 || c.TrafficClass != 0xa5 || c.SL != 5 || c.HopLimit != 64 || c.PID != 42 || c.CgroupID != 0 {
			t.Fatalf("recovered connection = %+v", c)
		}
	}
}

func TestDecodeMlx5QPRejectsUnknownOrInconsistentData(t *testing.T) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42, OwnerTGID: 42}
	for name, change := range map[string]func([]byte) []byte{
		"truncated":           func(b []byte) []byte { return b[:len(b)-1] },
		"zero_segment_length": func(b []byte) []byte { b[0], b[1] = 0, 0; return b },
		"wrong_command_qpn":   func(b []byte) []byte { b[27]++; return b },
		"wrong_resource_qpn":  func(b []byte) []byte { b[47]++; return b },
		"aggregate":           func(b []byte) []byte { b[43] = 1; return b },
		"error_segment":       func(b []byte) []byte { b[2], b[3] = 0xff, 0xfc; return b },
		"wrong_state":         func(b []byte) []byte { b[76] = 0x20; return b },
		"wrong_transport":     func(b []byte) []byte { b[77] = 2; return b },
		"wrong_remote_qpn":    func(b []byte) []byte { b[99]++; return b },
		"missing_gid":         func(b []byte) []byte { clear(b[116:132]); return b },
		"wrong_udp_sport":     func(b []byte) []byte { b[135]++; return b },
		"missing_termination": func(b []byte) []byte { return b[:len(b)-4] },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeMlx5QP(change(mlx5QPFixture(qp, 1)), qp); err == nil {
				t.Fatal("accepted invalid recovery data")
			}
		})
	}
}

func TestDecodeMlx5QPContextExtension(t *testing.T) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42, OwnerTGID: 42}
	raw := mlx5QPFixture(qp, 1)
	extended := append([]byte(nil), raw[:len(raw)-4]...)
	extended = append(extended, make([]byte, 192)...)
	extended = append(extended, raw[len(raw)-4:]...)
	binary.BigEndian.PutUint16(extended[36:], uint16((16+464)/4))
	if _, err := decodeMlx5QP(extended, qp); err != nil {
		t.Fatal(err)
	}
}

func TestMlx5DCDoesNotBecomeConnectedFlow(t *testing.T) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200,
		QPType: QPTypeDriver, QPState: QPStateRTS, Port: 1}
	for _, transport := range []byte{5, 6} { // MLX5_QP_ST_DCI, MLX5_QP_ST_DCT
		raw := mlx5QPFixture(qp, 1)
		raw[77] = transport
		if _, err := decodeMlx5QP(raw, qp); err == nil {
			t.Fatal("DC QP context was incorrectly treated as a per-send flow")
		}
	}
}

// mlx5Segments splits mlx5QPFixture's dump into its INFO, COMMAND, resource
// and TERMINATE segments, so cases can reorder or repeat them.
func mlx5Segments(raw []byte) (info, command, resource, terminate []byte) {
	return raw[0:16], raw[16:36], raw[36:324], raw[324:]
}

func TestDecodeMlx5QPCharacterization(t *testing.T) {
	base := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 41, OwnerTGID: 42}
	reason := func(r string) string { return "unsupported mlx5 QP dump: " + r }
	const (
		framing  = "truncated or trailing segment"
		length   = "invalid segment length"
		info     = "unknown info version"
		command  = "command identity mismatch"
		resType  = "invalid resource type"
		early    = "incomplete dump"
		resource = "unknown or mismatched resource segment"
		output   = "missing successful query output"
		identity = "QP state, transport or remote QPN mismatch"
		address  = "missing or mismatched address vector"
		sport    = "RoCEv2 source port cannot be reproduced"
	)
	put16 := func(b []byte, off int, v uint16) []byte { binary.BigEndian.PutUint16(b[off:], v); return b }
	set := func(off int, v byte) func([]byte) []byte { return func(b []byte) []byte { b[off] = v; return b } }
	inc := func(off int) func([]byte) []byte { return func(b []byte) []byte { b[off]++; return b } }
	segment := func(kind uint16, body []byte) []byte {
		return put16(put16(append(make([]byte, 4), body...), 0, uint16((4+len(body))/4)), 2, kind)
	}
	for _, tt := range []struct {
		name   string
		qp     func(*QPResource)
		label  uint32
		mutate func([]byte) []byte
		err    string
		want   func(*Connection)
	}{
		{name: "fixture", label: 1},
		{name: "derived flow label", label: 0, want: func(c *Connection) { c.FlowLabel = 0 }},
		{name: "rtr", qp: func(q *QPResource) { q.QPState = QPStateRTR }, label: 1},
		{name: "uc", qp: func(q *QPResource) { q.QPType = QPTypeUC }, label: 1, mutate: set(77, 1)},
		{name: "xrc initiator", qp: func(q *QPResource) { q.QPType = QPTypeXRCInitiator }, label: 1, mutate: set(77, 3)},
		{name: "xrc target", qp: func(q *QPResource) { q.QPType = QPTypeXRCTarget }, label: 1, mutate: set(77, 3)},
		{name: "unlisted type matches no transport but 0xff", qp: func(q *QPResource) { q.QPType = QPTypeUD }, label: 1, mutate: set(77, 0xff)},
		{name: "unlisted type", qp: func(q *QPResource) { q.QPType = QPTypeUD }, label: 1, err: identity},
		{name: "uc with rc transport", qp: func(q *QPResource) { q.QPType = QPTypeUC }, label: 1, err: identity},
		{name: "xrc with uc transport", qp: func(q *QPResource) { q.QPType = QPTypeXRCTarget }, label: 1, mutate: set(77, 1), err: identity},
		{name: "kernel", qp: func(q *QPResource) { q.Kernel = true }, label: 1, err: identity},
		{name: "init state", qp: func(q *QPResource) { q.QPState = QPStateInit }, label: 1, err: identity},
		{name: "state differs", label: 1, mutate: set(76, QPStateRTR<<4), err: identity},
		{name: "state low nibble ignored", label: 1, mutate: set(76, QPStateRTS<<4|0xf)},
		{name: "remote qpn differs", label: 1, mutate: inc(99), err: identity},
		{name: "remote qpn zero", qp: func(q *QPResource) { q.RemoteQPN = 0 }, label: 1,
			mutate: func(b []byte) []byte { clear(b[97:100]); return b }, err: identity},
		{name: "remote qpn learned", qp: func(q *QPResource) { q.RemoteQPN = 0 }, label: 1,
			mutate: func(b []byte) []byte { return put16(b, 98, 0x300) }, want: func(c *Connection) { c.RemoteQPN = 0x300 }},
		{name: "remote qpn top byte ignored", label: 1, mutate: set(96, 0xab)},
		{name: "fields", qp: func(q *QPResource) { q.Port = 2 }, label: 0xabcde,
			mutate: func(b []byte) []byte {
				b[112] |= 0xf0      // flow label/class word bits 28-31
				b[109] = 9          // source GID index
				b[111] = 17         // hop limit
				b[136] = 0xf5       // SL in the low nibble
				for i := range 16 { // remote GID
					b[116+i] = byte(0x10 + i)
				}
				return b
			},
			want: func(c *Connection) {
				c.FlowLabel, c.SGIDIndex, c.HopLimit, c.SL = 0xabcde, 9, 17, 5
				for i := range 16 {
					c.RemoteGID[i] = byte(0x10 + i)
				}
			}},
		{name: "missing gid", label: 1, mutate: func(b []byte) []byte { clear(b[116:132]); return b }, err: address},
		{name: "address port zero", label: 1, mutate: set(137, 0), err: address},
		{name: "address port differs", label: 1, mutate: set(137, 2), err: address},
		{name: "qp port zero", qp: func(q *QPResource) { q.Port = 0 }, label: 1, err: address},
		{name: "udp source port", label: 1, mutate: inc(135), err: sport},
		{name: "derived udp source port", label: 0, mutate: inc(134), err: sport},

		{name: "empty", label: 1, mutate: func([]byte) []byte { return nil }, err: output},
		{name: "short tail", label: 1, mutate: func(b []byte) []byte { return b[:len(b)-1] }, err: framing},
		{name: "trailing segment", label: 1, mutate: func(b []byte) []byte { return append(b, segment(0xfffb, nil)...) }, err: framing},
		{name: "trailing bytes", label: 1, mutate: func(b []byte) []byte { return append(b, 0, 0) }, err: framing},
		{name: "zero length", label: 1, mutate: func(b []byte) []byte { return put16(b, 0, 0) }, err: length},
		{name: "length past end", label: 1, mutate: func(b []byte) []byte { return put16(b, 324, 2) }, err: length},
		{name: "info version", label: 1, mutate: set(7, 1), err: info},
		{name: "info length", label: 1, mutate: func(b []byte) []byte { return put16(b, 0, 3) }, err: info},
		{name: "info twice", label: 1, mutate: func(b []byte) []byte { i, c, r, x := mlx5Segments(b); return nlJoin(i, i, c, r, x) }, err: info},
		{name: "info after command", label: 1, mutate: func(b []byte) []byte { i, c, r, x := mlx5Segments(b); return nlJoin(i, c, i, r, x) }, err: info},
		{name: "command without info", label: 1, mutate: func(b []byte) []byte { _, c, r, x := mlx5Segments(b); return nlJoin(c, r, x) }, err: command},
		{name: "command twice", label: 1, mutate: func(b []byte) []byte { i, c, r, x := mlx5Segments(b); return nlJoin(i, c, c, r, x) }, err: command},
		{name: "command length", label: 1, mutate: func(b []byte) []byte {
			i, c, r, x := mlx5Segments(b)
			return nlJoin(i, put16(append(slices.Clone(c), 0, 0, 0, 0), 0, 6), r, x)
		}, err: command},
		{name: "command qpn", label: 1, mutate: inc(27), err: command},
		{name: "command reserved", label: 1, mutate: set(31, 1), err: command},
		{name: "command object count", label: 1, mutate: set(33, 2), err: command},
		{name: "command trailing field", label: 1, mutate: set(35, 1), err: command},
		{name: "command unchecked field", label: 1, mutate: set(23, 0xff)},
		{name: "resource type reserved", label: 1, mutate: func(b []byte) []byte { return put16(put16(b, 20, 0xff00), 38, 0xff00) }, err: resType},
		{name: "resource type maximum", label: 1, mutate: func(b []byte) []byte { return put16(put16(b, 20, 0xfeff), 38, 0xfeff) }},
		{name: "terminate length", label: 1, mutate: func(b []byte) []byte { return put16(append(b, 0, 0, 0, 0), 324, 2) }, err: early},
		{name: "terminate before resource", label: 1, mutate: func(b []byte) []byte { i, c, _, x := mlx5Segments(b); return nlJoin(i, c, x) }, err: early},
		{name: "resource before command", label: 1, mutate: func(b []byte) []byte { i, c, r, x := mlx5Segments(b); return nlJoin(i, r, c, x) }, err: resource},
		{name: "resource type zero", label: 1, mutate: func(b []byte) []byte { return put16(put16(b, 20, 0), 38, 0) }},
		{name: "resource type zero before command", label: 1, mutate: func(b []byte) []byte {
			i, c, r, x := mlx5Segments(put16(put16(b, 20, 0), 38, 0))
			return nlJoin(i, r, c, x)
		}, err: resource},
		{name: "resource kind", label: 1, mutate: inc(39), err: resource},
		{name: "resource twice", label: 1, mutate: func(b []byte) []byte { i, c, r, x := mlx5Segments(b); return nlJoin(i, c, r, r, x) }, err: resource},
		{name: "resource length", label: 1, mutate: func(b []byte) []byte {
			i, c, r, x := mlx5Segments(b)
			return nlJoin(i, c, put16(append(slices.Clone(r), 0, 0, 0, 0), 0, 73), x)
		}, err: resource},
		{name: "resource aggregate", label: 1, mutate: set(43, 1), err: resource},
		{name: "resource qpn", label: 1, mutate: inc(47), err: resource},
		{name: "resource reserved", label: 1, mutate: set(51, 1), err: resource},
		{name: "error segment", label: 1, mutate: func(b []byte) []byte { return put16(b, 38, 0xfffc) }, err: resource},
		{name: "missing termination", label: 1, mutate: func(b []byte) []byte { return b[:324] }, err: output},
		{name: "failed status", label: 1, mutate: set(52, 1), err: output},
		{name: "context extension", label: 1, mutate: func(b []byte) []byte {
			i, c, r, x := mlx5Segments(b)
			return nlJoin(i, c, put16(append(slices.Clone(r), make([]byte, 192)...), 0, (16+464)/4), x)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			qp := base
			if tt.qp != nil {
				tt.qp(&qp)
			}
			fixtureQP := qp
			if fixtureQP.RemoteQPN == 0 {
				fixtureQP.RemoteQPN = 0x200
			}
			raw := mlx5QPFixture(fixtureQP, tt.label)
			if tt.mutate != nil {
				raw = tt.mutate(raw)
			}
			got, err := decodeMlx5QP(raw, qp)
			if tt.err != "" {
				if err == nil || err.Error() != reason(tt.err) || got != (Connection{}) {
					t.Fatalf("decode = %+v, %v; want %q", got, err, reason(tt.err))
				}
				return
			}
			want := mlx5FixtureConnection(fixtureQP, tt.label)
			if tt.want != nil {
				tt.want(&want)
			}
			if err != nil || got != want {
				t.Fatalf("decode = %+v, %v\nwant %+v", got, err, want)
			}
		})
	}
}
