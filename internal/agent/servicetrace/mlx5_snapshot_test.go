package servicetrace

import (
	"encoding/binary"
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
