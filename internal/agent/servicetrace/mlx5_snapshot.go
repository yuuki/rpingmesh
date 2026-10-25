package servicetrace

import (
	"encoding/binary"
	"fmt"
)

// decodeMlx5QP reads PRM_QUERY_QP resource dumps, as returned by mlx5's
// fill_res_qp_entry_raw. Framing is resource_dump_*_segment in Linux
// include/linux/mlx5/mlx5_ifc.h; the payload is query_qp_out's fixed prefix.
// Firmware chooses the resource segment ID: use the command echo, never a
// hard-coded firmware ID or a search for a plausible-looking address.
func decodeMlx5QP(raw []byte, qp QPResource) (Connection, error) {
	bad := func(reason string) (Connection, error) {
		return Connection{}, fmt.Errorf("unsupported mlx5 QP dump: %s", reason)
	}
	var resourceType uint16
	var payload []byte
	info, command, terminated := false, false, false
	for len(raw) > 0 {
		if len(raw) < 4 || terminated {
			return bad("truncated or trailing segment")
		}
		n := int(binary.BigEndian.Uint16(raw)) * 4
		kind := binary.BigEndian.Uint16(raw[2:])
		if n < 4 || n > len(raw) {
			return bad("invalid segment length")
		}
		segment := raw[:n]
		switch kind {
		case 0xfffe: // INFO
			if info || command || n != 16 || segment[7] != 0 {
				return bad("unknown info version")
			}
			info = true
		case 0xfffa: // COMMAND
			if !info || command || n != 20 || binary.BigEndian.Uint32(segment[8:]) != qp.LocalQPN || binary.BigEndian.Uint32(segment[12:]) != 0 || binary.BigEndian.Uint16(segment[16:]) != 1 || binary.BigEndian.Uint16(segment[18:]) != 0 {
				return bad("command identity mismatch")
			}
			resourceType = binary.BigEndian.Uint16(segment[4:])
			if resourceType > 0xfeff {
				return bad("invalid resource type")
			}
			command = true
		case 0xfffb: // TERMINATE
			if n != 4 || payload == nil {
				return bad("incomplete dump")
			}
			terminated = true
		default:
			if !command || kind != resourceType || payload != nil || (n != 16+272 && n != 16+464) || binary.BigEndian.Uint32(segment[4:]) != 0 || binary.BigEndian.Uint32(segment[8:]) != qp.LocalQPN || binary.BigEndian.Uint32(segment[12:]) != 0 {
				return bad("unknown or mismatched resource segment")
			}
			payload = segment[16:]
		}
		raw = raw[n:]
	}
	if !terminated || payload == nil || payload[0] != 0 {
		return bad("missing successful query output")
	}
	// query_qp_out.qpc starts at bit 0xc0. These fixed offsets follow
	// qpc/ads in mlx5_ifc.h and the driver's to_rdma_ah_attr conversion.
	// The 464-byte variant appends the 192-byte qp_context_extension; it
	// does not change this prefix.
	qpc := payload[24:256]
	transport, state := qpc[1], qpc[0]>>4
	wantTransport := byte(0xff)
	switch qp.QPType {
	case QPTypeRC:
		wantTransport = 0
	case QPTypeUC:
		wantTransport = 1
	case QPTypeXRCInitiator, QPTypeXRCTarget:
		wantTransport = 3
	}
	remoteQPN := binary.BigEndian.Uint32(qpc[20:]) & 0xffffff
	if qp.Kernel || (qp.QPState != QPStateRTR && qp.QPState != QPStateRTS) || state != qp.QPState || transport != wantTransport || remoteQPN == 0 || (qp.RemoteQPN != 0 && remoteQPN != qp.RemoteQPN) {
		return bad("QP state, transport or remote QPN mismatch")
	}
	path := qpc[24:68]
	labelAndClass := binary.BigEndian.Uint32(path[12:])
	c := Connection{
		Dev: qp.Dev, LocalQPN: qp.LocalQPN, RemoteQPN: remoteQPN, QPType: qp.QPType,
		PID: qp.OwnerTGID, FromSnapshot: true,
		FlowLabel: labelAndClass & FlowLabelMask, TrafficClass: uint8(labelAndClass >> 20),
		SGIDIndex: path[9], HopLimit: path[11], SL: path[36] & 0xf, Port: path[37],
	}
	copy(c.RemoteGID[:], path[16:32])
	if c.RemoteGID == ([16]byte{}) || c.Port == 0 || uint32(c.Port) != qp.Port {
		return bad("missing or mismatched address vector")
	}
	// Also reject IB/RoCEv1 paths and driver-specific UDP port overrides:
	// the normal prober must reproduce this RoCEv2 source port exactly.
	if binary.BigEndian.Uint16(path[34:]) != UDPSourcePort(c.EffectiveFlowLabel()) {
		return bad("RoCEv2 source port cannot be reproduced")
	}
	return c, nil
}
