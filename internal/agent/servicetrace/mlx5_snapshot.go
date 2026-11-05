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
	payload, err := mlx5QueryQPOutput(raw, qp.LocalQPN)
	if err != nil {
		return Connection{}, err
	}
	// query_qp_out.qpc starts at bit 0xc0. These fixed offsets follow
	// qpc/ads in mlx5_ifc.h and the driver's to_rdma_ah_attr conversion.
	// The 464-byte variant appends the 192-byte qp_context_extension; it
	// does not change this prefix.
	qpc := payload[24:256]
	transport, state := qpc[1], qpc[0]>>4
	remoteQPN := binary.BigEndian.Uint32(qpc[20:]) & 0xffffff
	if !mlx5ContextMatches(qp, state, transport, remoteQPN) {
		return Connection{}, mlx5DumpError("QP state, transport or remote QPN mismatch")
	}
	path := qpc[24:68]
	c := mlx5Connection(qp, remoteQPN, path)
	if c.RemoteGID == ([16]byte{}) || c.Port == 0 || uint32(c.Port) != qp.Port {
		return Connection{}, mlx5DumpError("missing or mismatched address vector")
	}
	// Also reject IB/RoCEv1 paths and driver-specific UDP port overrides:
	// the normal prober must reproduce this RoCEv2 source port exactly.
	if binary.BigEndian.Uint16(path[34:]) != UDPSourcePort(c.EffectiveFlowLabel()) {
		return Connection{}, mlx5DumpError("RoCEv2 source port cannot be reproduced")
	}
	return c, nil
}

func mlx5DumpError(reason string) error {
	return fmt.Errorf("unsupported mlx5 QP dump: %s", reason)
}

// Segment types of resource_dump_segment_header; any other type is the
// resource segment, whose type the COMMAND segment echoes.
const (
	mlx5SegmentInfo      = 0xfffe
	mlx5SegmentCommand   = 0xfffa
	mlx5SegmentTerminate = 0xfffb
)

// mlx5Dump accepts the segments of one PRM_QUERY_QP dump, in their only
// valid order: INFO, COMMAND, the resource segment and TERMINATE.
type mlx5Dump struct {
	qpn                       uint32
	info, command, terminated bool
	resourceType              uint16
	payload                   []byte
}

// mlx5QueryQPOutput returns the query_qp_out payload of a complete dump of
// QP qpn that firmware answered successfully.
func mlx5QueryQPOutput(raw []byte, qpn uint32) ([]byte, error) {
	d := mlx5Dump{qpn: qpn}
	for len(raw) > 0 {
		if len(raw) < 4 || d.terminated {
			return nil, mlx5DumpError("truncated or trailing segment")
		}
		n := int(binary.BigEndian.Uint16(raw)) * 4
		if n < 4 || n > len(raw) {
			return nil, mlx5DumpError("invalid segment length")
		}
		if err := d.add(binary.BigEndian.Uint16(raw[2:]), raw[:n]); err != nil {
			return nil, err
		}
		raw = raw[n:]
	}
	if !d.terminated || d.payload == nil || d.payload[0] != 0 {
		return nil, mlx5DumpError("missing successful query output")
	}
	return d.payload, nil
}

func (d *mlx5Dump) add(kind uint16, segment []byte) error {
	switch kind {
	case mlx5SegmentInfo:
		return d.addInfo(segment)
	case mlx5SegmentCommand:
		return d.addCommand(segment)
	case mlx5SegmentTerminate:
		return d.addTerminate(segment)
	default:
		return d.addResource(kind, segment)
	}
}

func (d *mlx5Dump) addInfo(segment []byte) error {
	if d.info || d.command || len(segment) != 16 || segment[7] != 0 {
		return mlx5DumpError("unknown info version")
	}
	d.info = true
	return nil
}

func (d *mlx5Dump) addCommand(segment []byte) error {
	if !d.info || d.command || !mlx5CommandEchoes(segment, d.qpn) {
		return mlx5DumpError("command identity mismatch")
	}
	d.resourceType = binary.BigEndian.Uint16(segment[4:])
	if d.resourceType > 0xfeff {
		return mlx5DumpError("invalid resource type")
	}
	d.command = true
	return nil
}

func (d *mlx5Dump) addTerminate(segment []byte) error {
	if len(segment) != 4 || d.payload == nil {
		return mlx5DumpError("incomplete dump")
	}
	d.terminated = true
	return nil
}

func (d *mlx5Dump) addResource(kind uint16, segment []byte) error {
	if !d.command || kind != d.resourceType || d.payload != nil || !mlx5ResourceDescribes(segment, d.qpn) {
		return mlx5DumpError("unknown or mismatched resource segment")
	}
	d.payload = segment[16:]
	return nil
}

// mlx5CommandEchoes reports whether a COMMAND segment echoes a query of one
// object: index1 is qpn, index2 and num_of_obj2 are zero, num_of_obj1 is 1.
func mlx5CommandEchoes(segment []byte, qpn uint32) bool {
	return len(segment) == 20 && binary.BigEndian.Uint32(segment[8:]) == qpn && binary.BigEndian.Uint32(segment[12:]) == 0 &&
		binary.BigEndian.Uint16(segment[16:]) == 1 && binary.BigEndian.Uint16(segment[18:]) == 0
}

// mlx5ResourceDescribes reports whether a resource segment holds one
// query_qp_out of qpn, with or without the qp_context_extension.
func mlx5ResourceDescribes(segment []byte, qpn uint32) bool {
	n := len(segment)
	return (n == 16+272 || n == 16+464) && binary.BigEndian.Uint32(segment[4:]) == 0 &&
		binary.BigEndian.Uint32(segment[8:]) == qpn && binary.BigEndian.Uint32(segment[12:]) == 0
}

// mlx5ContextMatches reports whether a QP context still describes qp: a
// user QP in RTR or RTS, in the same state, with its type's transport and
// a remote QPN that the inventory, when it knows one, agrees with.
func mlx5ContextMatches(qp QPResource, state, transport byte, remoteQPN uint32) bool {
	if qp.Kernel || (qp.QPState != QPStateRTR && qp.QPState != QPStateRTS) {
		return false
	}
	return state == qp.QPState && transport == mlx5Transport(qp.QPType) && remoteQPN != 0 &&
		(qp.RemoteQPN == 0 || remoteQPN == qp.RemoteQPN)
}

// mlx5Transport is the MLX5_QP_ST_* value of a connected QP type. Other
// types get 0xff, which no MLX5_QP_ST_* value uses.
func mlx5Transport(qpType uint32) byte {
	switch qpType {
	case QPTypeRC:
		return 0
	case QPTypeUC:
		return 1
	case QPTypeXRCInitiator, QPTypeXRCTarget:
		return 3
	}
	return 0xff
}

// mlx5Connection builds qp's connection from the primary address path
// (ads) of its QP context.
func mlx5Connection(qp QPResource, remoteQPN uint32, path []byte) Connection {
	labelAndClass := binary.BigEndian.Uint32(path[12:])
	c := Connection{
		Dev: qp.Dev, LocalQPN: qp.LocalQPN, RemoteQPN: remoteQPN, QPType: qp.QPType,
		PID: qp.OwnerTGID, FromSnapshot: true,
		FlowLabel: labelAndClass & FlowLabelMask, TrafficClass: uint8(labelAndClass >> 20),
		SGIDIndex: path[9], HopLimit: path[11], SL: path[36] & 0xf, Port: path[37],
	}
	copy(c.RemoteGID[:], path[16:32])
	return c
}
