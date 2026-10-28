package servicetrace

import (
	"encoding/binary"
	"fmt"
)

// mlx5DCAddress is the address vector of one submitted DC work request.
// AVUDPSourcePort is a candidate for the wire port, not proof of it: a provider
// adapter must rule out stream and QP-level overrides before using this value.
// In particular, FlowLabel == 0 must NOT use the connected-QP QPN calculation.
type mlx5DCAddress struct {
	LocalQPN        uint32
	StreamChannel   uint16
	StreamChannels  uint16
	RemoteDCT       uint32
	RemoteGID       [16]byte
	RemoteMAC       [6]byte
	AVUDPSourcePort uint16
	FlowLabel       uint32
	SGIDIndex       uint8
	TrafficClass    uint8
	SL              uint8
	HopLimit        uint8
}

// decodeMLX5DCAddress reads only the 16-byte control + 48-byte extended AV.
// Layout: rdma-core fdd5dbfb71a1f5c80b90f4e1d6340ce21338bf6c,
// providers/mlx5/mlx5dv.h (mlx5_wqe_ctrl_seg and mlx5_wqe_av).
//
// The caller must independently establish that the QP is a non-stream DCI,
// uses RoCEv2, and has no UDP-port override. UD WQEs share this layout; decoding
// cannot establish transport or successful submission. A capture must copy
// this prefix before a ring slot is reused and associate it with a confirmed
// submission. Access keys and payload bytes are never returned or retained.
func decodeMLX5DCAddress(prefix []byte, expectedQPN uint32) (mlx5DCAddress, error) {
	return decodeMLX5DCStreamAddress(prefix, expectedQPN, 0)
}

// decodeMLX5DCStreamAddress accepts streams only with an adapter-validated
// creation-time channel count. Zero preserves the non-stream decoder contract.
// Stream identity is retained separately; the AV port is never a wire-port claim.
func decodeMLX5DCStreamAddress(prefix []byte, expectedQPN uint32, channels uint32) (mlx5DCAddress, error) {
	var a mlx5DCAddress
	if len(prefix) < 64 {
		return a, fmt.Errorf("mlx5 DC WQE prefix: need 64 bytes, got %d", len(prefix))
	}
	be := binary.BigEndian
	ctrl := be.Uint32(prefix[0:4])
	qpnDS := be.Uint32(prefix[4:8])
	if expectedQPN == 0 || expectedQPN > 0xffffff || qpnDS>>8 != expectedQPN {
		return a, fmt.Errorf("mlx5 DC WQE QPN does not match DCI")
	}
	channel := be.Uint16(prefix[9:11])
	if channels != 0 && (channels < 2 || channels > 128 || channels&(channels-1) != 0) {
		return a, fmt.Errorf("invalid DCI stream channel count")
	}
	if (channels == 0 && channel != 0) || (channels != 0 && uint32(channel) >= channels) {
		return a, fmt.Errorf("mlx5 DC WQE stream is unsupported")
	}
	minDS := uint32(4)
	modifier := uint32(0)
	atomic := false
	switch byte(ctrl) {
	case 0x0a, 0x0b: // SEND, SEND_IMM
	case 0x08, 0x09, 0x10: // RDMA_WRITE, RDMA_WRITE_IMM, RDMA_READ
		minDS = 5 // remote address segment follows the AV
	case 0x11, 0x12: // ATOMIC_CS, ATOMIC_FA (64-bit)
		minDS, atomic = 7, true
	case 0x14, 0x15: // MASKED_CS, MASKED_FA (32/64-bit)
		modifier = ctrl >> 24
		if modifier != 8 && modifier != 9 {
			return a, fmt.Errorf("unsupported mlx5 DC atomic size modifier")
		}
		minDS, atomic = 7, true
		if byte(ctrl) == 0x14 && modifier == 9 {
			minDS = 8
		}
	default:
		return a, fmt.Errorf("mlx5 DC WQE opcode %#x is unsupported", byte(ctrl))
	}
	if ctrl>>24 != modifier || qpnDS&0xc0 != 0 || qpnDS&0x3f < minDS || (atomic && qpnDS&0x3f != minDS) {
		return a, fmt.Errorf("mlx5 DC WQE segment count is invalid")
	}
	dct := be.Uint32(prefix[24:28])
	if dct&0xff000000 != 0x80000000 || dct&0xffffff == 0 {
		return a, fmt.Errorf("mlx5 DC WQE needs an extended AV and nonzero DCT")
	}
	grh := be.Uint32(prefix[44:48])
	// Bits 31:28 are reserved for RoCE. Bit 30 is the IB GRH flag;
	// unlike InfiniBand, RoCE providers leave it clear even for a global AV.
	if grh&0xf0000000 != 0 || prefix[29] != 0 {
		return a, fmt.Errorf("mlx5 DC WQE has unsupported address-vector flags")
	}
	port := be.Uint16(prefix[30:32])
	if port < udpEncapPortMin {
		return a, fmt.Errorf("mlx5 DC WQE has no valid RoCEv2 AV UDP source port")
	}
	copy(a.RemoteGID[:], prefix[48:64])
	if a.RemoteGID == [16]byte{} {
		return mlx5DCAddress{}, fmt.Errorf("mlx5 DC WQE has no remote GID")
	}
	a.LocalQPN = expectedQPN
	a.StreamChannel, a.StreamChannels = channel, uint16(channels)
	a.RemoteDCT = dct & 0xffffff
	copy(a.RemoteMAC[:], prefix[36:42])
	a.AVUDPSourcePort = port
	a.FlowLabel = grh & FlowLabelMask
	a.SGIDIndex = uint8(grh >> 20)
	a.TrafficClass = prefix[42]
	a.HopLimit = prefix[43]
	a.SL = (prefix[28] >> 1) & 7 // Ethernet SL encoding, not IB's low nibble
	return a, nil
}
