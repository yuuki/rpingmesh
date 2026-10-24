package servicetrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Kind classifies a traced uverbs command. The values match the EV_*
// constants of bpf/uverbs_trace.bpf.c.
type Kind uint32

const (
	// KindQPCreate reports a new QP: its handle, number and type.
	KindQPCreate Kind = 1
	// KindQPModify reports a QP state transition with its address vector.
	KindQPModify Kind = 2
	// KindQPDestroy reports an explicit QP destroy.
	KindQPDestroy Kind = 3
	// KindContextClose reports the release of a uverbs context: every QP of
	// the context is gone, whether or not it was destroyed explicitly.
	KindContextClose Kind = 4
)

// String returns the metric label of the kind.
func (k Kind) String() string {
	switch k {
	case KindQPCreate:
		return "create"
	case KindQPModify:
		return "modify"
	case KindQPDestroy:
		return "destroy"
	case KindContextClose:
		return "context_close"
	}
	return fmt.Sprintf("kind(%d)", uint32(k))
}

// Source reports how the command reached the kernel (the SRC_* constants of
// the BPF program). It is diagnostic only.
type Source uint32

const (
	SourceWrite       Source = 1 // write(2) on the uverbs fd
	SourceIoctlWrite  Source = 2 // the ioctl INVOKE_WRITE method carrying a write command
	SourceIoctlNative Source = 3 // an ioctl-native method
)

// QP types, enum ib_uverbs_qp_type.
const (
	QPTypeRC           uint32 = 2
	QPTypeUC           uint32 = 3
	QPTypeUD           uint32 = 4
	QPTypeRawPacket    uint32 = 8
	QPTypeXRCInitiator uint32 = 9
	QPTypeXRCTarget    uint32 = 10
	QPTypeDriver       uint32 = 0xFF
)

// QP states, enum ib_qp_state.
const (
	QPStateReset uint8 = 0
	QPStateInit  uint8 = 1
	QPStateRTR   uint8 = 2
	QPStateRTS   uint8 = 3
	QPStateErr   uint8 = 6
)

// Bits of enum ib_qp_attr_mask the tracer interprets.
const (
	AttrMaskState   uint32 = 1 << 0
	AttrMaskAV      uint32 = 1 << 7
	AttrMaskDestQPN uint32 = 1 << 20
)

// Event is one decoded tracer event. Which fields are meaningful depends on
// Kind: a create carries QPHandle, QPNum and QPType; a modify carries
// QPHandle, AttrMask, QPState and the address vector (DGID, DestQPNum,
// FlowLabel, SGIDIndex, PortNum, ...); a destroy carries QPHandle; a context
// close carries only the identity fields.
type Event struct {
	// TimestampNS is CLOCK_MONOTONIC at the time the kernel completed the
	// command.
	TimestampNS uint64
	// Context identifies the uverbs context (one ibv_open_device) the
	// command belongs to. QP handles are unique only within a context.
	Context uint64
	// CgroupID, PID, TID and Comm identify the calling process.
	CgroupID uint64
	PID      uint32
	TID      uint32
	Comm     string
	Kind     Kind
	Source   Source
	// Dev is the device number (dev_t) of the uverbs node the context was
	// opened on; UverbsDevices maps it to the RDMA device name.
	Dev      uint32
	QPHandle uint32
	// QPNum and QPType are set by create events.
	QPNum  uint32
	QPType uint32
	// AttrMask, QPState and the address vector are set by modify events.
	AttrMask     uint32
	QPState      uint8
	DGID         [16]byte
	DestQPNum    uint32
	FlowLabel    uint32
	SGIDIndex    uint8
	PortNum      uint8
	HopLimit     uint8
	TrafficClass uint8
	SL           uint8
	IsGlobal     uint8
	DestPortNum  uint8
}

// eventSize is sizeof(struct qp_event) in the BPF program.
const eventSize = 112

// DecodeEvent decodes the wire form of struct qp_event. The agent runs on
// little-endian hosts only (the BPF objects are built for bpfel).
func DecodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("event too short: %d bytes, want %d", len(raw), eventSize)
	}
	le := binary.LittleEndian
	ev := Event{
		TimestampNS:  le.Uint64(raw[0:]),
		Context:      le.Uint64(raw[8:]),
		CgroupID:     le.Uint64(raw[16:]),
		PID:          le.Uint32(raw[24:]),
		TID:          le.Uint32(raw[28:]),
		Kind:         Kind(le.Uint32(raw[32:])),
		Source:       Source(le.Uint32(raw[36:])),
		Dev:          le.Uint32(raw[40:]),
		QPHandle:     le.Uint32(raw[44:]),
		QPNum:        le.Uint32(raw[48:]),
		QPType:       le.Uint32(raw[52:]),
		AttrMask:     le.Uint32(raw[56:]),
		DestQPNum:    le.Uint32(raw[60:]),
		FlowLabel:    le.Uint32(raw[64:]),
		QPState:      raw[88],
		SGIDIndex:    raw[89],
		PortNum:      raw[90],
		HopLimit:     raw[91],
		TrafficClass: raw[92],
		SL:           raw[93],
		IsGlobal:     raw[94],
		DestPortNum:  raw[95],
	}
	copy(ev.DGID[:], raw[72:88])
	comm := raw[96:112]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	ev.Comm = string(comm)
	return ev, nil
}

// IsConnect reports whether ev is the transition of a QP to Ready-To-Receive
// with an address vector: the point at which a connected QP (RC, UC, XRC)
// is bound to its remote and the service flow's 5-tuple becomes known.
func (ev Event) IsConnect() bool {
	return ev.Kind == KindQPModify &&
		ev.AttrMask&AttrMaskState != 0 && ev.QPState == QPStateRTR &&
		ev.AttrMask&AttrMaskAV != 0
}

// IsReset reports whether ev moves a QP back to the Reset state, which drops
// its connection without destroying the QP (some applications recycle QPs).
func (ev Event) IsReset() bool {
	return ev.Kind == KindQPModify &&
		ev.AttrMask&AttrMaskState != 0 && ev.QPState == QPStateReset
}

// IsConnectedType reports whether a QP type binds to a single remote at RTR,
// so that its modify events describe a service flow. UD QPs (including the
// agent's own probing queues), raw packet QPs and driver-specific transports
// (such as DC) do not.
func IsConnectedType(qpType uint32) bool {
	switch qpType {
	case QPTypeRC, QPTypeUC, QPTypeXRCInitiator, QPTypeXRCTarget:
		return true
	}
	return false
}
