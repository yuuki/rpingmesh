package servicetrace

import (
	"encoding/binary"
	"testing"
)

// rawEvent builds the wire form of struct qp_event from an Event, the
// inverse of DecodeEvent, so tests can exercise the decoder's offsets.
func rawEvent(ev Event) []byte {
	raw := make([]byte, eventSize)
	le := binary.LittleEndian
	le.PutUint64(raw[0:], ev.TimestampNS)
	le.PutUint64(raw[8:], ev.Context)
	le.PutUint64(raw[16:], ev.CgroupID)
	le.PutUint32(raw[24:], ev.PID)
	le.PutUint32(raw[28:], ev.TID)
	le.PutUint32(raw[32:], uint32(ev.Kind))
	le.PutUint32(raw[36:], uint32(ev.Source))
	le.PutUint32(raw[40:], ev.Dev)
	le.PutUint32(raw[44:], ev.QPHandle)
	le.PutUint32(raw[48:], ev.QPNum)
	le.PutUint32(raw[52:], ev.QPType)
	le.PutUint32(raw[56:], ev.AttrMask)
	le.PutUint32(raw[60:], ev.DestQPNum)
	le.PutUint32(raw[64:], ev.FlowLabel)
	copy(raw[72:88], ev.DGID[:])
	raw[88] = ev.QPState
	raw[89] = ev.SGIDIndex
	raw[90] = ev.PortNum
	raw[91] = ev.HopLimit
	raw[92] = ev.TrafficClass
	raw[93] = ev.SL
	raw[94] = ev.IsGlobal
	raw[95] = ev.DestPortNum
	copy(raw[96:112], ev.Comm)
	return raw
}

func TestDecodeEventRoundTrip(t *testing.T) {
	want := Event{
		TimestampNS:  0x0102030405060708,
		Context:      0xffff9a1b2c3d4e50,
		CgroupID:     4242,
		PID:          1234,
		TID:          1235,
		Kind:         KindQPModify,
		Source:       SourceIoctlWrite,
		Dev:          MakeDev(231, 192),
		QPHandle:     7,
		QPNum:        0x1a2b,
		QPType:       QPTypeRC,
		AttrMask:     AttrMaskState | AttrMaskAV | AttrMaskDestQPN,
		DestQPNum:    0x3c4d,
		FlowLabel:    0xabcde,
		QPState:      QPStateRTR,
		SGIDIndex:    3,
		PortNum:      1,
		HopLimit:     64,
		TrafficClass: 96,
		SL:           3,
		IsGlobal:     1,
		DestPortNum:  1,
		Comm:         "nccl-worker",
	}
	copy(want.DGID[:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1})

	got, err := DecodeEvent(rawEvent(want))
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if got != want {
		t.Fatalf("DecodeEvent mismatch:\n got %+v\nwant %+v", got, want)
	}
	if !got.IsConnect() {
		t.Error("RTR with AV must be a connect")
	}
	if got.IsReset() {
		t.Error("RTR must not be a reset")
	}
}

func TestDecodeEventCommWithoutTerminator(t *testing.T) {
	ev := Event{Kind: KindQPCreate, Comm: "sixteen-char-com"} // exactly 16 bytes
	raw := rawEvent(ev)
	got, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if got.Comm != "sixteen-char-com" {
		t.Fatalf("Comm = %q, want the full 16 bytes", got.Comm)
	}
}

func TestDecodeEventShort(t *testing.T) {
	if _, err := DecodeEvent(make([]byte, eventSize-1)); err == nil {
		t.Fatal("expected an error for a short record")
	}
}

func TestEventClassification(t *testing.T) {
	reset := Event{Kind: KindQPModify, AttrMask: AttrMaskState, QPState: QPStateReset}
	if !reset.IsReset() || reset.IsConnect() {
		t.Error("RESET must be a reset and not a connect")
	}
	rts := Event{Kind: KindQPModify, AttrMask: AttrMaskState, QPState: QPStateRTS}
	if rts.IsReset() || rts.IsConnect() {
		t.Error("RTS must be neither")
	}
	rtrNoAV := Event{Kind: KindQPModify, AttrMask: AttrMaskState, QPState: QPStateRTR}
	if rtrNoAV.IsConnect() {
		t.Error("RTR without an address vector must not be a connect")
	}
	create := Event{Kind: KindQPCreate, AttrMask: AttrMaskState | AttrMaskAV, QPState: QPStateRTR}
	if create.IsConnect() {
		t.Error("only modify events can be connects")
	}
	for qpType, want := range map[uint32]bool{
		QPTypeRC: true, QPTypeUC: true, QPTypeXRCInitiator: true, QPTypeXRCTarget: true,
		QPTypeUD: false, QPTypeRawPacket: false, QPTypeDriver: false, 0: false,
	} {
		if IsConnectedType(qpType) != want {
			t.Errorf("IsConnectedType(%d) = %v, want %v", qpType, !want, want)
		}
	}
}

func TestKindString(t *testing.T) {
	for k, want := range map[Kind]string{
		KindQPCreate: "create", KindQPModify: "modify", KindQPDestroy: "destroy",
		KindContextClose: "context_close", Kind(9): "kind(9)",
	} {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", uint32(k), got, want)
		}
	}
}
