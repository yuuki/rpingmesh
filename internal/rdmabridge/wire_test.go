package rdmabridge

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// decodeWire reads a probe packet back by the documented layout (see
// SerializeProbePacket and zig/src/wire.zig), independently of the Zig
// decoder that parses received packets in the CQ poller.
func decodeWire(buf []byte) ProbePacket {
	be := binary.BigEndian
	return ProbePacket{
		Version:     buf[0],
		MsgType:     buf[1],
		AckType:     buf[2],
		Flags:       buf[3],
		SequenceNum: be.Uint64(buf[4:12]),
		T1:          be.Uint64(buf[12:20]),
		T3:          be.Uint64(buf[20:28]),
		T4:          be.Uint64(buf[28:36]),
	}
}

// TestSerializeProbePacketLayout pins the 40-byte wire format with the same
// packet and expected bytes as the Zig test "serializeProbePacket writes the
// documented byte layout" in zig/src/wire.zig, so the Go and Zig encoders
// cannot drift apart unnoticed.
func TestSerializeProbePacketLayout(t *testing.T) {
	pkt := ProbePacket{
		Version:     PacketVersion,
		MsgType:     MsgTypeAck,
		AckType:     AckTypeFirst,
		Flags:       0x42,
		SequenceNum: 0x0102030405060708,
		T1:          1000,
		T3:          2000,
		T4:          3000,
	}
	buf := bytes.Repeat([]byte{0xFF}, ProbePacketSize)
	SerializeProbePacket(&pkt, buf)

	want := []byte{
		1, 1, 1, 0x42,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0x03, 0xE8,
		0, 0, 0, 0,
		0, 0, 0x07, 0xD0,
		0, 0, 0, 0,
		0, 0, 0x0B, 0xB8,
		0, 0, 0, 0,
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("SerializeProbePacket wrote\n%x\nwant\n%x", buf, want)
	}
}

// FuzzSerializeProbePacket checks that every packet serializes into the
// documented layout: each field reads back from its offset, the reserved
// bytes are zero whatever the buffer held, and nothing past the 40 bytes is
// written.
func FuzzSerializeProbePacket(f *testing.F) {
	f.Add(uint8(PacketVersion), uint8(MsgTypeAck), uint8(AckTypeFirst), uint8(0x42),
		uint64(0x0102030405060708), uint64(1000), uint64(2000), uint64(3000), byte(0xFF), uint8(0))
	f.Add(uint8(PacketVersion), uint8(MsgTypeProbe), uint8(AckTypeNone), uint8(0),
		^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), byte(0xA5), uint8(7))

	f.Fuzz(func(t *testing.T, version, msgType, ackType, flags uint8, seq, t1, t3, t4 uint64, fill byte, extra uint8) {
		pkt := ProbePacket{
			Version: version, MsgType: msgType, AckType: ackType, Flags: flags,
			SequenceNum: seq, T1: t1, T3: t3, T4: t4,
		}
		buf := bytes.Repeat([]byte{fill}, ProbePacketSize+int(extra%16))
		SerializeProbePacket(&pkt, buf)

		if got := decodeWire(buf); got != pkt {
			t.Fatalf("decoded %+v, serialized %+v", got, pkt)
		}
		if !bytes.Equal(buf[36:ProbePacketSize], make([]byte, 4)) {
			t.Fatalf("reserved bytes = %x, want zero", buf[36:ProbePacketSize])
		}
		for i, b := range buf[ProbePacketSize:] {
			if b != fill {
				t.Fatalf("byte %d past the packet was overwritten", ProbePacketSize+i)
			}
		}
	})
}

func BenchmarkSerializeProbePacket(b *testing.B) {
	pkt := ProbePacket{Version: PacketVersion, MsgType: MsgTypeProbe, SequenceNum: 1, T1: 2}
	buf := make([]byte, ProbePacketSize)
	b.ReportAllocs()
	for b.Loop() {
		pkt.SequenceNum++
		SerializeProbePacket(&pkt, buf)
	}
}
