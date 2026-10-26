package servicetrace

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Synthetic control + extended AV fixture; not a hardware capture. Keep the
// literal independent from the decoder's offsets. The nonzero DC access key
// must not appear in the decoded result or any retained flow.
func dcPrefix(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString("0000120a012345040000000000000000" +
		"010203040506070880abcdef5600d234" +
		"00000000001122334455a0400ab54321" +
		"00000000000000000000ffffc0000201")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeMLX5DCAddress(t *testing.T) {
	a, err := decodeMLX5DCAddress(dcPrefix(t), 0x12345)
	if err != nil {
		t.Fatal(err)
	}
	want := mlx5DCAddress{
		LocalQPN: 0x12345, RemoteDCT: 0xabcdef,
		RemoteGID:       [16]byte{10: 0xff, 11: 0xff, 12: 192, 14: 2, 15: 1},
		RemoteMAC:       [6]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55},
		AVUDPSourcePort: 0xd234, FlowLabel: 0x54321, SGIDIndex: 0xab,
		TrafficClass: 0xa0, SL: 3, HopLimit: 0x40,
	}
	if a != want {
		t.Fatalf("decoded %+v, want %+v", a, want)
	}
	// A zero application flow label does not make the AV's random sport zero,
	// and must not invoke the RC/UC/XRC QPN-derived fallback.
	b := dcPrefix(t)
	binary.BigEndian.PutUint32(b[44:48], 0x0ab00000)
	a, err = decodeMLX5DCAddress(b, 0x12345)
	if err != nil || a.FlowLabel != 0 || a.AVUDPSourcePort != 0xd234 {
		t.Fatalf("zero label: %+v, %v", a, err)
	}
	// The prefix can come from a larger capture, but payload and access key
	// changes must not affect the address or be retained in it.
	b[16] ^= 0xff
	b = append(b, 1, 2, 3, 4)
	again, err := decodeMLX5DCAddress(b, 0x12345)
	if err != nil || again != a {
		t.Fatalf("key/payload affected address: %+v, %v", again, err)
	}
}

func TestDecodeMLX5DCAddressRejectsUnsupported(t *testing.T) {
	for n := 0; n < 64; n++ {
		if _, err := decodeMLX5DCAddress(dcPrefix(t)[:n], 0x12345); err == nil {
			t.Fatalf("accepted %d-byte prefix", n)
		}
	}
	for _, qpn := range []uint32{0, 1, 0x1000000} {
		if _, err := decodeMLX5DCAddress(dcPrefix(t), qpn); err == nil {
			t.Fatalf("accepted mismatching/invalid QPN %#x", qpn)
		}
	}
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"modifier", func(b []byte) { b[0] = 1 }},
		{"stream", func(b []byte) { b[10] = 1 }},
		{"stream-high-byte", func(b []byte) { b[9] = 1 }},
		{"nop", func(b []byte) { b[3] = 0 }},
		{"atomic", func(b []byte) { b[3] = 0x11 }},
		{"short-segment-count", func(b []byte) { b[7] = 3 }},
		{"reserved-ds-bits", func(b []byte) { b[7] = 0x44 }},
		{"write-missing-raddr", func(b []byte) { b[3] = 8 }},
		{"compact-av", func(b []byte) { b[24] = 0 }},
		{"reserved-dct-bits", func(b []byte) { b[24] = 0x81 }},
		{"zero-dct", func(b []byte) { clear(b[25:28]) }},
		{"ib-grh-bit", func(b []byte) { b[44] |= 0x40 }},
		{"ib-path-bits", func(b []byte) { b[29] = 1 }},
		{"invalid-sport", func(b []byte) { b[30] = 0xbf }},
		{"zero-gid", func(b []byte) { clear(b[48:64]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := dcPrefix(t)
			tc.mutate(b)
			if a, err := decodeMLX5DCAddress(b, 0x12345); err == nil || a != (mlx5DCAddress{}) {
				t.Fatalf("expected error and empty address, got %+v, %v", a, err)
			}
		})
	}
}

func TestDecodeMLX5DCAddressOpcodes(t *testing.T) {
	for _, op := range []byte{0x08, 0x09, 0x0a, 0x0b, 0x10} {
		b := dcPrefix(t)
		b[3], b[7] = op, 6
		if _, err := decodeMLX5DCAddress(b, 0x12345); err != nil {
			t.Fatalf("opcode %#x: %v", op, err)
		}
	}
}

func FuzzDecodeMLX5DCAddress(f *testing.F) {
	f.Add(dcPrefix(f), uint32(0x12345))
	f.Fuzz(func(t *testing.T, b []byte, qpn uint32) {
		a, err := decodeMLX5DCAddress(b, qpn)
		if err != nil && a != (mlx5DCAddress{}) {
			t.Fatal("decoder exposed a partial address after error")
		}
	})
}
