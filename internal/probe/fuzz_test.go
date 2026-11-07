package probe

import (
	"net"
	"testing"
)

// FuzzParseGID checks that every GID ParseGID accepts has a canonical
// FormatGID text that parses back to the same 16 bytes, and that GIDFamily
// classifies the input by those bytes. GIDs arrive as text from the
// controller, the registry and configuration.
func FuzzParseGID(f *testing.F) {
	for _, s := range []string{
		"fe80:0000:0000:0000:0001:0002:0003:0004",
		"fe80::1",
		"::ffff:10.0.0.1",
		"0000:0000:0000:0000:0000:ffff:c0a8:0101",
		"192.168.1.1",
		"0:0:0:0:0:0:0:",
		"fe80::1%eth0",
		"g:0:0:0:0:0:0:0",
		"1:2:3:4:5:6:7:8:9",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		gid, err := ParseGID(s)
		if err != nil {
			if fam := GIDFamily(s); fam != GIDFamilyUnknown {
				t.Fatalf("GIDFamily(%q) = %q for an unparseable GID", s, fam)
			}
			return
		}
		text := FormatGID(gid)
		back, err := ParseGID(text)
		if err != nil || back != gid {
			t.Fatalf("ParseGID(FormatGID(%x)) = %x, %v", gid, back, err)
		}
		if again := FormatGID(back); again != text {
			t.Fatalf("FormatGID is not canonical: %q then %q", text, again)
		}
		want := GIDFamilyIPv6
		if isIPv4MappedGID(gid) {
			want = GIDFamilyIPv4Mapped
			// The display form of a mapped GID is its IPv4 address.
			if ip := net.ParseIP(GIDToIPv4(gid)); ip == nil || !ip.Equal(net.IP(gid[:])) {
				t.Fatalf("GIDToIPv4(%x) = %q does not name the same address", gid, GIDToIPv4(gid))
			}
		}
		if fam := GIDFamily(s); fam != want {
			t.Fatalf("GIDFamily(%q) = %q, want %q", s, fam, want)
		}
	})
}

// FuzzCalculateRTT checks CalculateRTT on arbitrary timestamps (T3 and T4
// come from the remote responder): the invalid kind is one of the fixed set
// used as a metric attribute, a valid result is within the sanity bounds,
// and its components add up to the measured intervals.
func FuzzCalculateRTT(f *testing.F) {
	f.Add(uint64(100_000), uint64(101_000), uint64(200_000), uint64(202_000), uint64(301_000), uint64(302_000))
	f.Add(uint64(0), uint64(1), uint64(2), uint64(3), uint64(4), uint64(5))
	f.Add(uint64(1), uint64(2), uint64(3), uint64(2), uint64(4), uint64(5))
	f.Add(^uint64(0), uint64(1), ^uint64(0), uint64(5), uint64(2), uint64(1))

	f.Fuzz(func(t *testing.T, t1, t2, t3, t4, t5, t6 uint64) {
		r := CalculateRTT(&ProbeResult{T1: t1, T2: t2, T3: t3, T4: t4, T5: t5, T6: t6})
		switch r.InvalidKind {
		case InvalidKindNone, InvalidKindMissingTimestamp, InvalidKindNegativeNetworkRTT,
			InvalidKindNetworkRTTTooLarge, InvalidKindNegativeResponderDelay,
			InvalidKindResponderDelayTooLarge, InvalidKindNegativeProberDelay,
			InvalidKindProberDelayTooLarge:
		default:
			t.Fatalf("InvalidKind %q is outside the fixed set", r.InvalidKind)
		}
		if r.Valid != (r.InvalidKind == InvalidKindNone) || r.Valid != (r.ValidationError == "") {
			t.Fatalf("inconsistent result: %+v", r)
		}
		missing := t1 == 0 || t2 == 0 || t3 == 0 || t4 == 0 || t5 == 0 || t6 == 0
		if missing != (r.InvalidKind == InvalidKindMissingTimestamp) {
			t.Fatalf("missing timestamp = %v but kind = %q", missing, r.InvalidKind)
		}
		if !r.Valid {
			return
		}
		if r.NetworkRTT < 0 || r.NetworkRTT > MaxSaneRTT ||
			r.ResponderDelay < 0 || r.ResponderDelay > MaxSaneDelay ||
			r.ProberDelay < 0 || r.ProberDelay > MaxSaneDelay {
			t.Fatalf("valid result outside the sanity bounds: %+v", r)
		}
		// Two's-complement differences, as computed from the timestamps.
		if r.NetworkRTT+r.ResponderDelay != int64(t5-t2) || r.ProberDelay+int64(t5-t2) != int64(t6-t1) {
			t.Fatalf("components do not add up to T5-T2 and T6-T1: %+v", r)
		}
	})
}
