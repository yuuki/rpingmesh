package probe

import "testing"

func TestCanonicalTorID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "  ", ""},
		{"tabs and spaces", " \t ", ""},
		{"named", "tor-1", "tor-1"},
		{"named with padding", " tor-1 ", "tor-1"},
		{"unknown is a normal name", "unknown", "unknown"},
		{"reserved label", "unspecified", "unspecified"},
		{"reserved label padded", " unspecified ", "unspecified"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalTorID(tc.in); got != tc.want {
				t.Errorf("CanonicalTorID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTorMetricLabel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", UnspecifiedTorLabel},
		{"whitespace only", "  ", UnspecifiedTorLabel},
		{"named", "tor-1", "tor-1"},
		{"named with padding", " tor-1 ", "tor-1"},
		{"unknown is a normal name", "unknown", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := TorMetricLabel(tc.in); got != tc.want {
				t.Errorf("TorMetricLabel(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsReservedTorID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty is not reserved", "", false},
		{"whitespace only is not reserved", "  ", false},
		{"named", "tor-1", false},
		{"unknown is a normal name", "unknown", false},
		{"reserved label", "unspecified", true},
		{"reserved label padded", " unspecified ", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsReservedTorID(tc.in); got != tc.want {
				t.Errorf("IsReservedTorID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
