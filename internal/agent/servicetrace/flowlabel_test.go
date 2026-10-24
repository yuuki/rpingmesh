package servicetrace

import "testing"

func TestCalcFlowLabel(t *testing.T) {
	// A product below 2^20 is returned unchanged.
	if got := CalcFlowLabel(0x11, 0x22); got != 0x242 {
		t.Errorf("CalcFlowLabel(0x11, 0x22) = %#x, want 0x242", got)
	}
	// 1<<20 folds onto bit 0 and is then masked away: (1<<20 ^ 1) & mask.
	if got := CalcFlowLabel(1<<20, 1); got != 1 {
		t.Errorf("CalcFlowLabel(1<<20, 1) = %#x, want 1", got)
	}
	// Symmetric, so both ends of a connection derive the same label.
	a, b := uint32(0xABCDE), uint32(0x12345)
	if CalcFlowLabel(a, b) != CalcFlowLabel(b, a) {
		t.Error("CalcFlowLabel must be symmetric in its arguments")
	}
	if got := CalcFlowLabel(0xFFFFFF, 0xFFFFFF); got > FlowLabelMask {
		t.Errorf("CalcFlowLabel exceeds 20 bits: %#x", got)
	}
}

func TestEffectiveFlowLabel(t *testing.T) {
	if got := EffectiveFlowLabel(5, 0x11, 0x22); got != 5 {
		t.Errorf("an explicit label must win, got %#x", got)
	}
	if got := EffectiveFlowLabel(0, 0x11, 0x22); got != 0x242 {
		t.Errorf("a zero label must fall back to CalcFlowLabel, got %#x", got)
	}
	if got := EffectiveFlowLabel(0x100005, 0x11, 0x22); got != 5 {
		t.Errorf("bits above the 20-bit label must be ignored, got %#x", got)
	}
}

func TestUDPSourcePort(t *testing.T) {
	for fl, want := range map[uint32]uint16{
		0:       0xC000,
		0x3FFF:  0xFFFF,
		0x4000:  0xC001,                   // bit 14 folds onto bit 0
		0xFFFFF: 0xFFC0,                   // 0x3FFF ^ 0x3F
		0xABCDE: 0xC000 | (0x3CDE ^ 0x2A), // low 14 bits 0x3CDE, high 6 bits 0x2A
	} {
		if got := UDPSourcePort(fl); got != want {
			t.Errorf("UDPSourcePort(%#x) = %#x, want %#x", fl, got, want)
		}
	}
}
