package servicetrace

import (
	"debug/dwarf"
	"debug/elf"
	"testing"
)

func TestDCFieldOffset(t *testing.T) {
	u32 := &dwarf.UintType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 4}}}
	inner := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 12}, Field: []*dwarf.StructField{{Name: "value", ByteOffset: 8, Type: u32}}}
	union := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 12}, Kind: "union", Field: []*dwarf.StructField{{Name: "qp", Type: inner}}}
	root := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 32}, Field: []*dwarf.StructField{{Name: "", ByteOffset: 16, Type: union}}}
	if off, err := dcFieldOffset(root, "qp.value", 4); err != nil || off != 24 {
		t.Fatalf("anonymous union offset: %d, %v", off, err)
	}
	for _, path := range []string{"missing", "qp.nope", "qp.value.child"} {
		if _, err := dcFieldOffset(root, path, 4); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	if _, err := dcFieldOffset(root, "qp.value", 8); err == nil {
		t.Fatal("accepted mismatching field size")
	}
	inner.Field[0].BitSize = 1
	if _, err := dcFieldOffset(root, "qp.value", 4); err == nil {
		t.Fatal("accepted bitfield")
	}
	inner.Field[0].BitSize = 0
	inner.Field[0].ByteOffset = 12
	if _, err := dcFieldOffset(root, "qp.value", 4); err == nil {
		t.Fatal("accepted field beyond parent")
	}
}

func TestDCExecutableOffset(t *testing.T) {
	f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_X, Vaddr: 0x5000, Off: 0x1000, Filesz: 0x100}}}}
	if off, ok := dcExecutableOffset(f, 0x5020, 0x10); !ok || off != 0x1020 {
		t.Fatalf("offset %#x, valid %v", off, ok)
	}
	for _, addr := range []uint64{0, 0x4fff, 0x50ff, 0x5100} {
		if _, ok := dcExecutableOffset(f, addr, 2); ok {
			t.Fatalf("accepted %#x", addr)
		}
	}
	f.Progs[0].Flags = elf.PF_R
	if _, ok := dcExecutableOffset(f, 0x5020, 0x10); ok {
		t.Fatal("accepted nonexecutable segment")
	}
}

func TestDCQPBaseLayout(t *testing.T) {
	base := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 16}}
	ex := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 24}, Field: []*dwarf.StructField{{Name: "qp_base", Type: base}}}
	verbs := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 32}, Field: []*dwarf.StructField{{Name: "qp", Type: base}, {Name: "qp_ex", Type: ex}}}
	qp := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 64}, Field: []*dwarf.StructField{{Name: "verbs_qp", ByteOffset: 24, Type: verbs}}}
	if err := dcValidateQPBase(qp, 24, 16); err != nil {
		t.Fatal(err)
	}
	ex.Field[0].ByteOffset = 8
	if err := dcValidateQPBase(qp, 24, 16); err == nil {
		t.Fatal("accepted shifted qp_base")
	}
	ex.Field[0].ByteOffset = 0
	verbs.Field[1].ByteOffset = 8
	if err := dcValidateQPBase(qp, 24, 16); err == nil {
		t.Fatal("accepted shifted qp_ex")
	}
	verbs.Field[1].ByteOffset = 0
	verbs.Field[0].ByteOffset = 8
	if err := dcValidateQPBase(qp, 24, 16); err == nil {
		t.Fatal("accepted shifted ordinary qp")
	}
}
