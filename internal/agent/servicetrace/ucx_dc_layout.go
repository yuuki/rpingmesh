package servicetrace

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"fmt"
)

// ucxDCLayout describes the experimental UCX dc_mlx5 AM-short adapter. It
// supports verbs-created, non-stream DCIs, not DevX or other UCT operations.
// Keep this order identical to struct ucx_dc_layout in the BPF program.
type ucxDCLayout struct {
	EPInterface, EPDCI, InterfaceBuffer, InterfaceLength uint32
	DCIWQ, WQType, WQQP, WQQPN                           uint32
	WQStart, WQEnd, WQCurrent, WQDB                      uint32
	WQPrevious, WQProducer                               uint32
}

type ucxDCProvider struct {
	layout  ucxDCLayout
	symbol  uint64
	machine elf.Machine
}

// inspectUCXDC requires matching full DWARF rather than a version-based offset
// table. Layout checks alone do not prove the semantics of an arbitrary build.
func inspectUCXDC(library, debugFile string) (*ucxDCProvider, error) {
	lib, err := elf.Open(library)
	if err != nil {
		return nil, err
	}
	defer lib.Close()
	dbg, err := elf.Open(debugFile)
	if err != nil {
		return nil, err
	}
	defer dbg.Close()
	if lib.Class != elf.ELFCLASS64 || lib.Data != elf.ELFDATA2LSB || lib.Type != elf.ET_DYN ||
		(lib.Machine != elf.EM_X86_64 && lib.Machine != elf.EM_AARCH64) ||
		dbg.Machine != lib.Machine || dbg.Class != lib.Class || dbg.Data != lib.Data {
		return nil, fmt.Errorf("unsupported or mismatching UCX ELF architecture")
	}
	lid, err := dcBuildID(lib)
	if err != nil {
		return nil, err
	}
	did, err := dcBuildID(dbg)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(lid, did) {
		return nil, fmt.Errorf("UCX and debug build IDs differ")
	}
	data, err := dbg.DWARF()
	if err != nil {
		return nil, fmt.Errorf("full UCX DWARF is required: %w", err)
	}
	p := &ucxDCProvider{machine: lib.Machine}
	fields := []struct {
		out        *uint32
		root, path string
		size       int64
	}{
		{&p.layout.EPInterface, "uct_dc_mlx5_ep", "super.super.iface", 8},
		{&p.layout.EPDCI, "uct_dc_mlx5_ep", "dci", 2},
		{&p.layout.InterfaceBuffer, "uct_dc_mlx5_iface", "tx.dcis.buffer", 8},
		{&p.layout.InterfaceLength, "uct_dc_mlx5_iface", "tx.dcis.length", 2},
		{&p.layout.DCIWQ, "uct_dc_dci", "txwq", -1},
		{&p.layout.WQType, "uct_ib_mlx5_txwq", "super.type", 4},
		{&p.layout.WQQP, "uct_ib_mlx5_txwq", "super.verbs.qp", 8},
		{&p.layout.WQQPN, "uct_ib_mlx5_txwq", "super.qp_num", 4},
		{&p.layout.WQStart, "uct_ib_mlx5_txwq", "qstart", 8},
		{&p.layout.WQEnd, "uct_ib_mlx5_txwq", "qend", 8},
		{&p.layout.WQCurrent, "uct_ib_mlx5_txwq", "curr", 8},
		{&p.layout.WQDB, "uct_ib_mlx5_txwq", "dbrec", 8},
		{&p.layout.WQPrevious, "uct_ib_mlx5_txwq", "prev_sw_pi", 2},
		{&p.layout.WQProducer, "uct_ib_mlx5_txwq", "sw_pi", 2},
	}
	types := make(map[string][]*dwarf.StructType)
	r := data.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return nil, err
		}
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := e.Val(dwarf.AttrName).(string)
		switch name {
		case "uct_dc_mlx5_ep", "uct_dc_mlx5_iface", "uct_dc_dci", "uct_ib_mlx5_txwq":
			t, err := data.Type(e.Offset)
			if err != nil {
				return nil, err
			}
			if s, ok := t.(*dwarf.StructType); ok && !s.Incomplete {
				types[name] = append(types[name], s)
			}
		}
	}
	for _, f := range fields {
		candidates := types[f.root]
		if len(candidates) == 0 {
			return nil, fmt.Errorf("missing UCX DWARF type %s", f.root)
		}
		for i, s := range candidates {
			off, err := dcFieldOffset(s, f.path, f.size)
			if err != nil {
				return nil, fmt.Errorf("UCX %s.%s: %w", f.root, f.path, err)
			}
			if i > 0 && (off != *f.out || s.Size() != candidates[0].Size()) {
				return nil, fmt.Errorf("ambiguous UCX layout for %s.%s", f.root, f.path)
			}
			*f.out = off
		}
	}
	// UCT passes base-class pointers; both container chains must start at zero.
	for root, path := range map[string]string{
		"uct_dc_mlx5_ep":    "super.super",
		"uct_dc_mlx5_iface": "super.super.super.super.super",
	} {
		for _, s := range types[root] {
			off, err := dcFieldOffset(s, path, -1)
			if err != nil || off != 0 {
				return nil, fmt.Errorf("unsupported UCX base layout: %s", root)
			}
		}
	}
	syms, err := dbg.Symbols()
	if err != nil {
		return nil, err
	}
	for _, s := range syms {
		if s.Name != "uct_dc_mlx5_ep_am_short" || elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Section == elf.SHN_UNDEF || s.Size == 0 {
			continue
		}
		off, ok := dcExecutableOffset(lib, s.Value, s.Size)
		if !ok {
			continue
		}
		if p.symbol != 0 && p.symbol != off {
			return nil, fmt.Errorf("ambiguous UCX AM-short function")
		}
		p.symbol = off
	}
	if p.symbol == 0 {
		return nil, fmt.Errorf("UCX dc_mlx5 AM-short function is unavailable")
	}
	return p, nil
}

// CheckUCXDC performs the optional adapter's non-privileged ELF/DWARF checks.
func CheckUCXDC(library, debugFile string) error {
	_, err := inspectUCXDC(library, debugFile)
	return err
}
