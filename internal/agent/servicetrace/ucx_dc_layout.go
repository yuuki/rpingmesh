package servicetrace

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
)

// ucxDCLayout describes the experimental UCX dc_mlx5 submission adapter. It
// supports verbs DCIs and explicitly enabled DevX DCIs and streams through the
// lifecycle adapter. AM short-iov, bcopy and zcopy require separate opt-in.
// RMA put/get, atomics and tag sends each require separate opt-in.
// Keep this order identical to struct ucx_dc_layout in the BPF program.
type ucxDCLayout struct {
	EPInterface, EPDCI, InterfaceBuffer, InterfaceLength uint32
	DCIWQ, WQType, WQQP, WQQPN                           uint32
	WQStart, WQEnd, WQCurrent, WQDB                      uint32
	WQPrevious, WQProducer                               uint32
	WQDevXObject, WQDevXBuffer, InterfacePort            uint32
	DevXContext, DevXQPN, DevXEnabled                    uint32
	EPChannel, StreamsEnabled                            uint32
}

type ucxDCProvider struct {
	layout                      ucxDCLayout
	symbol                      uint64
	amSymbols                   [3]uint64
	rmaSymbols                  [5]uint64
	atomicSymbols               [6]uint64
	tagSymbols                  [5]uint64
	createSymbol, connectSymbol uint64
	machine                     elf.Machine
}

// inspectUCXDC requires matching full DWARF rather than a version-based offset
// table. Layout checks alone do not prove the semantics of an arbitrary build.
func inspectUCXDC(library, debugFile string) (*ucxDCProvider, error) {
	return inspectUCXDCMode(library, debugFile, false)
}

func inspectUCXDCMode(library, debugFile string, devx bool) (*ucxDCProvider, error) {
	return inspectUCXDCStreams(library, debugFile, devx, false)
}

func inspectUCXDCStreams(library, debugFile string, devx, streams bool) (*ucxDCProvider, error) {
	return inspectUCXDCOperations(library, debugFile, devx, streams, false, false, false, false)
}

func inspectUCXDCOperations(library, debugFile string, devx, streams, am, rma, atomic, tag bool) (*ucxDCProvider, error) {
	if streams && !devx {
		return nil, fmt.Errorf("UCX streams require the DevX lifecycle adapter")
	}
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
	data, err := dcMatchingDWARF(lib, dbg, "UCX")
	if err != nil {
		return nil, err
	}
	p := &ucxDCProvider{machine: lib.Machine}
	if streams {
		p.layout.StreamsEnabled = 1
	}
	types, err := ucxDCStructs(data)
	if err != nil {
		return nil, err
	}
	for _, f := range ucxDCFields(&p.layout, devx, streams) {
		if err := ucxResolveField(f, types[f.root]); err != nil {
			return nil, err
		}
	}
	if err := ucxCheckBaseLayouts(types, devx); err != nil {
		return nil, err
	}
	syms, err := dbg.Symbols()
	if err != nil {
		return nil, err
	}
	if err := ucxResolveFunctions(lib, syms, ucxDCFunctions(p, devx, am, rma, atomic, tag)); err != nil {
		return nil, err
	}
	return p, nil
}

func ucxDCFields(layout *ucxDCLayout, devx, streams bool) []dcDWARFField {
	fields := []dcDWARFField{
		{&layout.EPInterface, "uct_dc_mlx5_ep", "super.super.iface", 8},
		{&layout.EPDCI, "uct_dc_mlx5_ep", "dci", 2},
		{&layout.InterfaceBuffer, "uct_dc_mlx5_iface", "tx.dcis.buffer", 8},
		{&layout.InterfaceLength, "uct_dc_mlx5_iface", "tx.dcis.length", 2},
		{&layout.DCIWQ, "uct_dc_dci", "txwq", -1},
		{&layout.WQType, "uct_ib_mlx5_txwq", "super.type", 4},
		{&layout.WQQP, "uct_ib_mlx5_txwq", "super.verbs.qp", 8},
		{&layout.WQQPN, "uct_ib_mlx5_txwq", "super.qp_num", 4},
		{&layout.WQStart, "uct_ib_mlx5_txwq", "qstart", 8},
		{&layout.WQEnd, "uct_ib_mlx5_txwq", "qend", 8},
		{&layout.WQCurrent, "uct_ib_mlx5_txwq", "curr", 8},
		{&layout.WQDB, "uct_ib_mlx5_txwq", "dbrec", 8},
		{&layout.WQPrevious, "uct_ib_mlx5_txwq", "prev_sw_pi", 2},
		{&layout.WQProducer, "uct_ib_mlx5_txwq", "sw_pi", 2},
	}
	if devx {
		fields = append(fields,
			dcDWARFField{&layout.WQDevXObject, "uct_ib_mlx5_txwq", "super.devx.obj", 8},
			dcDWARFField{&layout.WQDevXBuffer, "uct_ib_mlx5_txwq", "super.devx.wq_buf", 8},
			dcDWARFField{&layout.InterfacePort, "uct_dc_mlx5_iface", "super.super.super.config.port_num", 1})
	}
	if streams {
		fields = append(fields, dcDWARFField{&layout.EPChannel, "uct_dc_mlx5_ep", "dci_channel_index", 1})
	}
	return fields
}

// ucxDCStructs collects every complete definition of the UCX structures in
// DWARF order.
func ucxDCStructs(data *dwarf.Data) (map[string][]*dwarf.StructType, error) {
	types := make(map[string][]*dwarf.StructType)
	r := data.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return nil, err
		}
		if e == nil {
			return types, nil
		}
		if e.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := e.Val(dwarf.AttrName).(string)
		if !ucxDCStructWanted(name) {
			continue
		}
		s, err := dcCompleteStruct(data, e)
		if err != nil {
			return nil, err
		}
		if s != nil {
			types[name] = append(types[name], s)
		}
	}
}

func ucxDCStructWanted(name string) bool {
	switch name {
	case "uct_dc_mlx5_ep", "uct_dc_mlx5_iface", "uct_dc_dci", "uct_ib_mlx5_txwq":
		return true
	}
	return false
}

// ucxResolveField stores the field's offset and requires every definition of
// its root structure to agree on both the offset and the structure size.
func ucxResolveField(f dcDWARFField, candidates []*dwarf.StructType) error {
	if len(candidates) == 0 {
		return fmt.Errorf("missing UCX DWARF type %s", f.root)
	}
	for i, s := range candidates {
		off, err := dcFieldOffset(s, f.path, f.size)
		if err != nil {
			return fmt.Errorf("UCX %s.%s: %w", f.root, f.path, err)
		}
		if i > 0 && (off != *f.out || s.Size() != candidates[0].Size()) {
			return fmt.Errorf("ambiguous UCX layout for %s.%s", f.root, f.path)
		}
		*f.out = off
	}
	return nil
}

// ucxCheckBaseLayouts requires the base-class chains that UCT converts
// pointers through to start at offset zero in every definition.
func ucxCheckBaseLayouts(types map[string][]*dwarf.StructType, devx bool) error {
	// UCT passes base-class pointers; both container chains must start at zero.
	for root, path := range map[string]string{
		"uct_dc_mlx5_ep":    "super.super",
		"uct_dc_mlx5_iface": "super.super.super.super.super",
	} {
		if !ucxPathAtZero(types[root], path) {
			return fmt.Errorf("unsupported UCX base layout: %s", root)
		}
	}
	if devx && !ucxPathAtZero(types["uct_ib_mlx5_txwq"], "super") {
		return fmt.Errorf("unsupported UCX QP base layout")
	}
	return nil
}

// ucxPathAtZero reports whether path resolves to offset zero in every
// structure definition.
func ucxPathAtZero(definitions []*dwarf.StructType, path string) bool {
	for _, s := range definitions {
		off, err := dcFieldOffset(s, path, -1)
		if err != nil || off != 0 {
			return false
		}
	}
	return true
}

// ucxDCFunctions maps every function the selected operations need to the
// field of p that receives its file offset.
func ucxDCFunctions(p *ucxDCProvider, devx, am, rma, atomic, tag bool) map[string]*uint64 {
	wanted := map[string]*uint64{"uct_dc_mlx5_ep_am_short": &p.symbol}
	if am {
		ucxWantFunctions(wanted, p.amSymbols[:], "uct_dc_mlx5_ep_am_short_iov", "uct_dc_mlx5_ep_am_bcopy", "uct_dc_mlx5_ep_am_zcopy")
	}
	if rma {
		ucxWantFunctions(wanted, p.rmaSymbols[:], "uct_dc_mlx5_ep_put_short", "uct_dc_mlx5_ep_put_bcopy", "uct_dc_mlx5_ep_put_zcopy", "uct_dc_mlx5_ep_get_bcopy", "uct_dc_mlx5_ep_get_zcopy")
	}
	if atomic {
		ucxWantFunctions(wanted, p.atomicSymbols[:], "uct_dc_mlx5_ep_atomic32_post", "uct_dc_mlx5_ep_atomic64_post", "uct_dc_mlx5_ep_atomic32_fetch", "uct_dc_mlx5_ep_atomic64_fetch", "uct_dc_mlx5_ep_atomic_cswap32", "uct_dc_mlx5_ep_atomic_cswap64")
	}
	if tag {
		ucxWantFunctions(wanted, p.tagSymbols[:], "uct_dc_mlx5_ep_tag_eager_short", "uct_dc_mlx5_ep_tag_eager_bcopy", "uct_dc_mlx5_ep_tag_eager_zcopy", "uct_dc_mlx5_ep_tag_rndv_request", "uct_dc_mlx5_ep_tag_rndv_zcopy")
	}
	if devx {
		wanted["uct_dc_mlx5_iface_create_dci"] = &p.createSymbol
		wanted["uct_dc_mlx5_iface_dci_connect"] = &p.connectSymbol
	}
	return wanted
}

// ucxWantFunctions maps names[i] to targets[i].
func ucxWantFunctions(wanted map[string]*uint64, targets []uint64, names ...string) {
	for i, name := range names {
		wanted[name] = &targets[i]
	}
}

// ucxResolveFunctions stores the file offset of every wanted function,
// rejecting a function defined at several offsets or not at all.
func ucxResolveFunctions(lib *elf.File, syms []elf.Symbol, wanted map[string]*uint64) error {
	for _, s := range syms {
		target := wanted[s.Name]
		if target == nil {
			continue
		}
		off, ok := dcFunctionOffset(lib, s)
		if !ok {
			continue
		}
		if *target != 0 && *target != off {
			return fmt.Errorf("ambiguous UCX function %s", s.Name)
		}
		*target = off
	}
	for name, target := range wanted {
		if *target == 0 {
			return fmt.Errorf("required UCX function %s is unavailable", name)
		}
	}
	return nil
}

// CheckUCXDC performs the optional adapter's non-privileged ELF/DWARF checks.
func CheckUCXDC(library, debugFile string) error {
	_, err := inspectUCXDC(library, debugFile)
	return err
}

// CheckUCXDCDevX additionally validates both libraries' DevX lifecycle layouts.
func CheckUCXDCDevX(provider, providerDebug, ucx, ucxDebug string) error {
	p, err := inspectDCProviderMode(provider, providerDebug, true)
	if err != nil {
		return err
	}
	u, err := inspectUCXDCMode(ucx, ucxDebug, true)
	if err != nil {
		return err
	}
	if p.machine != u.machine {
		return fmt.Errorf("UCX/provider architectures differ")
	}
	return nil
}

// CheckUCXDCStreams validates the optional DevX stream adapter without BPF.
func CheckUCXDCStreams(provider, providerDebug, ucx, ucxDebug string) error {
	if err := CheckUCXDCDevX(provider, providerDebug, ucx, ucxDebug); err != nil {
		return err
	}
	_, err := inspectUCXDCStreams(ucx, ucxDebug, true, true)
	return err
}

// CheckUCXDCAM validates the additional active-message submission symbols.
func CheckUCXDCAM(library, debugFile string) error {
	_, err := inspectUCXDCOperations(library, debugFile, false, false, true, false, false, false)
	return err
}

// CheckUCXDCRMA validates the optional put/get submission symbols.
func CheckUCXDCRMA(library, debugFile string) error {
	_, err := inspectUCXDCOperations(library, debugFile, false, false, false, true, false, false)
	return err
}

// CheckUCXDCAtomic validates the optional 32/64-bit atomic submission symbols.
func CheckUCXDCAtomic(library, debugFile string) error {
	_, err := inspectUCXDCOperations(library, debugFile, false, false, false, false, true, false)
	return err
}

// CheckUCXDCTag validates the optional tag submission symbols.
func CheckUCXDCTag(library, debugFile string) error {
	_, err := inspectUCXDCOperations(library, debugFile, false, false, false, false, false, true)
	return err
}
