package servicetrace

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

// dcLayout contains byte offsets, never an assumed copy of provider structs.
// Keep the order identical to struct dc_layout in bpf/dc_trace.bpf.c.
type dcLayout struct {
	QPBase, QPNum, QPType, ContextFD                                  uint32
	DCType, SQStart, SQCount, SQShift, SQPost, PostRollback, Requests uint32
	CreateMask, CreateDCType                                          uint32
	AttrState, AttrPort, AttrAVPort                                   uint32
}

type dcProvider struct {
	layout               dcLayout
	symbols              map[string]uint64
	machine              elf.Machine
	devxContext, devxQPN uint32
}

var dcRequiredSymbols = []string{
	"mlx5dv_create_qp", "mlx5_modify_qp", "mlx5_destroy_qp",
	"mlx5_send_wr_complete", "mlx5dv_modify_qp_udp_sport",
}

// inspectDCProvider deliberately requires full, matching DWARF. Mini-debug
// symbol tables, version strings and plausible offsets are not substitutes.
// This proves layout identity, not provider semantics or wire-port behavior.
func inspectDCProvider(library, debugFile string) (*dcProvider, error) {
	return inspectDCProviderMode(library, debugFile, false)
}

func inspectDCProviderMode(library, debugFile string, devx bool) (*dcProvider, error) {
	lib, err := elf.Open(library)
	if err != nil {
		return nil, fmt.Errorf("open provider ELF: %w", err)
	}
	defer lib.Close()
	dbg, err := elf.Open(debugFile)
	if err != nil {
		return nil, fmt.Errorf("open provider debug ELF: %w", err)
	}
	defer dbg.Close()
	data, err := dcMatchingDWARF(lib, dbg, "provider")
	if err != nil {
		return nil, err
	}
	types, candidates, err := dcProviderStructs(data, devx)
	if err != nil {
		return nil, err
	}
	p := &dcProvider{symbols: make(map[string]uint64), machine: lib.Machine}
	if err := dcResolveProviderLayout(p, types, candidates, devx); err != nil {
		return nil, err
	}
	syms, err := dbg.Symbols()
	if err != nil {
		return nil, fmt.Errorf("full provider symbol table is required: %w", err)
	}
	required := append([]string(nil), dcRequiredSymbols...)
	if devx {
		required = append(required, "mlx5dv_devx_obj_modify", "mlx5dv_devx_obj_destroy")
	}
	if err := dcResolveProviderFunctions(lib, syms, required, p.symbols); err != nil {
		return nil, err
	}
	return p, nil
}

// dcMatchingDWARF checks that dbg describes the same 64-bit little-endian
// x86-64 or arm64 shared-object build as lib and returns its full DWARF.
// what names the library in error messages ("provider" or "UCX").
func dcMatchingDWARF(lib, dbg *elf.File, what string) (*dwarf.Data, error) {
	if lib.Class != elf.ELFCLASS64 || lib.Data != elf.ELFDATA2LSB || lib.Type != elf.ET_DYN ||
		(lib.Machine != elf.EM_X86_64 && lib.Machine != elf.EM_AARCH64) ||
		dbg.Machine != lib.Machine || dbg.Class != lib.Class || dbg.Data != lib.Data {
		return nil, fmt.Errorf("unsupported or mismatching %s ELF architecture", what)
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
		return nil, fmt.Errorf("%s and debug build IDs differ", what)
	}
	data, err := dbg.DWARF()
	if err != nil {
		return nil, fmt.Errorf("full %s DWARF is required: %w", what, err)
	}
	return data, nil
}

// dcProviderStructs collects every complete definition of the provider
// structures in DWARF order. types holds the last definition of each name,
// and definitions of one name that differ in size are rejected as they appear.
func dcProviderStructs(data *dwarf.Data, devx bool) (map[string]*dwarf.StructType, map[string][]*dwarf.StructType, error) {
	types := make(map[string]*dwarf.StructType)
	candidates := make(map[string][]*dwarf.StructType)
	r := data.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return nil, nil, err
		}
		if e == nil {
			return types, candidates, nil
		}
		if e.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := e.Val(dwarf.AttrName).(string)
		if !dcProviderStructWanted(name, devx) {
			continue
		}
		s, err := dcCompleteStruct(data, e)
		if err != nil {
			return nil, nil, err
		}
		if s == nil {
			continue
		}
		if old := types[name]; old != nil && old.Size() != s.Size() {
			return nil, nil, fmt.Errorf("ambiguous provider DWARF type %s", name)
		}
		types[name] = s
		candidates[name] = append(candidates[name], s)
	}
}

func dcProviderStructWanted(name string, devx bool) bool {
	switch name {
	case "mlx5_qp", "ibv_qp", "ibv_context", "mlx5dv_qp_init_attr", "ibv_qp_attr":
		return true
	case "mlx5dv_devx_obj":
		return devx
	}
	return false
}

// dcCompleteStruct returns the structure type an entry defines, or nil when
// the type is not a complete structure.
func dcCompleteStruct(data *dwarf.Data, e *dwarf.Entry) (*dwarf.StructType, error) {
	t, err := data.Type(e.Offset)
	if err != nil {
		return nil, err
	}
	if s, ok := t.(*dwarf.StructType); ok && !s.Incomplete {
		return s, nil
	}
	return nil, nil
}

// dcResolveProviderLayout fills p's layout and DevX offsets from the provider
// structures and checks the verbs_qp container relationship.
func dcResolveProviderLayout(p *dcProvider, types map[string]*dwarf.StructType, candidates map[string][]*dwarf.StructType, devx bool) error {
	for _, f := range dcProviderFields(p, devx) {
		if err := dcResolveProviderField(f, types[f.root], candidates[f.root]); err != nil {
			return err
		}
	}
	// ibv_qp_ex and verbs_qp must start with the ordinary ibv_qp. The provider
	// converts the callback's qp pointer via this exact container relationship.
	for _, candidate := range candidates["mlx5_qp"] {
		if err := dcValidateQPBase(candidate, p.layout.QPBase, types["ibv_qp"].Size()); err != nil {
			return err
		}
	}
	return nil
}

func dcProviderFields(p *dcProvider, devx bool) []dcDWARFField {
	fields := []dcDWARFField{
		{&p.layout.QPBase, "mlx5_qp", "verbs_qp", -1},
		{&p.layout.QPNum, "ibv_qp", "qp_num", 4},
		{&p.layout.QPType, "ibv_qp", "qp_type", 4},
		{&p.layout.ContextFD, "ibv_context", "cmd_fd", 4},
		{&p.layout.DCType, "mlx5_qp", "dc_type", 4},
		{&p.layout.SQStart, "mlx5_qp", "sq_start", 8},
		{&p.layout.SQCount, "mlx5_qp", "sq.wqe_cnt", 4},
		{&p.layout.SQShift, "mlx5_qp", "sq.wqe_shift", 4},
		{&p.layout.SQPost, "mlx5_qp", "sq.cur_post", 4},
		{&p.layout.PostRollback, "mlx5_qp", "cur_post_rb", 4},
		{&p.layout.Requests, "mlx5_qp", "nreq", 4},
		{&p.layout.CreateMask, "mlx5dv_qp_init_attr", "comp_mask", 8},
		{&p.layout.CreateDCType, "mlx5dv_qp_init_attr", "dc_init_attr.dc_type", 4},
		{&p.layout.AttrState, "ibv_qp_attr", "qp_state", 4},
		{&p.layout.AttrPort, "ibv_qp_attr", "port_num", 1},
		{&p.layout.AttrAVPort, "ibv_qp_attr", "ah_attr.port_num", 1},
	}
	if devx {
		fields = append(fields, dcDWARFField{&p.devxContext, "mlx5dv_devx_obj", "context", 8}, dcDWARFField{&p.devxQPN, "mlx5dv_devx_obj", "object_id", 4})
	}
	return fields
}

// dcResolveProviderField stores the field's offset in root and requires every
// alternative definition of the root structure to agree on it.
func dcResolveProviderField(f dcDWARFField, root *dwarf.StructType, alternatives []*dwarf.StructType) error {
	off, err := dcFieldOffset(root, f.path, f.size)
	if err != nil {
		return fmt.Errorf("%s.%s: %w", f.root, f.path, err)
	}
	*f.out = off
	for _, alternative := range alternatives {
		other, err := dcFieldOffset(alternative, f.path, f.size)
		if err != nil || other != off {
			return fmt.Errorf("ambiguous provider layout for %s.%s", f.root, f.path)
		}
	}
	return nil
}

// dcResolveProviderFunctions records the file offsets of the required
// functions and of the optional mlx5dv_devx_qp_modify in symbols, rejecting
// a function defined at several offsets.
func dcResolveProviderFunctions(lib *elf.File, syms []elf.Symbol, required []string, symbols map[string]uint64) error {
	for _, s := range syms {
		if s.Name != "mlx5dv_devx_qp_modify" && !slices.Contains(required, s.Name) {
			continue
		}
		offset, ok := dcFunctionOffset(lib, s)
		if !ok {
			continue
		}
		if old, exists := symbols[s.Name]; exists && old != offset {
			return fmt.Errorf("ambiguous provider function %s", s.Name)
		}
		symbols[s.Name] = offset
	}
	for _, name := range required {
		if symbols[name] == 0 {
			return fmt.Errorf("required provider function %s is unavailable", name)
		}
	}
	return nil
}

// dcFunctionOffset returns the file offset of a defined, sized function
// symbol that lies inside an executable segment of lib.
func dcFunctionOffset(lib *elf.File, s elf.Symbol) (uint64, bool) {
	if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Section == elf.SHN_UNDEF || s.Size == 0 {
		return 0, false
	}
	return dcExecutableOffset(lib, s.Value, s.Size)
}

func dcValidateQPBase(qp *dwarf.StructType, want uint32, size int64) error {
	for _, path := range []string{"verbs_qp.qp", "verbs_qp.qp_ex", "verbs_qp.qp_ex.qp_base"} {
		width := size
		if path == "verbs_qp.qp_ex" {
			width = -1
		}
		base, err := dcFieldOffset(qp, path, width)
		if err != nil || base != want {
			return fmt.Errorf("unsupported verbs_qp base layout: %s", path)
		}
	}
	return nil
}

func dcFieldOffset(root *dwarf.StructType, path string, wantSize int64) (uint32, error) {
	if root == nil || root.Size() <= 0 || root.Size() > 1<<20 {
		return 0, fmt.Errorf("missing or invalid structure")
	}
	var offset int64
	var typ dwarf.Type = root
	for _, name := range strings.Split(path, ".") {
		for {
			switch t := typ.(type) {
			case *dwarf.TypedefType:
				typ = t.Type
			case *dwarf.QualType:
				typ = t.Type
			default:
				goto unwrapped
			}
		}
	unwrapped:
		s, ok := typ.(*dwarf.StructType)
		if !ok {
			return 0, fmt.Errorf("field parent is not a structure")
		}
		found, err := dcMember(s, name, 0)
		if err != nil {
			return 0, err
		}
		offset += found.ByteOffset
		typ = found.Type
	}
	if wantSize >= 0 && typ.Size() != wantSize {
		return 0, fmt.Errorf("field size does not match supported ABI")
	}
	if offset < 0 || offset > root.Size()-typ.Size() {
		return 0, fmt.Errorf("field outside structure")
	}
	return uint32(offset), nil
}

// C anonymous structs/unions promote their members into the parent scope.
func dcMember(s *dwarf.StructType, name string, depth int) (*dwarf.StructField, error) {
	if depth > 8 {
		return nil, fmt.Errorf("anonymous field nesting exceeds supported depth")
	}
	var result *dwarf.StructField
	for _, field := range s.Field {
		if field.Type == nil || field.BitSize != 0 || field.ByteOffset < 0 ||
			field.Type.Size() <= 0 || field.ByteOffset > s.Size()-field.Type.Size() {
			continue
		}
		var found *dwarf.StructField
		if field.Name == name {
			copy := *field
			found = &copy
		}
		if field.Name == "" {
			if nested, ok := field.Type.(*dwarf.StructType); ok {
				if member, err := dcMember(nested, name, depth+1); err == nil {
					copy := *member
					copy.ByteOffset += field.ByteOffset
					found = &copy
				}
			}
		}
		if found != nil {
			if result != nil {
				return nil, fmt.Errorf("ambiguous field %s", name)
			}
			result = found
		}
	}
	if result == nil {
		return nil, fmt.Errorf("missing or invalid field %s", name)
	}
	return result, nil
}

// UprobeOptions.Address expects a file offset, not an ELF virtual address.
func dcExecutableOffset(f *elf.File, address, size uint64) (uint64, bool) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && address >= p.Vaddr &&
			address-p.Vaddr < p.Filesz && size <= p.Filesz-(address-p.Vaddr) {
			return p.Off + (address - p.Vaddr), true
		}
	}
	return 0, false
}

func dcBuildID(f *elf.File) ([]byte, error) {
	s := f.Section(".note.gnu.build-id")
	if s == nil || s.Size > 4096 {
		return nil, fmt.Errorf("provider ELF needs a bounded GNU build ID note")
	}
	b, err := s.Data()
	if err != nil {
		return nil, err
	}
	for len(b) >= 12 {
		n, d, kind := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:])
		b = b[12:]
		npad, dpad := (uint64(n)+3)&^3, (uint64(d)+3)&^3
		if npad+dpad > uint64(len(b)) {
			break
		}
		if kind == 3 && n == 4 && bytes.Equal(b[:4], []byte("GNU\x00")) && d >= 16 && d <= 64 {
			return append([]byte(nil), b[npad:npad+uint64(d)]...), nil
		}
		b = b[npad+dpad:]
	}
	return nil, fmt.Errorf("provider ELF has no supported GNU build ID")
}

// dcDWARFField identifies a checked member in a complete ELF structure.
type dcDWARFField struct {
	out        *uint32
	root, path string
	size       int64
}
