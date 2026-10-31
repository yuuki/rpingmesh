//go:build linux

package servicetrace

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

const ibCoreBTF = "/sys/kernel/btf/ib_core"

// EnableKernelULP adds the optional ib_core probes before Start is called.
// Failure leaves the uverbs tracer intact; callers should log it and continue.
// Out-of-tree stacks without module BTF must never load this object.
func (t *Tracer) EnableKernelULP() error {
	if t.kernel != nil {
		return nil
	}
	if _, err := os.Stat(ibCoreBTF); err != nil {
		return fmt.Errorf("kernel ULP tracing requires %s: %w", ibCoreBTF, err)
	}
	spec, err := btf.LoadKernelModuleSpec("ib_core")
	if err != nil {
		return fmt.Errorf("load ib_core BTF: %w", err)
	}
	var objs kernelObjects
	if err := loadKernelObjects(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"events": t.objs.Events, "stats": t.objs.Stats},
		Programs:        ebpf.ProgramOptions{ExtraRelocationTargets: []*btf.Spec{spec}},
	}); err != nil {
		return fmt.Errorf("load kernel ULP tracer: %w", err)
	}
	var links []link.Link
	for _, p := range []struct {
		symbol string
		prog   *ebpf.Program
		ret    bool
	}{
		{"ib_modify_qp", objs.KernelModifyExit, true},
		{"ib_modify_qp", objs.KernelModifyEnter, false},
		{"ib_destroy_qp_user", objs.KernelDestroyExit, true},
		{"ib_destroy_qp_user", objs.KernelDestroyEnter, false},
	} {
		var l link.Link
		if p.ret {
			l, err = link.Kretprobe(p.symbol, p.prog, nil)
		} else {
			l, err = link.Kprobe(p.symbol, p.prog, nil)
		}
		if err != nil {
			for _, attached := range links {
				attached.Close()
			}
			objs.Close()
			return fmt.Errorf("attach kernel ULP probe to %s: %w", p.symbol, err)
		}
		links = append(links, l)
	}
	t.kernel = &objs
	t.links = append(t.links, links...)
	return nil
}
