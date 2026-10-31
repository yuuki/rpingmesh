//go:build linux

package servicetrace

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func TestKernelTracerOpenClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
	for _, path := range []string{vmlinuxBTF, ibCoreBTF} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("BTF is not available: %v", err)
		}
	}
	tr, err := Open()
	if errors.Is(err, ErrNoUverbs) {
		t.Skipf("ib_uverbs is not loaded: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if tr.kernel != nil {
		t.Fatal("default tracer loaded the kernel extension")
	}
	if err := tr.EnableKernelULP(); err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier: %+v", verifier)
		}
		t.Fatalf("EnableKernelULP: %+v", err)
	}
	if err := tr.EnableKernelULP(); err != nil {
		t.Fatal(err)
	}
	if len(tr.links) != 9 {
		t.Fatalf("attached %d links, want 5 uverbs + 4 kernel links", len(tr.links))
	}
	// Both objects must share the actual map, not just a map specification.
	if err := tr.kernel.Stats.Put(statParseErrors, uint64(7)); err != nil {
		t.Fatal(err)
	}
	if tr.Stats().ParseErrors != 7 {
		t.Fatal("kernel and uverbs counters are not shared")
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}
