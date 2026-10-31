package servicetrace

// The eBPF program is compiled ahead of time with bpf2go (make generate-bpf,
// which needs a clang with the BPF backend) and the resulting objects are
// committed next to this file, so building the agent needs neither clang nor
// kernel headers. Regenerate after changing anything under bpf/.
//
// Only little-endian 64-bit targets are generated: the agent links
// libibverbs through Cgo and is packaged for linux/amd64 and linux/arm64.
//
// The Makefile's check-bpf target repeats this command line with another
// output directory; keep the two in sync.

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type qp_event -no-global-types uverbs bpf/uverbs_trace.bpf.c -- -I bpf -I bpf/include -O2 -g -Wall -Werror
//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type kernel_event -no-global-types kernel bpf/kernel_trace.bpf.c -- -I bpf -I bpf/include -O2 -g -Wall -Werror
//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type dc_batch -type dc_devx_queue -type dc_identity -type dc_config -no-global-types dc bpf/dc_trace.bpf.c -- -mcpu=v3 -I bpf -I bpf/include -O2 -g -Wall -Werror
