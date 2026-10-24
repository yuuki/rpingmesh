package servicetrace

// The eBPF program is compiled ahead of time with bpf2go (make generate-bpf,
// which needs a clang with the BPF backend) and the resulting objects are
// committed next to this file, so building the agent needs neither clang nor
// kernel headers. Regenerate after changing anything under bpf/.
//
// Only little-endian 64-bit targets are generated: the agent links
// libibverbs through Cgo and is packaged for linux/amd64 and linux/arm64.

//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type qp_event -no-global-types uverbs bpf/uverbs_trace.bpf.c -- -I bpf -I bpf/include -O2 -g -Wall -Werror
