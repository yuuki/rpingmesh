package servicetrace

import "errors"

// Errors Open returns when the tracer cannot run on this host. The agent
// treats every one of them as a reason to continue without service tracing.
var (
	// ErrUnsupported: the agent was built for a platform without eBPF.
	ErrUnsupported = errors.New("service tracing: eBPF is supported on Linux only")
	// ErrNoBTF: the kernel exposes no BTF (/sys/kernel/btf/vmlinux), which
	// the tracer needs to relocate its two struct file / struct inode reads.
	ErrNoBTF = errors.New("service tracing: kernel BTF is not available (CONFIG_DEBUG_INFO_BTF)")
	// ErrPermission: loading or attaching was refused. On Linux 5.8+ the
	// agent needs CAP_BPF and CAP_PERFMON (older kernels: CAP_SYS_ADMIN) and
	// the bpf and perf_event_open system calls.
	ErrPermission = errors.New("service tracing: permission denied loading eBPF programs (CAP_BPF and CAP_PERFMON required)")
	// ErrNoUverbs: the ib_uverbs kernel module is not loaded, so there is
	// nothing to trace yet.
	ErrNoUverbs = errors.New("service tracing: ib_uverbs is not loaded (no uverbs entry points to trace)")
)

// Stats are the tracer's counters.
type Stats struct {
	// Events is the number of events delivered to the handler.
	Events uint64
	// DecodeErrors counts records the Go side could not decode.
	DecodeErrors uint64
	// RingBufferDropped counts events the BPF program could not reserve
	// ring-buffer space for; the consumer is too slow for the event rate.
	RingBufferDropped uint64
	// ParseErrors counts uverbs commands the BPF program could not read
	// from user memory.
	ParseErrors uint64
}
