// Package servicetrace implements the agent side of R-Pingmesh service
// tracing (paper section 4.2.2): an eBPF tracer that observes the lifecycle
// of the application RDMA queue pairs on the host, and a table that folds its
// events into the set of live connections, each with the 5-tuple the service
// flow uses (local RNIC, remote GID and QPN, flow label).
//
// The tracer attaches kprobes to the uverbs character device entry points
// (ib_uverbs_ioctl, ib_uverbs_write, ib_uverbs_close) and parses the
// command buffers libibverbs passes to the kernel. Those follow the uverbs
// user-space ABI, so the tracer works with any RDMA stack, including
// out-of-tree ones that ship their kernel modules without BTF; only two
// fields of the core kernel's struct file and struct inode are relocated
// with CO-RE against the vmlinux BTF. See bpf/uverbs_trace.bpf.c.
//
// The eBPF program is loaded on Linux only; on other platforms Open returns
// ErrUnsupported. Everything else in the package (event decoding, the
// connection table, the kernel's flow-label arithmetic, the sysfs lookups) is
// pure Go and unit tested everywhere.
package servicetrace
