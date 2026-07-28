// Package ebpf provides eBPF functionality for monitoring RDMA connections.
package ebpf

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 rdmaTracing bpf/rdma_tracing.c -- -I./bpf/include -I/usr/include -I/usr/include/linux/bpf -I/usr/include/x86_64-linux-gnu

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
)

//go:embed bpf/*
var bpfFS embed.FS

//go:embed btf/*
var btfFS embed.FS

// Event type constants matching eBPF definitions
const (
	RdmaEventCreate  = 1
	RdmaEventModify  = 2
	RdmaEventDestroy = 3
)

// Statistics keys matching eBPF definitions
const (
	StatCreateCount     = 0
	StatModifyCount     = 1
	StatDestroyCount    = 2
	StatErrorCount      = 3
	StatGidReadSuccess  = 4
	StatGidReadFailure  = 5
	StatPortDataFailure = 6
	StatGidTableFailure = 7
)

// RdmaConnTuple represents RDMA connection 5-tuple information
// Struct layout optimized to match eBPF struct with proper alignment
// Must maintain exact byte-for-byte compatibility with C struct
type RdmaConnTuple struct {
	Timestamp uint64   // Timestamp when the event occurred (nanoseconds) - offset 0, 8 bytes
	SrcGID    [16]byte // Source Global Identifier (GID) - offset 8, 16 bytes
	DstGID    [16]byte // Destination Global Identifier (GID) - offset 24, 16 bytes
	SrcQPN    uint32   // Source Queue Pair Number - offset 40, 4 bytes
	DstQPN    uint32   // Destination Queue Pair Number - offset 44, 4 bytes
	PID       uint32   // Process ID - offset 48, 4 bytes
	TID       uint32   // Thread ID - offset 52, 4 bytes
	QPState   int32    // QP state (valid only for modify_qp) - offset 56, 4 bytes
	EventType uint8    // Event type (1: create, 2: modify, 3: destroy) - offset 60, 1 byte
	PortNum   uint8    // Port number for debugging - offset 61, 1 byte
	Reserved  [2]uint8 // Explicit padding for alignment - offset 62, 2 bytes
	Comm      [16]byte // Process name - offset 64, 16 bytes
}

// Verify struct size at compile time
// Go doesn't have static_assert, but we can check at runtime
const expectedStructSize = 80

// ValidateStructSize verifies RdmaConnTuple size matches eBPF definition
// This should be called before using eBPF tracing functionality
func ValidateStructSize() error {
	actualSize := int(unsafe.Sizeof(RdmaConnTuple{}))
	if actualSize != expectedStructSize {
		return fmt.Errorf("RdmaConnTuple size mismatch: expected %d bytes, got %d bytes", expectedStructSize, actualSize)
	}
	return nil
}

// EventTypeString returns the string representation of the event type
func (t *RdmaConnTuple) EventTypeString() string {
	switch t.EventType {
	case RdmaEventCreate:
		return "CREATE"
	case RdmaEventModify:
		return "MODIFY"
	case RdmaEventDestroy:
		return "DESTROY"
	default:
		return "UNKNOWN"
	}
}

// SrcGIDString returns the string representation of SrcGID
func (t *RdmaConnTuple) SrcGIDString() string {
	return hex.EncodeToString(t.SrcGID[:])
}

// DstGIDString returns the string representation of DstGID
func (t *RdmaConnTuple) DstGIDString() string {
	return hex.EncodeToString(t.DstGID[:])
}

// CommString returns the process name as a trimmed string
func (t *RdmaConnTuple) CommString() string {
	return string(bytes.TrimRight(t.Comm[:], "\x00"))
}

// IsValidEvent returns true if the event type is known
func (t *RdmaConnTuple) IsValidEvent() bool {
	return t.EventType >= RdmaEventCreate && t.EventType <= RdmaEventDestroy
}

// String returns a human-readable representation of RdmaConnTuple
func (t *RdmaConnTuple) String() string {
	return fmt.Sprintf(
		"Event: %s, Time: %s, Src QPN: %d, Dst QPN: %d, Src GID: %s, Dst GID: %s, QP State: %d, PID: %d, Port: %d, Comm: %s",
		t.EventTypeString(),
		time.Unix(0, int64(t.Timestamp)),
		t.SrcQPN,
		t.DstQPN,
		t.SrcGIDString(),
		t.DstGIDString(),
		t.QPState,
		t.PID,
		t.PortNum,
		t.CommString(),
	)
}

// ServiceTracer manages the eBPF program for tracing RDMA connections
type ServiceTracer struct {
	objs    rdmaTracingObjects
	kprobes []link.Link
	reader  *ringbuf.Reader
	eventCh chan RdmaConnTuple
	stopCh  chan struct{}
}

// Note: rdmaTracingObjects is defined in the auto-generated file rdmatracing_x86_bpfel.go

// checkPrivileges verifies if the current process has sufficient privileges
func checkPrivileges() error {
	// Check if running as root
	if os.Getuid() == 0 {
		return nil
	}

	// For non-root users, we can proceed but warn about potential issues
	log.Warn().Msg("Not running as root. You may need CAP_BPF and CAP_SYS_ADMIN capabilities.")
	return nil
}

// setMemlockLimit attempts to set MEMLOCK limit manually
func setMemlockLimit() error {
	// Try to set MEMLOCK to unlimited
	var rlim syscall.Rlimit
	rlim.Cur = ^uint64(0) // RLIM_INFINITY
	rlim.Max = ^uint64(0) // RLIM_INFINITY

	// RLIMIT_MEMLOCK constant value for Linux
	const RLIMIT_MEMLOCK = 8

	if err := syscall.Setrlimit(RLIMIT_MEMLOCK, &rlim); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_MEMLOCK) failed: %w", err)
	}

	return nil
}

// isPermissionError checks if the error is related to permission issues
func isPermissionError(err error) bool {
	errStr := err.Error()
	permissionErrorPatterns := []string{
		"operation not permitted",
		"permission denied",
		"EPERM",
		"EACCES",
		"MEMLOCK",
		"insufficient privileges",
	}

	for _, pattern := range permissionErrorPatterns {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// NewServiceTracer creates a new ServiceTracer instance
func NewServiceTracer() (*ServiceTracer, error) {
	if err := ValidateStructSize(); err != nil {
		return nil, err
	}

	if err := checkPrivileges(); err != nil {
		return nil, fmt.Errorf("insufficient privileges: %w", err)
	}

	// Remove kernel memory lock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		// Try to increase MEMLOCK limit manually if RemoveMemlock fails
		if err := setMemlockLimit(); err != nil {
			return nil, fmt.Errorf("failed to set memory lock limit: %w (original error: %v)", err, err)
		}
		log.Warn().Msg("rlimit.RemoveMemlock() failed, but manual MEMLOCK setting succeeded")
	}

	vmlinux, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel spec: %w", err)
	}

	moduleSpecs := make(map[string]*btf.Spec)
	for _, file := range []string{"ib_core.full.btf", "ib_uverbs.full.btf"} {
		// Read embedded BTF file
		data, err := btfFS.ReadFile("btf/" + file)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded BTF file %s: %w", file, err)
		}

		// Create reader from embedded data
		reader := bytes.NewReader(data)
		specs, err := btf.LoadSplitSpecFromReader(reader, vmlinux)
		if err != nil {
			return nil, fmt.Errorf("failed to load split spec from embedded file %s: %w", file, err)
		}
		// Use base name without extension for the key, but preserve the original logic
		baseName := strings.TrimSuffix(strings.TrimSuffix(file, ".btf"), ".full")
		moduleSpecs[baseName] = specs
	}

	// Options for compiling eBPF program
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelModuleTypes: moduleSpecs,
		},
	}

	// Compile and load eBPF program
	var objs rdmaTracingObjects
	if err := loadRdmaTracingObjects(&objs, &opts); err != nil {
		// Enhanced error handling for RDMA environment issues
		if isRdmaRelatedError(err) {
			return nil, fmt.Errorf("RDMA environment not available (missing drivers or kernel support): %w", err)
		}
		if isPermissionError(err) {
			return nil, fmt.Errorf("insufficient permissions to load eBPF program (try running as root or with CAP_BPF/CAP_SYS_ADMIN capabilities): %w", err)
		}
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Initialize channels
	eventCh := make(chan RdmaConnTuple, 100)
	stopCh := make(chan struct{})

	return &ServiceTracer{
		objs:    objs,
		eventCh: eventCh,
		stopCh:  stopCh,
	}, nil
}

// isRdmaRelatedError checks if the error is related to RDMA functionality not being available
func isRdmaRelatedError(err error) bool {
	errStr := err.Error()
	// Check for common RDMA-related error patterns
	rdmaErrorPatterns := []string{
		"bad CO-RE relocation",
		"invalid func",
		"ib_modify_qp_with_udata",
		"ib_destroy_qp_user",
		"kprobe",
		"symbol not found",
		"function not found",
	}

	for _, pattern := range rdmaErrorPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

// Start begins tracing
func (t *ServiceTracer) Start() error {
	var err error
	var kprobes []link.Link
	var hookAttempts int
	var successfulHooks int

	// Check which functions are available for hooking
	available := checkAvailableFunctions()

	log.Info().
		Int("available_functions", len(available)).
		Msg("Starting eBPF tracing with available RDMA functions")

	// Attach to ib_modify_qp (this should always be available)
	if available["ib_modify_qp_with_udata"] {
		hookAttempts++
		kp, err := link.Kprobe("ib_modify_qp_with_udata", t.objs.TraceModifyQp, nil)
		if err != nil {
			log.Error().Err(err).Msg("Critical: Failed to attach kprobe to ib_modify_qp_with_udata")
			return fmt.Errorf("attaching kprobe to ib_modify_qp_with_udata: %w", err)
		}
		kprobes = append(kprobes, kp)
		successfulHooks++
		log.Info().Msg("Successfully attached to ib_modify_qp_with_udata")
	} else {
		log.Warn().Msg("ib_modify_qp_with_udata not available - RDMA monitoring may be limited")
	}

	// Try to attach to ib_destroy_qp_user
	if available["ib_destroy_qp_user"] {
		hookAttempts++
		kp, err := link.Kprobe("ib_destroy_qp_user", t.objs.TraceDestroyQpUser, nil)
		if err != nil {
			log.Warn().Err(err).Str("function", "ib_destroy_qp_user").Msg("Failed to attach kprobe (continuing without destroy monitoring)")
		} else {
			kprobes = append(kprobes, kp)
			successfulHooks++
			log.Info().Msg("Successfully attached to ib_destroy_qp_user")
		}
	} else {
		log.Debug().Msg("ib_destroy_qp_user not available in this kernel")
	}

	// Validate that we have at least some hooks
	if len(kprobes) == 0 {
		return fmt.Errorf("no RDMA functions could be hooked - RDMA monitoring not available")
	}

	// Warn if we couldn't hook to any functions despite them being available
	if hookAttempts > 0 && successfulHooks == 0 {
		return fmt.Errorf("all %d hook attempts failed despite functions being available - check permissions and kernel compatibility", hookAttempts)
	}

	t.kprobes = kprobes

	log.Info().
		Int("active_hooks", len(kprobes)).
		Int("attempted_hooks", hookAttempts).
		Int("successful_hooks", successfulHooks).
		Msg("eBPF kprobe attachment completed")

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(t.objs.RdmaEvents)
	if err != nil {
		return fmt.Errorf("creating ringbuf reader: %w", err)
	}
	t.reader = reader

	// Process events in background
	go t.processEvents()

	return nil
}

// processEvents reads events from the ring buffer and sends them to the channel
func (t *ServiceTracer) processEvents() {
	defer t.reader.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-t.stopCh
		cancel()
	}()

	for {
		record, err := t.reader.Read()
		if err != nil {
			if ctx.Err() == context.Canceled {
				// Normal termination
				return
			}
			log.Error().Err(err).Msg("Error reading from ringbuf")
			continue
		}

		// Convert binary data to RdmaConnTuple struct
		var event RdmaConnTuple
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("Error parsing ringbuf event")
			continue
		}

		// Validate event before sending
		if !event.IsValidEvent() {
			log.Warn().Uint8("event_type", event.EventType).Msg("Received invalid event type")
			continue
		}

		// Send event to channel
		select {
		case t.eventCh <- event:
			// Event sent
		case <-ctx.Done():
			return
		}
	}
}

// Events returns the channel of detected RDMA connection events
func (t *ServiceTracer) Events() <-chan RdmaConnTuple {
	return t.eventCh
}

// GetStatistics retrieves the current statistics from the eBPF program
func (t *ServiceTracer) GetStatistics() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	if t.objs.RdmaStats == nil {
		return stats, fmt.Errorf("statistics map not available")
	}

	// Read all statistics from the eBPF map
	statKeys := []uint32{
		StatCreateCount,
		StatModifyCount,
		StatDestroyCount,
		StatErrorCount,
		StatGidReadSuccess,
		StatGidReadFailure,
		StatPortDataFailure,
		StatGidTableFailure,
	}

	statNames := []string{
		"create_count",
		"modify_count",
		"destroy_count",
		"error_count",
		"gid_read_success",
		"gid_read_failure",
		"port_data_failure",
		"gid_table_failure",
	}

	for i, key := range statKeys {
		var value uint64
		if err := t.objs.RdmaStats.Lookup(key, &value); err != nil {
			log.Warn().Err(err).Uint32("key", key).Str("stat", statNames[i]).Msg("Failed to read statistic from eBPF map")
			stats[statNames[i]] = 0
		} else {
			stats[statNames[i]] = value
		}
	}

	return stats, nil
}

// Stop terminates tracing
func (t *ServiceTracer) Stop() error {
	// Signal stop to the event processor
	close(t.stopCh)

	// Detach all kprobes
	for _, kp := range t.kprobes {
		if err := kp.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing kprobe")
		}
	}
	t.kprobes = nil

	// Close ring buffer reader
	if t.reader != nil {
		if err := t.reader.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing ringbuf reader")
		}
		t.reader = nil
	}

	// Close eBPF objects
	if err := t.objs.Close(); err != nil {
		return fmt.Errorf("closing eBPF objects: %w", err)
	}

	return nil
}

// Note: The actual loadRdmaTracingObjects is generated by bpf2go
// and is defined in rdmatracing_x86_bpfel.go

// DiagnoseEnvironment provides diagnostic information about the eBPF environment
func DiagnoseEnvironment() {
	log.Info().Msg("=== eBPF Environment Diagnostics ===")

	// Check running user
	if os.Getuid() == 0 {
		log.Info().Msg("✓ Running as root (UID: 0)")
	} else {
		log.Warn().Int("uid", os.Getuid()).Msg("⚠ Not running as root")
	}

	// Check current MEMLOCK limit
	var rlim syscall.Rlimit
	const RLIMIT_MEMLOCK = 8
	if err := syscall.Getrlimit(RLIMIT_MEMLOCK, &rlim); err != nil {
		log.Error().Err(err).Msg("✗ Failed to get MEMLOCK limit")
	} else {
		if rlim.Cur == ^uint64(0) {
			log.Info().Msg("✓ MEMLOCK limit: unlimited")
		} else {
			log.Warn().
				Uint64("current", rlim.Cur).
				Uint64("max", rlim.Max).
				Msg("⚠ MEMLOCK limit (bytes)")
		}
	}

	// Check if eBPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		log.Warn().Err(err).Msg("⚠ BPF filesystem not found at /sys/fs/bpf")
	} else {
		log.Info().Msg("✓ BPF filesystem available")
	}

	// Check available RDMA functions
	available := checkAvailableFunctions()
	if len(available) > 0 {
		log.Info().
			Int("count", len(available)).
			Msg("✓ RDMA functions available for monitoring")
		for fn, avail := range available {
			if avail {
				log.Info().Str("function", fn).Msg("  ✓ Available")
			} else {
				log.Warn().Str("function", fn).Msg("  ✗ Not available")
			}
		}
	} else {
		log.Warn().Msg("⚠ No RDMA functions found - RDMA monitoring not available")
	}

	// Check kernel version (basic check)
	if data, err := os.ReadFile("/proc/version"); err != nil {
		log.Warn().Err(err).Msg("⚠ Failed to read kernel version")
	} else {
		log.Info().Str("version", strings.TrimSpace(string(data))).Msg("ℹ Kernel version")
	}

	log.Info().Msg("=== End Diagnostics ===")
}

// checkAvailableFunctions checks which RDMA functions are available for hooking
func checkAvailableFunctions() map[string]bool {
	available := make(map[string]bool)

	// List of functions to check
	functions := []string{
		"ib_modify_qp_with_udata",
		"ib_destroy_qp_user",
	}

	// Read /proc/kallsyms to check function availability
	if data, err := os.ReadFile("/proc/kallsyms"); err == nil {
		kallsyms := string(data)
		for _, fn := range functions {
			// Check if function appears in kallsyms (more robust check)
			if strings.Contains(kallsyms, " "+fn+" ") || strings.Contains(kallsyms, " "+fn+"\t") {
				available[fn] = true
				log.Debug().Str("function", fn).Msg("RDMA function available for hooking")
			} else {
				log.Debug().Str("function", fn).Msg("RDMA function not found in kallsyms")
			}
		}
	} else {
		log.Warn().Err(err).Msg("Failed to read /proc/kallsyms, assuming all functions available")
		// Fallback: assume all functions are available
		for _, fn := range functions {
			available[fn] = true
		}
	}

	return available
}

// PrintBpfTraceLog reads and displays eBPF trace log (bpf_printk output)
// This helps debug GID read failures and other eBPF issues
func PrintBpfTraceLog() {
	log.Info().Msg("=== eBPF Trace Log (for debugging GID read failures) ===")
	log.Info().Msg("Run the following command to see eBPF debug output:")
	log.Info().Msg("  sudo cat /sys/kernel/debug/tracing/trace_pipe | grep 'trace_modify_qp\\|read_dest_qp_info\\|read_source_gid_safe'")
	log.Info().Msg("Or to see all eBPF trace output:")
	log.Info().Msg("  sudo cat /sys/kernel/debug/tracing/trace_pipe")
	log.Info().Msg("=== End eBPF Trace Log Instructions ===")
}

// ValidateStructAlignment checks if the received event data makes sense
func ValidateStructAlignment(event *RdmaConnTuple) error {
	// Check struct size
	if unsafe.Sizeof(*event) != expectedStructSize {
		return fmt.Errorf("struct size mismatch: expected %d, got %d", expectedStructSize, unsafe.Sizeof(*event))
	}

	// Validate QPN ranges (QPNs should be reasonable values)
	const maxQPN = 0x1000000 // 24-bit max
	if event.SrcQPN > maxQPN {
		return fmt.Errorf("source QPN %d (0x%x) exceeds maximum expected value", event.SrcQPN, event.SrcQPN)
	}
	if event.DstQPN > maxQPN {
		return fmt.Errorf("destination QPN %d (0x%x) exceeds maximum expected value", event.DstQPN, event.DstQPN)
	}

	// Validate event type
	if event.EventType < RdmaEventCreate || event.EventType > RdmaEventDestroy {
		return fmt.Errorf("invalid event type %d", event.EventType)
	}

	// Validate timestamp (should be recent)
	now := uint64(time.Now().UnixNano())
	if event.Timestamp > now || event.Timestamp < now-uint64(time.Hour) {
		return fmt.Errorf("timestamp %d seems invalid (now: %d)", event.Timestamp, now)
	}

	return nil
}

// DiagnoseStructAlignment provides detailed analysis of struct alignment issues
func DiagnoseStructAlignment(event *RdmaConnTuple) {
	log.Info().Msg("=== Struct Alignment Diagnosis ===")
	log.Info().
		Int("expected_size", expectedStructSize).
		Int("actual_size", int(unsafe.Sizeof(*event))).
		Msg("Struct size comparison")

	// Print field offsets for debugging
	log.Info().Str("field_offsets", fmt.Sprintf(
		"Timestamp: %d, SrcGID: %d, DstGID: %d, SrcQPN: %d, DstQPN: %d, PID: %d, TID: %d, QPState: %d, EventType: %d, PortNum: %d, Reserved: %d, Comm: %d",
		unsafe.Offsetof(event.Timestamp),
		unsafe.Offsetof(event.SrcGID),
		unsafe.Offsetof(event.DstGID),
		unsafe.Offsetof(event.SrcQPN),
		unsafe.Offsetof(event.DstQPN),
		unsafe.Offsetof(event.PID),
		unsafe.Offsetof(event.TID),
		unsafe.Offsetof(event.QPState),
		unsafe.Offsetof(event.EventType),
		unsafe.Offsetof(event.PortNum),
		unsafe.Offsetof(event.Reserved),
		unsafe.Offsetof(event.Comm),
	)).Msg("Field offsets")

	// Validate alignment
	if err := ValidateStructAlignment(event); err != nil {
		log.Error().Err(err).Msg("Struct alignment validation failed")
	} else {
		log.Info().Msg("Struct alignment validation passed")
	}
	log.Info().Msg("=== End Struct Alignment Diagnosis ===")
}

// DiagnoseGidReadFailures provides specific guidance for troubleshooting GID read failures
func DiagnoseGidReadFailures(stats map[string]uint64) {
	gidReadSuccess := stats["gid_read_success"]
	gidReadFailure := stats["gid_read_failure"]
	errorCount := stats["error_count"]
	portDataFailure := stats["port_data_failure"]
	gidTableFailure := stats["gid_table_failure"]

	log.Info().Msg("=== GID Read Failure Diagnosis ===")
	log.Info().
		Uint64("gid_read_success", gidReadSuccess).
		Uint64("gid_read_failure", gidReadFailure).
		Uint64("port_data_failure", portDataFailure).
		Uint64("gid_table_failure", gidTableFailure).
		Uint64("total_errors", errorCount).
		Msg("Current eBPF statistics")

	if gidReadFailure > 0 || errorCount > 0 || portDataFailure > 0 || gidTableFailure > 0 {
		log.Warn().Msg("Detected GID read failures. Possible causes:")

		if portDataFailure > 0 {
			log.Warn().Msg("- Port data access failures: RDMA device structure mismatch")
		}
		if gidTableFailure > 0 {
			log.Warn().Msg("- GID table access failures: Kernel structure alignment issues")
		}
		if gidReadFailure > 0 {
			log.Warn().Msg("- GID read failures: Memory access or pointer issues")
		}

		log.Warn().Msg("1. Kernel version incompatibility with RDMA structure definitions")
		log.Warn().Msg("2. RDMA driver not loaded or incompatible")
		log.Warn().Msg("3. BTF (BPF Type Format) information mismatch")
		log.Warn().Msg("4. Insufficient privileges for kernel memory access")
		log.Warn().Msg("5. RDMA device not properly initialized")

		log.Info().Msg("Troubleshooting steps:")
		log.Info().Msg("1. Check kernel version: uname -r")
		log.Info().Msg("2. Check RDMA modules: lsmod | grep ib_")
		log.Info().Msg("3. Check RDMA devices: ibv_devices")
		log.Info().Msg("4. Check eBPF trace log (see instructions above)")
		log.Info().Msg("5. Verify running with root privileges")
		log.Info().Msg("6. Check dmesg for RDMA/InfiniBand errors")
	} else if gidReadSuccess > 0 {
		log.Info().Msg("GID reads are working correctly")
	} else {
		log.Warn().Msg("No GID read attempts detected - RDMA traffic may not be present")
	}
	log.Info().Msg("=== End GID Read Failure Diagnosis ===")
}
