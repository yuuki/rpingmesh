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
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/*
var bpfFS embed.FS

// Event type constants matching eBPF definitions
const (
	RdmaEventCreate  = 1
	RdmaEventModify  = 2
	RdmaEventDestroy = 3
)

// Statistics keys matching eBPF definitions
const (
	StatCreateCount    = 0
	StatModifyCount    = 1
	StatDestroyCount   = 2
	StatErrorCount     = 3
	StatGidReadSuccess = 4
	StatGidReadFailure = 5
)

// RdmaConnTuple represents RDMA connection 5-tuple information
// Struct layout optimized to match eBPF struct with proper alignment
type RdmaConnTuple struct {
	Timestamp uint64   // Timestamp when the event occurred (nanoseconds)
	SrcGID    [16]byte // Source Global Identifier (GID) - 16 bytes
	DstGID    [16]byte // Destination Global Identifier (GID) - 16 bytes
	SrcQPN    uint32   // Source Queue Pair Number
	DstQPN    uint32   // Destination Queue Pair Number
	PID       uint32   // Process ID
	TID       uint32   // Thread ID
	QPState   int32    // QP state (valid only for modify_qp)
	EventType uint8    // Event type (1: create, 2: modify, 3: destroy)
	PortNum   uint8    // Port number for debugging
	Reserved  [2]uint8 // Explicit padding for alignment
	Comm      [16]byte // Process name
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

// NewServiceTracer creates a new ServiceTracer instance
func NewServiceTracer() (*ServiceTracer, error) {
	// Remove kernel memory lock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// Options for compiling eBPF program
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{},
	}

	// Compile and load eBPF program
	var objs rdmaTracingObjects
	if err := loadRdmaTracingObjects(&objs, &opts); err != nil {
		// Enhanced error handling for RDMA environment issues
		if isRdmaRelatedError(err) {
			return nil, fmt.Errorf("RDMA environment not available (missing drivers or kernel support): %w", err)
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
		"ib_modify_qp",
		"ib_destroy_qp",
		"ib_create_qp",
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

	// Attach kprobes
	kp, err := link.Kprobe("ib_modify_qp", t.objs.TraceModifyQp, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe to ib_modify_qp: %w", err)
	}
	kprobes = append(kprobes, kp)

	kp, err = link.Kprobe("ib_destroy_qp", t.objs.TraceDestroyQp, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe to ib_destroy_qp: %w", err)
	}
	kprobes = append(kprobes, kp)

	kp, err = link.Kprobe("ib_create_qp", t.objs.TraceCreateQp, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe to ib_create_qp: %w", err)
	}
	kprobes = append(kprobes, kp)

	t.kprobes = kprobes

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
			log.Printf("error reading from ringbuf: %v", err)
			continue
		}

		// Convert binary data to RdmaConnTuple struct
		var event RdmaConnTuple
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing ringbuf event: %v", err)
			continue
		}

		// Validate event before sending
		if !event.IsValidEvent() {
			log.Printf("received invalid event type: %d", event.EventType)
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
// Note: Statistics map will be available after eBPF regeneration
func (t *ServiceTracer) GetStatistics() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	// TODO: Implement statistics after eBPF regeneration
	// For now, return empty statistics
	stats["create_count"] = 0
	stats["modify_count"] = 0
	stats["destroy_count"] = 0
	stats["error_count"] = 0
	stats["gid_read_success"] = 0
	stats["gid_read_failure"] = 0

	return stats, nil
}

// Stop terminates tracing
func (t *ServiceTracer) Stop() error {
	// Signal stop to the event processor
	close(t.stopCh)

	// Detach all kprobes
	for _, kp := range t.kprobes {
		if err := kp.Close(); err != nil {
			log.Printf("error closing kprobe: %v", err)
		}
	}
	t.kprobes = nil

	// Close ring buffer reader
	if t.reader != nil {
		if err := t.reader.Close(); err != nil {
			log.Printf("error closing ringbuf reader: %v", err)
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
