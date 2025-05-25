# eBPF RDMA Tracing

This package provides eBPF-based monitoring of RDMA connections for service flow discovery and tracing.

## Overview

The eBPF RDMA tracing system monitors RDMA Queue Pair (QP) lifecycle events by hooking into kernel functions:

- `ib_create_qp` - QP creation events
- `ib_modify_qp` - QP state transitions (focuses on RTR state)
- `ib_destroy_qp` - QP destruction events

## Key Features

### 1. Improved Error Handling
- Comprehensive input validation
- Safe memory access with bounds checking
- Graceful degradation on failures
- Error statistics tracking

### 2. Performance Optimizations
- Optimized struct layout for better memory alignment
- Efficient BPF_CORE_READ usage
- Reduced memory allocations
- Early filtering to minimize processing overhead

### 3. Enhanced Observability
- Statistics collection for monitoring
- Debug information with port numbers
- Detailed error tracking
- Performance metrics

### 4. Better Code Organization
- Constants for maintainability
- Helper functions for code reuse
- Clear separation of concerns
- Comprehensive documentation

## Architecture

### eBPF Program Structure

```c
// Event type definitions
#define RDMA_EVENT_CREATE 1
#define RDMA_EVENT_MODIFY 2
#define RDMA_EVENT_DESTROY 3

// Optimized event structure
struct rdma_conn_tuple {
    __u64 timestamp;       // Event timestamp
    union ib_gid src_gid;  // Source GID (16 bytes)
    union ib_gid dst_gid;  // Destination GID (16 bytes)
    __u32 src_qpn;         // Source QPN
    __u32 dst_qpn;         // Destination QPN
    __u32 pid;             // Process ID
    __u32 tid;             // Thread ID
    __s32 qp_state;        // QP state
    __u8 event_type;       // Event type
    __u8 port_num;         // Port number
    __u8 reserved[2];      // Explicit padding
    char comm[16];         // Process name
} __attribute__((packed));
```

### Go Interface

```go
// Event types
const (
    RdmaEventCreate  = 1
    RdmaEventModify  = 2
    RdmaEventDestroy = 3
)

// RDMA connection tuple
type RdmaConnTuple struct {
    Timestamp uint64    // Event timestamp (ns)
    SrcGID    [16]byte  // Source GID
    DstGID    [16]byte  // Destination GID
    SrcQPN    uint32    // Source QPN
    DstQPN    uint32    // Destination QPN
    PID       uint32    // Process ID
    TID       uint32    // Thread ID
    QPState   int32     // QP state
    EventType uint8     // Event type
    PortNum   uint8     // Port number
    Reserved  [2]uint8  // Padding
    Comm      [16]byte  // Process name
}
```

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/yuuki/rpingmesh/internal/ebpf"
)

func main() {
    // Create service tracer
    tracer, err := ebpf.NewServiceTracer()
    if err != nil {
        log.Fatal(err)
    }
    defer tracer.Stop()

    // Start tracing
    if err := tracer.Start(); err != nil {
        log.Fatal(err)
    }

    // Process events
    for {
        select {
        case event := <-tracer.Events():
            log.Printf("RDMA Event: %s", event.String())

            // Handle different event types
            switch event.EventType {
            case ebpf.RdmaEventCreate:
                log.Printf("QP Created: QPN=%d, PID=%d, Comm=%s",
                    event.SrcQPN, event.PID, event.CommString())

            case ebpf.RdmaEventModify:
                if event.QPState == 3 { // IB_QPS_RTR
                    log.Printf("Connection Established: %s:%d -> %s:%d",
                        event.SrcGIDString(), event.SrcQPN,
                        event.DstGIDString(), event.DstQPN)
                }

            case ebpf.RdmaEventDestroy:
                log.Printf("QP Destroyed: QPN=%d", event.SrcQPN)
            }

        case <-time.After(10 * time.Second):
            // Get statistics periodically
            stats, err := tracer.GetStatistics()
            if err == nil {
                log.Printf("Statistics: %+v", stats)
            }
        }
    }
}
```

### Service Flow Detection

```go
// Track active RDMA connections
rdmaConnections := make(map[string]ebpf.RdmaConnTuple)

for event := range tracer.Events() {
    switch event.EventType {
    case ebpf.RdmaEventModify:
        if event.QPState == 3 { // RTR state
            key := fmt.Sprintf("%s:%d-%s:%d",
                event.SrcGIDString(), event.SrcQPN,
                event.DstGIDString(), event.DstQPN)
            rdmaConnections[key] = event

            // Trigger service tracing for this 5-tuple
            go startServiceTracing(event)
        }

    case ebpf.RdmaEventDestroy:
        // Remove destroyed connections
        for key, conn := range rdmaConnections {
            if conn.SrcQPN == event.SrcQPN {
                delete(rdmaConnections, key)
                stopServiceTracing(conn)
            }
        }
    }
}
```

## Implementation Details

### Key Improvements

1. **Memory Safety**
   - Bounds checking for all array accesses
   - Validation of pointer dereferencing
   - Safe CO-RE field access

2. **Performance**
   - Early filtering on QP state (RTR only)
   - Optimized struct packing
   - Efficient helper functions

3. **Reliability**
   - Comprehensive error handling
   - Graceful failure modes
   - Statistical monitoring

4. **Maintainability**
   - Well-defined constants
   - Modular helper functions
   - Clear documentation

### Error Handling Strategy

The improved eBPF program implements a multi-layered error handling approach:

1. **Input Validation**: Check all parameters before use
2. **Bounds Checking**: Validate array indices and memory access
3. **Graceful Degradation**: Continue operation even with partial failures
4. **Statistics Tracking**: Monitor error rates for debugging

### Performance Considerations

- **Early Exit**: Filter events at the earliest possible point
- **Memory Layout**: Optimized struct packing to reduce cache misses
- **Function Inlining**: Use `__always_inline` for hot paths
- **Minimal Allocations**: Reuse buffers and minimize dynamic allocation

## Requirements

- Linux kernel 5.4+ with eBPF support
- CAP_BPF or root privileges
- RDMA kernel modules loaded
- clang/LLVM for eBPF compilation

## Compilation

The eBPF program is automatically compiled using `go:generate`:

```bash
# Regenerate eBPF objects
go generate ./internal/ebpf/

# Build the Go package
go build ./internal/ebpf/
```

## Testing

```bash
# Run unit tests
go test ./internal/ebpf/

# Run benchmarks
go test -bench=. ./internal/ebpf/

# Test with race detection
go test -race ./internal/ebpf/
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure CAP_BPF capability or root privileges
   - Check `/proc/sys/kernel/unprivileged_bpf_disabled`

2. **Missing RDMA Support**
   - Load RDMA kernel modules: `modprobe rdma_core`
   - Verify devices: `ls /sys/class/infiniband/`

3. **eBPF Verification Errors**
   - Check kernel version compatibility
   - Verify CO-RE support: `cat /proc/version`

### Debug Information

Enable debug logging to troubleshoot issues:

```go
import "github.com/rs/zerolog/log"

// Enable debug logging
log.Logger = log.Level(zerolog.DebugLevel)
```

## Limitations

- Only monitors QP state transitions to RTR
- Requires kernel-level RDMA driver support
- Performance impact scales with QP creation rate
- Memory overhead for event buffering

## Future Enhancements

- [ ] Configurable GID index selection
- [ ] Extended QP state monitoring
- [ ] Custom event filtering
- [ ] Real-time statistics dashboard
- [ ] Integration with monitoring systems
