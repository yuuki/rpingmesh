# RDMA Package

This package provides functionalities for RDMA (Remote Direct Memory Access) operations using `libibverbs`.

## Directory Structure and Files

The `internal/rdma/` directory is organized as follows:

-   `device.go`: Contains definitions and methods related to RNIC (RDMA Network Interface Card) devices and the `RDMAManager`. This includes device discovery, opening/closing devices, and handling GID/IP addresses.
-   `queue.go`: Manages `UDQueue` (Unreliable Datagram Queue Pair) definitions and operations. This includes queue creation, modification, management (address handles), and destruction. Cgo directives and C helper functions related to queue operations are included.
-   `cq.go`: Handles Completion Queue (CQ) polling and completion event processing. This involves starting/stopping CQ pollers and processing individual work completions (send/receive). Cgo directives and C helper functions for CQ operations reside here.
-   `packet.go`: Defines packet-related data structures (e.g., `ProbePacket`, `GRHHeaderInfo`) and manages packet send/receive operations for UD queues. Cgo directives and C helper functions for packet handling are part of this file.
-   `rdma_test.go`: Contains unit tests for the `rdma` package.

## Overview of Responsibilities

The package is refactored to distribute responsibilities across multiple files for better organization and maintainability:

*   **Device Management (`device.go`):**
    *   Discovery of available RDMA devices.
    *   Opening and closing RNIC devices.
    *   Managing Protection Domains (PD).
    *   Querying device and port attributes.
    *   Handling GID and IP address resolution for RNICs.
*   **Queue Pair Management (`queue.go`):**
    *   Creation and destruction of Unreliable Datagram (UD) Queue Pairs.
    *   Allocation of memory resources (Memory Regions - MR).
    *   Modification of QP states (e.g., RTS, RTR).
    *   Creation of Address Handles (AH) for UD communication.
*   **Completion Handling (`cq.go`):**
    *   Polling Completion Queues for work completion events.
    *   Processing send and receive completions.
    *   Error handling for work completions.
*   **Packet Operations (`packet.go`):**
    *   Defining data structures for probe packets and acknowledgments.
    *   Posting send and receive work requests to QPs.
    *   Constructing and parsing packet headers (e.g., GRH).

## Cgo Usage

Cgo is used extensively throughout the package to interface with the `libibverbs` C library. Each Go file that interacts directly with C functions (e.g., `device.go`, `queue.go`, `cq.go`, `packet.go`) includes the necessary `import "C"` statement and any relevant Cgo directives (like `#cgo LDFLAGS`) and C helper functions or type definitions.
