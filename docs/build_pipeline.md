# Build Pipeline Documentation

This document describes the build pipeline for rpingmesh, particularly focusing on handling the Linux-dependent code including eBPF and RDMA components.

## Overview

The build pipeline uses Docker to provide a consistent build environment across different development platforms. This approach helps manage the complex dependencies required for eBPF and RDMA development, which are typically available only on Linux systems.

## Build Process

The build process consists of the following steps:

1. A multi-stage Dockerfile builds the application:
   - First stage: Builds the eBPF code and Go application
   - Second stage: Creates a minimal runtime image

2. The eBPF compilation process:
   - Generates or uses a minimal `vmlinux.h` file needed for eBPF compilation
   - Compiles the eBPF C code into a BPF object file
   - Uses `bpf2go` to generate Go bindings for the eBPF program

3. The Go application is compiled with CGO enabled to support RDMA library bindings

## Requirements

### Build Environment

- Docker installed on the build system
- Internet connectivity (for downloading dependencies)

### Runtime Environment

- Linux host with eBPF support (Linux kernel 4.18+)
- RDMA capable network interfaces for full functionality
- Root or CAP_SYS_ADMIN privileges for eBPF operations

## Build Tools

### Makefile

The `Makefile` provides several targets for common build operations:

- `make build`: Build the Docker image
- `make build-debug`: Build with debug output
- `make run`: Build and run the Docker container with privileged mode
- `make run-with-config`: Run with a specific config file
- `make generate-config`: Generate a default configuration file
- `make clean`: Remove the Docker image
- `make generate-bpf`: Generate eBPF Go bindings locally

### Build Script

The `scripts/build.sh` script provides additional flexibility for building and running:

```
./scripts/build.sh [options]
Options:
  --no-build      Skip building the Docker image
  --run           Run the Docker container after building
  --no-privileged Run container without privileged mode (eBPF won't work)
  --config PATH   Path to config file
  --help          Show help message
```

### eBPF Code Generation

The `scripts/generate_ebpf.sh` script helps with generating eBPF code during development:

- Creates a minimal `vmlinux.h` file if BTF information is not available
- Attempts to generate a complete `vmlinux.h` from the kernel if possible
- Compiles the eBPF C code with appropriate include paths
- Generates Go bindings using `bpf2go`

## Handling Linux Dependencies

### eBPF Dependencies

The build pipeline addresses several eBPF-related challenges:

1. **BTF Information**:
   - Many modern Linux distributions include BTF (BPF Type Format) information in their kernels
   - The build process tries to use this information to generate `vmlinux.h`
   - If not available, a minimal `vmlinux.h` is provided

2. **Architecture-specific headers**:
   - Architecture-specific includes are added to the compiler command line
   - This helps with cross-compilation and different host architectures

3. **Compilation failures**:
   - The build process is designed to continue even if eBPF compilation fails
   - This allows the application to be built and run, although eBPF functionality may be limited

### RDMA Dependencies

For RDMA support, the pipeline:

1. Installs RDMA development libraries in the build container:
   - `libibverbs-dev`
   - `librdmacm-dev`

2. Includes minimal runtime RDMA libraries in the final image:
   - `libibverbs1`
   - `librdmacm1`

## Troubleshooting

### Common Build Issues

1. **Missing kernel headers**:
   - Symptom: eBPF compilation fails with "asm/types.h file not found"
   - Solution: Ensure appropriate kernel headers are installed in the container

2. **BTF information not available**:
   - Symptom: "Error: failed to load BTF from /sys/kernel/btf/vmlinux"
   - Solution: The build will use the minimal `vmlinux.h` instead; this is expected on many systems

3. **Cannot open Docker device**:
   - Symptom: "Cannot connect to the Docker daemon"
   - Solution: Ensure Docker is running and you have appropriate permissions

### Runtime Issues

1. **eBPF loading fails**:
   - Symptom: "Error: failed to load eBPF program"
   - Solution: Ensure container is run with --privileged and CAP_SYS_ADMIN

2. **RDMA operations fail**:
   - Symptom: "Error: failed to open RDMA device"
   - Solution: Ensure RDMA hardware is available and modules are loaded on the host

## Extending the Build Pipeline

To add new eBPF programs:

1. Add the C source file to `pkg/ebpf/bpf/`
2. Update the Dockerfile and build scripts to compile the new program
3. Run `make generate-bpf` to generate Go bindings

For non-Linux development, the Docker-based approach provides the necessary environment for building and testing the application without requiring a Linux development system.
