# rpingmesh

RPingMesh is a monitoring tool for RDMA networks that uses eBPF to trace RDMA connections and perform network measurements.

## Requirements

For building the application:

- Docker (for containerized build environment)
- Make (optional, for simplified commands)

For running the application:

- Linux kernel with eBPF support (4.18+ recommended)
- RDMA capable network interfaces (for full functionality)
- Root or CAP_SYS_ADMIN privileges (for eBPF)

## Quick Start with Docker

The easiest way to build and run the application is using Docker:

```bash
# Build the Docker image
make build

# Run the application
make run
```

Or use the build script directly:

```bash
# Build and run in one command
./scripts/build.sh --run
```

## Build Pipeline

This project uses a Docker-based build pipeline to ensure consistent builds across different environments. The pipeline:

1. Builds the eBPF C code using clang
2. Generates Go bindings using bpf2go
3. Compiles the Go code
4. Creates a runtime container with minimal dependencies

For detailed information about the build pipeline, see [Build Pipeline Documentation](docs/build_pipeline.md).

### Using Make

```bash
# Build the Docker image
make build

# Build with debug output
make build-debug

# Run the application
make run

# Run with a specific config file
make run-with-config

# Generate a default config file
make generate-config

# Remove the Docker image
make clean
```

### Using Build Script

The `scripts/build.sh` script provides a flexible way to build and run the application:

```bash
# Build the Docker image
./scripts/build.sh

# Build and run the application
./scripts/build.sh --run

# Run with a specific config file
./scripts/build.sh --run --config /path/to/config.yaml

# Skip building the image (if already built)
./scripts/build.sh --no-build --run

# Show all options
./scripts/build.sh --help
```

## Docker Desktop Support

When running on Docker Desktop for Mac or Windows, additional setup is required for eBPF functionality:

1. Mount the debugfs filesystem:
   ```bash
   # Create a Docker volume for debugfs
   docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs

   # Add this volume when running the container
   docker run -it --rm \
     --privileged \
     --cap-add SYS_ADMIN \
     --cap-add NET_ADMIN \
     --cap-add IPC_LOCK \
     --network host \
     -v debugfs:/sys/kernel/debug \
     rpingmesh-agent:0.1.0
   ```

2. If BTF information is not available, the build will use a minimal `vmlinux.h` file included in the project.

3. For better debugging and development, consider switching to WSL 2 backend on Windows, which provides a more complete Linux environment with BTF support.

## Development Setup

For development on a Linux system with all required dependencies:

1. Install the necessary dependencies:
   ```bash
   # Debian/Ubuntu
   apt-get update && apt-get install -y \
     clang llvm libbpf-dev libelf-dev bpftool \
     linux-headers-$(uname -r) \
     pkg-config \
     libibverbs-dev librdmacm-dev
   ```

2. Generate eBPF code and Go bindings:
   ```bash
   ./scripts/generate_ebpf.sh
   ```

3. Build the application:
   ```bash
   go build -o ./bin/agent ./cmd/agent
   ```

4. Run the application (requires root or proper capabilities):
   ```bash
   sudo ./bin/agent
   ```

## Troubleshooting

If you encounter issues during build or runtime, please refer to the [Build Pipeline Documentation](docs/build_pipeline.md#troubleshooting) for common problems and solutions.

### Common eBPF Issues

- **Cannot access debugfs**: On some systems, debugfs may not be mounted. Mount it using:
  ```bash
  mount -t debugfs debugfs /sys/kernel/debug
  ```

- **Missing BTF information**: Older kernels or custom kernels may not have BTF enabled. The build will use a minimal vmlinux.h in this case, but some eBPF features may be limited.

- **No kernel headers**: The Dockerfile uses LinuxKit kernel headers for Docker Desktop environments. For native Linux, make sure the appropriate kernel headers are installed.

## Architecture

RPingMesh consists of several components:

- **eBPF Programs**: Kernel-space programs that trace RDMA connection operations
- **Agent**: User-space daemon that processes eBPF events and manages probing
- **Controller**: Coordinates agents across the network (future component)
- **Analyzer**: Processes gathered metrics for anomaly detection (future component)
- **Documentation**: Provides user guides and technical details

## License

See [LICENSE](LICENSE) file for details.
