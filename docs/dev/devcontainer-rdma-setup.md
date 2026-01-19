# Devcontainer RDMA Setup Guide

## Overview

R-Pingmesh's devcontainer provides an RDMA (soft-RoCE) development environment. This guide explains setup, verification, and troubleshooting procedures.

## Prerequisites

- Docker or compatible container runtime
- VS Code + Remote-Containers extension (or GitHub Codespaces)
- **For full RDMA functionality:**
  - Linux host (kernel 5.4+ recommended)
  - Host kernel modules: `rdma_rxe`, `ib_core`, `ib_uverbs`

## Automatic Setup

When devcontainer starts, `post-create.sh` automatically executes:

1. Load RDMA kernel modules
2. Create soft-RoCE on the first ethernet interface
3. Validate RDMA environment
4. Create helper scripts (`setup-soft-roce.sh`)

Check initialization output and verify there are no warnings or errors.

## Verification

### Automatic Verification

After container startup, run the validation script:

```bash
.devcontainer/validate-rdma-environment.sh
```

### Manual Verification

#### Check RDMA Tools

```bash
# rdma command
rdma version

# ibv_devinfo command
ibv_devinfo -l
```

#### Check RDMA Devices

```bash
# Check RDMA links
rdma link show
# Expected output:
# link rxe0/1 state ACTIVE physical_state LINK_UP netdev eth0

# Check InfiniBand devices
ls -la /sys/class/infiniband
# Expected output: rxe0 directory

# Device details
ibv_devinfo | head -n 20
# Expected output: hca_id: rxe0 and details
```

#### Run RDMA Tests

```bash
# RDMA device initialization test (requires soft-RoCE)
go test ./internal/rdma -run TestDeviceInit -v

# Test entire RDMA package
go test ./internal/rdma -v
```

#### Verify Build

```bash
# Build RDMA package (cgo)
go build ./internal/rdma

# Build Agent
go build ./cmd/agent
```

## Manual soft-RoCE Setup

If automatic setup fails, use the helper script:

```bash
# Check available network interfaces
ip link show

# Create soft-RoCE on default interface
setup-soft-roce.sh

# Specify specific interface
setup-soft-roce.sh eth0
```

## Troubleshooting

### Quick Diagnosis

If problems occur, first run the diagnostic tool:

```bash
.devcontainer/check-rdma-readiness.sh
```

This tool automatically checks:
- Platform and host environment
- Container capabilities
- Kernel module status
- RDMA device availability
- eBPF support
- Platform-specific guidance

### soft-RoCE Creation Fails

**Symptoms:** `rdma link add` fails or warning messages

**Causes and Solutions:**

1. **Kernel modules unavailable**
   ```bash
   # Check in container
   lsmod | grep rdma_rxe

   # Check and load on host machine
   sudo modprobe rdma_rxe
   sudo modprobe ib_core
   sudo modprobe ib_uverbs

   # Verify
   lsmod | grep rdma
   ```

2. **Insufficient privileges**
   - devcontainer has privileged mode and required capabilities (NET_ADMIN, SYS_ADMIN, CAP_BPF)
   - Verify capabilities with diagnostic tool: `.devcontainer/check-rdma-readiness.sh`
   - If still failing, host-side configuration may be needed

3. **Network interface not found**
   ```bash
   # Check interfaces in container
   ip link show

   # Manually specify interface
   setup-soft-roce.sh <interface-name>
   ```

### RDMA Tests Are Skipped

**Symptoms:** Some tests skip with `go test ./internal/rdma`

**Expected behavior:**
- It's normal for some tests to skip in environments without soft-RoCE
- Tests requiring hardware RDMA NIC also skip

**Things to check:**
- `TestDeviceInit` should PASS if soft-RoCE is available
- Skip reasons are logged in output

### Cgo Build Fails

**Symptoms:** `go build` errors like "C compiler not found" or "library not found"

**Solutions:**

1. **Verify build-essential**
   ```bash
   dpkg -l | grep build-essential
   gcc --version
   ```

2. **Check RDMA libraries**
   ```bash
   ldconfig -p | grep libibverbs
   ldconfig -p | grep librdmacm
   ```

3. **If libraries not found**
   ```bash
   # Rebuild container (Dockerfile changes may not be reflected)
   # VS Code: Command Palette > "Rebuild Container"
   ```

### Devices Not Showing

**Symptoms:** `rdma link show` shows nothing, or `ibv_devinfo` doesn't detect devices

**Solutions:**

1. **Create soft-RoCE manually**
   ```bash
   setup-soft-roce.sh
   ```

2. **Check host kernel support**
   ```bash
   # On host machine
   modinfo rdma_rxe
   # If output appears, kernel supports RXE
   ```

3. **Verify container configuration**
   - Ensure devcontainer.json is up-to-date
   - Required settings: `--privileged`, `CAP_BPF`, debugfs mount
   - VS Code: "Rebuild Container" to apply settings

## Container Limitations

The devcontainer environment has the following constraints:

### What's Supported
- ✅ Using soft-RoCE (if host modules are loaded)
- ✅ Developing and testing RDMA applications
- ✅ Building RDMA code with cgo
- ✅ Testing UD (Unreliable Datagram) send/receive
- ✅ Loading and running eBPF programs
- ✅ RDMA tracing (eBPF ServiceTracer)

### Constraints
- ⚠️ Kernel module loading depends on host environment
- ⚠️ Accessing real RDMA NICs requires device passthrough
- ⚠️ Platform-specific limitations (Docker Desktop vs Colima)

### Platform-Specific Support

**Linux Host:**
- ✅ Full RDMA/eBPF support
- Kernel modules can be loaded

**macOS + Colima:**
- ✅ Full RDMA/eBPF support
- Kernel modules customizable
- Recommended environment

**macOS + Docker Desktop:**
- ⚠️ Limited support
- Kernel module customization restricted
- Migration to Colima recommended ([macOS Colima VM Setup Guide](./macos-colima-vm.md))

## Host Environment Preparation

To use full RDMA features, prepare the host:

### Ubuntu/Debian Host

```bash
# Install RDMA packages
sudo apt-get update
sudo apt-get install -y \
    rdma-core \
    libibverbs-dev \
    librdmacm-dev \
    linux-headers-$(uname -r)

# Load kernel modules
sudo modprobe rdma_rxe
sudo modprobe ib_core
sudo modprobe ib_uverbs

# Verify
lsmod | grep rdma
```

### macOS Host

On macOS, Docker Desktop runs on a Linux VM, so:

1. **Alternative: Use Colima VM**
   - See [macOS Colima VM Setup Guide](./macos-colima-vm.md)
   - Colima runs as a Linux VM and can support RDMA kernel modules

2. **Docker Desktop Limitations**
   - Docker Desktop's Linux VM is difficult to customize
   - RDMA kernel modules likely unavailable
   - Development and builds are possible, but RDMA device testing is limited

## Development Workflow

### 1. Start Container
- In VS Code, select "Reopen in Container"
- Check initialization output (RDMA setup status)

### 2. Verify Environment
```bash
.devcontainer/validate-rdma-environment.sh
```

### 3. Development and Testing
```bash
# Make code changes

# Verify build
go build ./cmd/agent

# Run RDMA tests
go test ./internal/rdma -v

# Run full tests
go test ./... -v
```

### 4. Troubleshooting
- Use validation script to identify issues
- Run `setup-soft-roce.sh` if needed
- Check host environment

## Known Issues

### Issue: soft-RoCE Disappears After Container Restart

**Cause:** RDMA devices are created in the container's network namespace

**Solution:** Automatic setup runs when container starts. If it fails, manually run `setup-soft-roce.sh`

### Issue: ibv_devinfo Shows "No IB devices found"

**Cause:** soft-RoCE device not created

**Solution:**
```bash
# Manual setup
setup-soft-roce.sh

# Verify
rdma link show
ibv_devinfo
```

### Issue: rdma_rxe Not Found on Host

**Cause:** Host kernel doesn't include RXE module

**Solution:**
1. Kernel update, or
2. Use kernel with RXE support, or
3. Use alternative solution like Colima

## References

- [macOS Colima VM Setup](./macos-colima-vm.md) - For macOS developers
- [RDMA Development Guide](../README.md) - RDMA concepts and APIs
- [Soft-RoCE Documentation](https://github.com/SoftRoCE/rxe-dev/wiki) - Detailed soft-RoCE info

## Environment Variables

Environment variables set in devcontainer:

- `RDMA_ENABLED=1` - Indicates RDMA features are enabled
- `GOPATH=/go` - Go workspace
- `GO111MODULE=on` - Go module mode

## Additional Resources

### RDMA Command Reference

```bash
# List devices
rdma dev show

# Link status
rdma link show

# Show resources
rdma resource show

# InfiniBand device info
ibv_devices
ibv_devinfo

# Device details
ibv_devinfo -d rxe0
```

### Debug Commands

```bash
# Check kernel modules
lsmod | grep -E "rdma|ib_"

# Check system logs
dmesg | grep -i rdma
dmesg | grep -i rxe

# Network interfaces
ip link show

# Check libraries
ldconfig -p | grep -E "ibverbs|rdmacm"
```

## Summary

devcontainer automatically sets up the RDMA development environment:

1. ✅ **Automatic setup:** Initialize RDMA environment at startup
2. ✅ **Validation tools:** Use `validate-rdma-environment.sh` to verify environment
3. ✅ **Recovery:** Use `setup-soft-roce.sh` for manual setup
4. ⚠️ **Understand constraints:** Be aware of container and host limitations

If problems occur, run the validation script and follow error messages to resolve.
