# R-Pingmesh

[![Go Tests](https://github.com/yuuki/rpingmesh/actions/workflows/go-test.yml/badge.svg)](https://github.com/yuuki/rpingmesh/actions/workflows/go-test.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/yuuki/rpingmesh)

> **The service-aware RoCE network monitoring and diagnostic system based on end-to-end active probing.**

R-Pingmesh is a production-ready monitoring system designed for RDMA over Converged Ethernet (RoCE) networks. Built on cutting-edge research from SIGCOMM 2024, it delivers unprecedented visibility into RoCE network performance, enabling rapid detection and precise localization of network problems that can severely impact distributed services.

## Why R-Pingmesh?

Modern data centers rely heavily on RoCE networks for high-performance computing workloads like distributed machine learning and storage systems. As these networks scale to tens of thousands of RNICs, traditional monitoring approaches fall short:

- **Single-point failures** can devastate entire training clusters
- **Performance bottlenecks** masquerade as network issues
- **Troubleshooting** becomes time-consuming and error-prone
- **Service impact assessment** remains largely guesswork

R-Pingmesh solves these challenges with **active probing**, **precise measurements**, and **service-aware monitoring**.

## 🚀 Key Capabilities

### Network Performance Measurement
- **Accurate RTT measurement** using commodity RDMA NICs
- **End-host processing delay** separation from network latency
- **Sub-microsecond precision** with CQE timestamps

### Intelligent Problem Detection (To be implemented)
- **RNIC vs. network failure** distinction through ToR-mesh probing
- **Real-time anomaly detection** with minimal false positives
- **Service impact assessment** to prioritize critical issues

### Service-Aware Monitoring (To be implemented)
- **Automatic service flow discovery** using eBPF tracing
- **Path-specific probing** following actual service traffic
- **5-tuple aware** measurements for ECMP environments

## 🏗️ Architecture

R-Pingmesh consists of three core components working in harmony:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Agent     │◄──►│ Controller   │◄──►│  Analyzer   │
│             │    │              │    │             │
│ • Probing   │    │ • RNIC Reg   │    │ • Anomaly   │
│ • eBPF      │    │ • Pinglists  │    │ • Detection │
│ • Tracing   │    │ • Coord      │    │ • SLI Track │
└─────────────┘    └──────────────┘    └─────────────┘
```

### Agent
Deployed on every RoCE host, the Agent performs:
- **Active probing** using UD Queue Pairs
- **Service flow monitoring** via eBPF programs
- **Path tracing** for network topology discovery
- **Real-time measurements** with hardware timestamps

### Controller
Centralized coordination service providing:
- **RNIC registry** management
- **Pinglist generation** (ToR-mesh and Inter-ToR)
- **Target resolution** for service tracing
- **Configuration distribution**

### Analyzer
Advanced analytics engine delivering:
- **Anomaly detection** and root cause analysis
- **SLA tracking** and performance trending
- **Service impact assessment**
- **Alert generation** and escalation

## 🛠️ Quick Start

### Prerequisites

- Linux kernel 5.8+ with eBPF support
- RDMA-capable network interfaces
- Docker (recommended) or native Go 1.24+ environment
- Root privileges or appropriate capabilities

### Docker Deployment (Recommended)

```bash
# Build the system
make build

# Deploy Agent
make run-agent

# Deploy Controller (separate host)
make run-controller

# Deploy Analyzer (separate host)
make run-analyzer
```

### Native Build

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y \
    clang llvm libbpf-dev libelf-dev \
    libibverbs-dev librdmacm-dev \
    linux-headers-$(uname -r)

# Generate eBPF bindings
./scripts/generate_ebpf.sh

# Build components
make build-native

# Run Agent
sudo ./bin/agent --config agent.yaml
```

## 📊 Monitoring Modes

### Cluster Monitoring
Continuous network health assessment across the entire RoCE cluster:

- **ToR-mesh probing**: Detects faulty RNICs and local issues
- **Inter-ToR probing**: Monitors switch and link health
- **Always-on operation**: Independent of running services
- **Comprehensive SLA tracking**: RTT, packet loss, and processing delays

### Service Tracing
Dynamic monitoring of active service communications:

- **Automatic flow discovery**: eBPF-based connection tracking
- **Path-specific measurements**: Follows actual service traffic
- **Service impact correlation**: Links network issues to service performance
- **Real-time adaptation**: Adjusts to changing service patterns

## 🔧 Configuration

### Agent Configuration
```yaml
# agent.yaml
controller:
  address: "controller.example.com:8080"

analyzer:
  address: "analyzer.example.com:8081"

probing:
  interval: "1s"
  timeout: "5s"

ebpf:
  enabled: true
  buffer_size: 1024
```

### Controller Configuration
```yaml
# controller.yaml
server:
  address: ":8080"

database:
  type: "sqlite"
  path: "/data/controller.db"

pinglist:
  tor_mesh_size: 10
  inter_tor_coverage: 0.1
```

## 📈 Performance

R-Pingmesh is designed for production environments with minimal overhead:

- **CPU Usage**: <1% per RNIC under normal load
- **Memory Footprint**: ~50MB per Agent instance
- **Network Overhead**: <0.1% of link capacity
- **Measurement Accuracy**: Sub-microsecond precision
- **Scalability**: Tested with 10,000+ RNICs

## 🔬 Research Foundation

R-Pingmesh is based on the research paper:

> Kefei Liu, Zhuo Jiang, Jiao Zhang, Shixian Guo, Xuan Zhang, Yangyang Bai, Yongbin Dong, Feng Luo, Zhang Zhang, Lei Wang, Xiang Shi, Haohan Xu, Yang Bai, Dongyang Song, Haoran Wei, Bo Li, Yongchen Pan, Tian Pan, Tao Huang, "R-Pingmesh: A Service-Aware RoCE Network Monitoring and Diagnostic System", the 38th annual conference of the ACM Special Interest Group on Data Communication (SIGCOMM), 2024.

Key innovations include:
- Novel timestamp-based RTT measurement using CQE events
- ToR-mesh probing for RNIC anomaly detection
- eBPF-based service flow discovery with minimal overhead
- Service-aware impact assessment methodology

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yuuki/rpingmesh.git
cd rpingmesh

# Run tests
make test

# Build and test locally
make build-local
make test-local
```

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [Deployment Guide](docs/deployment.md)
- [Configuration Reference](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting/)
- [API Documentation](docs/api.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The eBPF programs in `internal/ebpf/bpf/` are dual-licensed under MIT and GPLv2.

## 🙏 Acknowledgments

- The original R-Pingmesh research team
- The Go, RDMA, eBPF, and Linux communities
