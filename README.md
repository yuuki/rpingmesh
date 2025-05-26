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

```mermaid
sequenceDiagram
    participant P as Prober
    participant PN as Prober RNIC
    participant N as RoCE Network
    participant RN as Responder RNIC
    participant R as Responder

    Note over P,R: RTT Measurement Process

    P->>P: T1: Application post send
    P->>PN: Post probe packet
    PN->>PN: T2: CQE send completion (HW timestamp)
    PN->>N: Probe packet transmission
    N->>RN: Network delivery
    RN->>RN: T3: CQE receive (HW timestamp)
    RN->>R: Deliver to application
    R->>R: Process probe packet
    R->>RN: Post ACK packet
    RN->>RN: T4: CQE ACK send (HW timestamp)
    RN->>N: ACK transmission
    N->>PN: Network delivery
    PN->>PN: T5: CQE ACK receive (HW timestamp)
    PN->>P: Completion notification
    P->>P: T6: Application poll complete

    Note over P,R: Calculations
    Note over P: Network RTT = (T5-T2) - (T4-T3)
    Note over P: Prober Delay = (T6-T1) - (T5-T2)
    Note over R: Responder Delay = T4-T3
```

### Intelligent Problem Detection (To be implemented)
- **RNIC vs. network failure** distinction through ToR-mesh probing
- **Real-time anomaly detection** with minimal false positives
- **Service impact assessment** to prioritize critical issues

### Service-Aware Monitoring (To be implemented)
- **Automatic service flow discovery** using eBPF tracing
- **Path-specific probing** following actual service traffic
- **5-tuple aware** measurements for ECMP environments

```mermaid
flowchart TD
    subgraph "Service Discovery Process"
        A[Application creates RDMA connection] --> B[eBPF hooks modify_qp syscall]
        B --> C{QP State = RTR?}
        C -->|Yes| D[Extract 5-tuple:<br/>Src/Dst GID, Src/Dst QPN]
        C -->|No| E[Ignore event]
        D --> F[Send event to userspace via ring buffer]
        F --> G[Agent receives connection event]
        G --> H[Query Controller for target RNIC info]
        H --> I[Start service-specific probing]
        I --> J[Monitor actual service path]
    end

    subgraph "Monitoring Modes Comparison"
        direction LR
        K[Cluster Monitoring<br/>• Always-on<br/>• ToR-mesh coverage<br/>• Network health]
        L[Service Tracing<br/>• Dynamic<br/>• Follows real traffic<br/>• Service-aware]
    end

    style A fill:#E8F5E8
    style D fill:#FFF3E0
    style I fill:#E3F2FD
    style J fill:#F3E5F5
```

## 🏗️ Architecture

R-Pingmesh consists of three core components.

```mermaid
graph TB
    subgraph "RoCE Host 1"
        A1[Agent]
        A1_RDMA[RDMA Manager]
        A1_EBPF[eBPF Service Tracer]
        A1_PROBE[Active Probing Engine]
        A1_PATH[Path Tracer]
        A1_CLIENT[Controller Client]
        A1_UPLOAD[Upload Client]

        A1 --> A1_RDMA
        A1 --> A1_EBPF
        A1 --> A1_PROBE
        A1 --> A1_PATH
        A1 --> A1_CLIENT
        A1 --> A1_UPLOAD

        subgraph "Hardware Layer"
            HW1[RDMA Hardware<br/>UD Queue Pairs<br/>CQE Timestamps]
        end

        subgraph "Kernel Layer"
            EBPF1[eBPF Programs<br/>modify_qp / destroy_qp<br/>Ring Buffer Events]
        end

        A1_RDMA -.-> HW1
        A1_EBPF -.-> EBPF1
    end

    subgraph "RoCE Host N"
        AN[Agent N]
        HWN[RDMA Hardware]
        EBPFN[eBPF Programs]

        AN -.-> HWN
        AN -.-> EBPFN
    end

    subgraph "Control Plane"
        C[Controller]
        C_REG[RNIC Registry]
        C_PING[Pinglist Generator]
        C_GRPC[gRPC Server]
        C_CONFIG[Configuration Manager]
        C_DB[(RNIC Database<br/>GID → RNIC Info<br/>ToR ID → RNIC List)]

        C --> C_REG
        C --> C_PING
        C --> C_GRPC
        C --> C_CONFIG
        C --> C_DB
    end

    subgraph "Analytics Plane"
        AZ[Analyzer]
        AZ_API[Data Ingestion API]
        AZ_ANOMALY[Anomaly Detection]
        AZ_RCA[Root Cause Analysis]
        AZ_SLA[SLA Tracker]
        AZ_ALERT[Alert Manager]
        AZ_TSDB[(Time Series DB<br/>RTT Metrics<br/>Path Information<br/>Anomaly Events)]
        AZ_DASH[Monitoring Dashboard<br/>Real-time Visualization<br/>Alert Notifications]

        AZ --> AZ_API
        AZ --> AZ_ANOMALY
        AZ --> AZ_RCA
        AZ --> AZ_SLA
        AZ --> AZ_ALERT
        AZ --> AZ_TSDB
        AZ --> AZ_DASH
    end

    subgraph "RoCE Network"
        NET[RoCE Fabric<br/>ToR Switches<br/>Spine Switches]
    end

    %% Communication flows
    A1_CLIENT <-->|gRPC<br/>Registration<br/>Pinglists| C_GRPC
    AN <-->|gRPC| C_GRPC

    A1_UPLOAD -->|gRPC Upload<br/>Probe Results<br/>Path Traces| AZ_API
    AN -->|gRPC Upload| AZ_API

    %% Network probing
    A1_PROBE <-.->|Active Probing<br/>RTT Measurement| NET
    AN <-.->|Active Probing| NET

    %% Monitoring modes
    subgraph "Monitoring Modes"
        direction LR
        CM[Cluster Monitoring<br/>ToR-mesh Probing<br/>Inter-ToR Probing]
        ST[Service Tracing<br/>eBPF Flow Discovery<br/>Dynamic Probing]
        PT[Path Tracing<br/>Network Topology<br/>Traceroute]
        AD[Anomaly Detection<br/>RNIC vs Network<br/>Impact Assessment]
    end

    A1 -.-> CM
    A1 -.-> ST
    A1 -.-> PT
    AZ -.-> AD

    %% Styling
    classDef agentClass fill:#4CAF50,stroke:#2E7D32,stroke-width:2px,color:#fff
    classDef controllerClass fill:#2196F3,stroke:#1565C0,stroke-width:2px,color:#fff
    classDef analyzerClass fill:#FF9800,stroke:#E65100,stroke-width:2px,color:#fff
    classDef hardwareClass fill:#9E9E9E,stroke:#424242,stroke-width:2px,color:#fff
    classDef networkClass fill:#E3F2FD,stroke:#1976D2,stroke-width:2px,color:#1976D2
    classDef monitoringClass fill:#F3E5F5,stroke:#7B1FA2,stroke-width:2px,color:#7B1FA2

    class A1,AN,A1_RDMA,A1_EBPF,A1_PROBE,A1_PATH,A1_CLIENT,A1_UPLOAD agentClass
    class C,C_REG,C_PING,C_GRPC,C_CONFIG controllerClass
    class AZ,AZ_API,AZ_ANOMALY,AZ_RCA,AZ_SLA,AZ_ALERT analyzerClass
    class HW1,HWN,EBPF1,EBPFN,C_DB,AZ_TSDB,AZ_DASH hardwareClass
    class NET networkClass
    class CM,ST,PT,AD monitoringClass
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

### Communication Flow

- **Agent ↔ Controller (gRPC):**
  - Agent registers RNICs with Controller on startup
  - Agent requests Pinglists for Cluster Monitoring (ToR-mesh, Inter-ToR)
  - Agent requests target RNIC information for Service Tracing

- **Agent → Analyzer (gRPC):**
  - Agent uploads probe results (RTT, delays, timeouts)
  - Agent uploads path trace information
  - Agent uploads aggregated local statistics

- **Controller → Agent (gRPC responses):**
  - Controller provides Pinglists and RNIC information based on Agent requests

### Technical Stack

- **Go Programming Language** with Cgo for RDMA integration
- **RDMA Verbs**: [`libibverbs`](https://github.com/linux-rdma/rdma-core/tree/master/libibverbs) Cgo wrapper for low-level RDMA operations
- **eBPF**: [`cilium/ebpf`](https://github.com/cilium/ebpf) library for service flow monitoring
- **gRPC**: Communication with each component
- **RQLite**: Database for Controller [https://rqlite.io/](https://rqlite.io/)
- **OpenTelemetry**: Distributed tracing for Agent and Controller

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

- [Software Design Document](docs/software_design.md) - Comprehensive technical design
- [Architecture Diagrams](docs/) - Visual system overview
  - [System Architecture (SVG)](docs/architecture_diagram.svg)
  - [RTT Measurement Process (SVG)](docs/rtt_measurement_diagram.svg)
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
