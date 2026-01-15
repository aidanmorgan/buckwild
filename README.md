# Buckwild Frequency Hopping Network Protocol

A high-performance, secure frequency hopping network protocol implementation for Linux. This system provides encrypted, authenticated communication using port hopping techniques inspired by military frequency hopping radio systems like [HAVE QUICK](https://en.wikipedia.org/wiki/Have_Quick).

## Overview

Buckwild implements a complete network protocol stack with:

- **Port Hopping**: Pseudorandom port sequences for enhanced security
- **eBPF Integration**: High-performance packet processing in kernel space
- **Zero-Copy Architecture**: Optimized for minimal latency and maximum throughput
- **Layered Security**: Multiple layers of cryptographic protection
- **Adaptive Networking**: Dynamic optimization based on network conditions

## Architecture

The system follows a clean layered architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                           │
│  • Session Management  • Connection Coordination               │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Network Layer                               │
│  • TUN/TAP Management  • Socket Management  • Routing          │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Engine Layer                                │
│  • Port Hopping  • Time Sync  • Recovery  • Flow Control      │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Protocol Layer                              │
│  • Packet Processing  • Fragmentation  • State Management      │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Security Layer                              │
│  • Cryptography  • Anti-Replay  • Key Management              │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Foundation Layer                            │
│  • Types  • Memory Management  • Error Handling               │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

The codebase is organized into logical, architecture-driven modules:

```
src/
├── common/                     # Shared common library (Rust)
│   └── src/
│       ├── types/              # Shared types across all layers
│       ├── error/              # Centralized error handling
│       ├── memory/             # Memory management and zero-copy
│       ├── security/           # Security layer (crypto, anti-replay)
│       ├── protocol/           # Protocol layer (packets, fragmentation)
│       ├── engines/            # Engine layer (port hopping, time sync, etc.)
│       ├── network/            # Network layer (TUN, sockets, routing)
│       ├── session/            # Session management
│       ├── connection/         # Connection management
│       ├── observability/      # Logging, metrics, tracing
│       ├── integration/        # External integrations (SIEM, SNMP)
│       └── performance/        # Performance optimizations
├── daemon/                     # Main daemon application
├── ebpf/                       # eBPF programs and Rust integration
├── tools/                      # Command-line tools
└── build/                      # Build system and deployment
```

## Quick Start

### Prerequisites

- **Docker & Docker Compose**: For containerized deployment
- **CMake**: For build orchestration
- **Python 3**: For key generation

### Build and Deploy

```bash
# Build the complete system
cd src/build
./build.sh build

# Start the three-node test environment
./build.sh start

# Check system status
./build.sh status

# Set up networking between nodes
./build.sh network
```

### Access the System

```bash
# Connect to Node 1
ssh -p 2221 root@localhost

# Connect to Node 2  
ssh -p 2222 root@localhost

# Connect to Node 3
ssh -p 2223 root@localhost
```

Default password: `buckwild`

## Key Features

### Security
- **ECDH Key Exchange**: Secure key establishment using Curve25519
- **HMAC Authentication**: Message authentication with SHA-256
- **Anti-Replay Protection**: Comprehensive replay attack prevention
- **Secure Memory**: Automatic zeroing of sensitive data

### Performance
- **Lock-Free Data Structures**: Atomic operations for high concurrency
- **Zero-Copy Processing**: Minimal memory allocation and copying
- **eBPF Integration**: Kernel-space packet processing
- **NUMA-Aware Allocation**: Optimized memory patterns

### Networking
- **Port Hopping**: Pseudorandom port sequences
- **Fragmentation**: Intelligent packet fragmentation and reassembly
- **Flow Control**: TCP-compatible congestion control
- **Adaptive Algorithms**: Dynamic network optimization

### Observability
- **Structured Logging**: Comprehensive logging with correlation
- **Metrics Collection**: Performance and operational metrics
- **Distributed Tracing**: End-to-end request tracing
- **SIEM Integration**: Security event reporting

## Development

### Building from Source

```bash
# Build common library
cd src/common/rust
cargo build --release

# Build daemon
cd src/daemon
cargo build --release

# Build eBPF components
cd ebpf
cargo build --release
```

### Running Tests

```bash
# Run unit tests
cargo test

# Run integration tests
cd tests/integration
cargo test

# Run performance benchmarks
cargo bench
```

### Code Organization

The codebase follows strict architectural principles:

- **Layered Architecture**: Clear separation of concerns
- **Rust Best Practices**: Idiomatic Rust patterns and error handling
- **Type Safety**: Extensive use of newtypes for domain modeling
- **Performance First**: Lock-free algorithms and zero-copy techniques
- **Security by Design**: Multiple layers of cryptographic protection

## Documentation

- [Build System](src/build/README.md) - Complete build and deployment guide
- [eBPF Layer](src/ebpf/README.md) - eBPF programs and kernel integration
- [Flow Control](src/common/rust/src/protocol/flow_control_readme.md) - Flow control implementation
- [Architecture Specification](.kiro/specs/rust-code-restructure/design.md) - Detailed system design
- [Requirements](.kiro/specs/rust-code-restructure/requirements.md) - System requirements

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Contributing

This is a personal learning project. While contributions are welcome, please note that this system is designed for educational purposes and should not be used in production environments without thorough security review.

## Disclaimer

This software is provided for educational and research purposes only. It should not be used in production environments or for any critical applications without proper security auditing and testing.