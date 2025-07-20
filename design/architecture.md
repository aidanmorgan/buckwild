# Architecture Design Document: Frequency Hopping Network System

## Overview

This document outlines the architecture for implementing the frequency hopping network protocol as specified in `protocol.md`. The system consists of three main components:

1. **eBPF Packet Interception Layer** - Low-level packet capture and filtering
2. **Rust Daemon Service** - Core protocol implementation and management
3. **Virtual Network Device** - User-space socket interface

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   App 1     │  │   App 2     │  │   App N     │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Virtual Network Device                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              TUN/TAP Interface                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ Socket API  │  │ Socket API  │  │ Socket API  │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Rust Daemon Service                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Protocol Stack                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ Session Mgmt│  │ Port Hopping│  │ Crypto Engine│   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ Flow Control│  │ Congestion  │  │ Recovery    │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Management Interface                       │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ SNMP Agent  │  │ Syslog      │  │ Audit Log   │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    eBPF Layer                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Packet Interception                        │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ XDP Program │  │ TC Program  │  │ Socket Filter│   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Kernel Network Stack                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   IP Layer  │  │   TCP/UDP   │  │   Device    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## Component Design Notes

### 1. eBPF Packet Interception Layer

#### Design Requirements
- **XDP Program**: Intercept packets at the earliest possible point in the network stack
- **TC Program**: Handle packets that bypass XDP for additional filtering
- **Socket Filter**: Provide application-level packet filtering

#### Implementation Notes
- Use eBPF maps for communication between kernel and user space
- Implement packet classification based on protocol signatures from `protocol.md` Section 3
- Support multiple network interfaces simultaneously
- Use ring buffers for efficient packet transfer to user space
- Implement rate limiting at the eBPF level for DoS protection

#### Critical Design Decisions
- **Packet Identification**: Use the protocol version field (0x01) and packet type field to identify protocol packets
- **Performance**: Minimize packet copying by using zero-copy techniques where possible
- **Security**: Validate packet headers before passing to user space to prevent malformed packet attacks

### 2. Rust Daemon Service

#### Core Architecture Components

##### Session Management
- **Lock-free Session Store**: Use `dashmap` crate for concurrent session storage
- **Session State Machine**: Implement states from `protocol.md` Section 4.2
- **Session Cleanup**: Implement background cleanup for expired sessions

##### Port Hopping Engine
- **Time Synchronization**: Implement NTP client with source validation
- **Port Calculation**: Use HMAC-SHA256 as specified in `protocol.md` Section 5.2
- **Delay Handling**: Implement transmission delay allowance as per Section 5.3

##### Cryptographic Engine
- **Key Derivation**: Use HKDF-SHA256 as specified in `protocol.md` Section 4.4
- **HMAC Calculation**: Implement constant-time HMAC-SHA256-128
- **Random Generation**: Use `getrandom` crate for secure random number generation

##### Flow Control and Congestion Control
- **Window Management**: Implement RFC 6298 RTO calculation
- **Congestion States**: Implement slow start, congestion avoidance, and fast recovery
- **Buffer Management**: Use lock-free ring buffers for packet queues

#### Management Interface Components

##### SNMP Agent
- **MIB Design**: Define custom MIB for protocol statistics
- **Performance Metrics**: Track session count, packet rates, error rates
- **Configuration**: Allow runtime configuration changes

##### Logging and Auditing
- **Syslog Integration**: Use `syslog` crate for system logging
- **Audit Events**: Log security-relevant events for SIEM consumption
- **Structured Logging**: Use JSON format for machine-readable logs

#### Security Components

##### Rate Limiting and DoS Protection
- **Token Bucket Algorithm**: Implement per-source rate limiting
- **Connection Limits**: Enforce maximum connections per source
- **Resource Monitoring**: Track memory and CPU usage

##### Entropy and Randomness
- **Entropy Pool**: Maintain minimum entropy requirements
- **Random Validation**: Verify random number quality
- **Key Rotation**: Implement automatic key rotation

##### Replay Attack Prevention
- **Timestamp Validation**: Use timestamp windows from `protocol.md` Section 2
- **Sequence Tracking**: Maintain recent sequence number cache
- **Nonce Management**: Implement nonce generation and validation

### 3. Virtual Network Device

#### TUN/TAP Interface Design
- **Device Creation**: Create virtual network device on startup
- **Packet Routing**: Route packets between virtual device and protocol stack
- **Socket API**: Provide standard socket interface for applications

#### Implementation Notes
- Use `tun` crate for TUN/TAP device management
- Implement packet encapsulation/decapsulation
- Support multiple concurrent connections
- Provide configuration interface for device parameters

## Data Flow Diagrams

### Packet Reception Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Network   │───▶│   eBPF XDP  │───▶│  Rust Daemon│───▶│  Virtual    │
│   Interface │    │   Program   │    │  Protocol   │    │  Network    │
│             │    │             │    │  Stack      │    │  Device     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                    │                    │
                          ▼                    ▼                    ▼
                   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                   │  Packet     │    │  Session    │    │  Application│
                   │  Validation │    │  Management │    │  Socket     │
                   └─────────────┘    └─────────────┘    └─────────────┘
```

### Packet Transmission Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Application │───▶│  Virtual    │───▶│  Rust Daemon│───▶│   eBPF TC   │
│ Socket      │    │  Network    │    │  Protocol   │    │  Program    │
│             │    │  Device     │    │  Stack      │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                    │                    │
                          ▼                    ▼                    ▼
                   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                   │  Packet     │    │  Port       │    │  Network    │
                   │  Encapsulation│  │  Calculation│    │  Interface  │
                   └─────────────┘    └─────────────┘    └─────────────┘
```

### Session State Management Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Discovery  │───▶│  Connection │───▶│ Established │───▶│  Recovery   │
│  Process    │    │  Setup      │    │  State      │    │  Process    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  PSK        │    │  Time Sync  │    │  Data       │    │  Error      │
│  Selection  │    │  & Port     │    │  Transfer   │    │  Handling   │
│             │    │  Calculation│    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## Critical Implementation Guidelines

### 1. Lock-Free Data Structures
- Use `dashmap` for session storage
- Use `crossbeam` channels for inter-thread communication
- Use `parking_lot` for any necessary locks
- Implement lock-free ring buffers for packet queues

### 2. Cryptographic Implementation
- Use `ring` crate for all cryptographic operations
- Implement constant-time comparisons for HMAC verification
- Use `getrandom` for secure random number generation
- Validate all cryptographic inputs before processing

### 3. Time Synchronization
- Implement NTP client with multiple sources
- Validate NTP responses to prevent spoofing
- Maintain time offset tracking as per `protocol.md` Section 5.1
- Implement drift detection and correction

### 4. Error Handling and Recovery
- Implement all error codes from `protocol.md` Section 2.2
- Use structured error types with context
- Implement exponential backoff for retries
- Log all errors with appropriate severity levels

### 5. Performance Considerations
- Use memory pools for packet buffers
- Implement zero-copy packet processing where possible
- Use async/await for I/O operations
- Profile and optimize critical paths

### 6. Security Hardening
- Implement all replay attack prevention measures
- Use constant-time cryptographic operations
- Validate all packet fields before processing
- Implement rate limiting and DoS protection
- Log security events for SIEM integration

### 7. Monitoring and Observability
- Implement comprehensive metrics collection
- Use structured logging for all events
- Provide SNMP interface for monitoring
- Create audit logs for security events

## Configuration Management

### Daemon Configuration
```toml
[network]
interface = "eth0"
virtual_device = "tun0"
mtu = 1500

[protocol]
hop_interval_ms = 250
time_sync_tolerance_ms = 50
heartbeat_interval_ms = 30000
max_packet_lifetime_ms = 60000

[security]
max_connections_per_source = 100
rate_limit_packets_per_second = 1000
entropy_requirement_bits = 256
replay_window_ms = 30000

[crypto]
key_rotation_interval_hours = 24
hmac_algorithm = "sha256"
key_derivation_algorithm = "hkdf-sha256"

[logging]
level = "info"
syslog_facility = "daemon"
audit_log_path = "/var/log/buckwild-audit.log"

[ntp]
servers = ["pool.ntp.org", "time.nist.gov"]
validation_timeout_ms = 5000
drift_threshold_ms = 100
```


## Deployment Considerations

### System Requirements
- Linux kernel 5.4+ with eBPF support
- Rust 1.70+ for compilation
- Systemd for service management
- Sufficient entropy sources

### Installation
- Install as systemd service
- Load eBPF programs at boot
- Configure virtual network device
- Set up logging and monitoring

### Monitoring
- Monitor system resource usage
- Track protocol statistics via SNMP
- Monitor security events via audit logs
- Alert on critical errors or attacks

