# Architecture Design Document: Frequency Hopping Network System

## Overview

This document outlines the architecture for implementing the frequency hopping network protocol as specified in `protocol.md`. The system consists of three main components:

1. **eBPF Packet Interception Layer** - Low-level packet capture and filtering
2. **Rust Daemon Service** - Core protocol implementation and management
3. **Virtual Network Device** - User-space socket interface

## Key Design Principle: Transparent Operation Over Stateless Protocol

**Applications remain completely unaware of the Buckwild protocol**. The system provides a standard network interface that applications interact with using normal socket operations (connect(), send(), recv(), etc.). The Buckwild daemon transparently translates between standard TCP/IP and the **stateless, datagram-based** Buckwild protocol.

### Critical Protocol Design: IP Datagrams Only
- **Stateless Transport**: Buckwild protocol operates as **IP datagrams only** - no connection state in the network
- **Daemon State Management**: All connection state, buffering, and reliability handled by Buckwild daemon
- **UDP-like Transport**: Each Buckwild packet is an independent IP datagram with port hopping
- **Transparent Reliability**: Daemon provides TCP reliability semantics over unreliable datagram transport

### Application Experience
- **Standard Sockets**: Applications use normal socket() API calls
- **No Code Changes**: Existing applications work without modification
- **Standard Network Interface**: Virtual TUN device appears as normal network interface
- **Transparent Security**: Port hopping and encryption happen invisibly
- **Transparent Reliability**: TCP reliability maintained despite underlying datagram transport

### Example Usage
```bash
# Application connects normally
curl http://10.0.1.1:80/api/data

# Behind the scenes:
# 1. TCP connection to 10.0.1.1:80 via TUN device
# 2. Daemon captures TCP packets from TUN device
# 3. Daemon maintains TCP connection state and buffers
# 4. Daemon translates to Buckwild IP datagrams with port hopping
# 5. Remote daemon receives Buckwild datagrams
# 6. Remote daemon reconstructs TCP stream and delivers to web server
# 7. All TCP reliability (retransmissions, ordering, flow control) handled by daemons
```

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
- **Secure Memory Management**: All cryptographic keys and sensitive data must be securely zeroed when no longer used

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

##### Secure Memory Management
- **Secure Zeroing**: All sensitive data must be securely zeroed when no longer used
- **Memory Protection**: Use `memsec` crate for secure memory allocation
- **Automatic Cleanup**: Implement Drop traits for all sensitive data structures
- **Memory Locking**: Prevent sensitive data from being swapped to disk
- **Zeroing Verification**: Implement runtime verification of zeroing operations

##### Entropy and Randomness
- **Entropy Pool**: Maintain minimum entropy requirements
- **Random Validation**: Verify random number quality
- **Key Rotation**: Implement automatic key rotation
- **Secure Cleanup**: All entropy pools and random state must be securely zeroed after use

##### Replay Attack Prevention
- **Timestamp Validation**: Use timestamp windows from `protocol.md` Section 2
- **Sequence Tracking**: Maintain recent sequence number cache
- **Nonce Management**: Implement nonce generation and validation

### 3. Virtual Network Device (Protocol Translation Layer)

#### TUN Interface Design for Transparent TCP/IP Operation
- **Standard TCP/IP Interface**: Virtual device presents as standard network interface to applications
- **Transparent Protocol Translation**: Daemon converts between standard TCP/IP and Buckwild protocol
- **Standard Socket API**: Applications use normal socket() calls without protocol awareness
- **Network Stack Integration**: Virtual device integrates with OS network stack for seamless operation

#### TCP/IP to Buckwild Datagram Translation
- **TCP Stream to Datagrams**: TCP byte streams segmented into independent Buckwild IP datagrams
- **Stateless Packet Format**: Each Buckwild datagram is self-contained with session context
- **Port Hopping Per Datagram**: Each datagram sent to calculated port based on current time window
- **No Network Connection State**: Network infrastructure sees only independent UDP-like datagrams
- **Daemon-Only State**: All connection tracking, sequencing, and buffering handled exclusively in daemon
- **Reliability Over Datagrams**: TCP reliability semantics (retransmission, ordering) implemented by daemon over unreliable datagram transport

#### Daemon State Management (Critical for Transparency)
- **TCP Connection Table**: Maps TCP 4-tuples (src_ip, src_port, dst_ip, dst_port) to Buckwild sessions
- **Session State Storage**: All Buckwild session state maintained only in daemon memory - never in network
- **TCP Stream Buffers**: Daemon buffers TCP data for reliable delivery over unreliable datagrams
- **Retransmission Queues**: Daemon handles all packet retransmissions using internal timers
- **Sequence Management**: TCP sequence numbers translated to Buckwild sequence numbers in daemon
- **Flow Control Simulation**: Daemon simulates TCP window management over datagram transport
- **Connection State Machines**: Full TCP state machine maintained in daemon for each connection

#### Implementation Notes
- Use `tun` crate for TUN device management (Layer 3 operation)
- Implement bidirectional packet translation (TCP streams ↔ Buckwild datagrams)
- Support multiple concurrent TCP connections over independent Buckwild datagram flows
- Provide standard network interface configuration (IP address, routing)
- Handle IP packet parsing and reconstruction using `pnet` or `etherparse` crates
- Maintain connection mapping table with O(1) lookup performance
- Implement full TCP state machine for each connection in daemon memory
- Handle TCP options and features (window scaling, selective ACK, etc.) transparently
- Implement reliable delivery algorithms (retransmission timers, congestion control) over datagrams
- Buffer management for TCP stream reconstruction from out-of-order datagrams
- Port calculation and time synchronization for per-datagram port hopping

## Data Flow Diagrams

### Component Interaction Overview
```
┌─────────────────────────────────────────────────────────────────────────┐
│                          User Applications                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │    HTTP     │  │     SSH     │  │   Database  │  │   Custom    │   │
│  │   Client    │  │   Client    │  │   Client    │  │   Apps      │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │ Standard Socket API
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     OS Network Stack (Unmodified)                      │
│                         TCP/IP Stack                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                │ TCP Packets
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Virtual TUN Device                              │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│ │   Packet    │  │ Connection  │  │   Stream    │  │   Buffer    │    │
│ │  Capture    │  │   Mapping   │  │  Assembly   │  │ Management  │    │
│ └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                │ Intercepted TCP
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Buckwild Daemon                               │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│ │  Protocol   │  │   Session   │  │   Crypto    │  │  Recovery   │    │
│ │ Translator  │  │  Manager    │  │   Engine    │  │Coordinator  │    │
│ └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│ │ Port Hopper │  │Time Sync    │  │   Discovery │  │   Flow      │    │
│ │             │  │             │  │   Engine    │  │  Control    │    │
│ └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                │ Buckwild Datagrams
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           eBPF Layer                                   │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│ │     XDP     │  │     TC      │  │   Socket    │  │  Packet     │    │
│ │   Program   │  │  Program    │  │   Filter    │  │ Validator   │    │
│ └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                │ Filtered Packets
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Physical Network Interface                        │
│                    (Independent IP Datagrams)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Packet Reception Flow (Buckwild → TCP/IP)
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Network   │───▶│   eBPF XDP  │───▶│  Rust Daemon│───▶│  Virtual    │
│   Interface │    │   Program   │    │  Protocol   │    │  TUN Device │
│             │    │             │    │  Stack      │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                    │                    │
                          ▼                    ▼                    ▼
                   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                   │  Buckwild   │    │  Session    │    │  TCP/IP     │
                   │  Packet     │    │  to TCP     │    │  Packet     │
                   │  Validation │    │  Translation│    │  Injection  │
                   └─────────────┘    └─────────────┘    └─────────────┘
                                                                   │
                                                                   ▼
                                                         ┌─────────────┐
                                                         │ Application │
                                                         │ Standard    │
                                                         │ Socket      │
                                                         └─────────────┘
```

### Packet Transmission Flow (TCP/IP → Buckwild)
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Application │───▶│  Virtual    │───▶│  Rust Daemon│───▶│   eBPF TC   │
│ Standard    │    │  TUN Device │    │  Protocol   │    │  Program    │
│ Socket      │    │             │    │  Stack      │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                    │                    │
                          ▼                    ▼                    ▼
                   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                   │  TCP/IP     │    │  TCP to     │    │  Buckwild   │
                   │  Packet     │    │  Buckwild   │    │  Packet     │
                   │  Capture    │    │  Translation│    │  Transmission│
                   └─────────────┘    └─────────────┘    └─────────────┘
                                             │                    │
                                             ▼                    ▼
                                   ┌─────────────┐    ┌─────────────┐
                                   │  Port       │    │  Network    │
                                   │  Calculation│    │  Interface  │
                                   └─────────────┘    └─────────────┘
```

### Time Synchronization and Port Hopping Flow
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Time Synchronization                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │     NTP     │  │    Local    │  │   Drift     │  │   Offset    │   │
│  │   Client    │  │    Clock    │  │ Detection   │  │ Calculation │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │ Synchronized Time
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Port Calculation Engine                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Time      │  │   Daily     │  │  Session    │  │ Connection  │   │
│  │  Window     │  │    Key      │  │     ID      │  │   Offset    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                        │                                              │
│                        ▼ HMAC-SHA256                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Base Port   │  │  Port Range │  │  Final Port │  │   Delay     │   │
│  │Calculation  │  │  Mapping    │  │    Value    │  │  Allowance  │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │ Current Port
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Port Hopping                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   250ms     │  │  Previous   │  │   Current   │  │   Next      │   │
│  │ Intervals   │  │    Port     │  │    Port     │  │   Port      │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                        │                    │                    │     │
│                        ▼                    ▼                    ▼     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Socket      │  │ Bind/Listen │  │ Transmit    │  │  Socket     │   │
│  │ Cleanup     │  │   Setup     │  │   Packets   │  │ Preparation │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Session Discovery and Establishment Flow
```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Initiator  │         │   Network   │         │  Responder  │
│             │         │             │         │             │
└─────────────┘         └─────────────┘         └─────────────┘
        │                       │                       │
        │                       │                       │
┌───────┴────────┐              │              ┌────────┴───────┐
│ Generate       │              │              │ Listen on      │
│ Discovery      │              │              │ Discovery      │
│ Commitment     │              │              │ Port 1025      │
└───────┬────────┘              │              └────────┬───────┘
        │                       │                       │
        │ DISCOVERY packet      │                       │
        │ ─────────────────────▶│──────────────────────▶│
        │ (PSK count, challenge,│                       │
        │  Pedersen commitment) │                       │
        │                       │                       │
        │                       │              ┌────────┴───────┐
        │                       │              │ Validate       │
        │                       │              │ Commitment     │
        │                       │              │ Generate       │
        │                       │              │ Response       │
        │                       │              └────────┬───────┘
        │                       │                       │
        │    DISCOVERY_RESPONSE │                       │
        │ ◀─────────────────────│◀──────────────────────│
        │ (PSK range, response  │                       │
        │  nonce, commitment)   │                       │
        │                       │                       │
┌───────┴────────┐              │                       │
│ Verify         │              │                       │
│ Response       │              │                       │
│ Select PSK     │              │                       │
│ Generate       │              │                       │
│ Session ID     │              │                       │
└───────┬────────┘              │                       │
        │                       │                       │
        │ DISCOVERY_CONFIRM     │                       │
        │ ─────────────────────▶│──────────────────────▶│
        │ (PSK index, session   │                       │
        │  ID, confirmation)    │                       │
        │                       │                       │
        │                       │              ┌────────┴───────┐
        │                       │              │ Verify         │
        │                       │              │ Selection      │
        │                       │              │ Store Session  │
        │                       │              │ Keys           │
        │                       │              └────────┬───────┘
        │                       │                       │
┌───────┴────────┐              │              ┌────────┴───────┐
│ Session        │              │              │ Session        │
│ Established    │              │              │ Established    │
│ Begin Port     │              │              │ Begin Port     │
│ Hopping        │              │              │ Hopping        │
└────────────────┘              │              └────────────────┘
```

### Protocol Translation Flow (Key Design Feature)
```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Application Layer (Unchanged)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │
│  │     HTTP    │  │     SSH     │  │   Any TCP   │                    │
│  │   Client    │  │   Client    │  │ Application │                    │
│  └─────────────┘  └─────────────┘  └─────────────┘                    │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ (Standard socket() calls)
┌─────────────────────────────────────────────────────────────────────────┐
│                      OS Network Stack                                  │
│                    (Standard TCP/IP streams)                           │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ (TCP packets via TUN device)
┌─────────────────────────────────────────────────────────────────────────┐
│                    Buckwild Daemon (State Management)                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │
│  │ TCP Stream  │  │ Connection  │  │ Datagram    │                    │
│  │ Buffers     │  │ State Mgmt  │  │ Generator   │                    │
│  └─────────────┘  └─────────────┘  └─────────────┘                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │
│  │Retransmit   │  │ Port Hop    │  │ Timer       │                    │
│  │ Queues      │  │ Calculator  │  │ Management  │                    │
│  └─────────────┘  └─────────────┘  └─────────────┘                    │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ (Independent IP datagrams with port hopping)
┌─────────────────────────────────────────────────────────────────────────┐
│                     Physical Network                                   │
│              (Stateless IP datagrams, no connection state)             │
└─────────────────────────────────────────────────────────────────────────┘
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

### Error Recovery and Failure Handling Flow
```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Normal Operation                              │
│                              ESTABLISHED                               │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                     ┌──────────┴──────────┐
                     │    Error/Failure    │
                     │     Detected        │
                     └──────────┬──────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Error Classification                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │    Time     │  │  Sequence   │  │    Auth     │  │   Network   │   │
│  │    Sync     │  │   Error     │  │   Failure   │  │   Error     │   │
│  │   Failure   │  │             │  │             │  │             │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Recovery Strategy Selection                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   RESYNC    │  │   REPAIR    │  │    REKEY    │  │ EMERGENCY   │   │
│  │ Time Sync   │  │  Sequence   │  │  Session    │  │  Full       │   │
│  │  Recovery   │  │   Repair    │  │   Rekey     │  │ Recovery    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                     ┌──────────┴──────────┐
                     │   Recovery Attempt  │
                     │      (Max 5)        │
                     └──────────┬──────────┘
                                │
                    ┌───────────┴────────────┐
                    │                        │
                    ▼                        ▼
         ┌─────────────────┐        ┌─────────────────┐
         │    Success      │        │     Failure     │
         │   ESTABLISHED   │        │     ERROR       │
         └─────────────────┘        └─────────────────┘
                    │                        │
                    ▼                        ▼
         ┌─────────────────┐        ┌─────────────────┐
         │ Resume Normal   │        │  Session        │
         │   Operation     │        │  Termination    │
         └─────────────────┘        └─────────────────┘
```

### Memory Management and Secure Cleanup Flow
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Sensitive Data Lifecycle                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Secure    │  │    Data     │  │  Operation  │  │   Secure    │   │
│  │ Allocation  │  │    Usage    │  │ Completion  │  │   Cleanup   │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Secure Memory Operations                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Memory    │  │   Memory    │  │ Constant    │  │ Zeroing     │   │
│  │   Locking   │  │Protection   │  │    Time     │  │Verification │   │
│  │  (mlock)    │  │(No Swap)    │  │ Operations  │  │            │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     Automatic Cleanup Triggers                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Session   │  │     Key     │  │    Error    │  │   Process   │   │
│  │Termination  │  │  Rotation   │  │ Conditions  │  │Termination  │   │
│  │             │  │             │  │             │  │             │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Drop Trait Implementation                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ SecureKey   │  │ SessionData │  │ CryptoState │  │   Buffer    │   │
│  │    Drop     │  │    Drop     │  │    Drop     │  │    Drop     │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
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
- **Secure Memory Zeroing**: Implement secure zeroing for all cryptographic keys, nonces, and sensitive data
- **Zeroing on Drop**: Use Rust's Drop trait to ensure automatic secure cleanup of sensitive data
- **Memory Protection**: Use `memsec` crate for secure memory allocation and zeroing

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

### 6. Secure Memory Management
- **Secure Zeroing**: Implement secure zeroing for all sensitive data using constant-time operations
- **Memory Protection**: Use `memsec` crate for secure memory allocation that prevents swapping
- **Automatic Cleanup**: Implement Drop traits for all sensitive data structures
- **Compiler Barriers**: Use `std::ptr::write_volatile` and `std::sync::atomic::compiler_fence` to prevent optimization
- **Memory Locking**: Use `mlock()` to prevent sensitive data from being swapped to disk
- **Zeroing Verification**: Implement runtime verification that zeroing operations completed successfully
- **Static Analysis**: Use tools like `cargo-audit` and `cargo-geiger` to verify secure memory practices

### 7. Security Hardening
- Implement all replay attack prevention measures
- Use constant-time cryptographic operations
- Validate all packet fields before processing
- Implement rate limiting and DoS protection
- Log security events for SIEM integration
- **Secure Memory Zeroing**: All secret data must be securely zeroed when no longer used

### 8. Monitoring and Observability
- Implement comprehensive metrics collection
- Use structured logging for all events
- Provide SNMP interface for monitoring
- Create audit logs for security events

### 8. Secure Memory Management and Zeroing

#### Critical Security Requirements
- **All Secret Data Must Be Securely Zeroed**: Cryptographic keys, nonces, passwords, session tokens, and any sensitive data must be securely zeroed when no longer needed
- **Zeroing on Drop**: Implement Rust Drop traits for all sensitive data structures to ensure automatic cleanup
- **Memory Protection**: Use secure memory allocation that prevents swapping to disk and enables secure zeroing
- **No Compiler Optimizations**: Ensure zeroing operations cannot be optimized away by the compiler

##### Memory Allocation Requirements
- **Use `memsec` crate**: For secure memory allocation that prevents swapping
- **Lock memory pages**: Prevent memory from being swapped to disk
- **Secure heap allocation**: Use secure allocators for sensitive data
- **Stack protection**: Ensure stack-allocated sensitive data is properly zeroed

##### Zeroing Implementation Requirements
- **Constant-time zeroing**: Use constant-time operations to prevent timing attacks
- **Compiler barriers**: Prevent compiler optimizations from removing zeroing code
- **Memory barriers**: Ensure zeroing operations complete before memory is freed
- **Verification**: Implement verification that zeroing operations completed successfully

##### Data Types Requiring Secure Zeroing
- **Cryptographic Keys**: Session keys, daily keys, PSKs, derived keys
- **Nonces and Random Values**: All random numbers, nonces, and entropy
- **Passwords and Tokens**: Authentication credentials and session tokens
- **Packet Data**: Sensitive packet payloads and headers
- **Session State**: Session IDs, sequence numbers, timestamps
- **Configuration Secrets**: Encrypted configuration data and secrets

##### Zeroing Triggers
- **Session Termination**: Zero all session-related data when sessions end
- **Key Rotation**: Zero old keys when new keys are generated
- **Error Conditions**: Zero sensitive data when errors occur
- **Process Termination**: Zero all sensitive data on process exit
- **Memory Deallocation**: Zero data before freeing memory
- **Context Switching**: Zero sensitive data when switching contexts


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


## Implementation Planning

### Overview

This section provides a structured approach to implementing the Buckwild system, breaking down the complex architecture into manageable phases with clear milestones and dependencies. The implementation follows a layered approach, building from the core infrastructure upward.

### Implementation Phases

#### Phase 1: Foundation and Infrastructure (Weeks 1-3)
**Objective**: Establish core infrastructure and security foundations

**1.1 Project Foundation Setup**
- Replace existing prototype Cargo.toml with production-grade dependencies
- Audit and replace existing module structure with production-ready architecture
- Update development tooling with strict security lints and zero-tolerance for unsafe patterns
- Remove all TODO comments, unwrap() calls, and placeholder implementations
- Establish testing framework and CI/CD pipeline
- Set up security audit tools (cargo-audit, cargo-geiger)

**1.2 Core Data Types and Protocol Structures**
- Implement complete PacketHeader struct matching protocol.md specifications
- Create production-grade packet type enums and flag constants
- Implement zero-copy packet parsing and construction
- Create comprehensive session and connection data models
- Implement configuration data structures with validation
- Write comprehensive unit tests for all data structures

**1.3 Secure Memory Management Foundation**
- Implement SecureMemoryManager using memsec crate
- Create SecureKey type with automatic zeroing on drop
- Implement secure buffer allocation and cleanup functions
- Establish memory protection and locking mechanisms
- Write comprehensive security tests for memory management
- Verify secure zeroing behavior and memory protection

**Milestone 1**: Core data structures and secure memory management functional with comprehensive test coverage

#### Phase 2: Cryptographic Engine and Key Management (Weeks 4-6)
**Objective**: Implement all cryptographic operations and key management systems

**2.1 Cryptographic Engine Core**
- Implement complete HMAC calculation and verification using ring crate
- Create HKDF-SHA256 implementation following RFC specifications
- Implement secure random number generation using getrandom
- Ensure all cryptographic operations are constant-time
- Write comprehensive cryptographic operation tests
- Verify side-channel resistance and attack vector coverage

**2.2 Key Management System**
- Implement KeyManager with secure key storage using dashmap
- Create complete session key derivation and rotation mechanisms
- Implement PSK management with secure storage and access controls
- Create comprehensive key lifecycle management
- Implement automatic cleanup and secure deletion
- Write comprehensive tests for key rotation and security scenarios

**2.3 Time Synchronization Engine**
- Implement complete NTP client with multiple server support
- Create time offset calculation and drift detection algorithms
- Implement background sync loop with health monitoring
- Add fallback mechanisms for NTP unavailability
- Write comprehensive tests for synchronization accuracy
- Verify failure scenario handling

**Milestone 2**: Complete cryptographic engine with key management and time synchronization operational

#### Phase 3: Port Hopping and Network Layer (Weeks 7-9)
**Objective**: Implement port calculation, hopping mechanisms, and network communication

**3.1 Port Calculation Engine**
- Implement PortCalculator using HMAC-SHA256 with proper key management
- Create complete port calculation following protocol.md specifications
- Implement transmission delay allowance handling
- Add port offset calculations for connection multiplexing
- Write comprehensive port calculation tests
- Verify collision avoidance and security properties

**3.2 Network Socket Management**
- Create socket manager using socket2 crate
- Implement dynamic port binding for port hopping
- Add socket reuse and connection management
- Create network I/O with tokio async runtime
- Implement proper error handling and retry logic
- Write comprehensive socket management tests

**3.3 eBPF Integration and Packet Processing**
- Replace existing eBPF programs with production-ready implementations
- Implement complete XDP, TC, and socket filter programs
- Create eBPF integration with Rust daemon using aya crate
- Implement packet filtering and early processing
- Add eBPF-to-userspace communication using ring buffers
- Write comprehensive tests for eBPF integration

**Milestone 3**: Complete port hopping and network layer with eBPF integration functional

#### Phase 4: Protocol Translation and TUN Device Integration (Weeks 10-12)
**Objective**: Implement transparent TCP/IP to Buckwild protocol translation

**4.1 TUN Device Management**
- Implement TunDeviceManager using tun crate
- Create packet capture loop for reading TCP packets
- Implement packet injection loop for writing TCP packets
- Add comprehensive error handling and graceful shutdown
- Write comprehensive tests for TUN device operations
- Verify proper resource cleanup and no resource leaks

**4.2 TCP Packet Processing**
- Implement complete TCP packet parsing using etherparse crate
- Create TCP packet constructor for response generation
- Add IP header processing and validation
- Implement TCP checksum calculation and verification
- Write comprehensive packet parsing tests
- Cover all TCP packet types and malformed packet scenarios

**4.3 Protocol Translation Layer**
- Implement TCP stream to datagram conversion
- Create TCP sequence number to Buckwild sequence mapping
- Add connection state tracking for translation
- Implement Buckwild packet to TCP stream reconstruction
- Create bidirectional connection mapping using dashmap
- Write comprehensive translation tests covering all scenarios

**Milestone 4**: Complete protocol translation with TUN device integration operational

#### Phase 5: Session Management and Flow Control (Weeks 13-15)
**Objective**: Implement session lifecycle, flow control, and congestion control

**5.1 Session Management System**
- Implement SessionManager with complete lifecycle management
- Create session state machine covering all protocol states
- Add session timeout and expiration handling
- Implement session cleanup and resource management
- Write comprehensive session lifecycle tests
- Cover all state transitions and failure scenarios

**5.2 Flow Control and Congestion Control**
- Implement TCP-compatible flow control over datagrams
- Create congestion control algorithms (slow start, congestion avoidance, fast recovery)
- Add RTT calculation using RFC 6298 algorithms
- Implement receive window management
- Write comprehensive flow control tests
- Cover all network conditions and edge cases

**5.3 Reliability and Retransmission**
- Implement packet retransmission with exponential backoff
- Create retransmission queue management
- Add duplicate detection and handling
- Implement selective acknowledgment (SACK) support
- Write comprehensive reliability tests
- Cover all failure scenarios and recovery mechanisms

**Milestone 5**: Complete session management with flow control and reliability operational

#### Phase 6: Discovery Engine and Zero-Knowledge Proofs (Weeks 16-18)
**Objective**: Implement PSK discovery with zero-knowledge proof system

**6.1 PSK Discovery Protocol**
- Implement DiscoveryEngine with complete state machine
- Create discovery packet generation and parsing
- Add discovery session management with proper cleanup
- Implement timeout handling and retry logic
- Write comprehensive discovery protocol tests
- Cover all protocol states and attack scenarios

**6.2 Zero-Knowledge Proof System**
- Implement cryptographic commitments using curve25519-dalek
- Create PSK enumeration prevention mechanisms
- Add commitment verification without revealing PSK information
- Implement secure PSK selection process
- Write comprehensive zero-knowledge proof tests
- Verify all cryptographic properties and security guarantees

**6.3 Discovery Integration**
- Integrate discovery engine with session manager
- Implement automatic session creation after successful discovery
- Add discovery failure handling and retry logic
- Implement discovery rate limiting and attack prevention
- Write comprehensive integration tests
- Cover all failure modes and edge cases

**Milestone 6**: Complete discovery engine with zero-knowledge proofs operational

#### Phase 7: Recovery System and Error Handling (Weeks 19-21)
**Objective**: Implement comprehensive recovery mechanisms and error handling

**7.1 Recovery Strategy Framework**
- Implement RecoveryCoordinator using strategy pattern
- Create TimeResyncStrategy for time synchronization recovery
- Add SequenceRepairStrategy for sequence number recovery
- Implement EmergencyRecoveryStrategy for complete session recovery
- Write comprehensive recovery strategy tests
- Cover all failure scenarios and recovery paths

**7.2 Error Handling System**
- Create complete Error enum with all protocol error codes
- Implement error context and recovery mechanisms
- Add structured error logging with tracing crate
- Implement error metrics collection
- Write comprehensive error handling tests
- Cover all error conditions and recovery scenarios

**7.3 Monitoring and Observability**
- Implement structured logging using tracing crate
- Add metrics collection for performance monitoring
- Create syslog integration for audit trails
- Implement health checks and status reporting
- Write comprehensive monitoring tests
- Cover all logging scenarios and metric collection

**Milestone 7**: Complete recovery system with error handling and monitoring operational

#### Phase 8: Configuration and Management (Weeks 22-24)
**Objective**: Implement configuration management, CLI interface, and deployment tools

**8.1 Configuration Management**
- Implement configuration loader using config crate
- Add TOML file parsing with comprehensive validation
- Create environment variable override support
- Implement configuration error reporting and validation
- Write comprehensive configuration loading tests
- Cover all configuration scenarios and validation edge cases

**8.2 Hot Reloading System**
- Implement file watching using notify crate
- Create configuration reload triggers and handlers
- Add safe configuration updates without service interruption
- Implement configuration rollback on invalid updates
- Write comprehensive hot reloading tests
- Cover all reload scenarios and failure conditions

**8.3 CLI Interface**
- Create command-line interface using clap crate
- Add service start/stop/status commands
- Create configuration validation and testing commands
- Implement daemon mode and process management
- Write comprehensive CLI interface tests
- Cover all commands and error conditions

**Milestone 8**: Complete configuration management with CLI interface operational

#### Phase 9: Integration and System Testing (Weeks 25-27)
**Objective**: Comprehensive integration testing and system validation

**9.1 Integration Test Framework**
- Create test utilities for daemon setup and teardown
- Implement mock network interfaces for testing
- Add test configuration and environment setup
- Create integration test helpers and utilities
- Build comprehensive test scenarios
- Cover all component interactions

**9.2 End-to-End System Tests**
- Create full session lifecycle tests
- Implement multi-peer communication tests
- Add failure recovery and resilience tests
- Create performance and load tests
- Write comprehensive system integration tests
- Cover all operational scenarios

**9.3 Security and Penetration Testing**
- Implement security validation tests
- Create attack simulation and prevention tests
- Add cryptographic security verification
- Implement DoS protection and rate limiting tests
- Write security compliance tests
- Cover all attack vectors and security guarantees

**Milestone 9**: Complete system with comprehensive test coverage and security validation

#### Phase 10: Performance Optimization and Production Readiness (Weeks 28-30)
**Objective**: Optimize performance and prepare for production deployment

**10.1 Performance Optimization**
- Profile and optimize packet processing pipeline
- Improve session lookup and management performance
- Optimize cryptographic operations and memory usage
- Enhance network I/O and socket management efficiency
- Create performance benchmarks and monitoring
- Verify performance targets are met

**10.2 Production Deployment**
- Create systemd service files and installation scripts
- Implement proper logging and monitoring integration
- Add configuration templates and examples
- Create deployment testing and validation
- Write comprehensive documentation
- Prepare security best practices guide

**10.3 Documentation and Training**
- Write API documentation with rustdoc
- Create deployment and configuration guides
- Add troubleshooting and debugging documentation
- Create operator training materials
- Prepare security audit documentation
- Write performance tuning guide

**Final Milestone**: Production-ready system with complete documentation and deployment tools

### Critical Success Factors

#### Security Requirements (Non-negotiable)
- **NO PLACEHOLDERS**: All code must be 100% complete and functional
- **NO UNWRAP()**: All error handling must be comprehensive with proper Result types
- **SECURE MEMORY**: All cryptographic operations must use secure memory management
- **COMPLETE VALIDATION**: All network input must be thoroughly validated
- **CONSTANT TIME**: All cryptographic comparisons must be constant-time
- **PRODUCTION GRADE**: Use only established, audited crates

#### Quality Gates
- **Code Coverage**: Minimum 90% test coverage for all components
- **Security Audit**: Pass comprehensive security audit at each milestone
- **Performance**: Meet or exceed performance targets
- **Documentation**: Complete documentation for all public APIs
- **Compliance**: Pass all regulatory and security compliance requirements

#### Risk Mitigation
- **Parallel Development**: Run multiple workstreams in parallel where possible
- **Early Integration**: Integrate components early and often
- **Continuous Testing**: Maintain comprehensive test suite throughout
- **Security Review**: Conduct security reviews at each phase
- **Performance Monitoring**: Track performance metrics throughout development

### Dependencies and Prerequisites

#### Technical Prerequisites
- Linux development environment with kernel 5.4+
- Rust 1.70+ with stable toolchain
- eBPF development tools and libraries
- Network testing infrastructure
- Security testing tools and frameworks

#### Team Prerequisites
- Rust systems programming expertise
- eBPF and kernel development experience
- Cryptographic implementation knowledge
- Network protocol development skills
- Security audit and testing capabilities

#### Infrastructure Prerequisites
- Development environment with network isolation
- CI/CD pipeline with security scanning
- Performance testing infrastructure
- Security testing environment
- Documentation and knowledge management systems

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

