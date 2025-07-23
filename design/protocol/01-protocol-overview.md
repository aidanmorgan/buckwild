# Protocol Overview and Specification

## Table of Contents

This document defines a complete specification for connection management and synchronization protocol for frequency hopping networks.

### Document Organization

**Part I: Protocol Foundation**
1. [Protocol Overview](01-protocol-overview.md) - Introduction, design goals, and architecture
2. [Core Definitions](02-core-definitions.md) - Constants, error codes, and naming conventions  
3. [Packet Architecture](03-packet-architecture.md) - Packet types, formats, and headers

**Part II: Cryptographic Framework**
4. [ECDH Cryptography](04-ecdh-cryptography.md) - Ephemeral key exchange and parameter derivation
5. [PSK Discovery](05-psk-discovery.md) - Privacy-preserving set intersection for key discovery

**Part III: Connection Management**
6. [Connection Lifecycle](06-connection-lifecycle.md) - State machine and connection management
7. [Data Transmission](07-data-transmission.md) - Flow control and fragmentation
8. [Timeout and Reliability](08-timeout-and-reliability.md) - RTO calculation and retry mechanisms

**Part IV: Network Synchronization** 
9. [Time Synchronization](09-time-synchronization.md) - Precise time coordination between peers
10. [Port Hopping](10-port-hopping.md) - Synchronized port transitions for security
11. [Adaptive Networking](11-adaptive-networking.md) - Dynamic delay tuning and optimization

**Part V: Resilience and Recovery**
12. [Recovery Mechanisms](12-recovery-mechanisms.md) - Multi-layer failure recovery strategies
13. [Edge Case Handling](13-edge-case-handling.md) - Boundary conditions and exceptional scenarios

**Part VI: Reference Materials**
14. [Sequence Diagrams](14-sequence-diagrams.md) - Visual protocol flows and interactions

---

## Abstract

**⚠️ DO NOT USE THIS PROTOCOL IN THE REAL WORLD - IT IS PURELY FOR LEARNING PURPOSES ⚠️**

This document defines a complete specification for connection establishment, port hopping synchronization, and recovery mechanisms in frequency hopping network systems. The protocol ensures reliable communication while maintaining synchronized port transitions between endpoints using ephemeral Diffie-Hellman key exchange, privacy-preserving PSK discovery, and cryptographically derived parameters.

The specification includes comprehensive mechanisms for congestion control, flow control, fragmentation, cryptographic operations, and robust recovery procedures to handle various failure scenarios with perfect forward secrecy.

## License

This specification is provided under an open license for implementation and use in compatible systems.

## Design Goals

The protocol is designed with the following key objectives:

### Security and Privacy
- **Perfect Forward Secrecy**: All connections use ephemeral Diffie-Hellman key exchange providing forward secrecy
- **Privacy-Preserving PSK Discovery**: Hash-based set intersection enables PSK discovery without revealing non-shared keys
- **Port Hopping Obfuscation**: Frequent port transitions make traffic analysis and connection tracking difficult
- **Anti-Replay Protection**: Comprehensive timestamp and sequence number validation prevents replay attacks
- **Cryptographic Parameter Derivation**: All session parameters derived from ECDH shared secrets using PBKDF2
- **Zero Data Exposure**: All sensitive exchanges use ECDH to prevent information leakage

### Reliability and Robustness
- **Comprehensive Recovery Mechanisms**: Multiple recovery strategies handle various failure scenarios including time desynchronization, sequence number conflicts, and network partitions
- **Adaptive Flow Control**: Dynamic window management optimizes throughput while preventing congestion
- **Fragmentation Support**: Large packets are fragmented and reassembled reliably
- **Timeout and Retry Logic**: Robust timeout handling with exponential backoff and maximum retry limits

### Performance and Efficiency
- **Adaptive Delay Tuning**: Dynamic adjustment of transmission delays based on network conditions
- **Congestion Control**: TCP-compatible congestion control algorithms ensure fair network utilization
- **Selective Acknowledgment**: Efficient acknowledgment of out-of-order packets
- **Optimized Packet Formats**: Compact packet headers minimize overhead

### Synchronization and Coordination
- **Time Synchronization**: Precise time coordination between endpoints enables reliable port hopping
- **Multiple Connection Support**: Collision avoidance mechanisms allow multiple parallel connections
- **Port Transition Coordination**: Synchronized port changes maintain connectivity during hops
- **Emergency Recovery**: Fail-safe mechanisms restore connectivity when normal operations fail

## Protocol Architecture

The protocol operates through several integrated subsystems:

1. **ECDH Connection Engine**: Handles ephemeral Diffie-Hellman connection establishment, maintenance, and teardown
2. **PSI Discovery Engine**: Manages privacy-preserving set intersection for PSK discovery
3. **Port Hopping Engine**: Manages synchronized port transitions using PBKDF2-derived offsets from ECDH secrets
4. **Cryptographic Layer**: Provides ECDH key exchange, PBKDF2 derivation, and HMAC authentication
5. **Flow Control Engine**: Manages data transmission rates and buffer utilization
6. **Recovery Engine**: Detects and recovers from various failure conditions using ECDH-based recovery
7. **Fragmentation Engine**: Handles packet fragmentation and reassembly
8. **Time Synchronization Engine**: Maintains synchronized time references between endpoints

## Document Status

This is a complete protocol specification that defines all aspects of the frequency hopping network communication system, including connection management, synchronization, security, and recovery mechanisms.