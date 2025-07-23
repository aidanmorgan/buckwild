# Overview

This document defines the complete specification for connection establishment, port hopping synchronization, and recovery mechanisms in the frequency hopping network system. The protocol ensures reliable communication while maintaining synchronized port transitions between endpoints using ephemeral Diffie-Hellman key exchange, privacy-preserving PSK discovery, and cryptographically derived parameters.

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

## Key Features

- **ECDH-Based Connection Tracking**: Comprehensive state machine manages ephemeral key-based connections
- **PBKDF2 Parameter Derivation**: All session parameters cryptographically derived from ECDH shared secrets
- **Privacy-Preserving Discovery**: Bloom filter-based PSK discovery protects key collections
- **Comprehensive Error Handling**: Detailed error codes and ECDH-based recovery procedures
- **Security by Design**: All operations use ECDH and assume hostile network environments
- **Scalable Architecture**: Support for multiple concurrent ECDH connections per endpoint
- **Perfect Forward Secrecy**: Ephemeral keys protect past communications