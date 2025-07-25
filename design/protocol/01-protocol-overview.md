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

This document defines a complete specification for connection establishment, port hopping synchronization, and recovery mechanisms in frequency hopping network systems. The protocol provides reliable communication with synchronized port transitions between endpoints using ephemeral Diffie-Hellman key exchange, privacy-preserving PSK discovery, and cryptographically derived parameters.

The specification includes congestion control, flow control, fragmentation, cryptographic operations, and recovery procedures for failure scenarios with perfect forward secrecy.

## License

This specification is provided under an open license for implementation and use in compatible systems.

## Design Goals

The protocol is designed with the following key objectives:

### Security and Privacy
- **Perfect Forward Secrecy**: All connections use ephemeral Diffie-Hellman key exchange providing forward secrecy
- **Privacy-Preserving PSK Discovery**: Hash-based set intersection enables PSK discovery without revealing non-shared keys
- **Port Hopping Obfuscation**: Frequent port transitions make traffic analysis and connection tracking difficult
- **Anti-Replay Protection**: Timestamp and sequence number validation prevents replay attacks
- **Cryptographic Parameter Derivation**: All session parameters derived from ECDH shared secrets using PBKDF2
- **Zero Data Exposure**: All sensitive exchanges use ECDH to prevent information leakage

### Reliability and Robustness
- **Recovery Mechanisms**: Multiple recovery strategies handle time desynchronization, sequence number conflicts, and network partitions
- **Flow Control**: Dynamic window management optimizes throughput and prevents congestion
- **Fragmentation**: Large packets are fragmented and reassembled
- **Timeout Handling**: Exponential backoff with maximum retry limits

### Performance and Efficiency
- **Adaptive Header Format**: Variable session ID, timestamp, and HMAC sizes reduce overhead by up to 54% (23-45 bytes vs 50 bytes)
- **Month-Based Timestamps**: Compressed timestamps using milliseconds since current month start
- **Tiered Authentication**: Different HMAC levels for different packet types (64-bit, 128-bit, 256-bit)
- **Deployment Flexibility**: Configurable for IoT devices to enterprise infrastructure
- **Adaptive Delay Tuning**: Dynamic transmission delay adjustment based on network conditions
- **Congestion Control**: TCP-compatible congestion control algorithms for fair network utilization
- **Selective Acknowledgment**: Efficient acknowledgment of out-of-order packets
- **Compact Packet Formats**: Minimized header overhead

### Synchronization and Coordination
- **Time Synchronization**: Precise time coordination between endpoints for reliable port hopping
- **Multiple Connection Support**: Collision avoidance mechanisms for multiple parallel connections
- **Port Transition Coordination**: Synchronized port changes maintain connectivity during hops
- **Emergency Recovery**: Fail-safe mechanisms restore connectivity when normal operations fail

## Cryptographic Key Management

The protocol uses a multi-layered key management system providing perfect forward secrecy, session isolation, and temporal key separation. All cryptographic keys serve specific purposes with defined lifetimes and security properties.

### Key Hierarchy and Relationships

The protocol uses a multi-layered key derivation system with two primary paths: PSK-based derivation for alternative session keys and ECDH-based derivation for the primary session parameters.

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                    Key Derivation Flow                     │
                    └─────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌────────────────────────────────────────────────────────────┐
│ Pre-Shared Key  │     │                ECDH Key Exchange                           │
│   (PSK)         │     │  ┌─────────────────┐    ┌─────────────────┐               │
│ 256+ bits       │     │  │  Client ECDH    │    │  Server ECDH    │               │
│ Long-term       │     │  │  Private Key    │    │  Private Key    │               │
└─────────┬───────┘     │  │   (256 bits)    │    │   (256 bits)    │               │
          │             │  │   Ephemeral     │    │   Ephemeral     │               │
          │             │  └─────────┬───────┘    └─────────┬───────┘               │
          │             │            │                      │                       │
          │             │            │ ┌────────────────────┼─────────────────────┐ │
          │             │            │ │    Public Key      │     Public Key      │ │
          │             │            │ │   Exchange         │    Exchange         │ │
          │             │            │ │                    │                     │ │
          │             │            └─┼────────────────────┼─────────────────────┘ │
          │             │              │                    │                       │
   ┌──────▼──────┐      │              └────────┬───────────┘                       │
   │ Daily Key   │      │                       │                                   │
   │ HKDF-SHA256 │      │              ┌────────▼────────┐                          │ 
   │ 256 bits    │      │              │ ECDH Shared     │                          │
   │ 24hr life   │      │              │ Secret          │◄─────────────────────────┘
   └──────┬──────┘      │              │ 256 bits        │
          │             │              │ Ephemeral       │
   ┌──────▼──────┐      │              └────────┬────────┘
   │ Session Key │      │                       │
   │ (Alt Path)  │      │       ┌───────────────┼───────────────┬─────────────────┐
   │ HKDF-SHA256 │      │       │               │               │                 │
   │ 256 bits    │      │       │               │               │                 │
   └──────┬──────┘      │       │               │               │                 │
          │             │ ┌─────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐          │
          │             │ │ Master Key │ │ Port Deriv. │ │ Auth Key    │          │
          │             │ │ Material   │ │ Material    │ │ Material    │          │
          │             │ │ PBKDF2     │ │ PBKDF2      │ │ PBKDF2      │          │
          │             │ │ 1024 bits  │ │ 8-12 bytes  │ │ 256 bits    │          │
          │             │ │ 4096 iters │ │ 2048 iters  │ │ 4096 iters  │          │
          │             │ └─────┬──────┘ └──────┬──────┘ └──────┬──────┘          │
          │             │       │               │               │                 │
          │             │       │               │               │                 │
┌─────────▼─────────┐   │ ┌─────▼─────────────────────────────┐ │ ┌─────────────▼──────────────┐
│ HMAC              │   │ │     Chunk Extraction              │ │ │ Session-Specific Port      │
│ Authentication    │   │ │     (64 × 16-bit chunks)          │ │ │ Hopping (Post-Connection)  │
│ (32/64/128-bit)   │   │ └─────┬─────────────────────────────┘ │ │ Unique per Session         │
└───────────────────┘   │       │                               │ └────────────────────────────┘
          │             │       │                               │
┌─────────▼─────────┐   │       │                               │
│ Base Port Hopping │   │       │                               │
│ (Connection Est.) │   │       │                               │
│ Daily Key + UTC   │   │       │                               │
│ Time Buckets      │   │       │                               │
└───────────────────┘   │       │                               │
                        │ ┌─────▼─────────────────────────────┐ │
                        │ │  Derived Session Parameters       │ │
                        │ │                                   │ │
                        │ │  Chunks 0-3:  Sequence Numbers   │ │ ┌──────────────────────────┐
                        │ │               (32-bit each)       │ │ │ Challenge-Response       │
                        │ │                                   │ │ │ Nonces                   │
                        │ │  Chunks 4-5:  Port Offsets       │ │ │ ┌──────────────────────┐ │
                        │ │               (16-bit each)       │ │ │ │ Time Sync Nonce      │ │
                        │ │                                   │ │ │ │ 32-bit random        │ │
                        │ │  Chunks 6-21: Session Key        │ │ │ └──────────────────────┘ │
                        │ │               (256 bits)          │ │ │ ┌──────────────────────┐ │
                        │ │                                   │ │ │ │ Recovery Nonces      │ │
                        │ │  Chunks 22-23: Port Hop Seed     │ │ │ │ 32-bit random        │ │
                        │ │                (32 bits)          │ │ │ └──────────────────────┘ │
                        │ │                                   │ │ │ ┌──────────────────────┐ │
                        │ │  Chunk 24:    Time Sync Offset   │ │ │ │ Discovery ID/Salt    │ │
                        │ │               (16 bits)           │ │ │ │ 64-bit + 32-bit      │ │
                        │ │                                   │ │ │ └──────────────────────┘ │
                        │ │  Chunk 25+:   Congestion Seed    │ │ └──────────────────────────┘
                        │ │               (16+ bits)          │ │
                        │ └───────────────┬───────────────────┘ │
                        └─────────────────┼─────────────────────┘
                                          │
                        ┌─────────────────▼─────────────────┐
                        │          Final Usage             │
                        │                                  │
                        │  • Session Key → HMAC Auth       │
                        │  • Sequences → Flow Control      │
                        │  • Port Data → Session-Specific  │
                        │    Hopping (Post-Connection)     │
                        │  • Time Offset → Sync Adjustment │
                        │  • Seeds → Crypto Randomization  │
                        │                                  │
                        │  • Daily Key → Base Port Hopping │
                        │    (Connection Establishment)    │
                        └──────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Base Port Hopping                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│ Algorithm:    HMAC-SHA256(daily_key, time_bucket_since_midnight_utc || "base_port") │
│ Daily Key:    HKDF-SHA256(PSK, date_salt, "daily_key" + UTC_date)                  │
│ Time Bucket:  (milliseconds_since_midnight_utc) / 500ms (integer division)      │
│ Usage:        SYN/SYN-ACK handshake only (before session keys exist)               │
│ Purpose:      Enable connection establishment using daily-rotating 500ms UTC buckets │
│ Security:     Daily rotation + UTC synchronization, PSK holders only              │
│ Transition:   Switches to session-specific after ECDH handshake completes         │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                Key Lifetimes                                        │
├─────────────────────────────────────────────────────────────────────────────────────┤
│ PSK:              Long-term (externally managed)                                    │
│ Daily Key:        24 hours (auto-rotation at UTC midnight)                         │
│ ECDH Keys:        Ephemeral (cleared after shared secret computation)              │
│ Shared Secret:    Ephemeral (cleared after parameter derivation)                  │
│ Master Material:  Ephemeral (cleared after chunk extraction)                      │
│ Session Key:      Session duration (cleared on termination)                       │
│ Port Material:    Session duration (session state storage)                        │
│ Nonces:           Single operation (seconds to minutes)                            │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Security Properties                                    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│ Perfect Forward Secrecy:    ECDH ephemeral keys prevent retroactive decryption    │
│ Session Isolation:          Independent key derivation per connection             │
│ Temporal Separation:        Daily key rotation + month-based epochs               │
│ Parameter Diversity:        PBKDF2 chunk extraction ensures separation            │
│ Attack Resistance:          Multi-layer protection + rate limiting                │
│ Memory Security:            secure_zero_memory() for all key material             │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Core Cryptographic Keys

#### Pre-Shared Keys (PSK)
- **Type**: Symmetric keys (256+ bits recommended)
- **Derivation**: Pre-configured and shared out-of-band between peers
- **Purpose**: Foundation of trust for all session key derivation and authentication during connection establishment
- **Lifetime**: Long-term, managed externally to the protocol
- **Use Cases**: 
  - Privacy-preserving PSK discovery using set intersection
  - Input to daily key derivation hierarchy
  - Authentication during ECDH key exchange
- **Security Properties**: Foundation of trust for entire protocol, protected through privacy-preserving discovery
- **Storage**: Secure local storage with cryptographic fingerprint collections

#### Daily Key
- **Type**: 256-bit symmetric key  
- **Derivation**: `HKDF-SHA256(PSK, date_salt, "daily_key" + UTC_date)`
- **Purpose**: Intermediate key providing temporal separation in the key hierarchy
- **Lifetime**: 24 hours, automatically rotated at UTC midnight
- **Use Cases**: 
  - Input to session key derivation when PSK-based keys are used
  - Provides forward secrecy through daily rotation
- **Security Properties**: Forward secrecy through automatic daily rotation
- **Storage**: Derived as needed, may be cached for current day

#### Session Key (Primary)
- **Type**: 256-bit symmetric key
- **Derivation**: Extracted from ECDH-derived master key material (PBKDF2 chunks 6-21)
- **Purpose**: Primary cryptographic protection for all session communication
- **Lifetime**: Session duration (connection establishment through termination)
- **Use Cases**: 
  - HMAC authentication of all packet types
  - Adaptive HMAC policies (64-bit, 128-bit, 256-bit)
  - Primary session protection mechanism
- **Security Properties**: Perfect forward secrecy through ECDH derivation, session isolation
- **Storage**: In-memory only, cleared on session termination with `secure_zero_memory()`

#### ECDH Key Pairs
- **Type**: P-256 elliptic curve key pairs (256-bit private, 512-bit uncompressed public)
- **Derivation**: Cryptographically secure random generation per connection
- **Purpose**: Ephemeral key exchange providing perfect forward secrecy
- **Lifetime**: Ephemeral - cleared immediately after shared secret computation
- **Use Cases**: 
  - Initial connection establishment
  - Session rekeying during recovery operations
  - Forward secrecy guarantees
- **Security Properties**: Perfect forward secrecy, prevents retroactive decryption
- **Storage**: Temporary memory only, private keys cleared with `secure_zero_memory()`

#### ECDH Shared Secret
- **Type**: 256-bit value (P-256 ECDH x-coordinate)
- **Derivation**: `ECDH(own_private_key, peer_public_key)`
- **Purpose**: Master secret for deriving all session-specific parameters
- **Lifetime**: Ephemeral - used immediately for parameter derivation then cleared
- **Use Cases**: 
  - Input to PBKDF2 master key material derivation
  - Source for session keys, sequence numbers, and port hopping parameters
- **Security Properties**: Never transmitted, provides perfect forward secrecy
- **Storage**: Temporary only, cleared immediately after use

### Session Parameter Derivation

#### Master Key Material
- **Type**: 1024-bit (128 bytes) cryptographically derived material
- **Derivation**: `PBKDF2-HMAC-SHA256(shared_secret, salt, 4096_iterations, 128_bytes)`
- **Salt**: `SHA256(client_pubkey || server_pubkey || session_context || "ecdh_salt_v1")`
- **Purpose**: Source material for all session-specific parameters
- **Lifetime**: Ephemeral - used immediately for parameter extraction
- **Use Cases**: 
  - Broken into 64 × 16-bit chunks for parameter extraction
  - Provides cryptographic separation of derived values
  - Ensures session uniqueness and unpredictability
- **Security Properties**: High entropy, cryptographically separated parameters
- **Storage**: Temporary only, cleared after chunk extraction

#### Derived Session Parameters
From master key material chunks:
- **Sequence Numbers**: Chunks 0-3 → 32-bit client/server initial sequences
- **Port Offsets**: Chunks 4-5 → 16-bit client/server port hopping offsets  
- **Session Key**: Chunks 6-21 → 256-bit primary authentication key
- **Port Hop Seed**: Chunks 22-23 → 32-bit port calculation randomization
- **Time Sync Offset**: Chunk 24 → 16-bit time synchronization adjustment
- **Congestion Seed**: Chunk 25+ → 16+ bit congestion control initialization

#### Port Hopping Keys

**Base Port Hopping (Connection Establishment):**
- **Type**: Uses daily key derived from PSK with 500ms UTC time buckets since midnight
- **Derivation**: `HMAC-SHA256(daily_key, time_bucket_since_midnight_utc || "base_port_sequence_v2")`
- **Daily Key**: `HKDF-SHA256(PSK, date_salt, "daily_key" + UTC_date)`
- **Time Calculation**: Milliseconds since UTC midnight divided by 500ms (integer division)
- **Purpose**: Enable connection establishment using shared daily-rotating algorithm with 500ms UTC buckets
- **Lifetime**: Used only during SYN/SYN-ACK handshake, rotates daily with daily key
- **Use Cases**: 
  - Initial SYN and SYN-ACK packet transmission/reception
  - 500ms time buckets since UTC midnight provide synchronized port calculation
  - Shared daily-rotating algorithm allows peers to find each other for connection establishment
  - Multi-port listening within adaptive delay windows
  - Daily rotation provides temporal security boundaries
- **Security Properties**: Cryptographically secure with daily rotation, predictable to PSK holders only
- **Storage**: Daily key cached for current day, base ports computed from 500ms UTC time buckets

**Session-Specific Port Hopping (Post-Connection):**
- **Type**: 32-bit port hop seed + additional port derivation material
- **Derivation**: 
  - Primary: Port hop seed from PBKDF2 master key material (chunks 22-23)
  - Secondary: Separate `PBKDF2-HMAC-SHA256(shared_secret, port_salt, 2048_iterations)`
- **Salt**: `SHA256(client_pubkey || server_pubkey || "port_derivation_v1")`
- **Purpose**: Generate unique, unpredictable port sequences per session
- **Lifetime**: Session duration (after ECDH handshake completion)
- **Use Cases**: 
  - All communication after connection establishment completes
  - Synchronized port transitions every 500ms
  - Unique sequences prevent port collisions between parallel connections
  - Maximum cryptographic unpredictability for ongoing communication
- **Security Properties**: Perfect forward secrecy through ECDH derivation, prevents port sequence prediction
- **Storage**: Session state storage

**Transition Point**: The switch from base to session-specific port hopping occurs immediately after ECDH key exchange completes and session parameters are derived. The final ACK and all subsequent packets use session-specific port hopping.

### Discovery and Recovery Keys

#### Discovery Session Keys
- **Discovery ID**: 64-bit secure random identifier for PSK discovery sessions
- **Session Salt**: 32-bit secure random salt for fingerprint blinding
- **Blinded Fingerprints**: `HMAC-SHA256-128(PSK_fingerprint, session_salt)`
- **Purpose**: Privacy-preserving PSK discovery using set intersection
- **Lifetime**: Discovery session duration (typically seconds)
- **Security Properties**: Unlinkability across discovery sessions, prevents PSK enumeration

#### Challenge-Response Nonces
- **Type**: 32-bit cryptographically secure random values
- **Use Cases**: 
  - Time synchronization challenge-response (`challenge_nonce`)
  - Recovery operation authentication (`repair_nonce`, `rekey_nonce`)
  - Request-response matching and replay prevention
- **Lifetime**: Single operation duration (seconds to minutes)
- **Security Properties**: Prevent replay attacks, ensure operation freshness

### Key Security Properties

#### Perfect Forward Secrecy
- ECDH ephemeral keys ensure past communications remain secure even if long-term keys are compromised
- Private keys are cleared immediately after shared secret computation
- Session keys cannot be retroactively derived without ephemeral private keys

#### Session Isolation
- Each connection derives unique session keys from independent ECDH exchanges
- PBKDF2 parameter derivation ensures cryptographic separation between sessions
- Session state is completely independent between connections

#### Temporal Key Separation
- Daily key rotation provides time-based security boundaries
- Month-based timestamp epochs limit time correlation attacks
- Automatic key material refresh prevents long-term key exposure

#### Attack Resistance
- PSK discovery prevents key enumeration through privacy-preserving set intersection  
- Multiple HMAC policies adapt to security requirements and performance needs
- Replay protection through timestamps and sequence numbers
- Rate limiting prevents brute force and enumeration attacks

### Implementation Requirements

#### Secure Memory Management
- All key material must be cleared using `secure_zero_memory()` after use
- Ephemeral keys require immediate cleanup after parameter derivation
- Session keys cleared on connection termination or recovery failure

#### Cryptographic Quality
- All random values require cryptographically secure random number generation
- PBKDF2/HKDF implementations must use proper salts and iteration counts
- Timing attack prevention through constant-time comparisons

#### Key Rotation and Recovery
- Session keys can be rotated through ECDH rekeying recovery mechanism
- Daily keys automatically rotate at UTC midnight boundaries
- PSK rotation managed externally with support for multiple concurrent PSKs

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
