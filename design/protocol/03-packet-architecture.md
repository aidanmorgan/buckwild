# Packet Architecture and Format Specifications

This document defines the complete packet format specifications for the protocol, including all packet types, header structures, and field definitions.

## Overview

The packet format provides optimized data structures for network communication between peers. The design minimizes overhead while maintaining all necessary functionality and providing excellent extensibility.

## Key Design Principles

- **Adaptive Header Size**: Variable session ID, timestamp, and HMAC sizes based on deployment requirements
- **Month-Based Timestamps**: Compressed timestamps using milliseconds since current month start
- **HMAC Policy Framework**: Three authentication policies (LIGHT, MEDIUM, STRONG) for different security requirements
- **Deployment Flexibility**: Configurable for everything from IoT devices to enterprise infrastructure

## Packet Type Definitions

All packet types and sub-types are defined in 02-core-definitions.md:

**Core packet types:**
- PACKET_TYPE_SYN = 0x01 (Connection establishment)
- PACKET_TYPE_SYN_ACK = 0x02 (Connection establishment response)
- PACKET_TYPE_ACK = 0x03 (Acknowledgment, includes WINDOW_UPDATE and SACK)
- PACKET_TYPE_DATA = 0x04 (Data packet, includes FRAGMENT functionality)
- PACKET_TYPE_FIN = 0x05 (Connection termination)
- PACKET_TYPE_HEARTBEAT = 0x06 (Keep-alive packet)
- PACKET_TYPE_ERROR = 0x09 (Error packet)
- PACKET_TYPE_RST = 0x0B (Reset connection)
- PACKET_TYPE_CONTROL = 0x0C (Control operations)
- PACKET_TYPE_MANAGEMENT = 0x0D (Management operations)
- PACKET_TYPE_DISCOVERY = 0x0E (PSK discovery with sub-types)

**CONTROL packet sub-types:**
- CONTROL_SUB_TIME_SYNC_REQUEST = 0x01, CONTROL_SUB_TIME_SYNC_RESPONSE = 0x02
- CONTROL_SUB_RECOVERY = 0x03, CONTROL_SUB_SEQUENCE_NEG = 0x04

**MANAGEMENT packet sub-types:**
- MANAGEMENT_SUB_REKEY_REQUEST = 0x01, MANAGEMENT_SUB_REKEY_RESPONSE = 0x02
- MANAGEMENT_SUB_REPAIR_REQUEST = 0x03, MANAGEMENT_SUB_REPAIR_RESPONSE = 0x04

**DISCOVERY packet sub-types:**
- DISCOVERY_SUB_REQUEST = 0x01, DISCOVERY_SUB_RESPONSE = 0x02, DISCOVERY_SUB_CONFIRM = 0x03

## Adaptive Header Format

### Configuration Encoding

The protocol uses version byte encoding to specify the adaptive configuration:

```pseudocode
Version Byte Encoding (8 bits):
Bits 0-3: Protocol version (0x01)
Bits 4-5: Session ID length
  00 = 16-bit session ID (2 bytes)
  01 = 32-bit session ID (4 bytes)
  10 = 64-bit session ID (8 bytes)
  11 = Reserved
Bits 6-7: Timestamp configuration
  00 = 16-bit timestamp (2 bytes, 1.09 minutes max)
  01 = 24-bit timestamp (3 bytes, 4.66 hours max)
  10 = 24-bit timestamp with 10ms precision (46.6 hours max)
  11 = 32-bit timestamp (4 bytes, full month max)

Examples:
0x11 = v1 + 16-bit ID + 16-bit timestamp
0x51 = v1 + 32-bit ID + 16-bit timestamp  
0x91 = v1 + 64-bit ID + 16-bit timestamp
0x71 = v1 + 32-bit ID + 24-bit timestamp (most common)
0xF1 = v1 + 32-bit ID + 32-bit timestamp (long-lived)
```

### Common Header Structure

```pseudocode
Adaptive Common Header Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| Type   |Sub-Type| Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
|  (2, 4, or 8 bytes based on      |
|   version bits 4-5)               |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
|  (2, 3, or 4 bytes based on      |
|   version bits 6-7)               |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 8-32 bytes)   |
|  LIGHT=8, MEDIUM=16, STRONG=32   |
+-----------------------------------+

Field Definitions:
- Version (8-bit): Protocol version and configuration encoding
- Type (8-bit): Packet type (see packet types above)
- Sub-Type (8-bit): Packet sub-type for CONTROL, MANAGEMENT, and DISCOVERY packets (0x00 for others)
- Flags (8-bit): Bit flags for packet options
  - Bit 0: FIN flag (connection termination)
  - Bit 1: SYN flag (connection establishment)
  - Bit 2: RST flag (reset connection)
  - Bit 3: PSH flag (push data immediately)
  - Bit 4: ACK flag (acknowledgment included)
  - Bit 5: URG flag (urgent data)
  - Bit 6: SACK flag (selective acknowledgment present in payload)
  - Bit 7: Fragment flag (fragmentation info present in payload)
- Session ID (Variable): Unique session identifier (big-endian)
- Sequence Number (32-bit): Packet sequence number (big-endian)
- Acknowledgment Number (32-bit): Next expected sequence (big-endian, 0 if not applicable)
- Timestamp (Variable): Dual epoch system as defined in 09-time-synchronization.md - Base port hopping uses daily epochs (500ms buckets since UTC midnight of current day), session packets use monthly epochs (500ms buckets since UTC midnight of current month) (big-endian)
- Payload Length (16-bit): Length of payload data in bytes (big-endian)
- HMAC (Variable): Authentication hash using session key (big-endian)
```

### Header Size Examples

```
Configuration Examples (Base header: 18 bytes as defined in 02-core-definitions.md + variable fields):
Ultra-compact:  26 bytes (18 + 2-byte ID + 2-byte TS + 4-byte HMAC)
Compact:        29 bytes (18 + 2-byte ID + 3-byte TS + 4-byte HMAC)
Standard:       31 bytes (18 + 4-byte ID + 3-byte TS + 4-byte HMAC) 
Secure:         35 bytes (18 + 4-byte ID + 3-byte TS + 8-byte HMAC)
Long-lived:     46 bytes (18 + 8-byte ID + 4-byte TS + 16-byte HMAC)
```

## HMAC Policy

### Packet Classification

Packets are classified into security levels that determine HMAC requirements:

```pseudocode
PACKET_CLASS_CRITICAL:   // Always full HMAC (128-bit)
- SYN, SYN_ACK, FIN packets
- DISCOVERY packets  
- REKEY operations

PACKET_CLASS_CONTROL:    // Strong HMAC minimum (64-bit)
- ERROR, RST, HEARTBEAT packets
- TIME_SYNC, RECOVERY operations
- REPAIR operations

PACKET_CLASS_DATA:       // Adaptive HMAC (64-bit/8-byte default)
- DATA packets between full HMAC intervals
- ACK packets for data
```

### Adaptive HMAC Rules

```pseudocode
HMAC Selection Algorithm:
1. Critical packets: Always use HMAC_FULL (128-bit)
2. Control packets: Use HMAC_STRONG (64-bit) minimum
3. Data packets: Use HMAC_LIGHT (64-bit/8-byte) with periodic full verification

Periodic Full HMAC Triggers (coordinated between peers):
- Every 100 data packets (both peers count independently)
- Every 5 seconds of activity (synchronized using protocol timestamps)
- After any HMAC verification failure (triggered by receiving peer)
- During month boundary transitions (synchronized using UTC month boundaries)

Peer Coordination:
- Peers maintain independent packet counters for the 100-packet trigger
- Time-based triggers use protocol timestamps to ensure synchronization
- HMAC failure triggers cause the receiving peer to require full HMAC on subsequent packets
- Both peers automatically use full HMAC during month boundary transition periods
```

## Conditional Fields

### Flow Control Fields (4 bytes when needed)

```pseudocode
Flow Control Header:
+-----------------------------------+
|       Window Size (16-bit)       |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+

Used in: ACK, DATA, HEARTBEAT packets
```

### Fragmentation Fields (8 bytes when Fragment flag set)

```pseudocode
Fragmentation Header:
+-----------------------------------+
|  Fragment ID     |Fragment Index |
|   (16-bit)       |   (16-bit)    |
+-------------------+---------------+
|  Total Frags     |   Reserved    |
|   (16-bit)       |   (16-bit)    |
+-------------------+---------------+

Field Definitions:
- Fragment ID (16-bit): Unique identifier for this fragmented message
- Fragment Index (16-bit): Zero-based index of this fragment  
- Total Frags (16-bit): Total number of fragments in message
- Reserved (16-bit): Must be 0x0000

Used in: DATA packets when fragmented
```

### Selective ACK Fields (Variable length when SACK flag set)

```pseudocode
SACK Header:
+-----------------------------------+
|    SACK Block Count (8-bit)      |
+-----------------------------------+
|      Primary SACK Bitmap         |
|        (32-bit)                  |
+-----------------------------------+
|   Additional SACK Ranges         |
|   (8 bytes per range)            |
|   Start Seq (32) + End Seq (32)  |
+-----------------------------------+

Used in: ACK packets when selective acknowledgment needed
```

## Timestamp Management

### Month-Based Epoch

The protocol uses two timestamp epochs: milliseconds since UTC midnight of the current day for base port hopping (divided into 500ms buckets for connection establishment), and milliseconds since UTC midnight of the current month for session packets. This provides:

- **32-bit coverage**: Handles longest month (31 days = 2.68 billion ms) with 1.6 billion ms buffer
- **24-bit practical**: Covers 4.66 hours, sufficient for most connections
- **16-bit ultra-compact**: Covers 1.09 minutes for very short connections

### Temporal Boundary Handling

```pseudocode
Daily Boundary Transition (Base Port Hopping):
1. At UTC midnight: Daily key rotates automatically
2. Base port sequences reset with new daily key using 500ms buckets
3. Connection establishment uses new daily epoch (500ms buckets since new midnight)
4. Time bucket = milliseconds_since_midnight_utc // 500

Month Boundary Transition (Session Packets):
1. One hour before month end: Begin transition preparation
2. Force full HMAC for all packets during transition window
3. Accept timestamps from both old and new month epochs
4. Log transition and notify active sessions
5. Reset timestamp epoch to new month start
```

### Anti-Replay Timestamp Validation

All packet timestamps are validated against the TIMESTAMP_WINDOW_MS (30-second) sliding window to prevent replay attacks:

```pseudocode
Timestamp Validation Process:
1. Extract timestamp from packet header (milliseconds since month start)
2. Calculate packet age: current_time - (month_start + packet_timestamp)
3. Reject if packet_age > TIMESTAMP_WINDOW_MS (30 seconds)
4. Reject if packet_age < -TIME_SYNC_TOLERANCE_MS (more than 50ms future)
5. Check for duplicate timestamp+session+sequence combination
6. Accept out-of-order packets within window if not duplicates
7. Add to timestamp cache for duplicate detection
8. Periodically cleanup expired cache entries

Security Properties:
- Prevents replay of packets older than 30 seconds
- Handles legitimate network reordering within window
- Detects duplicate packets through multi-attribute keys
- Resists clock skew attacks with future timestamp limits
- Maintains cache efficiency through periodic cleanup
```

## Session ID Management

### Adaptive Session ID Length

```pseudocode
Session ID Selection:
- 16-bit (65K sessions): IoT/embedded deployments
- 32-bit (4B sessions): Standard enterprise deployments  
- 64-bit (unlimited): Large-scale cloud deployments

Collision Handling:
- 16-bit: Use reuse queue for closed session IDs
- 32-bit: Random prefix + counter to reduce collisions
- 64-bit: Pure cryptographically random generation
```

## Deployment Configurations

### Standard Configurations

```pseudocode
// IoT/Embedded (ultra-compact)
iot_config = {
    session_id: SESSION_ID_16BIT,
    timestamp: TIMESTAMP_16BIT,     // 1.09 minutes max
    hmac_default: HMAC_LIGHT,
    header_size: 28 bytes          // 18 + 2 + 2 + 8 (HMAC_LIGHT)
}

// Standard Enterprise  
standard_config = {
    session_id: SESSION_ID_32BIT,
    timestamp: TIMESTAMP_24BIT,     // 4.66 hours max
    hmac_default: HMAC_LIGHT,
    header_size: 33 bytes          // 18 + 4 + 3 + 8 (HMAC_LIGHT)
}

// High Security
secure_config = {
    session_id: SESSION_ID_32BIT,
    timestamp: TIMESTAMP_24BIT,     // 4.66 hours max
    hmac_default: HMAC_STRONG,
    header_size: 57 bytes          // 18 + 4 + 3 + 32 (HMAC_STRONG)
}

// Infrastructure (long-lived)
infrastructure_config = {
    session_id: SESSION_ID_64BIT,
    timestamp: TIMESTAMP_32BIT,     // Full month max
    hmac_default: HMAC_MEDIUM,
    header_size: 46 bytes          // 18 + 8 + 4 + 16 (HMAC_MEDIUM)
}
```

## Packet Specifications

All packet types use the adaptive common header format with packet-specific payloads. The header size varies based on configuration, while payload structures remain consistent across deployments.

### SYN Packet (Type 0x01)

**When is it used**: Sent by the client to initiate a new connection to a server. Contains the client's ECDH public key and proposed configuration parameters.

```pseudocode
SYN Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x01   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
|      (Proposed by client)         |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
|           (Set to 0)              |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|      HMAC (HMAC_STRONG)         |
|           (32 bytes)             |
+-----------------------------------+
|    Client ECDH Public Key        |
|         (P-256 Point)            |
|           (64 bytes)             |
|                                 |
|                                 |
|                                 |
|                                 |
+-----------------------------------+
|       PSK Authentication         |
|           (16 bytes)             |
|                                 |
+-----------------------------------+
|  Key Exchange  | Initial Congestion|
|     ID         |    Window         |
+----------------+-------------------+
| Initial Receive|   Time Offset     |
|     Window     |    (32-bit)       |
+----------------+-------------------+
|    Supported Features (16-bit)   |
+-----------------------------------+
|       Reserved (16-bit)          |
+-----------------------------------+

Field Details:
- Flags: SYN flag (bit 1) set
- Session ID: Proposed session ID for the connection
- Sequence Number: Initial sequence number from client
- Client ECDH Public Key: P-256 public key for key exchange (64 bytes)
- PSK Authentication: HMAC of public key with PSK (16 bytes)
- Key Exchange ID: Unique identifier for this key exchange (16-bit)
- Initial Congestion Window: Client's initial congestion window size
- Initial Receive Window: Client's initial receive window size
- Time Offset: Client's time offset for synchronization
- Supported Features: Bitmap of client capabilities
- Reserved: Must be 0x0000

Total Size: Adaptive header + 108 bytes payload
```

### SYN-ACK Packet (Type 0x02)

**When is it used**: Sent by the server in response to a valid SYN packet from a client. Completes the server side of the three-way handshake.

```pseudocode
SYN-ACK Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x02   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
|    (Confirmed by server)          |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
|    (Client seq + 1)               |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|      HMAC (HMAC_STRONG)         |
|           (32 bytes)             |
+-----------------------------------+
|    Server ECDH Public Key        |
|         (P-256 Point)            |
|           (64 bytes)             |
|                                 |
|                                 |
|                                 |
|                                 |
+-----------------------------------+
|  Shared Secret Verification Hash |
|         (SHA256 Hash)            |
|        (32 bytes)                |
|                                 |
+-----------------------------------+
|  Key Exchange  | Initial Congestion|
|    ID Echo     |    Window         |
+----------------+-------------------+
| Initial Receive|   Time Offset     |
|     Window     |    (32-bit)       |
+----------------+-------------------+
|   Negotiated Features (16-bit)   |
+-----------------------------------+
|       Reserved (16-bit)          |
+-----------------------------------+

Field Details:
- Flags: SYN and ACK flags (bits 1,4) set
- Session ID: Confirmed session ID for the connection
- Acknowledgment Number: Client's sequence number + 1
- Server ECDH Public Key: Server's P-256 public key (64 bytes)
- Shared Secret Verification: SHA256 hash of computed shared secret (32 bytes)
- Key Exchange ID Echo: Echo of client's key exchange ID
- Negotiated Features: Final agreed capabilities

Total Size: Adaptive header + 124 bytes payload
```

### ACK Packet (Type 0x03)

**When is it used**: Sent to acknowledge received data, provide flow control updates, and handle selective acknowledgment for efficient loss recovery.

```pseudocode
ACK Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x03   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 32-128 bits)   |
+-----------------------------------+
|       Flow Control Header        |
|           (4 bytes)              |
+-----------------------------------+
|         SACK Header              |
|       (Variable Length)          |
|    (Present when SACK flag set)  |
+-----------------------------------+

Flow Control Header (4 bytes):
+-----------------------------------+
|       Window Size (16-bit)       |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+

SACK Header (when SACK flag set):
+-----------------------------------+
|    SACK Block Count (8-bit)      |
+-----------------------------------+
|      Primary SACK Bitmap         |
|        (32-bit)                  |
+-----------------------------------+
|   Additional SACK Ranges         |
|   (8 bytes per range)            |
|   Start Seq (32) + End Seq (32)  |
+-----------------------------------+

Field Details:
- Flags: ACK flag (bit 4) set, optionally SACK flag (bit 6)
- Flow Control Header: Always present, advertises receive window
- SACK Header: Present when selective acknowledgment needed

Total Size: Adaptive header + 4 bytes (basic) + variable SACK data
```

### DATA Packet (Type 0x04)

**When is it used**: Carries application data payload and handles fragmentation for large messages that exceed MTU limits.

```pseudocode
DATA Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x04   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+  
|  Timestamp (Variable Length)      |  
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 32-128 bits)   |
+-----------------------------------+
|       Flow Control Header        |
|           (4 bytes)              |
+-----------------------------------+
|      Fragmentation Header        |
|           (8 bytes)              |
|   (Present when Fragment flag set)|
+-----------------------------------+
|        Application Data          |
|        (Variable Length)         |
+-----------------------------------+

Fragmentation Header (when Fragment flag set):
+-----------------------------------+
|  Fragment ID     |Fragment Index |
|   (16-bit)       |   (16-bit)    |
+-------------------+---------------+
|  Total Frags     |   Reserved    |
|   (16-bit)       |   (16-bit)    |
+-------------------+---------------+

Field Details:
- Flags: PSH flag (bit 3) set, optionally Fragment flag (bit 7)
- Flow Control Header: Always present
- Fragmentation Header: Present when message fragmented
- Application Data: User payload or fragment data

Total Size: Adaptive header + 4 bytes + optional 8 bytes + payload
```

### FIN Packet (Type 0x05)

**When is it used**: Initiates graceful connection termination and signals that no more data will be sent.

```pseudocode
FIN Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x05   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|      HMAC (HMAC_STRONG)         |
|           (32 bytes)             |
+-----------------------------------+
|    Final Sequence Number         |
+-----------------------------------+

Field Details:
- Flags: FIN flag (bit 0) set
- Final Sequence Number: Last sequence number to be sent
- HMAC: Always full 128-bit for critical packets

Total Size: Adaptive header + 4 bytes payload
```

### HEARTBEAT Packet (Type 0x06)

**When is it used**: Maintains connection liveliness, synchronizes time between peers, and provides network performance feedback. Sent periodically (every 30 seconds) when no other data is being transmitted.

```pseudocode
HEARTBEAT Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x06   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 64-128 bits)   |
+-----------------------------------+
|       Flow Control Header        |
|           (4 bytes)              |
+-----------------------------------+
|        Current Time (32-bit)     |
+-----------------------------------+
|    Time Drift     |Sync State|Res|
|     (16-bit)      | (8-bit) |(8)|
+-------------------+---------+----+
|      Delay Negotiation Data      |
|           (8 bytes)              |
|                                 |
+-----------------------------------+

Field Details:
- Flags: ACK flag (bit 4) set
- Flow Control Header: Window advertisement
- Current Time: Sender's current timestamp
- Time Drift: Calculated time drift value
- Sync State: Current synchronization state
- Delay Negotiation Data: Network performance parameters

Total Size: Adaptive header + 20 bytes payload
```

### ERROR Packet (Type 0x09)

**When is it used**: Reports protocol errors, authentication failures, and other exceptional conditions to the peer. Sent when the protocol encounters errors that the peer needs to be informed about.

```pseudocode
ERROR Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x09   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 64-128 bits)   |
+-----------------------------------+
| Error Code|    Error Details     |
|  (8-bit) |      (24-bit)        |
+-----------------------------------+
|        Error Message              |
|        (Variable Length)          |
|                                 |
+-----------------------------------+

Field Details:
- Flags: RST flag (bit 2) may be set for critical errors
- Error Code: Specific error code from definitions
- Error Details: Additional error context information
- Error Message: Human-readable error description

Total Size: Adaptive header + 4 bytes + message length
```

### RST Packet (Type 0x0B)

**When is it used**: Immediately terminates a connection and rejects further communication attempts. Sent when connections must be immediately terminated due to errors, security violations, or invalid state transitions.

```pseudocode
RST Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x0B   | 0x00   | Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 64-128 bits)   |
+-----------------------------------+
| Reset Reason|      Reserved      |
|   (8-bit)   |     (24-bit)      |
+-----------------------------------+

Field Details:
- Flags: RST flag (bit 2) set
- Reset Reason: Reason code for connection reset
- Reserved: Must be 0x000000

Total Size: Adaptive header + 4 bytes payload
```

### CONTROL Packet (Type 0x0C)

**When is it used**: Handles various control operations including time synchronization and session recovery. Sent for time synchronization, session recovery operations, and sequence negotiations.

```pseudocode
CONTROL Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x0C   |Sub-Type| Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 64-128 bits)   |
+-----------------------------------+
|        Control Payload           |
|        (Variable Length)         |
|     Specific to Sub-Type         |
+-----------------------------------+

Sub-Type Specific Payloads:

TIME_SYNC_REQUEST (Sub-Type 0x01):
+-----------------------------------+
|    Challenge Nonce (32-bit)      |
+-----------------------------------+
|    Local Timestamp (32-bit)      |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+

TIME_SYNC_RESPONSE (Sub-Type 0x02):
+-----------------------------------+
|    Challenge Nonce (32-bit)      |
+-----------------------------------+
|    Local Timestamp (32-bit)      |
+-----------------------------------+
|    Peer Timestamp (32-bit)       |
+-----------------------------------+
|        Reserved (32-bit)         |
+-----------------------------------+

RECOVERY (Sub-Type 0x03):
+-----------------------------------+
|      Recovery Session ID         |
+-----------------------------------+
|    Last Known Sequence           |
+-----------------------------------+
| Congestion Window|  Send Window  |
+-------------------+---------------+
| Recovery Reason   |   Reserved   |
|     (8-bit)      |   (24-bit)   |
+-------------------+---------------+

Total Size: Adaptive header + 16 bytes payload (varies by sub-type)
```

### MANAGEMENT Packet (Type 0x0D)

**When is it used**: Handles session management operations including key rotation and sequence repair. Sent for session key rotation, sequence repair operations, and other session management functions.

```pseudocode
MANAGEMENT Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x0D   |Sub-Type| Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|   HMAC (Variable: 64-128 bits)   |
+-----------------------------------+
|      Management Payload          |
|        (Variable Length)         |
|     Specific to Sub-Type         |
+-----------------------------------+

Sub-Type Specific Payloads:

REKEY_REQUEST (Sub-Type 0x01):
+-----------------------------------+
|    Rekey Nonce (32-bit)         |
+-----------------------------------+
|   New Key Commitment (256-bit)   |
|                                 |
|                                 |
|                                 |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+

REKEY_RESPONSE (Sub-Type 0x02):
+-----------------------------------+
|    Rekey Nonce (32-bit)         |
+-----------------------------------+
|   New Key Commitment (256-bit)   |
|                                 |
|                                 |
|                                 |
+-----------------------------------+
|    Confirmation (128-bit)        |
|                                 |
+-----------------------------------+

REPAIR_REQUEST (Sub-Type 0x03):
+-----------------------------------+
|    Repair Nonce (32-bit)         |
+-----------------------------------+
| Last Known Sequence (32-bit)     |
+-----------------------------------+
| Repair Window Size (32-bit)      |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+

REPAIR_RESPONSE (Sub-Type 0x04):
+-----------------------------------+
|    Repair Nonce (32-bit)         |
+-----------------------------------+
| Current Sequence (32-bit)        |
+-----------------------------------+
| Repair Window Size (32-bit)      |
+-----------------------------------+
|    Confirmation (64-bit)         |
+-----------------------------------+

Total Size: Adaptive header + 16-52 bytes payload (varies by sub-type)
```

### DISCOVERY Packet (Type 0x0E)

**When is it used**: Handles pre-shared key (PSK) discovery and selection for secure connection establishment. Sent during connection establishment when PSK discovery is required to identify the correct shared key.

```pseudocode
DISCOVERY Packet Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| 0x0E   |Sub-Type| Flags  |
+--------+--------+--------+--------+
|    Session ID (Variable Length)   |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|  Timestamp (Variable Length)      |
+-----------------------------------+
|    Payload Length (16-bit)       |
+-----------------------------------+
|      HMAC (HMAC_STRONG)         |
|           (32 bytes)             |
+-----------------------------------+
|       Discovery Payload          |
|        (Variable Length)         |
|     Specific to Sub-Type         |
+-----------------------------------+

Sub-Type Specific Payloads:

DISCOVERY_REQUEST (Sub-Type 0x01):
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|       Session Salt (32-bit)      |
+-----------------------------------+
| Fingerprint Count|Bloom Filter   |
|     (16-bit)     | Size (16-bit) |
+-------------------+---------------+
| Initiator Features|   Reserved   |
|    (16-bit)      |   (16-bit)   |
+-------------------+---------------+
|     Bloom Filter Data            |
|     (Variable Length)            |
|    (512 bytes maximum)           |
+-----------------------------------+

DISCOVERY_RESPONSE (Sub-Type 0x02):
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|   Candidate Count (16-bit)       |
+-----------------------------------+
|  Intersection Status (16-bit)    |
+-----------------------------------+
| Responder Features|   Reserved   |
|    (16-bit)      |   (16-bit)   |
+-------------------+---------------+
|    Candidate Intersection        |
|         Hashes                   |
|   (32 bytes per candidate)       |
|   (Variable Length)              |
+-----------------------------------+

DISCOVERY_CONFIRM (Sub-Type 0x03):
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|    Confirmation Hash (256-bit)   |
|   (Selected PSK fingerprint      |
|    confirmation hash)            |
|                                 |
+-----------------------------------+
|  Confirmation Status (16-bit)    |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+
|        Session ID (64-bit)        |
+-----------------------------------+
|      Reserved (16-bit)            |
+-----------------------------------+
|        Commitment (128-bit)        |
|                                 |
+-----------------------------------+

Total Size: Adaptive header + 20-582 bytes payload (varies by sub-type)
```

## Configuration Negotiation

During connection establishment, peers negotiate the optimal configuration through the SYN/SYN-ACK exchange:

1. **SYN**: Client proposes configuration via version byte encoding
2. **SYN-ACK**: Server confirms or modifies configuration  
3. **Subsequent packets**: Use the negotiated format consistently

The negotiated configuration includes:
- Session ID length (16-bit, 32-bit, or 64-bit)
- Timestamp size (16-bit, 24-bit, or 32-bit)  
- HMAC policy (based on security requirements)

This provides optimal efficiency for each deployment scenario while maintaining protocol compatibility.

## HMAC Policy Framework

The protocol uses three HMAC policies balancing security and performance requirements across packet types and connection states. Each policy defines cryptographic parameters and authentication scope.

### HMAC Policy Definitions

**HMAC_LIGHT (Policy 1):**
- Algorithm: HMAC-SHA256 truncated to 64 bits
- Key Length: 128 bits (16 bytes)
- Output Length: 64 bits (8 bytes)
- Authenticated Components: Type, sub-type, session ID, sequence, timestamp, payload
- Use Case: High-frequency packets requiring performance optimization

**HMAC_MEDIUM (Policy 2):**
- Algorithm: HMAC-SHA256 truncated to 128 bits
- Key Length: 256 bits (32 bytes) 
- Output Length: 128 bits (16 bytes)
- Authenticated Components: All header fields and payload
- Use Case: Standard authentication for most packet types

**HMAC_STRONG (Policy 3):**
- Algorithm: HMAC-SHA512 truncated to 256 bits
- Key Length: 512 bits (64 bytes)
- Output Length: 256 bits (32 bytes)
- Authenticated Components: Full header, payload, and connection context hash
- Use Case: Security-critical operations and high-security deployments

### HMAC Policy Application Guidelines

**Connection Establishment:**
- SYN packets: HMAC_STRONG (security-critical)
- SYN-ACK packets: HMAC_STRONG (security-critical)
- ACK packets (handshake): HMAC_MEDIUM (completion)

**Control Packets:**
- Time synchronization: HMAC_MEDIUM (important for port hopping)
- Heartbeat: HMAC_LIGHT (high frequency, low security impact)
- Port hopping coordination: HMAC_MEDIUM (security-relevant)

**Management Packets:**
- Recovery requests: HMAC_STRONG (session continuity critical)
- Error packets: HMAC_MEDIUM (important for debugging)
- Flow control: HMAC_LIGHT (high frequency, performance-sensitive)

**Discovery Packets:**
- PSK discovery: HMAC_STRONG (prevents PSK enumeration attacks)
- Discovery response: HMAC_STRONG (confirms PSK match)

**Data Packets:**
- Regular data: HMAC_LIGHT (default) or HMAC_MEDIUM (configurable)
- Fragmented data: HMAC_MEDIUM (fragmentation adds complexity)
- Priority data: HMAC_MEDIUM (higher importance)

**Special Circumstances:**
- Recovery mode: All operations use HMAC_STRONG
- High security mode: All packets use HMAC_STRONG
- Performance mode: HMAC_LIGHT for all except connection establishment

### Security Mode Configuration

HMAC policy selection is controlled by deployment security mode:

- **SECURITY_MODE_PERFORMANCE**: Use HMAC_LIGHT where possible
- **SECURITY_MODE_BALANCED**: Use standard policy guidelines (default)  
- **SECURITY_MODE_HIGH_SECURITY**: Use HMAC_STRONG for all operations

This framework provides appropriate authentication strength while maintaining performance efficiency across deployment scenarios.