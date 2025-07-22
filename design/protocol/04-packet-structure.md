# Complete Packet Format Specifications

## Overview

This document defines the complete packet format specifications for the protocol, including all packet types, header structures, and field definitions. The packet format provides the fundamental data structures used for all network communication between peers.

## Purpose and Rationale

The packet format specification serves several critical functions:

- **Protocol Foundation**: Defines the basic communication units that enable all protocol functionality
- **Header Optimization**: Provides an optimized common header format that reduces overhead while maintaining necessary information
- **Type Consolidation**: Consolidates multiple legacy packet types into fewer, more efficient types with sub-type extensions
- **Field Efficiency**: Moves conditional fields to packet payloads to minimize header size for all packets
- **Extensibility**: Provides sub-type mechanisms that allow future protocol extensions without breaking compatibility

The optimized design reduces the common header from 64 to 50 bytes (21.9% reduction) while maintaining all necessary functionality and providing better extensibility through the sub-type architecture.

## Key Concepts

- **Common Header**: A standardized 50-byte header present in all packets containing essential routing and authentication information
- **Packet Types**: 11 base packet types that handle all protocol communication needs
- **Sub-Types**: Extension mechanism for CONTROL, MANAGEMENT, and DISCOVERY packets that provides functionality consolidation
- **Conditional Fields**: Header fields moved to packet payloads when not needed by all packet types
- **HMAC Authentication**: 128-bit authentication field in every packet header ensuring message integrity and authenticity

## Packet Type Definitions (Standardized)
```pseudocode
// Optimized packet types with sub-types
PACKET_TYPE_SYN = 0x01                  // Connection establishment
PACKET_TYPE_SYN_ACK = 0x02              // Connection establishment response
PACKET_TYPE_ACK = 0x03                  // Acknowledgment (includes WINDOW_UPDATE and SACK)
PACKET_TYPE_DATA = 0x04                 // Data packet (includes FRAGMENT functionality)
PACKET_TYPE_FIN = 0x05                  // Connection termination
PACKET_TYPE_HEARTBEAT = 0x06            // Keep-alive packet
PACKET_TYPE_ERROR = 0x09                // Error packet
PACKET_TYPE_RST = 0x0B                  // Reset connection
PACKET_TYPE_CONTROL = 0x0C              // Control operations (TIME_SYNC, RECOVERY, etc.)
PACKET_TYPE_MANAGEMENT = 0x0D           // Management operations (REKEY, REPAIR)
PACKET_TYPE_DISCOVERY = 0x0E            // PSK discovery with sub-types

// CONTROL packet sub-types
CONTROL_SUB_TIME_SYNC_REQUEST = 0x01    // Time synchronization request
CONTROL_SUB_TIME_SYNC_RESPONSE = 0x02   // Time synchronization response
CONTROL_SUB_RECOVERY = 0x03             // Session recovery
CONTROL_SUB_EMERGENCY_REQUEST = 0x04    // Emergency recovery request
CONTROL_SUB_EMERGENCY_RESPONSE = 0x05   // Emergency recovery response
CONTROL_SUB_SEQUENCE_NEG = 0x06         // Sequence number negotiation
CONTROL_SUB_EMERGENCY_VERIFY = 0x07     // Emergency recovery verification

// MANAGEMENT packet sub-types
MANAGEMENT_SUB_REKEY_REQUEST = 0x01     // Session key rotation request
MANAGEMENT_SUB_REKEY_RESPONSE = 0x02    // Session key rotation response
MANAGEMENT_SUB_REPAIR_REQUEST = 0x03    // Sequence repair request
MANAGEMENT_SUB_REPAIR_RESPONSE = 0x04   // Sequence repair response

// DISCOVERY packet sub-types
DISCOVERY_SUB_REQUEST = 0x01            // PSK discovery request
DISCOVERY_SUB_RESPONSE = 0x02           // PSK discovery response
DISCOVERY_SUB_CONFIRM = 0x03            // PSK discovery confirmation
```

## Optimized Common Header Format (All Packets)
```pseudocode
Optimized Common Header Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| Type   |Sub-Type| Flags  |
+--------+--------+--------+--------+
|          Session ID (64-bit)      |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|      Timestamp (32-bit)          |
+-----------------------------------+
|       Payload Length (16-bit)    |
+-----------------------------------+
|           HMAC (128-bit)         |
|                                 |
+-----------------------------------+

Field Definitions:
- Version (8-bit): Protocol version (0x02 for optimized header)
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
- Session ID (64-bit): Unique session identifier (big-endian)
- Sequence Number (32-bit): Packet sequence number (big-endian)
- Acknowledgment Number (32-bit): Next expected sequence (big-endian, 0 if not applicable)
- Timestamp (32-bit): Packet timestamp in milliseconds since UTC midnight of current day (big-endian)
- Payload Length (16-bit): Length of payload data in bytes (big-endian)
- HMAC (128-bit): Authentication hash using session key (big-endian)

Total Optimized Header Size: 50 bytes (14 bytes smaller than original)

## Conditional Fields (Moved to Packet Payloads)

### Flow Control Fields (when needed)
```pseudocode
Flow Control Header (4 bytes):
+-----------------------------------+
|       Window Size (16-bit)       |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+
```
Used in: ACK, DATA, HEARTBEAT packets

### Fragmentation Fields (when Fragment flag set)
```pseudocode
Fragmentation Header (8 bytes):
+-----------------------------------+
|  Fragment ID     |Fragment Index |
|   (16-bit)       |   (16-bit)    |
+-------------------+---------------+
|  Total Frags     |   Reserved    |
|   (16-bit)       |   (16-bit)    |
+-------------------+---------------+
```
Used in: DATA packets when fragmented

### Selective ACK Fields (when SACK flag set)
```pseudocode
SACK Header (Variable length):
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
```
Used in: ACK packets when selective acknowledgment needed
```

## Packet Type Specifications

### SYN Packet (Type 0x01)

**Purpose**: Initiates a new connection between peers and establishes the initial protocol parameters.

**Why it exists**: The SYN packet serves as the first step in the three-way handshake, allowing peers to:
- Negotiate initial sequence numbers using zero-knowledge commitments for security
- Exchange supported protocol features and capabilities
- Establish initial flow control windows
- Synchronize time offsets for port hopping coordination
- Begin the secure session establishment process

**When used**: Sent by the client to initiate a new connection to a server.

```pseudocode
SYN Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|   Sequence Commitment (32-bit)   |
+-----------------------------------+
| Initial Congestion|Initial Receive|
|     Window        |    Window     |
+-------------------+---------------+
|      Time Offset (32-bit)        |
+-----------------------------------+
|    Supported Features (16-bit)   |
+-----------------------------------+
|   Sequence Nonce (16-bit)        |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with SYN flag set
- Sequence Commitment (32-bit): Zero-knowledge commitment to initial sequence number (4 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Client's time offset from epoch (4 bytes)
- Supported Features (16-bit): Bitmap of supported features (2 bytes)
- Sequence Nonce (16-bit): Nonce for sequence number commitment (2 bytes)

Total SYN Packet Size: 50 + 18 = 68 bytes
```

### SYN-ACK Packet (Type 0x02)

**Purpose**: Responds to a SYN packet, acknowledging the connection request and providing server-side parameters.

**Why it exists**: The SYN-ACK packet completes the server side of the three-way handshake by:
- Acknowledging the client's SYN and sequence commitment
- Providing the server's own sequence commitment and parameters
- Validating the client's sequence number using zero-knowledge proofs
- Negotiating final protocol features and capabilities
- Establishing mutual time synchronization and flow control windows

**When used**: Sent by the server in response to a valid SYN packet from a client.

```pseudocode
SYN-ACK Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|   Sequence Commitment (32-bit)   |
+-----------------------------------+
|   Sequence Proof (32-bit)        |
+-----------------------------------+
| Initial Congestion|Initial Receive|
|     Window        |    Window     |
+-------------------+---------------+
|      Time Offset (32-bit)        |
+-----------------------------------+
|   Negotiated Features (16-bit)   |
+-----------------------------------+
|   Sequence Nonce (16-bit)        |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with SYN and ACK flags set
- Sequence Commitment (32-bit): Zero-knowledge commitment to server's initial sequence number (4 bytes)
- Sequence Proof (32-bit): Zero-knowledge proof validating client's sequence commitment (4 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Server's time offset from epoch (4 bytes)
- Negotiated Features (16-bit): Final feature bitmap (2 bytes)
- Sequence Nonce (16-bit): Nonce for server's sequence number commitment (2 bytes)

Total SYN-ACK Packet Size: 50 + 22 = 72 bytes
```

### ACK Packet (Type 0x03)

**Purpose**: Acknowledges received data, provides flow control updates, and handles selective acknowledgment for efficient loss recovery.

**Why it exists**: The ACK packet is essential for reliable data delivery and network efficiency:
- Confirms successful receipt of data packets to enable sender buffer cleanup
- Provides flow control by advertising current receive window size
- Implements selective acknowledgment (SACK) to efficiently recover from packet loss
- Replaces the separate WINDOW_UPDATE packet for better efficiency
- Enables precise congestion control feedback for optimal throughput

**When used**: Sent in response to DATA packets, for flow control updates, or to acknowledge connection establishment.

```pseudocode
Optimized ACK Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|       Flow Control Header        |
|           (4 bytes)              |
+-----------------------------------+
|         SACK Header              |
|       (Variable Length)          |
|    (Present when SACK flag set)  |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with ACK flag set
- Flow Control Header (4 bytes): Always present in ACK packets
  - Window Size (16-bit): Current receive window size
  - Reserved (16-bit): Always 0x0000
- SACK Header (Variable): Present when SACK flag (bit 6) is set
  - SACK Block Count (8-bit): Number of additional SACK ranges (0-15)
  - Primary SACK Bitmap (32-bit): Basic SACK information for recent packets
  - Additional SACK Ranges (8 bytes each): Extended ranges for complex loss patterns
    - Start Sequence (32-bit) + End Sequence (32-bit) per range

Usage:
- Basic ACK: Common header + Flow control header (54 bytes)
- ACK with SACK: Basic ACK + SACK header (59+ bytes depending on ranges)
- Window Update: Flow control header provides window advertisement

Total ACK Packet Size: 54 bytes (basic) + 5 + 8*N bytes (SACK with N ranges)
```

### DATA Packet (Type 0x04)

**Purpose**: Carries application data payload and handles fragmentation for large messages that exceed MTU limits.

**Why it exists**: The DATA packet is the primary vehicle for application data transmission:
- Transports application layer data reliably between peers
- Integrates fragmentation capabilities to handle large payloads that exceed network MTU
- Provides flow control information to prevent receiver buffer overflow
- Maintains sequence ordering for reliable data delivery
- Replaces the separate FRAGMENT packet type for better efficiency

**When used**: Sent whenever application data needs to be transmitted, including both regular and fragmented data.

```pseudocode
Optimized DATA Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|       Flow Control Header        |
|           (4 bytes)              |
+-----------------------------------+
|      Fragmentation Header        |
|           (8 bytes)              |
|   (Present when Fragment flag set)|
+-----------------------------------+
|        Payload Data              |
|        (Variable Length)         |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with PSH flag set
- Flow Control Header (4 bytes): Always present in DATA packets
  - Window Size (16-bit): Current receive window advertisement
  - Reserved (16-bit): Always 0x0000
- Fragmentation Header (8 bytes): Present when Fragment flag (bit 7) is set
  - Fragment ID (16-bit): Unique identifier for fragmented messages
  - Fragment Index (16-bit): Position of this fragment (0-based)
  - Total Frags (16-bit): Total fragments in message
  - Reserved (16-bit): Always 0x0000
- Payload Data (Variable Length): Application data or fragment data

Usage:
- Regular Data: Common header + Flow control header + Payload (54 + payload_length bytes)
- Fragmented Data: All headers + Payload (62 + payload_length bytes)

Total DATA Packet Size: 54 + payload_length bytes (regular) or 62 + payload_length bytes (fragmented)
```

### FIN Packet (Type 0x05)

**Purpose**: Initiates graceful connection termination and signals that no more data will be sent.

**Why it exists**: The FIN packet enables orderly connection shutdown:
- Signals to the peer that the sender has finished sending data
- Provides the final sequence number to ensure all data has been received
- Initiates the graceful shutdown handshake process
- Allows proper cleanup of connection resources
- Distinguishes between graceful shutdown and error conditions

**When used**: Sent when an application or protocol layer wants to close a connection gracefully.

```pseudocode
FIN Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|    Final Sequence Number         |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with FIN flag set
- Final Sequence Number (32-bit): Final sequence number

Total FIN Packet Size: 50 + 4 = 54 bytes
```

### HEARTBEAT Packet (Type 0x06)

**Purpose**: Maintains connection liveliness, synchronizes time between peers, and provides network performance feedback.

**Why it exists**: The HEARTBEAT packet serves multiple critical maintenance functions:
- Detects if the connection is still alive and the peer is responsive
- Provides time synchronization information to maintain port hopping coordination
- Measures network latency and jitter for adaptive delay tuning
- Advertises flow control window status during idle periods
- Carries delay negotiation data for network performance optimization

**When used**: Sent periodically (every 30 seconds) when no other data is being transmitted to maintain connection health.

```pseudocode
Optimized HEARTBEAT Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
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

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with ACK flag set
- Flow Control Header (4 bytes): Window advertisement
  - Window Size (16-bit): Current receive window size
  - Reserved (16-bit): Always 0x0000
- Current Time (32-bit): Sender's current time in milliseconds since UTC midnight
- Time Drift (16-bit): Calculated time drift
- Sync State (8-bit): Current synchronization state
- Reserved (8-bit): Always 0x00
- Delay Negotiation Data (64-bit): Compact delay adaptation parameters
  - Bits 0-7: Current delay window (1-16 time windows)
  - Bits 8-19: Network jitter (0-4095ms)
  - Bits 20-29: Packet loss rate (0-1023 per-mille)
  - Bits 30-37: Measurement sample count (0-255)
  - Bits 38-47: Negotiation sequence (rolling counter)
  - Bit 48: Adaptation enabled flag
  - Bits 49-63: Reserved for future use

Optimized HEARTBEAT Packet Size: 50 + 4 + 16 = 70 bytes (10 bytes smaller than original)
```


### ERROR Packet (Type 0x09)

**Purpose**: Reports protocol errors, authentication failures, and other exceptional conditions to the peer.

**Why it exists**: The ERROR packet enables robust error handling and debugging:
- Provides structured error reporting with specific error codes
- Enables the peer to understand why operations failed
- Supports debugging and troubleshooting of protocol issues
- Allows graceful error recovery when possible
- Includes human-readable error messages for diagnostic purposes

**When used**: Sent when the protocol encounters errors that the peer needs to be informed about, such as authentication failures, invalid packets, or state machine violations.

```pseudocode
ERROR Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
| Error Code|    Error Details     |
|  (8-bit) |      (24-bit)        |
+-----------------------------------+
|        Error Message              |
|        (Variable Length)          |
|                                 |
|                                 |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with RST flag set
- Error Code (8-bit): Specific error code
- Error Details (24-bit): Additional error information
- Error Message (Variable Length): Human-readable error message

Total ERROR Packet Size: 50 + 4 + error_message_length bytes
```

### CONTROL Packet (Type 0x0C)

**Purpose**: Handles various control operations including time synchronization, session recovery, and emergency procedures.

**Why it exists**: The CONTROL packet consolidates multiple control functions into a single packet type for efficiency:
- Provides time synchronization for coordinated port hopping between peers
- Enables enhanced session recovery with detailed state information
- Supports emergency recovery procedures with cryptographic verification
- Handles sequence number negotiation for secure connection establishment
- Replaces multiple legacy packet types with a unified, extensible control framework

**When used**: Sent for time synchronization, session recovery operations, emergency procedures, and sequence negotiations.

```pseudocode
CONTROL Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
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
Total: 50 + 16 = 66 bytes

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
Total: 50 + 16 = 66 bytes

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
Total: 50 + 16 = 66 bytes

SEQUENCE_NEG (Sub-Type 0x06):
+-----------------------------------+
|   Negotiation Phase (8-bit)      |
+-----------------------------------+
|   Sequence Commitment (32-bit)   |
+-----------------------------------+
|   Sequence Proof (32-bit)        |
+-----------------------------------+
|   Challenge Nonce (32-bit)       |
+-----------------------------------+
|        Reserved (24-bit)         |
+-----------------------------------+
Total: 50 + 16 = 66 bytes

EMERGENCY_VERIFY (Sub-Type 0x07):
+-----------------------------------+
|      Test Data (32-bit)          |
+-----------------------------------+
|      Expected HMAC (128-bit)     |
|                                 |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+
Total: 50 + 24 = 74 bytes
```

### RST Packet (Type 0x0B)

**Purpose**: Immediately terminates a connection and rejects further communication attempts.

**Why it exists**: The RST packet provides forceful connection termination for error conditions:
- Enables immediate connection shutdown when errors prevent normal operation
- Rejects connection attempts to invalid or unauthorized sessions
- Provides a clear signal that the connection cannot or should not continue
- Distinguishes between graceful shutdown (FIN) and forceful termination (RST)
- Includes a reason code to help diagnose why the connection was reset

**When used**: Sent when connections must be immediately terminated due to errors, security violations, or invalid state transitions.

```pseudocode
RST Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
| Reset Reason|      Reserved      |
|   (8-bit)   |     (24-bit)      |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with RST flag set
- Reset Reason (8-bit): Reason for reset
- Reserved (24-bit): Always 0x000000

Total RST Packet Size: 50 + 4 = 54 bytes
```

### MANAGEMENT Packet (Type 0x0D)

**Purpose**: Handles session management operations including key rotation and sequence repair.

**Why it exists**: The MANAGEMENT packet provides essential session maintenance capabilities:
- Enables secure session key rotation to maintain forward secrecy
- Provides sequence number repair mechanisms for connection recovery
- Supports session rekeying with cryptographic key exchange
- Consolidates management operations into a unified packet type for efficiency
- Maintains session security through periodic cryptographic updates

**When used**: Sent for session key rotation, sequence repair operations, and other session management functions.

```pseudocode
MANAGEMENT Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
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
Total: 50 + 44 = 94 bytes

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
Total: 50 + 52 = 102 bytes

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
Total: 50 + 16 = 66 bytes

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
Total: 50 + 16 = 66 bytes
```

### DISCOVERY Packet (Type 0x0E)

**Purpose**: Handles pre-shared key (PSK) discovery and selection for secure connection establishment.

**Why it exists**: The DISCOVERY packet enables secure key discovery in environments with multiple PSKs:
- Allows peers to identify which PSK to use without exposing key material
- Provides cryptographic commitments to prevent key enumeration attacks
- Supports multiple PSK environments with secure selection mechanisms
- Consolidates discovery phases into sub-types for efficient protocol flow
- Enables secure PSK negotiation while maintaining zero-knowledge properties

**When used**: Sent during connection establishment when PSK discovery is required to identify the correct shared key.

```pseudocode
DISCOVERY Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
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
|    PSK Count     |Challenge Nonce|
|    (16-bit)      |   (64-bit)   |
+-------------------+---------------+
| Initiator Features|   Reserved   |
|    (16-bit)      |   (16-bit)   |
+-------------------+---------------+
|        Commitment (128-bit)       |
|                                 |
+-----------------------------------+
Total: 50 + 36 = 86 bytes

DISCOVERY_RESPONSE (Sub-Type 0x02):
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|    PSK Count     |Challenge Nonce|
|    (16-bit)      |   (64-bit)   |
+-------------------+---------------+
|        Response Nonce (64-bit)    |
+-----------------------------------+
|        PSK Commitment (64-bit)    |
+-----------------------------------+
| Responder Features|   Reserved   |
|    (16-bit)      |   (16-bit)   |
+-------------------+---------------+
|        Commitment (128-bit)       |
|                                 |
+-----------------------------------+
Total: 50 + 52 = 102 bytes

DISCOVERY_CONFIRM (Sub-Type 0x03):
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|Selected PSK Index|Challenge Nonce|
|    (16-bit)      |   (64-bit)   |
+-------------------+---------------+
|        Response Nonce (64-bit)    |
+-----------------------------------+
|   PSK Selection Commitment       |
|        (64-bit)                  |
+-----------------------------------+
|        Session ID (64-bit)        |
+-----------------------------------+
|      Reserved (16-bit)            |
+-----------------------------------+
|        Commitment (128-bit)        |
|                                 |
+-----------------------------------+
Total: 50 + 52 = 102 bytes
```
