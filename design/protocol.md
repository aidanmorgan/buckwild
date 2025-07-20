# Protocol Specification: Connection Management and Synchronization

## Overview

This document defines the complete specification for connection establishment, port hopping synchronization, and recovery mechanisms in the frequency hopping network system. The protocol ensures reliable communication while maintaining synchronized port transitions between endpoints using only pre-shared keys and time-based synchronization.

## Protocol Constants and Default Values

### Core Protocol Constants
```pseudocode
// Time-related constants
HOP_INTERVAL_MS = 250                    // Port hop interval in milliseconds (250ms time windows)
TIME_SYNC_TOLERANCE_MS = 50              // Maximum allowed clock drift
HEARTBEAT_INTERVAL_MS = 30000            // Heartbeat interval (30 seconds)
HEARTBEAT_TIMEOUT_MS = 90000             // Heartbeat timeout (90 seconds)
MAX_PACKET_LIFETIME_MS = 60000           // Maximum packet age (60 seconds)
TIMESTAMP_WINDOW_MS = 30000              // Anti-replay timestamp window
SAFETY_MARGIN_MS = 100                   // Safety margin for delay calculations
TRANSMISSION_DELAY_ALLOWANCE_MS = 50     // Allowance for network transmission delay
MILLISECONDS_PER_DAY = 86400000          // Milliseconds in a day (for timestamp calculation)

// Sequence and window constants
INITIAL_SEQUENCE_NUMBER = 0x12345678     // Initial sequence number
MAX_SEQUENCE_NUMBER = 0xFFFFFFFF         // Maximum sequence number
SEQUENCE_WRAP_THRESHOLD = 0x80000000     // Threshold for sequence wraparound
INITIAL_CONGESTION_WINDOW = 1460         // Initial congestion window (bytes)
MIN_CONGESTION_WINDOW = 292              // Minimum congestion window (bytes)
MAX_CONGESTION_WINDOW = 65535            // Maximum congestion window (bytes)
INITIAL_RECEIVE_WINDOW = 65535           // Initial receive window (bytes)
MAX_RECEIVE_WINDOW = 65535               // Maximum receive window (bytes)

// Retransmission and timeout constants
MIN_RETRANSMISSION_TIMEOUT_MS = 200      // Minimum RTO
MAX_RETRANSMISSION_TIMEOUT_MS = 60000    // Maximum RTO
ACK_DELAY_MS = 50                        // ACK delay for batching
MAX_ACK_BATCH_SIZE = 10                  // Maximum ACKs per batch
CONNECTION_TIMEOUT_MS = 30000            // Connection establishment timeout
STATE_TIMEOUT_MS = 30000                 // State transition timeout
TIME_WAIT_TIMEOUT_MS = 60000             // TIME_WAIT state timeout

// RTO calculation constants (RFC 6298)
RTT_ALPHA = 0.875                        // RTT smoothing factor
RTT_BETA = 0.125                         // RTT variance factor
RTT_G = 0.25                             // RTT gain factor
RTT_K = 4                                // RTT variance multiplier
RTT_INITIAL_MS = 1000                    // Initial RTT estimate
RTT_MIN_MS = 100                         // Minimum RTT
RTT_MAX_MS = 60000                       // Maximum RTT

// Buffer and memory constants
REORDER_BUFFER_SIZE = 1000               // Maximum out-of-order packets
RECENT_SEQUENCES_SIZE = 100              // Recent sequence number cache
RECENT_TIMESTAMPS_SIZE = 1000            // Recent timestamp cache for replay detection
PORT_HISTORY_SIZE = 10                   // Number of recent ports to track

// Retry and attempt limits
MAX_RETRANSMISSION_ATTEMPTS = 8          // Maximum retransmission attempts
MAX_RECOVERY_ATTEMPTS = 5                // Maximum recovery attempts
MAX_SYNC_FAILURES = 3                    // Maximum sync failures before emergency

// Port and network constants
MIN_PORT = 1024                          // Minimum port (expanded range)
MAX_PORT = 65535                         // Maximum port
PORT_RANGE = 64512                       // Available port range (65535-1024+1)
DISCOVERY_PORT = 1025                   // Well-known port for discovery process
DEFAULT_MTU = 1500                       // Default MTU size
FRAGMENTATION_THRESHOLD = 1400           // Size threshold for fragmentation
MAX_FRAGMENTS = 255                      // Maximum fragments per packet

// Congestion control constants
SLOW_START_THRESHOLD = 65535             // Initial slow start threshold
CONGESTION_AVOIDANCE_INCREMENT = 1       // Window increment in congestion avoidance
FAST_RECOVERY_MULTIPLIER = 0.5          // Window reduction in fast recovery
MSS = 1460                               // Maximum segment size in bytes
MAX_CONGESTION_WINDOW = 65535            // Maximum congestion window size
MIN_CONGESTION_WINDOW = 292              // Minimum congestion window size
MAX_RECEIVE_WINDOW = 65535               // Maximum receive window size
MIN_RECEIVE_WINDOW = 1024                // Minimum receive window size

// Congestion control states
SLOW_START = 1                           // Slow start state
CONGESTION_AVOIDANCE = 2                 // Congestion avoidance state
FAST_RECOVERY = 3                        // Fast recovery state

// Discovery and zero-knowledge proof constants
MAX_PSK_COUNT = 256                     // Maximum number of PSKs per peer
DISCOVERY_TIMEOUT_MS = 10000            // Discovery process timeout (10 seconds)
DISCOVERY_RETRY_COUNT = 3               // Maximum discovery retry attempts
PEDERSEN_COMMITMENT_SIZE = 64           // Size of Pedersen commitment in bytes
DISCOVERY_CHALLENGE_SIZE = 32           // Size of challenge nonce in bytes
PSK_ID_LENGTH = 32                      // Length of PSK identifier
FRAGMENT_TIMEOUT_MS = 30000             // Fragment reassembly timeout (30 seconds)
BLOCK_DURATION_MS = 300000              // Block duration for enumeration attempts (5 minutes)
REPLAY_THRESHOLD = 5                    // Threshold for replay attack detection

// Discovery states
DISCOVERY_IDLE = 0                      // No discovery in progress
DISCOVERY_INITIATED = 1                 // Discovery initiated, waiting for response
DISCOVERY_RESPONDED = 2                 // Discovery response received, waiting for confirmation
DISCOVERY_COMPLETED = 3                 // Discovery completed, PSK selected
DISCOVERY_FAILED = 4                    // Discovery failed, no common PSK found
```

### Error Codes
```pseudocode
// Protocol error codes
ERROR_SUCCESS = 0x00
ERROR_INVALID_PACKET = 0x01
ERROR_AUTHENTICATION_FAILED = 0x02
ERROR_TIMESTAMP_INVALID = 0x03
ERROR_REPLAY_ATTACK = 0x04
ERROR_SESSION_NOT_FOUND = 0x05
ERROR_STATE_INVALID = 0x06
ERROR_WINDOW_OVERFLOW = 0x07
ERROR_SEQUENCE_INVALID = 0x08
ERROR_FRAGMENT_INVALID = 0x09
ERROR_SYNC_FAILED = 0x0A
ERROR_RECOVERY_FAILED = 0x0B
ERROR_TIMEOUT = 0x0C
ERROR_MEMORY_EXHAUSTED = 0x0D
ERROR_INVALID_PARAMETER = 0x0E
ERROR_PORT_CALCULATION_FAILED = 0x0F
ERROR_FRAGMENT_REASSEMBLY_FAILED = 0x10
ERROR_CONGESTION_CONTROL_FAILED = 0x11
ERROR_DISCOVERY_FAILED = 0x12
ERROR_PSK_NOT_FOUND = 0x13
ERROR_ZERO_KNOWLEDGE_PROOF_FAILED = 0x14
ERROR_DISCOVERY_TIMEOUT = 0x15
ERROR_PEDERSEN_COMMITMENT_FAILED = 0x16
ERROR_PSK_ENUMERATION_ATTEMPT = 0x17
```

## Complete Packet Format Specifications

### Packet Type Definitions (Standardized)
```pseudocode
// Standardized packet types
PACKET_TYPE_SYN = 0x01                  // Connection establishment
PACKET_TYPE_SYN_ACK = 0x02              // Connection establishment response
PACKET_TYPE_ACK = 0x03                  // Acknowledgment
PACKET_TYPE_DATA = 0x04                 // Data packet
PACKET_TYPE_FIN = 0x05                  // Connection termination
PACKET_TYPE_HEARTBEAT = 0x06            // Keep-alive packet
PACKET_TYPE_RECOVERY = 0x07             // Session recovery
PACKET_TYPE_FRAGMENT = 0x08             // Fragmented data packet
PACKET_TYPE_ERROR = 0x09                // Error packet
PACKET_TYPE_WINDOW_UPDATE = 0x0A        // Flow control update
PACKET_TYPE_RST = 0x0B                  // Reset connection
PACKET_TYPE_DISCOVERY = 0x0C            // PSK discovery with zero-knowledge proof
PACKET_TYPE_DISCOVERY_RESPONSE = 0x0D   // PSK discovery response
PACKET_TYPE_DISCOVERY_CONFIRM = 0x0E    // PSK discovery confirmation
```

### Common Header Format (All Packets)
```pseudocode
Common Header Structure (Big-Endian):
+--------+--------+--------+--------+
| Version| Type   | Flags  |Reserved|
+--------+--------+--------+--------+
|          Session ID (64-bit)      |
+-----------------------------------+
|       Sequence Number (32-bit)    |
+-----------------------------------+
|    Acknowledgment Number (32-bit) |
+-----------------------------------+
|      Timestamp (32-bit)          |
+-----------------------------------+
|    Window Size     | Fragment ID |
+-------------------+---------------+
|  Fragment Index   | Total Frags  |
+-------------------+---------------+
|        Selective ACK Bitmap       |
|            (32-bit)              |
+-----------------------------------+
|           Payload Length          |
+-----------------------------------+
|           HMAC (128-bit)         |
|                                 |
+-----------------------------------+

Field Definitions:
- Version (8-bit): Protocol version (currently 0x01)
- Type (8-bit): Packet type (see packet types above)
- Flags (8-bit): Bit flags for packet options
  - Bit 0: FIN flag (connection termination)
  - Bit 1: SYN flag (connection establishment)
  - Bit 2: RST flag (reset connection)
  - Bit 3: PSH flag (push data immediately)
  - Bit 4: ACK flag (acknowledgment included)
  - Bit 5: URG flag (urgent data)
  - Bits 6-7: Reserved
- Reserved (8-bit): Always 0x00
- Session ID (64-bit): Unique session identifier (big-endian)
- Sequence Number (32-bit): Packet sequence number (big-endian)
- Acknowledgment Number (32-bit): Next expected sequence (big-endian)
- Timestamp (32-bit): Packet timestamp in milliseconds since UTC midnight of current day (big-endian)
- Window Size (16-bit): Available receive window size (big-endian)
- Fragment ID (16-bit): Unique fragment identifier (big-endian)
- Fragment Index (16-bit): Fragment position (0-based, big-endian)
- Total Frags (16-bit): Total number of fragments (big-endian)
- Selective ACK Bitmap (32-bit): SACK bitmap for selective acknowledgment (big-endian)
- Payload Length (16-bit): Length of payload data in bytes (big-endian)
- HMAC (128-bit): Authentication hash using session key (big-endian)

Total Header Size: 64 bytes (48 + 16)
```

### Packet Type Specifications

#### SYN Packet (Type 0x01)
```pseudocode
SYN Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Initial Sequence Number       |
+-----------------------------------+
| Initial Congestion|Initial Receive|
|     Window        |    Window     |
+-------------------+---------------+
|      Time Offset (32-bit)        |
+-----------------------------------+
|    Supported Features (16-bit)   |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Initial Sequence Number (32-bit): Client's initial sequence number (4 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Client's time offset from epoch (4 bytes)
- Supported Features (16-bit): Bitmap of supported features (2 bytes)

Total SYN Packet Size: 64 + 16 = 80 bytes
```
```

#### SYN-ACK Packet (Type 0x02)
```pseudocode
SYN-ACK Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Initial Sequence Number       |
+-----------------------------------+
|    Acknowledgment Number         |
+-----------------------------------+
| Initial Congestion|Initial Receive|
|     Window        |    Window     |
+-------------------+---------------+
|      Time Offset (32-bit)        |
+-----------------------------------+
|   Negotiated Features (16-bit)   |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with SYN and ACK flags set
- Initial Sequence Number (32-bit): Server's initial sequence number (4 bytes)
- Acknowledgment Number (32-bit): Client's sequence + 1 (4 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Server's time offset from epoch (4 bytes)
- Negotiated Features (16-bit): Final feature bitmap (2 bytes)

Total SYN-ACK Packet Size: 64 + 20 = 84 bytes
```
```

#### ACK Packet (Type 0x03)
```pseudocode
ACK Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Acknowledgment Number         |
+-----------------------------------+
|    Window Size    |Selective ACK |
|                   |  Bitmap      |
+-------------------+---------------+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Acknowledgment Number (32-bit): Next expected sequence (4 bytes)
- Window Size (16-bit): Current receive window (2 bytes)
- Selective ACK Bitmap (16-bit): SACK information (2 bytes)

Total ACK Packet Size: 64 + 8 = 72 bytes
```
```

#### DATA Packet (Type 0x04)
```pseudocode
DATA Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|        Payload Data              |
|        (Variable Length)         |
|                                 |
|                                 |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with PSH flag set
- Payload Data (Variable Length): Application data

Total DATA Packet Size: 64 + payload_length bytes
```

#### FIN Packet (Type 0x05)
```pseudocode
FIN Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Final Sequence Number         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with FIN flag set
- Final Sequence Number (32-bit): Final sequence number

Total FIN Packet Size: 64 + 4 = 68 bytes
```

#### HEARTBEAT Packet (Type 0x06)
```pseudocode
HEARTBEAT Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|        Current Time (32-bit)     |
+-----------------------------------+
|    Time Drift     |Sync State|Res|
|     (16-bit)      | (8-bit) |(8)|
+-------------------+---------+----+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Current Time (32-bit): Sender's current time in milliseconds since UTC midnight
- Time Drift (16-bit): Calculated time drift
- Sync State (8-bit): Current synchronization state
- Reserved (8-bit): Always 0x00

Total HEARTBEAT Packet Size: 64 + 8 = 72 bytes
```

#### RECOVERY Packet (Type 0x07)
```pseudocode
RECOVERY Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Recovery Session ID (64-bit): Original session ID
- Last Known Sequence (32-bit): Last known sequence number
- Congestion Window (16-bit): Current congestion window
- Send Window (16-bit): Current send window
- Recovery Reason (8-bit): Reason for recovery
- Reserved (24-bit): Always 0x000000

Total RECOVERY Packet Size: 64 + 16 = 80 bytes
```

#### FRAGMENT Packet (Type 0x08)
```pseudocode
FRAGMENT Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
| Fragment ID      |Fragment Index |
+-------------------+---------------+
|   Total Fragments                |
+-----------------------------------+
|        Fragment Data              |
|        (Variable Length)          |
|                                 |
|                                 |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with PSH flag set
- Fragment ID (16-bit): Unique fragment identifier
- Fragment Index (16-bit): Fragment position (0-based)
- Total Fragments (16-bit): Total number of fragments
- Fragment Data (Variable Length): Fragment payload

Total FRAGMENT Packet Size: 64 + 6 + fragment_data_length bytes
```

#### ERROR Packet (Type 0x09)
```pseudocode
ERROR Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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
- Common Header (64 bytes): Standard header with RST flag set
- Error Code (8-bit): Specific error code
- Error Details (24-bit): Additional error information
- Error Message (Variable Length): Human-readable error message

Total ERROR Packet Size: 64 + 4 + error_message_length bytes
```

#### WINDOW_UPDATE Packet (Type 0x0A)
```pseudocode
WINDOW_UPDATE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|      New Window Size             |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- New Window Size (16-bit): Updated window size

Total WINDOW_UPDATE Packet Size: 64 + 2 = 66 bytes
```

#### RST Packet (Type 0x0B)
```pseudocode
RST Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
| Reset Reason|      Reserved      |
|   (8-bit)   |     (24-bit)      |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with RST flag set
- Reset Reason (8-bit): Reason for reset
- Reserved (24-bit): Always 0x000000

Total RST Packet Size: 64 + 4 = 68 bytes
```

#### DISCOVERY Packet (Type 0x0C)
```pseudocode
DISCOVERY Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Discovery ID (64-bit): Unique discovery session identifier
- PSK Count (16-bit): Number of PSKs available to initiator
- Challenge Nonce (64-bit): Random challenge for commitment
- Initiator Features (16-bit): Bitmap of supported features
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment (using challenge nonce)

Total DISCOVERY Packet Size: 64 + 20 + 16 = 100 bytes
```

#### DISCOVERY_RESPONSE Packet (Type 0x0D)
```pseudocode
DISCOVERY_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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

Field Definitions:
- Common Header (64 bytes): Standard header with SYN and ACK flags set
- Discovery ID (64-bit): Echo of discovery session identifier
- PSK Count (16-bit): Number of PSKs available to responder
- Challenge Nonce (64-bit): Echo of challenge nonce
- Response Nonce (64-bit): Random response nonce
- PSK Commitment (64-bit): PSK range commitment
- Responder Features (16-bit): Bitmap of supported features
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment (using response nonce)

Total DISCOVERY_RESPONSE Packet Size: 64 + 36 + 16 = 116 bytes
```

#### DISCOVERY_CONFIRM Packet (Type 0x0E)
```pseudocode
DISCOVERY_CONFIRM Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Discovery ID (64-bit): Echo of discovery session identifier
- Selected PSK Index (16-bit): Index of agreed-upon PSK
- Challenge Nonce (64-bit): Echo of challenge nonce
- Response Nonce (64-bit): Echo of response nonce
- PSK Selection Commitment (64-bit): PSK selection commitment
- Session ID (64-bit): New session identifier for communication
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment (using both nonces)

Total DISCOVERY_CONFIRM Packet Size: 64 + 36 + 16 = 116 bytes
```

#### 4. Secure Recovery Packet Types
```pseudocode
// New packet types for recovery processes
PACKET_TYPE_TIME_SYNC_REQUEST = 0x0F    // Time synchronization request
PACKET_TYPE_TIME_SYNC_RESPONSE = 0x10   // Time synchronization response
PACKET_TYPE_REKEY_REQUEST = 0x11        // Session key rotation request
PACKET_TYPE_REKEY_RESPONSE = 0x12       // Session key rotation response
PACKET_TYPE_REPAIR_REQUEST = 0x13       // Sequence repair request
PACKET_TYPE_REPAIR_RESPONSE = 0x14      // Sequence repair response
PACKET_TYPE_EMERGENCY_REQUEST = 0x15    // Emergency recovery request
PACKET_TYPE_EMERGENCY_RESPONSE = 0x16   // Emergency recovery response

// Time synchronization packet structure
TIME_SYNC_REQUEST Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Challenge Nonce (32-bit)      |
+-----------------------------------+
|    Local Timestamp (32-bit)      |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Challenge Nonce (32-bit): Random challenge for time sync (4 bytes)
- Local Timestamp (32-bit): Sender's current timestamp (4 bytes)
- Reserved (64-bit): Always 0x0000000000000000 (8 bytes)

Total TIME_SYNC_REQUEST Packet Size: 64 + 16 = 80 bytes

TIME_SYNC_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Challenge Nonce (32-bit)      |
+-----------------------------------+
|    Local Timestamp (32-bit)      |
+-----------------------------------+
|    Peer Timestamp (32-bit)       |
+-----------------------------------+
|        Reserved (32-bit)         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Challenge Nonce (32-bit): Echo of challenge nonce (4 bytes)
- Local Timestamp (32-bit): Sender's current timestamp (4 bytes)
- Peer Timestamp (32-bit): Peer's current timestamp (4 bytes)
- Reserved (32-bit): Always 0x00000000 (4 bytes)

Total TIME_SYNC_RESPONSE Packet Size: 64 + 16 = 80 bytes

// Session rekey packet structure
REKEY_REQUEST Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Rekey Nonce (32-bit): Random nonce for rekey operation (4 bytes)
- New Key Commitment (256-bit): Commitment to new session key (32 bytes)
- Reserved (64-bit): Always 0x0000000000000000 (8 bytes)

Total REKEY_REQUEST Packet Size: 64 + 44 = 108 bytes

REKEY_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Rekey Nonce (32-bit): Echo of rekey nonce (4 bytes)
- New Key Commitment (256-bit): Echo of new key commitment (32 bytes)
- Confirmation (128-bit): Confirmation of rekey operation (16 bytes)

Total REKEY_RESPONSE Packet Size: 64 + 52 = 116 bytes

// Sequence repair packet structure
REPAIR_REQUEST Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Repair Nonce (32-bit)         |
+-----------------------------------+
| Last Known Sequence (32-bit)     |
+-----------------------------------+
| Repair Window Size (32-bit)      |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Repair Nonce (32-bit): Random nonce for repair operation (4 bytes)
- Last Known Sequence (32-bit): Last known sequence number (4 bytes)
- Repair Window Size (32-bit): Size of repair window (4 bytes)
- Reserved (64-bit): Always 0x0000000000000000 (8 bytes)

Total REPAIR_REQUEST Packet Size: 64 + 16 = 80 bytes

REPAIR_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Repair Nonce (32-bit)         |
+-----------------------------------+
| Current Sequence (32-bit)        |
+-----------------------------------+
| Repair Window Size (32-bit)      |
+-----------------------------------+
|    Confirmation (64-bit)         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Repair Nonce (32-bit): Echo of repair nonce (4 bytes)
- Current Sequence (32-bit): Current sequence number (4 bytes)
- Repair Window Size (32-bit): Size of repair window (4 bytes)
- Confirmation (64-bit): Confirmation of repair operation (8 bytes)

Total REPAIR_RESPONSE Packet Size: 64 + 16 = 80 bytes

// Emergency recovery packet structure
EMERGENCY_REQUEST Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
| Emergency Token (32-bit)         |
+-----------------------------------+
|   Emergency Data (256-bit)       |
|                                 |
|                                 |
|                                 |
+-----------------------------------+
|        Reserved (64-bit)         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Emergency Token (32-bit): Emergency recovery token (4 bytes)
- Emergency Data (256-bit): Emergency recovery data (32 bytes)
- Reserved (64-bit): Always 0x0000000000000000 (8 bytes)

Total EMERGENCY_REQUEST Packet Size: 64 + 44 = 108 bytes

EMERGENCY_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
| Emergency Token (32-bit)         |
+-----------------------------------+
|   Emergency Data (256-bit)       |
|                                 |
|                                 |
|                                 |
+-----------------------------------+
|    Confirmation (128-bit)        |
|                                 |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with ACK flag set
- Emergency Token (32-bit): Echo of emergency token (4 bytes)
- Emergency Data (256-bit): Echo of emergency data (32 bytes)
- Confirmation (128-bit): Confirmation of emergency recovery (16 bytes)

Total EMERGENCY_RESPONSE Packet Size: 64 + 52 = 116 bytes
```

## Complete State Machine Specification

### Session State Variables
```pseudocode
// Session state variables for flow control and congestion control
session_state = {
    // Connection state
    'state': CLOSED,
    'session_id': 0,
    'session_key': None,
    'daily_key': None,
    
    // Sequence numbers
    'send_sequence': INITIAL_SEQUENCE_NUMBER,
    'receive_sequence': 0,
    'send_unacked': 0,
    'send_next': 0,
    'receive_next': 0,
    
    // Flow control
    'send_window': INITIAL_CONGESTION_WINDOW,
    'receive_window': INITIAL_RECEIVE_WINDOW,
    'congestion_window': INITIAL_CONGESTION_WINDOW,
    'slow_start_threshold': SLOW_START_THRESHOLD,
    'congestion_state': SLOW_START,
    
    // Buffers
    'send_buffer': [],
    'receive_buffer': [],
    'reorder_buffer': [],
    
    // Timing
    'rtt_srtt': RTT_INITIAL_MS,
    'rtt_rttvar': RTT_INITIAL_MS / 2,
    'rtt_rto': RTT_INITIAL_MS,
    'last_ack_time': 0,
    
    // Port hopping
    'current_port': 0,
    'port_history': [],
    'time_offset': 0,
    
    // Discovery
    'discovery_state': DISCOVERY_IDLE,
    'discovered_psk': None,
    'discovery_id': 0,
    'challenge_nonce': 0,
    'response_nonce': 0,
    
    // Error handling
    'retry_count': 0,
    'last_error': None,
    'recovery_attempts': 0
}
```

### Simplified Session States with Enhanced Recovery
```pseudocode
Session States:
- CLOSED: No session exists
- CONNECTING: Client attempting connection (includes discovery if needed)
- LISTENING: Server waiting for connection
- ESTABLISHED: Connection active, data flowing
- CLOSING: Connection termination in progress
- RECOVERING: Connection recovery in progress
- ERROR: Error state, connection should be closed

// Recovery states (sub-states within main states)
Recovery Sub-States:
- NORMAL: Normal operation
- RESYNC: Time synchronization recovery
- REKEY: Session key rotation/recovery
- REPAIR: Connection repair (sequence number recovery)
- EMERGENCY: Emergency recovery mode
```

### Simplified State Transitions with Integrated Recovery
```pseudocode
// Core state transitions with automatic recovery
CLOSED -> CONNECTING: connect() [Start connection with discovery if needed]
CLOSED -> LISTENING: bind() [Start listening for connections]

CONNECTING -> ESTABLISHED: connection_established() [Normal connection]
CONNECTING -> CLOSED: connection_failed() [Connection failed after retries]
CONNECTING -> RECOVERING: connection_recovery_needed() [Recovery required]

LISTENING -> ESTABLISHED: connection_established() [Normal connection]
LISTENING -> CLOSED: timeout() or error [Listen timeout or error]

ESTABLISHED -> CLOSING: close_requested() [Normal close]
ESTABLISHED -> RECOVERING: recovery_triggered() [Recovery needed]
ESTABLISHED -> ERROR: critical_error() [Critical error]

CLOSING -> CLOSED: close_completed() [Normal close completion]
CLOSING -> RECOVERING: close_recovery_needed() [Close recovery needed]

RECOVERING -> ESTABLISHED: recovery_success() [Recovery successful]
RECOVERING -> CLOSED: recovery_failed() [Recovery failed after attempts]
RECOVERING -> ERROR: recovery_critical_failure() [Critical recovery failure]

ERROR -> CLOSED: cleanup() [Immediate cleanup]

// Recovery sub-state transitions (within main states)
NORMAL -> RESYNC: time_drift_detected() [Time synchronization needed]
NORMAL -> REKEY: key_rotation_needed() [Session key rotation needed]
NORMAL -> REPAIR: sequence_mismatch() [Sequence number repair needed]
NORMAL -> EMERGENCY: critical_failure() [Emergency recovery needed]

RESYNC -> NORMAL: time_sync_completed() [Time sync successful]
REKEY -> NORMAL: key_rotation_completed() [Key rotation successful]
REPAIR -> NORMAL: sequence_repair_completed() [Sequence repair successful]
EMERGENCY -> NORMAL: emergency_recovery_completed() [Emergency recovery successful]
```

### Invalid State Packet Handling
```pseudocode
function handle_packet_in_invalid_state(packet, current_state):
    switch current_state:
        case CLOSED:
            if packet.type == PACKET_TYPE_SYN:
                # Passive open - transition to SYN_RECEIVED
                return handle_syn_in_closed_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case LISTENING:
            if packet.type == PACKET_TYPE_SYN:
                return handle_syn_in_listening_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case CONNECTING:
            if packet.type == PACKET_TYPE_SYN:
                # Simultaneous open
                send_syn_ack_packet(packet.session_id)
                return SUCCESS
            elif packet.type == PACKET_TYPE_SYN_ACK:
                return handle_syn_ack_in_connecting_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case ESTABLISHED:
            if packet.type == PACKET_TYPE_DATA:
                return handle_data_in_established_state(packet)
            elif packet.type == PACKET_TYPE_ACK:
                return handle_ack_in_established_state(packet)
            elif packet.type == PACKET_TYPE_FIN:
                return handle_fin_in_established_state(packet)
            else:
                send_error_packet(packet.session_id, ERROR_STATE_INVALID)
                return ERROR_STATE_INVALID
                
        # Handle other states similarly...
        
    return ERROR_STATE_INVALID
```

## Sequence Number Management

### Sequence Number Wraparound Handling
```pseudocode
function is_sequence_valid(sequence_number, expected_sequence):
    # Handle sequence number wraparound
    if expected_sequence > SEQUENCE_WRAP_THRESHOLD and sequence_number < SEQUENCE_WRAP_THRESHOLD:
        # Wraparound occurred
        return sequence_number >= 0 and sequence_number < (expected_sequence - SEQUENCE_WRAP_THRESHOLD)
    elif expected_sequence < SEQUENCE_WRAP_THRESHOLD and sequence_number > SEQUENCE_WRAP_THRESHOLD:
        # Wraparound occurred in reverse
        return sequence_number >= (expected_sequence + SEQUENCE_WRAP_THRESHOLD)
    else:
        # Normal case
        return sequence_number >= expected_sequence and sequence_number < (expected_sequence + SEQUENCE_WRAP_THRESHOLD)

function increment_sequence_number(sequence_number):
    if sequence_number == MAX_SEQUENCE_NUMBER:
        return 0
    else:
        return sequence_number + 1

function sequence_difference(seq1, seq2):
    # Calculate the difference between two sequence numbers, handling wraparound
    if seq1 >= seq2:
        return seq1 - seq2
    else:
        return (MAX_SEQUENCE_NUMBER - seq2 + 1) + seq1
```

## HMAC Calculation Specification

### Complete HMAC Calculation Algorithm
```pseudocode
function calculate_packet_hmac(packet_data, session_key):
    # HMAC is calculated over all packet fields except the HMAC field itself
    # The HMAC field is always the last 16 bytes of the packet (HMAC-SHA256-128)
    
    # Extract packet without HMAC
    packet_without_hmac = packet_data[0:len(packet_data)-16]
    
    # Calculate HMAC-SHA256-128 using session key
    hmac_result = HMAC_SHA256_128(session_key, packet_without_hmac)
    
    return hmac_result

function verify_packet_hmac(packet_data, session_key, received_hmac):
    # Calculate expected HMAC
    expected_hmac = calculate_packet_hmac(packet_data, session_key)
    
    # Compare HMACs (constant-time comparison)
    return constant_time_compare(expected_hmac, received_hmac)

function constant_time_compare(a, b):
    # Constant-time comparison to prevent timing attacks
    if len(a) != len(b):
        return False
    
    result = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]
    
    return result == 0

## Session Key Derivation Specification


### HKDF-SHA256 Key Derivation Algorithm
```pseudocode
function derive_session_key(daily_key, session_id, nonce):
    # Derive session key using HKDF-SHA256 (RFC 5869)
    # Input key material (IKM): Daily key (derived from PSK and current date)
    # Salt: Session ID for context separation
    # Info: Nonce for additional entropy
    
    # Convert inputs to bytes
    daily_key_bytes = daily_key if isinstance(daily_key, bytes) else daily_key
    session_id_bytes = uint64_to_bytes(session_id)
    nonce_bytes = nonce if isinstance(nonce, bytes) else nonce.encode('utf-8')
    
    # HKDF-SHA256 Extract phase
    # PRK = HMAC-SHA256(salt, IKM)
    salt = session_id_bytes
    ikm = daily_key_bytes
    prk = HMAC_SHA256(salt, ikm)
    
    # HKDF-SHA256 Expand phase
    # OKM = HKDF-Expand(PRK, info, L)
    info = b"session_key" + nonce_bytes
    l = 32  # 256-bit session key
    
    # Expand using HMAC-SHA256
    session_key = hkdf_expand_sha256(prk, info, l)
    
    return session_key

function hkdf_expand_sha256(prk, info, l):
    # HKDF-Expand implementation using HMAC-SHA256
    # Based on RFC 5869 Section 2.3
    
    if l > 255 * 32:  # SHA256 output is 32 bytes
        raise ValueError("Requested key length too large")
    
    # Initialize
    t = b""
    okm = b""
    counter = 1
    
    while len(okm) < l:
        # T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
        t = HMAC_SHA256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    
    return okm[:l]

function derive_daily_key(psk, date_string):
    # Derive daily key for port calculation and session key derivation using HKDF-SHA256
    # This provides key separation between session keys and port calculation
    # Daily key is derived from PSK and current UTC date (YYYY-MM-DD format)
    
    psk_bytes = psk if isinstance(psk, bytes) else psk.encode('utf-8')
    date_bytes = date_string.encode('utf-8')
    
    # HKDF-SHA256 Extract
    salt = b"daily_key_salt"
    ikm = psk_bytes
    prk = HMAC_SHA256(salt, ikm)
    
    # HKDF-SHA256 Expand
    info = b"daily_key" + date_bytes
    l = 32  # 256-bit daily key
    
    daily_key = hkdf_expand_sha256(prk, info, l)
    
    return daily_key

function derive_daily_key_for_current_date(psk):
    # Convenience function to derive daily key for current UTC date
    current_date = get_current_utc_date()
    return derive_daily_key(psk, current_date)

function initialize_session_keys(psk, session_id, nonce):
    # Initialize session keys using daily key derivation
    # This ensures all session keys are derived from the daily key, not directly from PSK
    
    # Step 1: Derive daily key from PSK and current UTC date
    daily_key = derive_daily_key_for_current_date(psk)
    
    # Step 2: Derive session key from daily key
    session_key = derive_session_key(daily_key, session_id, nonce)
    
    return {
        'daily_key': daily_key,
        'session_key': session_key
    }

function rekey_session_keys(psk, session_id, new_nonce):
    # Rekey session keys using current daily key
    # This maintains the daily key but generates a new session key
    
    # Get current daily key (or derive if not available)
    daily_key = derive_daily_key_for_current_date(psk)
    
    # Derive new session key from daily key
    new_session_key = derive_session_key(daily_key, session_id, new_nonce)
    
    return {
        'daily_key': daily_key,
        'session_key': new_session_key
    }
```
```

## Port Calculation Specification

### Time Window Calculation
```pseudocode
# Time windows are 250ms wide and based on UTC time from start of current day
# This ensures synchronized port hopping across all peers regardless of timezone
# 
# Time window calculation:
# 1. Get current UTC time in milliseconds since epoch
# 2. Calculate milliseconds since start of current UTC day
# 3. Divide by 250ms to get current time window number
# 4. Use time window number for port calculation
#
# Example: If current UTC time is 14:30:25.123, then:
# - Milliseconds since start of day = (14*3600 + 30*60 + 25)*1000 + 123 = 52225123ms
# - Time window = 52225123 // 250 = 208900 (window number)
# - Port will be calculated using this window number
```

### Port Calculation Algorithm
```pseudocode
function calculate_port(daily_key, session_id, time_window, entropy):
    # Calculate port based on time window, session ID, and entropy
    # Time window is 250ms wide based on UTC time from start of day
    session_id_bytes = uint64_to_bytes(session_id)
    time_window_bytes = uint64_to_bytes(time_window)
    entropy_bytes = uint64_to_bytes(entropy)
    
    # Use HMAC for port calculation
    hmac_input = time_window_bytes || session_id_bytes || entropy_bytes
    hmac_result = HMAC_SHA256(daily_key, hmac_input)
    
    # Extract port efficiently
    port_value = (hmac_result[0] << 8) | hmac_result[1]
    port = MIN_PORT + (port_value % PORT_RANGE)
    
    return port
```

### Transmission Delay Handling
```pseudocode
# Network transmission delays can cause packets to arrive during the next time window
# To handle this, the protocol calculates ports for adjacent time windows
# and listens on multiple ports simultaneously during transitions
#
# Delay allowance strategy:
# 1. Calculate ports for current time window
# 2. Also calculate ports for previous and next time windows
# 3. Listen on all three ports during transitions
# 4. This provides 50ms allowance for transmission delay
```

function get_current_port_with_delay_allowance(daily_key, session_id):
    # Calculate current port with allowance for transmission delay
    # This function calculates ports for current and adjacent time windows
    # to handle network transmission delays
    
    # Get current time window (assume time functions are available)
    current_time_window = get_current_time_window()
    
    # Calculate ports for current window and adjacent windows
    # This provides allowance for transmission delay
    ports = []
    
    # Include previous, current, and next time windows
    for offset in [-1, 0, 1]:
        time_window = current_time_window + offset
        port = calculate_port(daily_key, session_id, time_window, 0)
        ports.append(port)
    
    return ports

function calculate_multiple_ports(daily_key, session_id, count):
    # Multiple port calculation with batch processing
    # Includes allowance for transmission delay by calculating adjacent time windows
    ports = []
    
    # Get current time window (assume time functions are available)
    base_time_window = get_current_time_window()
    
    # Pre-calculate time windows including allowance for transmission delay
    # Calculate ports for current window and adjacent windows to handle delay
    time_windows = []
    for i in range(-count + 1, count + 1):
        time_windows.append(base_time_window + i)
    
    # Batch calculate ports
    for time_window in time_windows:
        port = calculate_port(daily_key, session_id, time_window, 0)
        ports.append(port)
    
    return ports
```

function uint64_to_bytes(value):
    # Optimized uint64 to bytes conversion
    return value.to_bytes(8, byteorder='big')

function bytes_to_uint16(bytes_array):
    # Optimized bytes to uint16 conversion
    return int.from_bytes(bytes_array[0:2], byteorder='big')
```

## Time Synchronization Specification

### Time Offset Calculation
```pseudocode
function calculate_time_offset(client_time, server_time):
    # Calculate time offset between client and server
    return server_time - client_time

function apply_time_offset(local_time, time_offset):
    # Apply time offset to local time
    return local_time + time_offset

function get_synchronized_time():
    # Get current time with offset applied
    return apply_time_offset(get_current_time(), time_offset)

function detect_time_drift(peer_time, local_time):
    # Detect time drift between peers
    time_difference = abs(peer_time - local_time)
    return time_difference > TIME_SYNC_TOLERANCE_MS

function adjust_time_offset(new_offset):
    # Adjust time offset based on drift detection
    time_offset = (time_offset + new_offset) / 2
    return time_offset
```

## RTO Calculation Specification (RFC 6298)

### Complete RTO Calculation Algorithm
```pseudocode
// RTO state variables
rtt_srtt = RTT_INITIAL_MS        // Smoothed RTT
rtt_rttvar = RTT_INITIAL_MS / 2  // RTT variation
rtt_rto = RTT_INITIAL_MS         // Retransmission timeout

function calculate_rtt(send_time, ack_time):
    # Calculate RTT from send time to acknowledgment time
    rtt_sample = ack_time - send_time
    
    # Ensure RTT is within valid range
    if rtt_sample < RTT_MIN_MS:
        rtt_sample = RTT_MIN_MS
    elif rtt_sample > RTT_MAX_MS:
        rtt_sample = RTT_MAX_MS
    
    return rtt_sample

function update_rto(rtt_sample):
    # Update RTO using RFC 6298 algorithm
    
    if rtt_srtt == RTT_INITIAL_MS:
        # First RTT measurement
        rtt_srtt = rtt_sample
        rtt_rttvar = rtt_sample / 2
    else:
        # Update smoothed RTT
        rtt_rttvar = (1 - RTT_BETA) * rtt_rttvar + RTT_BETA * abs(rtt_sample - rtt_srtt)
        rtt_srtt = (1 - RTT_ALPHA) * rtt_srtt + RTT_ALPHA * rtt_sample
    
    # Calculate RTO
    rtt_rto = rtt_srtt + RTT_K * rtt_rttvar
    
    # Ensure RTO is within bounds
    if rtt_rto < MIN_RETRANSMISSION_TIMEOUT_MS:
        rtt_rto = MIN_RETRANSMISSION_TIMEOUT_MS
    elif rtt_rto > MAX_RETRANSMISSION_TIMEOUT_MS:
        rtt_rto = MAX_RETRANSMISSION_TIMEOUT_MS
    
    return rtt_rto

function handle_retransmission_timeout():
    # Handle RTO expiration - exponential backoff
    rtt_rto = min(rtt_rto * 2, MAX_RETRANSMISSION_TIMEOUT_MS)
    
    # Reset RTT measurement on timeout
    rtt_srtt = RTT_INITIAL_MS
    rtt_rttvar = RTT_INITIAL_MS / 2
    
    return rtt_rto

function get_current_rto():
    # Get current RTO value
    return rtt_rto

function reset_rto():
    # Reset RTO to initial values
    rtt_srtt = RTT_INITIAL_MS
    rtt_rttvar = RTT_INITIAL_MS / 2
    rtt_rto = RTT_INITIAL_MS
```

## Flow Control Specification

### Complete Flow Control Algorithm
```pseudocode
// Flow control state variables
send_window = INITIAL_CONGESTION_WINDOW    // Send window size
receive_window = INITIAL_RECEIVE_WINDOW    // Receive window size
send_unacked = 0                          // Unacknowledged data
send_next = 0                             // Next sequence to send
receive_next = 0                          // Next expected sequence
receive_buffer = []                       // Out-of-order receive buffer

function update_send_window(ack_packet):
    # Update send window based on acknowledgment
    acked_bytes = ack_packet.acknowledgment_number - session_state.send_unacked
    
    if acked_bytes > 0:
        session_state.send_unacked = ack_packet.acknowledgment_number
        session_state.send_window = min(session_state.send_window + acked_bytes, MAX_CONGESTION_WINDOW)
    
    # Update based on window advertisement
    if ack_packet.window_size < session_state.receive_window:
        session_state.receive_window = ack_packet.window_size

function can_send_data():
    # Check if we can send more data
    available_window = min(session_state.send_window, session_state.receive_window)
    unacked_data = session_state.send_next - session_state.send_unacked
    
    return (unacked_data + MSS) <= available_window

function send_data(data):
    # Send data if window allows
    if not can_send_data():
        return ERROR_WINDOW_OVERFLOW
    
    # Create data packet
    data_packet = create_data_packet(
        sequence_number = session_state.send_next,
        data = data
    )
    
    # Update send state
    session_state.send_next += len(data)
    session_state.send_window -= len(data)
    
    # Send packet
    send_packet(data_packet)
    return SUCCESS

function receive_data(data_packet):
    # Handle incoming data with flow control
    sequence_number = data_packet.sequence_number
    data_length = len(data_packet.data)
    
    # Check if packet is within receive window
    if sequence_number < session_state.receive_next:
        # Duplicate packet - send ACK
        send_ack(session_state.receive_next)
        return SUCCESS
    
    if sequence_number > session_state.receive_next + session_state.receive_window:
        # Packet beyond window - drop
        return ERROR_WINDOW_OVERFLOW
    
    # Handle in-order packet
    if sequence_number == session_state.receive_next:
        deliver_to_application(data_packet.data)
        session_state.receive_next += data_length
        
        # Process out-of-order buffer
        while len(session_state.receive_buffer) > 0:
            next_packet = find_next_in_order(session_state.receive_buffer, session_state.receive_next)
            if next_packet:
                deliver_to_application(next_packet.data)
                session_state.receive_next += len(next_packet.data)
                remove_from_buffer(session_state.receive_buffer, next_packet)
            else:
                break
        
        # Update receive window
        session_state.receive_window = max(session_state.receive_window - data_length, MIN_CONGESTION_WINDOW)
        
        # Send ACK
        send_ack(session_state.receive_next)
        
    else:
        # Out-of-order packet
        if sequence_number < session_state.receive_next + session_state.receive_window:
            add_to_buffer(session_state.receive_buffer, data_packet)
            send_ack(session_state.receive_next)  # Send duplicate ACK
    
    return SUCCESS

function send_window_update():
    # Send window update when receive buffer is freed
    new_window_size = calculate_available_window()
    
    if new_window_size > session_state.receive_window:
        window_update_packet = create_window_update_packet(new_window_size)
        send_packet(window_update_packet)
        session_state.receive_window = new_window_size

function calculate_available_window():
    # Calculate available receive window
    used_buffer = len(session_state.receive_buffer) + (session_state.receive_next - session_state.send_sequence)
    return MAX_RECEIVE_WINDOW - used_buffer

function handle_zero_window():
    # Handle zero window probe
    if session_state.receive_window == 0:
        # Send zero window probe
        probe_packet = create_zero_window_probe()
        send_packet(probe_packet)
        set_zero_window_timer()
```

## Congestion Control Specification

### Complete Congestion Control Algorithm
```pseudocode
function update_congestion_window(ack_packet):
    if session_state.congestion_state == SLOW_START:
        # Slow start: exponential growth
        session_state.congestion_window = min(session_state.congestion_window + MSS, MAX_CONGESTION_WINDOW)
        
        if session_state.congestion_window >= session_state.slow_start_threshold:
            session_state.congestion_state = CONGESTION_AVOIDANCE
            
    elif session_state.congestion_state == CONGESTION_AVOIDANCE:
        # Congestion avoidance: linear growth
        session_state.congestion_window = min(session_state.congestion_window + (MSS * MSS / session_state.congestion_window), MAX_CONGESTION_WINDOW)
        
    elif session_state.congestion_state == FAST_RECOVERY:
        # Fast recovery: maintain window size
        session_state.congestion_window = session_state.slow_start_threshold
        session_state.congestion_state = CONGESTION_AVOIDANCE

function handle_congestion_event():
    # Reduce window size on congestion
    session_state.slow_start_threshold = max(session_state.congestion_window / 2, MIN_CONGESTION_WINDOW)
    session_state.congestion_window = MIN_CONGESTION_WINDOW
    session_state.congestion_state = SLOW_START

function handle_fast_recovery():
    # Fast recovery with SACK
    session_state.slow_start_threshold = max(session_state.congestion_window / 2, MIN_CONGESTION_WINDOW)
    session_state.congestion_window = session_state.slow_start_threshold
    session_state.congestion_state = FAST_RECOVERY
```

## Fragment Reassembly Specification

### Fragment Reassembly Algorithm
```pseudocode
function handle_fragment_packet(fragment_packet):
    fragment_id = fragment_packet.fragment_id
    fragment_index = fragment_packet.fragment_index
    total_fragments = fragment_packet.total_fragments
    
    # Initialize fragment buffer if needed
    if fragment_id not in fragment_buffers:
        fragment_buffers[fragment_id] = {
            'fragments': [None] * total_fragments,
            'total_fragments': total_fragments,
            'received_count': 0,
            'timer': current_time + FRAGMENT_TIMEOUT_MS
        }
    
    buffer = fragment_buffers[fragment_id]
    
    # Store fragment
    if fragment_index < total_fragments and buffer['fragments'][fragment_index] is None:
        buffer['fragments'][fragment_index] = fragment_packet.fragment_data
        buffer['received_count'] += 1
        
        # Check if all fragments received
        if buffer['received_count'] == total_fragments:
            reassembled_data = reassemble_fragments(buffer['fragments'])
            deliver_to_application(reassembled_data)
            del fragment_buffers[fragment_id]
        else:
            # Extend timer
            buffer['timer'] = current_time + FRAGMENT_TIMEOUT_MS

function reassemble_fragments(fragments):
    # Reassemble fragments in order
    reassembled_data = b''
    for fragment in fragments:
        if fragment is not None:
            reassembled_data += fragment
        else:
            raise FragmentReassemblyError("Missing fragment")
    
    return reassembled_data

function cleanup_expired_fragments():
    # Clean up expired fragment buffers
    current_time = get_current_time()
    expired_fragments = []
    
    for fragment_id, buffer in fragment_buffers.items():
        if current_time > buffer['timer']:
            expired_fragments.append(fragment_id)
    
    for fragment_id in expired_fragments:
        del fragment_buffers[fragment_id]
```

## Complete Error Handling Specification

### Enhanced Error Packet Processing with Recovery Mechanisms
```pseudocode
// Error recovery state tracking
error_recovery_state = {
    'retry_count': 0,
    'last_error': None,
    'recovery_attempts': 0,
    'backoff_timer': 0
}

function process_error_packet(error_packet):
    error_code = error_packet.error_code
    error_details = error_packet.error_details
    error_message = error_packet.error_message
    
    # Log error with context
    log_error_with_context(error_code, error_details, error_message)
    
    # Update error recovery state
    error_recovery_state['last_error'] = error_code
    error_recovery_state['retry_count'] += 1
    
    switch error_code:
        case ERROR_INVALID_PACKET:
            log_error("Invalid packet format: " + error_message)
            handle_invalid_packet_error(error_details)
            
        case ERROR_AUTHENTICATION_FAILED:
            log_error("Authentication failed: " + error_message)
            handle_authentication_error(error_details)
            
        case ERROR_TIMESTAMP_INVALID:
            log_error("Invalid timestamp: " + error_message)
            handle_timestamp_error(error_details)
            
        case ERROR_REPLAY_ATTACK:
            log_error("Replay attack detected: " + error_message)
            handle_replay_attack(error_details)
            
        case ERROR_SESSION_NOT_FOUND:
            log_error("Session not found: " + error_message)
            handle_session_not_found_error(error_details)
            
        case ERROR_STATE_INVALID:
            log_error("Invalid state transition: " + error_message)
            handle_state_error(error_details)
            
        case ERROR_WINDOW_OVERFLOW:
            log_error("Window overflow: " + error_message)
            handle_window_overflow_error(error_details)
            
        case ERROR_SEQUENCE_INVALID:
            log_error("Invalid sequence: " + error_message)
            handle_sequence_error(error_details)
            
        case ERROR_FRAGMENT_INVALID:
            log_error("Invalid fragment: " + error_message)
            handle_fragment_error(error_details)
            
        case ERROR_SYNC_FAILED:
            log_error("Synchronization failed: " + error_message)
            handle_sync_error(error_details)
            
        case ERROR_RECOVERY_FAILED:
            log_error("Recovery failed: " + error_message)
            handle_recovery_error(error_details)
            
        case ERROR_TIMEOUT:
            log_error("Operation timeout: " + error_message)
            handle_timeout_error(error_details)
            
        case ERROR_MEMORY_EXHAUSTED:
            log_error("Memory exhausted: " + error_message)
            handle_memory_error(error_details)
            
        case ERROR_INVALID_PARAMETER:
            log_error("Invalid parameter: " + error_message)
            handle_parameter_error(error_details)
            
        case ERROR_PORT_CALCULATION_FAILED:
            log_error("Port calculation failed: " + error_message)
            handle_port_calculation_error(error_details)
            
        case ERROR_FRAGMENT_REASSEMBLY_FAILED:
            log_error("Fragment reassembly failed: " + error_message)
            handle_fragment_reassembly_error(error_details)
            
        case ERROR_CONGESTION_CONTROL_FAILED:
            log_error("Congestion control failed: " + error_message)
            handle_congestion_control_error(error_details)
            
        case ERROR_DISCOVERY_FAILED:
            log_error("Discovery failed: " + error_message)
            handle_discovery_error(error_details)
            
        case ERROR_PSK_NOT_FOUND:
            log_error("PSK not found: " + error_message)
            handle_psk_error(error_details)
            
        case ERROR_ZERO_KNOWLEDGE_PROOF_FAILED:
            log_error("Zero-knowledge proof failed: " + error_message)
            handle_zkp_error(error_details)
            
        case ERROR_PSK_ENUMERATION_ATTEMPT:
            log_error("PSK enumeration attempt: " + error_message)
            handle_enumeration_attempt(error_details)

function handle_invalid_packet_error(error_details):
    # Handle malformed packet errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Request packet retransmission
        request_packet_retransmission()
    else:
        transition_to(ERROR)

function handle_authentication_error(error_details):
    # Handle authentication failures
    if current_state == ESTABLISHED:
        # Try to re-authenticate
        initiate_reauthentication()
    else:
        transition_to(ERROR)

function handle_timestamp_error(error_details):
    # Handle timestamp synchronization errors
    if current_state == ESTABLISHED:
        # Attempt time resynchronization
        initiate_time_resync()
    else:
        transition_to(ERROR)

function handle_replay_attack(error_details):
    # Handle replay attack detection
    # Log attack details for security monitoring
    log_security_event("Replay attack detected", error_details)
    
    # Continue normal operation but monitor for patterns
    if error_recovery_state['retry_count'] > REPLAY_THRESHOLD:
        # Block source if too many replays
        block_source_address()

function handle_session_not_found_error(error_details):
    # Handle session lookup failures
    cleanup_session_state()
    transition_to(CLOSED)

function handle_state_error(error_details):
    # Handle invalid state transitions
    log_state_transition_error(error_details)
    
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Attempt state recovery
        attempt_state_recovery()
    else:
        transition_to(ERROR)

function handle_window_overflow_error(error_details):
    # Handle flow control errors
    # Reduce window size and continue
    send_window = max(send_window / 2, min_congestion_window)
    receive_window = max(receive_window / 2, min_congestion_window)
    
    # Send window update
    send_window_update_packet()

function handle_sequence_error(error_details):
    # Handle sequence number errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Request selective retransmission
        request_selective_retransmission(error_details)
    else:
        # Reset sequence numbers
        reset_sequence_numbers()

function handle_fragment_error(error_details):
    # Handle fragment processing errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Request fragment retransmission
        request_fragment_retransmission(error_details)
    else:
        # Clean up fragment buffer
        cleanup_fragment_buffer()

function handle_sync_error(error_details):
    # Handle synchronization failures
    if error_recovery_state['retry_count'] < MAX_SYNC_FAILURES:
        # Attempt resynchronization
        initiate_resync()
    else:
        transition_to(RECOVERING)

function handle_recovery_error(error_details):
    # Handle recovery failures
    if error_recovery_state['recovery_attempts'] < MAX_RECOVERY_ATTEMPTS:
        # Try alternative recovery method
        attempt_alternative_recovery()
    else:
        transition_to(ERROR)

function handle_timeout_error(error_details):
    # Handle timeout errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Implement exponential backoff
        backoff_time = calculate_backoff_time(error_recovery_state['retry_count'])
        schedule_retry(backoff_time)
    else:
        transition_to(ERROR)

function handle_memory_error(error_details):
    # Handle memory exhaustion
    # Clean up resources
    cleanup_memory_resources()
    
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Try with reduced buffer sizes
        reduce_buffer_sizes()
    else:
        transition_to(ERROR)

function handle_parameter_error(error_details):
    # Handle invalid parameter errors
    log_parameter_error(error_details)
    
    if current_state == ESTABLISHED:
        # Try to renegotiate parameters
        initiate_parameter_renegotiation()
    else:
        transition_to(ERROR)

function handle_port_calculation_error(error_details):
    # Handle port calculation failures
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Try alternative port calculation
        attempt_alternative_port_calculation()
    else:
        transition_to(ERROR)

function handle_fragment_reassembly_error(error_details):
    # Handle fragment reassembly failures
    cleanup_fragment_buffer()
    
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Request complete retransmission
        request_complete_retransmission()
    else:
        transition_to(ERROR)

function handle_congestion_control_error(error_details):
    # Handle congestion control failures
    reset_congestion_control()
    
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Try conservative congestion control
        initiate_conservative_congestion_control()
    else:
        transition_to(ERROR)

function handle_discovery_error(error_details):
    # Handle discovery process errors
    if error_recovery_state['retry_count'] < DISCOVERY_RETRY_COUNT:
        # Retry discovery with backoff
        backoff_time = calculate_discovery_backoff(error_recovery_state['retry_count'])
        schedule_discovery_retry(backoff_time)
    else:
        transition_to(DISCOVERY_FAILED)

function handle_psk_error(error_details):
    # Handle PSK-related errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Try alternative PSK
        attempt_alternative_psk()
    else:
        transition_to(ERROR)

function handle_zkp_error(error_details):
    # Handle zero-knowledge proof errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Retry with new challenge
        retry_zero_knowledge_proof()
    else:
        transition_to(ERROR)

function handle_enumeration_attempt(error_details):
    # Handle PSK enumeration attempts
    # Block source address
    block_source_address()
    
    # Log security event
    log_security_event("PSK enumeration attempt blocked", error_details)
    
    # Send error response
    send_error_packet(ERROR_PSK_ENUMERATION_ATTEMPT, "Enumeration attempt detected")

// Error recovery utility functions
function calculate_backoff_time(retry_count):
    # Exponential backoff with jitter
    base_time = 1000 * (2 ** retry_count)  # Base exponential backoff
    jitter = random(0, base_time * 0.1)    # Add 10% jitter
    return min(base_time + jitter, MAX_RETRANSMISSION_TIMEOUT_MS)

function calculate_discovery_backoff(retry_count):
    # Discovery-specific backoff
    base_time = 5000 * (2 ** retry_count)
    return min(base_time, DISCOVERY_TIMEOUT_MS)

function log_error_with_context(error_code, error_details, error_message):
    # Enhanced error logging with context
    log_context = {
        'error_code': error_code,
        'error_details': error_details,
        'current_state': current_state,
        'session_id': session_id,
        'timestamp': get_current_time(),
        'retry_count': error_recovery_state['retry_count']
    }
    
    log_error("Protocol error: " + error_message, log_context)

function reset_error_recovery_state():
    # Reset error recovery state
    error_recovery_state['retry_count'] = 0
    error_recovery_state['last_error'] = None
    error_recovery_state['recovery_attempts'] = 0
    error_recovery_state['backoff_timer'] = 0
```

### Malformed Packet Handling
```pseudocode
function handle_malformed_packet(packet_data, error_reason):
    # Try to extract session ID if possible
    session_id = 0
    try:
        if len(packet_data) >= 16:  # Minimum header size
            session_id = bytes_to_uint64(packet_data[8:16])
    except:
        pass
    
    # Create error packet if we can extract session ID
    if session_id != 0:
        error_packet = create_error_packet(
            session_id = session_id,
            error_code = ERROR_INVALID_PACKET,
            error_details = error_reason,
            error_message = "Malformed packet received"
        )
        send_packet(error_packet)
    
    # Log the error
    log_error("Malformed packet: " + error_reason)
```