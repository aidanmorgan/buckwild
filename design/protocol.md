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

### Optimized Packet Format Changes

The protocol has been optimized to reduce packet overhead while maintaining security and functionality:

#### Timestamp Format
- **Previous**: 64-bit timestamp in milliseconds since epoch
- **Current**: 32-bit timestamp in milliseconds since UTC midnight of current day
- **Range**: 0-86,399,999 milliseconds (24 hours)
- **Benefits**: Reduces timestamp size by 50% while maintaining millisecond precision
- **Rollover**: Timestamps reset at UTC midnight each day

#### HMAC Authentication
- **Previous**: 256-bit HMAC (32 bytes)
- **Current**: 128-bit HMAC (16 bytes)
- **Security**: Standard HMAC-SHA256-128 truncation
- **Benefits**: Reduces authentication overhead by 50% while maintaining cryptographic strength

#### Header Size Reduction
- **Previous**: 80-byte common header
- **Current**: 64-byte common header
- **Total Reduction**: 20% smaller headers across all packet types

#### Packet Size Comparison
| Packet Type | Previous Size | Optimized Size | Reduction | % Reduction |
|-------------|---------------|----------------|-----------|-------------|
| SYN | 96 bytes | 80 bytes | 16 bytes | 16.7% |
| SYN-ACK | 100 bytes | 84 bytes | 16 bytes | 16.0% |
| ACK | 88 bytes | 72 bytes | 16 bytes | 18.2% |
| DATA | 80+payload | 64+payload | 16 bytes | 20.0% |
| FIN | 84 bytes | 68 bytes | 16 bytes | 19.0% |
| HEARTBEAT | 92 bytes | 72 bytes | 20 bytes | 21.7% |
| RECOVERY | 96 bytes | 80 bytes | 16 bytes | 16.7% |
| FRAGMENT | 86+data | 70+data | 16 bytes | 18.6% |
| ERROR | 84+msg | 68+msg | 16 bytes | 19.0% |
| WINDOW_UPDATE | 82 bytes | 66 bytes | 16 bytes | 19.5% |
| RST | 84 bytes | 68 bytes | 16 bytes | 19.0% |
| DISCOVERY | 132 bytes | 100 bytes | 32 bytes | 24.2% |
| DISCOVERY_RESPONSE | 148 bytes | 116 bytes | 32 bytes | 21.6% |
| DISCOVERY_CONFIRM | 148 bytes | 116 bytes | 32 bytes | 21.6% |

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

### Simplified Session States
```pseudocode
Session States:
- CLOSED: No session exists
- LISTENING: Server waiting for connection
- SYN_SENT: Client sent SYN, waiting for SYN-ACK
- SYN_RECEIVED: Server received SYN, sent SYN-ACK
- ESTABLISHED: Connection active, data flowing
- FIN_WAIT_1: Sent FIN, waiting for ACK
- FIN_WAIT_2: Received FIN-ACK, waiting for FIN
- CLOSE_WAIT: Received FIN, waiting to close
- CLOSING: Both sides sent FIN, waiting for ACKs
- LAST_ACK: Sent FIN, waiting for final ACK
- TIME_WAIT: Connection closing, waiting for timeout
- RECOVERING: Session recovery in progress
- ERROR: Error state, connection should be closed
```

### Complete State Transitions with Error Handling
```pseudocode
State Transitions with Error Handling:

CLOSED -> LISTENING: bind()
LISTENING -> SYN_RECEIVED: receive_syn() [Timeout: 30s]
LISTENING -> CLOSED: timeout() or error
LISTENING -> ERROR: receive_invalid_packet()

CLOSED -> SYN_SENT: connect()
SYN_SENT -> ESTABLISHED: receive_syn_ack() && send_ack()
SYN_SENT -> CLOSED: timeout() [Timeout: 30s] or error
SYN_SENT -> ERROR: receive_error() or authentication_failure()
SYN_SENT -> SYN_SENT: receive_syn() [Send RST]

SYN_RECEIVED -> ESTABLISHED: receive_ack()
SYN_RECEIVED -> CLOSED: timeout() [Timeout: 30s] or error
SYN_RECEIVED -> ERROR: receive_error() or authentication_failure()
SYN_RECEIVED -> SYN_RECEIVED: receive_syn() [Resend SYN-ACK]

ESTABLISHED -> CLOSE_WAIT: receive_fin()
ESTABLISHED -> ERROR: receive_error() or authentication_failure()
ESTABLISHED -> RECOVERING: sync_failure() or heartbeat_timeout()
ESTABLISHED -> ESTABLISHED: receive_data() or receive_ack()

CLOSING -> TIME_WAIT: receive_fin_ack()
CLOSING -> CLOSED: timeout() [Timeout: 30s] or error
CLOSING -> ERROR: receive_error()

LAST_ACK -> CLOSED: receive_ack()
LAST_ACK -> CLOSED: timeout() [Timeout: 30s] or error
LAST_ACK -> ERROR: receive_error()

TIME_WAIT -> CLOSED: timeout() [Timeout: 60s]

RECOVERING -> ESTABLISHED: recovery_success()
RECOVERING -> CLOSED: recovery_failure() [Timeout: 30s]
RECOVERING -> ERROR: max_recovery_attempts_exceeded()

ERROR -> CLOSED: cleanup() [Immediate]

## Discovery Process with Zero-Knowledge Proof

### Zero-Knowledge Discovery Protocol

The discovery process uses a truly zero-knowledge approach that requires no pre-shared keys or secret material exchange. Instead, it relies on Pedersen commitments and zero-knowledge proofs to establish trust and find common PSKs.

```pseudocode
# Discovery protocol uses Pedersen commitments for zero-knowledge proofs
# No pre-shared keys are required for the discovery process

// Pedersen commitment implementation follows RFC 9380 (HPKE)
// Reference: https://tools.ietf.org/html/rfc9380
// Uses standard elliptic curve cryptography for zero-knowledge proofs

function generate_pedersen_commitment(value, randomness):
    # Generate Pedersen commitment following RFC 9380 specification
    # C = g^value * h^randomness where g and h are public generators
    # This provides perfect hiding and computational binding
    # Implementation should use standard elliptic curve library (e.g., OpenSSL, BouncyCastle)
    commitment = elliptic_curve_pedersen_commit(value, randomness)
    return commitment

function verify_pedersen_commitment(commitment, value, randomness):
    # Verify Pedersen commitment following RFC 9380 specification
    # Implementation should use standard elliptic curve library (e.g., OpenSSL, BouncyCastle)
    expected_commitment = elliptic_curve_pedersen_commit(value, randomness)
    return constant_time_compare(commitment, expected_commitment)

function generate_psk_commitment(psk_list, challenge_nonce):
    # Generate Pedersen commitment to PSK list without revealing individual PSKs
    # This prevents enumeration of available PSKs
    # Uses RFC 9380 Pedersen commitment for zero-knowledge proof
    
    # Hash PSK list for deterministic commitment
    psk_hash = hash_psk_list(psk_list)
    
    # Generate random blinding factor using RFC 5869 HKDF
    randomness = generate_random_scalar()
    
    # Create Pedersen commitment following RFC 9380
    commitment = generate_pedersen_commitment(psk_hash, randomness)
    
    return commitment, randomness

function verify_psk_commitment(commitment, challenge_nonce, psk_count):
    # Verify Pedersen commitment structure and format
    # Follows RFC 9380 specification for commitment validation
    if len(commitment) != PEDERSEN_COMMITMENT_SIZE:
        return False
    
    # Verify commitment is not identity element
    if commitment == identity_element:
        return False
    
    return True
```


### Discovery States
```pseudocode
Discovery States:
- DISCOVERY_IDLE: No discovery in progress
- DISCOVERY_INITIATED: Discovery initiated, waiting for response
- DISCOVERY_RESPONDED: Discovery response received, waiting for confirmation
- DISCOVERY_COMPLETED: Discovery completed, PSK selected
- DISCOVERY_FAILED: Discovery failed, no common PSK found
```

### Discovery State Transitions
```pseudocode
Discovery State Transitions:

DISCOVERY_IDLE -> DISCOVERY_INITIATED: initiate_discovery()
DISCOVERY_INITIATED -> DISCOVERY_RESPONDED: receive_discovery_response()
DISCOVERY_INITIATED -> DISCOVERY_FAILED: timeout() [Timeout: 10s] or error
DISCOVERY_RESPONDED -> DISCOVERY_COMPLETED: send_discovery_confirm()
DISCOVERY_RESPONDED -> DISCOVERY_FAILED: timeout() [Timeout: 10s] or error
DISCOVERY_COMPLETED -> DISCOVERY_IDLE: start_session_establishment()
DISCOVERY_FAILED -> DISCOVERY_IDLE: cleanup_discovery()
```

### Simplified PSK Discovery Protocol
```pseudocode
function generate_psk_commitment(psk_list, challenge_nonce):
    # Generate Pedersen commitment to PSK list without revealing individual PSKs
    # This prevents enumeration of available PSKs
    # Uses RFC 9380 Pedersen commitment for zero-knowledge proof
    
    # Hash PSK list for deterministic commitment
    psk_hash = hash_psk_list(psk_list)
    
    # Generate random blinding factor using RFC 5869 HKDF
    randomness = generate_random_scalar()
    
    # Create Pedersen commitment following RFC 9380
    commitment = generate_pedersen_commitment(psk_hash, randomness)
    
    return commitment, randomness

function verify_psk_commitment(commitment, challenge_nonce, psk_count):
    # Verify Pedersen commitment structure and format
    # Follows RFC 9380 specification for commitment validation
    if len(commitment) != PEDERSEN_COMMITMENT_SIZE:
        return False
    
    # Verify commitment is not identity element
    if commitment == identity_element:
        return False
    
    return True

function find_common_psk(initiator_psk_list, responder_psk_list):
    # Find common PSK between two lists using secure set intersection
    # Prevents enumeration of available PSKs
    
    # Use secure set intersection protocol
    common_psk_index = secure_set_intersection(initiator_psk_list, responder_psk_list)
    
    return common_psk_index

function secure_set_intersection(list_a, list_b):
    # Secure set intersection that prevents PSK enumeration
    # Uses oblivious transfer to find intersection without revealing individual PSKs
    
    # Generate random blinding factors
    blinding_factors = generate_random_blinding_factors(len(list_a))
    
    # Blind the PSK lists
    blinded_list_a = blind_psk_list(list_a, blinding_factors)
    blinded_list_b = blind_psk_list(list_b, blinding_factors)
    
    # Find intersection using oblivious transfer
    intersection = oblivious_set_intersection(blinded_list_a, blinded_list_b)
    
    # Unblind the result
    common_psk_index = unblind_intersection(intersection, blinding_factors)
    
    return common_psk_index

## Complete Cryptographic Specifications

### PSK Discovery Protocol Implementation
```pseudocode
// PSK discovery parameters
DISCOVERY_COMMITMENT_SIZE = 32           // Size of PSK commitment in bytes
DISCOVERY_CHALLENGE_SIZE = 32            // Size of challenge nonce in bytes
MAX_PSK_LIST_SIZE = 256                  // Maximum number of PSKs per peer

function hash_psk_list(psk_list):
    # Hash PSK list for commitment generation
    # Uses SHA256 as specified in RFC 6234
    
    if not psk_list:
        return SHA256(b'')
    
    # Sort PSKs for deterministic hashing
    sorted_psks = sorted(psk_list)
    
    # Concatenate all PSKs
    concatenated = b''
    for psk in sorted_psks:
        concatenated += psk
    
    return SHA256(concatenated)

function generate_psk_commitment(psk_list, challenge_nonce):
    # Generate Pedersen commitment to PSK list
    # Follows RFC 9380 for Pedersen commitments
    
    psk_hash = hash_psk_list(psk_list)
    randomness = generate_random_scalar()
    commitment = generate_pedersen_commitment(psk_hash, randomness)
    
    return commitment, randomness

function verify_psk_commitment(commitment, challenge_nonce, psk_count):
    # Verify Pedersen commitment structure and format
    if len(commitment) != PEDERSEN_COMMITMENT_SIZE:
        return False
    
    # Verify commitment is not identity element
    if commitment == identity_element:
        return False
    
    return True

function generate_psk_selection_commitment(selected_index, psk_list, challenge_nonce, response_nonce):
    # Generate Pedersen commitment for PSK selection following RFC 9380
    # This proves that the selected PSK is valid without revealing the selection process
    
    # Hash the selection parameters using RFC 6234 SHA256
    selection_hash = hash_selection_parameters(selected_index, psk_list, challenge_nonce, response_nonce)
    
    # Generate random blinding factor using RFC 5869 HKDF
    randomness = generate_random_scalar()
    
    # Create Pedersen commitment following RFC 9380
    commitment = generate_pedersen_commitment(selection_hash, randomness)
    
    return commitment, randomness

function verify_psk_selection_commitment(commitment, selected_index, psk_list, challenge_nonce, response_nonce, randomness):
    # Verify Pedersen commitment for PSK selection following RFC 9380
    selection_hash = hash_selection_parameters(selected_index, psk_list, challenge_nonce, response_nonce)
    expected_commitment = generate_pedersen_commitment(selection_hash, randomness)
    
    return constant_time_compare(commitment, expected_commitment)

function hash_selection_parameters(selected_index, psk_list, challenge_nonce, response_nonce):
    # Hash selection parameters for commitment using RFC 6234 SHA256
    data = selected_index.to_bytes(2, 'big') + challenge_nonce.to_bytes(8, 'big') + response_nonce.to_bytes(8, 'big')
    
    # Add PSK list hash
    psk_hash = hash_psk_list(psk_list)
    data += psk_hash
    
    return SHA256(data)
```

### Secure Set Intersection Implementation
```pseudocode
function secure_set_intersection(list_a, list_b):
    # Secure set intersection using oblivious transfer
    # Prevents enumeration of individual PSKs
    # Implementation follows RFC 9380 for zero-knowledge proofs
    
    # Generate random blinding factors using RFC 5869 HKDF
    blinding_factors = generate_random_blinding_factors(len(list_a))
    
    # Blind the PSK lists using RFC 2104 HMAC-SHA256
    blinded_list_a = blind_psk_list(list_a, blinding_factors)
    blinded_list_b = blind_psk_list(list_b, blinding_factors)
    
    # Find intersection using oblivious transfer
    intersection = oblivious_set_intersection(blinded_list_a, blinded_list_b)
    
    # Unblind the result
    common_psk_index = unblind_intersection(intersection, blinding_factors)
    
    return common_psk_index

function generate_random_blinding_factors(count):
    # Generate cryptographically secure random blinding factors
    # Uses RFC 5869 HKDF for key derivation
    factors = []
    for i in range(count):
        factor = secure_random_bytes(32)
        factors.append(factor)
    return factors

function blind_psk_list(psk_list, blinding_factors):
    # Blind PSK list using RFC 2104 HMAC-SHA256
    blinded_list = []
    
    for i, psk in enumerate(psk_list):
        blinding_factor = blinding_factors[i]
        blinded_psk = HMAC_SHA256(blinding_factor, psk)
        blinded_list.append(blinded_psk)
    
    return blinded_list

function oblivious_set_intersection(blinded_list_a, blinded_list_b):
    # Find intersection without revealing individual values
    intersection = []
    
    # Use hash-based intersection
    set_b = set(blinded_list_b)
    
    for blinded_psk in blinded_list_a:
        if blinded_psk in set_b:
            intersection.append(blinded_psk)
    
    return intersection

function unblind_intersection(intersection, blinding_factors):
    # Unblind intersection result to find original index
    if len(intersection) == 0:
        return -1  # No common PSK found
    
    # Find the index of the first intersection
    for i, blinding_factor in enumerate(blinding_factors):
        test_blinded = HMAC_SHA256(blinding_factor, psk_list[i])
        if test_blinded in intersection:
            return i
    
    return -1
```

### HKDF Implementation (RFC 5869)
```pseudocode
# HKDF implementation follows RFC 5869 specification
# Reference: https://tools.ietf.org/html/rfc5869

function HKDF_SHA256(salt, ikm, info, length):
    # HKDF-SHA256 implementation as specified in RFC 5869
    # salt: salt value
    # ikm: input keying material
    # info: context and application specific information
    # length: length of output keying material
    
    # Extract phase
    prk = HMAC_SHA256(salt, ikm)
    
    # Expand phase
    okm = HKDF_Expand(prk, info, length)
    
    return okm

function HKDF_Expand(prk, info, length):
    # HKDF expand function
    # prk: pseudorandom key from extract phase
    # info: context and application specific information
    # length: length of output keying material
    
    if length > 255 * 32:  # SHA256 output size is 32 bytes
        raise ValueError("Length too long for HKDF")
    
    # Calculate number of hash blocks needed
    n = (length + 31) // 32  # Ceiling division
    
    # Initialize output
    okm = b''
    t = b''
    
    for i in range(1, n + 1):
        # T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
        t = HMAC_SHA256(prk, t + info + bytes([i]))
        okm += t
    
    return okm[:length]

function HMAC_SHA256(key, data):
    # HMAC-SHA256 implementation as specified in RFC 2104
    # Reference: https://tools.ietf.org/html/rfc2104
    # key: key for HMAC
    # data: data to hash
    
    # Constants
    BLOCK_SIZE = 64  # SHA256 block size
    OUTPUT_SIZE = 32  # SHA256 output size
    
    # Prepare key
    if len(key) > BLOCK_SIZE:
        key = SHA256(key)
    
    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))
    
    # Outer and inner padding
    outer_pad = bytes(x ^ 0x5c for x in key)
    inner_pad = bytes(x ^ 0x36 for x in key)
    
    # HMAC calculation
    inner_hash = SHA256(inner_pad + data)
    outer_hash = SHA256(outer_pad + inner_hash)
    
    return outer_hash

function SHA256(data):
    # SHA256 implementation as specified in RFC 6234
    # Reference: https://tools.ietf.org/html/rfc6234
    # In practice, use a cryptographic library
    # This is a placeholder for the actual SHA256 implementation
    pass
```

# Discovery protocol uses Pedersen commitments for zero-knowledge proofs
# No pre-shared keys are required for the discovery process

function get_discovered_psk(session_id):
    # Retrieve the PSK that was discovered for this session
    return session_state.discovered_psk

function store_discovered_psk(session_id, psk):
    # Store the discovered PSK for this session
    session_state.discovered_psk = psk

function cleanup_discovery():
    # Clean up discovery state
    clear_discovery_timer()
    clear_discovery_state()
    session_state.discovery_state = DISCOVERY_IDLE
    session_state.discovered_psk = None
    session_state.discovery_id = 0
    session_state.challenge_nonce = 0
    session_state.response_nonce = 0
```

### Discovery Process Algorithm
```pseudocode
function initiate_discovery():
    # Start discovery process on well-known port
    discovery_id = generate_random_64bit()
    challenge_nonce = generate_random_64bit()
    
    # Generate Pedersen commitment to PSK list
    psk_commitment, randomness = generate_psk_commitment(local_psk_list, challenge_nonce)
    
    discovery_packet = create_discovery_packet(
        discovery_id = discovery_id,
        psk_count = len(local_psk_list),
        challenge_nonce = challenge_nonce,
        features = supported_features,
        commitment = psk_commitment
    )
    
    # Store randomness for later verification
    session_state.discovery_randomness = randomness
    
    send_packet(discovery_packet, DISCOVERY_PORT)
    set_discovery_timer(DISCOVERY_TIMEOUT_MS)
    transition_to(DISCOVERY_INITIATED)

function handle_discovery_packet(discovery_packet):
    # Handle incoming discovery packet
    discovery_id = discovery_packet.discovery_id
    initiator_psk_count = discovery_packet.psk_count
    challenge_nonce = discovery_packet.challenge_nonce
    initiator_features = discovery_packet.initiator_features
    initiator_commitment = discovery_packet.commitment
    
    # Verify Pedersen commitment structure
    if not verify_psk_commitment(initiator_commitment, challenge_nonce, initiator_psk_count):
        log_error("Discovery packet commitment verification failed")
        return
    
    # Generate response nonce
    response_nonce = generate_random_64bit()
    
    # Generate Pedersen commitment for our PSK list
    psk_commitment, randomness = generate_psk_commitment(local_psk_list, challenge_nonce)
    
    discovery_response = create_discovery_response_packet(
        discovery_id = discovery_id,
        psk_count = len(local_psk_list),
        challenge_nonce = challenge_nonce,
        response_nonce = response_nonce,
        commitment = psk_commitment,
        features = supported_features
    )
    
    # Store randomness for later verification
    session_state.discovery_randomness = randomness
    
    send_packet(discovery_response, DISCOVERY_PORT)
    transition_to(DISCOVERY_RESPONDED)

function handle_discovery_response(discovery_response):
    # Handle discovery response
    discovery_id = discovery_response.discovery_id
    responder_psk_count = discovery_response.psk_count
    challenge_nonce = discovery_response.challenge_nonce
    response_nonce = discovery_response.response_nonce
    responder_commitment = discovery_response.commitment
    responder_features = discovery_response.responder_features
    
    # Verify Pedersen commitment structure
    if not verify_psk_commitment(responder_commitment, challenge_nonce, responder_psk_count):
        log_error("Discovery response commitment verification failed")
        transition_to(DISCOVERY_FAILED)
        return
    
    # Find common PSK using secure set intersection
    common_psk_index = find_common_psk(local_psk_list, responder_psk_count)
    
    if common_psk_index == -1:
        # No common PSK found
        transition_to(DISCOVERY_FAILED)
        return
    
    # Generate Pedersen commitment for PSK selection
    selection_commitment, selection_randomness = generate_psk_selection_commitment(
        common_psk_index, 
        local_psk_list, 
        challenge_nonce, 
        response_nonce
    )
    
    # Generate new session ID
    session_id = generate_session_id()
    
    discovery_confirm = create_discovery_confirm_packet(
        discovery_id = discovery_id,
        selected_psk_index = common_psk_index,
        challenge_nonce = challenge_nonce,
        response_nonce = response_nonce,
        commitment = selection_commitment,
        session_id = session_id
    )
    
    # Store selection randomness for later verification
    session_state.selection_randomness = selection_randomness
    
    send_packet(discovery_confirm, DISCOVERY_PORT)
    transition_to(DISCOVERY_COMPLETED)

function handle_discovery_confirm(discovery_confirm):
    # Handle discovery confirmation
    discovery_id = discovery_confirm.discovery_id
    selected_psk_index = discovery_confirm.selected_psk_index
    challenge_nonce = discovery_confirm.challenge_nonce
    response_nonce = discovery_confirm.response_nonce
    selection_commitment = discovery_confirm.commitment
    session_id = discovery_confirm.session_id
    
    # Verify Pedersen commitment structure
    if not verify_psk_commitment(selection_commitment, challenge_nonce, len(local_psk_list)):
        log_error("Discovery confirm commitment verification failed")
        transition_to(DISCOVERY_FAILED)
        return
    
    # Verify selection commitment using stored randomness
    if not verify_psk_selection_commitment(selection_commitment, selected_psk_index, local_psk_list, challenge_nonce, response_nonce, session_state.selection_randomness):
        transition_to(DISCOVERY_FAILED)
        return
    
    # Store selected PSK and session ID
    selected_psk = local_psk_list[selected_psk_index]
    session_state.discovered_psk = selected_psk
    session_state.session_id = session_id
    
    # Start session establishment using selected PSK
    start_session_establishment(selected_psk, session_id)
    transition_to(DISCOVERY_IDLE)

function start_session_establishment(selected_psk, session_id):
    # Begin normal session establishment using discovered PSK
    # This integrates with the existing SYN/SYN-ACK handshake
    
    # Set the selected PSK for this session
    session_psk = selected_psk
    current_session_id = session_id
    
    # Calculate initial port using selected PSK with delay allowance
    daily_key = derive_daily_key(selected_psk, get_current_date())
    available_ports = get_current_port_with_delay_allowance(daily_key, session_id)
    
    # Begin connection establishment on calculated ports
    # Try each port in order to handle transmission delay
    for port in available_ports:
        initiate_connection(port, session_id)

### Integration with Existing Session Establishment
```pseudocode
function initiate_connection(port, session_id):
    # Modified connection initiation to use discovered PSK
    # This replaces the original connect() function
    
    # Get the PSK that was discovered during the discovery process
    discovered_psk = get_discovered_psk(session_id)
    if not discovered_psk:
        log_error("No discovered PSK found for session " + session_id)
        transition_to(ERROR)
        return
    
    # Use the discovered PSK for key derivation
    daily_key = derive_daily_key(discovered_psk, get_current_date())
    
    # Establish initial session key using discovered PSK
    session_key = establish_session_key_with_psk(discovered_psk, session_id)
    
    # Create SYN packet with discovered session ID
    syn_packet = create_syn_packet(
        session_id = session_id,
        sequence_number = INITIAL_SEQUENCE_NUMBER,
        congestion_window = INITIAL_CONGESTION_WINDOW,
        receive_window = INITIAL_RECEIVE_WINDOW,
        time_offset = get_time_offset(),
        features = negotiated_features
    )
    
    # Calculate HMAC using session key derived from discovered PSK
    syn_hmac = calculate_packet_hmac(syn_packet, session_key)
    syn_packet.hmac = syn_hmac
    
    # Send SYN packet to calculated port
    send_packet(syn_packet, port)
    transition_to(SYN_SENT)

function handle_syn_with_discovery(syn_packet):
    # Handle SYN packet when PSK was discovered through discovery process
    session_id = syn_packet.session_id
    
    # Get the PSK that was selected during discovery
    discovered_psk = get_discovered_psk(session_id)
    if not discovered_psk:
        log_error("No discovered PSK found for session " + session_id)
        send_error_packet(session_id, ERROR_SESSION_NOT_FOUND)
        return
    
    # Use the discovered PSK for key derivation
    daily_key = derive_daily_key(discovered_psk, get_current_date())
    
    # Establish initial session key using discovered PSK
    session_key = establish_session_key_with_psk(discovered_psk, session_id)
    
    # Verify HMAC using session key derived from discovered PSK
    if not verify_packet_hmac(syn_packet, session_key, syn_packet.hmac):
        send_error_packet(session_id, ERROR_AUTHENTICATION_FAILED)
        return
    
    # Create SYN-ACK packet
    syn_ack_packet = create_syn_ack_packet(
        session_id = session_id,
        sequence_number = generate_sequence_number(),
        acknowledgment_number = syn_packet.sequence_number + 1,
        congestion_window = INITIAL_CONGESTION_WINDOW,
        receive_window = INITIAL_RECEIVE_WINDOW,
        time_offset = get_time_offset(),
        features = negotiate_features(syn_packet.features, supported_features)
    )
    
    # Calculate HMAC using session key derived from discovered PSK
    syn_ack_hmac = calculate_packet_hmac(syn_ack_packet, session_key)
    syn_ack_packet.hmac = syn_ack_hmac
    
    # Send SYN-ACK packet
    send_packet(syn_ack_packet, syn_packet.source_port)
    transition_to(SYN_RECEIVED)

### Complete Discovery Workflow
```pseudocode
function establish_connection_with_discovery():
    # Complete workflow: Discovery -> Session Establishment
    
    # Step 1: Start discovery process
    initiate_discovery()
    
    # Discovery process runs asynchronously
    # When discovery completes, start_session_establishment() is called
    # which then calls initiate_connection() to begin normal session establishment

function handle_discovery_timeout():
    # Handle discovery timeout
    if discovery_retry_count < DISCOVERY_RETRY_COUNT:
        discovery_retry_count += 1
        initiate_discovery()  # Retry discovery
    else:
        transition_to(DISCOVERY_FAILED)
        log_error("Discovery failed after " + DISCOVERY_RETRY_COUNT + " attempts")

function handle_discovery_error(error_code):
    # Handle discovery errors
    switch error_code:
        case ERROR_DISCOVERY_FAILED:
            log_error("Discovery process failed")
            transition_to(DISCOVERY_FAILED)
            
        case ERROR_PSK_NOT_FOUND:
            log_error("No common PSK found between peers")
            transition_to(DISCOVERY_FAILED)
            
        case ERROR_ZERO_KNOWLEDGE_PROOF_FAILED:
            log_error("Commitment verification failed")
            transition_to(DISCOVERY_FAILED)
            
        case ERROR_DISCOVERY_TIMEOUT:
            log_error("Discovery process timed out")
            handle_discovery_timeout()

# Integration with existing connection establishment
function connect_with_discovery(remote_address):
    # Enhanced connect function that includes discovery
    # This replaces the original connect() function
    
    # Start discovery process
    establish_connection_with_discovery()
    
    # Discovery will automatically trigger session establishment
    # when a common PSK is found

function listen_with_discovery():
    # Enhanced listen function that handles discovery
    # This replaces the original listen() function
    
    # Listen on well-known discovery port
    bind_socket(DISCOVERY_PORT)
    
    # Also listen on ephemeral ports for normal communication
    # after discovery completes

### Complete Discovery Workflow Summary

The discovery process uses a truly zero-knowledge approach that requires no pre-shared keys or secret material exchange. Instead, it relies on cryptographic commitments and zero-knowledge proofs to establish trust and find common PSKs.

**Discovery Phase (Uses Cryptographic Commitments):**
1. **Discovery Initiation**: Client sends DISCOVERY packet with commitment using challenge nonce
2. **Discovery Response**: Server responds with DISCOVERY_RESPONSE packet with commitment using response nonce
3. **Discovery Confirmation**: Client sends DISCOVERY_CONFIRM packet with commitment using both nonces
4. **PSK Selection**: Both parties agree on a common PSK through zero-knowledge proof

**Session Establishment Phase (Uses Discovered PSK):**
1. **Session Key Derivation**: Both parties derive session keys from the discovered PSK
2. **Connection Establishment**: Normal SYN/SYN-ACK handshake using session keys
3. **Data Communication**: All subsequent packets use session keys derived from discovered PSK

**Key Benefits:**
- **No Pre-shared Keys**: Discovery uses cryptographic commitments, not shared secrets
- **Zero-Knowledge**: No secret material is exchanged during discovery
- **Trust Establishment**: Trust is established through cryptographic proofs
- **PSK Protection**: PSK discovery prevents enumeration of available PSKs
- **Seamless Integration**: Discovery automatically transitions to normal session establishment

```
```
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
                
        case SYN_SENT:
            if packet.type == PACKET_TYPE_SYN:
                # Simultaneous open
                send_syn_ack_packet(packet.session_id)
                return SUCCESS
            elif packet.type == PACKET_TYPE_SYN_ACK:
                return handle_syn_ack_in_syn_sent_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case SYN_RECEIVED:
            if packet.type == PACKET_TYPE_SYN:
                # Resend SYN-ACK
                send_syn_ack_packet(packet.session_id)
                return SUCCESS
            elif packet.type == PACKET_TYPE_ACK:
                return handle_ack_in_syn_received_state(packet)
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
    # The HMAC field is always the last 32 bytes of the packet (SHA256)
    
    # Extract packet without HMAC
    packet_without_hmac = packet_data[0:len(packet_data)-32]
    
    # Calculate HMAC-SHA256 using session key
    hmac_result = HMAC_SHA256(session_key, packet_without_hmac)
    
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

## Flow Control Specification (RFC 793)

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

## Security Parameter Specifications

### Enhanced Key Management with Session Key Derivation
```pseudocode
// Key derivation parameters
MASTER_PSK_LENGTH = 32                   // Master PSK length in bytes
DAY_KEY_LENGTH = 32                      // Day key length in bytes
DAILY_KEY_LENGTH = 32                    // Derived daily key length
HMAC_KEY_LENGTH = 32                     // HMAC key length
SESSION_KEY_LENGTH = 32                  // Session key length

// Key rotation schedule
DAY_KEY_ROTATION_INTERVAL = 86400000     // 24 hours in milliseconds
KEY_PRE_ROTATION_TIME = 3600000          // 1 hour before rotation
SESSION_KEY_ROTATION_INTERVAL = 300000   // 5 minutes session key rotation

// Session key derivation using RFC 5869 HKDF
function derive_daily_key(master_psk, day_key, current_date):
    salt = day_key
    ikm = master_psk || current_date
    info = "FHOP-DAILY-KEY" || current_date
    return HKDF_SHA256(salt, ikm, info, DAILY_KEY_LENGTH)

function derive_session_key(daily_key, session_id, current_time):
    # Derive session-specific key using time-based entropy
    # Follows RFC 5869 HKDF specification
    
    # Generate time-based entropy for session key
    time_entropy = generate_time_based_entropy(current_time)
    
    # Use HKDF for key derivation
    salt = daily_key
    ikm = time_entropy || session_id
    info = "FHOP-SESSION-KEY" || session_id
    return HKDF_SHA256(salt, ikm, info, SESSION_KEY_LENGTH)

function generate_time_based_entropy(current_time):
    # Generate entropy based on current time window
    # Uses 5-minute windows for session key rotation
    # Based on UTC time from start of current day
    utc_time_ms = get_utc_time_milliseconds()
    time_from_day_start = utc_time_ms % (24 * 60 * 60 * 1000)  # Milliseconds since start of day
    time_window = time_from_day_start // SESSION_KEY_ROTATION_INTERVAL
    
    # Convert time window to bytes
    time_window_bytes = time_window.to_bytes(8, byteorder='big')
    
    # Generate entropy using HMAC with daily key
    entropy = HMAC_SHA256(daily_key, time_window_bytes)
    
    return entropy

function rotate_session_key():
    # Rotate session key every 5 minutes
    # Based on UTC time from start of current day
    utc_time_ms = get_utc_time_milliseconds()
    time_from_day_start = utc_time_ms % (24 * 60 * 60 * 1000)  # Milliseconds since start of day
    new_session_key = derive_session_key(daily_key, session_id, time_from_day_start)
    
    # Update session state
    current_session_key = new_session_key
    current_session_key_generation_time = (time_from_day_start // SESSION_KEY_ROTATION_INTERVAL) * SESSION_KEY_ROTATION_INTERVAL
    
    # Schedule next rotation
    schedule_session_key_rotation(time_from_day_start + SESSION_KEY_ROTATION_INTERVAL)

function schedule_session_key_rotation(next_rotation_time):
    # Schedule next session key rotation
    rotation_timer = next_rotation_time - get_current_time()
    if rotation_timer > 0:
        schedule_timer(rotation_timer, rotate_session_key)

// Enhanced HMAC calculation with session keys
function calculate_packet_hmac(packet_data, session_key):
    hmac_input = packet_data[0:len(packet_data)-32]  // Exclude HMAC field
    return HMAC_SHA256(session_key, hmac_input)

// Session key management during connection establishment
function establish_session_key(session_id):
    # Establish initial session key during connection setup
    # Based on UTC time from start of current day
    utc_time_ms = get_utc_time_milliseconds()
    time_from_day_start = utc_time_ms % (24 * 60 * 60 * 1000)  # Milliseconds since start of day
    session_key = derive_session_key(daily_key, session_id, time_from_day_start)
    
    # Store session key and generation time
    current_session_key = session_key
    current_session_key_generation_time = (time_from_day_start // SESSION_KEY_ROTATION_INTERVAL) * SESSION_KEY_ROTATION_INTERVAL
    
    # Schedule first rotation
    schedule_session_key_rotation(time_from_day_start + SESSION_KEY_ROTATION_INTERVAL)
    
    return session_key

function establish_session_key_with_psk(psk, session_id):
    # Establish session key using a specific PSK (for discovered PSKs)
    # Based on UTC time from start of current day
    utc_time_ms = get_utc_time_milliseconds()
    time_from_day_start = utc_time_ms % (24 * 60 * 60 * 1000)  # Milliseconds since start of day
    
    # Derive daily key from the specific PSK
    daily_key = derive_daily_key(psk, get_current_date())
    
    # Derive session key using the daily key
    session_key = derive_session_key(daily_key, session_id, time_from_day_start)
    
    # Store session key and generation time
    current_session_key = session_key
    current_session_key_generation_time = (time_from_day_start // SESSION_KEY_ROTATION_INTERVAL) * SESSION_KEY_ROTATION_INTERVAL
    
    # Schedule first rotation
    schedule_session_key_rotation(time_from_day_start + SESSION_KEY_ROTATION_INTERVAL)
    
    return session_key

function get_current_session_key():
    # Get current session key, rotating if necessary
    # Based on UTC time from start of current day
    utc_time_ms = get_utc_time_milliseconds()
    time_from_day_start = utc_time_ms % (24 * 60 * 60 * 1000)  # Milliseconds since start of day
    expected_rotation_time = (time_from_day_start // SESSION_KEY_ROTATION_INTERVAL) * SESSION_KEY_ROTATION_INTERVAL
    
    if current_session_key_generation_time != expected_rotation_time:
        # Session key needs rotation
        rotate_session_key()
    
    return current_session_key
```

### Anti-Replay Protection
```pseudocode
// Replay protection parameters
REPLAY_WINDOW_SIZE = 1000                // Number of recent timestamps to track
REPLAY_WINDOW_TIME_MS = 30000            // Time window for replay detection

// Timestamp validation
function validate_packet_timestamp(packet_timestamp, current_time):
    time_difference = abs(current_time - packet_timestamp)
    
    if time_difference > TIMESTAMP_WINDOW_MS:
        return ERROR_TIMESTAMP_INVALID
    
    if packet_timestamp in recent_timestamps:
        return ERROR_REPLAY_ATTACK
    
    add_to_recent_timestamps(packet_timestamp)
    return SUCCESS

function add_to_recent_timestamps(timestamp):
    # Add timestamp to sliding window
    recent_timestamps.add(timestamp)
    
    # Remove old timestamps
    current_time = get_current_time()
    expired_timestamps = []
    
    for ts in recent_timestamps:
        if current_time - ts > REPLAY_WINDOW_TIME_MS:
            expired_timestamps.append(ts)
    
    for ts in expired_timestamps:
        recent_timestamps.remove(ts)
```

### PSK Enumeration Prevention
```pseudocode
// PSK enumeration prevention parameters
MAX_PSK_DISCOVERY_ATTEMPTS = 5          // Maximum discovery attempts per peer
PSK_DISCOVERY_RATE_LIMIT_MS = 60000     // Rate limit for discovery attempts (1 minute)
ENUMERATION_DETECTION_THRESHOLD = 10     // Threshold for detecting enumeration attempts

// PSK enumeration detection
function detect_psk_enumeration_attempt(peer_address, discovery_attempts):
    # Track discovery attempts per peer
    if peer_address not in discovery_attempts:
        discovery_attempts[peer_address] = {
            'count': 0,
            'first_attempt': get_current_time(),
            'last_attempt': get_current_time()
        }
    
    attempts = discovery_attempts[peer_address]
    attempts['count'] += 1
    attempts['last_attempt'] = get_current_time()
    
    # Check for enumeration patterns
    if attempts['count'] > MAX_PSK_DISCOVERY_ATTEMPTS:
        return ERROR_PSK_ENUMERATION_ATTEMPT
    
    # Check rate limiting
    time_since_first = get_current_time() - attempts['first_attempt']
    if time_since_first < PSK_DISCOVERY_RATE_LIMIT_MS:
        if attempts['count'] > ENUMERATION_DETECTION_THRESHOLD:
            return ERROR_PSK_ENUMERATION_ATTEMPT
    
    return SUCCESS

function handle_enumeration_attempt(peer_address):
    # Block peer for extended period
    block_peer(peer_address, BLOCK_DURATION_MS)
    
    # Log enumeration attempt
    log_security_event("PSK enumeration attempt detected from " + peer_address)
    
    # Send error response
    send_error_packet(ERROR_PSK_ENUMERATION_ATTEMPT, "Enumeration attempt detected")
```

### Session ID Generation
```pseudocode
function generate_session_id():
    # Generate cryptographically secure random session ID
    random_bytes = secure_random_bytes(8)
    session_id = bytes_to_uint64(random_bytes)
    
    # Ensure session ID is not zero
    if session_id == 0:
        session_id = 1
    
    return session_id

```

## Configuration Parameters

### Negotiable Parameters
```pseudocode
// Parameters that can be negotiated during handshake
NEGOTIABLE_PARAMETERS = {
    'hop_interval_ms': {
        'default': 250,
        'min': 100,
        'max': 1000,
        'description': 'Port hop interval in milliseconds'
    },
    'heartbeat_interval_ms': {
        'default': 30000,
        'min': 10000,
        'max': 60000,
        'description': 'Heartbeat interval in milliseconds'
    },
    'initial_congestion_window': {
        'default': 1460,
        'min': 292,
        'max': 65535,
        'description': 'Initial congestion window size in bytes'
    },
    'initial_receive_window': {
        'default': 65535,
        'min': 1024,
        'max': 65535,
        'description': 'Initial receive window size in bytes'
    },
    'max_retransmission_attempts': {
        'default': 8,
        'min': 3,
        'max': 15,
        'description': 'Maximum retransmission attempts'
    },
    'ack_delay_ms': {
        'default': 50,
        'min': 10,
        'max': 200,
        'description': 'ACK delay for batching in milliseconds'
    }
}
```

### Parameter Validation
```pseudocode
function validate_negotiated_parameters(parameters):
    for param_name, param_value in parameters.items():
        if param_name not in NEGOTIABLE_PARAMETERS:
            return ERROR_INVALID_PARAMETER
        
        param_config = NEGOTIABLE_PARAMETERS[param_name]
        
        if param_value < param_config['min'] or param_value > param_config['max']:
            return ERROR_INVALID_PARAMETER
    
    return SUCCESS
```

### Feature Negotiation
```pseudocode
// Supported features bitmap
FEATURE_SACK = 0x00000001               // Selective ACK support
FEATURE_WINDOW_SCALING = 0x00000002     // Window scaling support
FEATURE_TIMESTAMP = 0x00000004          // Timestamp option support
FEATURE_FRAGMENTATION = 0x00000008      // Packet fragmentation support
FEATURE_COMPRESSION = 0x00000010        // Data compression support
FEATURE_ENCRYPTION = 0x00000020         // Data encryption support

function negotiate_features(client_features, server_features):
    # Intersection of supported features
    negotiated_features = client_features & server_features
    
    # Ensure required features are present
    required_features = FEATURE_SACK | FEATURE_TIMESTAMP
    if (negotiated_features & required_features) != required_features:
        return ERROR_INVALID_PARAMETER
    
    return negotiated_features
```


