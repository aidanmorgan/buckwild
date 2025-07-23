# Core Protocol Definitions

This document contains all fundamental definitions including constants, error codes, and naming conventions that are referenced throughout the protocol specification.

## Protocol Constants and Default Values

These constants establish the fundamental operational parameters that ensure consistent behavior across all protocol components.

### Core Protocol Constants

```pseudocode
// Protocol structure constants
OPTIMIZED_COMMON_HEADER_SIZE = 50        // Optimized header size in bytes (used in: packet-structure.md, fragmentation.md)
FRAGMENT_HEADER_SIZE = 8                 // Fragment header size in bytes (used in: fragmentation.md)

// Time-related constants  
HOP_INTERVAL_MS = 500                    // Port hop interval in milliseconds (500ms time windows - used in: port-hopping.md, time-sync.md)
TIME_SYNC_TOLERANCE_MS = 50              // Maximum allowed clock drift (used in: time-sync.md)
HEARTBEAT_INTERVAL_MS = 30000            // Heartbeat interval (30 seconds - used in: timeout-handling.md)
HEARTBEAT_TIMEOUT_MS = 90000             // Heartbeat timeout (90 seconds - used in: timeout-handling.md)
MAX_PACKET_LIFETIME_MS = 60000           // Maximum packet age (60 seconds - used in: timeout-handling.md)
TIMESTAMP_WINDOW_MS = 30000              // Anti-replay timestamp window (used in: crypto.md)
SAFETY_MARGIN_MS = 100                   // Safety margin for delay calculations
BASE_TRANSMISSION_DELAY_ALLOWANCE_MS = 1000 // Base allowance for network transmission delay
ADAPTIVE_DELAY_WINDOW_MIN = 1            // Minimum delay window size (time windows - used in: delay-tuning.md)
ADAPTIVE_DELAY_WINDOW_MAX = 16           // Maximum delay window size (time windows - used in: delay-tuning.md)
DELAY_MEASUREMENT_SAMPLES = 10           // Number of samples for delay measurement (used in: delay-tuning.md)
DELAY_NEGOTIATION_INTERVAL_MS = 60000    // Delay parameters negotiation interval (1 minute - used in: delay-tuning.md)
DELAY_PERCENTILE_TARGET = 95             // Target percentile for delay allowance (95th percentile - used in: delay-tuning.md)
BASE_HEARTBEAT_PAYLOAD_SIZE = 8          // Size of base heartbeat payload (bytes)
MILLISECONDS_PER_DAY = 86400000          // Milliseconds in a day (for timestamp calculation)

// Sequence and window constants
ECDH_KEY_EXCHANGE_TIMEOUT_MS = 10000     // ECDH connection establishment timeout (used in: packet-structure.md)
SESSION_KEY_MATERIAL_SIZE = 128          // Size of master key material from PBKDF2 (1024 bits)
CHUNK_SIZE = 2                           // Size of each 16-bit chunk in bytes
MAX_CHUNKS_PER_DERIVATION = 64           // Maximum number of 16-bit chunks from key material
MAX_SEQUENCE_NUMBER = 0xFFFFFFFF         // Maximum sequence number (used in: 12-psk-discovery.md)
SEQUENCE_WRAP_THRESHOLD = 0x80000000     // Threshold for sequence wraparound (used in: 12-psk-discovery.md)
SEQUENCE_WINDOW_SIZE = 1000              // Sequence number acceptance window (used in: recovery.md)
INITIAL_CONGESTION_WINDOW = 1460         // Initial congestion window (bytes - used in: flow-control.md)
MIN_CONGESTION_WINDOW = 292              // Minimum congestion window (bytes - used in: flow-control.md)
MAX_CONGESTION_WINDOW = 65535            // Maximum congestion window (bytes - used in: flow-control.md)
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

// Port and network constants (maximum realistic range - no collision avoidance needed)
MIN_PORT = 1024                          // Minimum non-privileged port (avoid well-known ports 0-1023)
MAX_PORT = 65535                         // Maximum port value
PORT_RANGE = 64512                       // Full available port range (65535-1024+1)
DISCOVERY_PORT = 1025                    // Well-known port for discovery process
// Note: Port collision avoidance removed - packets routed by session ID
DEFAULT_MTU = 1500                       // Default MTU size
FRAGMENTATION_THRESHOLD = 1400           // Size threshold for fragmentation
MAX_FRAGMENTS = 255                      // Maximum fragments per packet

// Congestion control constants
SLOW_START_THRESHOLD = 65535             // Initial slow start threshold
CONGESTION_AVOIDANCE_INCREMENT = 1       // Window increment in congestion avoidance
FAST_RECOVERY_MULTIPLIER = 0.5          // Window reduction in fast recovery
MSS = 1460                               // Maximum segment size in bytes
MIN_RECEIVE_WINDOW = 1024                // Minimum receive window size

// Congestion control states
SLOW_START = 1                           // Slow start state
CONGESTION_AVOIDANCE = 2                 // Congestion avoidance state
FAST_RECOVERY = 3                        // Fast recovery state

// Discovery and privacy-preserving set intersection constants
MAX_PSK_COUNT = 256                     // Maximum number of PSKs per peer
MAX_PSK_PROOFS_PER_DISCOVERY = 8        // Maximum PSK proofs per discovery request (to limit packet size)
PSK_PROOF_SIZE = 16                     // Size of PSK knowledge proof in bytes
DISCOVERY_TIMEOUT_MS = 10000            // Discovery process timeout (10 seconds)
DISCOVERY_RETRY_COUNT = 3               // Maximum discovery retry attempts
DISCOVERY_CACHE_TTL_MS = 3600000        // Discovery cache time-to-live (1 hour)
DISCOVERY_CHALLENGE_SIZE = 32           // Size of challenge nonce in bytes
PSK_ID_LENGTH = 32                      // Length of PSK identifier

// Privacy-preserving set intersection constants
BLOOM_FILTER_SIZE_BITS_DEFAULT = 2048   // Default Bloom filter size in bits (256 bytes)
BLOOM_FILTER_SIZE_BITS_MAX = 4096       // Maximum Bloom filter size in bits (512 bytes)
BLOOM_FILTER_HASH_FUNCTIONS = 3         // Number of hash functions for Bloom filter
BLOOM_FILTER_FALSE_POSITIVE_RATE = 0.01 // Target false positive rate (1%)
PSI_CANDIDATE_HASH_SIZE = 32            // Size of candidate intersection hash (256-bit)
PSI_MAX_CANDIDATES_PER_RESPONSE = 16    // Maximum candidates in response packet
PSI_BLINDED_FINGERPRINT_SIZE = 16       // Size of blinded PSK fingerprint (128-bit)
PSI_SESSION_SALT_SIZE = 4               // Size of PSI session salt (32-bit)

// Elliptic curve constants (P-256)
CURVE_P256_FIELD_SIZE = 32              // P-256 field element size in bytes
CURVE_P256_SCALAR_SIZE = 32             // P-256 scalar size in bytes
CURVE_P256_POINT_SIZE = 64              // P-256 uncompressed point size in bytes (x + y coordinates)
CURVE_P256_COMPRESSED_SIZE = 33         // P-256 compressed point size (sign + x coordinate)

// ECDH and PBKDF2 constants
ECDH_SHARED_SECRET_SIZE = 32            // ECDH shared secret size in bytes (x-coordinate)
PBKDF2_ITERATIONS_SESSION = 4096        // PBKDF2 iterations for session key derivation
PBKDF2_ITERATIONS_SEQUENCE = 2048       // PBKDF2 iterations for sequence number derivation
PBKDF2_ITERATIONS_PORT = 2048           // PBKDF2 iterations for port offset derivation
KEY_EXCHANGE_TIMEOUT_MS = 10000         // ECDH key exchange timeout (10 seconds)
SHARED_SECRET_VERIFY_SIZE = 32          // Size of shared secret verification hash
FRAGMENT_TIMEOUT_MS = 30000             // Fragment reassembly timeout (30 seconds - used in: fragmentation.md, timeout-handling.md)
BLOCK_DURATION_MS = 300000              // Block duration for enumeration attempts (5 minutes)
REPLAY_THRESHOLD = 5                    // Threshold for replay attack detection

// Recovery timeout constants
RECOVERY_TIMEOUT_MS = 15000             // Recovery process timeout (15 seconds)
RECOVERY_RETRY_INTERVAL_MS = 2000       // Interval between recovery attempts
RECOVERY_MAX_ATTEMPTS = 3               // Maximum recovery attempts before failure
TIME_RESYNC_TIMEOUT_MS = 5000           // Time resynchronization timeout
SEQUENCE_REPAIR_TIMEOUT_MS = 8000       // Sequence repair timeout
REKEY_TIMEOUT_MS = 10000                // Session rekey timeout

// Fragmentation constants
MAX_FRAGMENT_SIZE = 1400                // Maximum fragment payload size (bytes)
FRAGMENT_REASSEMBLY_BUFFER_SIZE = 64    // Maximum fragments in reassembly buffer
FRAGMENT_ID_SPACE = 0xFFFF              // Fragment ID space (16-bit)
FRAGMENT_DUPLICATE_WINDOW = 100         // Window for detecting duplicate fragments

// Flow control constants
INITIAL_SEND_WINDOW = 8192              // Initial send window size (bytes)
INITIAL_RECEIVE_WINDOW = 16384          // Initial receive window size (bytes)
WINDOW_SCALE_FACTOR = 1                 // Window scaling factor
WINDOW_UPDATE_THRESHOLD = 0.5           // Threshold for sending window updates (fraction)
ZERO_WINDOW_PROBE_INTERVAL_MS = 5000    // Zero window probe interval
WINDOW_TIMEOUT_MS = 60000               // Window timeout for flow control

// Recovery mechanism constants
MAX_REPAIR_WINDOW_SIZE = 1000           // Maximum repair window size (packets)
MAX_WINDOW_SIZE = 65535                 // Maximum flow control window size

// Discovery states
DISCOVERY_IDLE = 0                      // No discovery in progress
DISCOVERY_INITIATED = 1                 // Discovery initiated, waiting for response
DISCOVERY_RESPONDED = 2                 // Discovery response received, waiting for confirmation
DISCOVERY_COMPLETED = 3                 // Discovery completed, PSK selected
DISCOVERY_FAILED = 4                    // Discovery failed, no common PSK found

// Protocol validation constants
PACKET_TYPE_MAX = 0x0A                  // Maximum valid packet type value (used in: edge-case-handling.md)
PROTOCOL_MAX_VERSION = 0x01             // Maximum supported protocol version (used in: edge-case-handling.md)
```

The error code design follows a hierarchical structure where similar error types are grouped into ranges, making it easier to categorize and handle errors systematically.


### Enumerated Protocol Error Codes

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
ERROR_ECDH_KEY_EXCHANGE_FAILED = 0x14
ERROR_DISCOVERY_TIMEOUT = 0x15
ERROR_ECDH_VERIFICATION_FAILED = 0x16
ERROR_PSK_ENUMERATION_ATTEMPT = 0x17

// CONTROL packet sub-type errors
ERROR_TIME_SYNC_REQUEST_FAILED = 0x18
ERROR_TIME_SYNC_RESPONSE_FAILED = 0x19
ERROR_RECOVERY_REQUEST_FAILED = 0x1A
ERROR_SEQUENCE_NEGOTIATION_FAILED = 0x1B

// MANAGEMENT packet sub-type errors
ERROR_REKEY_REQUEST_FAILED = 0x1C
ERROR_REKEY_RESPONSE_FAILED = 0x1D
ERROR_REPAIR_REQUEST_FAILED = 0x1E
ERROR_REPAIR_RESPONSE_FAILED = 0x1F

// DISCOVERY packet sub-type errors
ERROR_DISCOVERY_REQUEST_FAILED = 0x20
ERROR_DISCOVERY_RESPONSE_FAILED = 0x21
ERROR_DISCOVERY_CONFIRM_FAILED = 0x22

// Fragmentation and flow control errors
ERROR_FRAGMENT_TIMEOUT = 0x23
ERROR_FRAGMENT_OVERLAP = 0x24
ERROR_FRAGMENT_BOMB = 0x25
ERROR_ZERO_WINDOW_DEADLOCK = 0x26
ERROR_WINDOW_UPDATE_FAILED = 0x27

// Multi-connection errors
ERROR_PORT_COLLISION = 0x28
ERROR_SESSION_ID_COLLISION = 0x29
ERROR_CONNECTION_LIMIT_EXCEEDED = 0x2A

// Security attack detection errors
ERROR_RATE_LIMITED = 0x2B
ERROR_ENUMERATION_DETECTED = 0x2C
ERROR_INJECTION_ATTEMPT = 0x2D
ERROR_TAMPERING_DETECTED = 0x2E

// Privacy-preserving set intersection errors
ERROR_PSI_BLOOM_FILTER_INVALID = 0x2F
ERROR_PSI_NO_INTERSECTION = 0x30
ERROR_PSI_CANDIDATE_VERIFICATION_FAILED = 0x31
ERROR_PSK_CONFIRMATION_INVALID = 0x32
ERROR_PSI_BLINDED_FINGERPRINT_FAILED = 0x33
ERROR_BLOOM_FILTER_SIZE_INVALID = 0x34

// Additional error codes for edge case handling
ERROR_ZERO_KNOWLEDGE_PROOF_FAILED = 0x35
ERROR_UNSUPPORTED_VERSION = 0x36
ERROR_INVALID_PACKET_TYPE = 0x37
ERROR_UNKNOWN_PACKET_TYPE = 0x38
ERROR_INVALID_SUB_TYPE = 0x39
ERROR_PAYLOAD_TOO_LARGE = 0x3A
ERROR_EMPTY_DATA_PACKET = 0x3B
ERROR_INVALID_SESSION_ID = 0x3C

// Connection termination error
ERROR_CONNECTION_TERMINATE = 0x3D
```

### Error Code Descriptions

| Code | Name | Description |
|------|------|-------------|
| 0x00 | ERROR_SUCCESS | Operation completed successfully |
| 0x01 | ERROR_INVALID_PACKET | Packet format is invalid or corrupted |
| 0x02 | ERROR_AUTHENTICATION_FAILED | HMAC verification failed |
| 0x03 | ERROR_TIMESTAMP_INVALID | Packet timestamp is outside acceptable window |
| 0x04 | ERROR_REPLAY_ATTACK | Packet appears to be a replay attack |
| 0x05 | ERROR_SESSION_NOT_FOUND | Referenced session does not exist |
| 0x06 | ERROR_STATE_INVALID | Operation not valid in current connection state |
| 0x07 | ERROR_WINDOW_OVERFLOW | Flow control window exceeded |
| 0x08 | ERROR_SEQUENCE_INVALID | Sequence number is invalid or out of range |
| 0x09 | ERROR_FRAGMENT_INVALID | Fragment packet is malformed or invalid |
| 0x0A | ERROR_SYNC_FAILED | Time or port synchronization failed |
| 0x0B | ERROR_RECOVERY_FAILED | Recovery procedure failed |
| 0x0C | ERROR_TIMEOUT | Operation timed out |
| 0x0D | ERROR_MEMORY_EXHAUSTED | Insufficient memory to complete operation |
| 0x0E | ERROR_INVALID_PARAMETER | Parameter value is invalid |
| 0x0F | ERROR_PORT_CALCULATION_FAILED | Port calculation algorithm failed |
| 0x10 | ERROR_FRAGMENT_REASSEMBLY_FAILED | Fragment reassembly failed |
| 0x11 | ERROR_CONGESTION_CONTROL_FAILED | Congestion control algorithm failed |
| 0x12 | ERROR_DISCOVERY_FAILED | Discovery process failed |
| 0x13 | ERROR_PSK_NOT_FOUND | Pre-shared key not found |
| 0x14 | ERROR_ECDH_KEY_EXCHANGE_FAILED | ECDH key exchange failed or invalid public key |
| 0x15 | ERROR_DISCOVERY_TIMEOUT | Discovery process timed out |
| 0x16 | ERROR_ECDH_VERIFICATION_FAILED | ECDH shared secret verification failed |
| 0x17 | ERROR_PSK_ENUMERATION_ATTEMPT | Detected PSK enumeration attack |

### Error Handling Guidelines

#### Critical Errors (Connection Termination)
- ERROR_AUTHENTICATION_FAILED
- ERROR_PSK_NOT_FOUND
- ERROR_PSK_ENUMERATION_ATTEMPT
- ERROR_ZERO_KNOWLEDGE_PROOF_FAILED
- ERROR_TAMPERING_DETECTED
- ERROR_INJECTION_ATTEMPT
- ERROR_CONNECTION_TERMINATE

#### Recoverable Errors (Retry/Recovery)
- ERROR_SYNC_FAILED
- ERROR_TIMEOUT
- ERROR_DISCOVERY_FAILED
- ERROR_FRAGMENT_REASSEMBLY_FAILED
- ERROR_TIME_SYNC_REQUEST_FAILED
- ERROR_TIME_SYNC_RESPONSE_FAILED
- ERROR_RECOVERY_REQUEST_FAILED
- ERROR_REKEY_REQUEST_FAILED
- ERROR_REKEY_RESPONSE_FAILED
- ERROR_REPAIR_REQUEST_FAILED
- ERROR_REPAIR_RESPONSE_FAILED
- ERROR_DISCOVERY_REQUEST_FAILED
- ERROR_DISCOVERY_RESPONSE_FAILED
- ERROR_DISCOVERY_CONFIRM_FAILED

#### Security-Related Errors
- ERROR_REPLAY_ATTACK
- ERROR_TIMESTAMP_INVALID
- ERROR_PSK_ENUMERATION_ATTEMPT
- ERROR_FRAGMENT_OVERLAP
- ERROR_FRAGMENT_BOMB
- ERROR_RATE_LIMITED
- ERROR_ENUMERATION_DETECTED
- ERROR_INJECTION_ATTEMPT
- ERROR_TAMPERING_DETECTED

