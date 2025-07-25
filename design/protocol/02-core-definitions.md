# Core Protocol Definitions

This document contains all fundamental definitions including constants, error codes, and naming conventions that are referenced throughout the protocol specification.

## Protocol Constants and Default Values

These constants establish the fundamental operational parameters that ensure consistent behavior across all protocol components.

### Core Protocol Constants

```pseudocode
// Protocol version and header constants
PROTOCOL_VERSION = 0x01                  // Current protocol version
PROTOCOL_MAX_VERSION = 0x01              // Maximum supported protocol version
BASE_HEADER_SIZE = 18                    // Minimum header size (version + type + sub-type + flags + seq + ack + payload_len)
FRAGMENT_HEADER_SIZE = 8                 // Fragment header size in bytes (when fragmentation used)

// Time-related constants  
HOP_INTERVAL_MS = 500                    // Port hop interval in milliseconds (500ms time windows - used in: 10-port-hopping.md, 09-time-synchronization.md)
TIME_SYNC_TOLERANCE_MS = 50              // Maximum allowed clock drift (used in: 09-time-synchronization.md)
HEARTBEAT_INTERVAL_MS = 30000            // Heartbeat interval (30 seconds - used in: 08-timeout-and-reliability.md)
HEARTBEAT_TIMEOUT_MS = 90000             // Heartbeat timeout (90 seconds - used in: 08-timeout-and-reliability.md)
MAX_PACKET_LIFETIME_MS = 60000           // Maximum packet age (60 seconds - used in: 08-timeout-and-reliability.md)
TIMESTAMP_WINDOW_MS = 30000              // Anti-replay timestamp window
HANDSHAKE_TIMESTAMP_WINDOW_MS = 10000    // Stricter window for handshake packets (10 seconds)
MONTH_TRANSITION_PREPARATION_MS = 3600000 // Start month transition prep 1 hour before
SAFETY_MARGIN_MS = 100                   // Safety margin for delay calculations
BASE_TRANSMISSION_DELAY_ALLOWANCE_MS = 1000 // Base allowance for network transmission delay
ADAPTIVE_DELAY_WINDOW_MIN = 1            // Minimum delay window size (time windows - used in: 11-adaptive-networking.md)
ADAPTIVE_DELAY_WINDOW_MAX = 16           // Maximum delay window size (time windows = 8 seconds - used in: 11-adaptive-networking.md)
DELAY_MEASUREMENT_SAMPLES = 10           // Number of samples for delay measurement (used in: 11-adaptive-networking.md)
DELAY_NEGOTIATION_INTERVAL_MS = 60000    // Delay parameters negotiation interval (1 minute - used in: 11-adaptive-networking.md)
DELAY_PERCENTILE_TARGET = 95             // Target percentile for delay allowance (95th percentile - used in: 11-adaptive-networking.md)
BASE_HEARTBEAT_PAYLOAD_SIZE = 8          // Size of base heartbeat payload (bytes)
MILLISECONDS_PER_DAY = 86400000          // Milliseconds in a day (for timestamp calculation)

// Sequence and window constants
ECDH_KEY_EXCHANGE_TIMEOUT_MS = 10000     // ECDH connection establishment timeout (used in: 04-ecdh-cryptography.md)
SESSION_KEY_MATERIAL_SIZE = 128          // Size of master key material from PBKDF2 (1024 bits)
CHUNK_SIZE = 2                           // Size of each 16-bit chunk in bytes
MAX_CHUNKS_PER_DERIVATION = 64           // Maximum number of 16-bit chunks from key material
MAX_SEQUENCE_NUMBER = 0xFFFFFFFF         // Maximum sequence number (used in: 05-psk-discovery.md)
SEQUENCE_WRAP_THRESHOLD = 0x80000000     // Threshold for sequence wraparound (used in: 14-replay-protection.md)
SEQUENCE_WINDOW_SIZE = 1000              // Sequence number acceptance window (used in: 14-replay-protection.md)
INITIAL_CONGESTION_WINDOW = 1460         // Initial congestion window (bytes - used in: 07-data-transmission.md)
MIN_CONGESTION_WINDOW = 292              // Minimum congestion window (bytes - used in: 07-data-transmission.md)
MAX_CONGESTION_WINDOW = 65535            // Maximum congestion window (bytes - used in: 07-data-transmission.md)
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
BLOCK_DURATION_MS = 300000              // Block duration for enumeration attempts (5 minutes)
REPLAY_THRESHOLD = 5                    // Threshold for replay attack detection

// Anti-replay protection constants
MAX_OUT_OF_ORDER_RATE = 10              // Maximum out-of-order packets per minute
SYN_FLOOD_THRESHOLD = 100               // Maximum SYN attempts per source per minute
HANDSHAKE_CACHE_SIZE = 50000            // Server-side handshake cache entries
REORDER_TIMEOUT_MS = 5000               // Timeout for reorder buffer entries
SYN_CLEANUP_INTERVAL = 30000            // SYN cache cleanup interval (30 seconds)

// Recovery timeout constants
RECOVERY_TIMEOUT_MS = 15000             // Recovery process timeout (15 seconds)
RECOVERY_RETRY_INTERVAL_MS = 2000       // Interval between recovery attempts
RECOVERY_MAX_ATTEMPTS = 3               // Maximum recovery attempts before failure
TIME_RESYNC_TIMEOUT_MS = 5000           // Time resynchronization timeout
SEQUENCE_REPAIR_TIMEOUT_MS = 8000       // Sequence repair timeout
REKEY_TIMEOUT_MS = 10000                // Session rekey timeout

// Fragmentation constants
MAX_FRAGMENT_SIZE = 1400                // Maximum fragment payload size (bytes)
MAX_FRAGMENTS_PER_PACKET = 16           // Maximum fragments per reassembled packet (security limit)
MIN_FRAGMENT_SIZE = 64                  // Minimum fragment payload size (prevents tiny fragment attacks)
FRAGMENT_REASSEMBLY_BUFFER_SIZE = 64    // Maximum fragments in reassembly buffer
FRAGMENT_ID_SPACE = 0xFFFF              // Fragment ID space (16-bit)
FRAGMENT_DUPLICATE_WINDOW = 100         // Window for detecting duplicate fragments
FRAGMENT_TIMEOUT_MS = 5000              // Fragment reassembly timeout (5 seconds - security hardened)
MAX_REASSEMBLY_MEMORY_PER_SESSION = 1048576  // Maximum memory for reassembly per session (1MB)
MAX_CONCURRENT_REASSEMBLIES_GLOBAL = 1000    // Maximum concurrent reassemblies system-wide
MAX_CONCURRENT_REASSEMBLIES_PER_SESSION = 10 // Maximum concurrent reassemblies per session
FRAGMENT_ARRIVAL_RATE_LIMIT = 20        // Maximum fragments per second per source
MAX_TOTAL_REASSEMBLED_SIZE = 65536      // Maximum size of reassembled packet (64KB)

// Session ID configuration
SESSION_ID_16BIT = 0                    // 16-bit session ID (2 bytes, 65K sessions)
SESSION_ID_32BIT = 1                    // 32-bit session ID (4 bytes, 4B sessions)  
SESSION_ID_64BIT = 2                    // 64-bit session ID (8 bytes, unlimited)
SESSION_ID_REUSE_QUEUE_SIZE = 1000      // Maximum IDs in reuse queue for 16-bit
SESSION_ID_COLLISION_THRESHOLD = 100    // Alert threshold for collisions

// Timestamp configuration  
TIMESTAMP_16BIT = 0                     // 16-bit timestamp (2 bytes, 1.09 minutes)
TIMESTAMP_24BIT = 1                     // 24-bit timestamp (3 bytes, 4.66 hours)
TIMESTAMP_32BIT = 2                     // 32-bit timestamp (4 bytes, full month)

// HMAC Policy Configuration
// Three distinct HMAC policies for different security/performance requirements
HMAC_LIGHT = 1                         // 64-bit HMAC-SHA256, 128-bit key, minimal authentication (8 bytes output)
HMAC_MEDIUM = 2                        // 128-bit HMAC-SHA256, 256-bit key, standard authentication (16 bytes output)  
HMAC_STRONG = 3                        // 256-bit HMAC-SHA256, 256-bit key, maximum authentication (32 bytes output)

// HMAC Policy Output Lengths
HMAC_LIGHT_OUTPUT_SIZE = 8             // 64 bits (8 bytes)
HMAC_MEDIUM_OUTPUT_SIZE = 16           // 128 bits (16 bytes)
HMAC_STRONG_OUTPUT_SIZE = 32           // 256 bits (32 bytes)

// HMAC Policy Key Lengths
HMAC_LIGHT_KEY_SIZE = 16               // 128 bits (16 bytes)
HMAC_MEDIUM_KEY_SIZE = 32              // 256 bits (32 bytes)
HMAC_STRONG_KEY_SIZE = 32              // 256 bits (32 bytes) - consistent with SHA256

// HMAC Policy Algorithm Specifications:
// HMAC_LIGHT: HMAC-SHA256 truncated to 64 bits with 128-bit key
// HMAC_MEDIUM: HMAC-SHA256 truncated to 128 bits with 256-bit key
// HMAC_STRONG: HMAC-SHA256 truncated to 256 bits with 256-bit key

// Connection Context Hash Size (used in HMAC_STRONG)
CONNECTION_CONTEXT_HASH_SIZE = 32      // 256 bits (32 bytes)

// Security Mode Configuration
SECURITY_MODE_PERFORMANCE = 1          // Prefer HMAC_LIGHT for performance
SECURITY_MODE_BALANCED = 2             // Use standard policy guidelines
SECURITY_MODE_HIGH_SECURITY = 3        // Prefer HMAC_STRONG for security

// Flow control constants
INITIAL_SEND_WINDOW = 8192              // Initial send window size (bytes)
INITIAL_RECEIVE_WINDOW = 16384          // Initial receive window size (bytes)
WINDOW_SCALE_FACTOR = 1                 // Window scaling factor
WINDOW_UPDATE_THRESHOLD = 0.5           // Threshold for sending window updates (fraction)
ZERO_WINDOW_PROBE_INTERVAL_MS = 5000    // Zero window probe interval
WINDOW_UPDATE_TIMEOUT_MS = 60000        // Window update detection timeout (consolidated from WINDOW_TIMEOUT_MS)

// Recovery mechanism constants
MAX_REPAIR_WINDOW_SIZE = 1000           // Maximum repair window size (packets)
MAX_WINDOW_SIZE = 65535                 // Maximum flow control window size

// Additional timeout constants (previously referenced but not defined)
SESSION_IDLE_TIMEOUT_MS = 900000        // Session idle timeout (15 minutes)
MAX_HEARTBEAT_FAILURES = 3              // Maximum consecutive heartbeat failures
EMERGENCY_RECOVERY_TIMEOUT_MS = 5000    // Emergency recovery timeout (5 seconds)
HOP_INTERVAL_SAFETY_MARGIN_MS = 50      // Safety margin for time window boundaries (50ms)
AUTH_TIMEOUT_EXTENSION_MS = 3000        // Authentication timeout extension (3 seconds)
RECOVERY_TIMEOUT_EXTENSION_MS = 5000    // Recovery timeout extension (5 seconds)

// Consolidated timeout constants (removing duplicates)
// KEY_EXCHANGE_TIMEOUT_MS covers all ECDH operations including connection establishment

// Discovery states (aligned with connection lifecycle sub-states)
DISCOVERY_SUB_STATE_IDLE = 0            // No discovery in progress
DISCOVERY_SUB_STATE_REQUEST = 1         // Discovery initiated, waiting for response
DISCOVERY_SUB_STATE_RESPONSE = 2        // Discovery response received, processing
DISCOVERY_SUB_STATE_CONFIRM = 3         // Discovery confirmation sent/received
DISCOVERY_SUB_STATE_COMPLETED = 4       // Discovery completed, PSK selected
DISCOVERY_SUB_STATE_FAILED = 5          // Discovery failed, no common PSK found

// Packet type definitions (as defined in 03-packet-architecture.md)
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

// Packet sub-type definitions (as defined in 03-packet-architecture.md)
// CONTROL packet sub-types
CONTROL_SUB_TIME_SYNC_REQUEST = 0x01    // Time synchronization request
CONTROL_SUB_TIME_SYNC_RESPONSE = 0x02   // Time synchronization response
CONTROL_SUB_RECOVERY = 0x03             // Session recovery
CONTROL_SUB_SEQUENCE_NEG = 0x04         // Sequence number negotiation

// Reserved CONTROL sub-types (for future use)
CONTROL_SUB_HMAC_POLICY_REQUEST = 0x05  // HMAC policy change request
CONTROL_SUB_HMAC_POLICY_RESPONSE = 0x06 // HMAC policy change acknowledgment

// MANAGEMENT packet sub-types
MANAGEMENT_SUB_REKEY_REQUEST = 0x01     // Session key rotation request
MANAGEMENT_SUB_REKEY_RESPONSE = 0x02    // Session key rotation response
MANAGEMENT_SUB_REPAIR_REQUEST = 0x03    // Sequence repair request
MANAGEMENT_SUB_REPAIR_RESPONSE = 0x04   // Sequence repair response

// DISCOVERY packet sub-types
DISCOVERY_SUB_REQUEST = 0x01            // PSK discovery request
DISCOVERY_SUB_RESPONSE = 0x02           // PSK discovery response
DISCOVERY_SUB_CONFIRM = 0x03            // PSK discovery confirmation

// Protocol validation constants
PACKET_TYPE_MAX = 0x0E                  // Maximum valid packet type value (DISCOVERY = 0x0E)
MAX_SESSION_ID_GENERATION_ATTEMPTS = 100 // Max attempts to generate unique ID
SESSION_ID_CLEANUP_INTERVAL_MS = 3600000 // ID cleanup interval (1 hour)
```

## Utility Functions

These utility functions are referenced throughout the protocol specification and must be implemented:

```pseudocode
// Time utility functions
function get_current_utc_time_ms():
    # Get current UTC time in milliseconds since Unix epoch
    return current_utc_milliseconds

function get_current_day_start_utc():
    # Get UTC timestamp of start of current day (00:00:00.000 UTC)
    current_time = get_current_utc_time_ms()
    ms_per_day = 86400000  # 24 * 60 * 60 * 1000
    return (current_time // ms_per_day) * ms_per_day

function get_current_month_start_utc():
    # Get UTC timestamp of start of current month (1st day, 00:00:00.000 UTC)
    # Implementation must handle month/year boundaries correctly
    current_time = get_current_utc_time_ms()
    # Convert to date, set to 1st day of month, convert back
    # This is implementation-specific but must return correct month boundary
    return month_start_timestamp_utc

// Byte conversion utility functions
function bytes_to_uint16(bytes):
    # Convert 2 bytes to 16-bit unsigned integer (big-endian)
    if len(bytes) < 2:
        return 0
    return (bytes[0] << 8) | bytes[1]

function bytes_to_uint32(bytes):
    # Convert 4 bytes to 32-bit unsigned integer (big-endian)
    if len(bytes) < 4:
        return 0
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]

function bytes_to_uint64(bytes):
    # Convert 8 bytes to 64-bit unsigned integer (big-endian)
    if len(bytes) < 8:
        return 0
    return ((bytes[0] << 56) | (bytes[1] << 48) | (bytes[2] << 40) | (bytes[3] << 32) |
            (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7])

function uint16_to_bytes(value):
    # Convert 16-bit unsigned integer to 2 bytes (big-endian)
    return [(value >> 8) & 0xFF, value & 0xFF]

function uint32_to_bytes(value):
    # Convert 32-bit unsigned integer to 4 bytes (big-endian)
    return [(value >> 24) & 0xFF, (value >> 16) & 0xFF, 
            (value >> 8) & 0xFF, value & 0xFF]

function uint64_to_bytes(value):
    # Convert 64-bit unsigned integer to 8 bytes (big-endian)
    return [(value >> 56) & 0xFF, (value >> 48) & 0xFF, (value >> 40) & 0xFF, (value >> 32) & 0xFF,
            (value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF]

// Memory security functions
function secure_zero_memory(data):
    # Securely zero memory to prevent data leakage
    # Implementation must ensure compiler doesn't optimize away
    # Use platform-specific secure memory zeroing (e.g., SecureZeroMemory, explicit_bzero)
    secure_memory_zero(data, len(data))

// Random number generation
function get_secure_random_bytes(length):
    # Generate cryptographically secure random bytes
    # Must use platform cryptographic RNG (e.g., /dev/urandom, CryptGenRandom, etc.)
    return cryptographic_random_bytes(length)

// Hash utility function
function hash_64bit(data):
    # Generate 64-bit hash from arbitrary data
    full_hash = SHA256(data)
    return bytes_to_uint64(full_hash[0:8])
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
ERROR_TIME_SYNC_REQUEST_FAILED = 0x19
ERROR_TIME_SYNC_RESPONSE_FAILED = 0x1A
ERROR_RECOVERY_REQUEST_FAILED = 0x1B
ERROR_SEQUENCE_NEGOTIATION_FAILED = 0x1C

// MANAGEMENT packet sub-type errors
ERROR_REKEY_REQUEST_FAILED = 0x1D
ERROR_REKEY_RESPONSE_FAILED = 0x1E
ERROR_REPAIR_REQUEST_FAILED = 0x1F
ERROR_REPAIR_RESPONSE_FAILED = 0x20

// DISCOVERY packet sub-type errors
ERROR_DISCOVERY_REQUEST_FAILED = 0x21
ERROR_DISCOVERY_RESPONSE_FAILED = 0x22
ERROR_DISCOVERY_CONFIRM_FAILED = 0x23

// Fragmentation and flow control errors
ERROR_FRAGMENT_TIMEOUT = 0x24
ERROR_FRAGMENT_OVERLAP = 0x25
ERROR_FRAGMENT_BOMB = 0x26
ERROR_ZERO_WINDOW_DEADLOCK = 0x27
ERROR_WINDOW_UPDATE_FAILED = 0x28

// Multi-connection errors
ERROR_PORT_COLLISION = 0x29
ERROR_SESSION_ID_COLLISION = 0x2A
ERROR_CONNECTION_LIMIT_EXCEEDED = 0x2B

// Security attack detection errors
ERROR_RATE_LIMITED = 0x2C
ERROR_ENUMERATION_DETECTED = 0x2D
ERROR_INJECTION_ATTEMPT = 0x2E
ERROR_TAMPERING_DETECTED = 0x2F

// Privacy-preserving set intersection errors
ERROR_PSI_BLOOM_FILTER_INVALID = 0x30
ERROR_PSI_NO_INTERSECTION = 0x31
ERROR_PSI_CANDIDATE_VERIFICATION_FAILED = 0x32
ERROR_PSK_CONFIRMATION_INVALID = 0x33
ERROR_PSI_BLINDED_FINGERPRINT_FAILED = 0x34
ERROR_BLOOM_FILTER_SIZE_INVALID = 0x35

// Additional error codes for edge case handling
ERROR_ZERO_KNOWLEDGE_PROOF_FAILED = 0x36
ERROR_UNSUPPORTED_VERSION = 0x37
ERROR_INVALID_PACKET_TYPE = 0x38
ERROR_UNKNOWN_PACKET_TYPE = 0x39
ERROR_INVALID_SUB_TYPE = 0x3A
ERROR_PAYLOAD_TOO_LARGE = 0x3B
ERROR_EMPTY_DATA_PACKET = 0x3C
ERROR_INVALID_SESSION_ID = 0x3D
ERROR_PACKET_TOO_LARGE = 0x3E

// Additional error codes for edge case handling and recovery
ERROR_TIME_RESYNC_TIMEOUT = 0x3F
ERROR_TIME_RESYNC_INVALID_CHALLENGE = 0x40
ERROR_TIME_RESYNC_OFFSET_TOO_LARGE = 0x41
ERROR_TIME_RESYNC_VERIFICATION_FAILED = 0x42
ERROR_SEQUENCE_REPAIR_TIMEOUT = 0x43
ERROR_SEQUENCE_REPAIR_INVALID_NONCE = 0x44
ERROR_SEQUENCE_REPAIR_INVALID_CONFIRMATION = 0x45
ERROR_REKEY_TIMEOUT = 0x46
ERROR_REKEY_INVALID_NONCE = 0x47
ERROR_REKEY_INVALID_KEY = 0x48
ERROR_REKEY_SHARED_SECRET_MISMATCH = 0x49
ERROR_RECOVERY_ALREADY_IN_PROGRESS = 0x4A
ERROR_RECOVERY_RETRY_SCHEDULED = 0x4B
ERROR_SESSION_UNRECOVERABLE = 0x4C
ERROR_INVALID_RECOVERY_LEVEL = 0x4D
ERROR_REPLAY_ATTACK_DETECTED = 0x4E
ERROR_SOURCE_BLOCKED = 0x4F
ERROR_INVALID_CONFIGURATION = 0x50
ERROR_TIMESTAMP_OUT_OF_RANGE = 0x51
ERROR_SEQUENCE_WRAPAROUND_NOT_READY = 0x52
ERROR_PACKET_TOO_SHORT = 0x53
ERROR_PAYLOAD_LENGTH_MISMATCH = 0x54
ERROR_RESERVED_FIELDS_NOT_ZERO = 0x55
ERROR_INVALID_FLAG_COMBINATION = 0x56
ERROR_FRAGMENT_INDEX_OUT_OF_BOUNDS = 0x57
ERROR_TOO_MANY_FRAGMENTS = 0x58
ERROR_FRAGMENT_ID_COLLISION = 0x59
ERROR_FRAGMENT_DATA_MISMATCH = 0x5A
ERROR_EMPTY_FINAL_FRAGMENT = 0x5B
ERROR_CLOCK_REGRESSION_DETECTED = 0x5C
ERROR_RECOVERY_DURING_TERMINATION = 0x5D
ERROR_RECOVERY_ATTEMPTS_EXHAUSTED = 0x5E
ERROR_CRITICAL_OPERATION_INTERRUPTED = 0x5F
ERROR_PORT_RANGE_EXHAUSTED = 0x60
ERROR_PERMISSION_DENIED = 0x61
ERROR_NO_AVAILABLE_PORTS = 0x62
ERROR_ADDRESS_IN_USE = 0x63
ERROR_SYSTEM_SHUTTING_DOWN = 0x64
ERROR_VERSION_TOO_OLD = 0x65
ERROR_VERSION_TOO_NEW = 0x66
ERROR_SEND_BUFFER_OVERFLOW = 0x67
ERROR_RESOURCE_EXHAUSTED = 0x68
ERROR_BUFFER_FULL = 0x69
ERROR_BUFFER_EMPTY = 0x6A
ERROR_TIMESTAMP_ATTACK_DETECTED = 0x6B
ERROR_INVALID_CRYPTO_PARAMETERS = 0x6C
ERROR_AUTH_LOCKOUT = 0x6D
ERROR_INVALID_PUBLIC_KEY = 0x6E

// Connection termination error
ERROR_CONNECTION_TERMINATE = 0x6F

// Additional constants for edge case handling
MAX_ERROR_RESPONSES = 3                      // Maximum error responses to prevent loops
MAX_RECOVERY_HMAC_FAILURES = 3               // Maximum HMAC failures during recovery
MAX_LEGITIMATE_CLOCK_SKEW = 10000            // Maximum legitimate clock skew (10 seconds)
MAX_DISCOVERY_RATE = 10                      // Maximum discovery attempts per minute
MIN_REQUIRED_MEMORY = 1048576                // Minimum required memory (1 MB)
CRITICAL_SEND_BUFFER_SIZE = 16777216         // Critical send buffer size (16 MB)
CRITICAL_RECEIVE_BUFFER_SIZE = 16777216      // Critical receive buffer size (16 MB)
MAX_CONCURRENT_REASSEMBLIES = 1000           // Maximum concurrent fragment reassemblies
MAX_TOTAL_RECOVERY_ATTEMPTS = 10             // Maximum total recovery attempts per session
HOP_INTERVAL_SAFETY_MARGIN = 50              // Safety margin for time window boundaries (50ms)
MIN_DEADLOCK_WINDOW_SIZE = 1024              // Minimum window size for deadlock resolution
MAX_AUTH_ATTEMPTS = 5                        // Maximum authentication attempts
HIGH_JITTER_THRESHOLD = 500                  // High jitter threshold (500ms)
MAX_TIMESTAMP_DRIFT = 30000                  // Maximum acceptable timestamp drift (30 seconds)
MAX_EXTREME_TIME_DRIFT = 3600000             // Maximum extreme time drift (1 hour)
MAX_ACCEPTABLE_TIME_REGRESSION = 5000        // Maximum acceptable time regression (5 seconds)
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

