/**
 * @file protocol.h
 * @brief SINGLE SOURCE OF TRUTH for all Buckwild protocol constants
 *
 * ============================================================================
 * IMPORTANT: This is the ONLY file that should define protocol constants.
 * ============================================================================
 *
 * All C code (eBPF and userspace) must include THIS file for protocol constants.
 * DO NOT create duplicate constant definitions in other files.
 *
 * Aligned with:
 * - Rust implementation: src/common/rust/src/protocol/types.rs
 * - Protocol specification: design/protocol/
 *
 * If you need to add/modify protocol constants:
 * 1. Update this file ONLY
 * 2. Verify alignment with Rust types.rs
 * 3. Verify alignment with protocol specs
 * 4. Update tests to match
 *
 * Session ID sizes:
 * - Variable length: 16-bit (2 bytes), 32-bit (4 bytes), or 64-bit (8 bytes)
 * - Maximum size: u64 (8 bytes)
 * - Map keys use __u64 to support maximum session ID size
 */

#ifndef BUCKWILD_EBPF_PROTOCOL_H
#define BUCKWILD_EBPF_PROTOCOL_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// BPF-specific includes only when compiling for eBPF target
#ifdef __BPF__
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#else
// Userspace alternatives for BPF helper functions
#include <arpa/inet.h>
#include <time.h>
#define bpf_ntohs(x) ntohs(x)
#define bpf_ntohl(x) ntohl(x)
#define bpf_htons(x) htons(x)
#define bpf_htonl(x) htonl(x)
// Convert big-endian 64-bit to host byte order
static __always_inline __u64 bpf_be64_to_cpu(__u64 x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(x);
#else
    return x;
#endif
}
// Userspace time - returns nanoseconds (mock for testing)
static __always_inline __u64 bpf_ktime_get_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif // __BPF__

// Protocol version
#define BUCKWILD_VERSION 0x01

// Minimum and maximum header sizes
#define MIN_HEADER_SIZE 26
#define MAX_HEADER_SIZE 57

// Packet types (aligned with protocol specification)
#define PKT_TYPE_SYN            0x01
#define PKT_TYPE_SYN_ACK        0x02
#define PKT_TYPE_ACK            0x03
#define PKT_TYPE_DATA           0x04
#define PKT_TYPE_FIN            0x05
#define PKT_TYPE_HEARTBEAT      0x06
#define PKT_TYPE_ERROR          0x09
#define PKT_TYPE_RST            0x0B
#define PKT_TYPE_CONTROL        0x0C
#define PKT_TYPE_MANAGEMENT     0x0D
#define PKT_TYPE_DISCOVERY      0x0E

// CONTROL packet sub-types (aligned with protocol specification)
#define CONTROL_SUB_TIME_SYNC_REQUEST    0x01
#define CONTROL_SUB_TIME_SYNC_RESPONSE   0x02
#define CONTROL_SUB_RECOVERY             0x03
#define CONTROL_SUB_SEQUENCE_NEG         0x04
#define CONTROL_SUB_HMAC_POLICY_REQUEST  0x05
#define CONTROL_SUB_HMAC_POLICY_RESPONSE 0x06

// MANAGEMENT packet sub-types (aligned with protocol specification)
#define MANAGEMENT_SUB_REKEY_REQUEST     0x01
#define MANAGEMENT_SUB_REKEY_RESPONSE    0x02
#define MANAGEMENT_SUB_REPAIR_REQUEST    0x03
#define MANAGEMENT_SUB_REPAIR_RESPONSE   0x04

// DISCOVERY packet sub-types (aligned with protocol specification)
#define DISCOVERY_SUB_REQUEST            0x01
#define DISCOVERY_SUB_RESPONSE           0x02
#define DISCOVERY_SUB_CONFIRM            0x03

// Packet flags
#define PKT_FLAG_ENCRYPTED      0x01
#define PKT_FLAG_COMPRESSED     0x02
#define PKT_FLAG_FRAGMENTED     0x04
#define PKT_FLAG_URGENT         0x08
#define PKT_FLAG_RECOVERY       0x10
#define PKT_FLAG_REKEYING       0x20

// Session ID configuration (aligned with protocol specification)
#define SESSION_ID_16BIT        0
#define SESSION_ID_32BIT        1
#define SESSION_ID_64BIT        2

// Timestamp configuration (aligned with protocol specification)
#define TIMESTAMP_16BIT         0
#define TIMESTAMP_24BIT         1
#define TIMESTAMP_24BIT_HIGH    2
#define TIMESTAMP_32BIT         3

// HMAC Policy configuration (aligned with protocol specification)
#define HMAC_POLICY_LIGHT       1
#define HMAC_POLICY_MEDIUM      2
#define HMAC_POLICY_STRONG      3

// Time epochs
#define EPOCH_DAILY             0
#define EPOCH_MONTHLY           1

// Protocol error codes (aligned with protocol specification 0x00-0x6F)
#define ERROR_SUCCESS                           0x00
#define ERROR_INVALID_PACKET                    0x01
#define ERROR_AUTHENTICATION_FAILED             0x02
#define ERROR_TIMESTAMP_INVALID                 0x03
#define ERROR_REPLAY_ATTACK                     0x04
#define ERROR_SESSION_NOT_FOUND                 0x05
#define ERROR_STATE_INVALID                     0x06
#define ERROR_WINDOW_OVERFLOW                   0x07
#define ERROR_SEQUENCE_INVALID                  0x08
#define ERROR_FRAGMENT_INVALID                  0x09
#define ERROR_SYNC_FAILED                       0x0A
#define ERROR_RECOVERY_FAILED                   0x0B
#define ERROR_TIMEOUT                           0x0C
#define ERROR_MEMORY_EXHAUSTED                  0x0D
#define ERROR_INVALID_PARAMETER                 0x0E
#define ERROR_PORT_CALCULATION_FAILED           0x0F
#define ERROR_FRAGMENT_REASSEMBLY_FAILED        0x10
#define ERROR_CONGESTION_CONTROL_FAILED         0x11
#define ERROR_DISCOVERY_FAILED                  0x12
#define ERROR_PSK_NOT_FOUND                     0x13
#define ERROR_ECDH_KEY_EXCHANGE_FAILED          0x14
#define ERROR_DISCOVERY_TIMEOUT                 0x15
#define ERROR_ECDH_VERIFICATION_FAILED          0x16
#define ERROR_PSK_ENUMERATION_ATTEMPT           0x17
#define ERROR_TIME_SYNC_REQUEST_FAILED          0x19
#define ERROR_TIME_SYNC_RESPONSE_FAILED         0x1A
#define ERROR_RECOVERY_REQUEST_FAILED           0x1B
#define ERROR_SEQUENCE_NEGOTIATION_FAILED       0x1C
#define ERROR_REKEY_REQUEST_FAILED              0x1D
#define ERROR_REKEY_RESPONSE_FAILED             0x1E
#define ERROR_REPAIR_REQUEST_FAILED             0x1F
#define ERROR_REPAIR_RESPONSE_FAILED            0x20
#define ERROR_DISCOVERY_REQUEST_FAILED          0x21
#define ERROR_DISCOVERY_RESPONSE_FAILED         0x22
#define ERROR_DISCOVERY_CONFIRM_FAILED          0x23
#define ERROR_FRAGMENT_TIMEOUT                  0x24
#define ERROR_FRAGMENT_OVERLAP                  0x25
#define ERROR_FRAGMENT_BOMB                     0x26
#define ERROR_ZERO_WINDOW_DEADLOCK              0x27
#define ERROR_WINDOW_UPDATE_FAILED              0x28
#define ERROR_PORT_COLLISION                    0x29
#define ERROR_SESSION_ID_COLLISION              0x2A
#define ERROR_CONNECTION_LIMIT_EXCEEDED         0x2B
#define ERROR_RATE_LIMITED                      0x2C
#define ERROR_ENUMERATION_DETECTED              0x2D
#define ERROR_INJECTION_ATTEMPT                 0x2E
#define ERROR_TAMPERING_DETECTED                0x2F
#define ERROR_PSI_BLOOM_FILTER_INVALID          0x30
#define ERROR_PSI_NO_INTERSECTION               0x31
#define ERROR_PSI_CANDIDATE_VERIFICATION_FAILED 0x32
#define ERROR_PSK_CONFIRMATION_INVALID          0x33
#define ERROR_PSI_BLINDED_FINGERPRINT_FAILED    0x34
#define ERROR_BLOOM_FILTER_SIZE_INVALID         0x35
#define ERROR_ZERO_KNOWLEDGE_PROOF_FAILED       0x36
#define ERROR_UNSUPPORTED_VERSION               0x37
#define ERROR_INVALID_PACKET_TYPE               0x38
#define ERROR_UNKNOWN_PACKET_TYPE               0x39
#define ERROR_INVALID_SUB_TYPE                  0x3A
#define ERROR_PAYLOAD_TOO_LARGE                 0x3B
#define ERROR_EMPTY_DATA_PACKET                 0x3C
#define ERROR_INVALID_SESSION_ID                0x3D
#define ERROR_PACKET_TOO_LARGE                  0x3E
#define ERROR_TIME_RESYNC_TIMEOUT               0x3F
#define ERROR_TIME_RESYNC_INVALID_CHALLENGE     0x40
#define ERROR_TIME_RESYNC_OFFSET_TOO_LARGE      0x41
#define ERROR_TIME_RESYNC_VERIFICATION_FAILED   0x42
#define ERROR_SEQUENCE_REPAIR_TIMEOUT           0x43
#define ERROR_SEQUENCE_REPAIR_INVALID_NONCE     0x44
#define ERROR_SEQUENCE_REPAIR_INVALID_CONFIRMATION 0x45
#define ERROR_REKEY_TIMEOUT                     0x46
#define ERROR_REKEY_INVALID_NONCE               0x47
#define ERROR_REKEY_INVALID_KEY                 0x48
#define ERROR_REKEY_SHARED_SECRET_MISMATCH      0x49
#define ERROR_RECOVERY_ALREADY_IN_PROGRESS      0x4A
#define ERROR_RECOVERY_RETRY_SCHEDULED          0x4B
#define ERROR_SESSION_UNRECOVERABLE             0x4C
#define ERROR_INVALID_RECOVERY_LEVEL            0x4D
#define ERROR_REPLAY_ATTACK_DETECTED            0x4E
#define ERROR_SOURCE_BLOCKED                    0x4F
#define ERROR_INVALID_CONFIGURATION             0x50
#define ERROR_TIMESTAMP_OUT_OF_RANGE            0x51
#define ERROR_SEQUENCE_WRAPAROUND_NOT_READY     0x52
#define ERROR_PACKET_TOO_SHORT                  0x53
#define ERROR_PAYLOAD_LENGTH_MISMATCH           0x54
#define ERROR_RESERVED_FIELDS_NOT_ZERO          0x55
#define ERROR_INVALID_FLAG_COMBINATION          0x56
#define ERROR_FRAGMENT_INDEX_OUT_OF_BOUNDS      0x57
#define ERROR_TOO_MANY_FRAGMENTS                0x58
#define ERROR_FRAGMENT_ID_COLLISION             0x59
#define ERROR_FRAGMENT_DATA_MISMATCH            0x5A
#define ERROR_EMPTY_FINAL_FRAGMENT              0x5B
#define ERROR_CLOCK_REGRESSION_DETECTED         0x5C
#define ERROR_RECOVERY_DURING_TERMINATION       0x5D
#define ERROR_RECOVERY_ATTEMPTS_EXHAUSTED       0x5E
#define ERROR_CRITICAL_OPERATION_INTERRUPTED    0x5F
#define ERROR_PORT_RANGE_EXHAUSTED              0x60
#define ERROR_PERMISSION_DENIED                 0x61
#define ERROR_NO_AVAILABLE_PORTS                0x62
#define ERROR_ADDRESS_IN_USE                    0x63
#define ERROR_SYSTEM_SHUTTING_DOWN              0x64
#define ERROR_VERSION_TOO_OLD                   0x65
#define ERROR_VERSION_TOO_NEW                   0x66
#define ERROR_SEND_BUFFER_OVERFLOW              0x67
#define ERROR_RESOURCE_EXHAUSTED                0x68
#define ERROR_BUFFER_FULL                       0x69
#define ERROR_BUFFER_EMPTY                      0x6A
#define ERROR_TIMESTAMP_ATTACK_DETECTED         0x6B
#define ERROR_INVALID_CRYPTO_PARAMETERS         0x6C
#define ERROR_AUTH_LOCKOUT                      0x6D
#define ERROR_INVALID_PUBLIC_KEY                0x6E
#define ERROR_CONNECTION_TERMINATE              0x6F

// Security validation flags
#define VALIDATION_OK           0x00
#define VALIDATION_INVALID_SIZE 0x01
#define VALIDATION_INVALID_VERSION 0x02
#define VALIDATION_INVALID_SESSION 0x04
#define VALIDATION_INVALID_TIMESTAMP 0x08
#define VALIDATION_INVALID_HMAC 0x10
#define VALIDATION_RATE_LIMITED 0x20
#define VALIDATION_FRAGMENT_ATTACK 0x40
#define VALIDATION_REPLAY_ATTACK 0x80

// Security event types (used by security validation pipeline)
#define SEC_EVENT_UNKNOWN_SESSION       0x01
#define SEC_EVENT_RATE_LIMIT_VIOLATION  0x02
#define SEC_EVENT_ENUMERATION_ATTACK    0x03
#define SEC_EVENT_REPLAY_ATTACK         0x04
#define SEC_EVENT_TIMING_ATTACK         0x05
#define SEC_EVENT_FRAGMENT_BOMB         0x06
#define SEC_EVENT_FRAGMENT_OVERLAP      0x07
#define SEC_EVENT_SESSION_HIJACK        0x08
#define SEC_EVENT_PORT_SCAN             0x09

// Security severity levels (used for event prioritization)
// Maximum sessions for eBPF maps
#define MAX_SESSIONS 10000

// Data packet sub-types (for PKT_TYPE_DATA)
#define DATA_SUBTYPE_NORMAL             0x00
#define DATA_SUBTYPE_URGENT             0x01
#define DATA_SUBTYPE_KEEPALIVE          0x02
#define DATA_SUBTYPE_BULK               0x03

// Fragment packet type (for fragmented data)
#define PKT_TYPE_FRAGMENT               0x0F
#define SEC_SEVERITY_LOW                0x01
#define SEC_SEVERITY_MEDIUM             0x02
#define SEC_SEVERITY_HIGH               0x03
#define SEC_SEVERITY_CRITICAL           0x04

// Adaptive header structure (variable length)
struct buckwild_header {
    __u8 version_info;      // bits 0-3: version, 4-5: session_id_len, 6-7: timestamp_len
    __u8 packet_type;       // Packet type
    __u8 packet_subtype;    // Packet sub-type
    __u8 flags;             // Packet flags
    // Variable length fields follow:
    // - session_id (2, 4, or 8 bytes)
    // - timestamp (2, 3, or 4 bytes)
    // - sequence_number (4 bytes)
    // - acknowledgment (4 bytes, optional)
    // - window_size (2 bytes, optional)
    // - hmac (8, 16, or 32 bytes based on policy)
} __attribute__((packed));

// Fragment header (follows main header for fragmented packets)
struct fragment_header {
    __u16 fragment_id;      // Fragment identifier
    __u16 fragment_index;   // Fragment index (0-based)
    __u16 total_fragments;  // Total number of fragments
    __u16 fragment_size;    // Size of this fragment
} __attribute__((packed));

// Parsed header information
struct parsed_header {
    __u8 version;
    __u8 session_id_length;
    __u8 timestamp_length;
    __u8 hmac_policy;
    __u8 packet_type;
    __u8 packet_subtype;
    __u8 flags;
    __u64 session_id;
    __u32 timestamp;
    __u32 sequence_number;
    __u32 acknowledgment;
    __u16 window_size;
    __u16 header_length;
    __u8 validation_status;
    __u8 security_flags;
    struct fragment_header fragment;
};

// Time bucket calculation for dual-epoch system
static __always_inline __u32 calculate_time_bucket(__u64 current_time, __u8 epoch_type) {
    __u64 epoch_start;
    
    if (epoch_type == EPOCH_DAILY) {
        // Daily epoch: 500ms buckets since UTC midnight
        __u64 seconds_since_epoch = current_time / 1000000000ULL;
        __u64 seconds_today = seconds_since_epoch % 86400; // 24 * 60 * 60
        epoch_start = seconds_today * 1000000000ULL;
    } else {
        // Monthly epoch: 500ms buckets since month start (uses 30-day approximation for eBPF)
        __u64 seconds_since_epoch = current_time / 1000000000ULL;
        __u64 seconds_this_month = seconds_since_epoch % 2592000; // 30 * 24 * 60 * 60 (approx)
        epoch_start = seconds_this_month * 1000000000ULL;
    }
    
    __u64 time_in_epoch = current_time - epoch_start;
    return (__u32)(time_in_epoch / 500000000ULL); // 500ms buckets
}

// Extract session ID from variable-length field
static __always_inline __u64 extract_session_id(void *data, void *data_end, 
                                                __u8 session_id_length, 
                                                __u16 *offset) {
    void *session_id_ptr = data + *offset;
    __u64 session_id = 0;
    
    switch (session_id_length) {
        case SESSION_ID_16BIT:
            if (session_id_ptr + 2 > data_end)
                return 0;
            session_id = bpf_ntohs(*(__u16 *)session_id_ptr);
            *offset += 2;
            break;
        case SESSION_ID_32BIT:
            if (session_id_ptr + 4 > data_end)
                return 0;
            session_id = bpf_ntohl(*(__u32 *)session_id_ptr);
            *offset += 4;
            break;
        case SESSION_ID_64BIT:
            if (session_id_ptr + 8 > data_end)
                return 0;
            session_id = bpf_be64_to_cpu(*(__u64 *)session_id_ptr);
            *offset += 8;
            break;
        default:
            return 0;
    }
    
    return session_id;
}

// Extract timestamp from variable-length field
static __always_inline __u32 extract_timestamp(void *data, void *data_end, 
                                               __u8 timestamp_length, 
                                               __u16 *offset) {
    void *timestamp_ptr = data + *offset;
    __u32 timestamp = 0;
    
    switch (timestamp_length) {
        case TIMESTAMP_16BIT:
            if (timestamp_ptr + 2 > data_end)
                return 0;
            timestamp = bpf_ntohs(*(__u16 *)timestamp_ptr);
            *offset += 2;
            break;
        case TIMESTAMP_24BIT:
            if (timestamp_ptr + 3 > data_end)
                return 0;
            // Extract 24-bit value (big-endian)
            timestamp = ((*(__u8 *)timestamp_ptr) << 16) |
                       ((*((__u8 *)timestamp_ptr + 1)) << 8) |
                       (*((__u8 *)timestamp_ptr + 2));
            *offset += 3;
            break;
        case TIMESTAMP_32BIT:
            if (timestamp_ptr + 4 > data_end)
                return 0;
            timestamp = bpf_ntohl(*(__u32 *)timestamp_ptr);
            *offset += 4;
            break;
        default:
            return 0;
    }
    
    return timestamp;
}

// Get HMAC size based on policy
static __always_inline __u8 get_hmac_size(__u8 hmac_policy) {
    switch (hmac_policy) {
        case HMAC_POLICY_LIGHT:
            return 8;   // 64-bit HMAC
        case HMAC_POLICY_MEDIUM:
            return 16;  // 128-bit HMAC
        case HMAC_POLICY_STRONG:
            return 32;  // 256-bit HMAC
        default:
            return 8;
    }
}

// Get HMAC size from session map lookup (eBPF context only)
// Returns HMAC size based on session's configured policy, or default (8 bytes) if session not found
#ifdef __BPF__
static __always_inline __u8 get_hmac_size_from_session(__u64 session_id) {
    struct session_info *session = MAP_LOOKUP_ELEM(session_map, &session_id);
    if (!session) {
        return 8;  // Default to LIGHT policy if session not found
    }
    return get_hmac_size(session->hmac_policy);
}
#endif // __BPF__

// Determine HMAC policy based on packet type and security context (eBPF context only)
#ifdef __BPF__
static __always_inline __u8 determine_hmac_policy(__u8 packet_type,
                                                  __u8 flags,
                                                  __u64 current_time,
                                                  struct session_info *session) {
    // Critical packets always use STRONG HMAC
    if (packet_type == PKT_TYPE_SYN || 
        packet_type == PKT_TYPE_SYN_ACK || 
        packet_type == PKT_TYPE_FIN ||
        packet_type == PKT_TYPE_DISCOVERY) {
        return HMAC_POLICY_STRONG;
    }
    
    // Control packets use minimum MEDIUM HMAC
    if (packet_type == PKT_TYPE_ERROR || 
        packet_type == PKT_TYPE_RST || 
        packet_type == PKT_TYPE_HEARTBEAT ||
        packet_type == PKT_TYPE_CONTROL ||
        packet_type == PKT_TYPE_MANAGEMENT ||
        (flags & PKT_FLAG_RECOVERY)) {
        return HMAC_POLICY_MEDIUM;
    }
    
    // Month boundary transitions force STRONG HMAC
    __u32 current_bucket = calculate_time_bucket(current_time, EPOCH_MONTHLY);
    __u32 buckets_per_month = 2592000 * 2; // 30 days * 24 hours * 60 minutes * 60 seconds * 2 (500ms buckets)
    if (current_bucket > buckets_per_month - 7200) { // Last hour of month
        return HMAC_POLICY_STRONG;
    }
    
    // Check if session requires STRONG HMAC due to previous failures
    if (session && session->security_violations > 0) {
        return HMAC_POLICY_STRONG;
    }

    // Use session's configured HMAC policy if available
    if (session && session->hmac_policy != 0) {
        return session->hmac_policy;
    }

    // Data packets use LIGHT HMAC by default
    return HMAC_POLICY_LIGHT;
}
#else
// Userspace simplified version of determine_hmac_policy (no session lookup)
static __always_inline __u8 determine_hmac_policy(__u8 packet_type,
                                                  __u8 flags,
                                                  __u64 current_time,
                                                  void *session) {
    (void)current_time;  // Unused in userspace stub
    (void)session;       // Not available in userspace

    // Critical packets always use STRONG HMAC
    if (packet_type == PKT_TYPE_SYN ||
        packet_type == PKT_TYPE_SYN_ACK ||
        packet_type == PKT_TYPE_FIN ||
        packet_type == PKT_TYPE_DISCOVERY) {
        return HMAC_POLICY_STRONG;
    }

    // Control packets use minimum MEDIUM HMAC
    if (packet_type == PKT_TYPE_ERROR ||
        packet_type == PKT_TYPE_RST ||
        packet_type == PKT_TYPE_HEARTBEAT ||
        packet_type == PKT_TYPE_CONTROL ||
        packet_type == PKT_TYPE_MANAGEMENT ||
        (flags & PKT_FLAG_RECOVERY)) {
        return HMAC_POLICY_MEDIUM;
    }

    // Data packets use LIGHT HMAC by default in userspace
    return HMAC_POLICY_LIGHT;
}
#endif // __BPF__

// Parse adaptive header with comprehensive bounds checking
static __always_inline int parse_buckwild_header(void *data, void *data_end,
                                                 struct parsed_header *parsed) {
    if (data + sizeof(struct buckwild_header) > data_end)
        return -1;
    
    struct buckwild_header *hdr = (struct buckwild_header *)data;
    __u16 offset = 4; // Skip fixed fields
    
    // Parse version information
    parsed->version = hdr->version_info & 0x0F;
    parsed->session_id_length = (hdr->version_info >> 4) & 0x03;
    parsed->timestamp_length = (hdr->version_info >> 6) & 0x03;
    parsed->packet_type = hdr->packet_type;
    parsed->packet_subtype = hdr->packet_subtype;
    parsed->flags = hdr->flags;
    parsed->validation_status = VALIDATION_OK;
    parsed->security_flags = 0;
    
    // Validate version
    if (parsed->version != BUCKWILD_VERSION) {
        parsed->validation_status |= VALIDATION_INVALID_VERSION;
        return -1;
    }
    
    // Extract session ID
    parsed->session_id = extract_session_id(data, data_end, 
                                           parsed->session_id_length, &offset);
    if (parsed->session_id == 0 && parsed->session_id_length != SESSION_ID_16BIT) {
        parsed->validation_status |= VALIDATION_INVALID_SESSION;
        return -1;
    }
    
    // Extract timestamp
    parsed->timestamp = extract_timestamp(data, data_end, 
                                         parsed->timestamp_length, &offset);
    if (parsed->timestamp == 0) {
        parsed->validation_status |= VALIDATION_INVALID_TIMESTAMP;
        return -1;
    }
    
    // Extract sequence number
    if (data + offset + 4 > data_end) {
        parsed->validation_status |= VALIDATION_INVALID_SIZE;
        return -1;
    }
    parsed->sequence_number = bpf_ntohl(*(__u32 *)(data + offset));
    offset += 4;
    
    // Extract acknowledgment (optional for some packet types)
    if (parsed->packet_type != PKT_TYPE_SYN) {
        if (data + offset + 4 > data_end) {
            parsed->validation_status |= VALIDATION_INVALID_SIZE;
            return -1;
        }
        parsed->acknowledgment = bpf_ntohl(*(__u32 *)(data + offset));
        offset += 4;
    }
    
    // Extract window size (optional for some packet types)
    if (parsed->packet_type == PKT_TYPE_DATA || 
        parsed->packet_type == PKT_TYPE_ACK) {
        if (data + offset + 2 > data_end) {
            parsed->validation_status |= VALIDATION_INVALID_SIZE;
            return -1;
        }
        parsed->window_size = bpf_ntohs(*(__u16 *)(data + offset));
        offset += 2;
    }
    
    // Parse fragment header if fragmented
    if (parsed->flags & PKT_FLAG_FRAGMENTED) {
        if (data + offset + sizeof(struct fragment_header) > data_end) {
            parsed->validation_status |= VALIDATION_INVALID_SIZE;
            return -1;
        }
        struct fragment_header *frag = (struct fragment_header *)(data + offset);
        parsed->fragment.fragment_id = bpf_ntohs(frag->fragment_id);
        parsed->fragment.fragment_index = bpf_ntohs(frag->fragment_index);
        parsed->fragment.total_fragments = bpf_ntohs(frag->total_fragments);
        parsed->fragment.fragment_size = bpf_ntohs(frag->fragment_size);
        offset += sizeof(struct fragment_header);
    }
    
    // Determine HMAC policy
    __u64 current_time = bpf_ktime_get_ns();
    parsed->hmac_policy = determine_hmac_policy(parsed->packet_type, 
                                               parsed->flags, 
                                               current_time, NULL);
    
    // Calculate final header length including HMAC
    __u8 hmac_size = get_hmac_size(parsed->hmac_policy);
    parsed->header_length = offset + hmac_size;
    
    // Validate total header size
    if (data + parsed->header_length > data_end) {
        parsed->validation_status |= VALIDATION_INVALID_SIZE;
        return -1;
    }
    
    // Validate header size bounds
    if (parsed->header_length < MIN_HEADER_SIZE || 
        parsed->header_length > MAX_HEADER_SIZE) {
        parsed->validation_status |= VALIDATION_INVALID_SIZE;
        return -1;
    }
    
    return 0;
}

// Validate timestamp against dual-epoch system
static __always_inline int validate_timestamp(__u32 packet_timestamp,
                                              __u8 timestamp_length,
                                              __u64 current_time,
                                              __u8 epoch_type) {
    __u32 current_bucket = calculate_time_bucket(current_time, epoch_type);
    __u32 packet_bucket = packet_timestamp;
    
    // Calculate maximum timestamp value for the given length
    __u32 max_timestamp;
    switch (timestamp_length) {
        case TIMESTAMP_16BIT:
            max_timestamp = 0xFFFF;
            break;
        case TIMESTAMP_24BIT:
            max_timestamp = 0xFFFFFF;
            break;
        case TIMESTAMP_32BIT:
            max_timestamp = 0xFFFFFFFF;
            break;
        default:
            return -1;
    }
    
    // Handle timestamp wraparound
    __u32 time_diff;
    if (packet_bucket > current_bucket) {
        // Check if this is wraparound or future timestamp
        __u32 forward_diff = packet_bucket - current_bucket;
        __u32 backward_diff = (max_timestamp - packet_bucket) + current_bucket + 1;
        time_diff = (forward_diff < backward_diff) ? forward_diff : backward_diff;
    } else {
        time_diff = current_bucket - packet_bucket;
    }
    
    // 30-second sliding window (60 buckets of 500ms each)
    if (time_diff > 60) {
        return -1; // Outside valid window
    }
    
    return 0;
}

// Check if packet could be Buckwild protocol
static __always_inline int is_buckwild_packet(void *data, void *data_end) {
    if (data + MIN_HEADER_SIZE > data_end)
        return 0;
    
    struct buckwild_header *hdr = (struct buckwild_header *)data;
    
    // Check version
    if ((hdr->version_info & 0x0F) != BUCKWILD_VERSION)
        return 0;
    
    // Check packet type (valid range: 0x01-0x0E)
    if (hdr->packet_type == 0 || hdr->packet_type > PKT_TYPE_DISCOVERY)
        return 0;
    
    // Basic size validation
    __u8 session_id_length = (hdr->version_info >> 4) & 0x03;
    __u8 timestamp_length = (hdr->version_info >> 6) & 0x03;
    
    __u16 min_size = 4; // Fixed header
    min_size += (session_id_length == SESSION_ID_16BIT) ? 2 : 
                (session_id_length == SESSION_ID_32BIT) ? 4 : 8;
    min_size += (timestamp_length == TIMESTAMP_16BIT) ? 2 : 
                (timestamp_length == TIMESTAMP_24BIT) ? 3 : 4;
    min_size += 4; // Sequence number
    min_size += 8; // Minimum HMAC
    
    if (data + min_size > data_end)
        return 0;
    
    return 1;
}

// Check if port could be a Buckwild protocol port (quick pre-filter for eBPF)
// Note: Exact port validation is done against session.expected_port after session lookup
// Upper bound check (65535) is implicit for __u16 type
static __always_inline int is_potential_buckwild_port(__u16 port) {
    return (port >= 1024);
}

#endif // BUCKWILD_EBPF_PROTOCOL_H