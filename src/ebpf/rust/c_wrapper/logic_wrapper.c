/**
 * @file logic_wrapper.c
 * @brief C wrapper for Stage 3 logic functions (makes inline functions linkable)
 *
 * The logic functions are defined as static inline in headers for eBPF usage.
 * This wrapper compiles them into a library so Rust can link against them via FFI.
 *
 * Note: We intentionally use the same function names (without static inline)
 * so the linker finds these instead of complaining about undefined references.
 */

#include <stdint.h>
#include <stddef.h>

// Include the inline implementations
#define BUCKWILD_PACKET_DETECTION_H  // Prevent double-include guard
#define BUCKWILD_HEADER_PARSING_H
#define BUCKWILD_SESSION_VALIDATION_H
#define BUCKWILD_PORT_CALCULATION_H
#define BUCKWILD_SECURITY_CHECKS_H

// Manually include the inline function definitions
// We'll compile them as normal functions for FFI linking

// From packet_detection.h
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

int is_buckwild_protocol(const uint8_t *packet, size_t packet_len) {
    if (!packet || packet_len < 4) {
        return 0;
    }

    uint8_t version_byte = packet[0];
    uint8_t version = (version_byte >> 4) & 0x0F;

    if (version != 0x01) {
        return 0;
    }

    uint8_t packet_type = packet[1];

    switch (packet_type) {
        case PKT_TYPE_SYN:
        case PKT_TYPE_SYN_ACK:
        case PKT_TYPE_ACK:
        case PKT_TYPE_DATA:
        case PKT_TYPE_FIN:
        case PKT_TYPE_HEARTBEAT:
        case PKT_TYPE_ERROR:
        case PKT_TYPE_RST:
        case PKT_TYPE_CONTROL:
        case PKT_TYPE_MANAGEMENT:
        case PKT_TYPE_DISCOVERY:
            return 1;
        default:
            return 0;
    }
}

// From header_parsing.h
#define SESSION_ID_16BIT 0
#define SESSION_ID_32BIT 1
#define SESSION_ID_64BIT 2
#define HMAC_POLICY_LIGHT 1

struct parsed_header {
    uint8_t version;
    uint8_t packet_type;
    uint8_t session_id_type;
    uint64_t session_id;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint32_t timestamp;
    uint16_t payload_length;
    uint8_t hmac_policy;
    uint8_t flags;
};

int parse_buckwild_header(const uint8_t *packet, size_t packet_len,
                           struct parsed_header *parsed) {
    if (!packet || !parsed || packet_len < 26) {
        return -1;
    }

    size_t offset = 0;
    uint8_t version_byte = packet[offset++];
    parsed->version = (version_byte >> 4) & 0x0F;
    uint8_t sid_type = (version_byte >> 2) & 0x03;
    uint8_t ts_type = version_byte & 0x03;

    parsed->session_id_type = sid_type;
    parsed->packet_type = packet[offset++];
    offset++; // Skip sub-type
    parsed->flags = packet[offset++];

    // Variable-length session ID
    parsed->session_id = 0;
    switch (sid_type) {
        case SESSION_ID_16BIT:
            if (offset + 2 > packet_len) return -1;
            parsed->session_id = (uint64_t)packet[offset] << 8 |
                                 (uint64_t)packet[offset + 1];
            offset += 2;
            break;
        case SESSION_ID_32BIT:
            if (offset + 4 > packet_len) return -1;
            parsed->session_id = ((uint64_t)packet[offset] << 24) |
                                 ((uint64_t)packet[offset + 1] << 16) |
                                 ((uint64_t)packet[offset + 2] << 8) |
                                 ((uint64_t)packet[offset + 3]);
            offset += 4;
            break;
        case SESSION_ID_64BIT:
            if (offset + 8 > packet_len) return -1;
            parsed->session_id = ((uint64_t)packet[offset] << 56) |
                                 ((uint64_t)packet[offset + 1] << 48) |
                                 ((uint64_t)packet[offset + 2] << 40) |
                                 ((uint64_t)packet[offset + 3] << 32) |
                                 ((uint64_t)packet[offset + 4] << 24) |
                                 ((uint64_t)packet[offset + 5] << 16) |
                                 ((uint64_t)packet[offset + 6] << 8) |
                                 ((uint64_t)packet[offset + 7]);
            offset += 8;
            break;
        default:
            return -1;
    }

    // Sequence number
    if (offset + 4 > packet_len) return -1;
    parsed->sequence_number = ((uint32_t)packet[offset] << 24) |
                              ((uint32_t)packet[offset + 1] << 16) |
                              ((uint32_t)packet[offset + 2] << 8) |
                              ((uint32_t)packet[offset + 3]);
    offset += 4;

    // Ack number
    if (offset + 4 > packet_len) return -1;
    parsed->ack_number = ((uint32_t)packet[offset] << 24) |
                         ((uint32_t)packet[offset + 1] << 16) |
                         ((uint32_t)packet[offset + 2] << 8) |
                         ((uint32_t)packet[offset + 3]);
    offset += 4;

    // Variable-length timestamp
    parsed->timestamp = 0;
    switch (ts_type) {
        case 0:  // 16-bit
            if (offset + 2 > packet_len) return -1;
            parsed->timestamp = (uint32_t)packet[offset] << 8 |
                                (uint32_t)packet[offset + 1];
            offset += 2;
            break;
        case 1:  // 24-bit
            if (offset + 3 > packet_len) return -1;
            parsed->timestamp = ((uint32_t)packet[offset] << 16) |
                                ((uint32_t)packet[offset + 1] << 8) |
                                ((uint32_t)packet[offset + 2]);
            offset += 3;
            break;
        case 2:  // 32-bit
            if (offset + 4 > packet_len) return -1;
            parsed->timestamp = ((uint32_t)packet[offset] << 24) |
                                ((uint32_t)packet[offset + 1] << 16) |
                                ((uint32_t)packet[offset + 2] << 8) |
                                ((uint32_t)packet[offset + 3]);
            offset += 4;
            break;
        default:
            return -1;
    }

    // Payload length
    if (offset + 2 > packet_len) return -1;
    parsed->payload_length = (uint16_t)packet[offset] << 8 |
                             (uint16_t)packet[offset + 1];
    offset += 2;

    parsed->hmac_policy = HMAC_POLICY_LIGHT;
    return 0;
}

// From session_validation.h
#define SESSION_STATE_ACTIVE 2
#define SESSION_TIMEOUT_NS 60000000000ULL

struct session_state {
    uint64_t session_id;
    uint32_t state;
    uint64_t last_packet_time;
    uint16_t current_port;
    uint16_t next_port;
    uint32_t port_window_start;
    uint32_t port_window_size;
};

int is_session_active(const struct session_state *session,
                      uint64_t current_time_ns) {
    if (!session || session->state != SESSION_STATE_ACTIVE) {
        return 0;
    }

    uint64_t time_since_last_packet = current_time_ns - session->last_packet_time;
    if (time_since_last_packet > SESSION_TIMEOUT_NS) {
        return 0;
    }

    return 1;
}

// From port_calculation.h
#define PORT_VALID 0
#define PORT_VALID_NEXT_WINDOW 1
#define PORT_INVALID -1

int validate_port(const struct session_state *session,
                  uint16_t received_port,
                  uint32_t current_time_bucket) {
    if (!session) {
        return PORT_INVALID;
    }

    if (received_port == session->current_port) {
        return PORT_VALID;
    }

    // Adaptive transition: accept next port in last 20% of window
    uint32_t buckets_into_window = current_time_bucket - session->port_window_start;
    uint32_t transition_threshold = (session->port_window_size * 80) / 100;

    if (buckets_into_window >= transition_threshold) {
        if (received_port == session->next_port) {
            return PORT_VALID_NEXT_WINDOW;
        }
    }

    return PORT_INVALID;
}

// From security_checks.h
#define FRAGMENT_RATE_LIMIT 20
#define MAX_FRAGMENTS_PER_SESSION 10
#define MIN_FRAGMENT_SIZE 64
#define MAX_FRAGMENT_SIZE 1400
#define NSEC_PER_SEC 1000000000ULL
#define RATE_LIMIT_OK 0
#define RATE_LIMIT_EXCEEDED 1
#define FRAGMENT_BOMB_NONE 0
#define FRAGMENT_BOMB_DETECTED 1
#define FRAGMENT_SIZE_VALID 0
#define FRAGMENT_SIZE_INVALID 1

struct session_security_state {
    uint32_t fragment_count_current_window;
    uint64_t rate_limit_window_start;
    uint32_t outstanding_fragments;
    uint64_t total_reassembly_memory;
};

int check_fragment_rate_limit(const struct session_security_state *sec,
                               uint64_t current_time_ns) {
    if (!sec) {
        return RATE_LIMIT_EXCEEDED;
    }

    uint64_t window_elapsed = current_time_ns - sec->rate_limit_window_start;

    if (window_elapsed >= NSEC_PER_SEC) {
        return RATE_LIMIT_OK;
    }

    if (sec->fragment_count_current_window > FRAGMENT_RATE_LIMIT) {
        return RATE_LIMIT_EXCEEDED;
    }

    return RATE_LIMIT_OK;
}

int check_fragment_bomb(const struct session_security_state *sec) {
    if (!sec) {
        return FRAGMENT_BOMB_NONE;
    }

    if (sec->outstanding_fragments > MAX_FRAGMENTS_PER_SESSION) {
        return FRAGMENT_BOMB_DETECTED;
    }

    return FRAGMENT_BOMB_NONE;
}

int validate_fragment_size(uint16_t fragment_size) {
    if (fragment_size < MIN_FRAGMENT_SIZE || fragment_size > MAX_FRAGMENT_SIZE) {
        return FRAGMENT_SIZE_INVALID;
    }
    return FRAGMENT_SIZE_VALID;
}
