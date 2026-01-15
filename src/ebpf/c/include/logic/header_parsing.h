/**
 * @file header_parsing.h
 * @brief Pure C logic for parsing Buckwild adaptive headers
 *
 * Handles variable-length fields:
 * - Session ID: 16-bit, 32-bit, or 64-bit
 * - Timestamp: 16-bit, 24-bit, or 32-bit
 * - HMAC: 8, 16, or 32 bytes
 */

#ifndef BUCKWILD_HEADER_PARSING_H
#define BUCKWILD_HEADER_PARSING_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Session ID type constants (from protocol.h, duplicated for userspace testing)
#define SESSION_ID_16BIT 0
#define SESSION_ID_32BIT 1
#define SESSION_ID_64BIT 2

// HMAC policy constants (from protocol.h, duplicated for userspace testing)
#define HMAC_POLICY_LIGHT 1
#define HMAC_POLICY_MEDIUM 2
#define HMAC_POLICY_STRONG 3

/**
 * Parsed header structure (matches test definition)
 */
struct parsed_header {
    uint8_t version;
    uint8_t packet_type;
    uint8_t session_id_type;  // 0=16bit, 1=32bit, 2=64bit
    uint64_t session_id;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint32_t timestamp;
    uint16_t payload_length;
    uint8_t hmac_policy;
    uint8_t flags;
};

/**
 * Parse Buckwild header with adaptive fields
 *
 * @param packet Pointer to packet data
 * @param packet_len Length of packet data
 * @param parsed Output structure for parsed fields
 * @return 0 on success, negative on error
 */
static inline int parse_buckwild_header(const uint8_t *packet, size_t packet_len,
                                         struct parsed_header *parsed) {
    // Minimum packet is 26 bytes (16-bit SID, 16-bit TS, HMAC_LIGHT)
    if (!packet || !parsed || packet_len < 26) {
        return -1;
    }

    size_t offset = 0;

    // Byte 0: Version + SID type + TS type
    uint8_t version_byte = packet[offset++];
    parsed->version = (version_byte >> 4) & 0x0F;
    uint8_t sid_type = (version_byte >> 2) & 0x03;
    uint8_t ts_type = version_byte & 0x03;

    parsed->session_id_type = sid_type;

    // Byte 1: Packet type
    parsed->packet_type = packet[offset++];

    // Byte 2: Sub-type
    offset++;  // Skip sub-type for now

    // Byte 3: Flags
    parsed->flags = packet[offset++];

    // Variable-length session ID
    parsed->session_id = 0;
    switch (sid_type) {
        case SESSION_ID_16BIT:  // 0 = 16-bit
            if (offset + 2 > packet_len) return -1;
            parsed->session_id = (uint64_t)packet[offset] << 8 |
                                 (uint64_t)packet[offset + 1];
            offset += 2;
            break;

        case SESSION_ID_32BIT:  // 1 = 32-bit
            if (offset + 4 > packet_len) return -1;
            parsed->session_id = ((uint64_t)packet[offset] << 24) |
                                 ((uint64_t)packet[offset + 1] << 16) |
                                 ((uint64_t)packet[offset + 2] << 8) |
                                 ((uint64_t)packet[offset + 3]);
            offset += 4;
            break;

        case SESSION_ID_64BIT:  // 2 = 64-bit
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
            return -1;  // Invalid session ID type
    }

    // Sequence number (always 32-bit)
    if (offset + 4 > packet_len) return -1;
    parsed->sequence_number = ((uint32_t)packet[offset] << 24) |
                              ((uint32_t)packet[offset + 1] << 16) |
                              ((uint32_t)packet[offset + 2] << 8) |
                              ((uint32_t)packet[offset + 3]);
    offset += 4;

    // Ack number (always 32-bit)
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
            return -1;  // Invalid timestamp type
    }

    // Payload length (always 16-bit)
    if (offset + 2 > packet_len) return -1;
    parsed->payload_length = (uint16_t)packet[offset] << 8 |
                             (uint16_t)packet[offset + 1];
    offset += 2;

    // HMAC policy defaults to LIGHT; actual HMAC validation occurs post-parsing in session validation
    parsed->hmac_policy = HMAC_POLICY_LIGHT;

    return 0;  // Success
}

#endif // BUCKWILD_HEADER_PARSING_H
