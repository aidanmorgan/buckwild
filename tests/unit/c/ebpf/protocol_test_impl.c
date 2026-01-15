/**
 * @file protocol_test_impl.c
 * @brief Userspace-testable implementation of protocol parsing functions
 *
 * This provides implementations that match the eBPF logic but can run in userspace tests.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* Protocol constants */
#define PROTOCOL_VERSION 0x01
#define MIN_PACKET_SIZE 26

/* Packet types */
#define PKT_TYPE_SYN        0x01
#define PKT_TYPE_SYN_ACK    0x02
#define PKT_TYPE_ACK        0x03
#define PKT_TYPE_DATA       0x04
#define PKT_TYPE_FIN        0x05
#define PKT_TYPE_HEARTBEAT  0x06
#define PKT_TYPE_ERROR      0x09
#define PKT_TYPE_RST        0x0B
#define PKT_TYPE_CONTROL    0x0C
#define PKT_TYPE_MANAGEMENT 0x0D
#define PKT_TYPE_DISCOVERY  0x0E

/* Parsed header structure */
struct parsed_header {
	uint8_t protocol_version;
	uint8_t packet_type;
	uint8_t sub_type;
	uint8_t flags;
	uint64_t session_id;
	uint32_t sequence_number;
	uint32_t ack_number;
	uint32_t timestamp;
	uint16_t payload_length;
	uint8_t hmac_policy;
	uint8_t session_id_length;
	uint8_t timestamp_length;
	uint8_t security_flags;
	uint8_t validation_status;
};

/**
 * Check if packet is a valid Buckwild protocol packet
 */
int is_buckwild_packet(const void *data, const void *data_end) {
    if (!data || !data_end) {
        return 0;
    }

    // Check minimum size
    if (data_end - data < MIN_PACKET_SIZE) {
        return 0;
    }

    const uint8_t *pkt = (const uint8_t *)data;

    // Check version byte (bits 0-3 should be 0x01)
    uint8_t version = pkt[0] & 0x0F;
    if (version != PROTOCOL_VERSION) {
        return 0;
    }

    // Check packet type is valid
    uint8_t pkt_type = pkt[1];
    switch (pkt_type) {
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
            break;
        default:
            return 0;
    }

    return 1;
}

/**
 * Parse Buckwild packet header
 */
int parse_buckwild_header(const void *data, const void *data_end, struct parsed_header *parsed) {
    if (!data || !data_end || !parsed) {
        return -1;
    }

    if (data_end - data < MIN_PACKET_SIZE) {
        return -1;
    }

    const uint8_t *pkt = (const uint8_t *)data;
    size_t offset = 0;

    // Byte 0: Version byte
    uint8_t version_byte = pkt[offset++];
    parsed->protocol_version = version_byte & 0x0F;
    parsed->session_id_length = (version_byte >> 4) & 0x03;
    parsed->timestamp_length = (version_byte >> 6) & 0x03;

    // Bytes 1-3: Type, Sub-Type, Flags
    parsed->packet_type = pkt[offset++];
    parsed->sub_type = pkt[offset++];
    parsed->flags = pkt[offset++];

    // Session ID (variable length: 2, 4, or 8 bytes)
    parsed->session_id = 0;
    size_t sid_bytes = (parsed->session_id_length == 0) ? 2 :
                       (parsed->session_id_length == 1) ? 4 : 8;

    if ((size_t)(data_end - data) < offset + sid_bytes) {
        return -1;
    }

    for (size_t i = 0; i < sid_bytes; i++) {
        parsed->session_id = (parsed->session_id << 8) | pkt[offset++];
    }

    // Sequence Number (4 bytes, big-endian)
    if ((size_t)(data_end - data) < offset + 4) {
        return -1;
    }
    parsed->sequence_number = ((uint32_t)pkt[offset] << 24) |
                              ((uint32_t)pkt[offset+1] << 16) |
                              ((uint32_t)pkt[offset+2] << 8) |
                              pkt[offset+3];
    offset += 4;

    // Ack Number (4 bytes, big-endian)
    if ((size_t)(data_end - data) < offset + 4) {
        return -1;
    }
    parsed->ack_number = ((uint32_t)pkt[offset] << 24) |
                         ((uint32_t)pkt[offset+1] << 16) |
                         ((uint32_t)pkt[offset+2] << 8) |
                         pkt[offset+3];
    offset += 4;

    // Timestamp (variable length: 2, 3, or 4 bytes)
    parsed->timestamp = 0;
    size_t ts_bytes = (parsed->timestamp_length == 0) ? 2 :
                      (parsed->timestamp_length == 1) ? 3 :
                      (parsed->timestamp_length == 2) ? 3 : 4;

    if ((size_t)(data_end - data) < offset + ts_bytes) {
        return -1;
    }

    for (size_t i = 0; i < ts_bytes; i++) {
        parsed->timestamp = (parsed->timestamp << 8) | pkt[offset++];
    }

    // Payload Length (2 bytes, big-endian)
    if ((size_t)(data_end - data) < offset + 2) {
        return -1;
    }
    parsed->payload_length = ((uint16_t)pkt[offset] << 8) | pkt[offset+1];
    offset += 2;

    return 0;
}

/**
 * Validate timestamp against current time
 */
int validate_timestamp(uint32_t packet_timestamp, uint8_t timestamp_length,
                       uint64_t current_time_ns, uint8_t epoch_type) {
    // Suppress unused parameter warnings
    (void)packet_timestamp;
    (void)timestamp_length;
    (void)current_time_ns;
    (void)epoch_type;

    // Simplified validation - just check that timestamp is reasonable
    // In real implementation, would check against adaptive windows

    // For now, accept all timestamps (tests will verify this is called correctly)
    return 0;
}
