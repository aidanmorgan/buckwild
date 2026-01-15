// C Test Helper for Ring Buffer Integration Tests
//
// This file provides C functions to create packet_event structs
// that can be used to test C-to-Rust interoperability.

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

// Match the struct from src/ebpf/c/include/maps.h exactly
struct packet_event {
    uint64_t session_id;
    uint64_t sequence;
    uint64_t timestamp_us;
    uint16_t payload_length;
    uint8_t packet_type;
    uint8_t flags;
    uint32_t src_ip;
} __attribute__((packed));

// Verify struct size at compile time
_Static_assert(sizeof(struct packet_event) == 32,
               "packet_event must be exactly 32 bytes");

/// Create a test packet_event with specified values
void create_packet_event(
    uint8_t *buffer,
    uint64_t session_id,
    uint64_t sequence,
    uint64_t timestamp_us,
    uint16_t payload_length,
    uint8_t packet_type,
    uint8_t flags,
    uint32_t src_ip)
{
    struct packet_event *event = (struct packet_event *)buffer;

    event->session_id = session_id;
    event->sequence = sequence;
    event->timestamp_us = timestamp_us;
    event->payload_length = payload_length;
    event->packet_type = packet_type;
    event->flags = flags;
    event->src_ip = src_ip;
}

/// Create a test event with default values
void create_test_packet_event(uint8_t *buffer) {
    create_packet_event(
        buffer,
        0x1234567890ABCDEF,  // session_id
        42,                  // sequence
        1000000,             // timestamp_us
        1500,                // payload_length
        0x01,                // packet_type
        0x80,                // flags
        0xC0A80164           // src_ip (192.168.1.100)
    );
}

/// Get the size of packet_event struct
uint32_t get_packet_event_size(void) {
    return sizeof(struct packet_event);
}

/// Verify field offsets match expectations
int verify_packet_event_layout(void) {
    // Check field offsets
    if (offsetof(struct packet_event, session_id) != 0) return 0;
    if (offsetof(struct packet_event, sequence) != 8) return 0;
    if (offsetof(struct packet_event, timestamp_us) != 16) return 0;
    if (offsetof(struct packet_event, payload_length) != 24) return 0;
    if (offsetof(struct packet_event, packet_type) != 26) return 0;
    if (offsetof(struct packet_event, flags) != 27) return 0;
    if (offsetof(struct packet_event, src_ip) != 28) return 0;

    // Check total size
    if (sizeof(struct packet_event) != 32) return 0;

    return 1;  // All checks passed
}

/// Create multiple test events
void create_batch_events(uint8_t *buffer, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *event_buffer = buffer + (i * sizeof(struct packet_event));
        create_packet_event(
            event_buffer,
            i,                      // session_id
            i * 10,                 // sequence
            1000000 + i,            // timestamp_us
            1000 + i,               // payload_length
            0x01,                   // packet_type
            (uint8_t)i,            // flags
            0xC0A80101 + i         // src_ip
        );
    }
}

/// Parse a packet_event from buffer and extract values
void extract_packet_event_values(
    const uint8_t *buffer,
    uint64_t *session_id,
    uint64_t *sequence,
    uint64_t *timestamp_us,
    uint16_t *payload_length,
    uint8_t *packet_type,
    uint8_t *flags,
    uint32_t *src_ip)
{
    const struct packet_event *event = (const struct packet_event *)buffer;

    *session_id = event->session_id;
    *sequence = event->sequence;
    *timestamp_us = event->timestamp_us;
    *payload_length = event->payload_length;
    *packet_type = event->packet_type;
    *flags = event->flags;
    *src_ip = event->src_ip;
}

/// Test endianness conversion
int test_endianness(void) {
    uint64_t value = 0x0102030405060708ULL;
    uint8_t *bytes = (uint8_t *)&value;

    // On little-endian system, least significant byte first
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    if (bytes[0] != 0x08) return 0;
    if (bytes[7] != 0x01) return 0;
    #endif

    return 1;
}

/// Create a packet event with maximum values
void create_max_values_event(uint8_t *buffer) {
    create_packet_event(
        buffer,
        UINT64_MAX,  // session_id
        UINT64_MAX,  // sequence
        UINT64_MAX,  // timestamp_us
        UINT16_MAX,  // payload_length
        UINT8_MAX,   // packet_type
        UINT8_MAX,   // flags
        UINT32_MAX   // src_ip
    );
}

/// Create a packet event with zero values
void create_zero_values_event(uint8_t *buffer) {
    memset(buffer, 0, sizeof(struct packet_event));
}
