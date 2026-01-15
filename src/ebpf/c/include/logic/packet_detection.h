/**
 * @file packet_detection.h
 * @brief Pure C logic for Buckwild protocol detection
 *
 * These functions are pure C (no eBPF dependencies) and can be:
 * - Unit tested in userspace
 * - Used in eBPF programs
 * - Used in userspace daemon
 *
 * **Design**: Detect Buckwild protocol vs. generic UDP
 */

#ifndef BUCKWILD_PACKET_DETECTION_H
#define BUCKWILD_PACKET_DETECTION_H

#include <stdint.h>
#include <stddef.h>

// Packet type constants (from protocol.h, duplicated here for userspace testing)
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

/**
 * Check if packet is Buckwild protocol
 *
 * Validates:
 * - Minimum packet size (minimum header is 28 bytes)
 * - Version field (must be 0x01)
 * - Packet type field (must be valid PKT_TYPE_*)
 *
 * @param packet Pointer to packet data
 * @param packet_len Length of packet data
 * @return 1 if Buckwild protocol, 0 otherwise
 */
static inline int is_buckwild_protocol(const uint8_t *packet, size_t packet_len) {
    // Check minimum size (at least 4 bytes for version/type/subtype/flags)
    // Full validation will happen in parsing
    if (!packet || packet_len < 4) {
        return 0;
    }

    // Byte 0: Version (4 bits) + SID type (2 bits) + TS type (2 bits)
    uint8_t version_byte = packet[0];
    uint8_t version = (version_byte >> 4) & 0x0F;  // Upper 4 bits

    // Version must be 0x01
    if (version != 0x01) {
        return 0;
    }

    // Byte 1: Packet type
    uint8_t packet_type = packet[1];

    // Validate packet type (from protocol.h)
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
            return 1;  // Valid Buckwild packet
        default:
            return 0;  // Invalid packet type
    }
}

#endif // BUCKWILD_PACKET_DETECTION_H
