/**
 * QoS Priority Classification Implementation
 */

#include "qos.h"

uint8_t classify_packet_priority(uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    (void)protocol;  // Protocol can be used for future protocol-specific classification

    // Check destination port first (most common case)
    // DNS - Critical for connectivity
    if (dst_port == 53 || src_port == 53) {
        return QOS_PRIORITY_CRITICAL;
    }

    // SSH - High priority for interactive sessions
    if (dst_port == 22 || src_port == 22) {
        return QOS_PRIORITY_HIGH;
    }

    // HTTP/HTTPS - Normal priority for web traffic
    if (dst_port == 80 || dst_port == 443 || src_port == 80 || src_port == 443) {
        return QOS_PRIORITY_NORMAL;
    }

    // High ephemeral ports on both ends - likely bulk/P2P transfer
    if (src_port > 49152 && dst_port > 49152) {
        return QOS_PRIORITY_LOW;
    }

    // Default - normal priority
    return QOS_PRIORITY_NORMAL;
}
