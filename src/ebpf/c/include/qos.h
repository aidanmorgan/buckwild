/**
 * QoS (Quality of Service) Priority Classification
 *
 * Classifies network packets into priority levels based on port numbers,
 * protocols, and traffic patterns for traffic control.
 */

#ifndef BUCKWILD_QOS_H
#define BUCKWILD_QOS_H

#include <stdint.h>

// QoS priority levels (0-7, higher is more critical)
#define QOS_PRIORITY_CRITICAL  7  // DNS, NTP, critical infrastructure
#define QOS_PRIORITY_HIGH      5  // SSH, interactive sessions
#define QOS_PRIORITY_NORMAL    3  // HTTP/HTTPS, general traffic
#define QOS_PRIORITY_LOW       1  // Bulk transfers, background
#define QOS_PRIORITY_BULK      0  // Large file transfers, lowest priority

// Traffic class identifiers
#define TC_CLASS_INTERACTIVE   0x01  // Interactive traffic (SSH, telnet)
#define TC_CLASS_BULK          0x02  // Bulk transfers (FTP, rsync)
#define TC_CLASS_BACKGROUND    0x03  // Background traffic
#define TC_CLASS_REALTIME      0x04  // Real-time traffic (VoIP, streaming)

/**
 * Classify packet priority based on port and protocol
 *
 * @param src_port Source port number
 * @param dst_port Destination port number
 * @param protocol IP protocol number (6=TCP, 17=UDP)
 * @return QoS priority level (0-7)
 *
 * Priority assignment:
 * - CRITICAL (7): DNS (53), essential infrastructure
 * - HIGH (5): SSH (22), interactive protocols
 * - NORMAL (3): HTTP/HTTPS (80/443), standard web traffic
 * - LOW (1): High ephemeral ports (>49152), P2P traffic
 * - Default: NORMAL (3) for unrecognized traffic
 */
uint8_t classify_packet_priority(uint16_t src_port, uint16_t dst_port, uint8_t protocol);

#endif // BUCKWILD_QOS_H
