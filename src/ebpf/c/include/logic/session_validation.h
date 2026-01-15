/**
 * @file session_validation.h
 * @brief Pure C logic for session state validation
 *
 * Validates session activity and state
 */

#ifndef BUCKWILD_SESSION_VALIDATION_H
#define BUCKWILD_SESSION_VALIDATION_H

#include <stdint.h>

// Session states (matches test definition)
#define SESSION_STATE_ACTIVE 1
#define SESSION_STATE_CLOSING 2
#define SESSION_STATE_CLOSED 3

// Session timeout: 60 seconds
#define SESSION_TIMEOUT_NS 60000000000ULL  // 60 * 10^9 nanoseconds

/**
 * Session state structure (matches test definition)
 */
struct session_state {
    uint64_t session_id;
    uint32_t current_port;
    uint32_t next_port;
    uint64_t last_packet_time;  // nanoseconds
    uint32_t port_window_start;  // time bucket
    uint8_t port_window_size;    // adaptive window (1-10)
    uint8_t state;              // SESSION_STATE_* constants
    uint8_t hmac_policy;
    uint8_t reserved;
};

/**
 * Check if session is active
 *
 * A session is active if:
 * - State is SESSION_STATE_ACTIVE
 * - Last packet time is within timeout (60 seconds)
 *
 * @param session Session state to check
 * @param current_time_ns Current time in nanoseconds
 * @return 1 if active, 0 if inactive/expired
 */
static inline int is_session_active(const struct session_state *session,
                                     uint64_t current_time_ns) {
    if (!session) {
        return 0;
    }

    // Check if session is in active state
    if (session->state != SESSION_STATE_ACTIVE) {
        return 0;  // Closing or closed
    }

    // Check if session has timed out (> 60 seconds since last packet)
    uint64_t time_since_last_packet = current_time_ns - session->last_packet_time;
    if (time_since_last_packet > SESSION_TIMEOUT_NS) {
        return 0;  // Expired
    }

    return 1;  // Active
}

#endif // BUCKWILD_SESSION_VALIDATION_H
