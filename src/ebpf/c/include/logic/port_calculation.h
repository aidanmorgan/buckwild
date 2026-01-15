/**
 * @file port_calculation.h
 * @brief Pure C logic for port hopping validation
 *
 * Validates ports against session state and time windows
 */

#ifndef BUCKWILD_PORT_CALCULATION_H
#define BUCKWILD_PORT_CALCULATION_H

#include <stdint.h>

// Port validation results (matches test definition)
#define PORT_VALID 0
#define PORT_VALID_NEXT_WINDOW 1
#define PORT_INVALID -1

/**
 * Validate port against session state
 *
 * Checks if received port matches:
 * 1. Current port (exact match)
 * 2. Next port (if within adaptive window transition)
 *
 * Adaptive window transition:
 * - When current window is 80% complete, accept next window port
 * - This allows smooth transitions without packet loss
 *
 * @param session Session state with port information
 * @param received_port Port number from received packet
 * @param current_time_bucket Current 500ms time bucket
 * @return PORT_VALID, PORT_VALID_NEXT_WINDOW, or PORT_INVALID
 */
static inline int validate_port(const struct session_state *session,
                                 uint16_t received_port,
                                 uint32_t current_time_bucket) {
    if (!session) {
        return PORT_INVALID;
    }

    // Check if port matches current port
    if (received_port == session->current_port) {
        return PORT_VALID;
    }

    // Check if we should accept next window port (adaptive transition)
    // Calculate how far we are into the current window
    uint32_t buckets_into_window = current_time_bucket - session->port_window_start;

    // Accept next window port if we're in the last 20% of current window
    // For a window size of 5, accept at bucket 4 (4/5 = 80%)
    uint32_t transition_threshold = (session->port_window_size * 80) / 100;

    if (buckets_into_window >= transition_threshold) {
        // We're in transition zone - check next port
        if (received_port == session->next_port) {
            return PORT_VALID_NEXT_WINDOW;
        }
    }

    // Port doesn't match current or next
    return PORT_INVALID;
}

#endif // BUCKWILD_PORT_CALCULATION_H
