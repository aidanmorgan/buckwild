/**
 * @file port_hopping.c
 * @brief Port hopping implementation using HMAC-SHA256
 */

#include "buckwild/common/port_hopping.h"
#include "buckwild/common/crypto/hmac.h"
#include <string.h>

/**
 * @brief Convert uint32_t to big-endian bytes
 */
static inline void u32_to_be_bytes(uint32_t value, uint8_t *bytes) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)((value >> 16) & 0xFF);
    bytes[2] = (uint8_t)((value >> 8) & 0xFF);
    bytes[3] = (uint8_t)(value & 0xFF);
}

/**
 * @brief Extract uint32 from HMAC output
 */
static inline uint32_t extract_u32_from_hmac(const uint8_t *hmac) {
    // Use first 4 bytes of HMAC
    return ((uint32_t)hmac[0] << 24) |
           ((uint32_t)hmac[1] << 16) |
           ((uint32_t)hmac[2] << 8) |
           ((uint32_t)hmac[3]);
}

/**
 * @brief Derive port from key and time bucket
 *
 * Internal function used by both base and session port derivation.
 */
static uint16_t derive_port_internal(const uint8_t *key, size_t key_len,
                                     uint32_t time_bucket) {
    if (!key || key_len == 0) {
        return 0;  // Error
    }

    // Convert time bucket to big-endian bytes
    uint8_t bucket_bytes[4];
    u32_to_be_bytes(time_bucket, bucket_bytes);

    // Compute HMAC-SHA256(key, bucket_bytes)
    uint8_t hmac[BUCKWILD_HMAC_SHA256_SIZE];
    int result = buckwild_hmac_sha256(key, key_len,
                                      bucket_bytes, sizeof(bucket_bytes),
                                      hmac);

    if (result != 0) {
        return 0;  // HMAC computation failed
    }

    // Extract 32-bit value from HMAC
    uint32_t raw_value = extract_u32_from_hmac(hmac);

    // Map to port range [BUCKWILD_PORT_MIN, BUCKWILD_PORT_MAX]
    uint32_t port_range = BUCKWILD_PORT_MAX - BUCKWILD_PORT_MIN + 1;
    uint16_t port = (uint16_t)((raw_value % port_range) + BUCKWILD_PORT_MIN);

    return port;
}

// ============================================================================
// Port Derivation Functions
// ============================================================================

uint16_t buckwild_derive_base_port(const uint8_t *daily_key, size_t key_len,
                                    uint32_t time_bucket) {
    return derive_port_internal(daily_key, key_len, time_bucket);
}

uint16_t buckwild_derive_session_port(const uint8_t *session_key, size_t key_len,
                                       uint32_t time_bucket) {
    return derive_port_internal(session_key, key_len, time_bucket);
}

// ============================================================================
// Adaptive Window Functions
// ============================================================================

int buckwild_calculate_port_window(buckwild_port_window_t *window,
                                    uint32_t current_bucket,
                                    uint8_t delay_windows) {
    if (!window) {
        return -EINVAL;
    }

    // Validate delay windows range
    if (delay_windows < BUCKWILD_MIN_DELAY_WINDOWS ||
        delay_windows > BUCKWILD_MAX_DELAY_WINDOWS) {
        return -EINVAL;
    }

    // Window extends backwards: [current - (delay_windows - 1), current]
    // For delay_windows=1: [current, current] (only current bucket)
    // For delay_windows=4: [current-3, current] (current + 3 past buckets)
    window->bucket_end = current_bucket;
    window->bucket_start = current_bucket - (delay_windows - 1);
    window->delay_windows = delay_windows;

    return 0;
}

// ============================================================================
// Port Validation Functions
// ============================================================================

bool buckwild_validate_base_port(const uint8_t *daily_key, size_t key_len,
                                  uint32_t current_bucket,
                                  uint8_t delay_windows,
                                  uint16_t received_port) {
    if (!daily_key || key_len == 0) {
        return false;
    }

    // Calculate port window
    buckwild_port_window_t window;
    int result = buckwild_calculate_port_window(&window, current_bucket, delay_windows);
    if (result != 0) {
        return false;
    }

    // Check if received port matches any bucket in the window
    for (uint32_t bucket = window.bucket_start; bucket <= window.bucket_end; bucket++) {
        uint16_t expected_port = buckwild_derive_base_port(daily_key, key_len, bucket);

        if (expected_port == received_port) {
            return true;  // Match found
        }
    }

    return false;  // No match in window
}

bool buckwild_validate_session_port(const uint8_t *session_key, size_t key_len,
                                     uint32_t current_bucket,
                                     uint8_t delay_windows,
                                     uint16_t received_port) {
    if (!session_key || key_len == 0) {
        return false;
    }

    // Calculate port window
    buckwild_port_window_t window;
    int result = buckwild_calculate_port_window(&window, current_bucket, delay_windows);
    if (result != 0) {
        return false;
    }

    // Check if received port matches any bucket in the window
    for (uint32_t bucket = window.bucket_start; bucket <= window.bucket_end; bucket++) {
        uint16_t expected_port = buckwild_derive_session_port(session_key, key_len, bucket);

        if (expected_port == received_port) {
            return true;  // Match found
        }
    }

    return false;  // No match in window
}
