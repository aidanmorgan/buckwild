/**
 * @file port_hopping.h
 * @brief Port hopping calculation and validation
 *
 * Implements the frequency hopping protocol using time-based port transitions
 * with HMAC-SHA256 derivation. Supports both base port sequences (using daily
 * keys) and session-specific port sequences (using ECDH-derived keys).
 *
 * Port Hopping Algorithm:
 * 1. Calculate time bucket (500ms intervals since UTC midnight)
 * 2. Derive port using HMAC-SHA256(key, bucket_bytes)
 * 3. Map HMAC output to port range (1024-65535)
 * 4. Support adaptive delay windows (1-16 time buckets)
 *
 * Security Properties:
 * - Deterministic: Same key + bucket always produces same port
 * - Unpredictable: Without key, port sequence appears random
 * - Large space: 64,511 possible ports (1024-65535)
 * - Fast transitions: 500ms intervals
 */

#ifndef BUCKWILD_COMMON_PORT_HOPPING_H
#define BUCKWILD_COMMON_PORT_HOPPING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Port range constants
 */
#define BUCKWILD_PORT_MIN 1024   ///< Minimum port (avoid privileged ports)
#define BUCKWILD_PORT_MAX 65535  ///< Maximum port

/**
 * @brief Adaptive window limits
 */
#define BUCKWILD_MIN_DELAY_WINDOWS 1   ///< Minimum delay tolerance
#define BUCKWILD_MAX_DELAY_WINDOWS 16  ///< Maximum delay tolerance

/**
 * @brief Port window structure for adaptive delay tolerance
 *
 * Represents the range of time buckets within which ports are considered valid.
 * The window extends backwards from the current bucket to accommodate network
 * delays and clock skew.
 */
typedef struct {
    uint32_t bucket_start;   ///< Earliest valid bucket (inclusive)
    uint32_t bucket_end;     ///< Latest valid bucket (inclusive, usually current)
    uint8_t delay_windows;   ///< Number of time windows in tolerance
} buckwild_port_window_t;

// ============================================================================
// Port Derivation Functions
// ============================================================================

/**
 * @brief Derive base port for handshake/discovery
 *
 * Calculates the base port used for initial connection discovery. Base ports
 * use the daily key (derived from master secret + date) and change every 500ms.
 *
 * Algorithm:
 * 1. hmac = HMAC-SHA256(daily_key, bucket_as_u32_be)
 * 2. Extract 32-bit value from hmac
 * 3. Map to port range: port = (value % port_range) + BUCKWILD_PORT_MIN
 *
 * @param daily_key Daily derivation key
 * @param key_len Length of daily key (typically 32 bytes)
 * @param time_bucket Time bucket number (500ms intervals)
 * @return Port number (1024-65535), or 0 on error
 */
uint16_t buckwild_derive_base_port(const uint8_t *daily_key, size_t key_len,
                                    uint32_t time_bucket);

/**
 * @brief Derive session-specific port
 *
 * Calculates session-specific ports used after ECDH key exchange. Session ports
 * use the shared secret and change every 500ms, independent of base ports.
 *
 * Algorithm: Same as base port but with session key
 *
 * @param session_key Session-specific key (from ECDH)
 * @param key_len Length of session key (typically 32 bytes)
 * @param time_bucket Time bucket number (500ms intervals)
 * @return Port number (1024-65535), or 0 on error
 */
uint16_t buckwild_derive_session_port(const uint8_t *session_key, size_t key_len,
                                       uint32_t time_bucket);

// ============================================================================
// Adaptive Window Functions
// ============================================================================

/**
 * @brief Calculate port validation window for adaptive delay tolerance
 *
 * Computes the range of time buckets to accept based on the current bucket
 * and adaptive delay window setting. The window extends backwards to accommodate
 * network delays.
 *
 * Examples:
 * - delay_windows=1: Accept only current bucket
 * - delay_windows=4: Accept current and 3 past buckets
 * - delay_windows=16: Accept current and 15 past buckets
 *
 * @param window Output structure to populate
 * @param current_bucket Current time bucket
 * @param delay_windows Number of time windows to tolerate (1-16)
 * @return 0 on success, -EINVAL if parameters are invalid
 */
int buckwild_calculate_port_window(buckwild_port_window_t *window,
                                    uint32_t current_bucket,
                                    uint8_t delay_windows);

// ============================================================================
// Port Validation Functions
// ============================================================================

/**
 * @brief Validate base port against expected sequence
 *
 * Checks if a received port matches the expected base port sequence within
 * the adaptive delay window. Tests all buckets in the window until a match
 * is found or the window is exhausted.
 *
 * Process:
 * 1. Calculate port window (current - delay_windows to current)
 * 2. For each bucket in window:
 *    - Derive expected port
 *    - Compare with received port
 * 3. Return true if any match found
 *
 * @param daily_key Daily derivation key
 * @param key_len Length of daily key
 * @param current_bucket Current time bucket
 * @param delay_windows Adaptive delay tolerance (1-16)
 * @param received_port Port number to validate
 * @return true if port is valid, false otherwise
 */
bool buckwild_validate_base_port(const uint8_t *daily_key, size_t key_len,
                                  uint32_t current_bucket,
                                  uint8_t delay_windows,
                                  uint16_t received_port);

/**
 * @brief Validate session port against expected sequence
 *
 * Same as buckwild_validate_base_port() but for session-specific ports.
 *
 * @param session_key Session-specific key
 * @param key_len Length of session key
 * @param current_bucket Current time bucket
 * @param delay_windows Adaptive delay tolerance (1-16)
 * @param received_port Port number to validate
 * @return true if port is valid, false otherwise
 */
bool buckwild_validate_session_port(const uint8_t *session_key, size_t key_len,
                                     uint32_t current_bucket,
                                     uint8_t delay_windows,
                                     uint16_t received_port);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get expected port for specific bucket
 *
 * Convenience function to get the expected port for a specific time bucket
 * without full validation. Useful for debugging and logging.
 *
 * @param daily_key Daily or session key
 * @param key_len Length of key
 * @param time_bucket Specific time bucket
 * @return Expected port for that bucket
 */
static inline uint16_t buckwild_get_expected_port(const uint8_t *daily_key,
                                                   size_t key_len,
                                                   uint32_t time_bucket) {
    return buckwild_derive_base_port(daily_key, key_len, time_bucket);
}

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_COMMON_PORT_HOPPING_H
