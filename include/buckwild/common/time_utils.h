/**
 * @file time_utils.h
 * @brief Time utility functions for Buckwild protocol
 *
 * Provides time bucket calculation, timestamp conversion, and epoch handling
 * for the frequency hopping protocol.
 *
 * Protocol Requirements:
 * - Time buckets: 500ms intervals since UTC midnight
 * - Dual epoch system: Daily (base ports), Monthly (session packets)
 * - Timestamp formats: 16-bit, 24-bit, 32-bit with wraparound handling
 * - Time synchronization tolerance: 50ms
 */

#ifndef BUCKWILD_TIME_UTILS_H
#define BUCKWILD_TIME_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Time constants
#define BUCKWILD_TIME_BUCKET_INTERVAL_MS    500         // 500ms per bucket
#define BUCKWILD_TIME_SYNC_TOLERANCE_MS     50          // 50ms tolerance
#define BUCKWILD_NS_PER_MS                  1000000ULL  // Nanoseconds per millisecond
#define BUCKWILD_NS_PER_SEC                 1000000000ULL // Nanoseconds per second
#define BUCKWILD_SEC_PER_DAY                86400ULL    // Seconds per day (24 * 60 * 60)
#define BUCKWILD_SEC_PER_MONTH              2592000ULL  // Seconds per 30-day month
#define BUCKWILD_BUCKETS_PER_DAY            172800      // 86400 * 1000 / 500

// ============================================================================
// Time Bucket Calculation
// ============================================================================

/**
 * @brief Calculate time bucket (500ms interval) from nanosecond timestamp
 *
 * Time buckets are 500ms intervals since UTC midnight. This is the core
 * timing mechanism for port hopping.
 *
 * @param timestamp_ns Time in nanoseconds since some epoch
 * @return Time bucket number (500ms intervals since midnight)
 *
 * Example:
 *   00:00:00.000 UTC -> bucket 0
 *   00:00:00.500 UTC -> bucket 1
 *   00:00:01.000 UTC -> bucket 2
 */
uint32_t buckwild_calculate_time_bucket(uint64_t timestamp_ns);

/**
 * @brief Get current time in nanoseconds (monotonic clock)
 *
 * Returns monotonic time suitable for time bucket calculation.
 * Uses CLOCK_MONOTONIC to prevent time regression.
 *
 * @return Current time in nanoseconds
 */
uint64_t buckwild_get_current_time_ns(void);

/**
 * @brief Get current time bucket (convenience function)
 *
 * @return Current time bucket number
 */
uint32_t buckwild_get_current_time_bucket(void);

// ============================================================================
// Timestamp Conversion (Variable Length Formats)
// ============================================================================

/**
 * @brief Convert nanosecond timestamp to 16-bit format
 *
 * 16-bit timestamps can represent 0-65535 buckets (up to ~9.1 hours).
 * Wraps around at 65536.
 *
 * @param timestamp_ns Time in nanoseconds
 * @return 16-bit timestamp (bucket number % 65536)
 */
uint16_t buckwild_timestamp_to_16bit(uint64_t timestamp_ns);

/**
 * @brief Convert nanosecond timestamp to 24-bit format
 *
 * 24-bit timestamps can represent 0-16777215 buckets (up to ~97 days).
 * Wraps around at 16777216.
 *
 * @param timestamp_ns Time in nanoseconds
 * @return 24-bit timestamp (bucket number % 16777216)
 */
uint32_t buckwild_timestamp_to_24bit(uint64_t timestamp_ns);

/**
 * @brief Convert nanosecond timestamp to 32-bit format
 *
 * 32-bit timestamps can represent 0-4294967295 buckets (up to ~68 years).
 *
 * @param timestamp_ns Time in nanoseconds
 * @return 32-bit timestamp (bucket number)
 */
uint32_t buckwild_timestamp_to_32bit(uint64_t timestamp_ns);

// ============================================================================
// Timestamp Validation
// ============================================================================

/**
 * @brief Validate timestamp is within acceptable tolerance
 *
 * Checks if received_bucket is within acceptable range of current_bucket.
 * Allows for 50ms tolerance (same bucket or adjacent bucket).
 *
 * @param current_bucket Current time bucket
 * @param received_bucket Received timestamp bucket
 * @return true if valid, false if outside tolerance
 */
bool buckwild_validate_timestamp(uint32_t current_bucket, uint32_t received_bucket);

/**
 * @brief Calculate distance between two 16-bit timestamps (with wraparound)
 *
 * Returns signed distance from timestamp1 to timestamp2, accounting for
 * wraparound at 65536. Positive means timestamp2 is ahead, negative means behind.
 *
 * @param timestamp1 First timestamp
 * @param timestamp2 Second timestamp
 * @return Distance in buckets (-32768 to +32767)
 */
int buckwild_calculate_timestamp_distance_16bit(uint16_t timestamp1, uint16_t timestamp2);

/**
 * @brief Calculate distance between two 24-bit timestamps (with wraparound)
 *
 * Returns signed distance accounting for wraparound at 16777216.
 *
 * @param timestamp1 First timestamp (24-bit value)
 * @param timestamp2 Second timestamp (24-bit value)
 * @return Distance in buckets
 */
int buckwild_calculate_timestamp_distance_24bit(uint32_t timestamp1, uint32_t timestamp2);

// ============================================================================
// Epoch Handling (Daily vs Monthly)
// ============================================================================

/**
 * @brief Calculate time bucket within daily epoch
 *
 * Daily epoch resets at UTC midnight (00:00:00.000).
 * Used for base port calculations.
 *
 * @param timestamp_ns Time in nanoseconds
 * @return Bucket number within current day (0-172799)
 */
uint32_t buckwild_calculate_daily_epoch_bucket(uint64_t timestamp_ns);

/**
 * @brief Calculate time bucket within monthly epoch
 *
 * Monthly epoch resets at month start (simplified: every 30 days).
 * Used for session-specific port calculations.
 *
 * @param timestamp_ns Time in nanoseconds
 * @return Bucket number within current month
 */
uint32_t buckwild_calculate_monthly_epoch_bucket(uint64_t timestamp_ns);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_TIME_UTILS_H
