/**
 * @file time_utils.c
 * @brief Implementation of time utility functions
 *
 * Implements time bucket calculation, timestamp conversion, and epoch handling
 * for the Buckwild frequency hopping protocol.
 */

#include "buckwild/common/time_utils.h"
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// ============================================================================
// Time Bucket Calculation
// ============================================================================

uint32_t buckwild_calculate_time_bucket(uint64_t timestamp_ns) {
    // Calculate milliseconds since epoch
    uint64_t ms_since_epoch = timestamp_ns / BUCKWILD_NS_PER_MS;

    // Calculate milliseconds since midnight (UTC)
    uint64_t ms_per_day = BUCKWILD_SEC_PER_DAY * 1000ULL;
    uint64_t ms_since_midnight = ms_since_epoch % ms_per_day;

    // Calculate bucket number (500ms intervals)
    uint32_t bucket = (uint32_t)(ms_since_midnight / BUCKWILD_TIME_BUCKET_INTERVAL_MS);

    return bucket;
}

uint64_t buckwild_get_current_time_ns(void) {
    struct timespec ts;

    // CRITICAL: Use CLOCK_REALTIME for port hopping synchronization
    // Port hopping calculations MUST use wall-clock time (CLOCK_REALTIME)
    // to ensure peers calculate identical port sequences. CLOCK_MONOTONIC
    // varies between machines and would cause port synchronization failures.
    // Requires NTP synchronization for peer agreement within 50ms tolerance.
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        // If REALTIME fails (should never happen), return 0 to trigger error
        return 0;
    }

    // Convert to nanoseconds
    uint64_t ns = (uint64_t)ts.tv_sec * BUCKWILD_NS_PER_SEC;
    ns += (uint64_t)ts.tv_nsec;

    return ns;
}

uint32_t buckwild_get_current_time_bucket(void) {
    uint64_t current_time = buckwild_get_current_time_ns();
    return buckwild_calculate_time_bucket(current_time);
}

// ============================================================================
// Timestamp Conversion (Variable Length Formats)
// ============================================================================

uint16_t buckwild_timestamp_to_16bit(uint64_t timestamp_ns) {
    // Calculate ABSOLUTE bucket number (not midnight-relative)
    // For timestamp formats, we count buckets since epoch
    uint64_t ms_since_epoch = timestamp_ns / BUCKWILD_NS_PER_MS;
    uint64_t bucket = ms_since_epoch / BUCKWILD_TIME_BUCKET_INTERVAL_MS;

    // Wrap to 16-bit range (0-65535)
    return (uint16_t)(bucket & 0xFFFF);
}

uint32_t buckwild_timestamp_to_24bit(uint64_t timestamp_ns) {
    // Calculate ABSOLUTE bucket number (not midnight-relative)
    uint64_t ms_since_epoch = timestamp_ns / BUCKWILD_NS_PER_MS;
    uint64_t bucket = ms_since_epoch / BUCKWILD_TIME_BUCKET_INTERVAL_MS;

    // Wrap to 24-bit range (0-16777215)
    return (uint32_t)(bucket & 0xFFFFFF);
}

uint32_t buckwild_timestamp_to_32bit(uint64_t timestamp_ns) {
    // Calculate ABSOLUTE bucket number (not midnight-relative)
    uint64_t ms_since_epoch = timestamp_ns / BUCKWILD_NS_PER_MS;
    uint64_t bucket = ms_since_epoch / BUCKWILD_TIME_BUCKET_INTERVAL_MS;

    // 32-bit can hold full bucket value
    return (uint32_t)bucket;
}

// ============================================================================
// Timestamp Validation
// ============================================================================

bool buckwild_validate_timestamp(uint32_t current_bucket, uint32_t received_bucket) {
    // 50ms tolerance with 500ms buckets
    // Edge case: if we're at 499ms into current bucket and packet is at 1ms into next bucket,
    // that's only 2ms difference but crosses bucket boundary
    // Therefore, allow ±1 bucket difference to accommodate 50ms tolerance at bucket edges

    int32_t diff = (int32_t)received_bucket - (int32_t)current_bucket;

    // Accept same bucket or adjacent buckets (±1)
    // This ensures 50ms tolerance is always satisfied
    return (diff >= -1 && diff <= 1);
}

// ============================================================================
// Timestamp Distance Calculation (Wraparound Handling)
// ============================================================================

int buckwild_calculate_timestamp_distance_16bit(uint16_t timestamp1, uint16_t timestamp2) {
    // Calculate forward and backward distances
    int32_t forward_distance = (int32_t)timestamp2 - (int32_t)timestamp1;

    // Handle wraparound
    if (forward_distance < 0) {
        forward_distance += 65536;
    }

    // If forward distance > half range, backward distance is shorter
    if (forward_distance > 32768) {
        return forward_distance - 65536;
    }

    return forward_distance;
}

int buckwild_calculate_timestamp_distance_24bit(uint32_t timestamp1, uint32_t timestamp2) {
    // Mask to 24-bit
    timestamp1 &= 0xFFFFFF;
    timestamp2 &= 0xFFFFFF;

    // Calculate forward and backward distances
    int32_t forward_distance = (int32_t)timestamp2 - (int32_t)timestamp1;

    // Handle wraparound
    const int32_t max_24bit = 0x1000000; // 16777216
    const int32_t half_range = 0x800000; // 8388608

    if (forward_distance < 0) {
        forward_distance += max_24bit;
    }

    // If forward distance > half range, backward distance is shorter
    if (forward_distance > half_range) {
        return forward_distance - max_24bit;
    }

    return forward_distance;
}

// ============================================================================
// Epoch Handling (Daily vs Monthly)
// ============================================================================

uint32_t buckwild_calculate_daily_epoch_bucket(uint64_t timestamp_ns) {
    // Daily epoch: buckets since UTC midnight
    // This is the same as the base time bucket calculation
    return buckwild_calculate_time_bucket(timestamp_ns);
}

uint32_t buckwild_calculate_monthly_epoch_bucket(uint64_t timestamp_ns) {
    // Monthly epoch: buckets since month start (simplified: 30-day month)
    uint64_t ms_since_epoch = timestamp_ns / BUCKWILD_NS_PER_MS;

    // Calculate milliseconds since month start
    uint64_t ms_per_month = BUCKWILD_SEC_PER_MONTH * 1000ULL;
    uint64_t ms_since_month_start = ms_since_epoch % ms_per_month;

    // Calculate bucket number (500ms intervals)
    uint32_t bucket = (uint32_t)(ms_since_month_start / BUCKWILD_TIME_BUCKET_INTERVAL_MS);

    return bucket;
}
