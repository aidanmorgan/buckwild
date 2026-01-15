/**
 * @file test_time_utils.c
 * @brief Unit tests for time utility functions (TDD - Tests First)
 *
 * Protocol Requirements:
 * - Time buckets: 500ms intervals since UTC midnight
 * - Dual epoch system: Daily (base ports), Monthly (session packets)
 * - Timestamp formats: 16-bit, 24-bit, 32-bit
 * - Wraparound handling for all formats
 * - Time synchronization: 50ms tolerance
 */

#include "unity.h"
#include "buckwild/common/time_utils.h"
#include <time.h>
#include <stdint.h>

// Test fixtures
void setUp(void) {
    // Reset any global state before each test
}

void tearDown(void) {
    // Clean up after each test
}

// ============================================================================
// Test Group 1: Time Bucket Calculation (500ms intervals)
// ============================================================================

/**
 * Test: Time bucket calculation produces deterministic results
 * Requirement: Same timestamp must always produce same bucket
 */
void test_time_bucket_deterministic(void) {
    // UTC midnight (00:00:00.000)
    uint64_t midnight_ns = 0;

    // Calculate bucket multiple times
    uint32_t bucket1 = buckwild_calculate_time_bucket(midnight_ns);
    uint32_t bucket2 = buckwild_calculate_time_bucket(midnight_ns);
    uint32_t bucket3 = buckwild_calculate_time_bucket(midnight_ns);

    // All should be identical
    TEST_ASSERT_EQUAL_UINT32(bucket1, bucket2);
    TEST_ASSERT_EQUAL_UINT32(bucket2, bucket3);
    TEST_ASSERT_EQUAL_UINT32(0, bucket1); // Midnight = bucket 0
}

/**
 * Test: Time bucket increments every 500ms
 * Requirement: Buckets change every 500 milliseconds
 */
void test_time_bucket_500ms_intervals(void) {
    uint64_t ns_per_ms = 1000000ULL;
    uint64_t base_time = 5000 * ns_per_ms; // 5 seconds after midnight

    // Bucket at exactly 5.000s
    uint32_t bucket_0ms = buckwild_calculate_time_bucket(base_time);

    // Bucket at 5.499s (same bucket)
    uint32_t bucket_499ms = buckwild_calculate_time_bucket(base_time + 499 * ns_per_ms);

    // Bucket at 5.500s (next bucket)
    uint32_t bucket_500ms = buckwild_calculate_time_bucket(base_time + 500 * ns_per_ms);

    // Bucket at 5.999s (still same as 5.500s)
    uint32_t bucket_999ms = buckwild_calculate_time_bucket(base_time + 999 * ns_per_ms);

    // Bucket at 6.000s (next bucket)
    uint32_t bucket_1000ms = buckwild_calculate_time_bucket(base_time + 1000 * ns_per_ms);

    TEST_ASSERT_EQUAL_UINT32(bucket_0ms, bucket_499ms);
    TEST_ASSERT_EQUAL_UINT32(bucket_0ms + 1, bucket_500ms);
    TEST_ASSERT_EQUAL_UINT32(bucket_500ms, bucket_999ms);
    TEST_ASSERT_EQUAL_UINT32(bucket_0ms + 2, bucket_1000ms);
}

/**
 * Test: Time bucket resets at UTC midnight
 * Requirement: Daily epoch starts at 00:00:00.000 UTC
 */
void test_time_bucket_midnight_reset(void) {
    uint64_t ns_per_sec = 1000000000ULL;
    uint64_t ns_per_day = 86400ULL * ns_per_sec; // 24 * 60 * 60

    // Last bucket of the day (23:59:59.500 - 23:59:59.999)
    uint64_t last_bucket_time = ns_per_day - (500 * 1000000ULL);
    uint32_t last_bucket = buckwild_calculate_time_bucket(last_bucket_time);

    // First bucket of next day (00:00:00.000)
    uint64_t first_bucket_time = ns_per_day;
    uint32_t first_bucket = buckwild_calculate_time_bucket(first_bucket_time);

    // First bucket should wrap to 0
    TEST_ASSERT_EQUAL_UINT32(0, first_bucket);

    // Last bucket should be maximum for the day
    uint32_t buckets_per_day = (86400 * 1000) / 500; // 172,800 buckets
    TEST_ASSERT_EQUAL_UINT32(buckets_per_day - 1, last_bucket);
}

/**
 * Test: Time bucket calculation for known values
 * Requirement: Verify correct bucket for specific times
 */
void test_time_bucket_known_values(void) {
    uint64_t ns_per_sec = 1000000000ULL;

    // 00:00:00.000 UTC = bucket 0
    TEST_ASSERT_EQUAL_UINT32(0, buckwild_calculate_time_bucket(0));

    // 00:00:00.500 UTC = bucket 1
    TEST_ASSERT_EQUAL_UINT32(1, buckwild_calculate_time_bucket(500 * 1000000ULL));

    // 00:00:01.000 UTC = bucket 2
    TEST_ASSERT_EQUAL_UINT32(2, buckwild_calculate_time_bucket(1 * ns_per_sec));

    // 00:01:00.000 UTC = bucket 120 (60 seconds * 2)
    TEST_ASSERT_EQUAL_UINT32(120, buckwild_calculate_time_bucket(60 * ns_per_sec));

    // 01:00:00.000 UTC = bucket 7200 (3600 seconds * 2)
    TEST_ASSERT_EQUAL_UINT32(7200, buckwild_calculate_time_bucket(3600 * ns_per_sec));
}

// ============================================================================
// Test Group 2: Timestamp Conversion (Variable Length)
// ============================================================================

/**
 * Test: Convert nanoseconds to 16-bit timestamp
 * Requirement: Support 16-bit timestamp format (0-65535 buckets)
 */
void test_timestamp_to_16bit(void) {
    uint64_t ns_per_sec = 1000000000ULL;

    // Bucket 0
    uint16_t ts1 = buckwild_timestamp_to_16bit(0);
    TEST_ASSERT_EQUAL_UINT16(0, ts1);

    // Bucket 100
    uint16_t ts2 = buckwild_timestamp_to_16bit(50 * ns_per_sec);
    TEST_ASSERT_EQUAL_UINT16(100, ts2);

    // Bucket 65535 (max 16-bit)
    uint16_t ts3 = buckwild_timestamp_to_16bit(32767500ULL * 1000000ULL);
    TEST_ASSERT_EQUAL_UINT16(65535, ts3);

    // Wraparound: Bucket 65536 wraps to 0
    uint16_t ts4 = buckwild_timestamp_to_16bit(32768000ULL * 1000000ULL);
    TEST_ASSERT_EQUAL_UINT16(0, ts4);
}

/**
 * Test: Convert nanoseconds to 24-bit timestamp
 * Requirement: Support 24-bit timestamp format (0-16777215 buckets)
 */
void test_timestamp_to_24bit(void) {
    uint64_t ns_per_sec = 1000000000ULL;

    // Bucket 0
    uint32_t ts1 = buckwild_timestamp_to_24bit(0);
    TEST_ASSERT_EQUAL_UINT32(0, ts1);

    // Bucket 1000
    uint32_t ts2 = buckwild_timestamp_to_24bit(500 * ns_per_sec);
    TEST_ASSERT_EQUAL_UINT32(1000, ts2);

    // Bucket 16777215 (max 24-bit: 0xFFFFFF)
    uint32_t ts3 = buckwild_timestamp_to_24bit(8388607500ULL * 1000000ULL);
    TEST_ASSERT_EQUAL_UINT32(0xFFFFFF, ts3);

    // Wraparound: Bucket 16777216 wraps to 0
    uint32_t ts4 = buckwild_timestamp_to_24bit(8388608000ULL * 1000000ULL);
    TEST_ASSERT_EQUAL_UINT32(0, ts4);
}

/**
 * Test: Convert nanoseconds to 32-bit timestamp
 * Requirement: Support 32-bit timestamp format (0-4294967295 buckets)
 */
void test_timestamp_to_32bit(void) {
    uint64_t ns_per_sec = 1000000000ULL;

    // Bucket 0
    uint32_t ts1 = buckwild_timestamp_to_32bit(0);
    TEST_ASSERT_EQUAL_UINT32(0, ts1);

    // Bucket 10000
    uint32_t ts2 = buckwild_timestamp_to_32bit(5000 * ns_per_sec);
    TEST_ASSERT_EQUAL_UINT32(10000, ts2);

    // Large bucket value
    uint32_t ts3 = buckwild_timestamp_to_32bit(1000000000ULL * ns_per_sec);
    TEST_ASSERT_EQUAL_UINT32(2000000000UL, ts3);
}

// ============================================================================
// Test Group 3: Timestamp Validation (50ms tolerance)
// ============================================================================

/**
 * Test: Validate timestamp within tolerance
 * Requirement: Accept timestamps within 50ms (TIME_SYNC_TOLERANCE_MS)
 */
void test_timestamp_validation_within_tolerance(void) {
    uint64_t ns_per_ms = 1000000ULL;
    uint64_t current_time = 1000000 * ns_per_ms; // Arbitrary base time
    uint32_t current_bucket = buckwild_calculate_time_bucket(current_time);

    // Exact match
    TEST_ASSERT_TRUE(buckwild_validate_timestamp(current_bucket, current_bucket));

    // Within 50ms tolerance (0 buckets difference at 500ms granularity)
    uint32_t bucket_plus_25ms = buckwild_calculate_time_bucket(current_time + 25 * ns_per_ms);
    TEST_ASSERT_TRUE(buckwild_validate_timestamp(current_bucket, bucket_plus_25ms));

    uint32_t bucket_minus_25ms = buckwild_calculate_time_bucket(current_time - 25 * ns_per_ms);
    TEST_ASSERT_TRUE(buckwild_validate_timestamp(current_bucket, bucket_minus_25ms));
}

/**
 * Test: Reject timestamp outside tolerance
 * Requirement: Reject timestamps more than 1 bucket away (> ±500ms)
 */
void test_timestamp_validation_outside_tolerance(void) {
    uint64_t ns_per_ms = 1000000ULL;
    uint64_t current_time = 1000000 * ns_per_ms;
    uint32_t current_bucket = buckwild_calculate_time_bucket(current_time);

    // Too far in future (1000ms = 2 buckets away)
    uint32_t bucket_plus_1000ms = buckwild_calculate_time_bucket(current_time + 1000 * ns_per_ms);
    TEST_ASSERT_FALSE(buckwild_validate_timestamp(current_bucket, bucket_plus_1000ms));

    // Too far in past (1000ms = 2 buckets away)
    uint32_t bucket_minus_1000ms = buckwild_calculate_time_bucket(current_time - 1000 * ns_per_ms);
    TEST_ASSERT_FALSE(buckwild_validate_timestamp(current_bucket, bucket_minus_1000ms));
}

// ============================================================================
// Test Group 4: Epoch Handling (Daily vs Monthly)
// ============================================================================

/**
 * Test: Calculate daily epoch bucket
 * Requirement: Daily epoch resets at UTC midnight
 */
void test_daily_epoch_calculation(void) {
    uint64_t ns_per_sec = 1000000000ULL;
    uint64_t ns_per_day = 86400ULL * ns_per_sec;

    // Day 1: 00:01:00 UTC = bucket 120
    uint64_t day1_time = (1 * ns_per_day) + (60 * ns_per_sec);
    uint32_t day1_bucket = buckwild_calculate_daily_epoch_bucket(day1_time);
    TEST_ASSERT_EQUAL_UINT32(120, day1_bucket);

    // Day 2: 00:01:00 UTC = bucket 120 (same as day 1, epoch reset)
    uint64_t day2_time = (2 * ns_per_day) + (60 * ns_per_sec);
    uint32_t day2_bucket = buckwild_calculate_daily_epoch_bucket(day2_time);
    TEST_ASSERT_EQUAL_UINT32(120, day2_bucket);

    // Buckets should be equal (daily reset)
    TEST_ASSERT_EQUAL_UINT32(day1_bucket, day2_bucket);
}

/**
 * Test: Calculate monthly epoch bucket
 * Requirement: Monthly epoch resets at month start (simplified: 30 days)
 */
void test_monthly_epoch_calculation(void) {
    uint64_t ns_per_sec = 1000000000ULL;
    uint64_t ns_per_month = 2592000ULL * ns_per_sec; // 30 days

    // Month 1: Day 5, 00:00:00 UTC
    uint64_t month1_time = (5 * 86400ULL * ns_per_sec);
    uint32_t month1_bucket = buckwild_calculate_monthly_epoch_bucket(month1_time);

    // Month 2: Day 5 of month 2
    uint64_t month2_time = ns_per_month + (5 * 86400ULL * ns_per_sec);
    uint32_t month2_bucket = buckwild_calculate_monthly_epoch_bucket(month2_time);

    // Buckets should be equal (monthly reset)
    TEST_ASSERT_EQUAL_UINT32(month1_bucket, month2_bucket);
}

// ============================================================================
// Test Group 5: Timestamp Wraparound Handling
// ============================================================================

/**
 * Test: Handle 16-bit timestamp wraparound correctly
 * Requirement: Detect wraparound and handle gracefully
 */
void test_16bit_wraparound_detection(void) {
    // Near wraparound: bucket 65534
    uint16_t near_max = 65534;

    // Wraparound: bucket 65536 -> 0
    uint16_t wrapped = 0;

    // Should detect as close (2 buckets apart, not 65534)
    int distance = buckwild_calculate_timestamp_distance_16bit(near_max, wrapped);
    TEST_ASSERT_EQUAL_INT(2, distance);

    // Reverse direction
    int distance_reverse = buckwild_calculate_timestamp_distance_16bit(wrapped, near_max);
    TEST_ASSERT_EQUAL_INT(-2, distance_reverse);
}

/**
 * Test: Handle 24-bit timestamp wraparound correctly
 * Requirement: Detect wraparound for 24-bit timestamps
 */
void test_24bit_wraparound_detection(void) {
    // Near wraparound: bucket 16777214 (0xFFFFFE)
    uint32_t near_max = 0xFFFFFE;

    // Wraparound: bucket 0
    uint32_t wrapped = 0;

    // Should detect as close (2 buckets apart)
    int distance = buckwild_calculate_timestamp_distance_24bit(near_max, wrapped);
    TEST_ASSERT_EQUAL_INT(2, distance);
}

// ============================================================================
// Test Group 6: Current Time Utilities
// ============================================================================

/**
 * Test: Get current time in nanoseconds
 * Requirement: Provide monotonic clock access
 */
void test_get_current_time_ns(void) {
    uint64_t time1 = buckwild_get_current_time_ns();

    // Small delay
    for (volatile int i = 0; i < 1000; i++);

    uint64_t time2 = buckwild_get_current_time_ns();

    // Time should advance (monotonic)
    TEST_ASSERT_GREATER_THAN(time1, time2);
}

/**
 * Test: Get current time bucket
 * Requirement: Convenience function for current bucket
 */
void test_get_current_time_bucket(void) {
    uint32_t bucket1 = buckwild_get_current_time_bucket();

    // Should be a valid bucket value
    TEST_ASSERT_LESS_THAN(172800, bucket1); // Max buckets per day

    // Multiple calls in quick succession should return same or adjacent bucket
    uint32_t bucket2 = buckwild_get_current_time_bucket();
    int difference = (int)bucket2 - (int)bucket1;
    TEST_ASSERT_TRUE(difference >= -1 && difference <= 1);
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // Time bucket calculation tests
    RUN_TEST(test_time_bucket_deterministic);
    RUN_TEST(test_time_bucket_500ms_intervals);
    RUN_TEST(test_time_bucket_midnight_reset);
    RUN_TEST(test_time_bucket_known_values);

    // Timestamp conversion tests
    RUN_TEST(test_timestamp_to_16bit);
    RUN_TEST(test_timestamp_to_24bit);
    RUN_TEST(test_timestamp_to_32bit);

    // Timestamp validation tests
    RUN_TEST(test_timestamp_validation_within_tolerance);
    RUN_TEST(test_timestamp_validation_outside_tolerance);

    // Epoch handling tests
    RUN_TEST(test_daily_epoch_calculation);
    RUN_TEST(test_monthly_epoch_calculation);

    // Wraparound handling tests
    RUN_TEST(test_16bit_wraparound_detection);
    RUN_TEST(test_24bit_wraparound_detection);

    // Current time utility tests
    RUN_TEST(test_get_current_time_ns);
    RUN_TEST(test_get_current_time_bucket);

    return UNITY_END();
}
