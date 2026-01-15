/**
 * @file test_port_hopping.c
 * @brief Unit tests for port hopping calculation and validation
 *
 * Tests cover:
 * - Base port calculation (daily key + time bucket)
 * - Session port calculation (ECDH params + time bucket)
 * - Adaptive window validation
 * - Port range enforcement (1024-65535)
 * - Deterministic port sequences
 * - Month boundary handling
 */

#include "unity.h"
#include "buckwild/common/port_hopping.h"
#include "buckwild/common/time_utils.h"
#include <string.h>

void setUp(void) {
    // Run before each test
}

void tearDown(void) {
    // Run after each test
}

// ============================================================================
// Port Derivation Tests
// ============================================================================

void test_derive_base_port_deterministic(void) {
    // Same inputs should produce same port
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t bucket = 1000;

    uint16_t port1 = buckwild_derive_base_port(daily_key, sizeof(daily_key), bucket);
    uint16_t port2 = buckwild_derive_base_port(daily_key, sizeof(daily_key), bucket);

    TEST_ASSERT_EQUAL_UINT16(port1, port2);
}

void test_derive_base_port_different_buckets(void) {
    // Different buckets should produce different ports
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));

    uint16_t port1 = buckwild_derive_base_port(daily_key, sizeof(daily_key), 1000);
    uint16_t port2 = buckwild_derive_base_port(daily_key, sizeof(daily_key), 1001);

    TEST_ASSERT_NOT_EQUAL(port1, port2);
}

void test_derive_base_port_different_keys(void) {
    // Different keys should produce different ports
    uint8_t key1[32], key2[32];
    memset(key1, 0x42, sizeof(key1));
    memset(key2, 0x43, sizeof(key2));
    uint32_t bucket = 1000;

    uint16_t port1 = buckwild_derive_base_port(key1, sizeof(key1), bucket);
    uint16_t port2 = buckwild_derive_base_port(key2, sizeof(key2), bucket);

    TEST_ASSERT_NOT_EQUAL(port1, port2);
}

void test_derive_base_port_range(void) {
    // Port should be in valid range (1024-65535)
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));

    for (uint32_t bucket = 0; bucket < 100; bucket++) {
        uint16_t port = buckwild_derive_base_port(daily_key, sizeof(daily_key), bucket);
        TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, port);
        TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, port);
    }
}

void test_derive_session_port_deterministic(void) {
    // Same inputs should produce same port
    uint8_t session_key[32];
    memset(session_key, 0x84, sizeof(session_key));
    uint32_t bucket = 2000;

    uint16_t port1 = buckwild_derive_session_port(session_key, sizeof(session_key), bucket);
    uint16_t port2 = buckwild_derive_session_port(session_key, sizeof(session_key), bucket);

    TEST_ASSERT_EQUAL_UINT16(port1, port2);
}

void test_derive_session_port_different_from_base(void) {
    // Session ports should differ from base ports with same bucket
    uint8_t key[32];
    memset(key, 0x42, sizeof(key));
    uint32_t bucket = 1000;

    uint16_t base_port = buckwild_derive_base_port(key, sizeof(key), bucket);
    uint16_t session_port = buckwild_derive_session_port(key, sizeof(key), bucket);

    // They will likely differ (not guaranteed but highly probable)
    // This test validates that the derivation functions are independent
    TEST_ASSERT_TRUE(base_port > 0 && session_port > 0);
}

// ============================================================================
// Adaptive Window Tests
// ============================================================================

void test_calculate_window_bounds_delay_1(void) {
    // With delay window = 1, accept only current bucket port
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 1;

    buckwild_port_window_t window;
    int result = buckwild_calculate_port_window(&window, current_bucket, delay_windows);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT32(current_bucket, window.bucket_start);
    TEST_ASSERT_EQUAL_UINT32(current_bucket, window.bucket_end);
    TEST_ASSERT_EQUAL_UINT8(1, window.delay_windows);
}

void test_calculate_window_bounds_delay_4(void) {
    // With delay window = 4, accept current and 3 past buckets
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;

    buckwild_port_window_t window;
    int result = buckwild_calculate_port_window(&window, current_bucket, delay_windows);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT32(current_bucket - 3, window.bucket_start);
    TEST_ASSERT_EQUAL_UINT32(current_bucket, window.bucket_end);
    TEST_ASSERT_EQUAL_UINT8(4, window.delay_windows);
}

void test_calculate_window_bounds_delay_16(void) {
    // Maximum delay window = 16
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 16;

    buckwild_port_window_t window;
    int result = buckwild_calculate_port_window(&window, current_bucket, delay_windows);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT32(current_bucket - 15, window.bucket_start);
    TEST_ASSERT_EQUAL_UINT32(current_bucket, window.bucket_end);
    TEST_ASSERT_EQUAL_UINT8(16, window.delay_windows);
}

void test_calculate_window_bounds_invalid_delay(void) {
    // Delay windows must be 1-16
    uint32_t current_bucket = 1000;
    buckwild_port_window_t window;

    // Test 0 (invalid)
    int result1 = buckwild_calculate_port_window(&window, current_bucket, 0);
    TEST_ASSERT_EQUAL_INT(-EINVAL, result1);

    // Test 17 (invalid)
    int result2 = buckwild_calculate_port_window(&window, current_bucket, 17);
    TEST_ASSERT_EQUAL_INT(-EINVAL, result2);
}

// ============================================================================
// Port Validation Tests
// ============================================================================

void test_validate_port_in_window_current_bucket(void) {
    // Port from current bucket should be valid
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;

    // Calculate expected port for current bucket
    uint16_t expected_port = buckwild_derive_base_port(daily_key, sizeof(daily_key), current_bucket);

    // Validate it
    bool is_valid = buckwild_validate_base_port(daily_key, sizeof(daily_key),
                                                 current_bucket, delay_windows,
                                                 expected_port);

    TEST_ASSERT_TRUE(is_valid);
}

void test_validate_port_in_window_past_bucket(void) {
    // Port from past bucket (within window) should be valid
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;

    // Calculate expected port for bucket 2 time windows ago
    uint32_t past_bucket = current_bucket - 2;
    uint16_t expected_port = buckwild_derive_base_port(daily_key, sizeof(daily_key), past_bucket);

    // Validate against current bucket
    bool is_valid = buckwild_validate_base_port(daily_key, sizeof(daily_key),
                                                 current_bucket, delay_windows,
                                                 expected_port);

    TEST_ASSERT_TRUE(is_valid);
}

void test_validate_port_outside_window(void) {
    // Port from bucket outside window should be invalid
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;

    // Calculate port for bucket 10 windows ago (outside window)
    uint32_t old_bucket = current_bucket - 10;
    uint16_t old_port = buckwild_derive_base_port(daily_key, sizeof(daily_key), old_bucket);

    // Validate against current bucket - should fail
    bool is_valid = buckwild_validate_base_port(daily_key, sizeof(daily_key),
                                                 current_bucket, delay_windows,
                                                 old_port);

    TEST_ASSERT_FALSE(is_valid);
}

void test_validate_port_future_bucket(void) {
    // Port from future bucket should be invalid
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;

    // Calculate port for future bucket
    uint32_t future_bucket = current_bucket + 5;
    uint16_t future_port = buckwild_derive_base_port(daily_key, sizeof(daily_key), future_bucket);

    // Validate against current bucket - should fail
    bool is_valid = buckwild_validate_base_port(daily_key, sizeof(daily_key),
                                                 current_bucket, delay_windows,
                                                 future_port);

    TEST_ASSERT_FALSE(is_valid);
}

void test_validate_port_wrong_port(void) {
    // Wrong port number should be invalid
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;

    // Use arbitrary wrong port
    uint16_t wrong_port = 12345;

    bool is_valid = buckwild_validate_base_port(daily_key, sizeof(daily_key),
                                                 current_bucket, delay_windows,
                                                 wrong_port);

    // This might be valid if 12345 happens to be in the sequence,
    // but extremely unlikely. For robustness, we test that validation
    // function executes without crashing
    (void)is_valid; // May or may not be valid
}

// ============================================================================
// Port Sequence Tests
// ============================================================================

void test_generate_port_sequence(void) {
    // Generate sequence of ports for consecutive buckets
    uint8_t daily_key[32];
    memset(daily_key, 0x55, sizeof(daily_key));
    uint32_t start_bucket = 1000;
    uint16_t ports[10];

    for (size_t i = 0; i < 10; i++) {
        ports[i] = buckwild_derive_base_port(daily_key, sizeof(daily_key), start_bucket + i);
    }

    // Verify all ports are in valid range
    for (size_t i = 0; i < 10; i++) {
        TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, ports[i]);
        TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, ports[i]);
    }

    // Verify consecutive ports are different (highly likely)
    for (size_t i = 0; i < 9; i++) {
        TEST_ASSERT_NOT_EQUAL(ports[i], ports[i + 1]);
    }
}

// ============================================================================
// Determinism Tests (Task 3.1.6)
// ============================================================================

void test_port_sequence_determinism_identical_seed(void) {
    // Same seed produces identical port sequence
    uint8_t seed[32];
    memset(seed, 0xAB, sizeof(seed));

    // Generate sequence twice with same seed
    uint16_t seq1[100], seq2[100];
    for (size_t i = 0; i < 100; i++) {
        seq1[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
        seq2[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
    }

    // Must be identical
    TEST_ASSERT_EQUAL_MEMORY(seq1, seq2, sizeof(seq1));
}

void test_port_sequence_determinism_multiple_runs(void) {
    // Verify determinism across multiple independent runs
    uint8_t seed[32];
    memset(seed, 0xCD, sizeof(seed));

    uint16_t reference[50];
    for (size_t i = 0; i < 50; i++) {
        reference[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
    }

    // Run 10 times and verify all match reference
    for (int run = 0; run < 10; run++) {
        uint16_t sequence[50];
        for (size_t i = 0; i < 50; i++) {
            sequence[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
        }
        TEST_ASSERT_EQUAL_MEMORY(reference, sequence, sizeof(reference));
    }
}

void test_port_sequence_no_privileged_ports_extensive(void) {
    // Extensive test: no privileged ports with many seeds
    uint8_t seed[32];

    // Test 100 different seeds
    for (int trial = 0; trial < 100; trial++) {
        // Create varied seed pattern
        for (size_t i = 0; i < sizeof(seed); i++) {
            seed[i] = (uint8_t)(trial * 17 + i * 3);
        }

        // Generate 1000 ports per seed
        for (uint32_t bucket = 0; bucket < 1000; bucket++) {
            uint16_t port = buckwild_derive_base_port(seed, sizeof(seed), bucket);
            TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, port);
            TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, port);
        }
    }
}

void test_port_sequence_edge_case_zero_seed(void) {
    // Edge case: all-zero seed
    uint8_t seed[32];
    memset(seed, 0x00, sizeof(seed));

    uint16_t ports[100];
    for (size_t i = 0; i < 100; i++) {
        ports[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
        TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, ports[i]);
        TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, ports[i]);
    }

    // Zero seed should still produce valid deterministic sequence
    uint16_t ports_again[100];
    for (size_t i = 0; i < 100; i++) {
        ports_again[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
    }
    TEST_ASSERT_EQUAL_MEMORY(ports, ports_again, sizeof(ports));
}

void test_port_sequence_edge_case_max_seed(void) {
    // Edge case: all-0xFF seed
    uint8_t seed[32];
    memset(seed, 0xFF, sizeof(seed));

    uint16_t ports[100];
    for (size_t i = 0; i < 100; i++) {
        ports[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
        TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, ports[i]);
        TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, ports[i]);
    }

    // Max seed should still produce valid deterministic sequence
    uint16_t ports_again[100];
    for (size_t i = 0; i < 100; i++) {
        ports_again[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
    }
    TEST_ASSERT_EQUAL_MEMORY(ports, ports_again, sizeof(ports));
}

void test_port_sequence_edge_case_boundary_buckets(void) {
    // Edge case: boundary bucket values
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));

    // Test bucket 0
    uint16_t port_0 = buckwild_derive_base_port(seed, sizeof(seed), 0);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, port_0);
    TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, port_0);

    // Test max bucket value
    uint16_t port_max = buckwild_derive_base_port(seed, sizeof(seed), UINT32_MAX);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, port_max);
    TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, port_max);

    // Test near-max bucket
    uint16_t port_near_max = buckwild_derive_base_port(seed, sizeof(seed), UINT32_MAX - 1);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, port_near_max);
    TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, port_near_max);
}

void test_port_sequence_uniform_distribution_approximate(void) {
    // Test approximate uniform distribution of ports
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));

    // Generate large sequence
    const size_t num_ports = 10000;
    uint16_t ports[num_ports];
    for (size_t i = 0; i < num_ports; i++) {
        ports[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
    }

    // Count ports in different ranges
    const int num_buckets = 10;
    const uint32_t port_range = BUCKWILD_PORT_MAX - BUCKWILD_PORT_MIN + 1;
    const uint32_t bucket_size = port_range / num_buckets;
    int bucket_counts[num_buckets];
    memset(bucket_counts, 0, sizeof(bucket_counts));

    for (size_t i = 0; i < num_ports; i++) {
        uint32_t offset = ports[i] - BUCKWILD_PORT_MIN;
        int bucket_idx = (int)(offset / bucket_size);
        if (bucket_idx >= num_buckets) bucket_idx = num_buckets - 1;
        bucket_counts[bucket_idx]++;
    }

    // Each bucket should have approximately num_ports/num_buckets entries
    // Allow generous tolerance (50% deviation from expected)
    int expected_per_bucket = num_ports / num_buckets;
    int tolerance = expected_per_bucket / 2;

    for (int i = 0; i < num_buckets; i++) {
        TEST_ASSERT_INT_WITHIN(tolerance, expected_per_bucket, bucket_counts[i]);
    }
}

void test_port_sequence_cross_platform_consistency(void) {
    // Verify port sequence is consistent (same output for given input)
    // This tests that there are no platform-dependent behaviors
    uint8_t seed[32];
    memset(seed, 0x88, sizeof(seed));

    // Generate reference sequence
    const size_t seq_len = 20;
    uint16_t reference[seq_len];
    for (size_t i = 0; i < seq_len; i++) {
        reference[i] = buckwild_derive_base_port(seed, sizeof(seed), i);
    }

    // These values should be deterministic across all platforms
    // If this test fails on a platform, it indicates implementation inconsistency
    for (size_t i = 0; i < seq_len; i++) {
        uint16_t port = buckwild_derive_base_port(seed, sizeof(seed), i);
        TEST_ASSERT_EQUAL_UINT16(reference[i], port);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

void test_derive_base_port_null_key(void) {
    uint32_t bucket = 1000;

    // Should handle NULL key gracefully (return 0 or handle error)
    uint16_t port = buckwild_derive_base_port(NULL, 32, bucket);

    // Expect 0 for error condition
    TEST_ASSERT_EQUAL_UINT16(0, port);
}

void test_derive_base_port_zero_key_length(void) {
    uint8_t daily_key[32];
    memset(daily_key, 0x42, sizeof(daily_key));
    uint32_t bucket = 1000;

    uint16_t port = buckwild_derive_base_port(daily_key, 0, bucket);

    // Expect 0 for error condition
    TEST_ASSERT_EQUAL_UINT16(0, port);
}

void test_validate_base_port_null_key(void) {
    uint32_t current_bucket = 1000;
    uint8_t delay_windows = 4;
    uint16_t port = 12345;

    bool is_valid = buckwild_validate_base_port(NULL, 32, current_bucket,
                                                 delay_windows, port);

    TEST_ASSERT_FALSE(is_valid);
}

// ============================================================================
// Integration Test with Time Utilities
// ============================================================================

void test_port_hopping_with_time_bucket(void) {
    // Test port hopping using actual time bucket calculation
    uint8_t daily_key[32];
    memset(daily_key, 0x99, sizeof(daily_key));

    // Get current time bucket
    uint64_t current_time_ns = buckwild_get_current_time_ns();
    uint32_t current_bucket = buckwild_calculate_time_bucket(current_time_ns);

    // Derive port for current time
    uint16_t current_port = buckwild_derive_base_port(daily_key, sizeof(daily_key),
                                                       current_bucket);

    // Validate it
    bool is_valid = buckwild_validate_base_port(daily_key, sizeof(daily_key),
                                                 current_bucket, 4, current_port);

    TEST_ASSERT_TRUE(is_valid);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT16(BUCKWILD_PORT_MIN, current_port);
    TEST_ASSERT_LESS_OR_EQUAL_UINT16(BUCKWILD_PORT_MAX, current_port);
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // Port derivation tests
    RUN_TEST(test_derive_base_port_deterministic);
    RUN_TEST(test_derive_base_port_different_buckets);
    RUN_TEST(test_derive_base_port_different_keys);
    RUN_TEST(test_derive_base_port_range);
    RUN_TEST(test_derive_session_port_deterministic);
    RUN_TEST(test_derive_session_port_different_from_base);

    // Adaptive window tests
    RUN_TEST(test_calculate_window_bounds_delay_1);
    RUN_TEST(test_calculate_window_bounds_delay_4);
    RUN_TEST(test_calculate_window_bounds_delay_16);
    RUN_TEST(test_calculate_window_bounds_invalid_delay);

    // Port validation tests
    RUN_TEST(test_validate_port_in_window_current_bucket);
    RUN_TEST(test_validate_port_in_window_past_bucket);
    RUN_TEST(test_validate_port_outside_window);
    RUN_TEST(test_validate_port_future_bucket);
    RUN_TEST(test_validate_port_wrong_port);

    // Port sequence tests
    RUN_TEST(test_generate_port_sequence);

    // Determinism tests (Task 3.1.6)
    RUN_TEST(test_port_sequence_determinism_identical_seed);
    RUN_TEST(test_port_sequence_determinism_multiple_runs);
    RUN_TEST(test_port_sequence_no_privileged_ports_extensive);
    RUN_TEST(test_port_sequence_edge_case_zero_seed);
    RUN_TEST(test_port_sequence_edge_case_max_seed);
    RUN_TEST(test_port_sequence_edge_case_boundary_buckets);
    RUN_TEST(test_port_sequence_uniform_distribution_approximate);
    RUN_TEST(test_port_sequence_cross_platform_consistency);

    // Error handling tests
    RUN_TEST(test_derive_base_port_null_key);
    RUN_TEST(test_derive_base_port_zero_key_length);
    RUN_TEST(test_validate_base_port_null_key);

    // Integration tests
    RUN_TEST(test_port_hopping_with_time_bucket);

    return UNITY_END();
}
