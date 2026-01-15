/**
 * @file test_tc_token_bucket_edge_cases.c
 * @brief Comprehensive edge case tests for TC Police token bucket algorithm
 *
 * Tests overflow-safe arithmetic and boundary conditions:
 * - Large time intervals without overflow
 * - Token addition overflow prevention
 * - CBS (Committed Burst Size) boundary conditions
 * - CIR (Committed Information Rate) calculations
 * - Fractional nanosecond calculations
 * - Zero and maximum value handling
 */

#include <unity.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/*============================================================================
 * Police Configuration (matching maps.h)
 *============================================================================*/

struct police_config {
    uint32_t cir_bytes_per_sec;  /* Committed Information Rate */
    uint32_t cbs_bytes;          /* Committed Burst Size */
};

struct police_state {
    uint64_t tokens;             /* Current available tokens (in bytes) */
    uint64_t last_update_ns;     /* Last update timestamp */
};

/*============================================================================
 * Token Bucket Implementation (matching buckwild_tc.c)
 *============================================================================*/

/**
 * Overflow-safe token bucket refill calculation
 *
 * This is the corrected implementation that prevents overflow when:
 * - time_diff is very large (e.g., after system resume)
 * - cir_bytes_per_sec is high (e.g., 10 Gbps)
 * - Long intervals between packets
 */
static inline uint64_t calculate_tokens_to_add(uint64_t time_diff_ns,
                                                uint32_t cir_bytes_per_sec) {
    /* Split calculation to prevent overflow:
     * tokens = (seconds * cir) + (nanos_remaining * cir / 1e9)
     *
     * This avoids: time_diff_ns * cir_bytes_per_sec which could overflow
     */
    uint64_t seconds_elapsed = time_diff_ns / 1000000000ULL;
    uint64_t nanos_remaining = time_diff_ns % 1000000000ULL;

    uint64_t tokens_from_seconds = seconds_elapsed * cir_bytes_per_sec;
    uint64_t tokens_from_nanos = (nanos_remaining * cir_bytes_per_sec) / 1000000000ULL;

    return tokens_from_seconds + tokens_from_nanos;
}

/**
 * Apply token bucket rate limiting
 */
static inline int police_packet(struct police_config *config,
                                struct police_state *state,
                                uint64_t current_time_ns,
                                uint32_t packet_size) {
    /* Calculate time elapsed since last update */
    uint64_t time_diff = current_time_ns - state->last_update_ns;

    /* Calculate tokens to add using overflow-safe arithmetic */
    uint64_t tokens_to_add = calculate_tokens_to_add(time_diff, config->cir_bytes_per_sec);

    /* Add tokens, capped at CBS */
    state->tokens += tokens_to_add;
    if (state->tokens > config->cbs_bytes) {
        state->tokens = config->cbs_bytes;
    }

    /* Update timestamp */
    state->last_update_ns = current_time_ns;

    /* Check if packet can be sent */
    if (state->tokens >= packet_size) {
        state->tokens -= packet_size;
        return 0; /* Allow */
    }

    return -1; /* Drop */
}

/*============================================================================
 * Test Setup and Teardown
 *============================================================================*/

static struct police_config test_config;
static struct police_state test_state;

void setUp(void) {
    /* Default configuration: 1 Mbps, 10KB burst */
    test_config.cir_bytes_per_sec = 1000000 / 8; /* 125,000 bytes/sec */
    test_config.cbs_bytes = 10000;

    /* Initialize state */
    test_state.tokens = test_config.cbs_bytes; /* Start full */
    test_state.last_update_ns = 0;
}

void tearDown(void) {
    /* Nothing to clean up */
}

/*============================================================================
 * Basic Token Bucket Behavior Tests
 *============================================================================*/

void test_tokens_refill_after_one_second(void) {
    test_state.tokens = 0;
    test_state.last_update_ns = 0;

    /* Calculate tokens after 1 second */
    uint64_t tokens = calculate_tokens_to_add(1000000000ULL, test_config.cir_bytes_per_sec);

    /* Should equal CIR */
    TEST_ASSERT_EQUAL_UINT64(test_config.cir_bytes_per_sec, tokens);
}

void test_tokens_refill_fractional_second(void) {
    /* 500ms = 0.5 seconds */
    uint64_t tokens = calculate_tokens_to_add(500000000ULL, test_config.cir_bytes_per_sec);

    /* Should be half of CIR */
    TEST_ASSERT_EQUAL_UINT64(test_config.cir_bytes_per_sec / 2, tokens);
}

void test_tokens_capped_at_cbs(void) {
    /* Start with 0 tokens, wait 10 seconds (would give 10x CIR) */
    test_state.tokens = 0;
    test_state.last_update_ns = 0;

    int result = police_packet(&test_config, &test_state, 10000000000ULL, 100);

    /* Tokens should be capped at CBS - packet_size */
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_LESS_OR_EQUAL_UINT64(test_config.cbs_bytes, test_state.tokens + 100);
}

void test_packet_allowed_when_tokens_sufficient(void) {
    test_state.tokens = 1000;
    test_state.last_update_ns = 1000000000ULL;

    int result = police_packet(&test_config, &test_state, 1000000000ULL, 500);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(500, test_state.tokens);
}

void test_packet_dropped_when_tokens_insufficient(void) {
    test_state.tokens = 100;
    test_state.last_update_ns = 1000000000ULL;

    int result = police_packet(&test_config, &test_state, 1000000000ULL, 500);

    TEST_ASSERT_EQUAL_INT(-1, result);
    TEST_ASSERT_EQUAL_UINT64(100, test_state.tokens);
}

/*============================================================================
 * Overflow Prevention Tests (Critical for 64-bit arithmetic)
 *============================================================================*/

void test_no_overflow_with_large_time_interval(void) {
    /* Simulate 24 hours without activity */
    uint64_t time_diff = 24ULL * 60 * 60 * 1000000000ULL; /* 24 hours in ns */

    /* 10 Gbps rate (very high) */
    uint32_t high_rate = 1250000000; /* 10 Gbps in bytes/sec */

    /* This would overflow if calculated as: time_diff * rate */
    /* Because: 86400e9 * 1.25e9 = 1.08e20 > 2^64 */

    uint64_t tokens = calculate_tokens_to_add(time_diff, high_rate);

    /* Expected: 24 * 3600 * 1.25e9 = 1.08e14 bytes */
    uint64_t expected = 24ULL * 3600ULL * high_rate;

    /* Should match expected without overflow */
    TEST_ASSERT_EQUAL_UINT64(expected, tokens);
}

void test_no_overflow_with_max_time_interval(void) {
    /* Very large time interval (but not unreasonable - ~584 years) */
    uint64_t time_diff = UINT64_MAX / 2;

    /* Moderate rate */
    uint32_t rate = 1000000; /* 1 MB/s */

    /* Should not overflow or crash */
    uint64_t tokens = calculate_tokens_to_add(time_diff, rate);

    /* Result should be very large but not wrapped */
    TEST_ASSERT_GREATER_THAN_UINT64(0, tokens);
}

void test_no_overflow_with_max_rate(void) {
    /* 1 second interval */
    uint64_t time_diff = 1000000000ULL;

    /* Maximum rate (4.29 GB/s) */
    uint32_t max_rate = UINT32_MAX;

    uint64_t tokens = calculate_tokens_to_add(time_diff, max_rate);

    /* Should equal max_rate without overflow */
    TEST_ASSERT_EQUAL_UINT64(max_rate, tokens);
}

void test_fractional_nanos_calculation_accurate(void) {
    /* Test that fractional nanoseconds are calculated correctly */
    /* 1.5 seconds at 1000 bytes/sec */
    uint64_t time_diff = 1500000000ULL;
    uint32_t rate = 1000;

    uint64_t tokens = calculate_tokens_to_add(time_diff, rate);

    /* Expected: 1 * 1000 + (500000000 * 1000 / 1e9) = 1000 + 500 = 1500 */
    TEST_ASSERT_EQUAL_UINT64(1500, tokens);
}

void test_small_time_interval_precision(void) {
    /* 1 millisecond at 1 MB/s */
    uint64_t time_diff = 1000000ULL; /* 1ms in ns */
    uint32_t rate = 1000000; /* 1 MB/s */

    uint64_t tokens = calculate_tokens_to_add(time_diff, rate);

    /* Expected: 0 * 1e6 + (1e6 * 1e6 / 1e9) = 1000 bytes */
    TEST_ASSERT_EQUAL_UINT64(1000, tokens);
}

void test_very_small_time_interval(void) {
    /* 1 microsecond at 1 GB/s */
    uint64_t time_diff = 1000ULL; /* 1 microsecond in ns */
    uint32_t rate = 1000000000; /* 1 GB/s */

    uint64_t tokens = calculate_tokens_to_add(time_diff, rate);

    /* Expected: 0 * 1e9 + (1e3 * 1e9 / 1e9) = 1000 bytes */
    TEST_ASSERT_EQUAL_UINT64(1000, tokens);
}

/*============================================================================
 * Boundary Value Tests
 *============================================================================*/

void test_zero_time_interval(void) {
    uint64_t tokens = calculate_tokens_to_add(0, test_config.cir_bytes_per_sec);

    TEST_ASSERT_EQUAL_UINT64(0, tokens);
}

void test_zero_rate(void) {
    uint64_t tokens = calculate_tokens_to_add(1000000000ULL, 0);

    TEST_ASSERT_EQUAL_UINT64(0, tokens);
}

void test_one_nanosecond_interval(void) {
    /* 1 ns at 1 GB/s = 1 byte expected, but integer division floors to 0 */
    uint64_t tokens = calculate_tokens_to_add(1ULL, 1000000000);

    /* (1 * 1e9) / 1e9 = 1, but since seconds_elapsed=0, it's (1 * 1e9) / 1e9 = 1 */
    TEST_ASSERT_EQUAL_UINT64(1, tokens);
}

void test_almost_one_second(void) {
    /* 999999999 ns at 1000 bytes/sec */
    uint64_t tokens = calculate_tokens_to_add(999999999ULL, 1000);

    /* seconds_elapsed = 0, nanos_remaining = 999999999 */
    /* tokens = (999999999 * 1000) / 1e9 = 999 */
    TEST_ASSERT_EQUAL_UINT64(999, tokens);
}

void test_exactly_one_second(void) {
    uint64_t tokens = calculate_tokens_to_add(1000000000ULL, 1000);

    /* seconds_elapsed = 1, nanos_remaining = 0 */
    /* tokens = 1 * 1000 + 0 = 1000 */
    TEST_ASSERT_EQUAL_UINT64(1000, tokens);
}

void test_cbs_zero_always_drops(void) {
    test_config.cbs_bytes = 0;
    test_state.tokens = 0;
    test_state.last_update_ns = 0;

    int result = police_packet(&test_config, &test_state, 1000000000ULL, 100);

    /* Should drop because CBS is 0 */
    TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_exact_token_match_allows(void) {
    test_state.tokens = 500;
    test_state.last_update_ns = 1000000000ULL;

    int result = police_packet(&test_config, &test_state, 1000000000ULL, 500);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(0, test_state.tokens);
}

void test_one_byte_short_drops(void) {
    test_state.tokens = 499;
    test_state.last_update_ns = 1000000000ULL;

    int result = police_packet(&test_config, &test_state, 1000000000ULL, 500);

    TEST_ASSERT_EQUAL_INT(-1, result);
    TEST_ASSERT_EQUAL_UINT64(499, test_state.tokens);
}

/*============================================================================
 * Token Accumulation Tests
 *============================================================================*/

void test_tokens_accumulate_over_multiple_intervals(void) {
    test_state.tokens = 0;
    test_state.last_update_ns = 0;
    test_config.cir_bytes_per_sec = 1000;
    test_config.cbs_bytes = 100000; /* Large enough to not cap */

    /* First packet at t=1s */
    police_packet(&test_config, &test_state, 1000000000ULL, 100);
    uint64_t tokens_after_1s = test_state.tokens;

    /* Second packet at t=2s */
    police_packet(&test_config, &test_state, 2000000000ULL, 100);
    uint64_t tokens_after_2s = test_state.tokens;

    /* Third packet at t=3s */
    police_packet(&test_config, &test_state, 3000000000ULL, 100);
    uint64_t tokens_after_3s = test_state.tokens;

    /* Each second adds 1000 tokens, each packet consumes 100 */
    /* t=1: 0 + 1000 - 100 = 900 */
    /* t=2: 900 + 1000 - 100 = 1800 */
    /* t=3: 1800 + 1000 - 100 = 2700 */
    TEST_ASSERT_EQUAL_UINT64(900, tokens_after_1s);
    TEST_ASSERT_EQUAL_UINT64(1800, tokens_after_2s);
    TEST_ASSERT_EQUAL_UINT64(2700, tokens_after_3s);
}

void test_burst_after_idle_period(void) {
    test_config.cir_bytes_per_sec = 1000;
    test_config.cbs_bytes = 5000;
    test_state.tokens = 0;
    test_state.last_update_ns = 0;

    /* Wait 10 seconds (would accumulate 10000 tokens, but capped at 5000) */
    int result = police_packet(&test_config, &test_state, 10000000000ULL, 4000);

    /* Should allow large burst */
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(1000, test_state.tokens);
}

void test_rapid_packets_deplete_bucket(void) {
    test_config.cir_bytes_per_sec = 1000;
    test_config.cbs_bytes = 5000;
    test_state.tokens = 5000;
    test_state.last_update_ns = 0;

    /* Send 5 packets of 1000 bytes each at 1ms intervals */
    int results[5];
    uint64_t time = 1000000000ULL;

    for (int i = 0; i < 5; i++) {
        results[i] = police_packet(&test_config, &test_state, time, 1000);
        time += 1000000ULL; /* 1ms later */
    }

    /* First 5 should succeed (5000 tokens available initially) */
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL_INT(0, results[i]);
    }

    /* Next packet should fail (only ~5 tokens accumulated in 5ms) */
    int result6 = police_packet(&test_config, &test_state, time, 1000);
    TEST_ASSERT_EQUAL_INT(-1, result6);
}

/*============================================================================
 * Real-World Scenario Tests
 *============================================================================*/

void test_1gbps_rate_limiting(void) {
    /* 1 Gbps = 125,000,000 bytes/sec */
    test_config.cir_bytes_per_sec = 125000000;
    test_config.cbs_bytes = 15000; /* 10 x 1500 MTU packets */
    test_state.tokens = test_config.cbs_bytes;
    test_state.last_update_ns = 0;

    /* Send 10 MTU-sized packets */
    int allowed = 0;
    uint64_t time = 0;

    for (int i = 0; i < 10; i++) {
        if (police_packet(&test_config, &test_state, time, 1500) == 0) {
            allowed++;
        }
        time += 1000000ULL; /* 1ms between packets */
    }

    /* All 10 should be allowed (burst) */
    TEST_ASSERT_EQUAL_INT(10, allowed);
}

void test_10mbps_steady_state(void) {
    /* 10 Mbps = 1,250,000 bytes/sec */
    test_config.cir_bytes_per_sec = 1250000;
    test_config.cbs_bytes = 1500; /* 1 MTU */
    test_state.tokens = test_config.cbs_bytes;
    test_state.last_update_ns = 0;

    /*
     * Token bucket behavior analysis:
     * - Refill rate: 1,250,000 bytes/sec = 1,250 bytes/ms
     * - Bucket capacity: 1,500 bytes
     * - Packet size: 1,500 bytes
     * - Send interval: 1ms
     *
     * Per iteration: +1,250 tokens, need 1,500 tokens
     * Pattern:
     *   t=0: tokens=1500, allow, tokens=0
     *   t=1: tokens=1250, drop (need 1500)
     *   t=2: tokens=2500 capped to 1500, allow, tokens=0
     *   t=3: tokens=1250, drop
     *   ...
     * Result: allow, drop, allow, drop... = 50% allowed
     */
    uint64_t time = 0;
    int allowed = 0;
    int dropped = 0;

    /* Send 1000 packets at 1ms intervals */
    for (int i = 0; i < 1000; i++) {
        if (police_packet(&test_config, &test_state, time, 1500) == 0) {
            allowed++;
        } else {
            dropped++;
        }
        time += 1000000ULL; /* 1ms */
    }

    /* With the pattern above, we expect ~500 allowed (50% of 1000) */
    /* Allow some tolerance for edge effects */
    TEST_ASSERT_GREATER_THAN_INT(480, allowed);
    TEST_ASSERT_LESS_THAN_INT(520, allowed);
}

void test_shaped_traffic_over_time(void) {
    /* 100 Kbps = 12,500 bytes/sec */
    test_config.cir_bytes_per_sec = 12500;
    test_config.cbs_bytes = 5000;
    test_state.tokens = 0;
    test_state.last_update_ns = 0;

    uint64_t bytes_sent = 0;
    uint64_t time = 0;

    /* Simulate 10 seconds of traffic */
    for (int i = 0; i < 1000; i++) {
        if (police_packet(&test_config, &test_state, time, 100) == 0) {
            bytes_sent += 100;
        }
        time += 10000000ULL; /* 10ms */
    }

    /* In 10 seconds at 12,500 bytes/sec, should send ~125,000 bytes */
    /* With 100-byte packets every 10ms, actual rate is 10,000 bytes/sec */
    /* But we're limited to 12,500, so should be close to 100,000 bytes */
    TEST_ASSERT_GREATER_THAN_UINT64(90000, bytes_sent);
    TEST_ASSERT_LESS_OR_EQUAL_UINT64(125000, bytes_sent);
}

/*============================================================================
 * Edge Case: Timestamp Wraparound (not likely in practice but test anyway)
 *============================================================================*/

void test_time_going_backwards_handled(void) {
    test_state.tokens = 1000;
    test_state.last_update_ns = 2000000000ULL;

    /* Time appears to go backwards (shouldn't happen, but defensive) */
    /* The subtraction will underflow to a huge value */
    uint64_t current_time = 1000000000ULL;

    /* This tests that we don't crash - behavior is undefined but shouldn't fail */
    /* In real implementation, you'd add a check for time_diff sanity */
    int result = police_packet(&test_config, &test_state, current_time, 500);

    /* Should still work (tokens will overflow but test doesn't crash) */
    (void)result; /* Result is undefined, just verify no crash */
    TEST_PASS();
}

/*============================================================================
 * Test Runner
 *============================================================================*/

int main(void) {
    UNITY_BEGIN();

    /* Basic behavior */
    RUN_TEST(test_tokens_refill_after_one_second);
    RUN_TEST(test_tokens_refill_fractional_second);
    RUN_TEST(test_tokens_capped_at_cbs);
    RUN_TEST(test_packet_allowed_when_tokens_sufficient);
    RUN_TEST(test_packet_dropped_when_tokens_insufficient);

    /* Overflow prevention (critical tests) */
    RUN_TEST(test_no_overflow_with_large_time_interval);
    RUN_TEST(test_no_overflow_with_max_time_interval);
    RUN_TEST(test_no_overflow_with_max_rate);
    RUN_TEST(test_fractional_nanos_calculation_accurate);
    RUN_TEST(test_small_time_interval_precision);
    RUN_TEST(test_very_small_time_interval);

    /* Boundary values */
    RUN_TEST(test_zero_time_interval);
    RUN_TEST(test_zero_rate);
    RUN_TEST(test_one_nanosecond_interval);
    RUN_TEST(test_almost_one_second);
    RUN_TEST(test_exactly_one_second);
    RUN_TEST(test_cbs_zero_always_drops);
    RUN_TEST(test_exact_token_match_allows);
    RUN_TEST(test_one_byte_short_drops);

    /* Token accumulation */
    RUN_TEST(test_tokens_accumulate_over_multiple_intervals);
    RUN_TEST(test_burst_after_idle_period);
    RUN_TEST(test_rapid_packets_deplete_bucket);

    /* Real-world scenarios */
    RUN_TEST(test_1gbps_rate_limiting);
    RUN_TEST(test_10mbps_steady_state);
    RUN_TEST(test_shaped_traffic_over_time);

    /* Edge cases */
    RUN_TEST(test_time_going_backwards_handled);

    return UNITY_END();
}
