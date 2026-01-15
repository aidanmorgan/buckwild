/**
 * Unit tests for TC (Traffic Control) programs
 * Stage 4: Traffic Control (Rate Limiting, QoS, Traffic Shaping, Congestion Detection)
 */

#include <unity.h>
#include <stdint.h>
#include <string.h>
#include "rate_limiting.h"
#include "qos.h"
#include "congestion.h"

void setUp(void) {
    // Setup for each test
}

void tearDown(void) {
    // Cleanup after each test
}

// Test 4.1.1: Token Bucket Refill
void test_tc_token_bucket_refill(void) {
    // Given: Token bucket state
    struct token_bucket bucket = {
        .tokens = 0,
        .last_refill_ns = 1000000000,  // 1 second ago
        .rate_bps = 1000000,  // 1 Mbps
        .burst_bytes = 200000  // Large enough to not cap the refill
    };
    uint64_t current_ns = 2000000000;  // Now (1 second later)

    // When: Refill tokens
    refill_token_bucket(&bucket, current_ns);

    // Then: Should have refilled based on elapsed time
    // 1 second at 1 Mbps = 1,000,000 bits = 125,000 bytes
    uint64_t expected_tokens = 125000;
    TEST_ASSERT_UINT64_WITHIN(1000, expected_tokens, bucket.tokens);
    TEST_ASSERT_EQUAL_UINT64(current_ns, bucket.last_refill_ns);
}

// Test 4.1.2: Token Bucket Refill with Partial Time
void test_tc_token_bucket_refill_partial_second(void) {
    // Given: Token bucket with some tokens
    struct token_bucket bucket = {
        .tokens = 5000,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,  // 1 Mbps
        .burst_bytes = 200000
    };
    uint64_t current_ns = 1500000000;  // 0.5 seconds later

    // When: Refill tokens
    refill_token_bucket(&bucket, current_ns);

    // Then: Should add tokens for 0.5 seconds
    // 0.5 seconds at 1 Mbps = 500,000 bits = 62,500 bytes
    uint64_t expected_tokens = 5000 + 62500;
    TEST_ASSERT_UINT64_WITHIN(1000, expected_tokens, bucket.tokens);
}

// Test 4.1.3: Token Bucket Refill Respects Burst Limit
void test_tc_token_bucket_refill_burst_limit(void) {
    // Given: Token bucket that would exceed burst limit
    struct token_bucket bucket = {
        .tokens = 5000,
        .last_refill_ns = 1000000000,
        .rate_bps = 8000000,  // 8 Mbps = 1 MB/s
        .burst_bytes = 10000
    };
    uint64_t current_ns = 2000000000;  // 1 second later

    // When: Refill tokens (would add 1,000,000 bytes)
    refill_token_bucket(&bucket, current_ns);

    // Then: Should cap at burst_bytes
    TEST_ASSERT_EQUAL_UINT64(10000, bucket.tokens);
}

// Test 4.1.4: Token Bucket Consume Success
void test_tc_token_bucket_consume_success(void) {
    // Given: Bucket with sufficient tokens
    struct token_bucket bucket = {
        .tokens = 10000,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,
        .burst_bytes = 10000
    };

    // When: Consume tokens for packet
    int result = consume_tokens(&bucket, 5000);

    // Then: Should succeed and update token count
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(5000, bucket.tokens);
}

// Test 4.1.5: Token Bucket Consume Failure (Insufficient Tokens)
void test_tc_token_bucket_consume_insufficient(void) {
    // Given: Bucket with insufficient tokens
    struct token_bucket bucket = {
        .tokens = 1000,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,
        .burst_bytes = 10000
    };

    // When: Try to consume more tokens than available
    int result = consume_tokens(&bucket, 5000);

    // Then: Should fail and tokens unchanged
    TEST_ASSERT_EQUAL_INT(-1, result);
    TEST_ASSERT_EQUAL_UINT64(1000, bucket.tokens);
}

// Test 4.1.6: Token Bucket Consume Exact Amount
void test_tc_token_bucket_consume_exact(void) {
    // Given: Bucket with exact token count
    struct token_bucket bucket = {
        .tokens = 5000,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,
        .burst_bytes = 10000
    };

    // When: Consume exactly all tokens
    int result = consume_tokens(&bucket, 5000);

    // Then: Should succeed with zero tokens remaining
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(0, bucket.tokens);
}

// Test 4.1.7: Token Bucket Zero Time Elapsed
void test_tc_token_bucket_refill_zero_time(void) {
    // Given: Bucket with current time
    struct token_bucket bucket = {
        .tokens = 1000,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,
        .burst_bytes = 10000
    };
    uint64_t current_ns = 1000000000;  // Same time

    // When: Refill with zero time elapsed
    refill_token_bucket(&bucket, current_ns);

    // Then: Tokens should remain unchanged
    TEST_ASSERT_EQUAL_UINT64(1000, bucket.tokens);
}

// ============================================================================
// Test Suite 4.2: QoS Priority Classification
// ============================================================================

// Test 4.2.1: SSH Traffic Classification (High Priority)
void test_qos_classify_ssh_traffic(void) {
    // Given: SSH port 22
    uint16_t src_port = 12345;
    uint16_t dst_port = 22;
    uint8_t protocol = 6;  // TCP

    // When: Classify packet
    uint8_t priority = classify_packet_priority(src_port, dst_port, protocol);

    // Then: Should be high priority
    TEST_ASSERT_EQUAL_UINT8(QOS_PRIORITY_HIGH, priority);
}

// Test 4.2.2: HTTP/HTTPS Traffic Classification (Normal Priority)
void test_qos_classify_web_traffic(void) {
    // Given: HTTPS port 443
    uint16_t src_port = 54321;
    uint16_t dst_port = 443;
    uint8_t protocol = 6;  // TCP

    // When: Classify packet
    uint8_t priority = classify_packet_priority(src_port, dst_port, protocol);

    // Then: Should be normal priority
    TEST_ASSERT_EQUAL_UINT8(QOS_PRIORITY_NORMAL, priority);
}

// Test 4.2.3: DNS Traffic Classification (Critical Priority)
void test_qos_classify_dns_traffic(void) {
    // Given: DNS port 53
    uint16_t src_port = 60000;
    uint16_t dst_port = 53;
    uint8_t protocol = 17;  // UDP

    // When: Classify packet
    uint8_t priority = classify_packet_priority(src_port, dst_port, protocol);

    // Then: Should be critical priority (DNS is critical for connectivity)
    TEST_ASSERT_EQUAL_UINT8(QOS_PRIORITY_CRITICAL, priority);
}

// Test 4.2.4: Bulk Transfer Traffic Classification (Low Priority)
void test_qos_classify_bulk_traffic(void) {
    // Given: High port number (ephemeral, likely P2P/bulk)
    uint16_t src_port = 50000;
    uint16_t dst_port = 60000;
    uint8_t protocol = 6;  // TCP

    // When: Classify packet
    uint8_t priority = classify_packet_priority(src_port, dst_port, protocol);

    // Then: Should be low priority
    TEST_ASSERT_EQUAL_UINT8(QOS_PRIORITY_LOW, priority);
}

// ============================================================================
// Test Suite 4.3: Traffic Shaping
// ============================================================================

// Test 4.3.1: Traffic Shaping Allows Packet Within Rate
void test_traffic_shaping_allows_within_rate(void) {
    // Given: Token bucket with sufficient tokens
    struct token_bucket bucket = {
        .tokens = 10000,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,
        .burst_bytes = 20000
    };
    uint64_t packet_size = 1500;
    uint64_t current_ns = 1000000000;

    // When: Apply traffic shaping
    int result = apply_traffic_shaping(&bucket, packet_size, current_ns);

    // Then: Should allow packet (0 = allow, -1 = drop)
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(10000 - 1500, bucket.tokens);
}

// Test 4.3.2: Traffic Shaping Drops Packet Exceeding Rate
void test_traffic_shaping_drops_exceeding_rate(void) {
    // Given: Token bucket with insufficient tokens
    struct token_bucket bucket = {
        .tokens = 500,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,
        .burst_bytes = 20000
    };
    uint64_t packet_size = 1500;
    uint64_t current_ns = 1000000000;

    // When: Apply traffic shaping
    int result = apply_traffic_shaping(&bucket, packet_size, current_ns);

    // Then: Should drop packet
    TEST_ASSERT_EQUAL_INT(-1, result);
    TEST_ASSERT_EQUAL_UINT64(500, bucket.tokens);  // Unchanged
}

// Test 4.3.3: Traffic Shaping with Automatic Refill
void test_traffic_shaping_with_refill(void) {
    // Given: Bucket with few tokens but time has passed
    struct token_bucket bucket = {
        .tokens = 500,
        .last_refill_ns = 1000000000,
        .rate_bps = 1000000,  // 125000 bytes/sec
        .burst_bytes = 200000
    };
    uint64_t packet_size = 1500;
    uint64_t current_ns = 2000000000;  // 1 second later

    // When: Apply traffic shaping (should refill first)
    int result = apply_traffic_shaping(&bucket, packet_size, current_ns);

    // Then: Should allow after refill (500 + 125000 tokens available)
    TEST_ASSERT_EQUAL_INT(0, result);
}

// ============================================================================
// Test Suite 4.4: Congestion Detection
// ============================================================================

// Test 4.4.1: No Congestion Detected
void test_congestion_no_congestion(void) {
    // Given: Low queue depth, no drops
    uint64_t queue_depth = 10;
    uint64_t drop_count = 0;
    uint64_t total_packets = 1000;

    // When: Detect congestion
    uint8_t congestion_level = detect_congestion(queue_depth, drop_count, total_packets);

    // Then: Should report no congestion (0)
    TEST_ASSERT_EQUAL_UINT8(0, congestion_level);
}

// Test 4.4.2: Moderate Congestion Detected
void test_congestion_moderate(void) {
    // Given: Moderate queue depth, some drops
    uint64_t queue_depth = 500;  // Moderate queue
    uint64_t drop_count = 50;
    uint64_t total_packets = 1000;  // 5% drop rate

    // When: Detect congestion
    uint8_t congestion_level = detect_congestion(queue_depth, drop_count, total_packets);

    // Then: Should report moderate congestion (1)
    TEST_ASSERT_EQUAL_UINT8(1, congestion_level);
}

// Test 4.4.3: High Congestion Detected
void test_congestion_high(void) {
    // Given: High queue depth, many drops
    uint64_t queue_depth = 900;  // Near capacity
    uint64_t drop_count = 200;
    uint64_t total_packets = 1000;  // 20% drop rate

    // When: Detect congestion
    uint8_t congestion_level = detect_congestion(queue_depth, drop_count, total_packets);

    // Then: Should report high congestion (2)
    TEST_ASSERT_EQUAL_UINT8(2, congestion_level);
}

int main(void) {
    UNITY_BEGIN();

    // Test Suite 4.1: Token Bucket Rate Limiting
    RUN_TEST(test_tc_token_bucket_refill);
    RUN_TEST(test_tc_token_bucket_refill_partial_second);
    RUN_TEST(test_tc_token_bucket_refill_burst_limit);
    RUN_TEST(test_tc_token_bucket_consume_success);
    RUN_TEST(test_tc_token_bucket_consume_insufficient);
    RUN_TEST(test_tc_token_bucket_consume_exact);
    RUN_TEST(test_tc_token_bucket_refill_zero_time);

    // Test Suite 4.2: QoS Priority Classification
    RUN_TEST(test_qos_classify_ssh_traffic);
    RUN_TEST(test_qos_classify_web_traffic);
    RUN_TEST(test_qos_classify_dns_traffic);
    RUN_TEST(test_qos_classify_bulk_traffic);

    // Test Suite 4.3: Traffic Shaping
    RUN_TEST(test_traffic_shaping_allows_within_rate);
    RUN_TEST(test_traffic_shaping_drops_exceeding_rate);
    RUN_TEST(test_traffic_shaping_with_refill);

    // Test Suite 4.4: Congestion Detection
    RUN_TEST(test_congestion_no_congestion);
    RUN_TEST(test_congestion_moderate);
    RUN_TEST(test_congestion_high);

    return UNITY_END();
}

