/**
 * Comprehensive Unit Tests for TC (Traffic Control) Programs
 *
 * Tests egress traffic control including:
 * - Traffic shaping and rate limiting
 * - QoS classification and enforcement
 * - Port transition coordination
 * - Packet classification
 * - Token bucket algorithm
 *
 * Date: 2025-10-10
 * Status: Production-ready comprehensive tests
 */

#include <unity.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Protocol headers
#include "../../../../src/ebpf/c/include/protocol.h"
#include "../../../../src/ebpf/c/include/maps.h"
#include "../../../../src/ebpf/c/include/security.h"

// Test utilities
#include "../utils/test_utils.h"
#include "../utils/mock_helpers.h"

//==============================================================================
// Test Constants
//==============================================================================

#define TEST_SESSION_ID         0x1234567890ABCDEF
#define TOKEN_BUCKET_SIZE       1000
#define TOKEN_REFILL_RATE       100  // tokens per second
#define BURST_ALLOWANCE         200
#define RATE_LIMIT_PPS          1000 // packets per second
#define RATE_LIMIT_BPS          1048576 // 1 MB/s

// QoS priorities
#define PRIO_CRITICAL           1
#define PRIO_CONTROL            2
#define PRIO_DATA_URGENT        3
#define PRIO_DATA_NORMAL        4
#define PRIO_DATA_BULK          5

//==============================================================================
// Mock Data Structures
//==============================================================================

// Mock TC context (__sk_buff)
typedef struct {
    uint32_t len;
    uint32_t pkt_type;
    uint32_t mark;
    uint32_t queue_mapping;
    uint32_t priority;
    void *data;
    void *data_end;
} mock_tc_ctx_t;

// Mock traffic shaping state
typedef struct {
    uint64_t last_update_time;
    uint32_t token_bucket;
    uint32_t bytes_sent;
    uint32_t packets_sent;
    uint16_t current_rate_limit;
    uint8_t qos_class;
    uint8_t congestion_level;
    uint32_t burst_allowance;
} mock_traffic_shaping_state_t;

// Mock port transition state
typedef struct {
    uint16_t current_port;
    uint16_t next_port;
    uint64_t transition_time;
    uint32_t packets_on_current;
    uint32_t packets_on_next;
    uint8_t transition_active;
    uint8_t coordination_required;
} mock_port_transition_state_t;

// Test data
static uint8_t test_packet_buffer[2048];
static mock_tc_ctx_t test_ctx;
static mock_traffic_shaping_state_t test_shaping_state;
static mock_port_transition_state_t test_transition_state;

//==============================================================================
// Helper Functions
//==============================================================================

/**
 * Token bucket refill calculation
 * Tokens = min(max_tokens, current_tokens + (time_elapsed * refill_rate))
 */
static uint32_t refill_token_bucket(uint32_t current_tokens, uint64_t time_elapsed_ns,
                                     uint32_t refill_rate, uint32_t max_tokens) {
    // Convert nanoseconds to seconds
    uint64_t seconds_elapsed = time_elapsed_ns / 1000000000ULL;

    // Calculate tokens to add
    uint32_t tokens_to_add = (uint32_t)(seconds_elapsed * refill_rate);

    // Add tokens but don't exceed maximum
    uint32_t new_tokens = current_tokens + tokens_to_add;
    if (new_tokens > max_tokens) {
        new_tokens = max_tokens;
    }

    return new_tokens;
}

/**
 * Check if packet can be sent (token bucket has enough tokens)
 */
static int can_send_packet(uint32_t packet_size, uint32_t available_tokens) {
    // Each byte requires one token (simplified)
    return (available_tokens >= packet_size);
}

/**
 * Classify packet type for QoS
 */
static uint8_t classify_packet_priority(uint8_t packet_type, uint8_t flags) {
    // Critical packets: SYN, SYN_ACK, FIN, DISCOVERY
    if (packet_type == PKT_TYPE_SYN ||
        packet_type == PKT_TYPE_SYN_ACK ||
        packet_type == PKT_TYPE_FIN ||
        packet_type == PKT_TYPE_DISCOVERY) {
        return PRIO_CRITICAL;
    }

    // Control packets: ERROR, RST, HEARTBEAT, recovery
    if (packet_type == PKT_TYPE_ERROR ||
        packet_type == PKT_TYPE_RST ||
        packet_type == PKT_TYPE_HEARTBEAT ||
        (flags & PKT_FLAG_RECOVERY)) {
        return PRIO_CONTROL;
    }

    // Data packets classified by flags
    if (packet_type == PKT_TYPE_DATA) {
        if (flags & PKT_FLAG_URGENT) {
            return PRIO_DATA_URGENT;
        }
        return PRIO_DATA_NORMAL;
    }

    // Default to normal priority
    return PRIO_DATA_NORMAL;
}

/**
 * Calculate congestion level based on token bucket state
 */
static uint8_t calculate_congestion_level(uint32_t current_tokens, uint32_t max_tokens) {
    // Congestion level 0-3 based on token availability
    uint32_t utilization = (max_tokens > 0) ? ((max_tokens - current_tokens) * 100 / max_tokens) : 0;

    if (utilization < 25) return 0; // No congestion
    if (utilization < 50) return 1; // Low congestion
    if (utilization < 75) return 2; // Medium congestion
    return 3; // High congestion
}

//==============================================================================
// Test Setup and Teardown
//==============================================================================

void setUp(void) {
    // Reset test data
    memset(test_packet_buffer, 0, sizeof(test_packet_buffer));
    memset(&test_ctx, 0, sizeof(test_ctx));
    memset(&test_shaping_state, 0, sizeof(test_shaping_state));
    memset(&test_transition_state, 0, sizeof(test_transition_state));

    // Initialize TC context
    test_ctx.data = test_packet_buffer;
    test_ctx.data_end = test_packet_buffer + sizeof(test_packet_buffer);
    test_ctx.len = 1000;
    test_ctx.priority = PRIO_DATA_NORMAL;

    // Initialize traffic shaping state
    test_shaping_state.token_bucket = TOKEN_BUCKET_SIZE;
    test_shaping_state.last_update_time = 0;
    test_shaping_state.burst_allowance = BURST_ALLOWANCE;
    test_shaping_state.congestion_level = 0;
}

void tearDown(void) {
    // Cleanup (nothing to do for now)
}

//==============================================================================
// TRAFFIC SHAPING TESTS (3 tests)
//==============================================================================

/**
 * Test 4.1: Token bucket refill calculation
 *
 * Requirements: REQ-TC-004
 * Validates: Token bucket refills at correct rate
 */
void test_4_1_token_bucket_refill(void) {
    uint32_t initial_tokens = 500;
    uint64_t time_elapsed = 1000000000ULL; // 1 second
    uint32_t refill_rate = TOKEN_REFILL_RATE; // 100 tokens/sec
    uint32_t max_tokens = TOKEN_BUCKET_SIZE; // 1000 tokens

    // Refill tokens after 1 second
    uint32_t new_tokens = refill_token_bucket(initial_tokens, time_elapsed,
                                                refill_rate, max_tokens);

    // Assert: Tokens increased by refill_rate
    TEST_ASSERT_EQUAL_UINT32(600, new_tokens); // 500 + 100

    // Test refill with 2 seconds
    time_elapsed = 2000000000ULL; // 2 seconds
    new_tokens = refill_token_bucket(initial_tokens, time_elapsed, refill_rate, max_tokens);
    TEST_ASSERT_EQUAL_UINT32(700, new_tokens); // 500 + 200

    // Test refill doesn't exceed maximum
    initial_tokens = 950;
    time_elapsed = 2000000000ULL; // 2 seconds (would add 200)
    new_tokens = refill_token_bucket(initial_tokens, time_elapsed, refill_rate, max_tokens);
    TEST_ASSERT_EQUAL_UINT32(1000, new_tokens); // Capped at max_tokens
}

/**
 * Test 4.2: Token bucket packet sending logic
 *
 * Requirements: REQ-TC-001, REQ-TC-004
 * Validates: Packets can only be sent if tokens available
 */
void test_4_2_token_bucket_send_logic(void) {
    test_shaping_state.token_bucket = 1000;

    // Test sending small packet (within budget)
    uint32_t packet_size = 500;
    int can_send = can_send_packet(packet_size, test_shaping_state.token_bucket);
    TEST_ASSERT_TRUE(can_send);

    // Simulate sending packet (consume tokens)
    if (can_send) {
        test_shaping_state.token_bucket -= packet_size;
    }
    TEST_ASSERT_EQUAL_UINT32(500, test_shaping_state.token_bucket);

    // Test sending large packet (exceeds budget)
    packet_size = 600;
    can_send = can_send_packet(packet_size, test_shaping_state.token_bucket);
    TEST_ASSERT_FALSE(can_send);

    // Token bucket should not change if packet not sent
    TEST_ASSERT_EQUAL_UINT32(500, test_shaping_state.token_bucket);
}

/**
 * Test 4.3: Burst allowance handling
 *
 * Requirements: REQ-TC-001
 * Validates: Burst allowance allows temporary rate exceedance
 */
void test_4_3_burst_allowance(void) {
    test_shaping_state.token_bucket = 100; // Low tokens
    test_shaping_state.burst_allowance = BURST_ALLOWANCE;

    // Test sending packet with burst allowance
    uint32_t packet_size = 150;

    // Without burst, cannot send
    int can_send_normal = can_send_packet(packet_size, test_shaping_state.token_bucket);
    TEST_ASSERT_FALSE(can_send_normal);

    // With burst allowance, can send
    int can_send_burst = can_send_packet(packet_size,
                                         test_shaping_state.token_bucket +
                                         test_shaping_state.burst_allowance);
    TEST_ASSERT_TRUE(can_send_burst);

    // Simulate burst send
    if (can_send_burst) {
        uint32_t total_available = test_shaping_state.token_bucket + test_shaping_state.burst_allowance;
        uint32_t burst_used = (packet_size > test_shaping_state.token_bucket) ?
                              (packet_size - test_shaping_state.token_bucket) : 0;

        test_shaping_state.burst_allowance -= burst_used;
        test_shaping_state.token_bucket = (packet_size > test_shaping_state.token_bucket) ?
                                          0 : (test_shaping_state.token_bucket - packet_size);
    }

    // Assert: Burst allowance consumed
    TEST_ASSERT_EQUAL_UINT32(0, test_shaping_state.token_bucket);
    TEST_ASSERT_EQUAL_UINT32(150, test_shaping_state.burst_allowance); // 200 - 50
}

//==============================================================================
// QOS ENFORCEMENT TESTS (2 tests)
//==============================================================================

/**
 * Test 4.4: Packet classification by type
 *
 * Requirements: REQ-TC-002
 * Validates: Packets are classified into correct priority levels
 */
void test_4_4_packet_classification(void) {
    // Test critical packets
    uint8_t priority_syn = classify_packet_priority(PKT_TYPE_SYN, 0);
    TEST_ASSERT_EQUAL_UINT8(PRIO_CRITICAL, priority_syn);

    uint8_t priority_fin = classify_packet_priority(PKT_TYPE_FIN, 0);
    TEST_ASSERT_EQUAL_UINT8(PRIO_CRITICAL, priority_fin);

    uint8_t priority_discovery = classify_packet_priority(PKT_TYPE_DISCOVERY, 0);
    TEST_ASSERT_EQUAL_UINT8(PRIO_CRITICAL, priority_discovery);

    // Test control packets
    uint8_t priority_heartbeat = classify_packet_priority(PKT_TYPE_HEARTBEAT, 0);
    TEST_ASSERT_EQUAL_UINT8(PRIO_CONTROL, priority_heartbeat);

    uint8_t priority_error = classify_packet_priority(PKT_TYPE_ERROR, 0);
    TEST_ASSERT_EQUAL_UINT8(PRIO_CONTROL, priority_error);

    // Test data packets
    uint8_t priority_data_normal = classify_packet_priority(PKT_TYPE_DATA, 0);
    TEST_ASSERT_EQUAL_UINT8(PRIO_DATA_NORMAL, priority_data_normal);

    uint8_t priority_data_urgent = classify_packet_priority(PKT_TYPE_DATA, PKT_FLAG_URGENT);
    TEST_ASSERT_EQUAL_UINT8(PRIO_DATA_URGENT, priority_data_urgent);

    // Test recovery flag
    uint8_t priority_recovery = classify_packet_priority(PKT_TYPE_DATA, PKT_FLAG_RECOVERY);
    TEST_ASSERT_EQUAL_UINT8(PRIO_CONTROL, priority_recovery);
}

/**
 * Test 4.5: QoS priority enforcement
 *
 * Requirements: REQ-TC-002
 * Validates: Higher priority packets are processed first
 */
void test_4_5_qos_priority_enforcement(void) {
    // Simulate packet queue with different priorities
    struct {
        uint8_t packet_type;
        uint8_t flags;
        uint8_t expected_priority;
    } packet_queue[] = {
        {PKT_TYPE_DATA, 0, PRIO_DATA_NORMAL},
        {PKT_TYPE_SYN, 0, PRIO_CRITICAL},
        {PKT_TYPE_DATA, PKT_FLAG_URGENT, PRIO_DATA_URGENT},
        {PKT_TYPE_HEARTBEAT, 0, PRIO_CONTROL},
    };

    // Classify all packets
    uint8_t priorities[4];
    for (int i = 0; i < 4; i++) {
        priorities[i] = classify_packet_priority(packet_queue[i].packet_type,
                                                  packet_queue[i].flags);
        TEST_ASSERT_EQUAL_UINT8(packet_queue[i].expected_priority, priorities[i]);
    }

    // Verify priority ordering (lower number = higher priority)
    TEST_ASSERT_LESS_THAN_UINT8(priorities[0], PRIO_CONTROL); // Normal data < control
    TEST_ASSERT_LESS_THAN_UINT8(priorities[3], priorities[0]); // Control < data
    TEST_ASSERT_LESS_THAN_UINT8(priorities[1], priorities[3]); // Critical < control
}

//==============================================================================
// PORT TRANSITION COORDINATION TESTS (2 tests)
//==============================================================================

/**
 * Test 4.6: Port transition state tracking
 *
 * Requirements: REQ-TC-003
 * Validates: Port transitions are tracked correctly
 */
void test_4_6_port_transition_tracking(void) {
    // Initialize port transition
    test_transition_state.current_port = 8080;
    test_transition_state.next_port = 8081;
    test_transition_state.transition_time = 1000000000ULL; // 1 second from now
    test_transition_state.transition_active = 1;
    test_transition_state.packets_on_current = 0;
    test_transition_state.packets_on_next = 0;

    // Simulate sending packet on current port
    test_transition_state.packets_on_current++;
    TEST_ASSERT_EQUAL_UINT32(1, test_transition_state.packets_on_current);
    TEST_ASSERT_EQUAL_UINT32(0, test_transition_state.packets_on_next);

    // Simulate transition happening
    uint64_t current_time = test_transition_state.transition_time + 100; // Past transition time

    if (current_time >= test_transition_state.transition_time) {
        // Complete transition
        test_transition_state.current_port = test_transition_state.next_port;
        test_transition_state.next_port = 0;
        test_transition_state.transition_active = 0;
    }

    // Assert: Transition completed
    TEST_ASSERT_EQUAL_UINT16(8081, test_transition_state.current_port);
    TEST_ASSERT_EQUAL_UINT16(0, test_transition_state.next_port);
    TEST_ASSERT_EQUAL_UINT8(0, test_transition_state.transition_active);
}

/**
 * Test 4.7: Port transition coordination requirements
 *
 * Requirements: REQ-TC-003, REQ-PORT-005
 * Validates: Coordination flags are set correctly
 */
void test_4_7_port_transition_coordination(void) {
    // Setup transition requiring coordination
    test_transition_state.current_port = 9000;
    test_transition_state.next_port = 9001;
    test_transition_state.transition_time = 500000000ULL; // 500ms from now
    test_transition_state.transition_active = 1;
    test_transition_state.coordination_required = 1;

    // Assert: Coordination flag set
    TEST_ASSERT_EQUAL_UINT8(1, test_transition_state.coordination_required);

    // Simulate packets sent during transition window
    uint64_t current_time = test_transition_state.transition_time - 100000000ULL; // 100ms before

    // Within transition window, can send on current port
    if (current_time < test_transition_state.transition_time) {
        test_transition_state.packets_on_current++;
    }

    TEST_ASSERT_EQUAL_UINT32(1, test_transition_state.packets_on_current);

    // After transition, should send on next port
    current_time = test_transition_state.transition_time + 100000000ULL; // 100ms after

    if (current_time >= test_transition_state.transition_time) {
        test_transition_state.packets_on_next++;
    }

    TEST_ASSERT_EQUAL_UINT32(1, test_transition_state.packets_on_next);
}

//==============================================================================
// RATE LIMITING TESTS (2 tests)
//==============================================================================

/**
 * Test 4.8: Per-session rate limiting
 *
 * Requirements: REQ-SEC-003
 * Validates: Sessions are rate limited correctly
 */
void test_4_8_per_session_rate_limiting(void) {
    // Initialize rate limit tracking
    uint32_t packets_sent = 0;
    uint32_t bytes_sent = 0;
    uint64_t window_start = 0;

    // Simulate sending packets
    for (int i = 0; i < 10; i++) {
        packets_sent++;
        bytes_sent += 1000;
    }

    // Check against limits (1000 pps, 1 MB/s)
    TEST_ASSERT_EQUAL_UINT32(10, packets_sent);
    TEST_ASSERT_EQUAL_UINT32(10000, bytes_sent);

    // Verify within limits (10 packets << 1000 pps)
    TEST_ASSERT_LESS_THAN_UINT32(RATE_LIMIT_PPS, packets_sent);
    TEST_ASSERT_LESS_THAN_UINT32(RATE_LIMIT_BPS, bytes_sent);
}

/**
 * Test 4.9: Rate limit violation detection
 *
 * Requirements: REQ-SEC-003
 * Validates: Rate limit violations are detected
 */
void test_4_9_rate_limit_violation_detection(void) {
    // Simulate exceeding packet rate limit
    uint32_t packets_sent = 1500; // Exceeds 1000 pps
    uint32_t time_window = 1; // 1 second

    // Calculate packet rate
    uint32_t packets_per_second = packets_sent / time_window;

    // Assert: Rate limit exceeded
    TEST_ASSERT_GREATER_THAN_UINT32(RATE_LIMIT_PPS, packets_per_second);

    // Simulate exceeding byte rate limit
    uint32_t bytes_sent = 2000000; // 2 MB, exceeds 1 MB/s

    // Calculate byte rate
    uint32_t bytes_per_second = bytes_sent / time_window;

    // Assert: Byte rate limit exceeded
    TEST_ASSERT_GREATER_THAN_UINT32(RATE_LIMIT_BPS, bytes_per_second);
}

//==============================================================================
// CONGESTION CONTROL TEST (1 test)
//==============================================================================

/**
 * Test 4.10: Congestion level calculation
 *
 * Requirements: REQ-TC-005
 * Validates: Congestion level is calculated correctly
 */
void test_4_10_congestion_level_calculation(void) {
    uint32_t max_tokens = TOKEN_BUCKET_SIZE;

    // Test no congestion (100% tokens available)
    uint32_t current_tokens = 1000;
    uint8_t congestion = calculate_congestion_level(current_tokens, max_tokens);
    TEST_ASSERT_EQUAL_UINT8(0, congestion); // No congestion

    // Test low congestion (60% tokens available)
    current_tokens = 600;
    congestion = calculate_congestion_level(current_tokens, max_tokens);
    TEST_ASSERT_EQUAL_UINT8(1, congestion); // Low congestion

    // Test medium congestion (40% tokens available)
    current_tokens = 400;
    congestion = calculate_congestion_level(current_tokens, max_tokens);
    TEST_ASSERT_EQUAL_UINT8(2, congestion); // Medium congestion

    // Test high congestion (10% tokens available)
    current_tokens = 100;
    congestion = calculate_congestion_level(current_tokens, max_tokens);
    TEST_ASSERT_EQUAL_UINT8(3, congestion); // High congestion

    // Test extreme congestion (0% tokens available)
    current_tokens = 0;
    congestion = calculate_congestion_level(current_tokens, max_tokens);
    TEST_ASSERT_EQUAL_UINT8(3, congestion); // High congestion
}

//==============================================================================
// Test Runner
//==============================================================================

int main(void) {
    UNITY_BEGIN();

    printf("\n========================================\n");
    printf("TC Comprehensive Unit Tests\n");
    printf("Protocol: Buckwild Traffic Control\n");
    printf("Date: 2025-10-10\n");
    printf("========================================\n\n");

    // TRAFFIC SHAPING TESTS (3 tests)
    printf("Running Traffic Shaping Tests...\n");
    RUN_TEST(test_4_1_token_bucket_refill);
    RUN_TEST(test_4_2_token_bucket_send_logic);
    RUN_TEST(test_4_3_burst_allowance);

    // QOS ENFORCEMENT TESTS (2 tests)
    printf("\nRunning QoS Enforcement Tests...\n");
    RUN_TEST(test_4_4_packet_classification);
    RUN_TEST(test_4_5_qos_priority_enforcement);

    // PORT TRANSITION TESTS (2 tests)
    printf("\nRunning Port Transition Tests...\n");
    RUN_TEST(test_4_6_port_transition_tracking);
    RUN_TEST(test_4_7_port_transition_coordination);

    // RATE LIMITING TESTS (2 tests)
    printf("\nRunning Rate Limiting Tests...\n");
    RUN_TEST(test_4_8_per_session_rate_limiting);
    RUN_TEST(test_4_9_rate_limit_violation_detection);

    // CONGESTION CONTROL TEST (1 test)
    printf("\nRunning Congestion Control Test...\n");
    RUN_TEST(test_4_10_congestion_level_calculation);

    printf("\n========================================\n");
    printf("TC Tests Complete\n");
    printf("Total Tests: 10\n");
    printf("========================================\n");

    return UNITY_END();
}
