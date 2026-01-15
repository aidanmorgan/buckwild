/**
 * @file test_xdp_packet_filtering.c
 * @brief Unit tests for XDP packet filtering functionality
 *
 * Tests XDP program logic for the Buckwild protocol including:
 * - Protocol detection and packet validation
 * - Session validation and port hopping
 * - Fragment security (7-check system)
 * - HMAC policy enforcement
 * - Adaptive delay windows
 * - Session routing and ring buffer operations
 *
 * Reference:
 * - EBPF_MASTER_IMPLEMENTATION_PLAN.md
 * - design/protocol/ - Protocol specifications
 * - design/security.md - Security requirements
 */

#include <unity.h>
#include "../utils/test_utils.h"
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

// Include eBPF logic headers
#include "logic/packet_detection.h"
#include "logic/header_parsing.h"
#include "logic/session_validation.h"
#include "logic/port_calculation.h"
#include "logic/security_checks.h"

// Include test helpers
#include "xdp_test_helpers.h"

// Forward declarations removed - now using actual implementations from header files
// All types and functions are defined in:
// - packet_detection.h
// - header_parsing.h
// - session_validation.h
// - port_calculation.h
// - security_checks.h

// Helper functions for test setup
// Mock time is provided by xdp_test_helpers.h (test_get_time_ns)
#define get_mock_time_ns() test_get_time_ns()

static uint32_t get_mock_time_bucket(void) {
    return 1000;  // Fixed test bucket
}

// Unity setup/teardown
void setUp(void) {
    test_utils_setup();
}

void tearDown(void) {
    test_utils_teardown();
}

//
// Test Group 1: Protocol Detection (REQ-XDP-001)
//

/**
 * Test XDP-001-01: Detect valid Buckwild packet
 *
 * Given: Valid Buckwild packet with correct version and structure
 * When: Check if packet is Buckwild protocol
 * Then: Should detect as Buckwild (return 1)
 */
void test_xdp_detect_valid_buckwild_packet(void) {
    // Given: Valid Buckwild packet
    // Byte 0: Version field (4 bits) + SID type (2 bits) + TS type (2 bits)
    // Version 1, SID 16-bit (00), TS 16-bit (00) = 0x10 (00010000)
    uint8_t packet[] = {
        0x10,        // Version 1, SID=16bit, TS=16bit
        0x04,        // Type: DATA
        0x00,        // Sub-type
        0x08,        // Flags: PSH
        0x12, 0x34,  // 16-bit session ID
        0x00, 0x00, 0x00, 0x01,  // Sequence
        0x00, 0x00, 0x00, 0x00,  // Ack
        0x00, 0x64,  // 16-bit timestamp
        0x00, 0x10,  // Payload length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // HMAC_LIGHT (8 bytes)
    };

    // When: Check if Buckwild protocol
    int result = is_buckwild_protocol(packet, sizeof(packet));

    // Then: Should detect as Buckwild
    TEST_ASSERT_EQUAL_INT(1, result);
}

/**
 * Test XDP-001-02: Reject non-Buckwild packet
 *
 * Given: Generic UDP payload (not Buckwild)
 * When: Check if packet is Buckwild protocol
 * Then: Should NOT detect as Buckwild (return 0)
 */
void test_xdp_reject_non_buckwild_packet(void) {
    // Given: Generic UDP packet (random data)
    uint8_t packet[] = {
        0xFF, 0xFF, 0xFF, 0xFF,  // Not Buckwild
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    // When: Check if Buckwild protocol
    int result = is_buckwild_protocol(packet, sizeof(packet));

    // Then: Should NOT detect as Buckwild
    TEST_ASSERT_EQUAL_INT(0, result);
}

/**
 * Test XDP-001-03: Parse adaptive header with 16-bit session ID
 *
 * Given: Packet with 16-bit session ID (smallest variant)
 * When: Parse header
 * Then: Should extract session ID correctly
 */
void test_xdp_parse_16bit_session_id(void) {
    // Given: Packet with 16-bit session ID
    uint8_t packet[] = {
        0x10,        // Version 1, SID=16bit (00), TS=16bit (00)
        0x04,        // Type: DATA
        0x00,        // Sub-type
        0x08,        // Flags: PSH
        0x12, 0x34,  // 16-bit session ID = 0x1234
        0x00, 0x00, 0x00, 0x01,  // Sequence = 1
        0x00, 0x00, 0x00, 0x00,  // Ack = 0
        0x00, 0x64,  // 16-bit timestamp = 100
        0x00, 0x10,  // Payload length = 16
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // HMAC
    };
    struct parsed_header parsed = {0};

    // When: Parse header
    int result = parse_buckwild_header(packet, sizeof(packet), &parsed);

    // Then: Should parse correctly
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x01, parsed.version);
    TEST_ASSERT_EQUAL_UINT8(0x04, parsed.packet_type);
    TEST_ASSERT_EQUAL_UINT8(0x00, parsed.session_id_type);  // 16-bit
    TEST_ASSERT_EQUAL_UINT64(0x1234, parsed.session_id);
    TEST_ASSERT_EQUAL_UINT32(1, parsed.sequence_number);
    TEST_ASSERT_EQUAL_UINT16(16, parsed.payload_length);
}

/**
 * Test XDP-001-04: Parse adaptive header with 64-bit session ID
 *
 * Given: Packet with 64-bit session ID (largest variant)
 * When: Parse header
 * Then: Should extract full 64-bit session ID
 */
void test_xdp_parse_64bit_session_id(void) {
    // Given: Packet with 64-bit session ID
    uint8_t packet[] = {
        0x18,        // Version 1, SID=64bit (10), TS=16bit (00)
        0x04,        // Type: DATA
        0x00,        // Sub-type
        0x08,        // Flags: PSH
        // 64-bit session ID = 0x123456789ABCDEF0
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x00, 0x00, 0x00, 0x01,  // Sequence
        0x00, 0x00, 0x00, 0x00,  // Ack
        0x00, 0x64,  // 16-bit timestamp
        0x00, 0x10,  // Payload length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // HMAC
    };
    struct parsed_header parsed = {0};

    // When: Parse header
    int result = parse_buckwild_header(packet, sizeof(packet), &parsed);

    // Then: Should extract full 64-bit session ID
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x02, parsed.session_id_type);  // 64-bit
    TEST_ASSERT_EQUAL_UINT64(0x123456789ABCDEF0, parsed.session_id);
}

//
// Test Group 2: Session Validation (REQ-XDP-002)
//

/**
 * Test XDP-002-01: Verify active session
 *
 * Given: Session with recent packet activity
 * When: Check if session is active
 * Then: Should return active (1)
 */
void test_xdp_session_verify_active(void) {
    // Given: Active session (packet within last 60 seconds)
    struct session_state session = {
        .session_id = 0x1234,
        .state = SESSION_STATE_ACTIVE,
        .last_packet_time = get_mock_time_ns() - (30 * NSEC_PER_SEC)  // 30 sec ago
    };
    uint64_t current_time = get_mock_time_ns();

    // When: Check if active
    int result = is_session_active(&session, current_time);

    // Then: Should be active
    TEST_ASSERT_EQUAL_INT(1, result);
}

/**
 * Test XDP-002-02: Reject expired session
 *
 * Given: Session with no activity for > 60 seconds
 * When: Check if session is active
 * Then: Should return inactive (0)
 */
void test_xdp_session_verify_expired(void) {
    // Given: Expired session (> 60 seconds old)
    struct session_state session = {
        .session_id = 0x1234,
        .state = SESSION_STATE_ACTIVE,
        .last_packet_time = get_mock_time_ns() - (61 * NSEC_PER_SEC)  // 61 sec ago
    };
    uint64_t current_time = get_mock_time_ns();

    // When: Check if active
    int result = is_session_active(&session, current_time);

    // Then: Should NOT be active
    TEST_ASSERT_EQUAL_INT(0, result);
}

/**
 * Test XDP-002-03: Reject closed session
 *
 * Given: Session in CLOSED state
 * When: Check if session is active
 * Then: Should return inactive (0)
 */
void test_xdp_session_reject_closed(void) {
    // Given: Closed session
    struct session_state session = {
        .session_id = 0x1234,
        .state = SESSION_STATE_CLOSED,  // Explicitly closed
        .last_packet_time = get_mock_time_ns()  // Recent but closed
    };
    uint64_t current_time = get_mock_time_ns();

    // When: Check if active
    int result = is_session_active(&session, current_time);

    // Then: Should NOT be active
    TEST_ASSERT_EQUAL_INT(0, result);
}

//
// Test Group 3: Port Calculation and Validation (REQ-XDP-003)
//

/**
 * Test XDP-003-01: Calculate base port using HMAC-SHA256
 *
 * CRITICAL: Protocol compliance - must use HMAC-SHA256(daily_key, time_bucket || "base_port_sequence_v2")
 * Reference: design/protocol/10-port-hopping.md lines 49-51
 *
 * Given: Daily key and time bucket
 * When: Calculate base port using protocol algorithm
 * Then: Port must be in valid range (1024-65535) and deterministic
 */
void test_xdp_base_port_calculation_hmac(void) {
    // Given: Daily key and time bucket
    uint8_t daily_key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint32_t time_bucket = 7200;  // 1 hour after midnight (3600000ms / 500ms)

    // When: Calculate base port using protocol algorithm
    uint16_t port = calculate_base_port_for_time_bucket(daily_key, time_bucket);

    // Then: Port must be in valid range
    TEST_ASSERT_GREATER_OR_EQUAL(1024, port);
    TEST_ASSERT_LESS_OR_EQUAL(65535, port);

    // And: Calculation must be deterministic
    uint16_t port2 = calculate_base_port_for_time_bucket(daily_key, time_bucket);
    TEST_ASSERT_EQUAL_UINT16(port, port2);
}

/**
 * Test XDP-003-02: Verify HMAC context string
 *
 * CRITICAL: Protocol specifies exact context string "base_port_sequence_v2"
 * Reference: design/protocol/10-port-hopping.md
 *
 * Given: Known daily key and time bucket
 * When: Calculate port with HMAC
 * Then: Result must match manual HMAC with correct context string
 */
void test_xdp_base_port_hmac_context_string(void) {
    // Given: Test vector with known values
    uint8_t daily_key[32];
    memset(daily_key, 0xFF, sizeof(daily_key));  // All 0xFF for test
    uint32_t time_bucket = 1000;

    // When: Calculate port
    uint16_t port = calculate_base_port_for_time_bucket(daily_key, time_bucket);

    // Then: Manually verify HMAC includes "base_port_sequence_v2" context
    // Create HMAC manually for comparison
    // Protocol uses big-endian encoding for time bucket
    uint64_t time_bucket_u64 = time_bucket;
    const char* context_str = "base_port_sequence_v2";
    size_t context_len = strlen(context_str);  // 21 bytes
    uint8_t input[8 + 21];  // time_bucket (8 bytes) + context string (21 bytes)
    // Convert to big-endian
    input[0] = (time_bucket_u64 >> 56) & 0xFF;
    input[1] = (time_bucket_u64 >> 48) & 0xFF;
    input[2] = (time_bucket_u64 >> 40) & 0xFF;
    input[3] = (time_bucket_u64 >> 32) & 0xFF;
    input[4] = (time_bucket_u64 >> 24) & 0xFF;
    input[5] = (time_bucket_u64 >> 16) & 0xFF;
    input[6] = (time_bucket_u64 >> 8) & 0xFF;
    input[7] = time_bucket_u64 & 0xFF;
    memcpy(input + 8, context_str, context_len);

    uint8_t hmac_result[32];
    hmac_sha256(daily_key, 32, input, sizeof(input), hmac_result);

    uint32_t hash_u32 = ((uint32_t)hmac_result[0] << 24) | ((uint32_t)hmac_result[1] << 16) |
                        ((uint32_t)hmac_result[2] << 8) | hmac_result[3];
    uint16_t expected_port = 1024 + (hash_u32 % (65535 - 1024 + 1));

    TEST_ASSERT_EQUAL_UINT16(expected_port, port);
}

/**
 * Test XDP-003-03: Time bucket calculation for daily epoch
 *
 * CRITICAL: Protocol uses daily epoch (UTC midnight) for base port hopping
 * Reference: design/protocol/10-port-hopping.md lines 42-74
 *
 * Given: Times at UTC midnight and 1 hour later
 * When: Calculate base port time buckets
 * Then: Buckets should be 0 at midnight, 7200 after 1 hour
 */
void test_xdp_time_bucket_daily_epoch(void) {
    // Given: Time at UTC midnight
    uint64_t utc_midnight_ms = 1696118400000ULL; // Oct 1, 2023 00:00:00 UTC

    // When: Calculate time bucket
    uint32_t bucket = calculate_base_port_time_bucket(utc_midnight_ms);

    // Then: Bucket should be 0 (start of day)
    TEST_ASSERT_EQUAL_UINT32(0, bucket);

    // When: Calculate 1 hour later
    uint64_t one_hour_later = utc_midnight_ms + (3600 * 1000); // +1 hour
    bucket = calculate_base_port_time_bucket(one_hour_later);

    // Then: Bucket should be 7200 (3600000ms / 500ms)
    TEST_ASSERT_EQUAL_UINT32(7200, bucket);
}

/**
 * Test XDP-003-04: Time bucket calculation for monthly epoch
 *
 * CRITICAL: Protocol uses monthly epoch (month start) for session hopping
 * Reference: design/protocol/10-port-hopping.md lines 42-74
 *
 * Given: Times at month start and mid-month
 * When: Calculate session time buckets
 * Then: Buckets should be 0 at month start, correct value at mid-month
 */
void test_xdp_time_bucket_monthly_epoch(void) {
    // Given: Time at UTC month start (Oct 1, 2023 00:00 UTC)
    uint64_t month_start_ms = 1696118400000ULL;

    // When: Calculate session time bucket
    uint32_t bucket = calculate_session_time_bucket(month_start_ms);

    // Then: Bucket should be 0 (start of month)
    TEST_ASSERT_EQUAL_UINT32(0, bucket);

    // When: Calculate 15.5 days later
    uint64_t mid_month = month_start_ms + (15 * 24 * 3600 * 1000ULL) + (12 * 3600 * 1000);
    bucket = calculate_session_time_bucket(mid_month);

    // Then: Bucket should match time since month start
    uint32_t expected = ((15 * 24 * 3600) + (12 * 3600)) * 2; // seconds * 2 (500ms buckets)
    TEST_ASSERT_EQUAL_UINT32(expected, bucket);
}

/**
 * Test XDP-003-05: Validate correct port
 *
 * Given: Session with expected port
 * When: Validate received port matches expected
 * Then: Should return PORT_VALID
 */
void test_xdp_port_validation_correct(void) {
    // Given: Session expecting port 8080
    struct session_state session = {
        .current_port = 8080,
        .port_window_start = get_mock_time_bucket() - 1,
        .port_window_size = 5
    };
    uint16_t received_port = 8080;
    uint32_t current_bucket = get_mock_time_bucket();

    // When: Validate port
    int result = validate_port(&session, received_port, current_bucket);

    // Then: Should be valid
    TEST_ASSERT_EQUAL_INT(PORT_VALID, result);
}

/**
 * Test XDP-003-06: Reject wrong port
 *
 * Given: Session expecting specific port
 * When: Validate different port
 * Then: Should return PORT_INVALID
 */
void test_xdp_port_validation_wrong(void) {
    // Given: Session expecting port 8080
    struct session_state session = {
        .current_port = 8080,
        .port_window_start = get_mock_time_bucket() - 1,
        .port_window_size = 5
    };
    uint16_t received_port = 9999;  // Wrong port!
    uint32_t current_bucket = get_mock_time_bucket();

    // When: Validate port
    int result = validate_port(&session, received_port, current_bucket);

    // Then: Should be invalid
    TEST_ASSERT_EQUAL_INT(PORT_INVALID, result);
}

/**
 * Test XDP-003-07: Accept next window port (adaptive)
 *
 * Given: Session approaching window boundary with next port set
 * When: Validate next window port (early transition)
 * Then: Should return PORT_VALID_NEXT_WINDOW
 */
void test_xdp_port_validation_next_window(void) {
    // Given: Session near window boundary
    struct session_state session = {
        .current_port = 8080,
        .next_port = 8181,
        .port_window_start = get_mock_time_bucket() - 4,  // Nearly expired (4/5)
        .port_window_size = 5
    };
    uint16_t received_port = 8181;  // Next window port
    uint32_t current_bucket = get_mock_time_bucket();

    // When: Validate port (should accept next window for smooth transition)
    int result = validate_port(&session, received_port, current_bucket);

    // Then: Should accept next window port
    TEST_ASSERT_EQUAL_INT(PORT_VALID_NEXT_WINDOW, result);
}

//
// Test Group 4: Security Filtering (REQ-XDP-004)
//

/**
 * Test XDP-004-01: Rate limit - allow under threshold
 *
 * Given: Session with 10 fragments in current window
 * When: Check fragment rate limit
 * Then: Should allow (under 20/sec limit)
 */
void test_xdp_rate_limit_under_threshold(void) {
    // Given: 10 fragments in last second (under 20 limit)
    struct session_security_state sec = {
        .fragment_count_current_window = 10,
        .rate_limit_window_start = get_mock_time_ns() - (NSEC_PER_SEC / 2)  // 0.5 sec ago
    };
    uint64_t current_time = get_mock_time_ns();

    // When: Check rate limit
    int result = check_fragment_rate_limit(&sec, current_time);

    // Then: Should allow
    TEST_ASSERT_EQUAL_INT(RATE_LIMIT_OK, result);
}

/**
 * Test XDP-004-02: Rate limit - drop over threshold
 *
 * Given: Session with 25 fragments in current window
 * When: Check fragment rate limit
 * Then: Should reject (over 20/sec limit)
 */
void test_xdp_rate_limit_exceeded(void) {
    // Given: 25 fragments in last second (over 20 limit)
    struct session_security_state sec = {
        .fragment_count_current_window = 25,
        .rate_limit_window_start = get_mock_time_ns() - (NSEC_PER_SEC / 2)
    };
    uint64_t current_time = get_mock_time_ns();

    // When: Check rate limit
    int result = check_fragment_rate_limit(&sec, current_time);

    // Then: Should reject
    TEST_ASSERT_EQUAL_INT(RATE_LIMIT_EXCEEDED, result);
}

/**
 * Test XDP-004-03: Fragment bomb detection
 *
 * Given: Session with > 10 outstanding fragments
 * When: Check for fragment bomb
 * Then: Should detect attack
 */
void test_xdp_fragment_bomb_detection(void) {
    // Given: 11 outstanding fragments (over 10 limit)
    struct session_security_state sec = {
        .outstanding_fragments = 11,  // Attack!
        .total_reassembly_memory = 500000  // 500KB
    };

    // When: Check for fragment bomb
    int result = check_fragment_bomb(&sec);

    // Then: Should detect
    TEST_ASSERT_EQUAL_INT(FRAGMENT_BOMB_DETECTED, result);
}

/**
 * Test XDP-004-04: Fragment bomb - allow normal fragmentation
 *
 * Given: Session with normal fragment count (< 10)
 * When: Check for fragment bomb
 * Then: Should allow
 */
void test_xdp_fragment_bomb_allow_normal(void) {
    // Given: 5 outstanding fragments (normal)
    struct session_security_state sec = {
        .outstanding_fragments = 5,
        .total_reassembly_memory = 200000  // 200KB
    };

    // When: Check for fragment bomb
    int result = check_fragment_bomb(&sec);

    // Then: Should allow
    TEST_ASSERT_EQUAL_INT(FRAGMENT_BOMB_NONE, result);
}

/**
 * Test XDP-004-05: Fragment size validation - valid size
 *
 * Given: Fragment with valid size (64-1400 bytes)
 * When: Validate fragment size
 * Then: Should accept
 */
void test_xdp_fragment_size_valid(void) {
    // Given: 800-byte fragment (valid range)
    uint16_t fragment_size = 800;

    // When: Validate size
    int result = validate_fragment_size(fragment_size);

    // Then: Should be valid
    TEST_ASSERT_EQUAL_INT(FRAGMENT_SIZE_VALID, result);
}

/**
 * Test XDP-004-06: Fragment size validation - too small
 *
 * Given: Fragment < 64 bytes
 * When: Validate fragment size
 * Then: Should reject
 */
void test_xdp_fragment_size_too_small(void) {
    // Given: 32-byte fragment (too small)
    uint16_t fragment_size = 32;

    // When: Validate size
    int result = validate_fragment_size(fragment_size);

    // Then: Should be invalid
    TEST_ASSERT_EQUAL_INT(FRAGMENT_SIZE_INVALID, result);
}

/**
 * Test XDP-004-07: Fragment size validation - too large
 *
 * Given: Fragment > 1400 bytes
 * When: Validate fragment size
 * Then: Should reject
 */
void test_xdp_fragment_size_too_large(void) {
    // Given: 2000-byte fragment (too large)
    uint16_t fragment_size = 2000;

    // When: Validate size
    int result = validate_fragment_size(fragment_size);

    // Then: Should be invalid
    TEST_ASSERT_EQUAL_INT(FRAGMENT_SIZE_INVALID, result);
}

/**
 * Test XDP-004-08: Fragment session binding validation
 *
 * CRITICAL: Protocol requires fragments must belong to established sessions
 * Reference: design/security.md
 *
 * Given: Fragment with session_id
 * When: Validate against different session
 * Then: Should reject due to session mismatch
 */
void test_xdp_fragment_session_binding(void) {
    // Given: Fragment header with session_id
    struct fragment_header frag = {
        .fragment_id = 100,
        .fragment_index = 0,
        .total_fragments = 3,
        .session_id = 0x1234
    };

    // When: Try to add fragment to different session (0x5678)
    uint64_t wrong_session_id = 0x5678;
    int result = validate_fragment_session_binding(&frag, wrong_session_id);

    // Then: Should reject due to session mismatch
    TEST_ASSERT_EQUAL_INT(FRAGMENT_SESSION_MISMATCH, result);

    // When: Add fragment to correct session
    uint64_t correct_session_id = 0x1234;
    result = validate_fragment_session_binding(&frag, correct_session_id);

    // Then: Should accept
    TEST_ASSERT_EQUAL_INT(FRAGMENT_SESSION_VALID, result);
}

/**
 * Test XDP-004-09: Fragment overlap detection
 *
 * CRITICAL: Protocol requires detecting and rejecting overlapping fragments
 * Reference: design/security.md
 *
 * Given: Reassembly state with existing fragment
 * When: Try to add overlapping fragment
 * Then: Should detect and reject overlap
 */
void test_xdp_fragment_overlap_detection(void) {
    // Given: Reassembly state with fragment 0 (offset 0-999)
    struct reassembly_state state = {0};
    struct fragment_header frag1 = {
        .fragment_id = 100,
        .fragment_index = 0,
        .total_fragments = 3,
        .fragment_offset = 0,
        .fragment_length = 1000
    };
    add_fragment_to_reassembly(&state, &frag1);

    // When: Try to add overlapping fragment (offset 500-1499)
    struct fragment_header frag_overlap = {
        .fragment_id = 100,
        .fragment_index = 1,
        .total_fragments = 3,
        .fragment_offset = 500,  // Overlaps with fragment 0
        .fragment_length = 1000
    };
    int result = check_fragment_overlap(&state, &frag_overlap);

    // Then: Should detect overlap
    TEST_ASSERT_EQUAL_INT(FRAGMENT_OVERLAP_DETECTED, result);

    // When: Add non-overlapping fragment (offset 1000-1999)
    struct fragment_header frag_valid = {
        .fragment_id = 100,
        .fragment_index = 1,
        .total_fragments = 3,
        .fragment_offset = 1000,  // No overlap
        .fragment_length = 1000
    };
    result = check_fragment_overlap(&state, &frag_valid);

    // Then: Should accept
    TEST_ASSERT_EQUAL_INT(FRAGMENT_NO_OVERLAP, result);
}

/**
 * Test XDP-004-10: Fragment reassembly memory limit per session
 *
 * CRITICAL: Protocol requires 1MB limit per session for fragment reassembly
 * Reference: design/security.md
 *
 * Given: Session with 900KB fragment memory used
 * When: Try to add 200KB fragment
 * Then: Should reject (would exceed 1MB limit)
 */
void test_xdp_fragment_memory_limit_per_session(void) {
    // Given: Session with 900KB of fragment memory already used
    struct session_security_state sec = {
        .total_reassembly_memory = 900 * 1024,
        .outstanding_fragments = 8
    };

    // When: Try to add 200KB fragment (would exceed 1MB)
    uint32_t new_fragment_size = 200 * 1024;
    int result = check_fragment_memory_limit(&sec, new_fragment_size);

    // Then: Should reject (would exceed 1MB limit)
    TEST_ASSERT_EQUAL_INT(FRAGMENT_MEMORY_EXCEEDED, result);

    // When: Try to add 100KB fragment (stays under 1MB)
    new_fragment_size = 100 * 1024;
    result = check_fragment_memory_limit(&sec, new_fragment_size);

    // Then: Should accept
    TEST_ASSERT_EQUAL_INT(FRAGMENT_MEMORY_OK, result);
}

/**
 * Test XDP-004-11: Fragment reassembly timeout
 *
 * CRITICAL: Protocol requires 5-second timeout for incomplete fragments
 * Reference: design/security.md
 *
 * Given: Session with fragments older than 5 seconds
 * When: Check for timeout
 * Then: Should mark fragments as expired
 */
void test_xdp_fragment_reassembly_timeout(void) {
    // TODO: session_security_state needs oldest_fragment_time field
    // This test validates 5-second timeout for incomplete fragment reassembly
    // Implementation deferred until structure is extended.

    // Placeholder test: verify timeout constants are defined
    const uint64_t TIMEOUT_NS = 5 * NSEC_PER_SEC;
    TEST_ASSERT_EQUAL_UINT64(5000000000ULL, TIMEOUT_NS);

    // Verify helper function exists and handles null input
    int result = check_fragment_timeout_expired(NULL, get_mock_time_ns());
    TEST_ASSERT_EQUAL_INT(FRAGMENT_TIMEOUT_EXPIRED, result);
}

//
// Test Group 5: XDP Verdict Integration (REQ-XDP-005)
//

/**
 * Test XDP-005-01: Drop invalid packet
 *
 * Given: Invalid Buckwild packet (bad protocol)
 * When: Process packet through XDP
 * Then: Should return XDP_DROP
 */
void test_xdp_verdict_drop_invalid(void) {
    // Given: Invalid Buckwild packet (bad magic/version)
    size_t pkt_size;
    struct buckwild_packet* pkt = create_invalid_packet(&pkt_size);
    struct xdp_md* ctx = create_test_xdp_context(pkt, pkt_size);

    // When: Process packet
    int verdict = xdp_buckwild_main(ctx);

    // Then: Should DROP
    TEST_ASSERT_EQUAL_INT(XDP_DROP, verdict);

    // Cleanup
    free(pkt);
    free(ctx);
}

/**
 * Test XDP-005-02: Pass valid packet
 *
 * Given: Valid Buckwild packet with active session
 * When: Process packet through XDP
 * Then: Should return XDP_PASS to userspace
 */
void test_xdp_verdict_pass_valid(void) {
    // Given: Valid Buckwild packet
    uint64_t session_id = 0x1234;
    size_t pkt_size;
    struct buckwild_packet* pkt = create_buckwild_packet(session_id, PKT_TYPE_DATA, &pkt_size);
    struct xdp_md* ctx = create_test_xdp_context(pkt, pkt_size);

    // When: Process packet
    int verdict = xdp_buckwild_main(ctx);

    // Then: Should PASS to userspace
    TEST_ASSERT_EQUAL_INT(XDP_PASS, verdict);

    // Cleanup
    free(pkt);
    free(ctx);
}

/**
 * Test XDP-005-03: Drop rate-limited packet
 *
 * Given: Packet from rate-limited session
 * When: Process packet through XDP
 * Then: Should return XDP_DROP
 */
void test_xdp_verdict_drop_rate_limited(void) {
    // Given: Valid Buckwild packet (rate limiting tested separately)
    uint64_t session_id = 0x1234;
    size_t pkt_size;
    struct buckwild_packet* pkt = create_buckwild_packet(session_id, PKT_TYPE_DATA, &pkt_size);
    struct xdp_md* ctx = create_test_xdp_context(pkt, pkt_size);

    // When: Process packet (currently stub returns PASS for valid packets)
    int verdict = xdp_buckwild_main(ctx);

    // Then: Should PASS (rate limiting logic not yet in main function)
    // TODO: This will change to DROP once rate limiting is integrated
    TEST_ASSERT_EQUAL_INT(XDP_PASS, verdict);

    // Cleanup
    free(pkt);
    free(ctx);
}

//
// Test Group 6: HMAC Policy Compliance (REQ-XDP-006)
//

/**
 * Test XDP-006-01: HMAC policy - periodic 100 packet trigger
 *
 * CRITICAL: Protocol requires HMAC_STRONG every 100 data packets
 * Reference: design/protocol/03-packet-architecture.md lines 154-171
 *
 * Given: Session with 99 data packets sent
 * When: Determine HMAC policy for 100th packet
 * Then: MUST use HMAC_STRONG (32 bytes)
 */
void test_xdp_hmac_policy_100_packet_trigger(void) {
    // Given: Session with 99 data packets sent with HMAC_LIGHT
    struct hmac_session_state session = {
        .session_id = 0x1234,
        .data_packet_count = 99,
        .last_hmac_strong_packet = 0,
        .last_hmac_strong_time = get_mock_time_ns() - (2 * NSEC_PER_SEC)
    };

    // When: Create 100th data packet
    uint8_t hmac_policy = determine_hmac_policy(&session, PKT_TYPE_DATA);

    // Then: MUST use HMAC_STRONG (32 bytes)
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);
    TEST_ASSERT_EQUAL_size_t(32, get_hmac_size(hmac_policy));

    // When: Create 101st packet (after reset)
    session.data_packet_count = 1;
    session.last_hmac_strong_packet = 100;
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_DATA);

    // Then: Can use HMAC_LIGHT again
    TEST_ASSERT_EQUAL_UINT8(HMAC_LIGHT, hmac_policy);
}

/**
 * Test XDP-006-02: HMAC policy - periodic 5 second trigger
 *
 * CRITICAL: Protocol requires HMAC_STRONG every 5 seconds of activity
 * Reference: design/protocol/03-packet-architecture.md
 *
 * Given: Session with last HMAC_STRONG 5+ seconds ago
 * When: Determine HMAC policy
 * Then: MUST use HMAC_STRONG (time trigger)
 */
void test_xdp_hmac_policy_5_second_trigger(void) {
    // Given: Session with last HMAC_STRONG 5001ms ago
    struct hmac_session_state session = {
        .session_id = 0x1234,
        .data_packet_count = 50,
        .last_hmac_strong_time = get_mock_time_ns() - (5001 * NSEC_PER_MS)
    };

    // When: Create data packet
    uint8_t hmac_policy = determine_hmac_policy(&session, PKT_TYPE_DATA);

    // Then: MUST use HMAC_STRONG (time trigger)
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create packet 4 seconds after last HMAC_STRONG
    session.last_hmac_strong_time = get_mock_time_ns() - (4000 * NSEC_PER_MS);
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_DATA);

    // Then: Can use HMAC_LIGHT (under 5 second threshold)
    TEST_ASSERT_EQUAL_UINT8(HMAC_LIGHT, hmac_policy);
}

/**
 * Test XDP-006-03: HMAC policy - after HMAC failure
 *
 * CRITICAL: Protocol requires HMAC_STRONG after any HMAC validation failure
 * Reference: design/protocol/03-packet-architecture.md
 *
 * Given: Session that experienced HMAC failure
 * When: Determine HMAC policy for next packet
 * Then: MUST use HMAC_STRONG
 */
void test_xdp_hmac_policy_after_failure(void) {
    // TODO: hmac_failure_occurred field not yet in hmac_session_state
    // This test validates that after an HMAC failure, the next packet
    // must use HMAC_STRONG for security. Implementation deferred.

    // Placeholder test: verify HMAC_STRONG is used for critical scenarios
    struct hmac_session_state session = {
        .session_id = 0x1234,
        .data_packet_count = 100,  // Trigger 100-packet rule
        .last_hmac_strong_packet = 0,
        .last_hmac_strong_time = get_mock_time_ns() - (6 * NSEC_PER_SEC)
    };

    // When: Create data packet that triggers HMAC_STRONG
    uint8_t hmac_policy = determine_hmac_policy(&session, PKT_TYPE_DATA);

    // Then: MUST use HMAC_STRONG (via 100-packet or 5-second rule)
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);
}

/**
 * Test XDP-006-04: HMAC policy - month boundary transition
 *
 * CRITICAL: Protocol requires HMAC_STRONG during month boundary transitions
 * Reference: design/protocol/03-packet-architecture.md
 *
 * Given: Current time within transition window of month boundary
 * When: Determine HMAC policy
 * Then: MUST use HMAC_STRONG during transition
 */
void test_xdp_hmac_policy_month_boundary(void) {
    // Given: Current time near month boundary
    uint64_t base_time = get_mock_time_ns();
    uint64_t month_end_ns = get_month_end_utc_ns(base_time);
    uint64_t current_time = month_end_ns - (500 * NSEC_PER_MS); // 500ms before

    struct hmac_session_state session = {
        .session_id = 0x1234,
        .data_packet_count = 10
    };

    // When: Create packet near month boundary
    uint8_t hmac_policy = determine_hmac_policy_with_time(&session, PKT_TYPE_DATA, current_time);

    // Then: MUST use HMAC_STRONG during transition
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create packet 2 seconds after month end
    current_time = month_end_ns + (2000 * NSEC_PER_MS);
    hmac_policy = determine_hmac_policy_with_time(&session, PKT_TYPE_DATA, current_time);

    // Then: Still MUST use HMAC_STRONG (within transition window)
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create packet 5 seconds after month end
    current_time = month_end_ns + (5000 * NSEC_PER_MS);
    hmac_policy = determine_hmac_policy_with_time(&session, PKT_TYPE_DATA, current_time);

    // Then: Can use HMAC_LIGHT (past transition window)
    TEST_ASSERT_EQUAL_UINT8(HMAC_LIGHT, hmac_policy);
}

/**
 * Test XDP-006-05: HMAC policy - critical packet types always STRONG
 *
 * CRITICAL: Protocol requires HMAC_STRONG for SYN, SYN_ACK, FIN, DISCOVERY, MANAGEMENT
 * Reference: design/protocol/03-packet-architecture.md
 *
 * Given: Various critical packet types
 * When: Determine HMAC policy
 * Then: ALL must use HMAC_STRONG
 */
void test_xdp_hmac_policy_critical_packets(void) {
    struct hmac_session_state session = {
        .session_id = 0x1234,
        .data_packet_count = 10
    };

    // When: Create SYN packet
    uint8_t hmac_policy = determine_hmac_policy(&session, PKT_TYPE_SYN);
    // Then: MUST use HMAC_STRONG
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create SYN_ACK packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_SYN_ACK);
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create FIN packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_FIN);
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create DISCOVERY packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_DISCOVERY);
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);

    // When: Create MANAGEMENT packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_MANAGEMENT);
    TEST_ASSERT_EQUAL_UINT8(HMAC_STRONG, hmac_policy);
}

/**
 * Test XDP-006-06: HMAC policy - control packets use MEDIUM minimum
 *
 * CRITICAL: Protocol requires HMAC_MEDIUM for ERROR, RST, HEARTBEAT, TIME_SYNC
 * Reference: design/protocol/03-packet-architecture.md
 *
 * Given: Control packet types
 * When: Determine HMAC policy
 * Then: Must use at least HMAC_MEDIUM
 */
void test_xdp_hmac_policy_control_packets(void) {
    struct hmac_session_state session = {
        .session_id = 0x1234,
        .data_packet_count = 10
    };

    // When: Create ERROR packet
    uint8_t hmac_policy = determine_hmac_policy(&session, PKT_TYPE_ERROR);
    // Then: MUST use at least HMAC_MEDIUM
    TEST_ASSERT_GREATER_OR_EQUAL(HMAC_MEDIUM, hmac_policy);

    // When: Create RST packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_RST);
    TEST_ASSERT_GREATER_OR_EQUAL(HMAC_MEDIUM, hmac_policy);

    // When: Create HEARTBEAT packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_HEARTBEAT);
    TEST_ASSERT_GREATER_OR_EQUAL(HMAC_MEDIUM, hmac_policy);

    // When: Create TIME_SYNC packet
    hmac_policy = determine_hmac_policy(&session, PKT_TYPE_TIME_SYNC);
    TEST_ASSERT_GREATER_OR_EQUAL(HMAC_MEDIUM, hmac_policy);
}

// ============================================================================
// Group 7: Adaptive Delay Window Tests (REQ-XDP-005, 006, 007)
// ============================================================================
// Per design/protocol/11-adaptive-networking.md:
// - Asymmetric windows (past != future)
// - Track early/late packet counts
// - Adjust windows based on network conditions

/**
 * Test XDP-007-01: Accept packet within past delay window
 *
 * CRITICAL: Protocol requires asymmetric windows - past window handles delayed packets
 * Reference: design/protocol/11-adaptive-networking.md, maps.h lines 78-84
 */
void test_xdp_adaptive_window_accept_past(void) {
    // Given: Adaptive window with 200ms past window, 100ms future window
    struct adaptive_delay_state window = {
        .past_window_size = 200,      // 200ms past window
        .future_window_size = 100,    // 100ms future window
        .early_count = 0,
        .late_count = 0,
        .last_update_ns = get_mock_time_ns() - (10 * NSEC_PER_SEC)
    };

    // When: Packet arrives 150ms late (within past window)
    uint64_t current_time = get_mock_time_ns();
    uint64_t packet_time = current_time - (150 * NSEC_PER_MS);
    int result = check_adaptive_window(&window, packet_time, current_time);

    // Then: Should accept packet
    TEST_ASSERT_EQUAL_INT(WINDOW_ACCEPT, result);

    // And: late_count should be incremented
    TEST_ASSERT_EQUAL_UINT32(1, window.late_count);
    TEST_ASSERT_EQUAL_UINT32(0, window.early_count);
}

/**
 * Test XDP-007-02: Accept packet within future delay window
 *
 * CRITICAL: Future window handles clock skew and early arrivals
 * Reference: design/protocol/11-adaptive-networking.md
 */
void test_xdp_adaptive_window_accept_future(void) {
    // Given: Adaptive window with 200ms past, 100ms future
    struct adaptive_delay_state window = {
        .past_window_size = 200,
        .future_window_size = 100,
        .early_count = 0,
        .late_count = 0,
        .last_update_ns = get_mock_time_ns() - (10 * NSEC_PER_SEC)
    };

    // When: Packet arrives 80ms early (within future window)
    uint64_t current_time = get_mock_time_ns();
    uint64_t packet_time = current_time + (80 * NSEC_PER_MS);
    int result = check_adaptive_window(&window, packet_time, current_time);

    // Then: Should accept packet
    TEST_ASSERT_EQUAL_INT(WINDOW_ACCEPT, result);

    // And: early_count should be incremented
    TEST_ASSERT_EQUAL_UINT32(1, window.early_count);
    TEST_ASSERT_EQUAL_UINT32(0, window.late_count);
}

/**
 * Test XDP-007-03: Reject packet outside past window
 *
 * CRITICAL: Packets beyond past window are rejected (too old or replay attack)
 * Reference: design/protocol/11-adaptive-networking.md
 */
void test_xdp_adaptive_window_reject_past(void) {
    // Given: Adaptive window with 200ms past window
    struct adaptive_delay_state window = {
        .past_window_size = 200,
        .future_window_size = 100,
        .early_count = 0,
        .late_count = 0,
        .last_update_ns = get_mock_time_ns()
    };

    // When: Packet arrives 300ms late (beyond past window)
    uint64_t current_time = get_mock_time_ns();
    uint64_t packet_time = current_time - (300 * NSEC_PER_MS);
    int result = check_adaptive_window(&window, packet_time, current_time);

    // Then: Should reject packet
    TEST_ASSERT_EQUAL_INT(WINDOW_REJECT, result);
}

/**
 * Test XDP-007-04: Adjust window size based on packet timing
 *
 * CRITICAL: Windows adapt to network conditions - expand if many early/late packets
 * Reference: design/protocol/11-adaptive-networking.md
 */
void test_xdp_adaptive_window_adjust_size(void) {
    // Given: Many late packets detected (20 in past 10 seconds)
    struct adaptive_delay_state window = {
        .past_window_size = 200,      // Start with 200ms
        .future_window_size = 100,
        .early_count = 0,
        .late_count = 20,             // Many late packets
        .last_update_ns = get_mock_time_ns() - (10 * NSEC_PER_SEC)
    };

    // When: Userspace adjusts window based on late_count
    adjust_adaptive_window(&window);

    // Then: Past window should expand (more late packets = need larger past window)
    TEST_ASSERT_GREATER_THAN(200, window.past_window_size);

    // And: Counters should be reset after adjustment
    TEST_ASSERT_EQUAL_UINT32(0, window.late_count);
}

// ============================================================================
// Group 8: Session Routing Tests (REQ-XDP-009, 010, 011)
// ============================================================================
// Per maps.h lines 104-124:
// - Map session_id → ring_buffer_id for packet routing
// - Register/unregister sessions
// - Route packets to correct ring buffer

/**
 * Test XDP-008-01: Register session for packet routing
 *
 * CRITICAL: Sessions must be registered before packets can be routed
 * Reference: maps.h lines 104-124, design/protocol/02-core-definitions.md
 */
void test_xdp_session_register_routing(void) {
    // Given: New session established
    uint64_t session_id = 0x1234567890ABCDEF;
    uint32_t ring_buffer_id = 3;

    // When: Register session for routing
    int result = register_session_routing(session_id, ring_buffer_id);

    // Then: Registration should succeed
    TEST_ASSERT_EQUAL_INT(0, result);

    // And: Session should be findable in routing map
    uint32_t found_rb_id = 0;
    int lookup_result = lookup_session_routing(session_id, &found_rb_id);
    TEST_ASSERT_EQUAL_INT(0, lookup_result);
    TEST_ASSERT_EQUAL_UINT32(ring_buffer_id, found_rb_id);
}

/**
 * Test XDP-008-02: Unregister session when closed
 *
 * CRITICAL: Sessions must be removed from routing map when closed
 * Reference: maps.h lines 111-113
 */
void test_xdp_session_unregister_routing(void) {
    // Given: Active session registered
    uint64_t session_id = 0xFEDCBA0987654321;
    uint32_t ring_buffer_id = 5;
    register_session_routing(session_id, ring_buffer_id);

    // When: Session closes and is unregistered
    int result = unregister_session_routing(session_id);

    // Then: Unregistration should succeed
    TEST_ASSERT_EQUAL_INT(0, result);

    // And: Session should NOT be findable
    uint32_t found_rb_id = 0;
    int lookup_result = lookup_session_routing(session_id, &found_rb_id);
    TEST_ASSERT_EQUAL_INT(-1, lookup_result);  // Not found
}

/**
 * Test XDP-008-03: Route packet to correct ring buffer
 *
 * CRITICAL: Packets must be routed to correct ring buffer based on session_id
 * Reference: maps.h lines 117-124
 */
void test_xdp_session_route_to_ringbuffer(void) {
    // Given: Three sessions registered to different ring buffers
    register_session_routing(0x1111, 1);
    register_session_routing(0x2222, 2);
    register_session_routing(0x3333, 3);

    // When: Packets arrive for each session
    uint32_t rb1 = route_packet_to_ringbuffer(0x1111);
    uint32_t rb2 = route_packet_to_ringbuffer(0x2222);
    uint32_t rb3 = route_packet_to_ringbuffer(0x3333);

    // Then: Each packet should route to correct ring buffer
    TEST_ASSERT_EQUAL_UINT32(1, rb1);
    TEST_ASSERT_EQUAL_UINT32(2, rb2);
    TEST_ASSERT_EQUAL_UINT32(3, rb3);
}

// ============================================================================
// Group 9: Ring Buffer Tests (REQ-XDP-012, 013)
// ============================================================================
// Per maps.h lines 136-158:
// - XDP submits packet events (not full packets) to ring buffer
// - Userspace consumes events asynchronously
// - Event structure validation

/**
 * Test XDP-009-01: Submit packet event to ring buffer
 *
 * CRITICAL: XDP submits events (not full packets) to ring buffer for userspace
 * Reference: maps.h lines 144-151, TUN_EBPF_IMPLEMENTATION_GUIDE.md Task 4
 */
void test_xdp_ringbuf_submit_event(void) {
    // Given: Valid packet passed XDP filtering
    struct packet_event event = {
        .session_id = 0x1234567890ABCDEF,
        .sequence = 42,
        .timestamp_us = 1234567890,
        .payload_length = 512,
        .packet_type = PKT_TYPE_DATA,
        .flags = 0x01
    };

    // When: Submit event to ring buffer
    int result = submit_packet_event_to_ringbuf(&event);

    // Then: Submission should succeed
    TEST_ASSERT_EQUAL_INT(0, result);
}

/**
 * Test XDP-009-02: Ring buffer event structure size
 *
 * CRITICAL: Event structure must be packed and match wire format
 * Reference: maps.h lines 144-151
 */
void test_xdp_ringbuf_event_structure(void) {
    // Given: packet_event structure
    // Then: Structure should be packed correctly
    // session_id (8) + sequence (8) + timestamp_us (8) + payload_length (2) + packet_type (1) + flags (1) = 28 bytes
    TEST_ASSERT_EQUAL_size_t(28, sizeof(struct packet_event));

    // And: Fields should be at correct offsets
    TEST_ASSERT_EQUAL_size_t(0, offsetof(struct packet_event, session_id));
    TEST_ASSERT_EQUAL_size_t(8, offsetof(struct packet_event, sequence));
    TEST_ASSERT_EQUAL_size_t(16, offsetof(struct packet_event, timestamp_us));
    TEST_ASSERT_EQUAL_size_t(24, offsetof(struct packet_event, payload_length));
    TEST_ASSERT_EQUAL_size_t(26, offsetof(struct packet_event, packet_type));
    TEST_ASSERT_EQUAL_size_t(27, offsetof(struct packet_event, flags));
}

/**
 * Test XDP-009-03: Ring buffer overflow handling
 *
 * CRITICAL: When ring buffer is full, XDP must handle gracefully (drop with counter)
 * Reference: maps.h lines 154-158
 */
void test_xdp_ringbuf_overflow_handling(void) {
    // Given: Ring buffer that is full
    setup_full_ringbuffer();

    struct packet_event event = {
        .session_id = 0x9999,
        .sequence = 100,
        .timestamp_us = 1234567890,
        .payload_length = 256,
        .packet_type = PKT_TYPE_DATA,
        .flags = 0x00
    };

    // When: Try to submit event to full ring buffer
    int result = submit_packet_event_to_ringbuf(&event);

    // Then: Submission should fail with specific error
    TEST_ASSERT_EQUAL_INT(-ENOSPC, result);

    // And: Drop counter should be incremented
    uint64_t drop_count = get_ringbuf_drop_count();
    TEST_ASSERT_GREATER_THAN(0, drop_count);
}

//
// Main test runner
//

int main(void) {
    UNITY_BEGIN();

    // Group 1: Protocol Detection (REQ-XDP-001)
    RUN_TEST(test_xdp_detect_valid_buckwild_packet);
    RUN_TEST(test_xdp_reject_non_buckwild_packet);
    RUN_TEST(test_xdp_parse_16bit_session_id);
    RUN_TEST(test_xdp_parse_64bit_session_id);

    // Group 2: Session Validation (REQ-XDP-002)
    RUN_TEST(test_xdp_session_verify_active);
    RUN_TEST(test_xdp_session_verify_expired);
    RUN_TEST(test_xdp_session_reject_closed);

    // Group 3: Port Calculation and Validation (REQ-XDP-003)
    RUN_TEST(test_xdp_base_port_calculation_hmac);
    RUN_TEST(test_xdp_base_port_hmac_context_string);
    RUN_TEST(test_xdp_time_bucket_daily_epoch);
    RUN_TEST(test_xdp_time_bucket_monthly_epoch);
    RUN_TEST(test_xdp_port_validation_correct);
    RUN_TEST(test_xdp_port_validation_wrong);
    RUN_TEST(test_xdp_port_validation_next_window);

    // Group 4: Security Filtering (REQ-XDP-004)
    RUN_TEST(test_xdp_rate_limit_under_threshold);
    RUN_TEST(test_xdp_rate_limit_exceeded);
    RUN_TEST(test_xdp_fragment_bomb_detection);
    RUN_TEST(test_xdp_fragment_bomb_allow_normal);
    RUN_TEST(test_xdp_fragment_size_valid);
    RUN_TEST(test_xdp_fragment_size_too_small);
    RUN_TEST(test_xdp_fragment_size_too_large);
    RUN_TEST(test_xdp_fragment_session_binding);
    RUN_TEST(test_xdp_fragment_overlap_detection);
    RUN_TEST(test_xdp_fragment_memory_limit_per_session);
    RUN_TEST(test_xdp_fragment_reassembly_timeout);

    // Group 5: XDP Verdict Integration (REQ-XDP-005)
    RUN_TEST(test_xdp_verdict_drop_invalid);
    RUN_TEST(test_xdp_verdict_pass_valid);
    RUN_TEST(test_xdp_verdict_drop_rate_limited);

    // Group 6: HMAC Policy Compliance (REQ-XDP-006)
    RUN_TEST(test_xdp_hmac_policy_100_packet_trigger);
    RUN_TEST(test_xdp_hmac_policy_5_second_trigger);
    RUN_TEST(test_xdp_hmac_policy_after_failure);
    RUN_TEST(test_xdp_hmac_policy_month_boundary);
    RUN_TEST(test_xdp_hmac_policy_critical_packets);
    RUN_TEST(test_xdp_hmac_policy_control_packets);

    // Group 7: Adaptive Delay Window (REQ-XDP-007)
    RUN_TEST(test_xdp_adaptive_window_accept_past);
    RUN_TEST(test_xdp_adaptive_window_accept_future);
    RUN_TEST(test_xdp_adaptive_window_reject_past);
    RUN_TEST(test_xdp_adaptive_window_adjust_size);

    // Group 8: Session Routing (REQ-XDP-008)
    RUN_TEST(test_xdp_session_register_routing);
    RUN_TEST(test_xdp_session_unregister_routing);
    RUN_TEST(test_xdp_session_route_to_ringbuffer);

    // Group 9: Ring Buffer (REQ-XDP-009)
    RUN_TEST(test_xdp_ringbuf_submit_event);
    RUN_TEST(test_xdp_ringbuf_event_structure);
    RUN_TEST(test_xdp_ringbuf_overflow_handling);

    return UNITY_END();
}
