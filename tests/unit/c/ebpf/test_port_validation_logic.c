/**
 * @file test_port_validation_logic.c
 * @brief Unit tests for port validation logic (Tier 1 - rootless)
 *
 * Tests pure C logic from src/ebpf/c/include/logic/port_validation.h
 * No BPF helpers, no root required, runs in userspace.
 *
 * Following TDD: Tests written BEFORE XDP program implementation
 */

#include <unity.h>
#include "src/ebpf/c/include/logic/port_validation.h"
#include <stdint.h>
#include <stdbool.h>

/* Test fixtures */
void setUp(void) {
	/* Called before each test */
}

void tearDown(void) {
	/* Called after each test */
}

/**
 * Test: Current bucket port validation
 *
 * Scenario: Packet arrives on current time bucket port
 * Expected: Validation succeeds, is_late=false, is_early=false
 */
void test_port_current_bucket(void)
{
	uint16_t port = 12345;
	uint16_t current = 12345;
	uint16_t past[] = {11111, 11112};
	uint16_t future[] = {13333, 13334};
	bool is_late, is_early;

	bool result = validate_port_with_window(
		port, current, past, future, 2, 2,
		&is_late, &is_early
	);

	TEST_ASSERT_TRUE_MESSAGE(result, "Current bucket port should be valid");
	TEST_ASSERT_FALSE_MESSAGE(is_late, "Should not be marked as late");
	TEST_ASSERT_FALSE_MESSAGE(is_early, "Should not be marked as early");
}

/**
 * Test: Past window port validation (late packet)
 *
 * Scenario: Packet arrives on past bucket port (within window)
 * Expected: Validation succeeds, is_late=true
 */
void test_port_past_window(void)
{
	uint16_t port = 11111;  /* Past bucket port */
	uint16_t current = 12345;
	uint16_t past[] = {11111, 11112, 11113};
	uint16_t future[] = {13333};
	bool is_late, is_early;

	bool result = validate_port_with_window(
		port, current, past, future, 3, 1,
		&is_late, &is_early
	);

	TEST_ASSERT_TRUE_MESSAGE(result, "Past window port should be valid");
	TEST_ASSERT_TRUE_MESSAGE(is_late, "Should be marked as late");
	TEST_ASSERT_FALSE_MESSAGE(is_early, "Should not be marked as early");
}

/**
 * Test: Future window port validation (early packet)
 *
 * Scenario: Packet arrives on future bucket port (within window)
 * Expected: Validation succeeds, is_early=true
 */
void test_port_future_window(void)
{
	uint16_t port = 13333;  /* Future bucket port */
	uint16_t current = 12345;
	uint16_t past[] = {11111};
	uint16_t future[] = {13333, 13334};
	bool is_late, is_early;

	bool result = validate_port_with_window(
		port, current, past, future, 1, 2,
		&is_late, &is_early
	);

	TEST_ASSERT_TRUE_MESSAGE(result, "Future window port should be valid");
	TEST_ASSERT_FALSE_MESSAGE(is_late, "Should not be marked as late");
	TEST_ASSERT_TRUE_MESSAGE(is_early, "Should be marked as early");
}

/**
 * Test: Invalid port (outside all windows)
 *
 * Scenario: Packet arrives on port not in any window
 * Expected: Validation fails
 */
void test_port_invalid(void)
{
	uint16_t port = 9999;  /* Not in any window */
	uint16_t current = 12345;
	uint16_t past[] = {11111, 11112};
	uint16_t future[] = {13333, 13334};
	bool is_late, is_early;

	bool result = validate_port_with_window(
		port, current, past, future, 2, 2,
		&is_late, &is_early
	);

	TEST_ASSERT_FALSE_MESSAGE(result, "Invalid port should fail validation");
	TEST_ASSERT_FALSE_MESSAGE(is_late, "Should not be marked as late");
	TEST_ASSERT_FALSE_MESSAGE(is_early, "Should not be marked as early");
}

/**
 * Test: Empty past window
 *
 * Scenario: No past window ports (past_count=0)
 * Expected: Only current and future ports valid
 */
void test_port_empty_past_window(void)
{
	uint16_t current = 12345;
	uint16_t past[] = {};
	uint16_t future[] = {13333};
	bool is_late, is_early;

	/* Test current port */
	bool result = validate_port_with_window(
		12345, current, past, future, 0, 1,
		&is_late, &is_early
	);
	TEST_ASSERT_TRUE_MESSAGE(result, "Current port should be valid");

	/* Test that past port is now invalid */
	result = validate_port_with_window(
		11111, current, past, future, 0, 1,
		&is_late, &is_early
	);
	TEST_ASSERT_FALSE_MESSAGE(result, "Past port should be invalid with empty window");
}

/**
 * Test: Empty future window
 *
 * Scenario: No future window ports (future_count=0)
 * Expected: Only current and past ports valid
 */
void test_port_empty_future_window(void)
{
	uint16_t current = 12345;
	uint16_t past[] = {11111};
	uint16_t future[] = {};
	bool is_late, is_early;

	/* Test that future port is invalid */
	bool result = validate_port_with_window(
		13333, current, past, future, 1, 0,
		&is_late, &is_early
	);
	TEST_ASSERT_FALSE_MESSAGE(result, "Future port should be invalid with empty window");

	/* Test past port still works */
	result = validate_port_with_window(
		11111, current, past, future, 1, 0,
		&is_late, &is_early
	);
	TEST_ASSERT_TRUE_MESSAGE(result, "Past port should still be valid");
	TEST_ASSERT_TRUE(is_late);
}

/**
 * Test: is_port_current() helper
 */
void test_is_port_current(void)
{
	TEST_ASSERT_TRUE(is_port_current(12345, 12345));
	TEST_ASSERT_FALSE(is_port_current(12345, 54321));
	TEST_ASSERT_FALSE(is_port_current(0, 12345));
}

/**
 * Test: is_port_in_past_window() helper
 */
void test_is_port_in_past_window(void)
{
	uint16_t past[] = {11111, 11112, 11113, 11114};

	TEST_ASSERT_TRUE(is_port_in_past_window(11111, past, 4));
	TEST_ASSERT_TRUE(is_port_in_past_window(11114, past, 4));
	TEST_ASSERT_FALSE(is_port_in_past_window(64999, past, 4));
	TEST_ASSERT_FALSE(is_port_in_past_window(11111, past, 0));  /* Empty array */
}

/**
 * Test: is_port_in_future_window() helper
 */
void test_is_port_in_future_window(void)
{
	uint16_t future[] = {13333, 13334, 13335};

	TEST_ASSERT_TRUE(is_port_in_future_window(13333, future, 3));
	TEST_ASSERT_TRUE(is_port_in_future_window(13335, future, 3));
	TEST_ASSERT_FALSE(is_port_in_future_window(64999, future, 3));
	TEST_ASSERT_FALSE(is_port_in_future_window(13333, future, 0));  /* Empty array */
}

/**
 * Test: Large window arrays (boundary test)
 *
 * Scenario: Maximum window size (16 buckets)
 * Expected: All ports validated correctly
 */
void test_port_max_window_size(void)
{
	uint16_t current = 12345;
	uint16_t past[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	uint16_t future[16] = {101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116};
	bool is_late, is_early;

	/* Test first past port */
	bool result = validate_port_with_window(1, current, past, future, 16, 16, &is_late, &is_early);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(is_late);

	/* Test last past port */
	result = validate_port_with_window(16, current, past, future, 16, 16, &is_late, &is_early);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(is_late);

	/* Test first future port */
	result = validate_port_with_window(101, current, past, future, 16, 16, &is_late, &is_early);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(is_early);

	/* Test last future port */
	result = validate_port_with_window(116, current, past, future, 16, 16, &is_late, &is_early);
	TEST_ASSERT_TRUE(result);
	TEST_ASSERT_TRUE(is_early);
}

/* Main test runner */
int main(void)
{
	UNITY_BEGIN();

	/* Core validation tests */
	RUN_TEST(test_port_current_bucket);
	RUN_TEST(test_port_past_window);
	RUN_TEST(test_port_future_window);
	RUN_TEST(test_port_invalid);

	/* Edge cases */
	RUN_TEST(test_port_empty_past_window);
	RUN_TEST(test_port_empty_future_window);
	RUN_TEST(test_port_max_window_size);

	/* Helper function tests */
	RUN_TEST(test_is_port_current);
	RUN_TEST(test_is_port_in_past_window);
	RUN_TEST(test_is_port_in_future_window);

	return UNITY_END();
}
