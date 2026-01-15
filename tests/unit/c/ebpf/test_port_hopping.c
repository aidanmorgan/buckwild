/**
 * @file test_port_hopping.c
 * @brief Unit tests for port hopping calculation and validation
 *
 * Tests the core port hopping logic per design/protocol/10-port-hopping.md
 *
 * PLATFORM: Linux only
 *
 * Test Requirements:
 * - 500ms time bucket calculation
 * - Daily epoch (base port for connection establishment)
 * - Monthly epoch (session-specific ports)
 * - Port range validation (1024-65535)
 * - HMAC-based port derivation
 */

/* Platform check */
#if !defined(__linux__)
#error "Port hopping tests require Linux"
#endif

#include <unity.h>
#include "buckwild/common/time_utils.h"
#include "buckwild/common/port_hopping.h"
#include "../utils/test_utils.h"
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Constants from design/protocol/02-core-definitions.md */
#define HOP_INTERVAL_MS 500
#define MIN_PORT BUCKWILD_PORT_MIN
#define MAX_PORT BUCKWILD_PORT_MAX
#define MILLISECONDS_PER_DAY 86400000ULL
#define NANOSECONDS_PER_MS 1000000ULL
#define NANOSECONDS_PER_DAY (MILLISECONDS_PER_DAY * NANOSECONDS_PER_MS)

void setUp(void)
{
	test_utils_setup();
}

void tearDown(void)
{
	test_utils_teardown();
}

/**
 * Test 1.1: Daily time bucket calculation
 *
 * Given: A timestamp in nanoseconds since epoch
 * When: Calculating daily time bucket
 * Then: Returns 500ms buckets since UTC midnight
 */
void test_calculate_daily_time_bucket_midnight(void)
{
	uint64_t midnight_ns = 1704067200000ULL * NANOSECONDS_PER_MS; /* 2024-01-01 00:00:00 UTC */
	uint32_t bucket;

	bucket = buckwild_calculate_daily_epoch_bucket(midnight_ns);

	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, bucket,
					 "Midnight should be bucket 0");
}

void test_calculate_daily_time_bucket_first_interval(void)
{
	uint64_t time_ns = (1704067200000ULL + 500) * NANOSECONDS_PER_MS; /* 00:00:00.500 UTC */
	uint32_t bucket;

	bucket = buckwild_calculate_daily_epoch_bucket(time_ns);

	TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, bucket,
					 "500ms after midnight should be bucket 1");
}

void test_calculate_daily_time_bucket_one_second(void)
{
	uint64_t time_ns = (1704067200000ULL + 1000) * NANOSECONDS_PER_MS; /* 00:00:01.000 UTC */
	uint32_t bucket;

	bucket = buckwild_calculate_daily_epoch_bucket(time_ns);

	TEST_ASSERT_EQUAL_UINT32_MESSAGE(2, bucket,
					 "1 second after midnight should be bucket 2");
}

void test_calculate_daily_time_bucket_wraps_at_day_boundary(void)
{
	uint64_t day_start = 1704067200000ULL * NANOSECONDS_PER_MS; /* 2024-01-01 00:00:00 UTC */
	uint64_t next_day = day_start + NANOSECONDS_PER_DAY + (500 * NANOSECONDS_PER_MS);
	uint32_t bucket;

	bucket = buckwild_calculate_daily_epoch_bucket(next_day);

	/* Should wrap to bucket 1 (500ms into next day) */
	TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, bucket,
					 "Should wrap at day boundary");
}

/**
 * Test 1.2: Monthly time bucket calculation
 *
 * Given: A timestamp in nanoseconds since epoch
 * When: Calculating monthly time bucket
 * Then: Returns 500ms buckets since month start
 */
void test_calculate_monthly_time_bucket_month_start(void)
{
	uint64_t month_start_ns = 1704067200000ULL * NANOSECONDS_PER_MS; /* 2024-01-01 00:00:00 UTC */
	uint32_t bucket;

	bucket = buckwild_calculate_monthly_epoch_bucket(month_start_ns);

	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, bucket,
					 "Month start should be bucket 0");
}

void test_calculate_monthly_time_bucket_one_day_in(void)
{
	uint64_t month_start = 1704067200000ULL * NANOSECONDS_PER_MS;
	uint64_t one_day_later = month_start + NANOSECONDS_PER_DAY;
	uint32_t expected_bucket;
	uint32_t bucket;

	/* One day = 86400 seconds = 86400000 ms / 500 = 172800 buckets */
	expected_bucket = 172800;

	bucket = buckwild_calculate_monthly_epoch_bucket(one_day_later);

	TEST_ASSERT_EQUAL_UINT32_MESSAGE(expected_bucket, bucket,
					 "One day should be 172800 buckets");
}

/**
 * Test 1.3: Base port calculation
 *
 * Given: Daily key and time bucket
 * When: Calculating base port for connection establishment
 * Then: Returns port in valid range (1024-65535)
 */
void test_derive_base_port_returns_valid_port(void)
{
	uint8_t daily_key[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	};
	uint32_t time_bucket = 100;
	uint16_t port;

	port = buckwild_derive_base_port(daily_key, sizeof(daily_key), time_bucket);

	TEST_ASSERT_GREATER_OR_EQUAL_UINT16_MESSAGE(MIN_PORT, port,
						    "Port must be >= 1024");
	TEST_ASSERT_LESS_OR_EQUAL_UINT16_MESSAGE(MAX_PORT, port,
						 "Port must be <= 65535");
}

void test_derive_base_port_different_buckets_different_ports(void)
{
	uint8_t daily_key[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	};
	uint16_t port1, port2;

	port1 = buckwild_derive_base_port(daily_key, sizeof(daily_key), 100);
	port2 = buckwild_derive_base_port(daily_key, sizeof(daily_key), 101);

	TEST_ASSERT_NOT_EQUAL_UINT16_MESSAGE(port1, port2,
					     "Different buckets should give different ports");
}

void test_derive_base_port_same_bucket_same_port(void)
{
	uint8_t daily_key[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	};
	uint16_t port1, port2;

	port1 = buckwild_derive_base_port(daily_key, sizeof(daily_key), 100);
	port2 = buckwild_derive_base_port(daily_key, sizeof(daily_key), 100);

	TEST_ASSERT_EQUAL_UINT16_MESSAGE(port1, port2,
					 "Same bucket should give same port");
}

/**
 * Test 1.4: Session port calculation
 *
 * Given: Session-specific key and time bucket
 * When: Calculating session port
 * Then: Returns port in valid range
 */
void test_derive_session_port_returns_valid_port(void)
{
	uint8_t session_key[32] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
	};
	uint32_t time_bucket = 500;
	uint16_t port;

	port = buckwild_derive_session_port(session_key, sizeof(session_key),
					    time_bucket);

	TEST_ASSERT_GREATER_OR_EQUAL_UINT16_MESSAGE(MIN_PORT, port,
						    "Port must be >= 1024");
	TEST_ASSERT_LESS_OR_EQUAL_UINT16_MESSAGE(MAX_PORT, port,
						 "Port must be <= 65535");
}

void test_derive_session_port_different_keys_different_ports(void)
{
	uint8_t key1[32] = {
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
	};
	uint8_t key2[32] = {
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
	};
	uint32_t time_bucket = 500;
	uint16_t port1, port2;

	port1 = buckwild_derive_session_port(key1, sizeof(key1), time_bucket);
	port2 = buckwild_derive_session_port(key2, sizeof(key2), time_bucket);

	TEST_ASSERT_NOT_EQUAL_UINT16_MESSAGE(port1, port2,
					     "Different keys should give different ports");
}

/* Main test runner */
int main(void)
{
	UNITY_BEGIN();

	/* Daily time bucket tests */
	RUN_TEST(test_calculate_daily_time_bucket_midnight);
	RUN_TEST(test_calculate_daily_time_bucket_first_interval);
	RUN_TEST(test_calculate_daily_time_bucket_one_second);
	RUN_TEST(test_calculate_daily_time_bucket_wraps_at_day_boundary);

	/* Monthly time bucket tests */
	RUN_TEST(test_calculate_monthly_time_bucket_month_start);
	RUN_TEST(test_calculate_monthly_time_bucket_one_day_in);

	/* Base port derivation tests */
	RUN_TEST(test_derive_base_port_returns_valid_port);
	RUN_TEST(test_derive_base_port_different_buckets_different_ports);
	RUN_TEST(test_derive_base_port_same_bucket_same_port);

	/* Session port derivation tests */
	RUN_TEST(test_derive_session_port_returns_valid_port);
	RUN_TEST(test_derive_session_port_different_keys_different_ports);

	return UNITY_END();
}
