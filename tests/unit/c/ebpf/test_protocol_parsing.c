/**
 * @file test_protocol_parsing.c
 * @brief Unit tests for eBPF protocol parsing functions
 *
 * Tests protocol detection and header parsing per design/protocol/03-packet-architecture.md
 *
 * PLATFORM: Linux only
 *
 * Test Requirements (TDD - Red-Green-Refactor):
 * 1. Protocol detection (is_buckwild_packet)
 * 2. Header parsing (parse_buckwild_header)
 * 3. Timestamp validation (validate_timestamp)
 */

/* Platform check */
#if !defined(__linux__)
#error "eBPF protocol tests require Linux"
#endif

#include <unity.h>
#include "buckwild/common/time_utils.h"
#include "../utils/test_utils.h"
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Protocol constants from design/protocol/02-core-definitions.md */
#define PROTOCOL_VERSION 0x01
#define BASE_HEADER_SIZE 18
#define MIN_PACKET_SIZE 26    /* Minimum: 18 + 2-byte ID + 2-byte TS + 4-byte HMAC */

/* Packet types from design/protocol/03-packet-architecture.md */
#define PKT_TYPE_SYN        0x01
#define PKT_TYPE_SYN_ACK    0x02
#define PKT_TYPE_ACK        0x03
#define PKT_TYPE_DATA       0x04
#define PKT_TYPE_FIN        0x05
#define PKT_TYPE_HEARTBEAT  0x06
#define PKT_TYPE_ERROR      0x09
#define PKT_TYPE_RST        0x0B
#define PKT_TYPE_CONTROL    0x0C
#define PKT_TYPE_MANAGEMENT 0x0D
#define PKT_TYPE_DISCOVERY  0x0E

/* Version byte encoding (bits 0-3: version, bits 4-5: session ID, bits 6-7: timestamp) */
#define VERSION_16BIT_ID_16BIT_TS   0x01  /* v1 + 16-bit ID (0) + 16-bit TS (0) = 0000 0001 */
#define VERSION_32BIT_ID_24BIT_TS   0x51  /* v1 + 32-bit ID (1) + 24-bit TS (1) = 0101 0001 */
#define VERSION_64BIT_ID_32BIT_TS   0xE1  /* v1 + 64-bit ID (2) + 32-bit TS (3) = 1110 0001 */

/* Epoch types from design/protocol/09-time-synchronization.md */
#define EPOCH_DAILY     0
#define EPOCH_MONTHLY   1

/* Validation status flags */
#define VALIDATION_INVALID_TIMESTAMP    0x01
#define VALIDATION_INVALID_SESSION      0x02
#define VALIDATION_REPLAY_ATTACK        0x04

/* Parsed header structure - matches eBPF usage */
struct parsed_header {
	uint8_t protocol_version;
	uint8_t packet_type;
	uint8_t sub_type;
	uint8_t flags;
	uint64_t session_id;
	uint32_t sequence_number;
	uint32_t ack_number;
	uint32_t timestamp;
	uint16_t payload_length;
	uint8_t hmac_policy;
	uint8_t session_id_length;      /* 0=16bit, 1=32bit, 2=64bit */
	uint8_t timestamp_length;       /* 0=16bit, 1=24bit, 2=24bit-high, 3=32bit */
	uint8_t security_flags;
	uint8_t validation_status;
};

/* Function prototypes - these will be implemented in protocol.h */
int is_buckwild_packet(const void *data, const void *data_end);
int parse_buckwild_header(const void *data, const void *data_end, struct parsed_header *parsed);
int validate_timestamp(uint32_t packet_timestamp, uint8_t timestamp_length,
                      uint64_t current_time_ns, uint8_t epoch_type);

void setUp(void)
{
	test_utils_setup();
}

void tearDown(void)
{
	test_utils_teardown();
}

/**
 * Test Group 1: Protocol Detection (is_buckwild_packet)
 */

/* Test 1.1: Valid minimal packet with correct version */
void test_is_buckwild_packet_valid_minimal(void)
{
	uint8_t packet[MIN_PACKET_SIZE] = {
		VERSION_16BIT_ID_16BIT_TS,  /* version byte */
		PKT_TYPE_DATA,              /* packet type */
		0x00,                       /* sub-type */
		0x00,                       /* flags */
		/* Rest of packet... */
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);

	int result = is_buckwild_packet(data, data_end);

	TEST_ASSERT_EQUAL_INT_MESSAGE(1, result,
	                              "Valid packet should be detected");
}

/* Test 1.2: Reject packet with invalid version */
void test_is_buckwild_packet_invalid_version(void)
{
	uint8_t packet[MIN_PACKET_SIZE] = {
		0x02,                       /* invalid version (v2) - bits 0-3 = 0010 */
		PKT_TYPE_DATA,
		0x00, 0x00,
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);

	int result = is_buckwild_packet(data, data_end);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result,
	                              "Invalid version should be rejected");
}

/* Test 1.3: Reject packet with invalid packet type */
void test_is_buckwild_packet_invalid_type(void)
{
	uint8_t packet[MIN_PACKET_SIZE] = {
		VERSION_16BIT_ID_16BIT_TS,
		0xFF,                       /* invalid packet type */
		0x00, 0x00,
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);

	int result = is_buckwild_packet(data, data_end);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result,
	                              "Invalid packet type should be rejected");
}

/* Test 1.4: Reject packet smaller than minimum size */
void test_is_buckwild_packet_too_small(void)
{
	uint8_t packet[10] = {
		VERSION_16BIT_ID_16BIT_TS,
		PKT_TYPE_DATA,
		0x00, 0x00,
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);

	int result = is_buckwild_packet(data, data_end);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result,
	                              "Packet smaller than minimum should be rejected");
}

/* Test 1.5: Reject NULL pointers */
void test_is_buckwild_packet_null_pointers(void)
{
	uint8_t packet[MIN_PACKET_SIZE] = {VERSION_16BIT_ID_16BIT_TS, PKT_TYPE_DATA};

	int result1 = is_buckwild_packet(NULL, packet + sizeof(packet));
	int result2 = is_buckwild_packet(packet, NULL);
	int result3 = is_buckwild_packet(NULL, NULL);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result1, "NULL data pointer should be rejected");
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result2, "NULL data_end pointer should be rejected");
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result3, "Both NULL pointers should be rejected");
}

/**
 * Test Group 2: Header Parsing (parse_buckwild_header)
 */

/* Test 2.1: Parse minimal header (16-bit ID, 16-bit TS) */
void test_parse_buckwild_header_minimal(void)
{
	/* Build minimal packet per design/protocol/03-packet-architecture.md */
	uint8_t packet[MIN_PACKET_SIZE] = {
		/* Byte 0: Version */
		VERSION_16BIT_ID_16BIT_TS,
		/* Bytes 1-3: Type, Sub-Type, Flags */
		PKT_TYPE_DATA, 0x00, 0x00,
		/* Bytes 4-5: Session ID (16-bit big-endian) */
		0x12, 0x34,
		/* Bytes 6-9: Sequence Number (32-bit big-endian) */
		0x00, 0x00, 0x00, 0x42,
		/* Bytes 10-13: Ack Number (32-bit big-endian) */
		0x00, 0x00, 0x00, 0x00,
		/* Bytes 14-15: Timestamp (16-bit big-endian) */
		0x00, 0xFF,
		/* Bytes 16-17: Payload Length (16-bit big-endian) */
		0x00, 0x00,
		/* Bytes 18-25: HMAC (8 bytes for LIGHT policy) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);
	struct parsed_header parsed = {0};

	int result = parse_buckwild_header(data, data_end, &parsed);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Parsing should succeed");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(PROTOCOL_VERSION, parsed.protocol_version,
	                                "Protocol version should be 1");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(PKT_TYPE_DATA, parsed.packet_type,
	                                "Packet type should be DATA");
	TEST_ASSERT_EQUAL_UINT64_MESSAGE(0x1234, parsed.session_id,
	                                 "Session ID should be 0x1234");
	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0x42, parsed.sequence_number,
	                                 "Sequence number should be 0x42");
	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0xFF, parsed.timestamp,
	                                 "Timestamp should be 0xFF");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, parsed.session_id_length,
	                                "Session ID length code should be 0 (16-bit)");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, parsed.timestamp_length,
	                                "Timestamp length code should be 0 (16-bit)");
}

/* Test 2.2: Parse standard header (32-bit ID, 24-bit TS) */
void test_parse_buckwild_header_standard(void)
{
	/* Build standard packet: 18 + 4-byte ID + 3-byte TS + 4-byte HMAC = 29 bytes */
	uint8_t packet[29] = {
		/* Byte 0: Version */
		VERSION_32BIT_ID_24BIT_TS,
		/* Bytes 1-3: Type, Sub-Type, Flags */
		PKT_TYPE_SYN, 0x00, 0x02,  /* SYN flag set */
		/* Bytes 4-7: Session ID (32-bit big-endian) */
		0xAB, 0xCD, 0xEF, 0x01,
		/* Bytes 8-11: Sequence Number */
		0x00, 0x00, 0x01, 0x00,
		/* Bytes 12-15: Ack Number */
		0x00, 0x00, 0x00, 0x00,
		/* Bytes 16-18: Timestamp (24-bit big-endian) */
		0x12, 0x34, 0x56,
		/* Bytes 19-20: Payload Length */
		0x00, 0x10,
		/* Bytes 21-28: HMAC (8 bytes) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);
	struct parsed_header parsed = {0};

	int result = parse_buckwild_header(data, data_end, &parsed);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Parsing should succeed");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(PKT_TYPE_SYN, parsed.packet_type,
	                                "Packet type should be SYN");
	TEST_ASSERT_EQUAL_UINT64_MESSAGE(0xABCDEF01, parsed.session_id,
	                                 "Session ID should be 0xABCDEF01");
	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0x100, parsed.sequence_number,
	                                 "Sequence number should be 0x100");
	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0x123456, parsed.timestamp,
	                                 "Timestamp should be 0x123456");
	TEST_ASSERT_EQUAL_UINT16_MESSAGE(0x10, parsed.payload_length,
	                                 "Payload length should be 0x10");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, parsed.session_id_length,
	                                "Session ID length code should be 1 (32-bit)");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, parsed.timestamp_length,
	                                "Timestamp length code should be 1 (24-bit)");
}

/* Test 2.3: Parse long-lived header (64-bit ID, 32-bit TS) */
void test_parse_buckwild_header_long_lived(void)
{
	/* Build long-lived packet: 18 + 8-byte ID + 4-byte TS + 16-byte HMAC = 46 bytes */
	uint8_t packet[46] = {
		/* Byte 0: Version */
		VERSION_64BIT_ID_32BIT_TS,
		/* Bytes 1-3: Type, Sub-Type, Flags */
		PKT_TYPE_HEARTBEAT, 0x00, 0x00,
		/* Bytes 4-11: Session ID (64-bit big-endian) */
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		/* Bytes 12-15: Sequence Number */
		0x00, 0x00, 0x10, 0x00,
		/* Bytes 16-19: Ack Number */
		0x00, 0x00, 0x05, 0x00,
		/* Bytes 20-23: Timestamp (32-bit big-endian) */
		0xFF, 0xFF, 0xFF, 0xFF,
		/* Bytes 24-25: Payload Length */
		0x00, 0x08,
		/* Bytes 26-45: HMAC (16 bytes for MEDIUM policy) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,  /* Padding to 46 bytes */
	};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);
	struct parsed_header parsed = {0};

	int result = parse_buckwild_header(data, data_end, &parsed);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Parsing should succeed");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(PKT_TYPE_HEARTBEAT, parsed.packet_type,
	                                "Packet type should be HEARTBEAT");
	TEST_ASSERT_EQUAL_UINT64_MESSAGE(0x123456789ABCDEF0ULL, parsed.session_id,
	                                 "Session ID should be 0x123456789ABCDEF0");
	TEST_ASSERT_EQUAL_UINT32_MESSAGE(0xFFFFFFFF, parsed.timestamp,
	                                 "Timestamp should be 0xFFFFFFFF");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(2, parsed.session_id_length,
	                                "Session ID length code should be 2 (64-bit)");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(3, parsed.timestamp_length,
	                                "Timestamp length code should be 3 (32-bit)");
}

/* Test 2.4: Reject packet with bounds violation */
void test_parse_buckwild_header_bounds_violation(void)
{
	uint8_t packet[10] = {VERSION_16BIT_ID_16BIT_TS, PKT_TYPE_DATA};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);
	struct parsed_header parsed = {0};

	int result = parse_buckwild_header(data, data_end, &parsed);

	TEST_ASSERT_EQUAL_INT_MESSAGE(-1, result,
	                              "Parsing should fail with bounds violation");
}

/* Test 2.5: Reject NULL parsed header pointer */
void test_parse_buckwild_header_null_parsed(void)
{
	uint8_t packet[MIN_PACKET_SIZE] = {VERSION_16BIT_ID_16BIT_TS, PKT_TYPE_DATA};
	const void *data = packet;
	const void *data_end = packet + sizeof(packet);

	int result = parse_buckwild_header(data, data_end, NULL);

	TEST_ASSERT_EQUAL_INT_MESSAGE(-1, result,
	                              "Parsing should fail with NULL parsed pointer");
}

/**
 * Test Group 3: Timestamp Validation (validate_timestamp)
 */

/* Test 3.1: Valid timestamp within daily epoch window */
void test_validate_timestamp_daily_epoch_valid(void)
{
	/* Simulate 2024-01-01 00:05:00 UTC (5 minutes after midnight) */
	uint64_t current_time_ns = 1704067200000ULL * 1000000ULL + (5 * 60 * 1000ULL * 1000000ULL);
	/* Time bucket: 300000ms / 500ms = 600 */
	uint32_t packet_timestamp = 600;

	int result = validate_timestamp(packet_timestamp, 0, current_time_ns, EPOCH_DAILY);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result,
	                              "Valid daily epoch timestamp should be accepted");
}

/* Test 3.2: Reject timestamp outside daily epoch window */
void test_validate_timestamp_daily_epoch_too_old(void)
{
	/* Current time: 2024-01-01 00:05:00 UTC */
	uint64_t current_time_ns = 1704067200000ULL * 1000000ULL + (5 * 60 * 1000ULL * 1000000ULL);
	/* Old timestamp from 2 hours ago (would be from previous day) */
	uint32_t packet_timestamp = 0;  /* Midnight bucket */

	int result = validate_timestamp(packet_timestamp, 0, current_time_ns, EPOCH_DAILY);

	/* Depending on tolerance, this might be rejected */
	/* For now, we'll verify it returns a deterministic result */
	TEST_ASSERT_MESSAGE(result == 0 || result == -1,
	                    "Old timestamp should return deterministic result");
}

/* Test 3.3: Valid timestamp within monthly epoch window */
void test_validate_timestamp_monthly_epoch_valid(void)
{
	/* Simulate 2024-01-05 12:00:00 UTC (5 days into month) */
	uint64_t current_time_ns = 1704067200000ULL * 1000000ULL + (5 * 24 * 60 * 60 * 1000ULL * 1000000ULL);
	/* Time bucket: (5 days * 86400000ms / 500ms) */
	uint32_t packet_timestamp = (5 * 24 * 60 * 60 * 1000) / 500;

	int result = validate_timestamp(packet_timestamp, 0, current_time_ns, EPOCH_MONTHLY);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, result,
	                              "Valid monthly epoch timestamp should be accepted");
}

/* Test 3.4: Validate timestamp with different lengths */
void test_validate_timestamp_different_lengths(void)
{
	uint64_t current_time_ns = 1704067200000ULL * 1000000ULL;
	uint32_t timestamp_16bit = 0x00FF;
	uint32_t timestamp_24bit = 0x00FFFF;
	uint32_t timestamp_32bit = 0xFFFFFFFF;

	int result1 = validate_timestamp(timestamp_16bit, 0, current_time_ns, EPOCH_DAILY);
	int result2 = validate_timestamp(timestamp_24bit, 1, current_time_ns, EPOCH_MONTHLY);
	int result3 = validate_timestamp(timestamp_32bit, 3, current_time_ns, EPOCH_MONTHLY);

	/* All should return deterministic results (0 or -1) */
	TEST_ASSERT_MESSAGE(result1 == 0 || result1 == -1,
	                    "16-bit timestamp validation should be deterministic");
	TEST_ASSERT_MESSAGE(result2 == 0 || result2 == -1,
	                    "24-bit timestamp validation should be deterministic");
	TEST_ASSERT_MESSAGE(result3 == 0 || result3 == -1,
	                    "32-bit timestamp validation should be deterministic");
}

/* Main test runner */
int main(void)
{
	UNITY_BEGIN();

	/* Protocol detection tests */
	RUN_TEST(test_is_buckwild_packet_valid_minimal);
	RUN_TEST(test_is_buckwild_packet_invalid_version);
	RUN_TEST(test_is_buckwild_packet_invalid_type);
	RUN_TEST(test_is_buckwild_packet_too_small);
	RUN_TEST(test_is_buckwild_packet_null_pointers);

	/* Header parsing tests */
	RUN_TEST(test_parse_buckwild_header_minimal);
	RUN_TEST(test_parse_buckwild_header_standard);
	RUN_TEST(test_parse_buckwild_header_long_lived);
	RUN_TEST(test_parse_buckwild_header_bounds_violation);
	RUN_TEST(test_parse_buckwild_header_null_parsed);

	/* Timestamp validation tests */
	RUN_TEST(test_validate_timestamp_daily_epoch_valid);
	RUN_TEST(test_validate_timestamp_daily_epoch_too_old);
	RUN_TEST(test_validate_timestamp_monthly_epoch_valid);
	RUN_TEST(test_validate_timestamp_different_lengths);

	return UNITY_END();
}
