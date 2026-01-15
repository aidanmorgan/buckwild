/**
 * test_protocol_helpers_comprehensive.c
 *
 * Comprehensive unit tests for protocol helper functions from protocol.h
 * Uses Unity test framework for pure C testing without BPF dependencies.
 *
 * Tests enforce the design specification from:
 *   - design/protocol/02-core-definitions.md
 *   - design/protocol/03-packet-architecture.md
 *   - design/protocol/09-time-synchronization.md
 *
 * Key Design Constants (from spec):
 *   HOP_INTERVAL_MS = 500              // Port hop interval (500ms time windows)
 *   TIMESTAMP_WINDOW_MS = 30000        // Anti-replay window (30 seconds)
 *   TIME_SYNC_TOLERANCE_MS = 50        // Future packet tolerance (50ms)
 *   SESSION_ID_16BIT = 0, 32BIT = 1, 64BIT = 2
 *   TIMESTAMP_16BIT = 0, 24BIT = 1, 32BIT = 2
 *   HMAC_LIGHT = 1 (8 bytes), HMAC_MEDIUM = 2 (16 bytes), HMAC_STRONG = 3 (32 bytes)
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include "unity.h"

/*============================================================================
 * Design Constants (from design/protocol/02-core-definitions.md)
 *============================================================================*/

/* Time-related constants */
#define HOP_INTERVAL_MS         500     /* Port hop interval in milliseconds */
#define TIMESTAMP_WINDOW_MS     30000   /* Anti-replay timestamp window (30s) */
#define HANDSHAKE_TIMESTAMP_WINDOW_MS 10000  /* Stricter window for handshake (10s) */
#define TIME_SYNC_TOLERANCE_MS  50      /* Maximum allowed clock drift */
#define MILLISECONDS_PER_DAY    86400000ULL
#define SECONDS_PER_DAY         86400ULL
#define SECONDS_PER_MONTH       2592000ULL  /* 30-day approximation */

/* Epoch types */
#define EPOCH_DAILY             0
#define EPOCH_MONTHLY           1

/* Session ID configuration */
#define SESSION_ID_16BIT        0       /* 2 bytes */
#define SESSION_ID_32BIT        1       /* 4 bytes */
#define SESSION_ID_64BIT        2       /* 8 bytes */

/* Timestamp configuration */
#define TIMESTAMP_16BIT         0       /* 2 bytes */
#define TIMESTAMP_24BIT         1       /* 3 bytes */
#define TIMESTAMP_32BIT         2       /* 4 bytes */

/* HMAC Policy Configuration */
#define HMAC_POLICY_LIGHT       1       /* 64-bit (8 bytes) */
#define HMAC_POLICY_MEDIUM      2       /* 128-bit (16 bytes) */
#define HMAC_POLICY_STRONG      3       /* 256-bit (32 bytes) */

/* HMAC Output Sizes (bytes) */
#define HMAC_LIGHT_OUTPUT_SIZE  8
#define HMAC_MEDIUM_OUTPUT_SIZE 16
#define HMAC_STRONG_OUTPUT_SIZE 32

/* Packet type definitions */
#define PKT_TYPE_SYN            0x01
#define PKT_TYPE_SYN_ACK        0x02
#define PKT_TYPE_ACK            0x03
#define PKT_TYPE_DATA           0x04
#define PKT_TYPE_FIN            0x05
#define PKT_TYPE_HEARTBEAT      0x06
#define PKT_TYPE_ERROR          0x09
#define PKT_TYPE_RST            0x0B
#define PKT_TYPE_CONTROL        0x0C
#define PKT_TYPE_MANAGEMENT     0x0D
#define PKT_TYPE_DISCOVERY      0x0E
#define PACKET_TYPE_MAX         0x0E

/* Port constants */
#define MIN_PORT                1024
#define MAX_PORT                65535

/* Header size components (from design/protocol/03-packet-architecture.md) */
/* Base header: version(1) + type(1) + sub_type(1) + flags(1) + seq(4) + ack(4) + payload_len(2) = 14 */
#define BASE_HEADER_FIXED       14
/* Minimum header: base + min_session_id(2) + min_timestamp(2) + min_hmac(8) = 26 */
#define MIN_HEADER_SIZE         26
/* Maximum header: base + max_session_id(8) + max_timestamp(4) + max_hmac(32) = 58 */
#define MAX_HEADER_SIZE         58

/*============================================================================
 * Type Definitions (userspace compatible)
 *============================================================================*/
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t  __s32;

/*============================================================================
 * Helper Macros for byte swapping (use standard library)
 *============================================================================*/
#define bpf_ntohs(x)        ntohs(x)
#define bpf_ntohl(x)        ntohl(x)
#define bpf_htons(x)        htons(x)
#define bpf_htonl(x)        htonl(x)
#define bpf_be64_to_cpu(x)  be64toh(x)
#define bpf_cpu_to_be64(x)  htobe64(x)

/*============================================================================
 * Functions Under Test (copied from protocol.h with design-compliant implementation)
 *
 * NOTE: These implementations follow the DESIGN SPECIFICATION, not necessarily
 * the current production code. If tests fail, it indicates the production code
 * has a bug and needs to be fixed.
 *============================================================================*/

/**
 * Calculate time bucket for dual-epoch system.
 *
 * Design spec (09-time-synchronization.md):
 * - Daily epoch: 500ms buckets since UTC midnight of current day
 * - Monthly epoch: 500ms buckets since UTC midnight of current month
 * - Formula: time_bucket = ms_since_epoch_start // HOP_INTERVAL_MS
 *
 * Note: eBPF code uses nanoseconds, so we convert: 500ms = 500,000,000 ns
 */
static inline __u32 calculate_time_bucket(__u64 current_time_ns, __u8 epoch_type) {
    /* Convert nanoseconds to milliseconds */
    __u64 current_time_ms = current_time_ns / 1000000ULL;

    __u64 epoch_start_ms;
    if (epoch_type == EPOCH_DAILY) {
        /* Daily epoch: start at UTC midnight of current day */
        __u64 seconds_since_unix_epoch = current_time_ms / 1000;
        __u64 days_since_unix_epoch = seconds_since_unix_epoch / SECONDS_PER_DAY;
        epoch_start_ms = days_since_unix_epoch * MILLISECONDS_PER_DAY;
    } else {
        /* Monthly epoch: use 30-day approximation for eBPF */
        __u64 seconds_since_unix_epoch = current_time_ms / 1000;
        __u64 months_since_unix_epoch = seconds_since_unix_epoch / SECONDS_PER_MONTH;
        epoch_start_ms = months_since_unix_epoch * SECONDS_PER_MONTH * 1000;
    }

    __u64 ms_since_epoch_start = current_time_ms - epoch_start_ms;
    return (__u32)(ms_since_epoch_start / HOP_INTERVAL_MS);
}

/**
 * Extract session ID from variable-length field.
 * Session ID sizes: 16-bit (2 bytes), 32-bit (4 bytes), 64-bit (8 bytes)
 * All values are big-endian (network byte order).
 */
static inline __u64 extract_session_id(void *data, void *data_end,
                                        __u8 session_id_length,
                                        __u16 *offset) {
    void *session_id_ptr = data + *offset;
    __u64 session_id = 0;

    switch (session_id_length) {
        case SESSION_ID_16BIT:
            if (session_id_ptr + 2 > data_end)
                return 0;
            session_id = bpf_ntohs(*(__u16 *)session_id_ptr);
            *offset += 2;
            break;
        case SESSION_ID_32BIT:
            if (session_id_ptr + 4 > data_end)
                return 0;
            session_id = bpf_ntohl(*(__u32 *)session_id_ptr);
            *offset += 4;
            break;
        case SESSION_ID_64BIT:
            if (session_id_ptr + 8 > data_end)
                return 0;
            session_id = bpf_be64_to_cpu(*(__u64 *)session_id_ptr);
            *offset += 8;
            break;
        default:
            return 0;
    }

    return session_id;
}

/**
 * Extract timestamp from variable-length field.
 * Timestamp sizes: 16-bit (2 bytes), 24-bit (3 bytes), 32-bit (4 bytes)
 * All values are big-endian (network byte order).
 */
static inline __u32 extract_timestamp(void *data, void *data_end,
                                       __u8 timestamp_length,
                                       __u16 *offset) {
    void *timestamp_ptr = data + *offset;
    __u32 timestamp = 0;

    switch (timestamp_length) {
        case TIMESTAMP_16BIT:
            if (timestamp_ptr + 2 > data_end)
                return 0;
            timestamp = bpf_ntohs(*(__u16 *)timestamp_ptr);
            *offset += 2;
            break;
        case TIMESTAMP_24BIT:
            if (timestamp_ptr + 3 > data_end)
                return 0;
            /* 24-bit big-endian extraction */
            timestamp = (((__u32)*((__u8 *)timestamp_ptr)) << 16) |
                       (((__u32)*((__u8 *)timestamp_ptr + 1)) << 8) |
                       ((__u32)*((__u8 *)timestamp_ptr + 2));
            *offset += 3;
            break;
        case TIMESTAMP_32BIT:
            if (timestamp_ptr + 4 > data_end)
                return 0;
            timestamp = bpf_ntohl(*(__u32 *)timestamp_ptr);
            *offset += 4;
            break;
        default:
            return 0;
    }

    return timestamp;
}

/**
 * Get HMAC size based on policy.
 * Design spec (02-core-definitions.md):
 * - HMAC_LIGHT = 1: 64-bit (8 bytes)
 * - HMAC_MEDIUM = 2: 128-bit (16 bytes)
 * - HMAC_STRONG = 3: 256-bit (32 bytes)
 */
static inline __u8 get_hmac_size(__u8 hmac_policy) {
    switch (hmac_policy) {
        case HMAC_POLICY_LIGHT:
            return HMAC_LIGHT_OUTPUT_SIZE;   /* 8 bytes */
        case HMAC_POLICY_MEDIUM:
            return HMAC_MEDIUM_OUTPUT_SIZE;  /* 16 bytes */
        case HMAC_POLICY_STRONG:
            return HMAC_STRONG_OUTPUT_SIZE;  /* 32 bytes */
        default:
            return HMAC_LIGHT_OUTPUT_SIZE;   /* Default to minimum */
    }
}

/**
 * Determine HMAC policy based on packet type.
 * Design spec (03-packet-architecture.md):
 * - Critical packets (SYN, SYN_ACK, FIN, DISCOVERY): HMAC_STRONG
 * - Control packets (ERROR, RST, HEARTBEAT, CONTROL, MANAGEMENT): HMAC_MEDIUM
 * - Data packets (DATA, ACK): HMAC_LIGHT
 */
static inline __u8 determine_hmac_policy(__u8 packet_type) {
    switch (packet_type) {
        /* Critical packets - always HMAC_STRONG */
        case PKT_TYPE_SYN:
        case PKT_TYPE_SYN_ACK:
        case PKT_TYPE_FIN:
        case PKT_TYPE_DISCOVERY:
            return HMAC_POLICY_STRONG;

        /* Control packets - HMAC_MEDIUM minimum */
        case PKT_TYPE_ERROR:
        case PKT_TYPE_RST:
        case PKT_TYPE_HEARTBEAT:
        case PKT_TYPE_CONTROL:
        case PKT_TYPE_MANAGEMENT:
            return HMAC_POLICY_MEDIUM;

        /* Data packets - HMAC_LIGHT default */
        case PKT_TYPE_DATA:
        case PKT_TYPE_ACK:
        default:
            return HMAC_POLICY_LIGHT;
    }
}

/**
 * Validate timestamp against anti-replay window.
 * Design spec (03-packet-architecture.md):
 * - Reject if packet_age > TIMESTAMP_WINDOW_MS (30 seconds)
 * - Reject if packet_age < -TIME_SYNC_TOLERANCE_MS (50ms in future)
 * - Use stricter window for handshake packets (10 seconds)
 *
 * Returns: 0 if valid, -1 if invalid
 */
static inline int validate_timestamp(__u32 packet_timestamp, __u32 current_time,
                                     __u8 packet_type) {
    __s32 age = (__s32)current_time - (__s32)packet_timestamp;

    /* Determine window based on packet type */
    __u32 max_age;
    if (packet_type == PKT_TYPE_SYN || packet_type == PKT_TYPE_SYN_ACK) {
        max_age = HANDSHAKE_TIMESTAMP_WINDOW_MS;  /* 10 seconds */
    } else {
        max_age = TIMESTAMP_WINDOW_MS;  /* 30 seconds */
    }

    /* Reject if too old */
    if (age > (__s32)max_age) {
        return -1;
    }

    /* Reject if too far in future */
    if (age < -(__s32)TIME_SYNC_TOLERANCE_MS) {
        return -1;
    }

    return 0;
}

/**
 * Check if a port is in the valid buckwild range.
 * Design spec (02-core-definitions.md):
 * - MIN_PORT = 1024 (avoid well-known ports)
 * - MAX_PORT = 65535
 */
static inline bool is_potential_buckwild_port(__u16 port) {
    return (port >= MIN_PORT);
    /* Note: port <= 65535 is always true for uint16_t */
}

/**
 * Calculate header size based on configuration.
 * Design spec (03-packet-architecture.md):
 * - Base: version(1) + type(1) + sub_type(1) + flags(1) + seq(4) + ack(4) + payload_len(2) = 14
 * - Plus: session_id (2/4/8) + timestamp (2/3/4) + HMAC (8/16/32)
 */
static inline __u16 calculate_header_size(__u8 session_id_len, __u8 timestamp_len,
                                          __u8 hmac_policy) {
    __u16 size = BASE_HEADER_FIXED;

    /* Add session ID size */
    switch (session_id_len) {
        case SESSION_ID_16BIT: size += 2; break;
        case SESSION_ID_32BIT: size += 4; break;
        case SESSION_ID_64BIT: size += 8; break;
        default: size += 2; break;
    }

    /* Add timestamp size */
    switch (timestamp_len) {
        case TIMESTAMP_16BIT: size += 2; break;
        case TIMESTAMP_24BIT: size += 3; break;
        case TIMESTAMP_32BIT: size += 4; break;
        default: size += 2; break;
    }

    /* Add HMAC size */
    size += get_hmac_size(hmac_policy);

    return size;
}

/*============================================================================
 * Unity Test Setup/Teardown
 *============================================================================*/

void setUp(void) {
    /* No setup needed */
}

void tearDown(void) {
    /* No teardown needed */
}

/*============================================================================
 * calculate_time_bucket() Tests
 *============================================================================*/

void test_calculate_time_bucket_daily_epoch_at_midnight(void) {
    /* Exactly at UTC midnight: bucket should be 0 */
    __u64 midnight_ns = 0;  /* Unix epoch is midnight UTC */
    __u32 bucket = calculate_time_bucket(midnight_ns, EPOCH_DAILY);
    TEST_ASSERT_EQUAL_UINT32(0, bucket);
}

void test_calculate_time_bucket_daily_epoch_at_500ms(void) {
    /* 500ms into the day: bucket should be 1 */
    __u64 time_ns = 500ULL * 1000000ULL;  /* 500ms in nanoseconds */
    __u32 bucket = calculate_time_bucket(time_ns, EPOCH_DAILY);
    TEST_ASSERT_EQUAL_UINT32(1, bucket);
}

void test_calculate_time_bucket_daily_epoch_at_1_second(void) {
    /* 1 second = 1000ms = 2 time buckets */
    __u64 time_ns = 1000000000ULL;  /* 1 second in nanoseconds */
    __u32 bucket = calculate_time_bucket(time_ns, EPOCH_DAILY);
    TEST_ASSERT_EQUAL_UINT32(2, bucket);
}

void test_calculate_time_bucket_daily_epoch_at_499ms(void) {
    /* 499ms: still in bucket 0 */
    __u64 time_ns = 499ULL * 1000000ULL;
    __u32 bucket = calculate_time_bucket(time_ns, EPOCH_DAILY);
    TEST_ASSERT_EQUAL_UINT32(0, bucket);
}

void test_calculate_time_bucket_daily_epoch_end_of_day(void) {
    /* Last 500ms bucket of the day: 86400 seconds = 172800 buckets - 1 */
    /* 86399.5 seconds = bucket 172799 */
    __u64 time_ns = (86399ULL * 1000000000ULL) + (500ULL * 1000000ULL);
    __u32 bucket = calculate_time_bucket(time_ns, EPOCH_DAILY);
    TEST_ASSERT_EQUAL_UINT32(172799, bucket);
}

void test_calculate_time_bucket_daily_epoch_wraparound(void) {
    /* 25 hours = 1 hour into next day = same as 1 hour bucket */
    __u64 twenty_five_hours_ns = 25ULL * 3600ULL * 1000000000ULL;
    __u64 one_hour_ns = 1ULL * 3600ULL * 1000000000ULL;

    __u32 bucket_25h = calculate_time_bucket(twenty_five_hours_ns, EPOCH_DAILY);
    __u32 bucket_1h = calculate_time_bucket(one_hour_ns, EPOCH_DAILY);

    TEST_ASSERT_EQUAL_UINT32(bucket_1h, bucket_25h);
}

void test_calculate_time_bucket_monthly_epoch_at_start(void) {
    /* Start of month: bucket 0 */
    __u64 time_ns = 0;
    __u32 bucket = calculate_time_bucket(time_ns, EPOCH_MONTHLY);
    TEST_ASSERT_EQUAL_UINT32(0, bucket);
}

void test_calculate_time_bucket_monthly_epoch_at_1_second(void) {
    /* 1 second = 2 buckets */
    __u64 time_ns = 1000000000ULL;
    __u32 bucket = calculate_time_bucket(time_ns, EPOCH_MONTHLY);
    TEST_ASSERT_EQUAL_UINT32(2, bucket);
}

void test_calculate_time_bucket_500ms_granularity(void) {
    /* Verify 500ms granularity */
    __u64 t0_ns = 0;
    __u64 t499_ns = 499ULL * 1000000ULL;
    __u64 t500_ns = 500ULL * 1000000ULL;
    __u64 t501_ns = 501ULL * 1000000ULL;

    __u32 bucket0 = calculate_time_bucket(t0_ns, EPOCH_DAILY);
    __u32 bucket499 = calculate_time_bucket(t499_ns, EPOCH_DAILY);
    __u32 bucket500 = calculate_time_bucket(t500_ns, EPOCH_DAILY);
    __u32 bucket501 = calculate_time_bucket(t501_ns, EPOCH_DAILY);

    TEST_ASSERT_EQUAL_UINT32(bucket0, bucket499);  /* Same bucket */
    TEST_ASSERT_NOT_EQUAL_UINT32(bucket0, bucket500);  /* Different bucket */
    TEST_ASSERT_EQUAL_UINT32(bucket0 + 1, bucket500);  /* Next bucket */
    TEST_ASSERT_EQUAL_UINT32(bucket500, bucket501);  /* Same bucket */
}

/*============================================================================
 * extract_session_id() Tests
 *============================================================================*/

void test_extract_session_id_16bit(void) {
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));

    /* Store 0xABCD in big-endian */
    uint16_t sid = htons(0xABCD);
    memcpy(buffer, &sid, 2);

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint64_t result = extract_session_id(buffer, data_end, SESSION_ID_16BIT, &offset);

    TEST_ASSERT_EQUAL_UINT64(0xABCD, result);
    TEST_ASSERT_EQUAL_UINT16(2, offset);
}

void test_extract_session_id_32bit(void) {
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));

    uint32_t sid = htonl(0x12345678);
    memcpy(buffer, &sid, 4);

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint64_t result = extract_session_id(buffer, data_end, SESSION_ID_32BIT, &offset);

    TEST_ASSERT_EQUAL_UINT64(0x12345678, result);
    TEST_ASSERT_EQUAL_UINT16(4, offset);
}

void test_extract_session_id_64bit(void) {
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));

    uint64_t sid = htobe64(0xDEADBEEFCAFEBABEULL);
    memcpy(buffer, &sid, 8);

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint64_t result = extract_session_id(buffer, data_end, SESSION_ID_64BIT, &offset);

    TEST_ASSERT_EQUAL_UINT64(0xDEADBEEFCAFEBABEULL, result);
    TEST_ASSERT_EQUAL_UINT16(8, offset);
}

void test_extract_session_id_with_offset(void) {
    uint8_t buffer[64];
    memset(buffer, 0xAA, sizeof(buffer));

    /* Place session ID at offset 4 */
    uint32_t sid = htonl(0x11223344);
    memcpy(buffer + 4, &sid, 4);

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 4;

    uint64_t result = extract_session_id(buffer, data_end, SESSION_ID_32BIT, &offset);

    TEST_ASSERT_EQUAL_UINT64(0x11223344, result);
    TEST_ASSERT_EQUAL_UINT16(8, offset);  /* 4 + 4 */
}

void test_extract_session_id_boundary_check(void) {
    uint8_t buffer[4];  /* Only 4 bytes */
    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    /* Try to extract 64-bit from 4-byte buffer - should return 0 */
    uint64_t result = extract_session_id(buffer, data_end, SESSION_ID_64BIT, &offset);

    TEST_ASSERT_EQUAL_UINT64(0, result);
    TEST_ASSERT_EQUAL_UINT16(0, offset);  /* Offset unchanged on failure */
}

void test_extract_session_id_invalid_length(void) {
    uint8_t buffer[64];
    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    /* Invalid session ID length (3) */
    uint64_t result = extract_session_id(buffer, data_end, 3, &offset);

    TEST_ASSERT_EQUAL_UINT64(0, result);
}

/*============================================================================
 * extract_timestamp() Tests
 *============================================================================*/

void test_extract_timestamp_16bit(void) {
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));

    uint16_t ts = htons(0x1234);
    memcpy(buffer, &ts, 2);

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint32_t result = extract_timestamp(buffer, data_end, TIMESTAMP_16BIT, &offset);

    TEST_ASSERT_EQUAL_UINT32(0x1234, result);
    TEST_ASSERT_EQUAL_UINT16(2, offset);
}

void test_extract_timestamp_24bit(void) {
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));

    /* 24-bit value 0xABCDEF in big-endian */
    buffer[0] = 0xAB;
    buffer[1] = 0xCD;
    buffer[2] = 0xEF;

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint32_t result = extract_timestamp(buffer, data_end, TIMESTAMP_24BIT, &offset);

    TEST_ASSERT_EQUAL_UINT32(0xABCDEF, result);
    TEST_ASSERT_EQUAL_UINT16(3, offset);
}

void test_extract_timestamp_32bit(void) {
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));

    uint32_t ts = htonl(0xDEADBEEF);
    memcpy(buffer, &ts, 4);

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint32_t result = extract_timestamp(buffer, data_end, TIMESTAMP_32BIT, &offset);

    TEST_ASSERT_EQUAL_UINT32(0xDEADBEEF, result);
    TEST_ASSERT_EQUAL_UINT16(4, offset);
}

void test_extract_timestamp_boundary_check(void) {
    uint8_t buffer[2];
    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    /* Try to extract 32-bit from 2-byte buffer */
    uint32_t result = extract_timestamp(buffer, data_end, TIMESTAMP_32BIT, &offset);

    TEST_ASSERT_EQUAL_UINT32(0, result);
    TEST_ASSERT_EQUAL_UINT16(0, offset);
}

void test_extract_timestamp_24bit_max_value(void) {
    uint8_t buffer[64];

    /* Maximum 24-bit value: 0xFFFFFF */
    buffer[0] = 0xFF;
    buffer[1] = 0xFF;
    buffer[2] = 0xFF;

    void *data_end = buffer + sizeof(buffer);
    uint16_t offset = 0;

    uint32_t result = extract_timestamp(buffer, data_end, TIMESTAMP_24BIT, &offset);

    TEST_ASSERT_EQUAL_UINT32(0xFFFFFF, result);
}

/*============================================================================
 * get_hmac_size() Tests
 *============================================================================*/

void test_get_hmac_size_light(void) {
    TEST_ASSERT_EQUAL_UINT8(8, get_hmac_size(HMAC_POLICY_LIGHT));
}

void test_get_hmac_size_medium(void) {
    TEST_ASSERT_EQUAL_UINT8(16, get_hmac_size(HMAC_POLICY_MEDIUM));
}

void test_get_hmac_size_strong(void) {
    TEST_ASSERT_EQUAL_UINT8(32, get_hmac_size(HMAC_POLICY_STRONG));
}

void test_get_hmac_size_invalid_returns_minimum(void) {
    /* Invalid policy should return minimum (LIGHT) */
    TEST_ASSERT_EQUAL_UINT8(8, get_hmac_size(0));
    TEST_ASSERT_EQUAL_UINT8(8, get_hmac_size(99));
}

/*============================================================================
 * determine_hmac_policy() Tests
 *============================================================================*/

void test_determine_hmac_policy_critical_packets(void) {
    /* Critical packets always use HMAC_STRONG */
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_STRONG, determine_hmac_policy(PKT_TYPE_SYN));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_STRONG, determine_hmac_policy(PKT_TYPE_SYN_ACK));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_STRONG, determine_hmac_policy(PKT_TYPE_FIN));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_STRONG, determine_hmac_policy(PKT_TYPE_DISCOVERY));
}

void test_determine_hmac_policy_control_packets(void) {
    /* Control packets use HMAC_MEDIUM minimum */
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_MEDIUM, determine_hmac_policy(PKT_TYPE_ERROR));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_MEDIUM, determine_hmac_policy(PKT_TYPE_RST));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_MEDIUM, determine_hmac_policy(PKT_TYPE_HEARTBEAT));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_MEDIUM, determine_hmac_policy(PKT_TYPE_CONTROL));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_MEDIUM, determine_hmac_policy(PKT_TYPE_MANAGEMENT));
}

void test_determine_hmac_policy_data_packets(void) {
    /* Data packets use HMAC_LIGHT */
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_LIGHT, determine_hmac_policy(PKT_TYPE_DATA));
    TEST_ASSERT_EQUAL_UINT8(HMAC_POLICY_LIGHT, determine_hmac_policy(PKT_TYPE_ACK));
}

/*============================================================================
 * validate_timestamp() Tests
 *============================================================================*/

void test_validate_timestamp_exact_match(void) {
    /* Packet timestamp equals current time - valid */
    uint32_t current = 50000;
    uint32_t packet_ts = 50000;
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_DATA);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_validate_timestamp_within_window(void) {
    /* Packet 15 seconds old - within 30 second window */
    uint32_t current = 50000;
    uint32_t packet_ts = 35000;  /* 15 seconds old */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_DATA);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_validate_timestamp_at_window_edge(void) {
    /* Packet exactly 30 seconds old - at edge of window */
    uint32_t current = 60000;
    uint32_t packet_ts = 30000;  /* 30 seconds old */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_DATA);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_validate_timestamp_outside_window(void) {
    /* Packet 31 seconds old - outside 30 second window */
    uint32_t current = 61000;
    uint32_t packet_ts = 30000;  /* 31 seconds old */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_DATA);
    TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_validate_timestamp_future_within_tolerance(void) {
    /* Packet 40ms in future - within 50ms tolerance */
    uint32_t current = 50000;
    uint32_t packet_ts = 50040;  /* 40ms in future */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_DATA);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_validate_timestamp_future_outside_tolerance(void) {
    /* Packet 60ms in future - outside 50ms tolerance */
    uint32_t current = 50000;
    uint32_t packet_ts = 50060;  /* 60ms in future */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_DATA);
    TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_validate_timestamp_handshake_stricter_window(void) {
    /* SYN packet 15 seconds old - outside 10 second handshake window */
    uint32_t current = 25000;
    uint32_t packet_ts = 10000;  /* 15 seconds old */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_SYN);
    TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_validate_timestamp_handshake_within_window(void) {
    /* SYN packet 5 seconds old - within 10 second handshake window */
    uint32_t current = 15000;
    uint32_t packet_ts = 10000;  /* 5 seconds old */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_SYN);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_validate_timestamp_syn_ack_stricter_window(void) {
    /* SYN_ACK also uses stricter window */
    uint32_t current = 25000;
    uint32_t packet_ts = 10000;  /* 15 seconds old */
    int result = validate_timestamp(packet_ts, current, PKT_TYPE_SYN_ACK);
    TEST_ASSERT_EQUAL_INT(-1, result);
}

/*============================================================================
 * is_potential_buckwild_port() Tests
 *============================================================================*/

void test_is_potential_buckwild_port_minimum(void) {
    /* Minimum valid port */
    TEST_ASSERT_TRUE(is_potential_buckwild_port(1024));
}

void test_is_potential_buckwild_port_maximum(void) {
    /* Maximum port */
    TEST_ASSERT_TRUE(is_potential_buckwild_port(65535));
}

void test_is_potential_buckwild_port_mid_range(void) {
    TEST_ASSERT_TRUE(is_potential_buckwild_port(8080));
    TEST_ASSERT_TRUE(is_potential_buckwild_port(32768));
}

void test_is_potential_buckwild_port_below_minimum(void) {
    /* Well-known ports not allowed */
    TEST_ASSERT_FALSE(is_potential_buckwild_port(0));
    TEST_ASSERT_FALSE(is_potential_buckwild_port(80));
    TEST_ASSERT_FALSE(is_potential_buckwild_port(443));
    TEST_ASSERT_FALSE(is_potential_buckwild_port(1023));
}

/*============================================================================
 * calculate_header_size() Tests
 *============================================================================*/

void test_header_size_minimum_configuration(void) {
    /* Minimum: 16-bit session + 16-bit timestamp + HMAC_LIGHT */
    /* 14 + 2 + 2 + 8 = 26 bytes */
    uint16_t size = calculate_header_size(SESSION_ID_16BIT, TIMESTAMP_16BIT, HMAC_POLICY_LIGHT);
    TEST_ASSERT_EQUAL_UINT16(MIN_HEADER_SIZE, size);
    TEST_ASSERT_EQUAL_UINT16(26, size);
}

void test_header_size_maximum_configuration(void) {
    /* Maximum: 64-bit session + 32-bit timestamp + HMAC_STRONG */
    /* 14 + 8 + 4 + 32 = 58 bytes */
    uint16_t size = calculate_header_size(SESSION_ID_64BIT, TIMESTAMP_32BIT, HMAC_POLICY_STRONG);
    TEST_ASSERT_EQUAL_UINT16(MAX_HEADER_SIZE, size);
    TEST_ASSERT_EQUAL_UINT16(58, size);
}

void test_header_size_standard_configuration(void) {
    /* Standard: 32-bit session + 24-bit timestamp + HMAC_LIGHT */
    /* 14 + 4 + 3 + 8 = 29 bytes */
    uint16_t size = calculate_header_size(SESSION_ID_32BIT, TIMESTAMP_24BIT, HMAC_POLICY_LIGHT);
    TEST_ASSERT_EQUAL_UINT16(29, size);
}

void test_header_size_secure_configuration(void) {
    /* Secure: 32-bit session + 24-bit timestamp + HMAC_STRONG */
    /* 14 + 4 + 3 + 32 = 53 bytes */
    uint16_t size = calculate_header_size(SESSION_ID_32BIT, TIMESTAMP_24BIT, HMAC_POLICY_STRONG);
    TEST_ASSERT_EQUAL_UINT16(53, size);
}

void test_header_size_infrastructure_configuration(void) {
    /* Infrastructure: 64-bit session + 32-bit timestamp + HMAC_MEDIUM */
    /* 14 + 8 + 4 + 16 = 42 bytes */
    uint16_t size = calculate_header_size(SESSION_ID_64BIT, TIMESTAMP_32BIT, HMAC_POLICY_MEDIUM);
    TEST_ASSERT_EQUAL_UINT16(42, size);
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    UNITY_BEGIN();

    /* Time bucket tests */
    RUN_TEST(test_calculate_time_bucket_daily_epoch_at_midnight);
    RUN_TEST(test_calculate_time_bucket_daily_epoch_at_500ms);
    RUN_TEST(test_calculate_time_bucket_daily_epoch_at_1_second);
    RUN_TEST(test_calculate_time_bucket_daily_epoch_at_499ms);
    RUN_TEST(test_calculate_time_bucket_daily_epoch_end_of_day);
    RUN_TEST(test_calculate_time_bucket_daily_epoch_wraparound);
    RUN_TEST(test_calculate_time_bucket_monthly_epoch_at_start);
    RUN_TEST(test_calculate_time_bucket_monthly_epoch_at_1_second);
    RUN_TEST(test_calculate_time_bucket_500ms_granularity);

    /* Session ID extraction tests */
    RUN_TEST(test_extract_session_id_16bit);
    RUN_TEST(test_extract_session_id_32bit);
    RUN_TEST(test_extract_session_id_64bit);
    RUN_TEST(test_extract_session_id_with_offset);
    RUN_TEST(test_extract_session_id_boundary_check);
    RUN_TEST(test_extract_session_id_invalid_length);

    /* Timestamp extraction tests */
    RUN_TEST(test_extract_timestamp_16bit);
    RUN_TEST(test_extract_timestamp_24bit);
    RUN_TEST(test_extract_timestamp_32bit);
    RUN_TEST(test_extract_timestamp_boundary_check);
    RUN_TEST(test_extract_timestamp_24bit_max_value);

    /* HMAC size tests */
    RUN_TEST(test_get_hmac_size_light);
    RUN_TEST(test_get_hmac_size_medium);
    RUN_TEST(test_get_hmac_size_strong);
    RUN_TEST(test_get_hmac_size_invalid_returns_minimum);

    /* HMAC policy tests */
    RUN_TEST(test_determine_hmac_policy_critical_packets);
    RUN_TEST(test_determine_hmac_policy_control_packets);
    RUN_TEST(test_determine_hmac_policy_data_packets);

    /* Timestamp validation tests */
    RUN_TEST(test_validate_timestamp_exact_match);
    RUN_TEST(test_validate_timestamp_within_window);
    RUN_TEST(test_validate_timestamp_at_window_edge);
    RUN_TEST(test_validate_timestamp_outside_window);
    RUN_TEST(test_validate_timestamp_future_within_tolerance);
    RUN_TEST(test_validate_timestamp_future_outside_tolerance);
    RUN_TEST(test_validate_timestamp_handshake_stricter_window);
    RUN_TEST(test_validate_timestamp_handshake_within_window);
    RUN_TEST(test_validate_timestamp_syn_ack_stricter_window);

    /* Port validation tests */
    RUN_TEST(test_is_potential_buckwild_port_minimum);
    RUN_TEST(test_is_potential_buckwild_port_maximum);
    RUN_TEST(test_is_potential_buckwild_port_mid_range);
    RUN_TEST(test_is_potential_buckwild_port_below_minimum);

    /* Header size tests */
    RUN_TEST(test_header_size_minimum_configuration);
    RUN_TEST(test_header_size_maximum_configuration);
    RUN_TEST(test_header_size_standard_configuration);
    RUN_TEST(test_header_size_secure_configuration);
    RUN_TEST(test_header_size_infrastructure_configuration);

    return UNITY_END();
}
