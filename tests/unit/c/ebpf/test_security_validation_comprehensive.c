/**
 * @file test_security_validation_comprehensive.c
 * @brief Comprehensive unit tests for security.h validation functions
 *
 * Tests security pipeline functions with corner cases:
 * - is_source_blacklisted() - Blacklist checking with expiration
 * - apply_multi_layer_rate_limiting() - Multi-layer rate limiting
 * - detect_enumeration_attack() - Enumeration detection
 * - detect_replay_attack() - Replay attack detection
 * - detect_timing_attack() - Timing attack detection
 * - escalate_security_response() - Response escalation
 */

#include <unity.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/*============================================================================
 * Mock BPF Helpers and Map Operations
 *============================================================================*/

/* Mock time for bpf_ktime_get_ns */
static uint64_t mock_ktime_ns = 0;

/* Mock BPF endianness conversion functions */
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_be64_to_cpu(x) __builtin_bswap64(x)
#define bpf_cpu_to_be64(x) __builtin_bswap64(x)
#define bpf_ktime_get_ns() (mock_ktime_ns)

/* Mock BPF helper macros - avoid redefining if already defined */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* Stub Linux types for userspace testing */
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

/* Stub headers - must match actual guard macros */
#define _LINUX_TYPES_H
#define _UAPI_LINUX_TYPES_H
#define _LINUX_IF_ETHER_H
#define _LINUX_IP_H
#define _LINUX_UDP_H
#define __BPF_HELPERS__
#define __BPF_HELPER_DEFS_H__
#define __BPF_ENDIAN__
#define SEC(name)
#define BPF_ANY 0

/*============================================================================
 * Mock Map Storage
 *============================================================================*/

#define MAX_MOCK_ENTRIES 100

/* Attack detection info structure (from maps.h) */
struct attack_detection_info {
    __u32 src_ip;
    __u64 first_seen;
    __u64 last_seen;
    __u32 connection_attempts;
    __u32 failed_authentications;
    __u32 enumeration_score;
    __u32 replay_attempts;
    __u32 timing_violations;
    __u8 attack_type;
    __u8 confidence_level;
    __u8 response_level;
    __u8 permanent_block;
};

/* Rate limit info structure (from maps.h) */
struct rate_limit_info {
    __u64 last_reset_time;
    __u32 packet_count;
    __u32 byte_count;
    __u32 violation_count;
    __u8 blocked;
    __u8 escalation_level;
    __u16 block_duration;
    __u64 last_violation_time;
    __u32 total_violations;
};

/* Security event structure (from maps.h) */
struct security_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 session_id;
    __u8 event_type;
    __u8 severity;
    __u8 action_taken;
    __u8 reserved;
};

/* Security stats structure */
struct security_stats {
    __u64 total_packets;
    __u64 dropped_packets;
    __u64 security_events;
    __u64 rate_limit_violations;
    __u64 fragment_attacks;
    __u64 replay_attacks;
    __u64 enumeration_attempts;
    __u64 timing_attacks;
    __u64 blocked_sources;
    __u64 last_update_time;
};

/* Mock map entries */
static struct {
    __u32 key;
    struct attack_detection_info value;
    bool valid;
} mock_attack_detection_map[MAX_MOCK_ENTRIES];

static struct {
    __u32 key;
    struct rate_limit_info value;
    bool valid;
} mock_ip_rate_limit_map[MAX_MOCK_ENTRIES];

static struct security_stats mock_security_stats;
static size_t mock_attack_detection_count = 0;
static size_t mock_rate_limit_count = 0;

/* Ring buffer mock */
static struct security_event mock_ringbuf_events[100];
static size_t mock_ringbuf_count = 0;

/* Mock map lookup/update macros */
#define MAP_LOOKUP_ELEM(map, key_ptr) mock_map_lookup_##map(key_ptr)
#define MAP_UPDATE_ELEM(map, key_ptr, val_ptr, flags) mock_map_update_##map(key_ptr, val_ptr)

static struct attack_detection_info* mock_map_lookup_attack_detection_map(const __u32 *key) {
    for (size_t i = 0; i < mock_attack_detection_count; i++) {
        if (mock_attack_detection_map[i].valid && mock_attack_detection_map[i].key == *key) {
            return &mock_attack_detection_map[i].value;
        }
    }
    return NULL;
}

static int mock_map_update_attack_detection_map(const __u32 *key, const struct attack_detection_info *value) {
    /* Try to update existing */
    for (size_t i = 0; i < mock_attack_detection_count; i++) {
        if (mock_attack_detection_map[i].valid && mock_attack_detection_map[i].key == *key) {
            mock_attack_detection_map[i].value = *value;
            return 0;
        }
    }
    /* Add new */
    if (mock_attack_detection_count < MAX_MOCK_ENTRIES) {
        mock_attack_detection_map[mock_attack_detection_count].key = *key;
        mock_attack_detection_map[mock_attack_detection_count].value = *value;
        mock_attack_detection_map[mock_attack_detection_count].valid = true;
        mock_attack_detection_count++;
        return 0;
    }
    return -1;
}

static struct rate_limit_info* mock_map_lookup_ip_rate_limit_map(const __u32 *key) {
    for (size_t i = 0; i < mock_rate_limit_count; i++) {
        if (mock_ip_rate_limit_map[i].valid && mock_ip_rate_limit_map[i].key == *key) {
            return &mock_ip_rate_limit_map[i].value;
        }
    }
    return NULL;
}

static int mock_map_update_ip_rate_limit_map(const __u32 *key, const struct rate_limit_info *value) {
    /* Try to update existing */
    for (size_t i = 0; i < mock_rate_limit_count; i++) {
        if (mock_ip_rate_limit_map[i].valid && mock_ip_rate_limit_map[i].key == *key) {
            mock_ip_rate_limit_map[i].value = *value;
            return 0;
        }
    }
    /* Add new */
    if (mock_rate_limit_count < MAX_MOCK_ENTRIES) {
        mock_ip_rate_limit_map[mock_rate_limit_count].key = *key;
        mock_ip_rate_limit_map[mock_rate_limit_count].value = *value;
        mock_ip_rate_limit_map[mock_rate_limit_count].valid = true;
        mock_rate_limit_count++;
        return 0;
    }
    return -1;
}

static void* mock_map_lookup_security_stats_map(const __u32 *key) {
    (void)key;
    return &mock_security_stats;
}

static int mock_map_update_security_stats_map(const __u32 *key, const void *value) {
    (void)key;
    (void)value;
    return 0;
}

/* Mock ring buffer operations */
static struct security_event* bpf_ringbuf_reserve(void *map, size_t size, int flags) {
    (void)map;
    (void)size;
    (void)flags;
    if (mock_ringbuf_count < 100) {
        return &mock_ringbuf_events[mock_ringbuf_count];
    }
    return NULL;
}

static void bpf_ringbuf_submit(void *data, int flags) {
    (void)data;
    (void)flags;
    mock_ringbuf_count++;
}

/* Mock ring buffer declaration */
static int packet_ring_buffer;

/* Prevent maps.h from being included */
#define BUCKWILD_EBPF_MAPS_H

/* Mock session info */
struct session_info {
    __u64 session_id;
    __u32 last_sequence;
    __u16 expected_port;
    __u64 last_packet_time;
    __u32 packet_count;
    __u8 session_state;
    __u8 hmac_policy;
    __u32 src_ip;
    __u16 src_port;
    __u32 security_violations;
    __u8 attack_detected;
};

/* Mock fragment header */
struct fragment_header {
    __u16 fragment_id;
    __u16 fragment_index;
    __u16 total_fragments;
    __u16 fragment_size;
};

/* Mock parsed header */
struct parsed_header {
    __u8 version;
    __u8 session_id_length;
    __u8 timestamp_length;
    __u8 hmac_policy;
    __u8 packet_type;
    __u8 packet_subtype;
    __u8 flags;
    __u64 session_id;
    __u32 timestamp;
    __u32 sequence_number;
    __u32 acknowledgment;
    __u16 window_size;
    __u16 header_length;
    __u8 validation_status;
    __u8 security_flags;
    struct fragment_header fragment;
};

/* Mock port stats */
struct port_stats {
    __u64 packet_count;
    __u64 byte_count;
    __u32 security_events;
    __u32 rate_limit_violations;
    __u32 attack_attempts;
};

/* Protocol constants - define before including security.h */
#define BUCKWILD_EBPF_PROTOCOL_H

#define BUCKWILD_VERSION 0x01
#define MIN_HEADER_SIZE 26
#define MAX_HEADER_SIZE 57

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

#define SESSION_ID_16BIT        0
#define SESSION_ID_32BIT        1
#define SESSION_ID_64BIT        2

#define TIMESTAMP_16BIT         0
#define TIMESTAMP_24BIT         1
#define TIMESTAMP_24BIT_HIGH    2
#define TIMESTAMP_32BIT         3

#define HMAC_POLICY_LIGHT       1
#define HMAC_POLICY_MEDIUM      2
#define HMAC_POLICY_STRONG      3

#define EPOCH_DAILY             0
#define EPOCH_MONTHLY           1

#define PKT_FLAG_ENCRYPTED      0x01
#define PKT_FLAG_COMPRESSED     0x02
#define PKT_FLAG_FRAGMENTED     0x04
#define PKT_FLAG_URGENT         0x08
#define PKT_FLAG_RECOVERY       0x10
#define PKT_FLAG_REKEYING       0x20

#define VALIDATION_OK           0x00
#define VALIDATION_INVALID_SIZE 0x01
#define VALIDATION_INVALID_VERSION 0x02
#define VALIDATION_INVALID_SESSION 0x04
#define VALIDATION_INVALID_TIMESTAMP 0x08
#define VALIDATION_INVALID_HMAC 0x10
#define VALIDATION_RATE_LIMITED 0x20
#define VALIDATION_FRAGMENT_ATTACK 0x40
#define VALIDATION_REPLAY_ATTACK 0x80

#define SEC_EVENT_UNKNOWN_SESSION       0x01
#define SEC_EVENT_RATE_LIMIT_VIOLATION  0x02
#define SEC_EVENT_ENUMERATION_ATTACK    0x03
#define SEC_EVENT_REPLAY_ATTACK         0x04
#define SEC_EVENT_TIMING_ATTACK         0x05
#define SEC_EVENT_FRAGMENT_BOMB         0x06
#define SEC_EVENT_FRAGMENT_OVERLAP      0x07
#define SEC_EVENT_SESSION_HIJACK        0x08
#define SEC_EVENT_PORT_SCAN             0x09

#define SEC_SEVERITY_LOW                0x01
#define SEC_SEVERITY_MEDIUM             0x02
#define SEC_SEVERITY_HIGH               0x03
#define SEC_SEVERITY_CRITICAL           0x04

#define SEC_ACTION_ALLOW        0
#define SEC_ACTION_DROP         1
#define SEC_ACTION_RATE_LIMIT   2
#define SEC_ACTION_BLOCK_TEMP   3
#define SEC_ACTION_BLOCK_PERM   4

/* Stub fragment validation */
#define BUCKWILD_EBPF_FRAGMENT_SECURITY_H
#define FRAGMENT_VALID 0
#define FRAGMENT_BOMB_DETECTED 1
#define FRAGMENT_OVERLAP_DETECTED 2

static inline int validate_fragment_security(struct parsed_header *parsed,
                                             __u32 src_ip, __u16 src_port,
                                             void *data, void *data_end,
                                             __u64 current_time) {
    (void)parsed; (void)src_ip; (void)src_port;
    (void)data; (void)data_end; (void)current_time;
    return FRAGMENT_VALID;
}

/* Now include security.h */
#include "../../../../src/ebpf/c/include/security.h"

/*============================================================================
 * Test Setup and Teardown
 *============================================================================*/

void setUp(void) {
    mock_ktime_ns = 1000000000000ULL; /* Start at 1000 seconds */

    /* Reset mock maps */
    memset(mock_attack_detection_map, 0, sizeof(mock_attack_detection_map));
    memset(mock_ip_rate_limit_map, 0, sizeof(mock_ip_rate_limit_map));
    memset(&mock_security_stats, 0, sizeof(mock_security_stats));
    memset(mock_ringbuf_events, 0, sizeof(mock_ringbuf_events));

    mock_attack_detection_count = 0;
    mock_rate_limit_count = 0;
    mock_ringbuf_count = 0;
}

void tearDown(void) {
    mock_ktime_ns = 0;
}

/*============================================================================
 * is_source_blacklisted() Tests
 *============================================================================*/

void test_is_source_blacklisted_unknown_source_not_blocked(void) {
    __u32 src_ip = 0x0A000001; /* 10.0.0.1 */
    int result = is_source_blacklisted(src_ip, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_is_source_blacklisted_permanent_block(void) {
    __u32 src_ip = 0x0A000001;
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .permanent_block = 1,
        .response_level = RESPONSE_LEVEL_PERM_BLOCK
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = is_source_blacklisted(src_ip, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(1, result);
}

void test_is_source_blacklisted_temp_block_active(void) {
    __u32 src_ip = 0x0A000001;
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .permanent_block = 0,
        .response_level = RESPONSE_LEVEL_TEMP_BLOCK,
        .last_seen = mock_ktime_ns - 1000000000ULL /* 1 second ago */
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    /* Block duration at level 2 is 60 * 4 = 240 seconds */
    int result = is_source_blacklisted(src_ip, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(1, result);
}

void test_is_source_blacklisted_temp_block_expired(void) {
    __u32 src_ip = 0x0A000001;
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .permanent_block = 0,
        .response_level = RESPONSE_LEVEL_TEMP_BLOCK,
        .last_seen = mock_ktime_ns - (300ULL * 1000000000ULL) /* 300 seconds ago */
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    /* Block should have expired */
    int result = is_source_blacklisted(src_ip, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_is_source_blacklisted_monitor_level_not_blocked(void) {
    __u32 src_ip = 0x0A000001;
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .permanent_block = 0,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .last_seen = mock_ktime_ns
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = is_source_blacklisted(src_ip, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_is_source_blacklisted_rate_limit_level_not_blocked(void) {
    __u32 src_ip = 0x0A000001;
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .permanent_block = 0,
        .response_level = RESPONSE_LEVEL_RATE_LIMIT,
        .last_seen = mock_ktime_ns
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = is_source_blacklisted(src_ip, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

/*============================================================================
 * apply_multi_layer_rate_limiting() Tests
 *============================================================================*/

void test_rate_limiting_new_source_allowed(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;
    __u8 packet_type = PKT_TYPE_DATA;
    __u32 packet_size = 100;

    int result = apply_multi_layer_rate_limiting(src_ip, session_id, packet_type,
                                                  packet_size, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_ALLOW, result);
}

void test_rate_limiting_counter_reset_after_one_second(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;

    /* First packet */
    apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_DATA, 100, mock_ktime_ns);

    /* Advance time by more than 1 second */
    mock_ktime_ns += 2000000000ULL;

    /* Second packet after reset - should be allowed */
    int result = apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_DATA, 100, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_ALLOW, result);

    /* Check counter was reset */
    struct rate_limit_info *info = mock_map_lookup_ip_rate_limit_map(&src_ip);
    TEST_ASSERT_NOT_NULL(info);
    TEST_ASSERT_EQUAL_UINT32(1, info->packet_count);
}

void test_rate_limiting_pps_exceeded(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;

    /* Create rate limit entry with high packet count */
    struct rate_limit_info info = {
        .last_reset_time = mock_ktime_ns,
        .packet_count = 1001, /* Over 1000 pps limit */
        .byte_count = 1000,
        .violation_count = 0,
        .blocked = 0
    };
    mock_map_update_ip_rate_limit_map(&src_ip, &info);

    /* This should trigger rate limiting */
    int result = apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_DATA,
                                                  100, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_RATE_LIMIT, result);
}

void test_rate_limiting_bps_exceeded(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;

    /* Create rate limit entry with high byte count */
    struct rate_limit_info info = {
        .last_reset_time = mock_ktime_ns,
        .packet_count = 10,
        .byte_count = 1048577, /* Over 1MB/s limit */
        .violation_count = 0,
        .blocked = 0
    };
    mock_map_update_ip_rate_limit_map(&src_ip, &info);

    int result = apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_DATA,
                                                  100, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_RATE_LIMIT, result);
}

void test_rate_limiting_syn_limit(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;

    /* Create rate limit entry with high SYN count */
    struct rate_limit_info info = {
        .last_reset_time = mock_ktime_ns,
        .packet_count = 11, /* Over 10 SYN per second limit */
        .byte_count = 1000,
        .violation_count = 0,
        .blocked = 0
    };
    mock_map_update_ip_rate_limit_map(&src_ip, &info);

    int result = apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_SYN,
                                                  100, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_RATE_LIMIT, result);
}

void test_rate_limiting_discovery_limit(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;

    /* Create rate limit entry with high discovery count */
    struct rate_limit_info info = {
        .last_reset_time = mock_ktime_ns,
        .packet_count = 6, /* Over 5 discovery per second limit */
        .byte_count = 600,
        .violation_count = 0,
        .blocked = 0
    };
    mock_map_update_ip_rate_limit_map(&src_ip, &info);

    int result = apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_DISCOVERY,
                                                  100, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_RATE_LIMIT, result);
}

void test_rate_limiting_violations_cause_block(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;

    /* Create rate limit entry with many violations */
    struct rate_limit_info info = {
        .last_reset_time = mock_ktime_ns,
        .packet_count = 1001,
        .byte_count = 100000,
        .violation_count = 3,
        .blocked = 0
    };
    mock_map_update_ip_rate_limit_map(&src_ip, &info);

    int result = apply_multi_layer_rate_limiting(src_ip, session_id, PKT_TYPE_DATA,
                                                  100, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_RATE_LIMIT, result);

    /* Check blocked flag was set */
    struct rate_limit_info *updated = mock_map_lookup_ip_rate_limit_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_UINT8(1, updated->blocked);
}

/*============================================================================
 * detect_enumeration_attack() Tests
 *============================================================================*/

void test_enumeration_new_source_not_detected(void) {
    __u32 src_ip = 0x0A000001;
    __u16 dest_port = 8080;

    int result = detect_enumeration_attack(src_ip, dest_port, PKT_TYPE_SYN, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_enumeration_high_rate_detected(void) {
    __u32 src_ip = 0x0A000001;
    __u16 dest_port = 8080;

    /* Create attack info with high connection rate */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .first_seen = mock_ktime_ns - 500000000ULL, /* 0.5 seconds ago */
        .last_seen = mock_ktime_ns,
        .connection_attempts = 10, /* Will become 11 */
        .enumeration_score = 15,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    /* More SYNs should trigger detection */
    (void)detect_enumeration_attack(src_ip, dest_port, PKT_TYPE_SYN, mock_ktime_ns);

    /* Check if enumeration was detected based on score threshold */
    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_GREATER_THAN_UINT32(10, updated->connection_attempts);
}

void test_enumeration_many_attempts_short_window(void) {
    __u32 src_ip = 0x0A000001;
    __u16 dest_port = 8080;

    /* Create attack info with many attempts in short time */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .first_seen = mock_ktime_ns - 30000000000ULL, /* 30 seconds ago */
        .last_seen = mock_ktime_ns,
        .connection_attempts = 50, /* Will become 51 - triggers 50+ in 60s check */
        .enumeration_score = 25,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = detect_enumeration_attack(src_ip, dest_port, PKT_TYPE_SYN, mock_ktime_ns);

    /* Should detect enumeration */
    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_GREATER_THAN_UINT32(ENUMERATION_THRESHOLD, updated->enumeration_score);

    if (updated->enumeration_score > ENUMERATION_THRESHOLD) {
        TEST_ASSERT_EQUAL_INT(1, result);
    }
}

void test_enumeration_discovery_packets_counted(void) {
    __u32 src_ip = 0x0A000001;
    __u16 dest_port = 8080;

    /* Create baseline */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .first_seen = mock_ktime_ns - 1000000000ULL,
        .last_seen = mock_ktime_ns,
        .connection_attempts = 5,
        .enumeration_score = 0,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    /* Discovery packets should increment connection_attempts */
    detect_enumeration_attack(src_ip, dest_port, PKT_TYPE_DISCOVERY, mock_ktime_ns);

    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_UINT32(6, updated->connection_attempts);
}

void test_enumeration_data_packets_not_counted(void) {
    __u32 src_ip = 0x0A000001;
    __u16 dest_port = 8080;

    /* Create baseline */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .first_seen = mock_ktime_ns - 1000000000ULL,
        .last_seen = mock_ktime_ns,
        .connection_attempts = 5,
        .enumeration_score = 0,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    /* DATA packets should NOT increment connection_attempts */
    detect_enumeration_attack(src_ip, dest_port, PKT_TYPE_DATA, mock_ktime_ns);

    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_UINT32(5, updated->connection_attempts);
}

/*============================================================================
 * detect_replay_attack() Tests
 *============================================================================*/

void test_replay_new_source_not_detected(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;
    __u32 sequence = 100;
    __u32 timestamp = 50;

    int result = detect_replay_attack(src_ip, session_id, sequence, timestamp, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_replay_rapid_packets_detected(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;
    __u32 sequence = 100;
    __u32 timestamp = 50;

    /* Create attack info with rapid packet pattern */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .last_seen = mock_ktime_ns - 100000ULL, /* 0.1ms ago - very rapid */
        .replay_attempts = 5, /* Will become 6, triggering detection */
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = detect_replay_attack(src_ip, session_id, sequence, timestamp, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(1, result);
}

void test_replay_normal_timing_not_detected(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;
    __u32 sequence = 100;
    __u32 timestamp = 50;

    /* Create attack info with normal packet timing */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .last_seen = mock_ktime_ns - 10000000ULL, /* 10ms ago - normal */
        .replay_attempts = 0,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = detect_replay_attack(src_ip, session_id, sequence, timestamp, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_replay_increments_counter(void) {
    __u32 src_ip = 0x0A000001;
    __u64 session_id = 0x12345678;
    __u32 sequence = 100;
    __u32 timestamp = 50;

    /* Create attack info with rapid timing */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .last_seen = mock_ktime_ns - 500000ULL, /* 0.5ms ago */
        .replay_attempts = 2,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    detect_replay_attack(src_ip, session_id, sequence, timestamp, mock_ktime_ns);

    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_UINT32(3, updated->replay_attempts);
}

/*============================================================================
 * detect_timing_attack() Tests
 *============================================================================*/

void test_timing_attack_new_source_not_detected(void) {
    __u32 src_ip = 0x0A000001;
    __u64 processing_start = mock_ktime_ns - 10000; /* 10 microseconds */

    int result = detect_timing_attack(src_ip, processing_start, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_timing_attack_suspicious_fast_processing(void) {
    __u32 src_ip = 0x0A000001;
    __u64 processing_start = mock_ktime_ns - 500; /* 0.5 microseconds - very fast */

    /* Create attack info with many timing violations */
    struct attack_detection_info info = {
        .src_ip = src_ip,
        .timing_violations = TIMING_ATTACK_THRESHOLD, /* At threshold */
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = detect_timing_attack(src_ip, processing_start, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(1, result);
}

void test_timing_attack_normal_processing_not_flagged(void) {
    __u32 src_ip = 0x0A000001;
    __u64 processing_start = mock_ktime_ns - 5000; /* 5 microseconds - normal */

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .timing_violations = 0,
        .response_level = RESPONSE_LEVEL_MONITOR
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = detect_timing_attack(src_ip, processing_start, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(0, result);

    /* Timing violations should not increase for normal processing */
    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_UINT32(0, updated->timing_violations);
}

/*============================================================================
 * escalate_security_response() Tests
 *============================================================================*/

void test_escalation_unknown_source_allows(void) {
    __u32 src_ip = 0x0A000001;

    int result = escalate_security_response(src_ip, SEC_EVENT_ENUMERATION_ATTACK,
                                            CONFIDENCE_HIGH, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_ALLOW, result);
}

void test_escalation_critical_confidence_permanent_block(void) {
    __u32 src_ip = 0x0A000001;

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .permanent_block = 0
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = escalate_security_response(src_ip, SEC_EVENT_ENUMERATION_ATTACK,
                                            CONFIDENCE_CRITICAL, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_BLOCK_PERM, result);

    struct attack_detection_info *updated = mock_map_lookup_attack_detection_map(&src_ip);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_UINT8(1, updated->permanent_block);
}

void test_escalation_high_confidence_temp_block(void) {
    __u32 src_ip = 0x0A000001;

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .permanent_block = 0
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = escalate_security_response(src_ip, SEC_EVENT_ENUMERATION_ATTACK,
                                            CONFIDENCE_HIGH, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_BLOCK_TEMP, result);
}

void test_escalation_medium_confidence_rate_limit(void) {
    __u32 src_ip = 0x0A000001;

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .permanent_block = 0
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = escalate_security_response(src_ip, SEC_EVENT_ENUMERATION_ATTACK,
                                            CONFIDENCE_MEDIUM, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_RATE_LIMIT, result);
}

void test_escalation_low_confidence_allows(void) {
    __u32 src_ip = 0x0A000001;

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .permanent_block = 0
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = escalate_security_response(src_ip, SEC_EVENT_TIMING_ATTACK,
                                            CONFIDENCE_LOW, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_ALLOW, result);
}

void test_escalation_fragment_bomb_immediate_block(void) {
    __u32 src_ip = 0x0A000001;

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .permanent_block = 0
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = escalate_security_response(src_ip, SEC_EVENT_FRAGMENT_BOMB,
                                            CONFIDENCE_LOW, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_BLOCK_TEMP, result);
}

void test_escalation_session_hijack_immediate_block(void) {
    __u32 src_ip = 0x0A000001;

    struct attack_detection_info info = {
        .src_ip = src_ip,
        .response_level = RESPONSE_LEVEL_MONITOR,
        .permanent_block = 0
    };
    mock_map_update_attack_detection_map(&src_ip, &info);

    int result = escalate_security_response(src_ip, SEC_EVENT_SESSION_HIJACK,
                                            CONFIDENCE_LOW, mock_ktime_ns);
    TEST_ASSERT_EQUAL_INT(SEC_ACTION_BLOCK_TEMP, result);
}

/*============================================================================
 * Threshold and Constant Tests
 *============================================================================*/

void test_security_thresholds_defined(void) {
    TEST_ASSERT_EQUAL_INT(10, MAX_CONNECTIONS_PER_SOURCE);
    TEST_ASSERT_EQUAL_INT(5, CONNECTION_ATTEMPT_RATE_LIMIT);
    TEST_ASSERT_EQUAL_INT(3, AUTHENTICATION_FAILURE_LIMIT);
    TEST_ASSERT_EQUAL_INT(20, ENUMERATION_THRESHOLD);
    TEST_ASSERT_EQUAL_INT(60, REPLAY_WINDOW_SIZE);
    TEST_ASSERT_EQUAL_INT(1000, TIMING_ATTACK_THRESHOLD);
    TEST_ASSERT_EQUAL_INT(60, BLACKLIST_DURATION_BASE);
    TEST_ASSERT_EQUAL_INT(10, PERMANENT_BLOCK_THRESHOLD);
}

void test_confidence_levels_defined(void) {
    TEST_ASSERT_EQUAL_INT(25, CONFIDENCE_LOW);
    TEST_ASSERT_EQUAL_INT(50, CONFIDENCE_MEDIUM);
    TEST_ASSERT_EQUAL_INT(75, CONFIDENCE_HIGH);
    TEST_ASSERT_EQUAL_INT(90, CONFIDENCE_CRITICAL);
}

void test_response_levels_defined(void) {
    TEST_ASSERT_EQUAL_INT(0, RESPONSE_LEVEL_MONITOR);
    TEST_ASSERT_EQUAL_INT(1, RESPONSE_LEVEL_RATE_LIMIT);
    TEST_ASSERT_EQUAL_INT(2, RESPONSE_LEVEL_TEMP_BLOCK);
    TEST_ASSERT_EQUAL_INT(3, RESPONSE_LEVEL_PERM_BLOCK);
}

/*============================================================================
 * Test Runner
 *============================================================================*/

int main(void) {
    UNITY_BEGIN();

    /* is_source_blacklisted() tests */
    RUN_TEST(test_is_source_blacklisted_unknown_source_not_blocked);
    RUN_TEST(test_is_source_blacklisted_permanent_block);
    RUN_TEST(test_is_source_blacklisted_temp_block_active);
    RUN_TEST(test_is_source_blacklisted_temp_block_expired);
    RUN_TEST(test_is_source_blacklisted_monitor_level_not_blocked);
    RUN_TEST(test_is_source_blacklisted_rate_limit_level_not_blocked);

    /* apply_multi_layer_rate_limiting() tests */
    RUN_TEST(test_rate_limiting_new_source_allowed);
    RUN_TEST(test_rate_limiting_counter_reset_after_one_second);
    RUN_TEST(test_rate_limiting_pps_exceeded);
    RUN_TEST(test_rate_limiting_bps_exceeded);
    RUN_TEST(test_rate_limiting_syn_limit);
    RUN_TEST(test_rate_limiting_discovery_limit);
    RUN_TEST(test_rate_limiting_violations_cause_block);

    /* detect_enumeration_attack() tests */
    RUN_TEST(test_enumeration_new_source_not_detected);
    RUN_TEST(test_enumeration_high_rate_detected);
    RUN_TEST(test_enumeration_many_attempts_short_window);
    RUN_TEST(test_enumeration_discovery_packets_counted);
    RUN_TEST(test_enumeration_data_packets_not_counted);

    /* detect_replay_attack() tests */
    RUN_TEST(test_replay_new_source_not_detected);
    RUN_TEST(test_replay_rapid_packets_detected);
    RUN_TEST(test_replay_normal_timing_not_detected);
    RUN_TEST(test_replay_increments_counter);

    /* detect_timing_attack() tests */
    RUN_TEST(test_timing_attack_new_source_not_detected);
    RUN_TEST(test_timing_attack_suspicious_fast_processing);
    RUN_TEST(test_timing_attack_normal_processing_not_flagged);

    /* escalate_security_response() tests */
    RUN_TEST(test_escalation_unknown_source_allows);
    RUN_TEST(test_escalation_critical_confidence_permanent_block);
    RUN_TEST(test_escalation_high_confidence_temp_block);
    RUN_TEST(test_escalation_medium_confidence_rate_limit);
    RUN_TEST(test_escalation_low_confidence_allows);
    RUN_TEST(test_escalation_fragment_bomb_immediate_block);
    RUN_TEST(test_escalation_session_hijack_immediate_block);

    /* Threshold tests */
    RUN_TEST(test_security_thresholds_defined);
    RUN_TEST(test_confidence_levels_defined);
    RUN_TEST(test_response_levels_defined);

    return UNITY_END();
}
