/**
 * @file xdp_test_helpers.h
 * @brief Test helper functions for XDP packet filtering tests
 *
 * Provides userspace-testable implementations of XDP logic for unit testing.
 * Works with existing eBPF header structures and extends them only where needed.
 *
 * Reference: EBPF_MASTER_IMPLEMENTATION_PLAN.md Stage 3
 */

#ifndef BUCKWILD_XDP_TEST_HELPERS_H
#define BUCKWILD_XDP_TEST_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

// Include existing eBPF headers (these define base structures)
#include "logic/session_validation.h"
#include "logic/security_checks.h"

// ============================================================================
// Additional Constants (only those not in existing headers)
// ============================================================================

// Time constants (always define for tests)
#define NSEC_PER_SEC  1000000000ULL
#define NSEC_PER_MS   1000000ULL
#define MS_PER_SEC    1000ULL

// HMAC Policy Levels (design/protocol/03-packet-architecture.md lines 154-171)
#ifndef HMAC_LIGHT
#define HMAC_LIGHT    0  // 8 bytes (64-bit)
#define HMAC_MEDIUM   1  // 16 bytes (128-bit)
#define HMAC_STRONG   2  // 32 bytes (256-bit)
#endif

// Packet Types (design/protocol/03-packet-architecture.md)
#ifndef PKT_TYPE_DATA
#define PKT_TYPE_DATA         0x04
#endif
#ifndef PKT_TYPE_ACK
#define PKT_TYPE_ACK          0x03
#endif
#ifndef PKT_TYPE_CLOSE
#define PKT_TYPE_CLOSE        0x05
#endif
#ifndef PKT_TYPE_CLOSE_ACK
#define PKT_TYPE_CLOSE_ACK    0x06
#endif
#ifndef PKT_TYPE_TIME_SYNC
#define PKT_TYPE_TIME_SYNC    0x10
#endif
#ifndef PKT_TYPE_KEY_UPDATE
#define PKT_TYPE_KEY_UPDATE   0x11
#endif

// Fragment test results
#define FRAGMENT_SESSION_VALID    0
#define FRAGMENT_SESSION_MISMATCH -1
#define FRAGMENT_NO_OVERLAP       0
#define FRAGMENT_OVERLAP_DETECTED -2
#define FRAGMENT_MEMORY_OK        0
#define FRAGMENT_MEMORY_EXCEEDED  -1
#define FRAGMENT_TIMEOUT_OK       0
#define FRAGMENT_TIMEOUT_EXPIRED  -1

// Adaptive window results
#define WINDOW_ACCEPT  0
#define WINDOW_REJECT -1

// XDP verdicts
#ifndef XDP_DROP
#define XDP_DROP 1
#define XDP_PASS 2
#endif

// Ring buffer error
#ifndef ENOSPC
#define ENOSPC 28
#endif

// ============================================================================
// Test-Specific Data Structures
// ============================================================================

/**
 * Extended session state for HMAC policy testing
 * Adds fields needed for HMAC policy that aren't in base session_state
 */
struct hmac_session_state {
    uint64_t session_id;
    uint32_t data_packet_count;
    uint32_t last_hmac_strong_packet;
    uint64_t last_hmac_strong_time;
};

/**
 * Extended session state for rate limiting testing
 */
struct rate_limit_session_state {
    uint64_t session_id;
    uint32_t rate_limit_remaining;
    uint64_t rate_limit_reset_time;
};

/**
 * Fragment header structure
 */
struct fragment_header {
    uint64_t fragment_id;
    uint16_t fragment_index;
    uint16_t total_fragments;
    uint64_t session_id;
    uint16_t fragment_offset;
    uint16_t fragment_length;
};

/**
 * Fragment range for overlap detection
 */
struct fragment_range {
    uint16_t offset;
    uint16_t length;
};

/**
 * Fragment reassembly state
 */
struct reassembly_state {
    uint64_t session_id;
    uint32_t fragment_bitmap[4];  // Track up to 128 fragments
    uint64_t total_memory;
    uint64_t first_fragment_time;
    struct fragment_range ranges[128];  // Track offset ranges for overlap detection
    uint32_t range_count;
};

/**
 * Adaptive delay window state (from maps.h)
 */
struct adaptive_delay_state {
    uint32_t past_window_size;    /* milliseconds */
    uint32_t future_window_size;  /* milliseconds */
    uint32_t early_count;         /* packets from future */
    uint32_t late_count;          /* packets from past */
    uint64_t last_update_ns;      /* nanoseconds */
};

/**
 * Packet event structure (from maps.h)
 */
struct packet_event {
    uint64_t session_id;
    uint64_t sequence;
    uint64_t timestamp_us;
    uint16_t payload_length;
    uint8_t packet_type;
    uint8_t flags;
} __attribute__((packed));

/**
 * XDP context (simplified for testing)
 */
struct xdp_md {
    void *data;
    void *data_end;
    uint32_t ingress_ifindex;
};

/**
 * Buckwild packet header (simplified)
 */
struct buckwild_packet {
    uint8_t magic[4];      // "BKWD"
    uint64_t session_id;
    uint64_t sequence;
    uint8_t packet_type;
    uint8_t flags;
    uint16_t payload_length;
} __attribute__((packed));

// ============================================================================
// Port Calculation Functions
// ============================================================================

/**
 * Calculate HMAC-SHA256
 * Reference: design/protocol/10-port-hopping.md
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *output);

/**
 * Calculate base port for time bucket using HMAC-SHA256
 * Algorithm: HMAC-SHA256(daily_key, time_bucket || "base_port_sequence_v2")
 */
uint16_t calculate_base_port_for_time_bucket(const uint8_t *daily_key, uint32_t time_bucket);

/**
 * Calculate time bucket for base port hopping (daily epoch)
 */
uint32_t calculate_base_port_time_bucket(uint64_t utc_milliseconds);

/**
 * Calculate time bucket for session packets (monthly epoch)
 */
uint32_t calculate_session_time_bucket(uint64_t utc_milliseconds);

/**
 * Validate port matches expected
 */
int validate_port_matches(uint16_t received_port, uint16_t expected_port);

// ============================================================================
// Fragment Security Functions
// ============================================================================

/**
 * Validate fragment belongs to session
 */
int validate_fragment_session_binding(const struct fragment_header *frag,
                                       uint64_t expected_session_id);

/**
 * Check for fragment overlap in reassembly
 */
int check_fragment_overlap(struct reassembly_state *state,
                           const struct fragment_header *frag);

/**
 * Check fragment reassembly memory limit (1MB per session)
 */
int check_fragment_memory_limit(const struct session_security_state *sec,
                                 uint32_t new_fragment_size);

/**
 * Check fragment timeout (5 seconds)
 */
int check_fragment_timeout_expired(const struct session_security_state *sec,
                                    uint64_t current_time);

/**
 * Add fragment to reassembly state
 */
int add_fragment_to_reassembly(struct reassembly_state *state,
                                const struct fragment_header *frag);

// ============================================================================
// HMAC Policy Functions
// ============================================================================

/**
 * Determine HMAC policy for packet
 * Implements 4 triggers: 100 packets, 5 seconds, critical packets, control packets
 */
uint8_t determine_hmac_policy(const struct hmac_session_state *session, uint8_t packet_type);

/**
 * Determine HMAC policy with explicit time
 */
uint8_t determine_hmac_policy_with_time(const struct hmac_session_state *session,
                                         uint8_t packet_type,
                                         uint64_t current_time);

/**
 * Get HMAC size in bytes
 */
size_t get_hmac_size(uint8_t hmac_policy);

/**
 * Get month end timestamp
 */
uint64_t get_month_end_utc_ns(uint64_t current_time_ns);

// ============================================================================
// Adaptive Window Functions
// ============================================================================

/**
 * Check if packet is within adaptive delay window
 */
int check_adaptive_window(struct adaptive_delay_state *window,
                          uint64_t packet_time,
                          uint64_t current_time);

/**
 * Adjust window based on packet timing
 */
void adjust_adaptive_window(struct adaptive_delay_state *window);

// ============================================================================
// Session Routing Functions
// ============================================================================

/**
 * Register session for packet routing
 */
int register_session_routing(uint64_t session_id, uint32_t ring_buffer_id);

/**
 * Unregister session routing
 */
int unregister_session_routing(uint64_t session_id);

/**
 * Lookup session routing
 */
int lookup_session_routing(uint64_t session_id, uint32_t *ring_buffer_id);

/**
 * Route packet to ring buffer
 */
uint32_t route_packet_to_ringbuffer(uint64_t session_id);

// ============================================================================
// Ring Buffer Functions
// ============================================================================

/**
 * Submit packet event to ring buffer
 */
int submit_packet_event_to_ringbuf(const struct packet_event *event);

/**
 * Get ring buffer drop count
 */
uint64_t get_ringbuf_drop_count(void);

/**
 * Setup full ring buffer for overflow testing
 */
void setup_full_ringbuffer(void);

/**
 * Reset ring buffer state
 */
void reset_ringbuffer(void);

// ============================================================================
// Test Helper Functions
// ============================================================================

/**
 * Get mock time in nanoseconds
 */
uint64_t test_get_time_ns(void);

/**
 * Set mock time
 */
void test_set_time_ns(uint64_t time_ns);

/**
 * Create XDP context for testing
 */
struct xdp_md* create_test_xdp_context(const struct buckwild_packet *pkt, size_t pkt_size);

/**
 * Create invalid (non-Buckwild) packet
 */
struct buckwild_packet* create_invalid_packet(size_t *size);

/**
 * Create valid Buckwild packet
 */
struct buckwild_packet* create_buckwild_packet(uint64_t session_id, uint8_t type, size_t *size);

/**
 * XDP main entry point for testing
 */
int xdp_buckwild_main(struct xdp_md *ctx);

/**
 * Check rate limit for session
 */
int check_session_rate_limit(const struct rate_limit_session_state *session, uint64_t current_time);

/**
 * Mock BPF map update
 */
int bpf_map_update_elem(void *map, const void *key, const void *value, uint64_t flags);

#endif /* BUCKWILD_XDP_TEST_HELPERS_H */
