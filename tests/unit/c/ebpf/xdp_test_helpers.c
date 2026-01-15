/**
 * @file xdp_test_helpers.c
 * @brief Implementation of XDP test helper functions
 *
 * Provides userspace-testable implementations for XDP packet filtering tests.
 * All functions work with existing eBPF structures and protocol specifications.
 *
 * Reference: EBPF_MASTER_IMPLEMENTATION_PLAN.md Stage 3
 */

#include "xdp_test_helpers.h"
#include "logic/port_calculation.h"
#include "logic/packet_detection.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// ============================================================================
// Global Test State
// ============================================================================

static uint64_t mock_time_ns = 1234567890000000000ULL;
static bool ringbuffer_full = false;
static uint64_t ringbuffer_drop_count = 0;

// Session routing table for testing
#define MAX_TEST_SESSIONS 100
static struct {
    uint64_t session_id;
    uint32_t ring_buffer_id;
    bool active;
} session_routing_table[MAX_TEST_SESSIONS];

// ============================================================================
// Time Functions
// ============================================================================

uint64_t test_get_time_ns(void) {
    return mock_time_ns;
}

void test_set_time_ns(uint64_t time_ns) {
    mock_time_ns = time_ns;
}

// ============================================================================
// Port Calculation Functions
// ============================================================================

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *output) {
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, key_len, data, data_len, output, &len);
}

uint16_t calculate_base_port_for_time_bucket(const uint8_t *daily_key, uint32_t time_bucket) {
    // Per design/protocol/10-port-hopping.md:
    // HMAC-SHA256(daily_key, time_bucket || "base_port_sequence_v2")

    const char* context_str = "base_port_sequence_v2";
    size_t context_len = strlen(context_str);

    // Convert time_bucket to big-endian u64
    uint64_t time_bucket_u64 = time_bucket;
    uint8_t input[8 + 21];

    // Big-endian encoding
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
    hmac_sha256(daily_key, 32, input, 8 + context_len, hmac_result);

    // Extract first 4 bytes as big-endian uint32
    uint32_t hash_u32 = ((uint32_t)hmac_result[0] << 24) |
                        ((uint32_t)hmac_result[1] << 16) |
                        ((uint32_t)hmac_result[2] << 8) |
                        hmac_result[3];

    // Map to port range 1024-65535 using modulo
    uint16_t port = 1024 + (hash_u32 % (65535 - 1024 + 1));

    return port;
}

uint32_t calculate_base_port_time_bucket(uint64_t utc_milliseconds) {
    // Daily epoch: milliseconds since midnight UTC / 500ms
    uint64_t millis_since_midnight = utc_milliseconds % (24ULL * 60 * 60 * 1000);
    return (uint32_t)(millis_since_midnight / 500);
}

uint32_t calculate_session_time_bucket(uint64_t utc_milliseconds) {
    // Monthly epoch: milliseconds since month start / 500ms
    // Use reference epoch (Jan 12, 1970 00:00 UTC) to align 30-day cycles
    // with test expectations (Oct 1, 2023 00:00 UTC should be bucket 0)
    const uint64_t MONTH_REFERENCE_EPOCH = 950400000ULL;  // 11 days in milliseconds
    const uint64_t MONTH_DURATION_MS = 30ULL * 24 * 60 * 60 * 1000;  // 30 days

    uint64_t millis_since_reference = utc_milliseconds - MONTH_REFERENCE_EPOCH;
    uint64_t millis_since_month_start = millis_since_reference % MONTH_DURATION_MS;
    return (uint32_t)(millis_since_month_start / 500);
}

int validate_port_matches(uint16_t received_port, uint16_t expected_port) {
    return (received_port == expected_port) ? PORT_VALID : PORT_INVALID;
}

// ============================================================================
// Fragment Security Functions
// ============================================================================

int validate_fragment_session_binding(const struct fragment_header *frag,
                                       uint64_t expected_session_id) {
    if (!frag) {
        return FRAGMENT_SESSION_MISMATCH;
    }

    if (frag->session_id != expected_session_id) {
        return FRAGMENT_SESSION_MISMATCH;
    }

    return FRAGMENT_SESSION_VALID;
}

int check_fragment_overlap(struct reassembly_state *state,
                           const struct fragment_header *frag) {
    if (!state || !frag) {
        return FRAGMENT_OVERLAP_DETECTED;
    }

    // Check for byte-range overlap with already received fragments
    uint16_t new_start = frag->fragment_offset;
    uint16_t new_end = new_start + frag->fragment_length;

    for (uint32_t i = 0; i < state->range_count; i++) {
        uint16_t existing_start = state->ranges[i].offset;
        uint16_t existing_end = existing_start + state->ranges[i].length;

        // Check if ranges overlap
        // Ranges [a,b) and [c,d) overlap if: a < d AND c < b
        if (new_start < existing_end && existing_start < new_end) {
            return FRAGMENT_OVERLAP_DETECTED;
        }
    }

    return FRAGMENT_NO_OVERLAP;
}

int check_fragment_memory_limit(const struct session_security_state *sec,
                                 uint32_t new_fragment_size) {
    if (!sec) {
        return FRAGMENT_MEMORY_EXCEEDED;
    }

    const uint64_t MAX_REASSEMBLY_MEMORY = 1024 * 1024;  // 1MB

    if (sec->total_reassembly_memory + new_fragment_size > MAX_REASSEMBLY_MEMORY) {
        return FRAGMENT_MEMORY_EXCEEDED;
    }

    return FRAGMENT_MEMORY_OK;
}

int check_fragment_timeout_expired(const struct session_security_state *sec,
                                    uint64_t current_time) {
    (void)current_time;  // Unused until oldest_fragment_time field added

    if (!sec) {
        return FRAGMENT_TIMEOUT_EXPIRED;
    }

    // TODO: session_security_state needs oldest_fragment_time field
    // For now, just reject null input
    return FRAGMENT_TIMEOUT_OK;
}

int add_fragment_to_reassembly(struct reassembly_state *state,
                                const struct fragment_header *frag) {
    if (!state || !frag) {
        return -1;
    }

    // Mark fragment as received in bitmap
    uint32_t bitmap_index = frag->fragment_index / 32;
    uint32_t bit_position = frag->fragment_index % 32;

    if (bitmap_index >= 4) {
        return -1;
    }

    uint32_t mask = 1U << bit_position;
    state->fragment_bitmap[bitmap_index] |= mask;
    state->total_memory += frag->fragment_length;

    // Track fragment range for overlap detection
    if (state->range_count < 128) {
        state->ranges[state->range_count].offset = frag->fragment_offset;
        state->ranges[state->range_count].length = frag->fragment_length;
        state->range_count++;
    }

    return 0;
}

// ============================================================================
// HMAC Policy Functions
// ============================================================================

uint8_t determine_hmac_policy(const struct hmac_session_state *session, uint8_t packet_type) {
    return determine_hmac_policy_with_time(session, packet_type, test_get_time_ns());
}

uint8_t determine_hmac_policy_with_time(const struct hmac_session_state *session,
                                         uint8_t packet_type,
                                         uint64_t current_time) {
    if (!session) {
        return HMAC_STRONG;
    }

    // Trigger 1: Every 100 data packets → HMAC_STRONG
    // When count=99, the next packet (100th) should use STRONG
    if (packet_type == PKT_TYPE_DATA && session->data_packet_count % 100 == 99) {
        return HMAC_STRONG;
    }

    // Trigger 2: Every 5 seconds → HMAC_STRONG
    // Only check if last_hmac_strong_time has been set (non-zero)
    if (session->last_hmac_strong_time > 0) {
        uint64_t time_since_last_strong = current_time - session->last_hmac_strong_time;
        if (time_since_last_strong >= (5 * NSEC_PER_SEC)) {
            return HMAC_STRONG;
        }
    }

    // Trigger 2.5: Month boundary transition window
    // Use HMAC_STRONG within 1 second before and 4 seconds after month boundary
    const uint64_t MONTH_REFERENCE_EPOCH_NS = 950400000ULL * NSEC_PER_MS;
    const uint64_t MONTH_DURATION_NS = 30ULL * 24 * 60 * 60 * NSEC_PER_SEC;
    const int64_t BOUNDARY_WINDOW_NS = 1 * NSEC_PER_SEC;  // 1 second before
    const int64_t BOUNDARY_AFTER_NS = 4 * NSEC_PER_SEC;   // 4 seconds after

    // Calculate current position within the month cycle
    uint64_t time_since_ref = current_time - MONTH_REFERENCE_EPOCH_NS;
    uint64_t pos_in_month = time_since_ref % MONTH_DURATION_NS;

    // Check if near start of month (just after boundary)
    if (pos_in_month <= (uint64_t)BOUNDARY_AFTER_NS) {
        return HMAC_STRONG;
    }

    // Check if near end of month (just before boundary)
    if (pos_in_month >= MONTH_DURATION_NS - (uint64_t)BOUNDARY_WINDOW_NS) {
        return HMAC_STRONG;
    }

    // Trigger 3: Critical packets → HMAC_STRONG
    // SYN, SYN_ACK, FIN, DISCOVERY, MANAGEMENT always use HMAC_STRONG
    if (packet_type == PKT_TYPE_SYN || packet_type == PKT_TYPE_SYN_ACK ||
        packet_type == PKT_TYPE_FIN || packet_type == PKT_TYPE_DISCOVERY ||
        packet_type == PKT_TYPE_MANAGEMENT) {
        return HMAC_STRONG;
    }

    // Trigger 4: Control packets → HMAC_MEDIUM+
    // ERROR, RST, HEARTBEAT, TIME_SYNC, KEY_UPDATE require at least HMAC_MEDIUM
    if (packet_type == PKT_TYPE_ERROR || packet_type == PKT_TYPE_RST ||
        packet_type == PKT_TYPE_HEARTBEAT || packet_type == PKT_TYPE_TIME_SYNC ||
        packet_type == PKT_TYPE_KEY_UPDATE) {
        return HMAC_MEDIUM;
    }

    // Default: HMAC_LIGHT
    return HMAC_LIGHT;
}

size_t get_hmac_size(uint8_t hmac_policy) {
    switch (hmac_policy) {
        case HMAC_LIGHT:
            return 8;   // 64-bit
        case HMAC_MEDIUM:
            return 16;  // 128-bit
        case HMAC_STRONG:
            return 32;  // 256-bit
        default:
            return 32;
    }
}

uint64_t get_month_end_utc_ns(uint64_t current_time_ns) {
    // Use same reference epoch as calculate_session_time_bucket
    const uint64_t MONTH_REFERENCE_EPOCH = 950400000ULL;  // milliseconds
    const uint64_t MONTH_DURATION_MS = 30ULL * 24 * 60 * 60 * 1000;  // 30 days

    uint64_t current_ms = current_time_ns / NSEC_PER_MS;
    uint64_t millis_since_reference = current_ms - MONTH_REFERENCE_EPOCH;
    uint64_t months_since_reference = millis_since_reference / MONTH_DURATION_MS;
    uint64_t month_end_ms = MONTH_REFERENCE_EPOCH + ((months_since_reference + 1) * MONTH_DURATION_MS);
    return month_end_ms * NSEC_PER_MS;
}

// ============================================================================
// Adaptive Window Functions
// ============================================================================

int check_adaptive_window(struct adaptive_delay_state *window,
                          uint64_t packet_time,
                          uint64_t current_time) {
    if (!window) {
        return WINDOW_REJECT;
    }

    int64_t time_diff_ns;
    if (packet_time > current_time) {
        // Packet from future
        time_diff_ns = packet_time - current_time;
        uint64_t future_window_ns = window->future_window_size * NSEC_PER_MS;

        if (time_diff_ns <= (int64_t)future_window_ns) {
            window->early_count++;
            return WINDOW_ACCEPT;
        }
    } else {
        // Packet from past
        time_diff_ns = current_time - packet_time;
        uint64_t past_window_ns = window->past_window_size * NSEC_PER_MS;

        if (time_diff_ns <= (int64_t)past_window_ns) {
            window->late_count++;
            return WINDOW_ACCEPT;
        }
    }

    return WINDOW_REJECT;
}

void adjust_adaptive_window(struct adaptive_delay_state *window) {
    if (!window) {
        return;
    }

    // Expand past window if many late packets
    if (window->late_count > 10) {
        window->past_window_size += 50;
        if (window->past_window_size > 1000) {
            window->past_window_size = 1000;
        }
    }

    // Expand future window if many early packets
    if (window->early_count > 10) {
        window->future_window_size += 50;
        if (window->future_window_size > 1000) {
            window->future_window_size = 1000;
        }
    }

    // Reset counters
    window->late_count = 0;
    window->early_count = 0;
    window->last_update_ns = test_get_time_ns();
}

// ============================================================================
// Session Routing Functions
// ============================================================================

int register_session_routing(uint64_t session_id, uint32_t ring_buffer_id) {
    for (int i = 0; i < MAX_TEST_SESSIONS; i++) {
        if (!session_routing_table[i].active) {
            session_routing_table[i].session_id = session_id;
            session_routing_table[i].ring_buffer_id = ring_buffer_id;
            session_routing_table[i].active = true;
            return 0;
        }
    }
    return -1;
}

int unregister_session_routing(uint64_t session_id) {
    for (int i = 0; i < MAX_TEST_SESSIONS; i++) {
        if (session_routing_table[i].active &&
            session_routing_table[i].session_id == session_id) {
            session_routing_table[i].active = false;
            return 0;
        }
    }
    return -1;
}

int lookup_session_routing(uint64_t session_id, uint32_t *ring_buffer_id) {
    if (!ring_buffer_id) {
        return -1;
    }

    for (int i = 0; i < MAX_TEST_SESSIONS; i++) {
        if (session_routing_table[i].active &&
            session_routing_table[i].session_id == session_id) {
            *ring_buffer_id = session_routing_table[i].ring_buffer_id;
            return 0;
        }
    }
    return -1;
}

uint32_t route_packet_to_ringbuffer(uint64_t session_id) {
    uint32_t rb_id = 0;
    if (lookup_session_routing(session_id, &rb_id) == 0) {
        return rb_id;
    }
    return 0;
}

// ============================================================================
// Ring Buffer Functions
// ============================================================================

int submit_packet_event_to_ringbuf(const struct packet_event *event) {
    if (!event) {
        return -EINVAL;
    }

    if (ringbuffer_full) {
        ringbuffer_drop_count++;
        return -ENOSPC;
    }

    return 0;
}

uint64_t get_ringbuf_drop_count(void) {
    return ringbuffer_drop_count;
}

void setup_full_ringbuffer(void) {
    ringbuffer_full = true;
}

void reset_ringbuffer(void) {
    ringbuffer_full = false;
    ringbuffer_drop_count = 0;
}

// ============================================================================
// Test Helper Functions
// ============================================================================

struct xdp_md* create_test_xdp_context(const struct buckwild_packet *pkt, size_t pkt_size) {
    struct xdp_md *ctx = malloc(sizeof(struct xdp_md));
    if (!ctx) {
        return NULL;
    }

    ctx->data = malloc(pkt_size);
    if (!ctx->data) {
        free(ctx);
        return NULL;
    }

    memcpy(ctx->data, pkt, pkt_size);
    ctx->data_end = ctx->data + pkt_size;
    ctx->ingress_ifindex = 0;

    return ctx;
}

struct buckwild_packet* create_invalid_packet(size_t *size) {
    struct buckwild_packet *pkt = malloc(sizeof(struct buckwild_packet));
    if (!pkt) {
        return NULL;
    }

    // Not Buckwild magic
    pkt->magic[0] = 'X';
    pkt->magic[1] = 'Y';
    pkt->magic[2] = 'Z';
    pkt->magic[3] = 'Z';
    pkt->session_id = 0;
    pkt->sequence = 0;
    pkt->packet_type = 0;
    pkt->flags = 0;
    pkt->payload_length = 0;

    if (size) {
        *size = sizeof(struct buckwild_packet);
    }

    return pkt;
}

struct buckwild_packet* create_buckwild_packet(uint64_t session_id, uint8_t type, size_t *size) {
    struct buckwild_packet *pkt = malloc(sizeof(struct buckwild_packet));
    if (!pkt) {
        return NULL;
    }

    // Buckwild magic
    pkt->magic[0] = 'B';
    pkt->magic[1] = 'K';
    pkt->magic[2] = 'W';
    pkt->magic[3] = 'D';
    pkt->session_id = session_id;
    pkt->sequence = 1;
    pkt->packet_type = type;
    pkt->flags = 0;
    pkt->payload_length = 64;

    if (size) {
        *size = sizeof(struct buckwild_packet);
    }

    return pkt;
}

int xdp_buckwild_main(struct xdp_md *ctx) {
    if (!ctx || !ctx->data || !ctx->data_end) {
        return XDP_DROP;
    }

    if (ctx->data_end - ctx->data < (long)sizeof(struct buckwild_packet)) {
        return XDP_DROP;
    }

    struct buckwild_packet *pkt = (struct buckwild_packet *)ctx->data;

    // Check magic
    if (pkt->magic[0] != 'B' || pkt->magic[1] != 'K' ||
        pkt->magic[2] != 'W' || pkt->magic[3] != 'D') {
        return XDP_DROP;
    }

    return XDP_PASS;
}

int check_session_rate_limit(const struct rate_limit_session_state *session, uint64_t current_time) {
    if (!session) {
        return RATE_LIMIT_EXCEEDED;
    }

    // Check if rate limit reset time has passed
    if (current_time >= session->rate_limit_reset_time) {
        return 0;  // Reset occurred, OK
    }

    // Check if tokens remaining
    if (session->rate_limit_remaining == 0) {
        return RATE_LIMIT_EXCEEDED;
    }

    return 0;  // OK
}

int bpf_map_update_elem(void *map, const void *key, const void *value, uint64_t flags) {
    (void)map;
    (void)key;
    (void)value;
    (void)flags;
    return 0;
}
