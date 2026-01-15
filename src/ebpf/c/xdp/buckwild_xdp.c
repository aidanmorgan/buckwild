#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/maps.h"
#include "../include/events.h"
#include "../include/protocol.h"
#include "../include/security.h"
#include "../include/fragment_security.h"

char LICENSE[] SEC("license") = "GPL";

// Per-CPU array for parsed_header to avoid stack overflow
// BPF stack limit is 512 bytes; parsed_header struct exceeds this
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct parsed_header);
    __uint(max_entries, 1);
} parsed_header_map SEC(".maps");

// Helper function to extract IP addresses and ports
static __always_inline int extract_network_info(struct xdp_md *ctx,
                                                __u32 *src_ip,
                                                __u32 *dst_ip,
                                                __u16 *src_port,
                                                __u16 *dst_port) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    if (ip->protocol != IPPROTO_UDP)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;

    // Bounds check before UDP header pointer arithmetic
    // eBPF verifier requires bounds validation before pointer arithmetic
    if ((void *)ip + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
        return -1;

    // Parse UDP header
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return -1;
    
    *src_port = bpf_ntohs(udp->source);
    *dst_port = bpf_ntohs(udp->dest);
    
    return 0;
}

// Forward packet to userspace via ring buffer
static __always_inline int forward_to_userspace(struct xdp_md *ctx,
                                                struct parsed_header *parsed,
                                                __u32 src_ip,
                                                __u32 dst_ip,
                                                __u16 src_port,
                                                __u16 dst_port,
                                                __u8 security_action) {
    // Submit packet event using helper from events.h
    int ret = submit_packet_event(
        &packet_ring_buffer,
        parsed->session_id,
        parsed->sequence_number,
        (__u16)(ctx->data_end - ctx->data),
        parsed->packet_type,
        parsed->security_flags,
        src_ip
    );

    // If event submission failed, pass to kernel
    if (ret < 0) {
        return XDP_PASS; // Ring buffer full or error
    }

    // Submit security event if applicable
    if (security_action != SEC_ACTION_ALLOW) {
        // Map security action to appropriate event type for logging
        __u32 event_type;
        switch (security_action) {
            case SEC_ACTION_DROP:
                event_type = SEC_EVENT_UNKNOWN_SESSION;
                break;
            case SEC_ACTION_RATE_LIMIT:
                event_type = SEC_EVENT_RATE_LIMIT_VIOLATION;
                break;
            case SEC_ACTION_BLOCK_TEMP:
            case SEC_ACTION_BLOCK_PERM:
                event_type = SEC_EVENT_SESSION_HIJACK;
                break;
            default:
                event_type = SEC_EVENT_UNKNOWN_SESSION;
                break;
        }
        submit_security_event(
            &packet_ring_buffer,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            parsed->session_id,
            event_type,
            SEC_SEVERITY_MEDIUM
        );
    }

    return XDP_REDIRECT; // Redirect to userspace program
}

// Update port statistics with security metrics
static __always_inline void update_port_statistics(__u16 port,
                                                   __u32 packet_size,
                                                   __u8 security_event) {
    __u32 port_key = port;
    struct port_stats *stats = MAP_LOOKUP_ELEM(port_stats_map, &port_key);
    
    if (!stats) {
        struct port_stats new_stats = {
            .packet_count = 1,
            .byte_count = packet_size,
            .last_used_time = bpf_ktime_get_ns(),
            .session_count = 0,
            .security_events = (security_event != SEC_ACTION_ALLOW) ? 1 : 0,
            .rate_limit_violations = 0,
            .attack_attempts = 0,
            .current_hop_window = 0,
            .security_level = 0,
            .reserved = {0}
        };
        MAP_UPDATE_ELEM(port_stats_map, &port_key, &new_stats, BPF_ANY);
    } else {
        stats->packet_count++;
        stats->byte_count += packet_size;
        stats->last_used_time = bpf_ktime_get_ns();
        
        if (security_event != SEC_ACTION_ALLOW) {
            stats->security_events++;
            if (security_event == SEC_ACTION_RATE_LIMIT) {
                stats->rate_limit_violations++;
            } else if (security_event == SEC_ACTION_DROP ||
                      security_event == SEC_ACTION_BLOCK_TEMP ||
                      security_event == SEC_ACTION_BLOCK_PERM) {
                stats->attack_attempts++;
            }
        }
        
        MAP_UPDATE_ELEM(port_stats_map, &port_key, stats, BPF_ANY);
    }
}

// Validate session routing with efficient header parsing
static __always_inline int validate_session_routing(struct parsed_header *parsed,
                                                    __u32 src_ip,
                                                    __u16 src_port) {
    struct session_info *session = MAP_LOOKUP_ELEM(session_map, &parsed->session_id);
    
    if (!session) {
        // Unknown session - could be new connection or attack
        parsed->security_flags |= VALIDATION_INVALID_SESSION;
        return -1;
    }
    
    // Validate session binding
    if (session->src_ip != src_ip || session->src_port != src_port) {
        // Potential session hijacking
        session->security_violations++;
        session->attack_detected = 1;
        parsed->security_flags |= VALIDATION_INVALID_SESSION;
        MAP_UPDATE_ELEM(session_map, &parsed->session_id, session, BPF_ANY);
        return -1;
    }
    
    // Update session activity
    session->last_packet_time = bpf_ktime_get_ns();
    session->packet_count++;
    
    // Validate sequence number (eBPF can only do basic check; userspace handles full anti-replay window)
    if (parsed->sequence_number <= session->last_sequence) {
        // Potential replay attack
        parsed->security_flags |= VALIDATION_REPLAY_ATTACK;
        session->security_violations++;
    } else {
        session->last_sequence = parsed->sequence_number;
    }
    
    MAP_UPDATE_ELEM(session_map, &parsed->session_id, session, BPF_ANY);
    return 0;
}

// Port hopping validation - validates destination port against expected port from session
static __always_inline int validate_port_hopping(__u16 dest_port,
                                                 __u32 timestamp __attribute__((unused)),
                                                 __u64 session_id,
                                                 __u64 current_time __attribute__((unused))) {
    // Port hopping validation - validates against expected_port stored in session map
    // Note: PBKDF2-based port calculation is done in userspace and stored in session.expected_port
    // eBPF instruction limits prevent cryptographic operations here
    
    struct session_info *session = MAP_LOOKUP_ELEM(session_map, &session_id);
    if (!session) {
        return -1; // No session to validate against
    }
    
    // Check if port is within expected range (with timing tolerance for clock drift)
    __u32 expected_port = session->expected_port;
    __u16 port_tolerance = 10; // Allow some tolerance for timing
    
    if (dest_port < expected_port - port_tolerance ||
        dest_port > expected_port + port_tolerance) {
        return -1; // Port outside expected range
    }
    
    return 0;
}

// Early attack detection with comprehensive patterns
static __always_inline int detect_early_attacks(struct parsed_header *parsed,
                                                __u32 src_ip,
                                                __u16 src_port __attribute__((unused)),
                                                __u16 dest_port,
                                                __u64 current_time) {
    // Check for enumeration attempts
    if (parsed->packet_type == PKT_TYPE_SYN || 
        parsed->packet_type == PKT_TYPE_DISCOVERY) {
        if (detect_enumeration_attack(src_ip, dest_port, parsed->packet_type, current_time)) {
            return SEC_EVENT_ENUMERATION_ATTACK;
        }
    }
    
    // Check for replay attacks
    if (detect_replay_attack(src_ip, parsed->session_id, parsed->sequence_number,
                           parsed->timestamp, current_time)) {
        return SEC_EVENT_REPLAY_ATTACK;
    }
    
    // Check for port scanning patterns
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    if (attack_info) {
        // Optimized port scan detection: avoid division by rewriting inequality
        // Original: (attempts * 1e9) / time_diff > 50
        // Rewritten: attempts * 1e9 > 50 * time_diff
        __u64 time_diff = current_time - attack_info->first_seen;
        if (time_diff > 0) {
            if (attack_info->connection_attempts * 1000000000ULL > 50 * time_diff) {
                return SEC_EVENT_PORT_SCAN;
            }
        }
    }
    
    return 0; // No attack detected
}

// Implement proper tail calls for complex processing
static __always_inline int handle_complex_packet_processing(struct xdp_md *ctx,
                                                           struct parsed_header *parsed,
                                                           __u32 src_ip,
                                                           __u32 dst_ip,
                                                           __u16 src_port,
                                                           __u16 dst_port) {
    // This would use BPF tail calls for complex processing
    // For now, we'll do inline processing
    
    __u64 current_time = bpf_ktime_get_ns();
    
    // Comprehensive security validation
    int security_result = validate_packet_security(parsed, src_ip, src_port,
                                                   dst_ip, dst_port,
                                                   (void *)(long)ctx->data,
                                                   (void *)(long)ctx->data_end,
                                                   current_time);
    
    if (security_result != SEC_ACTION_ALLOW) {
        update_port_statistics(dst_port, ctx->data_end - ctx->data, security_result);
        
        if (security_result == SEC_ACTION_DROP ||
            security_result == SEC_ACTION_BLOCK_TEMP ||
            security_result == SEC_ACTION_BLOCK_PERM) {
            return XDP_DROP;
        }
    }
    
    // Forward to userspace for further processing
    return forward_to_userspace(ctx, parsed, src_ip, dst_ip, src_port, dst_port, security_result);
}

// Main XDP program entry point
SEC("xdp")
int xdp_buckwild_handler(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Extract network information
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    
    if (extract_network_info(ctx, &src_ip, &dst_ip, &src_port, &dst_port) < 0) {
        return XDP_PASS; // Not UDP packet
    }
    
    // Check if this could be a Buckwild protocol packet
    if (!is_potential_buckwild_port(dst_port)) {
        return XDP_PASS; // Not our protocol
    }
    
    // Get UDP payload
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);

    // Bounds check before payload access
    // eBPF verifier requires validation of all packet data access
    void *payload = (void *)(udp + 1);
    if (payload > data_end) {
        return XDP_PASS; // Malformed packet
    }

    // Basic protocol detection
    if (!is_buckwild_packet(payload, data_end)) {
        return XDP_PASS; // Not Buckwild protocol
    }

    // Get parsed_header from per-CPU map to avoid stack overflow
    __u32 key = 0;
    struct parsed_header *parsed = MAP_LOOKUP_ELEM(parsed_header_map, &key);
    if (!parsed) {
        return XDP_DROP; // Map lookup failed
    }

    // Zero-initialize the parsed header
    __builtin_memset(parsed, 0, sizeof(*parsed));

    // Parse adaptive header with comprehensive bounds checking
    if (parse_buckwild_header(payload, data_end, parsed) < 0) {
        // Invalid packet - update statistics and drop
        update_port_statistics(dst_port, ctx->data_end - ctx->data, SEC_ACTION_DROP);
        return XDP_DROP;
    }
    
    __u64 current_time = bpf_ktime_get_ns();

    // Validate timestamp against dual-epoch system
    __u8 epoch_type = (parsed->packet_type == PKT_TYPE_SYN ||
                      parsed->packet_type == PKT_TYPE_DISCOVERY) ?
                      EPOCH_DAILY : EPOCH_MONTHLY;

    if (validate_timestamp(parsed->timestamp, parsed->timestamp_length,
                          current_time, epoch_type) < 0) {
        parsed->validation_status |= VALIDATION_INVALID_TIMESTAMP;
        update_port_statistics(dst_port, ctx->data_end - ctx->data, SEC_ACTION_DROP);
        return XDP_DROP;
    }

    // HMAC Light Check (8-byte prefix validation)
    if (parsed->hmac_policy == HMAC_POLICY_LIGHT && parsed->session_id != 0) {
        struct session_info *session = MAP_LOOKUP_ELEM(session_map, &parsed->session_id);
        if (session) {
            // Calculate HMAC offset: header_length - hmac_size
            __u8 hmac_size = 8; // HMAC_POLICY_LIGHT = 8 bytes
            __u16 hmac_offset = parsed->header_length - hmac_size;

            // Calculate absolute pointer to HMAC in packet
            void *hmac_ptr = payload + hmac_offset;

            // Bounds check before HMAC access
            if (hmac_ptr + 8 > data_end) {
                parsed->validation_status |= VALIDATION_INVALID_HMAC;
                update_port_statistics(dst_port, ctx->data_end - ctx->data, SEC_ACTION_DROP);
                submit_drop_event(&packet_ring_buffer, src_ip, src_port,
                                 DROP_REASON_HMAC_FAILURE, parsed->session_id);
                return XDP_DROP;
            }

            // Compare first 8 bytes of HMAC using unrolled loop (verifier-safe)
            __u8 *expected = session->expected_hmac_prefix;
            __u8 *actual = (__u8 *)hmac_ptr;

            if (expected[0] != actual[0] || expected[1] != actual[1] ||
                expected[2] != actual[2] || expected[3] != actual[3] ||
                expected[4] != actual[4] || expected[5] != actual[5] ||
                expected[6] != actual[6] || expected[7] != actual[7]) {
                parsed->validation_status |= VALIDATION_INVALID_HMAC;
                update_port_statistics(dst_port, ctx->data_end - ctx->data, SEC_ACTION_DROP);
                submit_drop_event(&packet_ring_buffer, src_ip, src_port,
                                 DROP_REASON_HMAC_FAILURE, parsed->session_id);
                return XDP_DROP;
            }

            // HMAC validation passed
            parsed->validation_status &= ~VALIDATION_INVALID_HMAC;
        }
    }

    // Validate session routing (for established sessions)
    if (parsed->session_id != 0) {
        if (validate_session_routing(parsed, src_ip, src_port) < 0) {
            update_port_statistics(dst_port, ctx->data_end - ctx->data, SEC_ACTION_DROP);
            return XDP_DROP;
        }
    }

    // Validate port hopping
    if (validate_port_hopping(dst_port, parsed->timestamp, parsed->session_id, current_time) < 0) {
        // Port hopping validation failed - could be attack or timing issue
        parsed->security_flags |= VALIDATION_INVALID_TIMESTAMP;
    }

    // Early attack detection
    int attack_type = detect_early_attacks(parsed, src_ip, src_port, dst_port, current_time);
    if (attack_type > 0) {
        update_port_statistics(dst_port, ctx->data_end - ctx->data, SEC_ACTION_DROP);
        batch_security_event(attack_type, SEC_SEVERITY_HIGH,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        return XDP_DROP;
    }

    // Handle complex packet processing with security validation
    return handle_complex_packet_processing(ctx, parsed, src_ip, dst_ip, src_port, dst_port);
}

// XDP program for packet redirection - handles redirecting packets to specific interfaces
SEC("xdp_redirect")
int xdp_buckwild_redirect(struct xdp_md *ctx) {
    // Redirect validated packets to TUN device via devmap
    // Devmap is populated by userspace with TUN device ifindex

    __u32 ingress_ifindex = ctx->ingress_ifindex;
    __u32 *target_ifindex = bpf_map_lookup_elem(&xdp_devmap, &ingress_ifindex);

    if (!target_ifindex) {
        // No redirect target configured for this interface
        // Submit event and pass to kernel stack
        submit_drop_event(&packet_ring_buffer, 0, 0,
                         DROP_REASON_INVALID_PORT, 0);
        return XDP_PASS;
    }

    // Redirect packet to target interface (TUN device)
    // Use *target_ifindex (the VALUE from lookup) as the redirect target
    int ret = bpf_redirect_map(&xdp_devmap, *target_ifindex, 0);
    if (ret < 0) {
        // Redirect failed, pass to kernel
        submit_drop_event(&packet_ring_buffer, 0, 0,
                         DROP_REASON_PARSE_ERROR, 0);
        return XDP_PASS;
    }

    return ret;
}

// XDP program for load balancing - distributes packets across multiple processing units
SEC("xdp_lb")
int xdp_buckwild_load_balance(struct xdp_md *ctx) {
    // Distribute packets across CPUs based on session_id hash
    // Provides session affinity - same session always to same CPU

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse to get session_id for hashing
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Bounds check before UDP header pointer arithmetic
    // eBPF verifier requires bounds validation before pointer arithmetic
    if ((void *)ip + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Bounds check before payload access
    // eBPF verifier requires validation of all packet data access
    void *payload = (void *)(udp + 1);
    if (payload > data_end)
        return XDP_PASS;

    // Get parsed_header from per-CPU map to avoid stack overflow
    __u32 key = 0;
    struct parsed_header *parsed = MAP_LOOKUP_ELEM(parsed_header_map, &key);
    if (!parsed)
        return XDP_PASS;

    // Zero-initialize the parsed header
    __builtin_memset(parsed, 0, sizeof(*parsed));

    if (parse_buckwild_header(payload, data_end, parsed) < 0)
        return XDP_PASS;

    // Hash session_id to CPU index for session affinity
    // Use cpumap max_entries (256) as modulo - userspace populates only online CPUs
    // bpf_redirect_map returns XDP_PASS if target CPU not in map (graceful fallback)
    __u32 target_cpu = (__u32)(parsed->session_id % 256);

    // Redirect to target CPU via cpumap (XDP_PASS fallback on miss)
    return bpf_redirect_map(&xdp_cpumap, target_cpu, XDP_PASS);
}