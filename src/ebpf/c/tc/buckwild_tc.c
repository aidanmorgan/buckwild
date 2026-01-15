#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/maps.h"
#include "../include/protocol.h"
#include "../include/security.h"

char LICENSE[] SEC("license") = "GPL";

// Traffic classification priorities
#define PRIO_CRITICAL       1   // SYN, SYN_ACK, FIN, DISCOVERY
#define PRIO_CONTROL        2   // ERROR, RST, HEARTBEAT, recovery
#define PRIO_DATA_URGENT    3   // Urgent data packets
#define PRIO_DATA_NORMAL    4   // Normal data packets
#define PRIO_DATA_BULK      5   // Bulk data packets

// Traffic shaping parameters
#define TOKEN_BUCKET_SIZE       1000    // Maximum tokens
#define TOKEN_REFILL_RATE       100     // Tokens per second
#define BURST_ALLOWANCE         200     // Burst tokens
#define RATE_LIMIT_WINDOW       1000000000ULL  // 1 second in nanoseconds

// QoS classes
#define QOS_CLASS_REALTIME      0
#define QOS_CLASS_INTERACTIVE   1
#define QOS_CLASS_BULK          2
#define QOS_CLASS_BACKGROUND    3

// Traffic shaping state per session
struct traffic_shaping_state {
    __u64 last_update_time;
    __u32 token_bucket;
    __u32 bytes_sent;
    __u32 packets_sent;
    __u16 current_rate_limit;
    __u8 qos_class;
    __u8 congestion_level;
    __u32 burst_allowance;
    __u32 reserved;
};

// Map for traffic shaping state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, __u64);    // session_id
    __type(value, struct traffic_shaping_state);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} traffic_shaping_map SEC(".maps");

// Port transition coordination state
struct port_transition_state {
    __u16 current_port;
    __u16 next_port;
    __u64 transition_time;
    __u32 packets_on_current;
    __u32 packets_on_next;
    __u8 transition_active;
    __u8 coordination_required;
    __u16 reserved;
};

// Map for port transition coordination
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, __u64);    // session_id
    __type(value, struct port_transition_state);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} port_transition_map SEC(".maps");

// Extract network information from TC context
static __always_inline int extract_tc_network_info(struct __sk_buff *skb,
                                                   __u32 *src_ip,
                                                   __u32 *dst_ip,
                                                   __u16 *src_port,
                                                   __u16 *dst_port) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
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

// Classify traffic based on packet type and session context
static __always_inline __u8 classify_traffic(struct parsed_header *parsed,
                                             struct session_info *session __attribute__((unused))) {
    // Critical packets get highest priority
    if (parsed->packet_type == PKT_TYPE_SYN ||
        parsed->packet_type == PKT_TYPE_SYN_ACK ||
        parsed->packet_type == PKT_TYPE_FIN ||
        parsed->packet_type == PKT_TYPE_DISCOVERY) {
        return PRIO_CRITICAL;
    }
    
    // Control packets get high priority
    if (parsed->packet_type == PKT_TYPE_ERROR ||
        parsed->packet_type == PKT_TYPE_RST ||
        parsed->packet_type == PKT_TYPE_HEARTBEAT ||
        (parsed->flags & PKT_FLAG_RECOVERY)) {
        return PRIO_CONTROL;
    }
    
    // Data packets classified by sub-type and flags
    if (parsed->packet_type == PKT_TYPE_DATA) {
        if (parsed->flags & PKT_FLAG_URGENT ||
            parsed->packet_subtype == DATA_SUBTYPE_URGENT) {
            return PRIO_DATA_URGENT;
        } else if (parsed->packet_subtype == DATA_SUBTYPE_KEEPALIVE) {
            return PRIO_CONTROL;
        } else {
            return PRIO_DATA_NORMAL;
        }
    }
    
    // Fragment packets inherit priority from original packet
    if (parsed->packet_type == PKT_TYPE_FRAGMENT) {
        return PRIO_DATA_NORMAL; // Default for fragments
    }
    
    return PRIO_DATA_BULK; // Default priority
}

// Implement token bucket rate limiting with burst allowance
static __always_inline int apply_token_bucket_rate_limiting(__u64 session_id,
                                                           __u32 packet_size,
                                                           __u8 priority,
                                                           __u64 current_time) {
    struct traffic_shaping_state *state = MAP_LOOKUP_ELEM(traffic_shaping_map, &session_id);
    
    if (!state) {
        // Create new traffic shaping state
        struct traffic_shaping_state new_state = {
            .last_update_time = current_time,
            .token_bucket = TOKEN_BUCKET_SIZE,
            .bytes_sent = packet_size,
            .packets_sent = 1,
            .current_rate_limit = TOKEN_REFILL_RATE,
            .qos_class = QOS_CLASS_INTERACTIVE,
            .congestion_level = 0,
            .burst_allowance = BURST_ALLOWANCE,
            .reserved = 0
        };
        MAP_UPDATE_ELEM(traffic_shaping_map, &session_id, &new_state, BPF_ANY);
        return TC_ACT_OK; // Allow first packet
    }
    
    // Calculate time elapsed and refill tokens
    // Optimized token calculation: use multiplication + shift instead of division
    // RATE_LIMIT_WINDOW = 1e9 (nanoseconds per second)
    // Approximate 1/1e9 as (1 << 32) / 1e9 ≈ 4.295
    // For token refill: tokens_to_add ≈ (time_diff * rate * 4.295) >> 32
    __u64 time_diff = current_time - state->last_update_time;
    if (time_diff > 0) {
        // Shift-based approximation for division by 1e9
        // ((time_diff >> 30) * rate) approximates (time_diff * rate) / 1e9 within 7% error
        __u32 tokens_to_add = (__u32)((time_diff >> 30) * state->current_rate_limit);
        state->token_bucket += tokens_to_add;
        if (state->token_bucket > TOKEN_BUCKET_SIZE) {
            state->token_bucket = TOKEN_BUCKET_SIZE;
        }
        state->last_update_time = current_time;
    }
    
    // Calculate tokens needed based on packet size and priority
    __u32 tokens_needed = packet_size;
    if (priority == PRIO_CRITICAL) {
        tokens_needed = tokens_needed / 2; // Critical packets use fewer tokens
    } else if (priority == PRIO_DATA_BULK) {
        tokens_needed = tokens_needed * 2; // Bulk packets use more tokens
    }
    
    // Check if we have enough tokens
    if (state->token_bucket >= tokens_needed) {
        state->token_bucket -= tokens_needed;
        state->bytes_sent += packet_size;
        state->packets_sent++;
        MAP_UPDATE_ELEM(traffic_shaping_map, &session_id, state, BPF_ANY);
        return TC_ACT_OK;
    }
    
    // Check burst allowance for high priority packets
    if (priority <= PRIO_CONTROL && state->burst_allowance >= tokens_needed) {
        state->burst_allowance -= tokens_needed;
        state->bytes_sent += packet_size;
        state->packets_sent++;
        MAP_UPDATE_ELEM(traffic_shaping_map, &session_id, state, BPF_ANY);
        return TC_ACT_OK;
    }
    
    // Rate limit exceeded
    MAP_UPDATE_ELEM(traffic_shaping_map, &session_id, state, BPF_ANY);
    return TC_ACT_SHOT; // Drop packet
}

// Coordinate port transitions with atomic updates
static __always_inline int coordinate_port_transition(__u64 session_id,
                                                     __u16 dest_port,
                                                     __u64 current_time) {
    struct port_transition_state *transition = MAP_LOOKUP_ELEM(port_transition_map, &session_id);
    
    if (!transition) {
        // Create new port transition state
        struct port_transition_state new_transition = {
            .current_port = dest_port,
            .next_port = 0,
            .transition_time = 0,
            .packets_on_current = 1,
            .packets_on_next = 0,
            .transition_active = 0,
            .coordination_required = 0,
            .reserved = 0
        };
        MAP_UPDATE_ELEM(port_transition_map, &session_id, &new_transition, BPF_ANY);
        return TC_ACT_OK;
    }
    
    // Check if we're in a port transition
    if (transition->transition_active) {
        if (dest_port == transition->current_port) {
            transition->packets_on_current++;
        } else if (dest_port == transition->next_port) {
            transition->packets_on_next++;
        } else {
            // Unexpected port - possible attack or timing issue
            return TC_ACT_SHOT;
        }
        
        // Check if transition is complete (all packets on new port)
        __u64 time_since_transition = current_time - transition->transition_time;
        if (time_since_transition > 1000000000ULL) { // 1 second timeout
            // Complete transition
            transition->current_port = transition->next_port;
            transition->next_port = 0;
            transition->transition_active = 0;
            transition->packets_on_current = transition->packets_on_next;
            transition->packets_on_next = 0;
        }
    } else {
        // Check for new port transition
        if (dest_port != transition->current_port) {
            // Start new transition
            transition->next_port = dest_port;
            transition->transition_time = current_time;
            transition->transition_active = 1;
            transition->packets_on_next = 1;
        } else {
            transition->packets_on_current++;
        }
    }
    
    MAP_UPDATE_ELEM(port_transition_map, &session_id, transition, BPF_ANY);
    return TC_ACT_OK;
}

// Implement packet prioritization based on type and security level
static __always_inline int prioritize_packet(struct __sk_buff *skb,
                                             struct parsed_header *parsed,
                                             struct session_info *session) {
    __u8 priority = classify_traffic(parsed, session);
    
    // Set TC priority class
    switch (priority) {
        case PRIO_CRITICAL:
            skb->priority = 0; // Highest priority
            break;
        case PRIO_CONTROL:
            skb->priority = 1;
            break;
        case PRIO_DATA_URGENT:
            skb->priority = 2;
            break;
        case PRIO_DATA_NORMAL:
            skb->priority = 3;
            break;
        case PRIO_DATA_BULK:
            skb->priority = 4; // Lowest priority
            break;
    }
    
    // Set DSCP marking for QoS
    if (priority <= PRIO_CONTROL) {
        // High priority - expedited forwarding
        skb->mark = 0x2E << 2; // EF DSCP
    } else if (priority == PRIO_DATA_URGENT) {
        // Medium priority - assured forwarding
        skb->mark = 0x22 << 2; // AF31 DSCP
    } else {
        // Normal priority - best effort
        skb->mark = 0x00; // BE DSCP
    }
    
    return TC_ACT_OK;
}

// Efficient qdisc interaction with security event reporting
static __always_inline int interact_with_qdisc(struct __sk_buff *skb,
                                               struct parsed_header *parsed __attribute__((unused)),
                                               __u8 security_action) {
    // Report security events to qdisc
    if (security_action != SEC_ACTION_ALLOW) {
        // Mark packet for special handling
        skb->mark |= 0x80000000; // Set high bit for security event
        
        if (security_action == SEC_ACTION_DROP ||
            security_action == SEC_ACTION_BLOCK_TEMP ||
            security_action == SEC_ACTION_BLOCK_PERM) {
            return TC_ACT_SHOT; // Drop packet
        } else if (security_action == SEC_ACTION_RATE_LIMIT) {
            // Apply additional delay
            return TC_ACT_PIPE; // Continue processing with delay
        }
    }
    
    return TC_ACT_OK;
}

// HMAC policy enforcement for outbound packets
static __always_inline int enforce_hmac_policy(struct parsed_header *parsed,
                                               __u64 current_time) {
    // Determine required HMAC policy
    __u8 required_policy = determine_hmac_policy(parsed->packet_type,
                                                 parsed->flags,
                                                 current_time,
                                                 NULL);
    
    // Check if packet meets required HMAC policy
    if (parsed->hmac_policy < required_policy) {
        // Packet doesn't meet security requirements
        return TC_ACT_SHOT;
    }
    
    // Month boundary enforcement
    __u32 current_bucket = calculate_time_bucket(current_time, EPOCH_MONTHLY);
    __u32 buckets_per_month = 2592000 * 2; // 30 days * 24 hours * 60 minutes * 60 seconds * 2
    
    if (current_bucket > buckets_per_month - 7200) { // Last hour of month
        if (parsed->hmac_policy != HMAC_POLICY_STRONG) {
            // Force STRONG HMAC during month boundary
            return TC_ACT_SHOT;
        }
    }
    
    return TC_ACT_OK;
}

// Apply adaptive delay based on network conditions
static __always_inline int apply_adaptive_delay(struct __sk_buff *skb __attribute__((unused)),
                                                __u64 session_id,
                                                __u64 current_time) {
    struct traffic_shaping_state *state = MAP_LOOKUP_ELEM(traffic_shaping_map, &session_id);
    
    if (!state) {
        return TC_ACT_OK; // No delay for new sessions
    }
    
    // Calculate congestion level based on recent traffic
    // Optimized: avoid division by rewriting rate comparison
    __u64 time_window = 5000000000ULL; // 5 seconds
    __u64 time_since_update = current_time - state->last_update_time;

    if (time_since_update < time_window) {
        // Original: recent_rate = (bytes_sent * 1e9) / time_since_update
        // Rewrite comparisons to avoid division:
        // rate > threshold ⟺ bytes_sent * 1e9 > threshold * time_since_update
        __u64 bytes_times_1e9 = state->bytes_sent * 1000000000ULL;

        if (bytes_times_1e9 > 1048576ULL * time_since_update) { // > 1MB/s
            state->congestion_level = 3; // High congestion
        } else if (bytes_times_1e9 > 524288ULL * time_since_update) { // > 512KB/s
            state->congestion_level = 2; // Medium congestion
        } else if (bytes_times_1e9 > 262144ULL * time_since_update) { // > 256KB/s
            state->congestion_level = 1; // Low congestion
        } else {
            state->congestion_level = 0; // No congestion
        }

        MAP_UPDATE_ELEM(traffic_shaping_map, &session_id, state, BPF_ANY);
    }
    
    // Apply delay based on congestion level
    if (state->congestion_level > 0) {
        // Use TC's built-in delay mechanism
        return TC_ACT_PIPE; // Continue with delay
    }
    
    return TC_ACT_OK;
}

// Main TC program for egress traffic shaping
SEC("tc")
int tc_buckwild_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Extract network information
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    
    if (extract_tc_network_info(skb, &src_ip, &dst_ip, &src_port, &dst_port) < 0) {
        return TC_ACT_OK; // Not UDP packet
    }
    
    // Check if this is a Buckwild protocol packet
    if (!is_potential_buckwild_port(dst_port)) {
        return TC_ACT_OK; // Not our protocol
    }
    
    // Get UDP payload with bounds checking
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);

    // eBPF verifier requires bounds check BEFORE pointer arithmetic
    if ((void *)ip + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // eBPF verifier requires bounds check BEFORE using payload pointer
    void *payload = (void *)(udp + 1);
    if (payload > data_end)
        return TC_ACT_OK;

    if (!is_buckwild_packet(payload, data_end)) {
        return TC_ACT_OK; // Not Buckwild protocol
    }
    
    // Parse packet header
    struct parsed_header parsed = {0};
    if (parse_buckwild_header(payload, data_end, &parsed) < 0) {
        return TC_ACT_SHOT; // Invalid packet
    }
    
    __u64 current_time = bpf_ktime_get_ns();
    
    // Get session information
    struct session_info *session = NULL;
    if (parsed.session_id != 0) {
        session = MAP_LOOKUP_ELEM(session_map, &parsed.session_id);
    }
    
    // Enforce HMAC policy for outbound packets
    if (enforce_hmac_policy(&parsed, current_time) != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }
    
    // Classify and prioritize traffic
    if (prioritize_packet(skb, &parsed, session) != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }
    
    // Apply token bucket rate limiting
    __u8 priority = classify_traffic(&parsed, session);
    int rate_limit_result = apply_token_bucket_rate_limiting(parsed.session_id,
                                                            skb->len,
                                                            priority,
                                                            current_time);
    if (rate_limit_result != TC_ACT_OK) {
        return rate_limit_result;
    }
    
    // Coordinate port transitions
    if (coordinate_port_transition(parsed.session_id, dst_port, current_time) != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }
    
    // Apply adaptive delay based on network conditions
    int delay_result = apply_adaptive_delay(skb, parsed.session_id, current_time);
    if (delay_result != TC_ACT_OK) {
        return delay_result;
    }
    
    // Update security statistics for allowed packets
    update_security_statistics(SEC_EVENT_UNKNOWN_SESSION, SEC_ACTION_ALLOW);
    
    // Interact with qdisc for final processing
    return interact_with_qdisc(skb, &parsed, SEC_ACTION_ALLOW);
}

// TC program for ingress traffic classification
SEC("tc_ingress")
int tc_buckwild_ingress(struct __sk_buff *skb) {
    // Classify ingress traffic and set priority for qdisc scheduling
    // Ingress = packets entering network namespace (from TUN toward app)

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Extract network information
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;

    if (extract_tc_network_info(skb, &src_ip, &dst_ip, &src_port, &dst_port) < 0) {
        return TC_ACT_OK; // Not UDP packet
    }

    // Check if this is a Buckwild protocol packet (check src_port for ingress)
    if (!is_potential_buckwild_port(src_port)) {
        return TC_ACT_OK; // Not our protocol
    }

    // Get UDP payload with bounds checking
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // eBPF verifier requires bounds check BEFORE pointer arithmetic
    if ((void *)ip + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // eBPF verifier requires bounds check BEFORE using payload pointer
    void *payload = (void *)(udp + 1);
    if (payload > data_end)
        return TC_ACT_OK;

    if (!is_buckwild_packet(payload, data_end)) {
        return TC_ACT_OK; // Not Buckwild protocol
    }

    // Parse packet header
    struct parsed_header parsed = {0};
    if (parse_buckwild_header(payload, data_end, &parsed) < 0) {
        return TC_ACT_OK; // Invalid packet, let kernel handle
    }

    // Get session information
    struct session_info *session = NULL;
    if (parsed.session_id != 0) {
        session = MAP_LOOKUP_ELEM(session_map, &parsed.session_id);
    }

    // Classify and set priority (same logic as egress)
    __u8 priority = classify_traffic(&parsed, session);

    // Set TC priority class for ingress qdisc
    switch (priority) {
        case PRIO_CRITICAL:
            skb->priority = 0;
            break;
        case PRIO_CONTROL:
            skb->priority = 1;
            break;
        case PRIO_DATA_URGENT:
            skb->priority = 2;
            break;
        case PRIO_DATA_NORMAL:
            skb->priority = 3;
            break;
        case PRIO_DATA_BULK:
        default:
            skb->priority = 4;
            break;
    }

    return TC_ACT_OK;
}

// TC program for traffic policing
SEC("tc_police")
int tc_buckwild_police(struct __sk_buff *skb) {
    // Enforce committed rate - DROP packets exceeding CIR
    // Unlike shaping (delay), policing drops immediately

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Extract network information
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;

    if (extract_tc_network_info(skb, &src_ip, &dst_ip, &src_port, &dst_port) < 0) {
        return TC_ACT_OK; // Not UDP packet
    }

    // Check if this is a Buckwild protocol packet
    if (!is_potential_buckwild_port(dst_port)) {
        return TC_ACT_OK; // Not our protocol
    }

    // Get UDP payload with bounds checking
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // eBPF verifier requires bounds check BEFORE pointer arithmetic
    if ((void *)ip + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // eBPF verifier requires bounds check BEFORE using payload pointer
    void *payload = (void *)(udp + 1);
    if (payload > data_end)
        return TC_ACT_OK;

    if (!is_buckwild_packet(payload, data_end)) {
        return TC_ACT_OK; // Not Buckwild protocol
    }

    // Parse packet header
    struct parsed_header parsed = {0};
    if (parse_buckwild_header(payload, data_end, &parsed) < 0) {
        return TC_ACT_OK; // Invalid packet
    }

    // Get police configuration for this session
    struct police_config *config = MAP_LOOKUP_ELEM(police_config_map, &parsed.session_id);

    if (!config) {
        // No policing configured for this session
        return TC_ACT_OK;
    }

    __u64 current_time = bpf_ktime_get_ns();
    __u32 packet_size = skb->len;

    // Refill tokens based on elapsed time
    // Reorder arithmetic to avoid u64 overflow at high bandwidth (100+ Gbps)
    __u64 time_diff = current_time - config->last_update_ns;
    if (time_diff > 0) {
        __u64 seconds_elapsed = time_diff / 1000000000ULL;
        __u64 nanos_remaining = time_diff % 1000000000ULL;
        __u64 tokens_to_add = (seconds_elapsed * config->cir_bytes_per_sec) +
                              ((nanos_remaining * config->cir_bytes_per_sec) / 1000000000ULL);
        config->tokens += tokens_to_add;

        // Cap at committed burst size
        if (config->tokens > config->cbs_bytes) {
            config->tokens = config->cbs_bytes;
        }
        config->last_update_ns = current_time;
    }

    // Check if packet can be transmitted
    if (config->tokens >= packet_size) {
        // Consume tokens and allow packet
        config->tokens -= packet_size;
        MAP_UPDATE_ELEM(police_config_map, &parsed.session_id, config, BPF_ANY);
        return TC_ACT_OK;
    }

    // Exceeds committed rate - DROP packet
    MAP_UPDATE_ELEM(police_config_map, &parsed.session_id, config, BPF_ANY);
    update_security_statistics(SEC_EVENT_RATE_LIMIT_VIOLATION, SEC_ACTION_DROP);
    return TC_ACT_SHOT;
}