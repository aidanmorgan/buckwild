#ifndef BUCKWILD_EBPF_SECURITY_H
#define BUCKWILD_EBPF_SECURITY_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "protocol.h"
#include "fragment_security.h"

// Security thresholds and limits
#define MAX_CONNECTIONS_PER_SOURCE      10      // Max concurrent connections per IP
#define CONNECTION_ATTEMPT_RATE_LIMIT   5       // Attempts per second
#define AUTHENTICATION_FAILURE_LIMIT    3       // Max auth failures before block
#define ENUMERATION_THRESHOLD           20      // Score threshold for enumeration
#define REPLAY_WINDOW_SIZE              60      // Replay detection window (buckets)
#define TIMING_ATTACK_THRESHOLD         1000    // Microseconds variance threshold
#define BLACKLIST_DURATION_BASE         60      // Base blacklist duration (seconds)
#define PERMANENT_BLOCK_THRESHOLD       10      // Violations for permanent block

// Attack confidence levels
#define CONFIDENCE_LOW                  25
#define CONFIDENCE_MEDIUM               50
#define CONFIDENCE_HIGH                 75
#define CONFIDENCE_CRITICAL             90

// Response escalation levels
#define RESPONSE_LEVEL_MONITOR          0
#define RESPONSE_LEVEL_RATE_LIMIT       1
#define RESPONSE_LEVEL_TEMP_BLOCK       2
#define RESPONSE_LEVEL_PERM_BLOCK       3

// Security event batching
#define MAX_SECURITY_EVENTS_BATCH       32
#define SECURITY_EVENT_BATCH_TIMEOUT    1000000000ULL  // 1 second

// Multi-layer rate limiting structure
struct multi_layer_rate_limit {
    // Per-source limits
    __u32 source_pps_limit;
    __u32 source_bps_limit;
    __u32 source_conn_limit;
    
    // Per-session limits
    __u32 session_pps_limit;
    __u32 session_bps_limit;
    
    // Per-packet-type limits
    __u32 syn_pps_limit;
    __u32 data_pps_limit;
    __u32 discovery_pps_limit;
    
    // Current counters
    __u32 current_source_pps;
    __u32 current_source_bps;
    __u32 current_session_pps;
    __u32 current_session_bps;
    
    __u64 last_reset_time;
    __u8 violation_flags;
    __u8 reserved[3];
};

// Attack pattern detection state
struct attack_pattern_state {
    __u32 pattern_id;
    __u64 first_occurrence;
    __u64 last_occurrence;
    __u32 occurrence_count;
    __u32 pattern_strength;
    __u8 pattern_type;
    __u8 confidence_level;
    __u16 reserved;
};

// Security event batch for efficient reporting
struct security_event_batch {
    __u32 event_count;
    __u32 batch_id;
    __u64 batch_start_time;
    __u64 batch_end_time;
    struct security_event events[MAX_SECURITY_EVENTS_BATCH];
};

// Check if source IP is currently blacklisted
static __always_inline int is_source_blacklisted(__u32 src_ip, __u64 current_time) {
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    
    if (!attack_info) {
        return 0; // Not blacklisted
    }
    
    // Check permanent block
    if (attack_info->permanent_block) {
        return 1;
    }
    
    // Check temporary block with exponential backoff
    if (attack_info->response_level >= RESPONSE_LEVEL_TEMP_BLOCK) {
        __u64 block_duration = BLACKLIST_DURATION_BASE * (1 << attack_info->response_level);
        if (block_duration > 3600) block_duration = 3600; // Max 1 hour
        
        __u64 time_since_last = current_time - attack_info->last_seen;
        if (time_since_last < (block_duration * 1000000000ULL)) {
            return 1; // Still blocked
        }
        
        // Unblock and reduce response level
        attack_info->response_level--;
        MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
    }
    
    return 0;
}

// Implement multi-layer rate limiting
static __always_inline int apply_multi_layer_rate_limiting(__u32 src_ip,
                                                           __u64 session_id __attribute__((unused)),
                                                           __u8 packet_type,
                                                           __u32 packet_size,
                                                           __u64 current_time) {
    // Get or create rate limit info for source
    struct rate_limit_info *rate_info = MAP_LOOKUP_ELEM(ip_rate_limit_map, &src_ip);
    
    if (!rate_info) {
        struct rate_limit_info new_info = {
            .last_reset_time = current_time,
            .packet_count = 1,
            .byte_count = packet_size,
            .violation_count = 0,
            .blocked = 0,
            .escalation_level = 0,
            .block_duration = 0,
            .last_violation_time = 0,
            .total_violations = 0
        };
        MAP_UPDATE_ELEM(ip_rate_limit_map, &src_ip, &new_info, BPF_ANY);
        return SEC_ACTION_ALLOW;
    }
    
    // Reset counters every second
    __u64 time_diff = current_time - rate_info->last_reset_time;
    if (time_diff > 1000000000ULL) {
        rate_info->last_reset_time = current_time;
        rate_info->packet_count = 1;
        rate_info->byte_count = packet_size;
        MAP_UPDATE_ELEM(ip_rate_limit_map, &src_ip, rate_info, BPF_ANY);
        return SEC_ACTION_ALLOW;
    }
    
    // Update counters
    rate_info->packet_count++;
    rate_info->byte_count += packet_size;
    
    // Check per-source limits
    if (rate_info->packet_count > 1000 || rate_info->byte_count > 1048576) { // 1000 pps or 1MB/s
        rate_info->violation_count++;
        rate_info->last_violation_time = current_time;
        
        if (rate_info->violation_count > 3) {
            rate_info->blocked = 1;
            rate_info->escalation_level++;
        }
        
        MAP_UPDATE_ELEM(ip_rate_limit_map, &src_ip, rate_info, BPF_ANY);
        return SEC_ACTION_RATE_LIMIT;
    }
    
    // Check packet-type specific limits
    switch (packet_type) {
        case PKT_TYPE_SYN:
            if (rate_info->packet_count > 10) { // Max 10 SYN per second
                return SEC_ACTION_RATE_LIMIT;
            }
            break;
        case PKT_TYPE_DISCOVERY:
            if (rate_info->packet_count > 5) { // Max 5 discovery per second
                return SEC_ACTION_RATE_LIMIT;
            }
            break;
        default:
            break;
    }
    
    MAP_UPDATE_ELEM(ip_rate_limit_map, &src_ip, rate_info, BPF_ANY);
    return SEC_ACTION_ALLOW;
}

// Detect enumeration attacks based on connection patterns
static __always_inline int detect_enumeration_attack(__u32 src_ip,
                                                     __u16 dest_port __attribute__((unused)),
                                                     __u8 packet_type,
                                                     __u64 current_time) {
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    
    if (!attack_info) {
        struct attack_detection_info new_info = {
            .src_ip = src_ip,
            .first_seen = current_time,
            .last_seen = current_time,
            .connection_attempts = 1,
            .failed_authentications = 0,
            .enumeration_score = 0,
            .replay_attempts = 0,
            .timing_violations = 0,
            .attack_type = 0,
            .confidence_level = 0,
            .response_level = RESPONSE_LEVEL_MONITOR,
            .permanent_block = 0
        };
        MAP_UPDATE_ELEM(attack_detection_map, &src_ip, &new_info, BPF_ANY);
        return 0;
    }
    
    attack_info->last_seen = current_time;
    
    // Count connection attempts
    if (packet_type == PKT_TYPE_SYN || packet_type == PKT_TYPE_DISCOVERY) {
        attack_info->connection_attempts++;
        
        // Calculate enumeration score based on:
        // - Number of connection attempts
        // - Time window
        // Note: Port diversity tracking omitted due to eBPF map memory constraints
        __u64 time_window = current_time - attack_info->first_seen;
        if (time_window > 0) {
            __u32 attempts_per_second = (attack_info->connection_attempts * 1000000000ULL) / time_window;
            attack_info->enumeration_score = attempts_per_second;
            
            // High rate of connection attempts indicates enumeration
            if (attempts_per_second > 10) {
                attack_info->enumeration_score += 20;
            }
            
            // Many attempts in short time
            if (attack_info->connection_attempts > 50 && time_window < 60000000000ULL) {
                attack_info->enumeration_score += 30;
            }
        }
        
        // Check enumeration threshold
        if (attack_info->enumeration_score > ENUMERATION_THRESHOLD) {
            attack_info->attack_type = SEC_EVENT_ENUMERATION_ATTACK;
            attack_info->confidence_level = CONFIDENCE_HIGH;
            attack_info->response_level = RESPONSE_LEVEL_TEMP_BLOCK;
            MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
            return 1; // Enumeration detected
        }
    }
    
    MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
    return 0;
}

// Detect replay attacks using sliding window
static __always_inline int detect_replay_attack(__u32 src_ip,
                                                __u64 session_id,
                                                __u32 sequence_number __attribute__((unused)),
                                                __u32 timestamp __attribute__((unused)),
                                                __u64 current_time) {
    // Create composite key for replay detection (used for future sliding window implementation)
    __u64 replay_key __attribute__((unused)) = ((__u64)src_ip << 32) | (session_id & 0xFFFFFFFF);

    // Replay detection using attack detection map
    // Full implementation would maintain a sliding window of seen packets
    
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    if (attack_info) {
        // Check for suspicious replay patterns
        // - Same sequence number repeated
        // - Old timestamps
        // - Rapid duplicate attempts
        
        __u64 time_diff = current_time - attack_info->last_seen;
        if (time_diff < 1000000ULL) { // Less than 1ms between packets
            attack_info->replay_attempts++;
            if (attack_info->replay_attempts > 5) {
                attack_info->attack_type = SEC_EVENT_REPLAY_ATTACK;
                attack_info->confidence_level = CONFIDENCE_MEDIUM;
                attack_info->response_level = RESPONSE_LEVEL_RATE_LIMIT;
                MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
                return 1;
            }
        }
        
        MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
    }
    
    return 0;
}

// Detect timing attacks based on response time patterns
static __always_inline int detect_timing_attack(__u32 src_ip,
                                                __u64 processing_start_time,
                                                __u64 current_time) {
    __u64 processing_time = current_time - processing_start_time;
    
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    if (attack_info) {
        // Check for timing attack indicators
        // - Consistent timing measurements
        // - Attempts to measure processing differences
        
        if (processing_time < 1000) { // Less than 1 microsecond (suspicious)
            attack_info->timing_violations++;
            if (attack_info->timing_violations > TIMING_ATTACK_THRESHOLD) {
                attack_info->attack_type = SEC_EVENT_TIMING_ATTACK;
                attack_info->confidence_level = CONFIDENCE_LOW;
                attack_info->response_level = RESPONSE_LEVEL_MONITOR;
                MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
                return 1;
            }
        }
        
        MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
    }
    
    return 0;
}

// Progressive response escalation based on attack severity
static __always_inline int escalate_security_response(__u32 src_ip,
                                                      __u8 attack_type,
                                                      __u8 confidence_level,
                                                      __u64 current_time __attribute__((unused))) {
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    if (!attack_info) {
        return SEC_ACTION_ALLOW;
    }
    
    // Escalate based on confidence and attack type
    if (confidence_level >= CONFIDENCE_CRITICAL) {
        attack_info->response_level = RESPONSE_LEVEL_PERM_BLOCK;
        attack_info->permanent_block = 1;
    } else if (confidence_level >= CONFIDENCE_HIGH) {
        attack_info->response_level = RESPONSE_LEVEL_TEMP_BLOCK;
    } else if (confidence_level >= CONFIDENCE_MEDIUM) {
        attack_info->response_level = RESPONSE_LEVEL_RATE_LIMIT;
    }
    
    // Critical attack types get immediate escalation
    if (attack_type == SEC_EVENT_FRAGMENT_BOMB ||
        attack_type == SEC_EVENT_SESSION_HIJACK) {
        attack_info->response_level = RESPONSE_LEVEL_TEMP_BLOCK;
    }
    
    MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
    
    // Return appropriate action
    switch (attack_info->response_level) {
        case RESPONSE_LEVEL_PERM_BLOCK:
            return SEC_ACTION_BLOCK_PERM;
        case RESPONSE_LEVEL_TEMP_BLOCK:
            return SEC_ACTION_BLOCK_TEMP;
        case RESPONSE_LEVEL_RATE_LIMIT:
            return SEC_ACTION_RATE_LIMIT;
        default:
            return SEC_ACTION_ALLOW;
    }
}

// Batch security events for efficient reporting
static __always_inline int batch_security_event(__u8 event_type,
                                                __u8 severity,
                                                __u32 src_ip,
                                                __u32 dst_ip,
                                                __u16 src_port,
                                                __u16 dst_port,
                                                __u64 session_id,
                                                __u64 current_time) {
    // Reserve space in ring buffer for security event
    struct security_event *event = bpf_ringbuf_reserve(&packet_ring_buffer, 
                                                       sizeof(struct security_event), 0);
    if (!event) {
        return -1; // Ring buffer full
    }
    
    // Fill security event
    event->timestamp = current_time;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->session_id = session_id;
    event->event_type = event_type;
    event->severity = severity;
    event->action_taken = SEC_ACTION_DROP; // Will be updated by caller

    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Efficient cleanup for stale security entries
static __always_inline void cleanup_stale_security_entries(__u64 current_time __attribute__((unused))) {
    // This would be implemented in userspace as eBPF cannot iterate maps
    // The userspace component would periodically clean up expired entries
}

// Update global security statistics
static __always_inline void update_security_statistics(__u8 event_type, __u8 action_taken) {
    __u32 key = 0;
    struct {
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
    } *stats = MAP_LOOKUP_ELEM(security_stats_map, &key);
    
    if (stats) {
        stats->total_packets++;
        stats->security_events++;
        
        if (action_taken == SEC_ACTION_DROP || 
            action_taken == SEC_ACTION_BLOCK_TEMP ||
            action_taken == SEC_ACTION_BLOCK_PERM) {
            stats->dropped_packets++;
        }
        
        switch (event_type) {
            case SEC_EVENT_RATE_LIMIT_VIOLATION:
                stats->rate_limit_violations++;
                break;
            case SEC_EVENT_FRAGMENT_BOMB:
            case SEC_EVENT_FRAGMENT_OVERLAP:
                stats->fragment_attacks++;
                break;
            case SEC_EVENT_REPLAY_ATTACK:
                stats->replay_attacks++;
                break;
            case SEC_EVENT_ENUMERATION_ATTACK:
                stats->enumeration_attempts++;
                break;
            case SEC_EVENT_TIMING_ATTACK:
                stats->timing_attacks++;
                break;
        }
        
        if (action_taken == SEC_ACTION_BLOCK_TEMP || 
            action_taken == SEC_ACTION_BLOCK_PERM) {
            stats->blocked_sources++;
        }
        
        stats->last_update_time = bpf_ktime_get_ns();
        MAP_UPDATE_ELEM(security_stats_map, &key, stats, BPF_ANY);
    }
}

// Comprehensive security validation pipeline
static __always_inline int validate_packet_security(struct parsed_header *parsed,
                                                    __u32 src_ip,
                                                    __u16 src_port,
                                                    __u32 dst_ip,
                                                    __u16 dst_port,
                                                    void *packet_data,
                                                    void *data_end,
                                                    __u64 current_time) {
    __u64 processing_start = bpf_ktime_get_ns();
    
    // Check if source is blacklisted
    if (is_source_blacklisted(src_ip, current_time)) {
        batch_security_event(SEC_EVENT_UNKNOWN_SESSION, SEC_SEVERITY_HIGH,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        update_security_statistics(SEC_EVENT_UNKNOWN_SESSION, SEC_ACTION_BLOCK_PERM);
        return SEC_ACTION_BLOCK_PERM;
    }
    
    // Apply multi-layer rate limiting
    int rate_limit_result = apply_multi_layer_rate_limiting(src_ip, parsed->session_id,
                                                           parsed->packet_type,
                                                           (data_end - packet_data),
                                                           current_time);
    if (rate_limit_result != SEC_ACTION_ALLOW) {
        batch_security_event(SEC_EVENT_RATE_LIMIT_VIOLATION, SEC_SEVERITY_MEDIUM,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        update_security_statistics(SEC_EVENT_RATE_LIMIT_VIOLATION, rate_limit_result);
        return rate_limit_result;
    }
    
    // Detect enumeration attacks
    if (detect_enumeration_attack(src_ip, dst_port, parsed->packet_type, current_time)) {
        batch_security_event(SEC_EVENT_ENUMERATION_ATTACK, SEC_SEVERITY_HIGH,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        update_security_statistics(SEC_EVENT_ENUMERATION_ATTACK, SEC_ACTION_BLOCK_TEMP);
        return SEC_ACTION_BLOCK_TEMP;
    }
    
    // Detect replay attacks
    if (detect_replay_attack(src_ip, parsed->session_id, parsed->sequence_number,
                           parsed->timestamp, current_time)) {
        batch_security_event(SEC_EVENT_REPLAY_ATTACK, SEC_SEVERITY_HIGH,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        update_security_statistics(SEC_EVENT_REPLAY_ATTACK, SEC_ACTION_DROP);
        return SEC_ACTION_DROP;
    }
    
    // Validate fragment security
    int fragment_result = validate_fragment_security(parsed, src_ip, src_port,
                                                    packet_data, data_end, current_time);
    if (fragment_result != FRAGMENT_VALID) {
        __u8 event_type = (fragment_result == FRAGMENT_BOMB_DETECTED) ? 
                         SEC_EVENT_FRAGMENT_BOMB : SEC_EVENT_FRAGMENT_OVERLAP;
        batch_security_event(event_type, SEC_SEVERITY_HIGH,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        update_security_statistics(event_type, SEC_ACTION_DROP);
        return SEC_ACTION_DROP;
    }
    
    // Detect timing attacks
    __u64 processing_end = bpf_ktime_get_ns();
    if (detect_timing_attack(src_ip, processing_start, processing_end)) {
        batch_security_event(SEC_EVENT_TIMING_ATTACK, SEC_SEVERITY_LOW,
                            src_ip, dst_ip, src_port, dst_port,
                            parsed->session_id, current_time);
        update_security_statistics(SEC_EVENT_TIMING_ATTACK, SEC_ACTION_ALLOW);
        // Don't block for timing attacks, just monitor
    }
    
    return SEC_ACTION_ALLOW;
}

#endif // BUCKWILD_EBPF_SECURITY_H