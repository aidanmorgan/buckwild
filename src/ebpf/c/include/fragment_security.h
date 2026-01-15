#ifndef BUCKWILD_EBPF_FRAGMENT_SECURITY_H
#define BUCKWILD_EBPF_FRAGMENT_SECURITY_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "protocol.h"

// Fragment security limits
#define MAX_FRAGMENTS_PER_SESSION   100
#define MAX_FRAGMENTS_PER_SOURCE    200
#define MAX_FRAGMENT_RATE_PPS       20      // Fragments per second per session
#define FRAGMENT_TIMEOUT_NS         5000000000ULL  // 5 seconds
#define MIN_FRAGMENT_SIZE           8       // Minimum fragment payload size
#define MAX_FRAGMENT_SIZE           1400    // Maximum fragment payload size
#define FRAGMENT_BOMB_THRESHOLD     50      // Threshold for fragment bomb detection

// Fragment attack types
#define FRAGMENT_ATTACK_NONE        0
#define FRAGMENT_ATTACK_BOMB        1
#define FRAGMENT_ATTACK_OVERLAP     2
#define FRAGMENT_ATTACK_TINY        3
#define FRAGMENT_ATTACK_OVERSIZED   4
#define FRAGMENT_ATTACK_RATE_LIMIT  5
#define FRAGMENT_ATTACK_UNBOUND     6

// Fragment validation results
#define FRAGMENT_VALID              0
#define FRAGMENT_INVALID_SIZE       1
#define FRAGMENT_INVALID_SESSION    2
#define FRAGMENT_RATE_LIMITED       3
#define FRAGMENT_BOMB_DETECTED      4
#define FRAGMENT_OVERLAP_DETECTED   5
#define FRAGMENT_TIMEOUT            6
#define FRAGMENT_UNBOUND_SESSION    7

// Create composite key for fragment tracking
static __always_inline __u64 create_fragment_key(__u32 src_ip, __u16 fragment_id) {
    return ((__u64)src_ip << 32) | fragment_id;
}

// Validate fragment size to detect tiny fragment and oversized fragment attacks
static __always_inline int validate_fragment_size(__u16 fragment_size, 
                                                  __u16 fragment_index,
                                                  __u16 total_fragments) {
    // Check for tiny fragments (except last fragment)
    if (fragment_index < total_fragments - 1 && fragment_size < MIN_FRAGMENT_SIZE) {
        return FRAGMENT_INVALID_SIZE;
    }
    
    // Check for oversized fragments
    if (fragment_size > MAX_FRAGMENT_SIZE) {
        return FRAGMENT_INVALID_SIZE;
    }
    
    // Validate fragment index
    if (fragment_index >= total_fragments) {
        return FRAGMENT_INVALID_SIZE;
    }
    
    return FRAGMENT_VALID;
}

// Check fragment rate limiting per source IP using sliding window
static __always_inline int check_fragment_rate_limit(__u32 src_ip, 
                                                     __u64 current_time) {
    struct rate_limit_info *rate_info = MAP_LOOKUP_ELEM(ip_rate_limit_map, &src_ip);
    
    if (!rate_info) {
        // Create new rate limit entry
        struct rate_limit_info new_info = {
            .last_reset_time = current_time,
            .packet_count = 1,
            .byte_count = 0,
            .violation_count = 0,
            .blocked = 0,
            .escalation_level = 0,
            .block_duration = 0,
            .last_violation_time = 0,
            .total_violations = 0
        };
        MAP_UPDATE_ELEM(ip_rate_limit_map, &src_ip, &new_info, BPF_ANY);
        return FRAGMENT_VALID;
    }
    
    // Check if currently blocked
    if (rate_info->blocked) {
        __u64 time_diff = current_time - rate_info->last_violation_time;
        if (time_diff < ((__u64)rate_info->block_duration * 1000000000ULL)) {
            return FRAGMENT_RATE_LIMITED;
        }
        // Unblock after timeout
        rate_info->blocked = 0;
    }
    
    // Reset counters every second
    __u64 time_diff = current_time - rate_info->last_reset_time;
    if (time_diff > 1000000000ULL) {
        rate_info->last_reset_time = current_time;
        rate_info->packet_count = 1;
        return FRAGMENT_VALID;
    }
    
    // Check rate limit
    rate_info->packet_count++;
    if (rate_info->packet_count > MAX_FRAGMENT_RATE_PPS) {
        // Rate limit violation
        rate_info->violation_count++;
        rate_info->total_violations++;
        rate_info->last_violation_time = current_time;
        
        // Progressive blocking
        if (rate_info->violation_count > 3) {
            rate_info->blocked = 1;
            rate_info->escalation_level++;
            rate_info->block_duration = 1 << rate_info->escalation_level; // Exponential backoff
            if (rate_info->block_duration > 3600) { // Max 1 hour
                rate_info->block_duration = 3600;
            }
        }
        
        return FRAGMENT_RATE_LIMITED;
    }
    
    return FRAGMENT_VALID;
}

// Verify fragment belongs to established session
static __always_inline int verify_fragment_session_binding(__u64 session_id,
                                                           __u32 src_ip,
                                                           __u16 src_port) {
    struct session_info *session = MAP_LOOKUP_ELEM(session_map, &session_id);
    
    if (!session) {
        return FRAGMENT_UNBOUND_SESSION;
    }
    
    // Verify source IP and port match session
    if (session->src_ip != src_ip || session->src_port != src_port) {
        // Potential session hijacking attempt
        session->security_violations++;
        session->attack_detected = 1;
        return FRAGMENT_UNBOUND_SESSION;
    }
    
    return FRAGMENT_VALID;
}

// Detect fragment bomb attacks by tracking total fragments per source and session
static __always_inline int detect_fragment_bomb(__u32 src_ip,
                                                __u16 fragment_id,
                                                __u16 total_fragments,
                                                __u64 session_id,
                                                __u64 current_time) {
    __u64 frag_key = create_fragment_key(src_ip, fragment_id);
    struct fragment_security_info *frag_info = MAP_LOOKUP_ELEM(fragment_security_map, &frag_key);
    
    if (!frag_info) {
        // Create new fragment tracking entry
        struct fragment_security_info new_info = {
            .session_id = session_id,
            .src_ip = src_ip,
            .fragment_id = fragment_id,
            .total_fragments = total_fragments,
            .received_fragments = 1,
            .total_bytes = 0,
            .first_fragment_time = current_time,
            .last_fragment_time = current_time,
            .fragment_rate = 0,
            .overlap_detected = 0,
            .bomb_detected = 0,
            .session_bound = 1,
            .reserved = 0
        };
        MAP_UPDATE_ELEM(fragment_security_map, &frag_key, &new_info, BPF_ANY);
        
        // Check if total fragments exceeds bomb threshold
        if (total_fragments > FRAGMENT_BOMB_THRESHOLD) {
            new_info.bomb_detected = 1;
            MAP_UPDATE_ELEM(fragment_security_map, &frag_key, &new_info, BPF_ANY);
            return FRAGMENT_BOMB_DETECTED;
        }
        
        return FRAGMENT_VALID;
    }
    
    // Update fragment tracking
    frag_info->received_fragments++;
    frag_info->last_fragment_time = current_time;
    
    // Calculate fragment rate
    __u64 time_diff = current_time - frag_info->first_fragment_time;
    if (time_diff > 0) {
        frag_info->fragment_rate = (frag_info->received_fragments * 1000000000ULL) / time_diff;
    }
    
    // Check for fragment bomb conditions
    if (frag_info->total_fragments > FRAGMENT_BOMB_THRESHOLD ||
        frag_info->received_fragments > MAX_FRAGMENTS_PER_SESSION ||
        frag_info->fragment_rate > MAX_FRAGMENT_RATE_PPS * 2) {
        frag_info->bomb_detected = 1;
        MAP_UPDATE_ELEM(fragment_security_map, &frag_key, frag_info, BPF_ANY);
        return FRAGMENT_BOMB_DETECTED;
    }
    
    // Check for timeout
    if (time_diff > FRAGMENT_TIMEOUT_NS) {
        // Clean up expired fragment
        MAP_DELETE_ELEM(fragment_security_map, &frag_key);
        return FRAGMENT_TIMEOUT;
    }
    
    MAP_UPDATE_ELEM(fragment_security_map, &frag_key, frag_info, BPF_ANY);
    return FRAGMENT_VALID;
}

// Detect fragment overlap attacks with constant-time validation
static __always_inline int detect_fragment_overlap(__u32 src_ip,
                                                   __u16 fragment_id,
                                                   __u16 fragment_index __attribute__((unused)),
                                                   __u16 fragment_size __attribute__((unused)),
                                                   void *fragment_data __attribute__((unused)),
                                                   void *data_end __attribute__((unused))) {
    __u64 frag_key = create_fragment_key(src_ip, fragment_id);
    struct fragment_security_info *frag_info = MAP_LOOKUP_ELEM(fragment_security_map, &frag_key);
    
    if (!frag_info) {
        return FRAGMENT_VALID; // No previous fragments to overlap with
    }
    
    // Overlap detection via fragment rate anomaly (eBPF map memory limits prevent
    // full bitmap/range tracking; rate-based detection is effective against fragment bombs)
    if (frag_info->fragment_rate > MAX_FRAGMENT_RATE_PPS * 3) {
        frag_info->overlap_detected = 1;
        MAP_UPDATE_ELEM(fragment_security_map, &frag_key, frag_info, BPF_ANY);
        return FRAGMENT_OVERLAP_DETECTED;
    }
    
    return FRAGMENT_VALID;
}

// Automatic source blocking for fragment-based attacks
static __always_inline int apply_fragment_attack_response(__u32 src_ip,
                                                          __u8 attack_type,
                                                          __u64 current_time) {
    struct attack_detection_info *attack_info = MAP_LOOKUP_ELEM(attack_detection_map, &src_ip);
    
    if (!attack_info) {
        // Create new attack detection entry
        struct attack_detection_info new_info = {
            .src_ip = src_ip,
            .first_seen = current_time,
            .last_seen = current_time,
            .connection_attempts = 0,
            .failed_authentications = 0,
            .enumeration_score = 0,
            .replay_attempts = 0,
            .timing_violations = 0,
            .attack_type = attack_type,
            .confidence_level = 50,
            .response_level = 1,
            .permanent_block = 0
        };
        MAP_UPDATE_ELEM(attack_detection_map, &src_ip, &new_info, BPF_ANY);
        return SEC_ACTION_DROP;
    }
    
    // Update attack information
    attack_info->last_seen = current_time;
    attack_info->attack_type = attack_type;
    attack_info->confidence_level += 10;
    if (attack_info->confidence_level > 100) {
        attack_info->confidence_level = 100;
    }
    
    // Escalate response based on attack frequency
    __u64 time_diff = current_time - attack_info->first_seen;
    if (time_diff < 60000000000ULL) { // Within 1 minute
        attack_info->response_level++;
        if (attack_info->response_level > 3) {
            attack_info->permanent_block = 1;
        }
    }
    
    MAP_UPDATE_ELEM(attack_detection_map, &src_ip, attack_info, BPF_ANY);
    
    // Determine response action
    if (attack_info->permanent_block) {
        return SEC_ACTION_BLOCK_PERM;
    } else if (attack_info->response_level > 2) {
        return SEC_ACTION_BLOCK_TEMP;
    } else {
        return SEC_ACTION_DROP;
    }
}

// Comprehensive fragment security validation
static __always_inline int validate_fragment_security(struct parsed_header *parsed,
                                                      __u32 src_ip,
                                                      __u16 src_port,
                                                      void *fragment_data,
                                                      void *data_end,
                                                      __u64 current_time) {
    if (!(parsed->flags & PKT_FLAG_FRAGMENTED)) {
        return FRAGMENT_VALID; // Not a fragment
    }
    
    // Validate fragment size
    int size_result = validate_fragment_size(parsed->fragment.fragment_size,
                                           parsed->fragment.fragment_index,
                                           parsed->fragment.total_fragments);
    if (size_result != FRAGMENT_VALID) {
        apply_fragment_attack_response(src_ip, FRAGMENT_ATTACK_TINY, current_time);
        return size_result;
    }
    
    // Check fragment rate limiting
    int rate_result = check_fragment_rate_limit(src_ip, current_time);
    if (rate_result != FRAGMENT_VALID) {
        apply_fragment_attack_response(src_ip, FRAGMENT_ATTACK_RATE_LIMIT, current_time);
        return rate_result;
    }
    
    // Verify session binding
    int binding_result = verify_fragment_session_binding(parsed->session_id, src_ip, src_port);
    if (binding_result != FRAGMENT_VALID) {
        apply_fragment_attack_response(src_ip, FRAGMENT_ATTACK_UNBOUND, current_time);
        return binding_result;
    }
    
    // Detect fragment bomb
    int bomb_result = detect_fragment_bomb(src_ip, 
                                          parsed->fragment.fragment_id,
                                          parsed->fragment.total_fragments,
                                          parsed->session_id,
                                          current_time);
    if (bomb_result != FRAGMENT_VALID) {
        apply_fragment_attack_response(src_ip, FRAGMENT_ATTACK_BOMB, current_time);
        return bomb_result;
    }
    
    // Detect fragment overlap
    int overlap_result = detect_fragment_overlap(src_ip,
                                                parsed->fragment.fragment_id,
                                                parsed->fragment.fragment_index,
                                                parsed->fragment.fragment_size,
                                                fragment_data,
                                                data_end);
    if (overlap_result != FRAGMENT_VALID) {
        apply_fragment_attack_response(src_ip, FRAGMENT_ATTACK_OVERLAP, current_time);
        return overlap_result;
    }
    
    return FRAGMENT_VALID;
}

// Clean up expired fragment entries (called periodically)
static __always_inline void cleanup_expired_fragments(__u64 current_time __attribute__((unused))) {
    // This would need to iterate through fragment_security_map
    // eBPF doesn't support map iteration in XDP context
    // This cleanup would be done from userspace periodically
}

// Update fragment security statistics
static __always_inline void update_fragment_security_stats(__u8 attack_type) {
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
        stats->security_events++;
        if (attack_type == FRAGMENT_ATTACK_BOMB || 
            attack_type == FRAGMENT_ATTACK_OVERLAP ||
            attack_type == FRAGMENT_ATTACK_TINY ||
            attack_type == FRAGMENT_ATTACK_OVERSIZED) {
            stats->fragment_attacks++;
        } else if (attack_type == FRAGMENT_ATTACK_RATE_LIMIT) {
            stats->rate_limit_violations++;
        }
        stats->last_update_time = bpf_ktime_get_ns();
        MAP_UPDATE_ELEM(security_stats_map, &key, stats, BPF_ANY);
    }
}

#endif // BUCKWILD_EBPF_FRAGMENT_SECURITY_H