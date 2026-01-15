/**
 * @file maps.h
 * @brief eBPF map definitions for buckwild protocol
 *
 * Follows specifications from:
 * - C_EBPF_DETAILED_IMPLEMENTATION_PLAN.md
 * - TUN_EBPF_IMPLEMENTATION_GUIDE.md (Task 4 & 5)
 * - design/protocol/10-port-hopping.md
 * - design/protocol/11-adaptive-networking.md
 * - design/protocol/07-data-transmission.md
 *
 * These maps are shared between:
 * - XDP programs (packet filtering)
 * - TC programs (rate limiting)
 * - Userspace (control plane - both C and Rust)
 */

#ifndef BUCKWILD_EBPF_MAPS_H
#define BUCKWILD_EBPF_MAPS_H

#include <linux/types.h>

#ifdef __BPF__
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* BPF map helper macros */
#define MAP_LOOKUP_ELEM(map, key) bpf_map_lookup_elem(&map, key)
#define MAP_UPDATE_ELEM(map, key, value, flags) bpf_map_update_elem(&map, key, value, flags)
#define MAP_DELETE_ELEM(map, key) bpf_map_delete_elem(&map, key)
#endif

/* ============================================================================
 * Session Info Structure (used by all eBPF programs)
 * ============================================================================ */
struct session_info {
	__u64 session_id;           /* Session identifier */
	__u64 created_at_ns;        /* Creation timestamp */
	__u64 last_activity_ns;     /* Last activity timestamp */
	__u64 last_packet_time;     /* Last packet timestamp (ns) */
	__u32 src_ip;               /* Source IP address */
	__u32 dst_ip;               /* Destination IP address */
	__u16 src_port;             /* Source port */
	__u16 dst_port;             /* Destination port */
	__u32 expected_port;        /* Expected port for port hopping validation */
	__u32 packets_sent;         /* Packets sent counter */
	__u32 packets_received;     /* Packets received counter */
	__u32 packet_count;         /* Total packet count */
	__u32 last_sequence;        /* Last sequence number seen */
	__u64 bytes_sent;           /* Bytes sent counter */
	__u64 bytes_received;       /* Bytes received counter */
	__u32 security_violations;  /* Security violation counter */
	__u8 state;                 /* Session state */
	__u8 flags;                 /* Session flags */
	__u8 attack_detected;       /* Attack detected flag */
	__u8 hmac_policy;           /* HMAC policy for this session (LIGHT/MEDIUM/STRONG) */
	__u8 expected_hmac_prefix[8];  /* HMAC Light 8-byte prefix for fast validation */
};

/* ============================================================================
 * Fragment Security Info Structure (for fragment bomb/attack detection)
 * ============================================================================ */
struct fragment_security_info {
	__u64 session_id;           /* Associated session ID */
	__u32 src_ip;               /* Source IP address */
	__u16 fragment_id;          /* Fragment identifier */
	__u16 total_fragments;      /* Expected total fragments */
	__u32 received_fragments;   /* Received fragment count */
	__u64 total_bytes;          /* Total bytes received */
	__u64 first_fragment_time;  /* First fragment timestamp */
	__u64 last_fragment_time;   /* Last fragment timestamp */
	__u32 fragment_rate;        /* Fragments per second */
	__u8 overlap_detected;      /* Overlap attack detected */
	__u8 bomb_detected;         /* Fragment bomb detected */
	__u8 session_bound;         /* Session binding verified */
	__u8 reserved;              /* Padding */
};

/* ============================================================================
 * Attack Detection Info Structure (for security monitoring)
 * ============================================================================ */
struct attack_detection_info {
	__u64 first_seen;           /* First detection timestamp */
	__u64 last_seen;            /* Last detection timestamp */
	__u32 src_ip;               /* Source IP address */
	__u32 attack_type;          /* Type of attack detected */
	__u32 confidence_level;     /* Confidence level (0-100) */
	__u32 response_level;       /* Response escalation level */
	__u32 packet_count;         /* Suspicious packet count */
	__u32 connection_attempts;  /* Connection attempt count */
	__u32 failed_authentications; /* Failed auth count */
	__u32 enumeration_score;    /* Port scan enumeration score */
	__u32 replay_attempts;      /* Replay attack attempts */
	__u32 timing_violations;    /* Timing anomaly count */
	__u8 blocked;               /* Currently blocked */
	__u8 permanent_block;       /* Permanent block flag */
	__u8 reserved[2];           /* Padding */
};

/* Security action constants */
#define SEC_ACTION_PASS         0
#define SEC_ACTION_DROP         1
#define SEC_ACTION_LOG          2
#define SEC_ACTION_BLOCK        3
#define SEC_ACTION_BLOCK_TEMP   4
#define SEC_ACTION_BLOCK_PERM   5
#define SEC_ACTION_ALLOW        6
#define SEC_ACTION_RATE_LIMIT   7

/* ============================================================================
 * Security Event Structure (for security logging)
 * ============================================================================ */
struct security_event {
	__u64 timestamp;            /* Event timestamp */
	__u32 src_ip;               /* Source IP */
	__u32 dst_ip;               /* Destination IP */
	__u16 src_port;             /* Source port */
	__u16 dst_port;             /* Destination port */
	__u32 event_type;           /* Event type */
	__u32 severity;             /* Event severity */
	__u64 session_id;           /* Associated session */
	__u8 action_taken;          /* Action taken */
	__u8 reserved[7];           /* Padding */
};

/* ============================================================================
 * Security Stats Structure (for statistics tracking)
 * ============================================================================ */
struct security_stats {
	__u64 packets_inspected;    /* Total packets inspected */
	__u64 packets_dropped;      /* Packets dropped */
	__u64 packets_allowed;      /* Packets allowed */
	__u64 attacks_detected;     /* Attacks detected */
	__u64 sessions_blocked;     /* Sessions blocked */
};

#ifdef __BPF__
/* Security Stats Map - singleton for global statistics */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);           /* Index 0 (singleton) */
	__type(value, struct security_stats);
	__uint(max_entries, 1);
} security_stats_map SEC(".maps");
#endif

/* ============================================================================
 * Rate Limit Info Structure (for fragment rate limiting)
 * ============================================================================ */
struct rate_limit_info {
	__u64 last_reset_time;      /* Last counter reset timestamp */
	__u32 packet_count;         /* Packets in current window */
	__u64 byte_count;           /* Bytes in current window */
	__u32 violation_count;      /* Violations in current window */
	__u8 blocked;               /* Currently blocked flag */
	__u8 escalation_level;      /* Escalation level for progressive blocking */
	__u32 block_duration;       /* Block duration in seconds */
	__u64 last_violation_time;  /* Timestamp of last violation */
	__u32 total_violations;     /* Total violations (for statistics) */
};

#ifdef __BPF__
/* Session Map - tracks active sessions */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);           /* session_id */
	__type(value, struct session_info);
	__uint(max_entries, 10000);
} session_map SEC(".maps");

/* Per-IP Rate Limit Map - for fragment and packet rate limiting */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);           /* Source IP address */
	__type(value, struct rate_limit_info);
	__uint(max_entries, 10000);
} ip_rate_limit_map SEC(".maps");

/* Fragment Security Map - for fragment bomb/attack detection */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);           /* Fragment key (src_ip << 32 | fragment_id) */
	__type(value, struct fragment_security_info);
	__uint(max_entries, 10000);
} fragment_security_map SEC(".maps");

/* Attack Detection Map - for security monitoring */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);           /* Source IP address */
	__type(value, struct attack_detection_info);
	__uint(max_entries, 10000);
} attack_detection_map SEC(".maps");
#endif

/* ============================================================================
 * Port Statistics Structure (for port monitoring)
 * ============================================================================ */
struct port_stats {
	__u64 packet_count;         /* Total packets on this port */
	__u64 byte_count;           /* Total bytes on this port */
	__u64 last_used_time;       /* Last activity timestamp */
	__u32 session_count;        /* Active sessions on this port */
	__u32 security_events;      /* Security events on this port */
	__u32 rate_limit_violations; /* Rate limit violations */
	__u32 attack_attempts;      /* Attack attempts detected */
	__u32 current_hop_window;   /* Current hop window index */
	__u8 security_level;        /* Security level (0-3) */
	__u8 reserved[3];           /* Padding */
};

#ifdef __BPF__
/* Port Statistics Map - tracks per-port statistics */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);           /* Port number */
	__type(value, struct port_stats);
	__uint(max_entries, 1000);
} port_stats_map SEC(".maps");
#endif

/* ============================================================================
 * Port Hopping Maps (REQ-XDP-003, REQ-XDP-004)
 * ============================================================================
 * Per design/protocol/10-port-hopping.md:
 * - Ports derived via HMAC-SHA256(daily_key || time_bucket || salt)
 * - Time bucket = (millis_since_midnight_UTC) / 500ms
 * - Userspace computes ports, eBPF validates via lookup table
 */

/**
 * Port Validity Map
 *
 * Key: UDP destination port (u16)
 * Value: Validity flag (u8: 1 = valid, 0 = invalid)
 *
 * Updated by userspace every 10 seconds with:
 * - Current time bucket port
 * - Past window ports (adaptive delay)
 * - Future window ports (adaptive delay)
 *
 * Max entries: 512 (covers current + ~500ms past/future windows)
 */
#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);    /* port number */
	__type(value, __u8);   /* 1 = valid, 0 = invalid */
	__uint(max_entries, 512);
} port_validity_map SEC(".maps");
#endif

/* ============================================================================
 * Adaptive Delay Window Maps (REQ-XDP-005, REQ-XDP-006, REQ-XDP-007)
 * ============================================================================
 * Per design/protocol/11-adaptive-networking.md:
 * - Asymmetric windows (past != future)
 * - Track early/late packet counts for window adjustment
 * - Updated atomically by XDP programs
 */

/**
 * Adaptive Delay State
 *
 * Tracks network delay characteristics for window tuning:
 * - past_window_size: milliseconds of past packets to accept
 * - future_window_size: milliseconds of future packets to accept
 * - early_count: packets arriving in future window (atomic counter)
 * - late_count: packets arriving in past window (atomic counter)
 * - last_update_ns: timestamp of last window adjustment
 */
struct adaptive_delay_state {
	__u32 past_window_size;    /* milliseconds */
	__u32 future_window_size;  /* milliseconds */
	__u32 early_count;         /* atomic: packets from future */
	__u32 late_count;          /* atomic: packets from past */
	__u64 last_update_ns;      /* nanoseconds */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);    /* index 0 (singleton) */
	__type(value, struct adaptive_delay_state);
	__uint(max_entries, 1);
} adaptive_window_map SEC(".maps");
#endif

/* ============================================================================
 * Session Routing Maps (REQ-XDP-009, REQ-XDP-010, REQ-XDP-011)
 * ============================================================================
 * Per design/protocol/02-core-definitions.md:
 * - Session ID = u64 (8 bytes max, variable length 16/32/64-bit)
 * - Maps session_id → ring_buffer_id for packet routing
 * - Registered by userspace when session established
 */

/**
 * Session Routing Map
 *
 * Key: Session ID (u64, 8 bytes - supports max session ID size)
 * Value: Ring buffer ID (u32) - which ring buffer to route packets to
 *
 * Userspace operations:
 * - Register: Add entry when session established
 * - Unregister: Remove entry when session closes
 * - Lookup: eBPF uses for packet routing
 *
 * Max entries: 10,000 concurrent sessions
 */
#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);       /* session_id (8 bytes max) */
	__type(value, __u32);     /* ring_buffer_id */
	__uint(max_entries, 10000);
} session_routing_map SEC(".maps");
#endif

/* ============================================================================
 * Packet Ring Buffer (REQ-XDP-012, REQ-XDP-013)
 * ============================================================================
 * Per TUN_EBPF_IMPLEMENTATION_GUIDE.md Task 4:
 * - XDP submits packet events (not full packets) to ring buffer
 * - Userspace consumes events asynchronously
 * - 256KB buffer size (balance between throughput and memory)
 */

/**
 * Packet Event Structure
 *
 * Submitted to ring buffer when packet passes XDP validation.
 * Userspace reads events and processes full packets.
 *
 * Packed to match exact wire format for efficient parsing.
 * Session ID is u64 (8 bytes max) to support all session ID lengths.
 * Total size: 32 bytes
 */
struct packet_event {
	__u64 session_id;        /* Session identifier (8 bytes max) */
	__u64 sequence;          /* Sequence number */
	__u64 timestamp_us;      /* Timestamp (microseconds) */
	__u16 payload_length;    /* Payload size (bytes) */
	__u8 packet_type;        /* Protocol packet type */
	__u8 flags;              /* Protocol flags */
	__u32 src_ip;            /* Source IP address (4 bytes) */
} __attribute__((packed));

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  /* 256KB */
} packet_ring_buffer SEC(".maps");
#endif

/* ============================================================================
 * Rate Limiting Maps (REQ-TC-001 through REQ-TC-006)
 * ============================================================================
 * Per design/protocol/07-data-transmission.md:
 * - Token bucket algorithm for global rate limiting
 * - Refill based on elapsed time and configured rate
 * - Enforced by TC egress programs
 */

/**
 * Rate Limit State
 *
 * Token bucket parameters:
 * - last_update_ns: Last token refill timestamp
 * - tokens: Available tokens (bytes) - decremented on send
 * - max_tokens: Bucket capacity (bytes) - prevents token accumulation
 * - refill_rate_bpns: Bytes per nanosecond * 1000 (for precision)
 *
 * Algorithm:
 * 1. elapsed = now_ns - last_update_ns
 * 2. tokens += (elapsed * refill_rate_bpns) / 1000
 * 3. tokens = min(tokens, max_tokens)
 * 4. if (tokens >= packet_size) { tokens -= packet_size; return OK; }
 * 5. else { return DROP; }
 */
struct rate_limit_state {
	__u64 last_update_ns;    /* nanoseconds */
	__u64 tokens;            /* available bytes */
	__u64 max_tokens;        /* bucket capacity (bytes) */
	__u64 refill_rate_bpns;  /* (bytes/sec * 1000) / 1e9 */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);    /* index 0 (singleton) */
	__type(value, struct rate_limit_state);
	__uint(max_entries, 1);
} rate_limit_map SEC(".maps");
#endif

/* ============================================================================
 * Congestion Control Maps (REQ-TC-007 through REQ-TC-010)
 * ============================================================================
 * Per design/protocol/07-data-transmission.md:
 * - Per-session congestion windows
 * - Track in-flight bytes to enforce cwnd limit
 * - Updated atomically on packet send and ACK
 */

/**
 * Congestion Window State
 *
 * Per-session flow control:
 * - cwnd: Congestion window size (bytes) - max in-flight data
 * - in_flight: Current bytes in flight (atomic counter)
 * - last_ack_ns: Timestamp of last ACK received
 *
 * TC egress check:
 * if (in_flight + packet_size > cwnd) { return DROP; }
 * else { in_flight += packet_size; return OK; }
 *
 * Userspace on ACK:
 * in_flight -= acked_bytes;
 */
struct congestion_window {
	__u32 cwnd;           /* window size (bytes) */
	__u32 in_flight;      /* bytes currently in flight (atomic) */
	__u64 last_ack_ns;    /* nanoseconds */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);       /* session_id (8 bytes max) */
	__type(value, struct congestion_window);
	__uint(max_entries, 10000);
} congestion_map SEC(".maps");
#endif

/* ============================================================================
 * Fragment Security Maps (REQ-XDP-004, design/security.md)
 * ============================================================================
 * Per design/security.md (lines 247-259):
 * - 7 fragment security checks required
 * - Rate limiting: 20 fragments/second per source
 * - Fragment bomb detection: max 10 per session
 * - Memory limits: 1MB per session
 * - Timeout: 5 seconds
 * - Session binding validation
 * - Overlap detection
 */

/**
 * Fragment Rate Map
 *
 * Tracks fragment rate per source IP for DoS prevention.
 * LRU eviction ensures memory bounds with minimal overhead.
 *
 * Key: Source IPv4 address (u32)
 * Value: Fragment rate tracking entry
 *
 * Security: Enforces 20 fragments/second limit per source
 */
struct fragment_rate_entry {
	__u64 last_fragment_ns;    /* Last fragment timestamp */
	__u32 fragment_count;      /* Fragments in current window */
	__u32 violations;          /* Rate limit violation count */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);    /* Source IP address */
	__type(value, struct fragment_rate_entry);
	__uint(max_entries, 10000);
} fragment_rate_map SEC(".maps");
#endif

/**
 * Fragment Count Map
 *
 * Tracks active fragments and reassembly memory per session.
 * Used for fragment bomb detection and memory limit enforcement.
 *
 * Key: Session ID (u64)
 * Value: Fragment tracking entry
 *
 * Security: Enforces max 10 fragments and 1MB memory per session
 */
struct fragment_count_entry {
	__u32 active_fragments;    /* Number of fragments being reassembled */
	__u64 reassembly_memory;   /* Total memory used (bytes) */
	__u64 oldest_fragment_ns;  /* Timestamp of oldest fragment (for timeout) */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);    /* Session ID */
	__type(value, struct fragment_count_entry);
	__uint(max_entries, 10000);
} fragment_count_map SEC(".maps");
#endif

/**
 * Blocked Sources Map
 *
 * Tracks temporarily blocked source IPs due to violations.
 * LRU eviction prevents memory exhaustion from attack traffic.
 *
 * Key: Source IPv4 address (u32)
 * Value: Block information
 *
 * Security: Temporary blocks for rate limit violations and attacks
 */
struct blocked_source_entry {
	__u64 block_until_ns;      /* Block expiration timestamp */
	__u32 violation_count;     /* Total violation count */
	__u8 block_reason;         /* Reason code (rate limit, bomb, etc.) */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);    /* Source IP address */
	__type(value, struct blocked_source_entry);
	__uint(max_entries, 1000);
} blocked_sources_map SEC(".maps");
#endif

/* ============================================================================
 * Device Map for XDP Redirect (REQ-XDP-REDIRECT)
 * ============================================================================
 * Maps interface index to redirect target for XDP_REDIRECT action.
 * Userspace populates with TUN device ifindex on initialization.
 */
#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 64);
	__type(key, __u32);    /* source interface index */
	__type(value, __u32);  /* target interface index */
} xdp_devmap SEC(".maps");
#endif

/* ============================================================================
 * CPU Map for XDP Load Balancing (REQ-XDP-LB)
 * ============================================================================
 * Maps CPU index to XDP program for per-CPU packet processing.
 * Enables session affinity by hashing session_id to CPU.
 */
#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, 256);
	__type(key, __u32);    /* CPU index */
	__type(value, __u32);  /* queue size per CPU */
} xdp_cpumap SEC(".maps");
#endif

/* ============================================================================
 * Police Configuration Map (REQ-TC-POLICE)
 * ============================================================================
 * Configures Committed Information Rate and Burst Size for traffic policing.
 * Policing drops packets exceeding rate (vs shaping which delays).
 */
struct police_config {
	__u64 cir_bytes_per_sec;   /* Committed Information Rate */
	__u64 cbs_bytes;           /* Committed Burst Size */
	__u64 tokens;              /* Current token count */
	__u64 last_update_ns;      /* Last token refill time */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);        /* session_id */
	__type(value, struct police_config);
	__uint(max_entries, 10000);
} police_config_map SEC(".maps");
#endif

/**
 * Fragment Limits Map
 *
 * Singleton array storing global fragment validation limits.
 * Updated by userspace, read-only in eBPF for fast validation.
 *
 * Key: Index 0 (singleton)
 * Value: Fragment size and count limits
 *
 * Default values:
 * - min_size: 64 bytes
 * - max_size: 1400 bytes
 * - max_per_session: 10 fragments
 * - max_global: 1000 total fragments
 */
struct fragment_size_limits {
	__u16 min_size;            /* Minimum fragment size (64) */
	__u16 max_size;            /* Maximum fragment size (1400) */
	__u32 max_per_session;     /* Max fragments per session (10) */
	__u32 max_global;          /* Max total active fragments (1000) */
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);    /* Index 0 (singleton) */
	__type(value, struct fragment_size_limits);
	__uint(max_entries, 1);
} fragment_limits_map SEC(".maps");
#endif

/* ============================================================================
 * License (Required by eBPF verifier)
 * ============================================================================
 */

#ifdef __BPF__
char _license[] SEC("license") = "GPL";
#endif

#endif /* BUCKWILD_EBPF_MAPS_H */
