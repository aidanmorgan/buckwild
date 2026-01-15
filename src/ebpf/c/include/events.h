/* Ring Buffer Event Definitions
 *
 * This header defines the event structures and types for communication
 * between eBPF programs and userspace via ring buffers.
 */

#ifndef BUCKWILD_EBPF_EVENTS_H
#define BUCKWILD_EBPF_EVENTS_H

#include <linux/types.h>
#include "maps.h"  /* For packet_event structure */

/* Event types for ring buffer communication */
enum event_type {
	EVENT_TYPE_PACKET_RECEIVED = 1,
	EVENT_TYPE_PACKET_DROPPED = 2,
	EVENT_TYPE_SESSION_CREATED = 3,
	EVENT_TYPE_SESSION_CLOSED = 4,
	EVENT_TYPE_PORT_INVALID = 5,
	EVENT_TYPE_HMAC_FAILURE = 6,
	EVENT_TYPE_FRAGMENT_VIOLATION = 7,
	EVENT_TYPE_RATE_LIMIT_EXCEEDED = 8,
};

/* Note: packet_event structure is defined in maps.h */

/* Drop event structure
 * Sent when a packet is dropped for any reason.
 * Total size: 24 bytes
 */
struct drop_event {
	__u64 timestamp_us;     /* Event timestamp in microseconds (8 bytes) */
	__u32 src_ip;           /* Source IP address (4 bytes) */
	__u16 src_port;         /* Source port (2 bytes) */
	__u8 drop_reason;       /* Reason code (1 byte) */
	__u8 event_type;        /* EVENT_TYPE_PACKET_DROPPED (1 byte) */
	__u64 session_id;       /* Session ID if known, 0 otherwise (8 bytes) */
} __attribute__((packed));

/* Session event structure
 * Sent when a session is created or closed.
 * Total size: 24 bytes
 */
struct session_event {
	__u64 session_id;       /* Session identifier (8 bytes) */
	__u64 timestamp_us;     /* Event timestamp in microseconds (8 bytes) */
	__u32 src_ip;           /* Source IP address (4 bytes) */
	__u16 src_port;         /* Source port (2 bytes) */
	__u8 event_type;        /* EVENT_TYPE_SESSION_CREATED or CLOSED (1 byte) */
	__u8 reserved;          /* Padding (1 byte) */
} __attribute__((packed));

/* Security event struct: see maps.h (authoritative definition for BPF maps) */

/* Drop reason codes */
enum drop_reason {
	DROP_REASON_INVALID_PROTOCOL = 1,
	DROP_REASON_SESSION_NOT_FOUND = 2,
	DROP_REASON_INVALID_PORT = 3,
	DROP_REASON_HMAC_FAILURE = 4,
	DROP_REASON_FRAGMENT_VIOLATION = 5,
	DROP_REASON_RATE_LIMIT = 6,
	DROP_REASON_PARSE_ERROR = 7,
	DROP_REASON_SECURITY_BLOCK = 8,
};

/* Security violation codes */
enum security_violation {
	VIOLATION_HMAC_MISMATCH = 1,
	VIOLATION_FRAGMENT_SESSION_MISMATCH = 2,
	VIOLATION_FRAGMENT_OVERLAP = 3,
	VIOLATION_FRAGMENT_BOMB = 4,
	VIOLATION_FRAGMENT_RATE_EXCEEDED = 5,
	VIOLATION_FRAGMENT_TIMEOUT = 6,
	VIOLATION_FRAGMENT_SIZE_INVALID = 7,
};

/* Helper function declarations for eBPF programs */

/**
 * submit_packet_event - Submit a packet received event to ring buffer
 * @rb_map: Pointer to ring buffer map
 * @session_id: Session identifier
 * @sequence: Packet sequence number
 * @payload_length: Payload size in bytes
 * @packet_type: Type of packet
 * @flags: Packet flags
 * @src_ip: Source IP address
 *
 * Returns: 0 on success, negative on error
 */
static __always_inline int
submit_packet_event(void *rb_map,
		    __u64 session_id,
		    __u64 sequence,
		    __u16 payload_length,
		    __u8 packet_type,
		    __u8 flags,
		    __u32 src_ip)
{
	struct packet_event *event;

	event = bpf_ringbuf_reserve(rb_map, sizeof(*event), 0);
	if (!event)
		return -1;

	event->session_id = session_id;
	event->sequence = sequence;
	event->timestamp_us = bpf_ktime_get_ns() / 1000;
	event->payload_length = payload_length;
	event->packet_type = packet_type;
	event->flags = flags;
	event->src_ip = src_ip;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

/**
 * submit_drop_event - Submit a packet drop event to ring buffer
 * @rb_map: Pointer to ring buffer map
 * @src_ip: Source IP address
 * @src_port: Source port
 * @drop_reason: Reason for drop
 * @session_id: Session ID if known, 0 otherwise
 *
 * Returns: 0 on success, negative on error
 */
static __always_inline int
submit_drop_event(void *rb_map,
		  __u32 src_ip,
		  __u16 src_port,
		  __u8 drop_reason,
		  __u64 session_id)
{
	struct drop_event *event;

	event = bpf_ringbuf_reserve(rb_map, sizeof(*event), 0);
	if (!event)
		return -1;

	event->timestamp_us = bpf_ktime_get_ns() / 1000;
	event->src_ip = src_ip;
	event->src_port = src_port;
	event->drop_reason = drop_reason;
	event->event_type = EVENT_TYPE_PACKET_DROPPED;
	event->session_id = session_id;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

/**
 * submit_security_event - Submit a security violation event to ring buffer
 * @rb_map: Pointer to ring buffer map
 * @src_ip: Source IP address
 * @dst_ip: Destination IP address
 * @src_port: Source port
 * @dst_port: Destination port
 * @session_id: Session identifier
 * @event_type: Type of security event
 * @severity: Event severity level
 *
 * Returns: 0 on success, negative on error
 */
static __always_inline int
submit_security_event(void *rb_map,
		      __u32 src_ip,
		      __u32 dst_ip,
		      __u16 src_port,
		      __u16 dst_port,
		      __u64 session_id,
		      __u32 event_type,
		      __u32 severity)
{
	struct security_event *event;

	event = bpf_ringbuf_reserve(rb_map, sizeof(*event), 0);
	if (!event)
		return -1;

	event->timestamp = bpf_ktime_get_ns();
	event->src_ip = src_ip;
	event->dst_ip = dst_ip;
	event->src_port = src_port;
	event->dst_port = dst_port;
	event->event_type = event_type;
	event->severity = severity;
	event->session_id = session_id;
	event->action_taken = 0;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

#endif /* BUCKWILD_EBPF_EVENTS_H */
