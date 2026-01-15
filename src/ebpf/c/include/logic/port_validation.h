/**
 * @file port_validation.h
 * @brief Port hopping validation logic (pure C, no BPF helpers)
 *
 * This header contains PURE LOGIC functions testable in userspace.
 * No eBPF helper functions - can be unit tested with Unity framework.
 *
 * Per REQ-XDP-003, REQ-XDP-004, REQ-XDP-005, REQ-XDP-006, REQ-XDP-007
 * Following design/protocol/10-port-hopping.md
 */

#ifndef BUCKWILD_EBPF_PORT_VALIDATION_H
#define BUCKWILD_EBPF_PORT_VALIDATION_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Check if port is in current time bucket
 *
 * @param port Port to validate
 * @param current_port Expected port for current time bucket
 * @return true if port matches current bucket
 */
static inline bool is_port_current(uint16_t port, uint16_t current_port)
{
	return port == current_port;
}

/**
 * Check if port is in past window (late packets)
 *
 * Per REQ-XDP-006: Accept packets within past_window_size milliseconds
 *
 * @param port Port to validate
 * @param past_ports Array of valid past bucket ports
 * @param past_count Number of entries in past_ports
 * @return true if port matches any past bucket port
 */
static inline bool is_port_in_past_window(
	uint16_t port,
	const uint16_t *past_ports,
	uint32_t past_count)
{
	/* Bounded loop for eBPF verifier compliance */
#ifdef __BPF__
	#pragma unroll
#endif
	for (uint32_t i = 0; i < 16; i++) {  /* Max 16 past buckets (8 seconds) */
		if (i >= past_count) {
			break;
		}
		if (port == past_ports[i]) {
			return true;
		}
	}
	return false;
}

/**
 * Check if port is in future window (early packets)
 *
 * Per REQ-XDP-007: Accept packets within future_window_size milliseconds
 *
 * @param port Port to validate
 * @param future_ports Array of valid future bucket ports
 * @param future_count Number of entries in future_ports
 * @return true if port matches any future bucket port
 */
static inline bool is_port_in_future_window(
	uint16_t port,
	const uint16_t *future_ports,
	uint32_t future_count)
{
	/* Bounded loop for eBPF verifier compliance */
#ifdef __BPF__
	#pragma unroll
#endif
	for (uint32_t i = 0; i < 16; i++) {  /* Max 16 future buckets (8 seconds) */
		if (i >= future_count) {
			break;
		}
		if (port == future_ports[i]) {
			return true;
		}
	}
	return false;
}

/**
 * Comprehensive port validation with adaptive windows
 *
 * This is the MAIN validation function used by XDP program.
 * Tests against current bucket, past window, and future window.
 *
 * @param port Port to validate
 * @param current_port Expected port for current time bucket
 * @param past_ports Array of valid past ports
 * @param future_ports Array of valid future ports
 * @param past_count Number of past ports
 * @param future_count Number of future ports
 * @param[out] is_late Set to true if packet is from past window
 * @param[out] is_early Set to true if packet is from future window
 * @return true if port is valid (current, past, or future window)
 */
static inline bool validate_port_with_window(
	uint16_t port,
	uint16_t current_port,
	const uint16_t *past_ports,
	const uint16_t *future_ports,
	uint32_t past_count,
	uint32_t future_count,
	bool *is_late,
	bool *is_early)
{
	/* Initialize flags */
	*is_late = false;
	*is_early = false;

	/* Check current bucket first (most common case) */
	if (is_port_current(port, current_port)) {
		return true;
	}

	/* Check past window (late packets) */
	if (is_port_in_past_window(port, past_ports, past_count)) {
		*is_late = true;
		return true;
	}

	/* Check future window (early packets) */
	if (is_port_in_future_window(port, future_ports, future_count)) {
		*is_early = true;
		return true;
	}

	/* Port not in any window - invalid */
	return false;
}

/**
 * Simple map-based port validation (alternative approach)
 *
 * Used when ports are pre-computed in hash map by userspace.
 * This is the approach used in the actual XDP implementation.
 *
 * @param port Port to validate
 * @param port_map_lookup Function pointer to map lookup (or NULL for testing)
 * @return true if port is valid according to map
 */
static inline bool validate_port_from_map(
	uint16_t port,
	uint8_t (*port_map_lookup)(uint16_t))
{
	if (port_map_lookup == NULL) {
		return false;  /* No map available */
	}

	uint8_t valid = port_map_lookup(port);
	return valid == 1;
}

#endif /* BUCKWILD_EBPF_PORT_VALIDATION_H */
