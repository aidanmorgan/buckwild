/**
 * Traffic Shaping
 *
 * Applies rate limiting and traffic shaping using token bucket algorithm.
 * Smooths bursty traffic and enforces bandwidth limits.
 */

#ifndef BUCKWILD_TRAFFIC_SHAPING_H
#define BUCKWILD_TRAFFIC_SHAPING_H

#include <stdint.h>
#include "rate_limiting.h"

/**
 * Apply traffic shaping to a packet
 *
 * @param bucket Pointer to token bucket for rate limiting
 * @param packet_size Size of packet in bytes
 * @param current_ns Current timestamp in nanoseconds
 * @return 0 if packet allowed (tokens consumed), -1 if packet should be dropped
 *
 * This function combines token refill and consumption in a single operation.
 * It automatically refills tokens based on elapsed time before attempting
 * to consume tokens for the current packet.
 *
 * Use this for traffic shaping at the TC (Traffic Control) egress point.
 */
int apply_traffic_shaping(struct token_bucket *bucket, uint64_t packet_size, uint64_t current_ns);

#endif // BUCKWILD_TRAFFIC_SHAPING_H
