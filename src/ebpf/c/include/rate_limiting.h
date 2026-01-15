/**
 * Token Bucket Rate Limiting
 *
 * Implements token bucket algorithm for traffic control and rate limiting.
 * Can be used in both eBPF TC programs and userspace applications.
 */

#ifndef BUCKWILD_RATE_LIMITING_H
#define BUCKWILD_RATE_LIMITING_H

#include <stdint.h>

/**
 * Token bucket structure for rate limiting
 *
 * The token bucket algorithm allows bursts up to burst_bytes while maintaining
 * an average rate of rate_bps (bits per second).
 */
struct token_bucket {
    uint64_t tokens;         // Current token count (bytes available)
    uint64_t last_refill_ns; // Last refill timestamp (nanoseconds since epoch)
    uint64_t rate_bps;       // Rate in bits per second
    uint64_t burst_bytes;    // Maximum burst size in bytes
};

/**
 * Refill token bucket based on elapsed time
 *
 * @param bucket Pointer to token bucket structure
 * @param current_ns Current timestamp in nanoseconds
 *
 * Calculates elapsed time since last refill and adds tokens based on the
 * configured rate. Tokens are capped at the burst limit.
 */
void refill_token_bucket(struct token_bucket *bucket, uint64_t current_ns);

/**
 * Consume tokens from bucket
 *
 * @param bucket Pointer to token bucket structure
 * @param bytes Number of bytes (tokens) to consume
 * @return 0 on success (tokens consumed), -1 on failure (insufficient tokens)
 *
 * Attempts to consume the specified number of tokens from the bucket.
 * If insufficient tokens are available, returns -1 without modifying the bucket.
 */
int consume_tokens(struct token_bucket *bucket, uint64_t bytes);

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
 */
int apply_traffic_shaping(struct token_bucket *bucket, uint64_t packet_size, uint64_t current_ns);

#endif // BUCKWILD_RATE_LIMITING_H
