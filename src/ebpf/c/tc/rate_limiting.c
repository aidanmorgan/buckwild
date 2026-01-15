/**
 * Token Bucket Rate Limiting Implementation
 */

#include "rate_limiting.h"

void refill_token_bucket(struct token_bucket *bucket, uint64_t current_ns) {
    // Calculate time elapsed in nanoseconds
    if (current_ns <= bucket->last_refill_ns) {
        // No time elapsed or time went backwards
        return;
    }

    uint64_t elapsed_ns = current_ns - bucket->last_refill_ns;

    // Convert rate from bits/sec to bytes/sec
    uint64_t rate_bytes_per_sec = bucket->rate_bps / 8;

    // Calculate tokens to add: (elapsed_ns / 1_000_000_000) * rate_bytes_per_sec
    // To avoid overflow and maintain precision, calculate as:
    // tokens = (elapsed_ns * rate_bytes_per_sec) / 1_000_000_000
    uint64_t tokens_to_add = (elapsed_ns * rate_bytes_per_sec) / 1000000000ULL;

    // Add tokens to bucket
    bucket->tokens += tokens_to_add;

    // Cap at burst limit
    if (bucket->tokens > bucket->burst_bytes) {
        bucket->tokens = bucket->burst_bytes;
    }

    // Update last refill timestamp
    bucket->last_refill_ns = current_ns;
}

int consume_tokens(struct token_bucket *bucket, uint64_t bytes) {
    // Check if we have enough tokens
    if (bucket->tokens < bytes) {
        return -1;  // Insufficient tokens
    }

    // Consume the tokens
    bucket->tokens -= bytes;
    return 0;  // Success
}

int apply_traffic_shaping(struct token_bucket *bucket, uint64_t packet_size, uint64_t current_ns) {
    // Refill tokens based on elapsed time
    refill_token_bucket(bucket, current_ns);

    // Try to consume tokens for this packet
    return consume_tokens(bucket, packet_size);
}
