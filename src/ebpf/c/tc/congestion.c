/**
 * Congestion Detection Implementation
 */

#include "congestion.h"

uint8_t detect_congestion(uint64_t queue_depth, uint64_t drop_count, uint64_t total_packets) {
    // Calculate drop rate as percentage
    uint64_t drop_rate_percent = 0;
    if (total_packets > 0) {
        drop_rate_percent = (drop_count * 100) / total_packets;
    }

    // High congestion: queue > 80% full OR drop rate > 15%
    if (queue_depth > 800 || drop_rate_percent > 15) {
        return CONGESTION_HIGH;
    }

    // Moderate congestion: queue > 40% full OR drop rate > 3%
    if (queue_depth > 400 || drop_rate_percent > 3) {
        return CONGESTION_MODERATE;
    }

    // No congestion
    return CONGESTION_NONE;
}
