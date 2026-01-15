/**
 * Congestion Detection
 *
 * Detects network congestion based on queue depth and packet drop metrics.
 * Used for adaptive rate control and traffic management.
 */

#ifndef BUCKWILD_CONGESTION_H
#define BUCKWILD_CONGESTION_H

#include <stdint.h>

// Congestion levels
#define CONGESTION_NONE      0  // No congestion detected
#define CONGESTION_MODERATE  1  // Moderate congestion
#define CONGESTION_HIGH      2  // High congestion, aggressive action needed

/**
 * Detect congestion level based on queue metrics
 *
 * @param queue_depth Current queue depth (packets or bytes in queue)
 * @param drop_count Total packets dropped
 * @param total_packets Total packets processed
 * @return Congestion level: 0 = none, 1 = moderate, 2 = high
 *
 * Congestion detection algorithm:
 * - HIGH (2): Queue > 80% full OR drop rate > 15%
 * - MODERATE (1): Queue > 40% full OR drop rate > 3%
 * - NONE (0): Otherwise
 *
 * This function assumes queue_depth is measured against a reference
 * capacity of 1000 units (packets or bytes depending on queue type).
 */
uint8_t detect_congestion(uint64_t queue_depth, uint64_t drop_count, uint64_t total_packets);

#endif // BUCKWILD_CONGESTION_H
