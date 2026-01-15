// Fragment overlap detection
//
// This module provides overlap detection for fragmented packets to prevent
// fragment overlap attacks and ensure proper reassembly.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

// Import ALL types from the authoritative consolidated types module
use crate::error::{FragmentationError, FragmentationResult};
use crate::protocol::types::*;

/// Overlap detector for fragment validation
pub struct OverlapDetector {
    /// Fragment ranges for active reassembly contexts
    fragment_ranges: Arc<RwLock<HashMap<ReassemblyKey, FragmentRangeTracker>>>,
    /// Configuration
    config: OverlapConfig,
    /// Statistics
    stats: Arc<RwLock<OverlapStats>>,
}

/// Configuration for overlap detection
#[derive(Debug, Clone)]
pub struct OverlapConfig {
    /// Maximum number of tracked reassembly contexts
    pub max_tracked_contexts: usize,
    /// Context timeout in seconds
    pub context_timeout_sec: u64,
    /// Enable strict overlap checking
    pub strict_overlap_checking: bool,
    /// Allow adjacent fragments (touching but not overlapping)
    pub allow_adjacent_fragments: bool,
}

impl Default for OverlapConfig {
    fn default() -> Self {
        Self {
            max_tracked_contexts: 1000,
            context_timeout_sec: 30,
            strict_overlap_checking: true,
            allow_adjacent_fragments: true,
        }
    }
}

/// Key for identifying reassembly contexts
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ReassemblyKey {
    pub session_id: SessionId,
    pub fragment_id: FragmentId,
}

/// Fragment range tracker for a reassembly context
#[derive(Debug)]
struct FragmentRangeTracker {
    /// Fragment ranges (start_offset, end_offset)
    ranges: Vec<FragmentRange>,
    /// Total expected fragments
    fragment_count: Option<u16>,
    /// Creation timestamp
    #[allow(dead_code)]
    created_at: SystemTime,
    /// Last update timestamp
    last_update: SystemTime,
}

/// Fragment range information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentRange {
    /// Fragment index
    index: FragmentIndex,
    /// Start offset in the reassembled packet
    start_offset: StartOffset,
    /// End offset in the reassembled packet
    end_offset: EndOffset,
    /// Fragment size
    size: FragmentSize,
    /// Timestamp when fragment was received
    timestamp: SystemTime,
}

/// Fragment information for overlap checking
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    pub session_id: SessionId,
    pub fragment_id: FragmentId,
    pub fragment_index: FragmentIndex,
    pub fragment_count: FragmentCount,
    pub payload_size: FragmentSize,
}

/// Overlap detection result
#[derive(Debug, Clone)]
pub enum OverlapResult {
    /// No overlap detected
    NoOverlap,
    /// Overlap detected with existing fragment
    Overlap {
        conflicting_index: FragmentIndex,
        overlap_start: StartOffset,
        overlap_end: EndOffset,
    },
    /// Adjacent fragment (touching but not overlapping)
    Adjacent { adjacent_index: FragmentIndex },
    /// Duplicate fragment
    Duplicate { existing_index: FragmentIndex },
}

/// Overlap detection statistics
#[derive(Debug, Clone)]
pub struct OverlapStats {
    /// Total fragments checked
    pub total_checked: PacketCount,
    /// Overlaps detected
    pub overlaps_detected: PacketCount,
    /// Adjacent fragments detected
    pub adjacent_detected: PacketCount,
    /// Duplicate fragments detected
    pub duplicates_detected: PacketCount,
    /// Active tracking contexts
    pub active_contexts: usize,
    /// Contexts cleaned up due to timeout
    pub contexts_expired: PacketCount,
}

impl OverlapDetector {
    /// Create a new overlap detector
    pub fn new() -> Self {
        Self::with_config(OverlapConfig::default())
    }

    /// Create a new overlap detector with custom configuration
    pub fn with_config(config: OverlapConfig) -> Self {
        Self {
            fragment_ranges: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(OverlapStats {
                total_checked: PacketCount::zero(),
                overlaps_detected: PacketCount::zero(),
                adjacent_detected: PacketCount::zero(),
                duplicates_detected: PacketCount::zero(),
                active_contexts: 0,
                contexts_expired: PacketCount::zero(),
            })),
        }
    }

    /// Check for fragment overlap
    pub fn check_overlap(
        &self,
        reassembly_key: &ReassemblyKey,
        fragment_info: &FragmentInfo,
    ) -> FragmentationResult<OverlapResult> {
        // Update statistics
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.total_checked += 1;
        }

        // Calculate fragment range
        let fragment_range = self.calculate_fragment_range(fragment_info)?;

        let mut ranges = self
            .fragment_ranges
            .write()
            .unwrap_or_else(|e| e.into_inner());

        // Check if we're tracking too many contexts
        if ranges.len() >= self.config.max_tracked_contexts {
            return Err(FragmentationError::ReassemblyFailed {
                reason: "Too many tracked reassembly contexts".to_string(),
            });
        }

        // Get or create range tracker for this reassembly context
        let range_tracker =
            ranges
                .entry(reassembly_key.clone())
                .or_insert_with(|| FragmentRangeTracker {
                    ranges: Vec::new(),
                    fragment_count: Some(fragment_info.fragment_count.as_u16()),
                    created_at: SystemTime::now(),
                    last_update: SystemTime::now(),
                });

        // Validate total fragments consistency
        if let Some(expected_total) = range_tracker.fragment_count {
            if expected_total != fragment_info.fragment_count.as_u16() {
                return Err(
                    crate::error::fragmentation::FragmentationError::ReassemblyFailed {
                        reason: "Fragment total count mismatch".to_string(),
                    },
                );
            }
        } else {
            range_tracker.fragment_count = Some(fragment_info.fragment_count.as_u16());
        }

        // Check for overlaps with existing fragments
        let overlap_result = self.detect_overlap(&range_tracker.ranges, &fragment_range)?;

        // If no overlap, add the fragment range
        if matches!(
            overlap_result,
            OverlapResult::NoOverlap | OverlapResult::Adjacent { .. }
        ) {
            range_tracker.ranges.push(fragment_range);
            range_tracker.ranges.sort_by_key(|r| r.start_offset);
            self.merge_adjacent_fragments(&mut range_tracker.ranges);
            range_tracker.last_update = SystemTime::now();
        }

        // Update statistics based on result
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            match &overlap_result {
                OverlapResult::Overlap { .. } => stats.overlaps_detected += 1,
                OverlapResult::Adjacent { .. } => stats.adjacent_detected += 1,
                OverlapResult::Duplicate { .. } => stats.duplicates_detected += 1,
                OverlapResult::NoOverlap => {}
            }
            stats.active_contexts = ranges.len();
        }

        Ok(overlap_result)
    }

    /// Calculate fragment range from fragment information
    fn calculate_fragment_range(
        &self,
        fragment_info: &FragmentInfo,
    ) -> FragmentationResult<FragmentRange> {
        // For simplicity, we assume fragments are received in order and
        // each fragment (except possibly the last) has a standard size.
        // In a real implementation, you might need more sophisticated
        // offset calculation based on the actual fragmentation scheme.

        let fragment_size = fragment_info.payload_size;
        let start_offset = fragment_info.fragment_index.as_usize() * fragment_size;
        let end_offset = start_offset + fragment_size;

        Ok(FragmentRange {
            index: fragment_info.fragment_index,
            start_offset: StartOffset::new(start_offset),
            end_offset: EndOffset::new(end_offset),
            size: fragment_size,
            timestamp: SystemTime::now(),
        })
    }

    /// Detect overlap with existing fragment ranges
    fn detect_overlap(
        &self,
        existing_ranges: &[FragmentRange],
        new_range: &FragmentRange,
    ) -> FragmentationResult<OverlapResult> {
        let mut adjacent_found = None;

        for existing_range in existing_ranges {
            // Check for duplicate fragment (same index)
            if existing_range.index == new_range.index {
                return Ok(OverlapResult::Duplicate {
                    existing_index: existing_range.index,
                });
            }

            // Check for overlap
            let overlap_start = std::cmp::max(existing_range.start_offset, new_range.start_offset);
            let overlap_end = std::cmp::min(existing_range.end_offset, new_range.end_offset);

            if (overlap_start.as_u64()) < overlap_end.as_u64() {
                // Overlap detected
                if self.config.strict_overlap_checking {
                    return Ok(OverlapResult::Overlap {
                        conflicting_index: existing_range.index,
                        overlap_start,
                        overlap_end,
                    });
                }
            }

            // Check for adjacent fragments
            if self.config.allow_adjacent_fragments
                && (existing_range.end_offset.as_u64() == new_range.start_offset.as_u64()
                    || new_range.end_offset.as_u64() == existing_range.start_offset.as_u64())
            {
                adjacent_found = Some(existing_range.index);
            }
        }

        if let Some(adjacent_index) = adjacent_found {
            Ok(OverlapResult::Adjacent { adjacent_index })
        } else {
            Ok(OverlapResult::NoOverlap)
        }
    }

    /// Merge adjacent fragment ranges
    fn merge_adjacent_fragments(&self, ranges: &mut Vec<FragmentRange>) {
        if ranges.len() < 2 {
            return;
        }

        let mut merged = Vec::with_capacity(ranges.len());
        let mut current_range = ranges[0].clone();

        for next_range in ranges.iter().skip(1) {
            // Check if ranges are adjacent or overlapping (should be adjacent if we got here)
            if current_range.end_offset.as_u64() >= next_range.start_offset.as_u64() {
                // Calculate potential new size
                let new_end = std::cmp::max(current_range.end_offset, next_range.end_offset);
                let new_size_usize =
                    (new_end.as_u64() - current_range.start_offset.as_u64()) as usize;

                // Only merge if size fits in u16 (FragmentSize limit)
                if new_size_usize <= u16::MAX as usize {
                    // Merge ranges
                    current_range.end_offset = new_end;
                    current_range.size = FragmentSize::new(new_size_usize as u16);
                    // Keep the timestamp of the latest fragment
                    if next_range.timestamp > current_range.timestamp {
                        current_range.timestamp = next_range.timestamp;
                    }
                } else {
                    // Too big to merge, push current and start new
                    merged.push(current_range);
                    current_range = next_range.clone();
                }
            } else {
                // Gap found, push current and start new
                merged.push(current_range);
                current_range = next_range.clone();
            }
        }
        merged.push(current_range);

        *ranges = merged;
    }

    /// Remove completed reassembly context
    pub fn remove_context(&self, reassembly_key: &ReassemblyKey) {
        let mut ranges = self
            .fragment_ranges
            .write()
            .unwrap_or_else(|e| e.into_inner());
        ranges.remove(reassembly_key);

        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.active_contexts = ranges.len();
    }

    /// Clean up expired contexts
    pub fn cleanup_expired_contexts(&self) {
        let timeout = Duration::from_secs(self.config.context_timeout_sec);
        let now = SystemTime::now();

        let mut ranges = self
            .fragment_ranges
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let initial_count = ranges.len();

        ranges.retain(|_, tracker| {
            now.duration_since(tracker.last_update).unwrap_or_default() < timeout
        });

        let expired_count = initial_count - ranges.len();

        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.active_contexts = ranges.len();
        stats.contexts_expired += expired_count as u64;
    }

    /// Get fragment coverage for a reassembly context
    pub fn get_fragment_coverage(
        &self,
        reassembly_key: &ReassemblyKey,
    ) -> Option<FragmentCoverage> {
        let ranges = self
            .fragment_ranges
            .read()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(tracker) = ranges.get(reassembly_key) {
            let mut covered_ranges = tracker.ranges.clone();
            covered_ranges.sort_by_key(|r| r.start_offset);

            let total_expected = tracker.fragment_count.unwrap_or(0) as usize;
            let received_fragments = covered_ranges.len();

            // Calculate coverage gaps
            let mut gaps = Vec::new();
            let mut expected_offset = StartOffset::new(0);

            for range in &covered_ranges {
                if range.start_offset > expected_offset {
                    gaps.push(CoverageGap {
                        start_offset: expected_offset.as_usize(),
                        end_offset: range.start_offset.as_usize(),
                        size: range.start_offset.as_usize() - expected_offset.as_usize(),
                    });
                }
                expected_offset = StartOffset::new(range.end_offset.as_usize());
            }

            let is_complete = received_fragments == total_expected && gaps.is_empty();
            Some(FragmentCoverage {
                total_expected_fragments: total_expected,
                received_fragments,
                covered_ranges,
                gaps,
                is_complete,
            })
        } else {
            None
        }
    }

    /// Get overlap detection statistics
    pub fn get_stats(&self) -> OverlapStats {
        self.stats.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        *stats = OverlapStats {
            total_checked: PacketCount::new(0),
            overlaps_detected: PacketCount::new(0),
            adjacent_detected: PacketCount::new(0),
            duplicates_detected: PacketCount::new(0),
            active_contexts: stats.active_contexts, // Keep current active count
            contexts_expired: PacketCount::new(0),
        };
    }
}

impl Default for OverlapDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Fragment coverage information
#[derive(Debug, Clone)]
pub struct FragmentCoverage {
    /// Total expected fragments
    pub total_expected_fragments: usize,
    /// Number of received fragments
    pub received_fragments: usize,
    /// Covered ranges
    pub covered_ranges: Vec<FragmentRange>,
    /// Coverage gaps
    pub gaps: Vec<CoverageGap>,
    /// Whether coverage is complete
    pub is_complete: bool,
}

/// Coverage gap information
#[derive(Debug, Clone)]
pub struct CoverageGap {
    /// Start offset of the gap
    pub start_offset: usize,
    /// End offset of the gap
    pub end_offset: usize,
    /// Size of the gap
    pub size: usize,
}
