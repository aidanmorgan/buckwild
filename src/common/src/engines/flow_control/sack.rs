// SACK (Selective Acknowledgment) Engine
//
// Implements selective acknowledgment using bitmaps and ranges for efficient
// recovery from packet loss following design/protocol/07-data-transmission.md
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::ProtocolError;
use crate::protocol::packet::SackData;
use crate::protocol::types::*;
use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, RwLock};

/// SACK Engine for selective acknowledgment processing
pub struct SackEngine {
    /// Set of received out-of-order sequence numbers
    received_sequences: Arc<RwLock<BTreeSet<u32>>>,
    /// Statistics for SACK operations
    stats: Arc<RwLock<SackStats>>,
}

impl SackEngine {
    /// Create a new SACK engine
    pub fn new() -> Self {
        Self {
            received_sequences: Arc::new(RwLock::new(BTreeSet::new())),
            stats: Arc::new(RwLock::new(SackStats::default())),
        }
    }

    /// Build a 32-bit SACK bitmap for packets after receive_next
    ///
    /// The bitmap represents the next 32 packets after receive_next:
    /// - Bit 0 represents receive_next + 1
    /// - Bit 31 represents receive_next + 32
    pub fn build_sack_bitmap(&self, receive_next: SequenceNumber) -> SackBitmap {
        // Recover from poisoned RwLock - data is still readable
        let sequences = self
            .received_sequences
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut bitmap: u32 = 0;
        let base = receive_next.as_u32();

        // Check each of the next 32 sequence numbers
        for i in 0..32 {
            let seq_to_check = base.wrapping_add(i + 1);
            if sequences.contains(&seq_to_check) {
                bitmap |= 1 << i;
            }
        }

        // Update stats
        if bitmap != 0 {
            // Recover from poisoned RwLock - stats can still be updated
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.sack_blocks_sent += 1;
        }

        SackBitmap::new(bitmap)
    }

    /// Build SACK ranges for out-of-order received packets
    ///
    /// Scans the received sequences and groups contiguous ranges
    pub fn build_sack_ranges(&self, _receive_next: SequenceNumber) -> Vec<SackRange> {
        // Recover from poisoned RwLock - data is still readable
        let sequences = self
            .received_sequences
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut ranges = Vec::new();

        if sequences.is_empty() {
            return ranges;
        }

        let mut seq_vec: Vec<u32> = sequences.iter().copied().collect();
        seq_vec.sort_unstable();

        let mut current_start = seq_vec[0];
        let mut current_end = seq_vec[0];

        for &seq in &seq_vec[1..] {
            if seq == current_end.wrapping_add(1) {
                // Contiguous - extend current range
                current_end = seq;
            } else {
                // Gap - save current range and start new one
                ranges.push(SackRange::new(
                    SequenceNumber::new(current_start),
                    SequenceNumber::new(current_end.wrapping_add(1)), // end is exclusive
                ));
                current_start = seq;
                current_end = seq;
            }
        }

        // Add final range
        ranges.push(SackRange::new(
            SequenceNumber::new(current_start),
            SequenceNumber::new(current_end.wrapping_add(1)),
        ));

        // Update stats
        if !ranges.is_empty() {
            // Recover from poisoned RwLock - stats can still be updated
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.sack_blocks_sent += ranges.len() as u64;
        }

        ranges
    }

    /// Mark a sequence number as received (for out-of-order reception)
    pub fn mark_sequence_received(&self, sequence: SequenceNumber) {
        // Recover from poisoned RwLock - data can still be updated
        let mut sequences = self
            .received_sequences
            .write()
            .unwrap_or_else(|e| e.into_inner());
        sequences.insert(sequence.as_u32());
    }

    /// Process SACK bitmap from received ACK packet
    ///
    /// Returns a set of acknowledged sequence numbers
    pub fn process_sack_bitmap(
        &self,
        bitmap: SackBitmap,
        base_sequence: SequenceNumber,
    ) -> Result<HashSet<SequenceNumber>, ProtocolError> {
        let mut acked_sequences = HashSet::new();
        let bitmap_val = bitmap.as_u32();
        let base = base_sequence.as_u32();

        // Process each bit in the bitmap
        for i in 0..32 {
            if (bitmap_val & (1 << i)) != 0 {
                let acked_seq = base.wrapping_add(i + 1);
                acked_sequences.insert(SequenceNumber::new(acked_seq));
            }
        }

        // Update stats
        if !acked_sequences.is_empty() {
            // Recover from poisoned RwLock - stats can still be updated
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.sack_blocks_received += 1;
        }

        Ok(acked_sequences)
    }

    /// Process SACK ranges from received ACK packet
    ///
    /// Returns a set of acknowledged sequence numbers
    pub fn process_sack_ranges(
        &self,
        ranges: &[SackRange],
    ) -> Result<HashSet<SequenceNumber>, ProtocolError> {
        let mut acked_sequences = HashSet::new();

        for range in ranges {
            let start = range.start_seq.as_u32();
            let end = range.end_seq.as_u32();

            // Handle potential wraparound
            if end > start {
                for seq in start..end {
                    acked_sequences.insert(SequenceNumber::new(seq));
                }
            } else {
                // Wraparound case
                for seq in start..=u32::MAX {
                    acked_sequences.insert(SequenceNumber::new(seq));
                }
                for seq in 0..end {
                    acked_sequences.insert(SequenceNumber::new(seq));
                }
            }
        }

        // Update stats
        if !ranges.is_empty() {
            // Recover from poisoned RwLock - stats can still be updated
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.sack_blocks_received += ranges.len() as u64;
        }

        Ok(acked_sequences)
    }

    /// Process complete SACK data (bitmap + ranges)
    ///
    /// Returns all acknowledged sequence numbers from both bitmap and ranges
    pub fn process_sack_data(
        &self,
        sack_data: &SackData,
        base_sequence: SequenceNumber,
    ) -> Result<HashSet<SequenceNumber>, ProtocolError> {
        let mut all_acked = HashSet::new();

        // Process bitmap
        let bitmap_acked = self.process_sack_bitmap(sack_data.primary_bitmap, base_sequence)?;
        all_acked.extend(bitmap_acked);

        // Process ranges
        let ranges_acked = self.process_sack_ranges(&sack_data.additional_ranges)?;
        all_acked.extend(ranges_acked);

        Ok(all_acked)
    }

    /// Identify missing segments based on SACK data
    ///
    /// Returns sequence numbers that need retransmission
    pub fn identify_missing_segments(
        &self,
        base_sequence: SequenceNumber,
        highest_sent: SequenceNumber,
        sack_data: Option<&SackData>,
    ) -> Vec<SequenceNumber> {
        let base = base_sequence.as_u32();
        let highest = highest_sent.as_u32();

        // Determine the range to check
        let count = if highest >= base {
            highest - base
        } else {
            // Wraparound case
            (u32::MAX - base) + highest + 1
        };

        let mut missing = Vec::new();

        // Get acknowledged sequences from SACK data
        let acked = if let Some(sack) = sack_data {
            self.process_sack_data(sack, base_sequence)
                .unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Check each sequence in the range
        for i in 0..count {
            let seq = base.wrapping_add(i);
            let seq_num = SequenceNumber::new(seq);

            // If not acknowledged, it's missing
            if !acked.contains(&seq_num) {
                missing.push(seq_num);
            }
        }

        missing
    }

    /// Clear acknowledged sequences up to (and including) the given sequence number
    pub fn clear_acknowledged_sequences(&self, up_to: SequenceNumber) {
        // Recover from poisoned RwLock - data can still be updated
        let mut sequences = self
            .received_sequences
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let threshold = up_to.as_u32();

        // Remove all sequences <= threshold
        sequences.retain(|&seq| seq > threshold);
    }

    /// Get SACK statistics
    pub fn get_stats(&self) -> SackStats {
        // Recover from poisoned RwLock - stats are still readable
        self.stats.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Default for SackEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for SACK operations
#[derive(Debug, Clone, Default)]
pub struct SackStats {
    /// Number of SACK blocks sent
    pub sack_blocks_sent: u64,
    /// Number of SACK blocks received
    pub sack_blocks_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sack_engine_creation() {
        let engine = SackEngine::new();
        assert_eq!(engine.get_stats().sack_blocks_sent, 0);
    }

    #[test]
    fn test_mark_and_check_sequence() {
        let engine = SackEngine::new();
        engine.mark_sequence_received(SequenceNumber::new(42));

        let bitmap = engine.build_sack_bitmap(SequenceNumber::new(40));
        // Sequence 42 is base(40) + 2, so bit 1 should be set
        assert_ne!(bitmap.as_u32(), 0);
    }
}
