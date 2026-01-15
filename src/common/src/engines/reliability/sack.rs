// Selective Acknowledgment (SACK) processing
//
// Implements SACK-style acknowledgments to identify specific packets
// received out of order, enabling selective retransmission.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::*;
use std::collections::BTreeSet;

/// Maximum number of SACK blocks per acknowledgment
const MAX_SACK_BLOCKS: usize = 4;

/// Selective acknowledgment block identifying a range of received packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SackBlock {
    /// Start of acknowledged sequence range (inclusive)
    pub start: SequenceNumber,

    /// End of acknowledged sequence range (exclusive)
    pub end: SequenceNumber,
}

impl SackBlock {
    /// Create new SACK block
    pub fn new(start: SequenceNumber, end: SequenceNumber) -> Self {
        Self { start, end }
    }

    /// Check if this block contains a sequence number
    pub fn contains(&self, seq: SequenceNumber) -> bool {
        seq.as_u32() >= self.start.as_u32() && seq.as_u32() < self.end.as_u32()
    }

    /// Get the number of sequence numbers in this block
    pub fn len(&self) -> u32 {
        self.end.as_u32().saturating_sub(self.start.as_u32())
    }

    /// Check if block is empty
    pub fn is_empty(&self) -> bool {
        self.start.as_u32() >= self.end.as_u32()
    }

    /// Try to merge two adjacent or overlapping blocks
    ///
    /// Returns merged block if possible, None otherwise
    pub fn try_merge(&self, other: &SackBlock) -> Option<SackBlock> {
        // Check for overlap or adjacency
        if self.end.as_u32() >= other.start.as_u32() && other.end.as_u32() >= self.start.as_u32() {
            let new_start = if self.start.as_u32() < other.start.as_u32() {
                self.start
            } else {
                other.start
            };
            let new_end = if self.end.as_u32() > other.end.as_u32() {
                self.end
            } else {
                other.end
            };
            Some(SackBlock::new(new_start, new_end))
        } else {
            None
        }
    }

    /// Serialize block to bytes (8 bytes: 4 for start, 4 for end)
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.start.as_u32().to_be_bytes());
        bytes[4..8].copy_from_slice(&self.end.as_u32().to_be_bytes());
        bytes
    }

    /// Deserialize block from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }

        let start = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let end = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Some(SackBlock::new(
            SequenceNumber::new(start),
            SequenceNumber::new(end),
        ))
    }
}

/// SACK processor for managing selective acknowledgments
#[derive(Debug)]
pub struct SackProcessor {
    /// Received sequence numbers waiting to be acknowledged
    received_sequences: BTreeSet<u32>,

    /// Current cumulative ACK (highest in-order sequence)
    cumulative_ack: SequenceNumber,
}

impl SackProcessor {
    /// Create new SACK processor
    pub fn new(initial_ack: SequenceNumber) -> Self {
        Self {
            received_sequences: BTreeSet::new(),
            cumulative_ack: initial_ack,
        }
    }

    /// Record receipt of a sequence number
    ///
    /// Returns true if this advances the cumulative ACK
    pub fn record_received(&mut self, seq: SequenceNumber) -> bool {
        let seq_value = seq.as_u32();

        // Check if this is the next expected sequence
        if seq_value == self.cumulative_ack.as_u32() {
            // Advance cumulative ACK
            self.cumulative_ack = SequenceNumber::new(seq_value + 1);

            // Check if we can advance further with buffered sequences
            while self
                .received_sequences
                .remove(&self.cumulative_ack.as_u32())
            {
                self.cumulative_ack = SequenceNumber::new(self.cumulative_ack.as_u32() + 1);
            }

            return true;
        }

        // Out-of-order packet - add to received set
        if seq_value > self.cumulative_ack.as_u32() {
            self.received_sequences.insert(seq_value);
        }

        false
    }

    /// Generate SACK blocks for out-of-order received packets
    ///
    /// Returns up to MAX_SACK_BLOCKS blocks
    pub fn generate_sack_blocks(&self) -> Vec<SackBlock> {
        let mut blocks = Vec::new();

        if self.received_sequences.is_empty() {
            return blocks;
        }

        let mut current_start: Option<u32> = None;
        let mut current_end: Option<u32> = None;

        for &seq in &self.received_sequences {
            match (current_start, current_end) {
                (None, None) => {
                    // Start new block
                    current_start = Some(seq);
                    current_end = Some(seq + 1);
                }
                (Some(start), Some(end)) => {
                    if seq == end {
                        // Extend current block
                        current_end = Some(seq + 1);
                    } else {
                        // Finish current block and start new one
                        blocks.push(SackBlock::new(
                            SequenceNumber::new(start),
                            SequenceNumber::new(end),
                        ));

                        if blocks.len() >= MAX_SACK_BLOCKS {
                            break;
                        }

                        current_start = Some(seq);
                        current_end = Some(seq + 1);
                    }
                }
                _ => {}
            }
        }

        // Add final block if exists
        if let (Some(start), Some(end)) = (current_start, current_end) {
            if blocks.len() < MAX_SACK_BLOCKS {
                blocks.push(SackBlock::new(
                    SequenceNumber::new(start),
                    SequenceNumber::new(end),
                ));
            }
        }

        blocks
    }

    /// Process received SACK blocks to identify missing packets
    ///
    /// Returns sequence numbers that need retransmission
    pub fn identify_missing_packets(
        &self,
        sack_blocks: &[SackBlock],
        send_unacked: SequenceNumber,
        send_next: SequenceNumber,
    ) -> Vec<SequenceNumber> {
        let mut missing = Vec::new();

        // Check all sequences in the send window
        for seq in send_unacked.as_u32()..send_next.as_u32() {
            let seq_num = SequenceNumber::new(seq);

            // Check if this sequence is NOT in any SACK block
            let acknowledged = sack_blocks.iter().any(|block| block.contains(seq_num));

            if !acknowledged {
                missing.push(seq_num);
            }
        }

        missing
    }

    /// Get current cumulative ACK value
    pub fn cumulative_ack(&self) -> SequenceNumber {
        self.cumulative_ack
    }

    /// Get count of out-of-order sequences
    pub fn out_of_order_count(&self) -> usize {
        self.received_sequences.len()
    }

    /// Reset state (for connection reset)
    pub fn reset(&mut self, initial_ack: SequenceNumber) {
        self.received_sequences.clear();
        self.cumulative_ack = initial_ack;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sack_block_contains() {
        let block = SackBlock::new(SequenceNumber::new(100), SequenceNumber::new(110));

        assert!(block.contains(SequenceNumber::new(100)));
        assert!(block.contains(SequenceNumber::new(105)));
        assert!(block.contains(SequenceNumber::new(109)));
        assert!(!block.contains(SequenceNumber::new(110)));
        assert!(!block.contains(SequenceNumber::new(99)));
    }

    #[test]
    fn test_sack_block_merge() {
        let block1 = SackBlock::new(SequenceNumber::new(100), SequenceNumber::new(110));
        let block2 = SackBlock::new(SequenceNumber::new(110), SequenceNumber::new(120));

        let merged = block1.try_merge(&block2);
        assert!(merged.is_some());
        assert_eq!(merged.map(|b| b.start.as_u32()), Some(100));
        assert_eq!(merged.map(|b| b.end.as_u32()), Some(120));
    }

    #[test]
    fn test_sack_block_serialization() {
        let block = SackBlock::new(SequenceNumber::new(1000), SequenceNumber::new(2000));
        let bytes = block.to_bytes();
        let decoded = SackBlock::from_bytes(&bytes);

        assert!(decoded.is_some());
        assert_eq!(decoded.map(|b| b.start.as_u32()), Some(1000));
        assert_eq!(decoded.map(|b| b.end.as_u32()), Some(2000));
    }

    #[test]
    fn test_sack_processor_in_order() {
        let mut processor = SackProcessor::new(SequenceNumber::new(1000));

        // Receive in-order packet
        let advanced = processor.record_received(SequenceNumber::new(1000));
        assert!(advanced);
        assert_eq!(processor.cumulative_ack().as_u32(), 1001);

        // No SACK blocks needed
        let blocks = processor.generate_sack_blocks();
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_sack_processor_out_of_order() {
        let mut processor = SackProcessor::new(SequenceNumber::new(1000));

        // Receive out-of-order packets
        processor.record_received(SequenceNumber::new(1002));
        processor.record_received(SequenceNumber::new(1003));
        processor.record_received(SequenceNumber::new(1005));

        assert_eq!(processor.cumulative_ack().as_u32(), 1000);
        assert_eq!(processor.out_of_order_count(), 3);

        // Generate SACK blocks
        let blocks = processor.generate_sack_blocks();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].start.as_u32(), 1002);
        assert_eq!(blocks[0].end.as_u32(), 1004);
        assert_eq!(blocks[1].start.as_u32(), 1005);
        assert_eq!(blocks[1].end.as_u32(), 1006);
    }

    #[test]
    fn test_sack_processor_fill_gap() {
        let mut processor = SackProcessor::new(SequenceNumber::new(1000));

        // Receive out-of-order
        processor.record_received(SequenceNumber::new(1002));
        processor.record_received(SequenceNumber::new(1003));

        // Fill the gap
        let advanced = processor.record_received(SequenceNumber::new(1000));
        assert!(advanced);

        processor.record_received(SequenceNumber::new(1001));
        assert_eq!(processor.cumulative_ack().as_u32(), 1004);
        assert_eq!(processor.out_of_order_count(), 0);
    }

    #[test]
    fn test_identify_missing_packets() {
        let processor = SackProcessor::new(SequenceNumber::new(1000));

        let sack_blocks = vec![
            SackBlock::new(SequenceNumber::new(1002), SequenceNumber::new(1004)),
            SackBlock::new(SequenceNumber::new(1006), SequenceNumber::new(1008)),
        ];

        let missing = processor.identify_missing_packets(
            &sack_blocks,
            SequenceNumber::new(1000),
            SequenceNumber::new(1010),
        );

        assert_eq!(missing.len(), 6);
        assert!(missing.contains(&SequenceNumber::new(1000)));
        assert!(missing.contains(&SequenceNumber::new(1001)));
        assert!(missing.contains(&SequenceNumber::new(1004)));
        assert!(missing.contains(&SequenceNumber::new(1005)));
        assert!(missing.contains(&SequenceNumber::new(1008)));
        assert!(missing.contains(&SequenceNumber::new(1009)));
    }
}
