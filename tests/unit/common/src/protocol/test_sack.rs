// Selective Acknowledgment (SACK) Tests
// Tests for SACK implementation as defined in design/protocol/07-data-transmission.md

/// SACK block representing a contiguous range of received packets
#[derive(Debug, Clone, PartialEq, Eq)]
struct SackBlock {
    start_seq: u32,
    end_seq: u32,
}

/// SACK information structure
#[derive(Debug, Clone)]
struct SackInfo {
    /// Primary SACK bitmap (32 bits for first 32 packets after base_seq)
    bitmap: u32,
    /// Extended SACK ranges for complex loss patterns
    ranges: Vec<SackBlock>,
    /// Base sequence number that SACK is relative to
    base_seq: u32,
}

impl SackInfo {
    fn new(base_seq: u32) -> Self {
        Self {
            bitmap: 0,
            ranges: Vec::new(),
            base_seq,
        }
    }

    /// Build SACK bitmap from received packets
    fn build_bitmap(&mut self, received_packets: &[u32]) {
        self.bitmap = 0;

        for &seq in received_packets {
            if seq > self.base_seq {
                let offset = seq - self.base_seq - 1;
                if offset < 32 {
                    self.bitmap |= 1 << offset;
                }
            }
        }
    }

    /// Build extended SACK ranges for packets beyond the first 32
    fn build_ranges(&mut self, received_packets: &[u32]) {
        self.ranges.clear();

        // Find all contiguous ranges
        let mut sorted_packets: Vec<u32> = received_packets
            .iter()
            .filter(|&&seq| seq > self.base_seq + 32)
            .copied()
            .collect();
        sorted_packets.sort_unstable();

        if sorted_packets.is_empty() {
            return;
        }

        let mut range_start = sorted_packets[0];
        let mut range_end = sorted_packets[0];

        for &seq in sorted_packets.iter().skip(1) {
            if seq == range_end + 1 {
                // Continue current range
                range_end = seq;
            } else {
                // Start new range
                self.ranges.push(SackBlock {
                    start_seq: range_start,
                    end_seq: range_end,
                });
                range_start = seq;
                range_end = seq;
            }
        }

        // Add final range
        self.ranges.push(SackBlock {
            start_seq: range_start,
            end_seq: range_end,
        });
    }

    /// Check if a sequence number is acknowledged in SACK
    fn is_acked(&self, seq: u32) -> bool {
        // Check bitmap first
        if seq > self.base_seq && seq <= self.base_seq + 32 {
            let offset = seq - self.base_seq - 1;
            if (self.bitmap & (1 << offset)) != 0 {
                return true;
            }
        }

        // Check extended ranges
        for range in &self.ranges {
            if seq >= range.start_seq && seq <= range.end_seq {
                return true;
            }
        }

        false
    }

    /// Get missing sequence numbers (gaps in SACK)
    fn get_missing_sequences(&self, max_seq: u32) -> Vec<u32> {
        let mut missing = Vec::new();

        // Check bitmap range
        for seq in (self.base_seq + 1)..=std::cmp::min(self.base_seq + 32, max_seq) {
            if !self.is_acked(seq) {
                missing.push(seq);
            }
        }

        // Check extended range
        if max_seq > self.base_seq + 32 {
            let mut current_seq = self.base_seq + 33;

            for range in &self.ranges {
                // Add missing packets before this range
                while current_seq < range.start_seq && current_seq <= max_seq {
                    missing.push(current_seq);
                    current_seq += 1;
                }

                // Skip the range
                current_seq = range.end_seq + 1;
            }

            // Add remaining missing packets after last range
            while current_seq <= max_seq {
                missing.push(current_seq);
                current_seq += 1;
            }
        }

        missing
    }
}

#[test]
fn test_build_sack_bitmap_for_gaps() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received packets: 102, 103, 105, 107 (missing 101, 104, 106)
    let received = vec![102, 103, 105, 107];
    sack.build_bitmap(&received);

    // Bitmap should have bits set for: 102 (offset 1), 103 (offset 2), 105 (offset 4), 107 (offset 6)
    // Expected bitmap: 0b01010110 = 0x56
    assert_eq!(sack.bitmap & 0b01010110, 0b01010110);

    // Verify specific packets are acknowledged
    assert!(sack.is_acked(102));
    assert!(sack.is_acked(103));
    assert!(sack.is_acked(105));
    assert!(sack.is_acked(107));

    // Verify missing packets are NOT acknowledged
    assert!(!sack.is_acked(101));
    assert!(!sack.is_acked(104));
    assert!(!sack.is_acked(106));
}

#[test]
fn test_build_sack_ranges_complex_loss() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received packets with large gaps (beyond first 32)
    let received = vec![
        135, 136, 137, // Range 1: 135-137
        140, 141,      // Range 2: 140-141
        150,           // Range 3: 150
        160, 161, 162, 163, // Range 4: 160-163
    ];
    sack.build_ranges(&received);

    // Should have 4 ranges
    assert_eq!(sack.ranges.len(), 4);

    // Verify ranges
    assert_eq!(sack.ranges[0], SackBlock { start_seq: 135, end_seq: 137 });
    assert_eq!(sack.ranges[1], SackBlock { start_seq: 140, end_seq: 141 });
    assert_eq!(sack.ranges[2], SackBlock { start_seq: 150, end_seq: 150 });
    assert_eq!(sack.ranges[3], SackBlock { start_seq: 160, end_seq: 163 });
}

#[test]
fn test_process_sack_bitmap_retransmit() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Simulate: sent 101-110, received 102, 103, 105, 108, 109, 110
    let received = vec![102, 103, 105, 108, 109, 110];
    sack.build_bitmap(&received);

    // Get missing sequences (packets to retransmit)
    let missing = sack.get_missing_sequences(110);

    // Should identify: 101, 104, 106, 107
    assert_eq!(missing, vec![101, 104, 106, 107]);
}

#[test]
fn test_sack_block_count_validation() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Build ranges with many blocks
    let mut received = Vec::new();
    for i in 0..10 {
        // Create 10 separate ranges with gaps
        let start = 150 + (i * 10);
        received.push(start);
        received.push(start + 1);
    }

    sack.build_ranges(&received);

    // Should have 10 SACK blocks
    assert_eq!(sack.ranges.len(), 10);

    // Verify all ranges are present
    for i in 0..10 {
        let expected_start = (150 + (i * 10)) as u32;
        assert_eq!(sack.ranges[i].start_seq, expected_start);
        assert_eq!(sack.ranges[i].end_seq, expected_start + 1);
    }
}

#[test]
fn test_sack_range_boundaries() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Test boundary at exactly 32 packets offset
    let received = vec![132, 133]; // Exactly at bitmap boundary (offset 31, 32)
    sack.build_bitmap(&received);
    sack.build_ranges(&received);

    // 132 should be in bitmap (offset 31)
    assert!(sack.is_acked(132));

    // 133 is beyond bitmap (should be in ranges if > 132)
    assert!(sack.is_acked(133));
}

#[test]
fn test_sack_with_wraparound_sequence() {
    // Test SACK near sequence number wraparound
    let base_seq = u32::MAX - 10;
    let mut sack = SackInfo::new(base_seq);

    // This test verifies behavior near wraparound but doesn't cross it
    // (full wraparound handling would require modular arithmetic)
    let received = vec![
        base_seq + 2,
        base_seq + 3,
        base_seq + 5,
    ];
    sack.build_bitmap(&received);

    assert!(sack.is_acked(base_seq + 2));
    assert!(sack.is_acked(base_seq + 3));
    assert!(!sack.is_acked(base_seq + 4));
    assert!(sack.is_acked(base_seq + 5));
}

#[test]
fn test_sack_empty_bitmap() {
    let base_seq = 100;
    let sack = SackInfo::new(base_seq);

    // No packets received, bitmap should be empty
    assert_eq!(sack.bitmap, 0);
    assert!(sack.ranges.is_empty());

    // Nothing should be acknowledged
    assert!(!sack.is_acked(101));
    assert!(!sack.is_acked(105));
    assert!(!sack.is_acked(110));
}

#[test]
fn test_sack_all_packets_received() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received all packets from 101 to 132
    let received: Vec<u32> = (101..=132).collect();
    sack.build_bitmap(&received);

    // Bitmap should be all ones (0xFFFFFFFF)
    assert_eq!(sack.bitmap, 0xFFFFFFFF);

    // All packets should be acknowledged
    for seq in 101..=132 {
        assert!(sack.is_acked(seq), "Sequence {} should be acked", seq);
    }

    // Missing sequences should be empty
    let missing = sack.get_missing_sequences(132);
    assert!(missing.is_empty());
}

#[test]
fn test_sack_single_packet_gap() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received all packets except 105
    let mut received: Vec<u32> = (101..=110).collect();
    received.retain(|&x| x != 105);
    sack.build_bitmap(&received);

    // 105 should not be acknowledged
    assert!(!sack.is_acked(105));

    // All others should be acknowledged
    for seq in 101..=110 {
        if seq != 105 {
            assert!(sack.is_acked(seq));
        }
    }

    // Missing sequences should only contain 105
    let missing = sack.get_missing_sequences(110);
    assert_eq!(missing, vec![105]);
}

#[test]
fn test_sack_multiple_gaps() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received: 101-102, 105-107, 110-112 (gaps at 103-104, 108-109)
    let received = vec![101, 102, 105, 106, 107, 110, 111, 112];
    sack.build_bitmap(&received);

    // Verify gaps
    let missing = sack.get_missing_sequences(112);
    assert_eq!(missing, vec![103, 104, 108, 109]);

    // Verify received packets are acknowledged
    for &seq in &received {
        assert!(sack.is_acked(seq));
    }
}

#[test]
fn test_sack_performance_large_gaps() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Simulate large loss: only received every 10th packet
    let mut received = Vec::new();
    for i in 0..100 {
        if i % 10 == 0 {
            received.push(base_seq + i + 1);
        }
    }

    sack.build_bitmap(&received);
    sack.build_ranges(&received);

    // Verify all received packets are acknowledged
    for &seq in &received {
        assert!(sack.is_acked(seq), "Sequence {} should be acked", seq);
    }

    // Verify missing packets
    let missing = sack.get_missing_sequences(base_seq + 100);
    assert_eq!(missing.len(), 90); // 100 total - 10 received = 90 missing
}

#[test]
fn test_sack_extended_ranges_sorting() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received packets out of order (beyond bitmap range)
    let received = vec![160, 140, 150, 135, 161, 141, 151, 136];
    sack.build_ranges(&received);

    // Ranges should be sorted and merged
    // Expected: 135-136, 140-141, 150-151, 160-161
    assert_eq!(sack.ranges.len(), 4);
    assert_eq!(sack.ranges[0], SackBlock { start_seq: 135, end_seq: 136 });
    assert_eq!(sack.ranges[1], SackBlock { start_seq: 140, end_seq: 141 });
    assert_eq!(sack.ranges[2], SackBlock { start_seq: 150, end_seq: 151 });
    assert_eq!(sack.ranges[3], SackBlock { start_seq: 160, end_seq: 161 });
}

#[test]
fn test_sack_bitmap_and_ranges_combined() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Received packets in both bitmap range and extended range
    let received = vec![
        102, 103, 105, // In bitmap (101-132)
        140, 141, 142, // In extended range
    ];

    sack.build_bitmap(&received);
    sack.build_ranges(&received);

    // Verify bitmap packets
    assert!(sack.is_acked(102));
    assert!(sack.is_acked(103));
    assert!(!sack.is_acked(104)); // Gap
    assert!(sack.is_acked(105));

    // Verify extended range packets
    assert!(sack.is_acked(140));
    assert!(sack.is_acked(141));
    assert!(sack.is_acked(142));

    // Verify missing sequences
    let missing = sack.get_missing_sequences(142);
    // Should include: 101, 104, and all from 106-139 except acknowledged ones
    assert!(missing.contains(&101));
    assert!(missing.contains(&104));
    assert!(missing.contains(&110));
    assert!(missing.contains(&139));
}

#[test]
fn test_sack_retransmit_decision() {
    let base_seq = 100;
    let mut sack = SackInfo::new(base_seq);

    // Sender has sent 101-110
    // Receiver got 102, 103, 105, 108, 109, 110
    let received = vec![102, 103, 105, 108, 109, 110];
    sack.build_bitmap(&received);

    // Sender should retransmit: 101, 104, 106, 107
    let to_retransmit = sack.get_missing_sequences(110);

    assert_eq!(to_retransmit.len(), 4);
    assert!(to_retransmit.contains(&101));
    assert!(to_retransmit.contains(&104));
    assert!(to_retransmit.contains(&106));
    assert!(to_retransmit.contains(&107));

    // Sender should NOT retransmit already acked packets
    assert!(!to_retransmit.contains(&102));
    assert!(!to_retransmit.contains(&103));
    assert!(!to_retransmit.contains(&105));
}
