// SACK (Selective Acknowledgment) Tests
//
// Tests verify bitmap generation, range building, and SACK processing
// following design/protocol/07-data-transmission.md
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::sack::*;
use crate::protocol::packet::SackData;
use crate::protocol::types::*;

// =============================================================================
// SACK Engine Initialization Tests
// =============================================================================

#[test]
fn test_sack_engine_initialization() {
    let engine = SackEngine::new();

    let stats = engine.get_stats();
    assert_eq!(
        stats.sack_blocks_sent, 0,
        "Should start with zero SACK blocks sent"
    );
    assert_eq!(
        stats.sack_blocks_received, 0,
        "Should start with zero SACK blocks received"
    );
}

// =============================================================================
// SACK Bitmap Generation Tests
// =============================================================================

#[test]
fn test_build_sack_bitmap_empty() {
    let engine = SackEngine::new();

    // No out-of-order packets received
    let bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));

    assert_eq!(
        bitmap.as_u32(),
        0,
        "Bitmap should be empty when no out-of-order packets"
    );
}

#[test]
fn test_build_sack_bitmap_single_packet() {
    let engine = SackEngine::new();

    // Mark sequence 102 as received (skip 101)
    engine.mark_sequence_received(SequenceNumber::new(102));

    // Build bitmap with base=100 (receive_next=100, so checking 101-132)
    let bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));

    // Bit 1 should be set (sequence 102 = base + 1 + 1)
    assert_eq!(
        bitmap.as_u32(),
        1 << 1,
        "Bit 1 should be set for sequence 102"
    );
}

#[test]
fn test_build_sack_bitmap_multiple_packets() {
    let engine = SackEngine::new();

    // Mark multiple out-of-order sequences as received
    engine.mark_sequence_received(SequenceNumber::new(102)); // bit 1
    engine.mark_sequence_received(SequenceNumber::new(103)); // bit 2
    engine.mark_sequence_received(SequenceNumber::new(105)); // bit 4

    let bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));

    // Bits 1, 2, and 4 should be set
    let expected = (1 << 1) | (1 << 2) | (1 << 4);
    assert_eq!(bitmap.as_u32(), expected, "Bits 1, 2, 4 should be set");
}

#[test]
fn test_build_sack_bitmap_32_bit_coverage() {
    let engine = SackEngine::new();

    // Mark sequences throughout the 32-bit range
    engine.mark_sequence_received(SequenceNumber::new(101)); // bit 0
    engine.mark_sequence_received(SequenceNumber::new(115)); // bit 14
    engine.mark_sequence_received(SequenceNumber::new(132)); // bit 31

    let bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));

    let expected = (1 << 0) | (1 << 14) | (1 << 31);
    assert_eq!(bitmap.as_u32(), expected, "Bits 0, 14, 31 should be set");
}

#[test]
fn test_build_sack_bitmap_ignores_beyond_32() {
    let engine = SackEngine::new();

    // Mark sequence beyond 32-bit range
    engine.mark_sequence_received(SequenceNumber::new(150)); // Beyond bit 31

    let bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));

    assert_eq!(
        bitmap.as_u32(),
        0,
        "Should not include sequences beyond 32-bit range"
    );
}

// =============================================================================
// SACK Range Building Tests
// =============================================================================

#[test]
fn test_build_sack_ranges_empty() {
    let engine = SackEngine::new();

    let ranges = engine.build_sack_ranges(SequenceNumber::new(100));

    assert_eq!(
        ranges.len(),
        0,
        "Should have no ranges when no out-of-order packets"
    );
}

#[test]
fn test_build_sack_ranges_single_packet() {
    let engine = SackEngine::new();

    // Mark single packet as received
    engine.mark_sequence_received(SequenceNumber::new(105));

    let ranges = engine.build_sack_ranges(SequenceNumber::new(100));

    assert_eq!(ranges.len(), 1, "Should have one range");
    assert_eq!(ranges[0].start_seq, SequenceNumber::new(105));
    assert_eq!(ranges[0].end_seq, SequenceNumber::new(106)); // end is exclusive
}

#[test]
fn test_build_sack_ranges_contiguous_packets() {
    let engine = SackEngine::new();

    // Mark contiguous packets as received
    engine.mark_sequence_received(SequenceNumber::new(105));
    engine.mark_sequence_received(SequenceNumber::new(106));
    engine.mark_sequence_received(SequenceNumber::new(107));

    let ranges = engine.build_sack_ranges(SequenceNumber::new(100));

    assert_eq!(
        ranges.len(),
        1,
        "Contiguous packets should form single range"
    );
    assert_eq!(ranges[0].start_seq, SequenceNumber::new(105));
    assert_eq!(ranges[0].end_seq, SequenceNumber::new(108)); // end is exclusive
}

#[test]
fn test_build_sack_ranges_multiple_gaps() {
    let engine = SackEngine::new();

    // Mark packets with gaps: 105-107, gap, 110-112, gap, 115
    engine.mark_sequence_received(SequenceNumber::new(105));
    engine.mark_sequence_received(SequenceNumber::new(106));
    engine.mark_sequence_received(SequenceNumber::new(107));
    engine.mark_sequence_received(SequenceNumber::new(110));
    engine.mark_sequence_received(SequenceNumber::new(111));
    engine.mark_sequence_received(SequenceNumber::new(112));
    engine.mark_sequence_received(SequenceNumber::new(115));

    let ranges = engine.build_sack_ranges(SequenceNumber::new(100));

    assert_eq!(ranges.len(), 3, "Should have three separate ranges");

    // First range: 105-108
    assert_eq!(ranges[0].start_seq, SequenceNumber::new(105));
    assert_eq!(ranges[0].end_seq, SequenceNumber::new(108));

    // Second range: 110-113
    assert_eq!(ranges[1].start_seq, SequenceNumber::new(110));
    assert_eq!(ranges[1].end_seq, SequenceNumber::new(113));

    // Third range: 115-116
    assert_eq!(ranges[2].start_seq, SequenceNumber::new(115));
    assert_eq!(ranges[2].end_seq, SequenceNumber::new(116));
}

// =============================================================================
// SACK Processing Tests
// =============================================================================

#[test]
fn test_process_sack_bitmap() {
    let engine = SackEngine::new();

    // Create SACK bitmap: bits 1, 3, 5 set
    let bitmap = SackBitmap::new((1 << 1) | (1 << 3) | (1 << 5));
    let base_seq = SequenceNumber::new(100);

    let result = engine.process_sack_bitmap(bitmap, base_seq);
    assert!(result.is_ok(), "Processing SACK bitmap should succeed");

    // Verify sequences 102, 104, 106 are marked as acknowledged
    let acked_sequences = result.unwrap();
    assert_eq!(
        acked_sequences.len(),
        3,
        "Should have 3 acknowledged sequences"
    );
    assert!(acked_sequences.contains(&SequenceNumber::new(102)));
    assert!(acked_sequences.contains(&SequenceNumber::new(104)));
    assert!(acked_sequences.contains(&SequenceNumber::new(106)));
}

#[test]
fn test_process_sack_ranges() {
    let engine = SackEngine::new();

    // Create SACK ranges
    let ranges = vec![
        SackRange::new(SequenceNumber::new(105), SequenceNumber::new(108)),
        SackRange::new(SequenceNumber::new(110), SequenceNumber::new(113)),
    ];

    let result = engine.process_sack_ranges(&ranges);
    assert!(result.is_ok(), "Processing SACK ranges should succeed");

    // Verify all sequences in ranges are marked as acknowledged
    let acked_sequences = result.unwrap();
    assert_eq!(
        acked_sequences.len(),
        6,
        "Should have 6 acknowledged sequences"
    );

    // First range: 105, 106, 107
    assert!(acked_sequences.contains(&SequenceNumber::new(105)));
    assert!(acked_sequences.contains(&SequenceNumber::new(106)));
    assert!(acked_sequences.contains(&SequenceNumber::new(107)));

    // Second range: 110, 111, 112
    assert!(acked_sequences.contains(&SequenceNumber::new(110)));
    assert!(acked_sequences.contains(&SequenceNumber::new(111)));
    assert!(acked_sequences.contains(&SequenceNumber::new(112)));
}

#[test]
fn test_process_complete_sack_data() {
    let engine = SackEngine::new();

    // Create complete SACK data with both bitmap and ranges
    let bitmap = SackBitmap::new((1 << 1) | (1 << 2));
    let ranges = vec![SackRange::new(
        SequenceNumber::new(110),
        SequenceNumber::new(113),
    )];

    let sack_data = SackData {
        block_count: SackBlockCount::new(1),
        primary_bitmap: bitmap,
        additional_ranges: ranges,
    };

    let result = engine.process_sack_data(&sack_data, SequenceNumber::new(100));
    assert!(
        result.is_ok(),
        "Processing complete SACK data should succeed"
    );

    let acked = result.unwrap();

    // Should have sequences from both bitmap and ranges
    assert!(acked.contains(&SequenceNumber::new(102))); // From bitmap
    assert!(acked.contains(&SequenceNumber::new(103))); // From bitmap
    assert!(acked.contains(&SequenceNumber::new(110))); // From range
    assert!(acked.contains(&SequenceNumber::new(111))); // From range
    assert!(acked.contains(&SequenceNumber::new(112))); // From range
}

// =============================================================================
// Missing Segment Detection Tests
// =============================================================================

#[test]
fn test_identify_missing_segments_no_sack() {
    let engine = SackEngine::new();

    // No SACK data, so all segments are missing
    let base_seq = SequenceNumber::new(100);
    let highest_sent = SequenceNumber::new(110);

    let missing = engine.identify_missing_segments(base_seq, highest_sent, None);

    // All sequences from 100 to 109 should be considered missing
    assert_eq!(
        missing.len(),
        10,
        "Should identify all unacknowledged segments as missing"
    );
}

#[test]
fn test_identify_missing_segments_with_sack() {
    let engine = SackEngine::new();

    // Base: 100, Highest sent: 110
    // SACK bitmap indicates 102, 104, 106 received
    let bitmap = SackBitmap::new((1 << 1) | (1 << 3) | (1 << 5));
    let sack_data = SackData {
        block_count: SackBlockCount::new(0),
        primary_bitmap: bitmap,
        additional_ranges: vec![],
    };

    let base_seq = SequenceNumber::new(100);
    let highest_sent = SequenceNumber::new(110);

    let missing = engine.identify_missing_segments(base_seq, highest_sent, Some(&sack_data));

    // Missing: 100, 101, 103, 105, 107, 108, 109
    assert_eq!(missing.len(), 7, "Should identify gaps in SACK as missing");
    assert!(missing.contains(&SequenceNumber::new(100)));
    assert!(missing.contains(&SequenceNumber::new(101)));
    assert!(missing.contains(&SequenceNumber::new(103)));
    assert!(missing.contains(&SequenceNumber::new(105)));
    assert!(missing.contains(&SequenceNumber::new(107)));
}

// =============================================================================
// SACK Statistics Tests
// =============================================================================

#[test]
fn test_sack_statistics_tracking() {
    let engine = SackEngine::new();

    // Build and send SACK
    engine.mark_sequence_received(SequenceNumber::new(105));
    let _bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));
    let _ranges = engine.build_sack_ranges(SequenceNumber::new(100));

    // Process received SACK
    let sack_data = SackData {
        block_count: SackBlockCount::new(1),
        primary_bitmap: SackBitmap::new(1 << 2),
        additional_ranges: vec![],
    };
    let _ = engine.process_sack_data(&sack_data, SequenceNumber::new(200));

    let stats = engine.get_stats();
    assert!(
        stats.sack_blocks_sent > 0 || stats.sack_blocks_received > 0,
        "Should track SACK statistics"
    );
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_sack_with_sequence_wraparound() {
    let engine = SackEngine::new();

    // Test sequence number wraparound near u32::MAX
    let base_seq = SequenceNumber::new(u32::MAX - 10);

    // Mark sequences that wrap around
    engine.mark_sequence_received(SequenceNumber::new(u32::MAX - 5));
    engine.mark_sequence_received(SequenceNumber::new(u32::MAX - 3));

    let bitmap = engine.build_sack_bitmap(base_seq);

    // Should handle wraparound correctly
    assert!(bitmap.as_u32() > 0, "Should handle sequence wraparound");
}

#[test]
fn test_clear_acknowledged_sequences() {
    let engine = SackEngine::new();

    // Mark some sequences as received
    engine.mark_sequence_received(SequenceNumber::new(105));
    engine.mark_sequence_received(SequenceNumber::new(106));

    // Clear sequences up to 107
    engine.clear_acknowledged_sequences(SequenceNumber::new(107));

    // Build bitmap - should not include cleared sequences
    let bitmap = engine.build_sack_bitmap(SequenceNumber::new(100));
    assert_eq!(bitmap.as_u32(), 0, "Should clear acknowledged sequences");
}
