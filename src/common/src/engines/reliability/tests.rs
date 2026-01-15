// Integration tests for reliability module
#![cfg(test)]

use super::*;
use crate::protocol::types::*;
use std::time::{Duration, Instant};

#[test]
fn test_retransmission_basic_flow() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(100), SequenceNumber::new(100));

    // Send packet
    let seq = SequenceNumber::new(100);
    let rto = engine.track_sent_packet(seq);
    assert!(rto.as_u64() > 0);
    assert_eq!(engine.pending_count(), 1);

    // Acknowledge packet
    engine.handle_acknowledgment(seq);
    assert_eq!(engine.pending_count(), 0);
    assert_eq!(engine.stats().packets_sent(), 1);
    assert_eq!(engine.stats().packets_acked(), 1);
}

#[test]
fn test_selective_acknowledgment() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    // Send sequence 1000-1010
    for i in 0..11 {
        engine.track_sent_packet(SequenceNumber::new(1000 + i));
    }

    // Receive out-of-order: 1000, 1003-1007, 1009-1010
    engine.handle_acknowledgment(SequenceNumber::new(1000));

    let sack_blocks = vec![
        SackBlock::new(SequenceNumber::new(1003), SequenceNumber::new(1008)),
        SackBlock::new(SequenceNumber::new(1009), SequenceNumber::new(1011)),
    ];

    let missing = engine.handle_sack_blocks(
        &sack_blocks,
        SequenceNumber::new(1001), // 1000 was already acknowledged
        SequenceNumber::new(1011),
    );

    // Missing: 1001, 1002, 1008
    // SACK blocks: [1003,1008) and [1009,1011) acknowledge 1003-1007 and 1009-1010
    // Range [1001,1011): packet 1000 was already acknowledged separately
    assert_eq!(missing.len(), 3);
    assert!(missing.contains(&SequenceNumber::new(1001)));
    assert!(missing.contains(&SequenceNumber::new(1002)));
    assert!(missing.contains(&SequenceNumber::new(1008)));
}

#[test]
fn test_rto_calculation_updates() {
    let mut calculator = RtoCalculator::new();
    let initial_rto = calculator.current_rto();

    // Simulate RTT measurements
    let send_time = Instant::now();
    let rtt_samples = [100, 120, 90, 110, 105];

    for (idx, &rtt_ms) in rtt_samples.iter().enumerate() {
        let ack_time = send_time + Duration::from_millis(rtt_ms);
        let rtt = calculator.measure_rtt(send_time, ack_time);
        calculator.update_rto(rtt);

        if idx == 0 {
            // First measurement initializes SRTT
            assert_ne!(calculator.current_rto().as_u64(), initial_rto.as_u64());
        }
    }

    // RTO should stabilize around measured RTTs
    let final_rto = calculator.current_rto();
    assert!(final_rto.as_u64() >= 100);
    assert!(final_rto.as_u64() <= 1000);
}

#[test]
fn test_exponential_backoff() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    let seq = SequenceNumber::new(1000);
    let initial_rto = engine.track_sent_packet(seq);

    // First timeout - should double RTO
    let result = engine.handle_packet_timeout(seq);
    assert!(result.is_ok());
    let rto_after_first = engine.current_rto();
    assert_eq!(rto_after_first.as_u64(), initial_rto.as_u64() * 2);

    // Second timeout - should double again
    let result = engine.handle_packet_timeout(seq);
    assert!(result.is_ok());
    let rto_after_second = engine.current_rto();
    assert_eq!(rto_after_second.as_u64(), rto_after_first.as_u64() * 2);
}

#[test]
fn test_max_retransmission_attempts() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    let seq = SequenceNumber::new(1000);
    engine.track_sent_packet(seq);

    // Exhaust retransmission attempts
    for _ in 0..8 {
        let result = engine.handle_packet_timeout(seq);
        assert!(result.is_ok());
    }

    // Next attempt should fail
    let result = engine.handle_packet_timeout(seq);
    assert!(result.is_err());
    assert_eq!(engine.stats().packets_lost(), 1);
}

#[test]
fn test_sack_block_merging() {
    let block1 = SackBlock::new(SequenceNumber::new(100), SequenceNumber::new(110));
    let block2 = SackBlock::new(SequenceNumber::new(105), SequenceNumber::new(115));

    // Overlapping blocks should merge
    let merged = block1.try_merge(&block2);
    assert!(merged.is_some());
    let merged = merged.unwrap();
    assert_eq!(merged.start.as_u32(), 100);
    assert_eq!(merged.end.as_u32(), 115);

    // Non-overlapping blocks should not merge
    let block3 = SackBlock::new(SequenceNumber::new(200), SequenceNumber::new(210));
    let no_merge = block1.try_merge(&block3);
    assert!(no_merge.is_none());
}

#[test]
fn test_statistics_tracking() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    // Send 10 packets
    for i in 0..10 {
        engine.track_sent_packet(SequenceNumber::new(1000 + i));
    }

    // Acknowledge 8 packets
    for i in 0..8 {
        engine.handle_acknowledgment(SequenceNumber::new(1000 + i));
    }

    // Retransmit 2 packets
    for i in 8..10 {
        let result = engine.handle_packet_timeout(SequenceNumber::new(1000 + i));
        assert!(result.is_ok());
    }

    let stats = engine.stats();
    assert_eq!(stats.packets_sent(), 10);
    assert_eq!(stats.packets_acked(), 8);
    assert_eq!(stats.retransmissions(), 2);
    assert!((stats.retransmission_rate() - 0.2).abs() < 0.001);
}

#[test]
fn test_fast_retransmit() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    // Track packets
    for i in 0..5 {
        engine.track_sent_packet(SequenceNumber::new(1000 + i));
    }

    // Trigger fast retransmit for missing packets
    let missing = vec![SequenceNumber::new(1001), SequenceNumber::new(1002)];
    engine.fast_retransmit(&missing);

    assert_eq!(engine.stats().fast_retransmits(), 2);
    assert_eq!(engine.stats().retransmissions(), 2);
}

#[test]
fn test_out_of_order_delivery() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    // Receive packets out of order: 1002, 1003, 1004, 1000, 1001
    engine.handle_acknowledgment(SequenceNumber::new(1002));
    assert_eq!(engine.out_of_order_count(), 1);

    engine.handle_acknowledgment(SequenceNumber::new(1003));
    engine.handle_acknowledgment(SequenceNumber::new(1004));
    assert_eq!(engine.out_of_order_count(), 3);

    // Fill the gap with 1000
    engine.handle_acknowledgment(SequenceNumber::new(1000));
    engine.handle_acknowledgment(SequenceNumber::new(1001));

    // All should be in order now
    assert_eq!(engine.cumulative_ack().as_u32(), 1005);
    assert_eq!(engine.out_of_order_count(), 0);
}

#[test]
fn test_reset_functionality() {
    let mut engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

    // Create some state
    for i in 0..5 {
        engine.track_sent_packet(SequenceNumber::new(1000 + i));
    }
    engine.handle_acknowledgment(SequenceNumber::new(1000));

    assert!(engine.pending_count() > 0);
    assert!(engine.stats().packets_sent() > 0);

    // Reset should clear everything
    engine.reset(SequenceNumber::new(2000), SequenceNumber::new(2000));

    assert_eq!(engine.pending_count(), 0);
    assert_eq!(engine.cumulative_ack().as_u32(), 2000);
    assert_eq!(engine.stats().packets_sent(), 0);
}
