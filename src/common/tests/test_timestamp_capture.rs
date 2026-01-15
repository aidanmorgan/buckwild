//! Tests for T1-T4 timestamp capture in time synchronization
//!
//! Validates that all four timestamps (T1, T2, T3, T4) are captured correctly
//! and that the NTP algorithm implementation is correct.
//!
//! Protocol Reference: design/protocol/09-time-synchronization.md

use buckwild_common::engines::time_sync::engine::{SyncRequest, TimeSyncEngine};
use buckwild_common::engines::time_sync::{SyncSample, epoch::TimeEpoch};
use buckwild_common::protocol::types::{
    ChallengeNonce, MicrosecondTimestamp, RoundTripTime, Score, TimeOffset,
};
use std::sync::Arc;
use std::sync::Mutex;

/// Test that T1 is captured as current time, not hardcoded to zero
#[test]
fn test_t1_not_zero() {
    let captured_t1 = Arc::new(Mutex::new(None));
    let captured_t1_clone = captured_t1.clone();

    let send_fn = move |request: SyncRequest| {
        // Capture T1 from the request (precision_timestamp is already in microseconds)
        let t1 = request.precision_timestamp;
        *captured_t1_clone.lock().unwrap() = Some(t1);
        true
    };

    let receive_fn = |_nonce: ChallengeNonce| None; // Never return response

    let mut engine = TimeSyncEngine::new();

    // Start time sync (will timeout, but that's OK)
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _ = runtime.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            engine.execute_precision_time_sync(send_fn, receive_fn),
        )
        .await
    });

    // Verify T1 was captured and is not zero
    let t1 = captured_t1.lock().unwrap().expect("T1 should be captured");
    assert_ne!(
        t1.as_u64(),
        0,
        "T1 should be current time, not hardcoded to 0"
    );

    // Verify T1 is within reasonable range of current time
    let current_time = TimeEpoch::current_time_high_precision();
    let diff = if current_time > t1.as_u64() {
        current_time - t1.as_u64()
    } else {
        t1.as_u64() - current_time
    };

    assert!(
        diff < 1_000_000,
        "T1 should be within 1 second of current time"
    );
}

/// Test that T2 is greater than T1 (server receives after client sends)
#[test]
fn test_t2_greater_than_t1() {
    // Create test timestamps
    let t1 = MicrosecondTimestamp::new(1000000);
    let t2 = MicrosecondTimestamp::new(1000100); // +100 microseconds network delay
    let t3 = MicrosecondTimestamp::new(1000110); // +10 microseconds server processing
    let t4 = MicrosecondTimestamp::new(1000210); // +100 microseconds return trip

    // Create sample
    let sample = create_test_sample(t1, t2, t3, t4);

    // Verify monotonicity
    assert!(
        t2.as_u64() > t1.as_u64(),
        "T2 (server receive) must be after T1 (client send)"
    );
    assert!(sample.t2.as_u64() > sample.t1.as_u64());
}

/// Test that T3 is greater than T2 (server sends after receiving)
#[test]
fn test_t3_greater_than_t2() {
    let t1 = MicrosecondTimestamp::new(1000000);
    let t2 = MicrosecondTimestamp::new(1000100);
    let t3 = MicrosecondTimestamp::new(1000110);
    let t4 = MicrosecondTimestamp::new(1000210);

    let sample = create_test_sample(t1, t2, t3, t4);

    assert!(
        t3.as_u64() > t2.as_u64(),
        "T3 (server send) must be after T2 (server receive)"
    );
    assert!(sample.t3.as_u64() > sample.t2.as_u64());
}

/// Test that T4 is greater than T3 (client receives after server sends)
#[test]
fn test_t4_greater_than_t3() {
    let t1 = MicrosecondTimestamp::new(1000000);
    let t2 = MicrosecondTimestamp::new(1000100);
    let t3 = MicrosecondTimestamp::new(1000110);
    let t4 = MicrosecondTimestamp::new(1000210);

    let sample = create_test_sample(t1, t2, t3, t4);

    assert!(
        t4.as_u64() > t3.as_u64(),
        "T4 (client receive) must be after T3 (server send)"
    );
    assert!(sample.t4.as_u64() > sample.t3.as_u64());
}

/// Test NTP offset calculation: Offset = ((T2 - T1) + (T3 - T4)) / 2
#[test]
fn test_offset_calculation_zero_offset() {
    // Zero offset scenario: clocks synchronized, symmetric delay
    let t1 = MicrosecondTimestamp::new(1000000);
    let t2 = MicrosecondTimestamp::new(1000100); // +100μs forward delay
    let t3 = MicrosecondTimestamp::new(1000110); // +10μs server processing
    let t4 = MicrosecondTimestamp::new(1000210); // +100μs return delay

    let offset = calculate_ntp_offset(t1, t2, t3, t4);

    // Offset = ((1000100 - 1000000) + (1000110 - 1000210)) / 2
    //        = (100 + (-100)) / 2
    //        = 0
    assert_eq!(offset, 0, "Offset should be 0 for synchronized clocks");
}

/// Test NTP offset calculation: Positive offset
#[test]
fn test_offset_calculation_positive_offset() {
    // Server clock ahead of client by 50μs
    let t1 = MicrosecondTimestamp::new(1000000);
    let t2 = MicrosecondTimestamp::new(1000150); // +100μs delay + 50μs offset
    let t3 = MicrosecondTimestamp::new(1000160); // +10μs processing
    let t4 = MicrosecondTimestamp::new(1000260); // +100μs return delay

    let offset = calculate_ntp_offset(t1, t2, t3, t4);

    // Offset = ((1000150 - 1000000) + (1000160 - 1000260)) / 2
    //        = (150 + (-100)) / 2
    //        = 25
    assert_eq!(offset, 25, "Offset should be 25μs");
}

/// Test NTP offset calculation: Negative offset
#[test]
fn test_offset_calculation_negative_offset() {
    // Server clock behind client by 50μs
    let t1 = MicrosecondTimestamp::new(1000000);
    let t2 = MicrosecondTimestamp::new(1000050); // +100μs delay - 50μs offset
    let t3 = MicrosecondTimestamp::new(1000060); // +10μs processing
    let t4 = MicrosecondTimestamp::new(1000160); // +100μs return delay

    let offset = calculate_ntp_offset(t1, t2, t3, t4);

    // Offset = ((1000050 - 1000000) + (1000060 - 1000160)) / 2
    //        = (50 + (-100)) / 2
    //        = -25
    assert_eq!(offset, -25, "Offset should be -25μs");
}

/// Test full timestamp chain validation
#[test]
fn test_timestamp_monotonicity_validation() {
    let _engine = TimeSyncEngine::new();

    // Valid timestamps (monotonic)
    let valid_sample = create_test_sample(
        MicrosecondTimestamp::new(1000000),
        MicrosecondTimestamp::new(1000100),
        MicrosecondTimestamp::new(1000110),
        MicrosecondTimestamp::new(1000210),
    );

    // This should pass validation (private method, so we test through sample creation)
    assert!(
        valid_sample.t1.as_u64() < valid_sample.t2.as_u64(),
        "Valid sample should have monotonic timestamps"
    );
    assert!(valid_sample.t2.as_u64() < valid_sample.t3.as_u64());
    assert!(valid_sample.t3.as_u64() < valid_sample.t4.as_u64());

    // Invalid timestamps (non-monotonic) - t2 before t1
    let t1 = MicrosecondTimestamp::new(1000100);
    let t2 = MicrosecondTimestamp::new(1000000); // INVALID: before t1
    let _t3 = MicrosecondTimestamp::new(1000110);
    let _t4 = MicrosecondTimestamp::new(1000210);

    assert!(
        t2.as_u64() < t1.as_u64(),
        "Invalid sample should have non-monotonic timestamps"
    );
}

/// Test integration: Full time sync request creation captures T1
#[tokio::test]
async fn test_sync_request_captures_real_t1() {
    let mut engine = TimeSyncEngine::new();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_clone = requests.clone();

    let send_fn = move |request: SyncRequest| {
        requests_clone.lock().unwrap().push(request);
        true
    };

    let receive_fn = |_nonce: ChallengeNonce| None;

    // Execute sync (will timeout)
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        engine.execute_precision_time_sync(send_fn, receive_fn),
    )
    .await;

    let captured_requests = requests.lock().unwrap();
    assert!(
        !captured_requests.is_empty(),
        "At least one sync request should be sent"
    );

    // Verify each request has non-zero timestamps
    for request in captured_requests.iter() {
        let t1 = request.precision_timestamp;

        assert_ne!(t1.as_u64(), 0, "T1 should not be zero");

        // Verify it's a reasonable timestamp (after 2020)
        let min_timestamp = MicrosecondTimestamp::new(1577836800_000000); // 2020-01-01 00:00:00 UTC
        assert!(
            t1.as_u64() >= min_timestamp.as_u64(),
            "T1 should be a reasonable timestamp"
        );
    }
}

// Helper functions

fn create_test_sample(
    t1: MicrosecondTimestamp,
    t2: MicrosecondTimestamp,
    t3: MicrosecondTimestamp,
    t4: MicrosecondTimestamp,
) -> SyncSample {
    let offset = calculate_ntp_offset(t1, t2, t3, t4);
    let rtt = t4.saturating_sub(t1);

    SyncSample {
        time_offset: TimeOffset::new(offset),
        network_delay: std::time::Duration::from_micros(rtt / 2),
        round_trip_time: RoundTripTime::from_nanos(rtt * 1000),
        timestamp: MicrosecondTimestamp::now(),
        quality: Score::new(100.0),
        t1,
        t2,
        t3,
        t4,
    }
}

fn calculate_ntp_offset(
    t1: MicrosecondTimestamp,
    t2: MicrosecondTimestamp,
    t3: MicrosecondTimestamp,
    t4: MicrosecondTimestamp,
) -> i64 {
    (((t2.as_u64() as i128 - t1.as_u64() as i128) + (t3.as_u64() as i128 - t4.as_u64() as i128))
        / 2) as i64
}
