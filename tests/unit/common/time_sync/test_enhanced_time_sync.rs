use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time;

use buckwild_common::time_sync::{
    TimeSyncEngine, TimeSyncState, TimeSyncStatus, SyncSample, SyncRequest, SyncResponse,
    TimeEpoch, EpochType, create_shared_time_sync_state
};

/// Test dual-epoch time system functionality
#[tokio::test]
async fn test_dual_epoch_time_system() {
    let host1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let host2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
    
    // Test daily epoch time windows
    let daily_window = TimeEpoch::current_time_window_for_host(EpochType::Daily, host1, 0);
    assert_eq!(daily_window.epoch_type, EpochType::Daily);
    assert!(daily_window.window_start <= daily_window.window_end);
    assert_eq!(daily_window.window_end - daily_window.window_start, 500); // 500ms window
    
    // Test monthly epoch time windows
    let monthly_window = TimeEpoch::current_time_window_for_host(EpochType::Monthly, host1, 0);
    assert_eq!(monthly_window.epoch_type, EpochType::Monthly);
    assert!(monthly_window.window_start <= monthly_window.window_end);
    assert_eq!(monthly_window.window_end - monthly_window.window_start, 500); // 500ms window
    
    // Test per-host time offsets
    TimeEpoch::set_host_time_offset(host1, 1000000); // 1 second offset in microseconds
    TimeEpoch::set_host_time_offset(host2, -500000); // -0.5 second offset in microseconds
    
    assert_eq!(TimeEpoch::get_host_time_offset(host1), 1000000);
    assert_eq!(TimeEpoch::get_host_time_offset(host2), -500000);
    
    // Test synchronized time calculation
    let sync_time1 = TimeEpoch::synchronized_time_ms_for_host(host1);
    let sync_time2 = TimeEpoch::synchronized_time_ms_for_host(host2);
    let current_time = TimeEpoch::current_time_ms();
    
    // Host1 should be ~1 second ahead
    assert!((sync_time1 as i64 - current_time as i64 - 1000).abs() < 100);
    // Host2 should be ~0.5 seconds behind
    assert!((sync_time2 as i64 - current_time as i64 + 500).abs() < 100);
    
    // Cleanup
    TimeEpoch::remove_host_time_offset(host1);
    TimeEpoch::remove_host_time_offset(host2);
}

/// Test high-precision challenge-response time synchronization
#[tokio::test]
async fn test_high_precision_time_sync() {
    let mut engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Mock network functions
    let send_request = |request: SyncRequest| -> bool {
        // Simulate successful send
        assert!(request.challenge_nonce > 0);
        assert!(request.local_timestamp > 0);
        true
    };
    
    let receive_response = |challenge_nonce: u32| -> Option<SyncResponse> {
        // Simulate response with small time offset
        let current_time = TimeEpoch::current_time_high_precision();
        Some(SyncResponse {
            challenge_nonce,
            local_timestamp: current_time / 1000 + 10, // 10ms offset
            local_precision: (current_time % 1000) as u32,
            peer_timestamp: current_time / 1000,
            peer_precision: (current_time % 1000) as u32,
        })
    };
    
    // Execute precision time sync
    let result = engine.execute_precision_time_sync_for_host(
        host,
        send_request,
        receive_response,
    ).await;
    
    assert!(result.is_ok());
    let time_offset = result.unwrap();
    
    // Should detect the 10ms offset
    assert!((time_offset - 10.0).abs() < 5.0); // Within 5ms tolerance
    
    // Check that host sync state was updated
    assert!(engine.is_sync_healthy_for_host(host));
    assert_eq!(engine.state().status_for_host(host), TimeSyncStatus::Synchronized);
}

/// Test atomic gradual time adjustment
#[tokio::test]
async fn test_atomic_gradual_adjustment() {
    let engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Apply a gradual adjustment of 100ms
    let result = engine.apply_atomic_gradual_adjustment_for_host(host, 100.0, 80).await;
    assert!(result.is_ok());
    
    // Check that adjustment was queued
    assert_eq!(engine.state().status_for_host(host), TimeSyncStatus::Adjusting);
    let adjustments = engine.state().time_adjustments_for_host(host);
    assert!(!adjustments.is_empty());
    
    // Process adjustments (simulate time passing)
    let processed = engine.process_adjustments_for_host(host);
    
    // Check final state
    let final_offset = TimeEpoch::get_host_time_offset(host);
    assert!(final_offset != 0); // Some adjustment should have been applied
    
    // Cleanup
    TimeEpoch::remove_host_time_offset(host);
}

/// Test security validation functions
#[tokio::test]
async fn test_security_validation() {
    let current_time = TimeEpoch::current_time_ms();
    
    // Test time security boundary validation
    assert!(TimeEpoch::validate_time_security_boundary(current_time, current_time));
    assert!(TimeEpoch::validate_time_security_boundary(current_time + 1000, current_time));
    assert!(!TimeEpoch::validate_time_security_boundary(current_time + 60000, current_time));
    
    // Test time skew validation
    assert!(TimeEpoch::validate_time_skew(current_time, current_time));
    assert!(TimeEpoch::validate_time_skew(current_time + 1000, current_time));
    assert!(!TimeEpoch::validate_time_skew(current_time + 10000, current_time));
    
    // Test dual-epoch consistency validation
    assert!(TimeEpoch::validate_dual_epoch_consistency(current_time, current_time));
    assert!(!TimeEpoch::validate_dual_epoch_consistency(current_time + 60000, current_time));
}

/// Test month boundary transition handling
#[tokio::test]
async fn test_month_boundary_transition() {
    let engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Test month boundary preparation
    TimeEpoch::start_month_boundary_preparation();
    assert!(TimeEpoch::is_in_month_boundary_preparation());
    
    // Test month boundary handling
    let handled = engine.handle_month_boundary_for_host(host);
    
    // End preparation
    TimeEpoch::end_month_boundary_preparation();
    assert!(!TimeEpoch::is_in_month_boundary_preparation());
}

/// Test clock drift detection and compensation
#[tokio::test]
async fn test_clock_drift_detection() {
    let engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Add some sync samples with drift pattern
    let current_time = TimeEpoch::current_time_ms();
    for i in 0..5 {
        let sample = SyncSample {
            time_offset: i as f64 * 2.0, // 2ms drift per sample
            network_delay: 10.0,
            round_trip_time: 20.0,
            timestamp: current_time - (5 - i) * 60000, // 1 minute intervals
            quality: 80,
            t1: 0,
            t2: 0,
            t3: 0,
            t4: 0,
        };
        engine.state().add_sync_sample_for_host(host, sample);
    }
    
    // Detect drift
    let drift = engine.detect_drift_for_host(host);
    assert!(drift.abs() > 0.0); // Should detect some drift
    
    // Compensate drift
    let compensated = engine.compensate_drift_for_host(host);
    
    // Cleanup
    TimeEpoch::remove_host_time_offset(host);
}

/// Test per-host synchronization state management
#[tokio::test]
async fn test_per_host_sync_state() {
    let state = create_shared_time_sync_state();
    let host1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let host2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
    
    // Test initial state
    assert_eq!(state.status_for_host(host1), TimeSyncStatus::Synchronized);
    assert_eq!(state.local_offset_for_host(host1), 0);
    assert_eq!(state.sync_quality_for_host(host1), 100);
    
    // Test setting different states for different hosts
    state.set_status_for_host(host1, TimeSyncStatus::Adjusting);
    state.set_local_offset_for_host(host1, 1000000); // 1 second
    state.set_sync_quality_for_host(host1, 75);
    
    state.set_status_for_host(host2, TimeSyncStatus::Emergency);
    state.set_local_offset_for_host(host2, -500000); // -0.5 seconds
    state.set_sync_quality_for_host(host2, 50);
    
    // Verify independent state
    assert_eq!(state.status_for_host(host1), TimeSyncStatus::Adjusting);
    assert_eq!(state.local_offset_for_host(host1), 1000000);
    assert_eq!(state.sync_quality_for_host(host1), 75);
    
    assert_eq!(state.status_for_host(host2), TimeSyncStatus::Emergency);
    assert_eq!(state.local_offset_for_host(host2), -500000);
    assert_eq!(state.sync_quality_for_host(host2), 50);
    
    // Test global status (should be worst case)
    assert_eq!(state.status(), TimeSyncStatus::Emergency);
    
    // Test host removal
    state.remove_host(host2);
    assert_eq!(state.status(), TimeSyncStatus::Adjusting); // Should update to host1's status
    
    let hosts = state.get_all_hosts();
    assert_eq!(hosts.len(), 1);
    assert!(hosts.contains(&host1));
    assert!(!hosts.contains(&host2));
}

/// Test emergency time synchronization
#[tokio::test]
async fn test_emergency_time_sync() {
    let engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Apply emergency sync with large offset
    let result = engine.apply_emergency_time_sync_for_host(host, 5000.0).await; // 5 seconds
    assert!(result.is_ok());
    
    // Check that offset was applied immediately
    let host_offset = TimeEpoch::get_host_time_offset(host);
    assert!((host_offset - 5000000).abs() < 1000); // Within 1ms tolerance (5s in microseconds)
    
    // Check state
    assert_eq!(engine.state().status_for_host(host), TimeSyncStatus::Synchronized);
    
    // Cleanup
    TimeEpoch::remove_host_time_offset(host);
}

/// Test rate limiting for security
#[tokio::test]
async fn test_sync_rate_limiting() {
    let mut engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    let send_request = |_: SyncRequest| -> bool { true };
    let receive_response = |_: u32| -> Option<SyncResponse> { None }; // Always timeout
    
    // First sync attempt should work (but timeout)
    let result1 = engine.execute_precision_time_sync_for_host(
        host,
        send_request,
        receive_response,
    ).await;
    assert!(result1.is_err()); // Should timeout
    
    // Immediate second attempt should be rate limited
    let result2 = engine.execute_precision_time_sync_for_host(
        host,
        send_request,
        receive_response,
    ).await;
    assert!(result2.is_err());
    
    // Wait and try again
    time::sleep(Duration::from_millis(1100)).await;
    let result3 = engine.execute_precision_time_sync_for_host(
        host,
        send_request,
        receive_response,
    ).await;
    assert!(result3.is_err()); // Should timeout, but not be rate limited
}

/// Test sync sample security validation
#[tokio::test]
async fn test_sync_sample_security() {
    let engine = TimeSyncEngine::new();
    let current_time = TimeEpoch::current_time_ms();
    
    // Valid sample
    let valid_sample = SyncSample {
        time_offset: 10.0,
        network_delay: 50.0,
        round_trip_time: 100.0,
        timestamp: current_time,
        quality: 80,
        t1: 1000,
        t2: 2000,
        t3: 3000,
        t4: 4000,
    };
    assert!(engine.validate_sync_sample_security(&valid_sample));
    
    // Invalid sample - excessive network delay
    let invalid_sample1 = SyncSample {
        time_offset: 10.0,
        network_delay: 15000.0, // 15 seconds - too high
        round_trip_time: 100.0,
        timestamp: current_time,
        quality: 80,
        t1: 1000,
        t2: 2000,
        t3: 3000,
        t4: 4000,
    };
    assert!(!engine.validate_sync_sample_security(&invalid_sample1));
    
    // Invalid sample - suspicious timestamp
    let invalid_sample2 = SyncSample {
        time_offset: 10.0,
        network_delay: 50.0,
        round_trip_time: 100.0,
        timestamp: current_time + 5000, // 5 seconds in future
        quality: 80,
        t1: 1000,
        t2: 2000,
        t3: 3000,
        t4: 4000,
    };
    assert!(!engine.validate_sync_sample_security(&invalid_sample2));
    
    // Invalid sample - timing relationship violation
    let invalid_sample3 = SyncSample {
        time_offset: 10.0,
        network_delay: 50.0,
        round_trip_time: 100.0,
        timestamp: current_time,
        quality: 80,
        t1: 4000, // T1 > T4 - invalid
        t2: 2000,
        t3: 3000,
        t4: 1000,
    };
    assert!(!engine.validate_sync_sample_security(&invalid_sample3));
}

/// Test time offset security validation
#[tokio::test]
async fn test_time_offset_security() {
    let engine = TimeSyncEngine::new();
    
    // Valid offsets
    assert!(engine.validate_time_offset_security(0.0));
    assert!(engine.validate_time_offset_security(1000.0)); // 1 second
    assert!(engine.validate_time_offset_security(-1000.0)); // -1 second
    assert!(engine.validate_time_offset_security(29000.0)); // 29 seconds
    
    // Invalid offsets
    assert!(!engine.validate_time_offset_security(35000.0)); // 35 seconds - too large
    assert!(!engine.validate_time_offset_security(-35000.0)); // -35 seconds - too large
}

/// Test comprehensive monitoring and health checks
#[tokio::test]
async fn test_sync_monitoring() {
    let engine = TimeSyncEngine::new();
    let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Initially should be healthy
    assert!(engine.is_sync_healthy_for_host(host));
    
    // Set poor quality
    engine.state().set_sync_quality_for_host(host, 30);
    assert!(!engine.is_sync_healthy_for_host(host));
    
    // Reset quality and set failed status
    engine.state().set_sync_quality_for_host(host, 80);
    engine.state().set_status_for_host(host, TimeSyncStatus::Failed);
    assert!(!engine.is_sync_healthy_for_host(host));
    
    // Reset status and set old sync time
    engine.state().set_status_for_host(host, TimeSyncStatus::Synchronized);
    engine.state().set_last_sync_time_for_host(host, TimeEpoch::current_time_ms() - 400000); // 6+ minutes ago
    assert!(!engine.is_sync_healthy_for_host(host));
    
    // Reset sync time and set excessive drift
    engine.state().set_last_sync_time_for_host(host, TimeEpoch::current_time_ms());
    engine.state().set_drift_rate_for_host(host, 150.0); // 150 ppm - too high
    assert!(!engine.is_sync_healthy_for_host(host));
    
    // Reset everything - should be healthy again
    engine.state().set_drift_rate_for_host(host, 10.0);
    assert!(engine.is_sync_healthy_for_host(host));
}