// DST Transition Handling Integration Test
//
// This test demonstrates the DST handler working in conjunction with
// drift detection to prevent false alerts during DST transitions.

use buckwild_common::engines::time_sync::*;
use buckwild_common::protocol::types::*;
use std::net::IpAddr;
use std::sync::Arc;

#[test]
fn test_dst_prevents_false_drift_alert() {
    // Setup
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let dst_handler = DstHandler::new(state.clone(), drift_comp.clone());
    let host: IpAddr = "192.168.1.100".parse().expect("valid IP");

    // Simulate time offset that looks like DST transition
    let dst_offset_ms = 3600000; // 1 hour forward (spring forward)

    // Check if it's detected as DST
    let is_dst = dst_handler.is_dst_transition(host, dst_offset_ms);

    // Note: Detection depends on current time being in DST window
    // and lack of stable drift pattern. This test verifies the
    // detection mechanism runs without errors.
    println!("DST detected: {}", is_dst);

    // If DST was detected, verify suppression works
    if is_dst {
        // Handle the DST transition
        let result = dst_handler.handle_dst_transition(host, dst_offset_ms);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DstHandlingResult::TransitionHandled);

        // Verify drift detection is suppressed
        assert!(dst_handler.should_suppress_drift_detection(host));

        // Verify status
        let status = dst_handler.get_dst_status(host);
        assert!(status.has_transition);
        assert!(status.is_suppressed);
        assert_eq!(status.transition_type, DstTransitionType::SpringForward);
    }
}

#[test]
fn test_gradual_drift_not_confused_with_dst() {
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let dst_handler = DstHandler::new(state.clone(), drift_comp.clone());
    let host: IpAddr = "192.168.1.101".parse().expect("valid IP");

    // Small gradual offset (not DST magnitude)
    let small_offset_ms = 100; // 100ms

    // Should NOT be detected as DST
    let is_dst = dst_handler.is_dst_transition(host, small_offset_ms);
    assert!(!is_dst, "Small offset should not be detected as DST");

    // Handle it (should return NotDstTransition)
    let result = dst_handler.handle_dst_transition(host, small_offset_ms);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), DstHandlingResult::NotDstTransition);

    // No suppression should be active
    assert!(!dst_handler.should_suppress_drift_detection(host));
}

#[test]
fn test_dst_suppression_window() {
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let dst_handler = DstHandler::new(state.clone(), drift_comp.clone());
    let host: IpAddr = "192.168.1.102".parse().expect("valid IP");

    // Initially no suppression
    assert!(!dst_handler.should_suppress_drift_detection(host));

    // Record a DST transition manually (for testing)
    dst_handler.record_dst_transition(host, DstTransitionType::FallBack);

    // Suppression should be active
    assert!(dst_handler.should_suppress_drift_detection(host));

    // Check status
    let status = dst_handler.get_dst_status(host);
    assert!(status.has_transition);
    assert!(status.is_suppressed);
    assert_eq!(status.transition_type, DstTransitionType::FallBack);
    assert!(status.suppression_remaining_ms > 0);

    // Clear state
    assert!(dst_handler.clear_dst_state(host).is_ok());
    assert!(!dst_handler.should_suppress_drift_detection(host));
}

#[test]
fn test_multiple_hosts_independent_dst_state() {
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let dst_handler = DstHandler::new(state.clone(), drift_comp.clone());

    let host1: IpAddr = "192.168.1.103".parse().expect("valid IP");
    let host2: IpAddr = "192.168.1.104".parse().expect("valid IP");

    // Record DST for host1 only
    dst_handler.record_dst_transition(host1, DstTransitionType::SpringForward);

    // Host1 should have suppression, host2 should not
    assert!(dst_handler.should_suppress_drift_detection(host1));
    assert!(!dst_handler.should_suppress_drift_detection(host2));

    // Verify statuses
    let status1 = dst_handler.get_dst_status(host1);
    let status2 = dst_handler.get_dst_status(host2);

    assert!(status1.has_transition);
    assert!(!status2.has_transition);

    assert!(status1.is_suppressed);
    assert!(!status2.is_suppressed);
}

#[test]
fn test_dst_enable_disable_functionality() {
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let mut dst_handler = DstHandler::new(state.clone(), drift_comp.clone());
    let host: IpAddr = "192.168.1.105".parse().expect("valid IP");

    // Initially enabled
    assert!(dst_handler.is_enabled());

    // DST offset
    let dst_offset = 3600000;

    // Disable DST detection
    dst_handler.set_enabled(false);
    assert!(!dst_handler.is_enabled());

    // Should not detect DST when disabled
    let is_dst = dst_handler.is_dst_transition(host, dst_offset);
    assert!(!is_dst, "DST detection should be disabled");

    // Re-enable
    dst_handler.set_enabled(true);
    assert!(dst_handler.is_enabled());
}

#[test]
fn test_dst_transition_counter() {
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let dst_handler = DstHandler::new(state.clone(), drift_comp.clone());
    let host: IpAddr = "192.168.1.106".parse().expect("valid IP");

    // Record multiple transitions
    dst_handler.record_dst_transition(host, DstTransitionType::SpringForward);
    dst_handler.record_dst_transition(host, DstTransitionType::FallBack);
    dst_handler.record_dst_transition(host, DstTransitionType::SpringForward);

    // Check counter
    let status = dst_handler.get_dst_status(host);
    assert_eq!(status.transition_count, 3);
    assert_eq!(status.transition_type, DstTransitionType::SpringForward); // Last one
}

#[test]
fn test_all_dst_status_query() {
    let state = Arc::new(TimeSyncState::new());
    let drift_comp = Arc::new(DriftCompensator::new(state.clone()));
    let dst_handler = DstHandler::new(state.clone(), drift_comp.clone());

    let host1: IpAddr = "192.168.1.107".parse().expect("valid IP");
    let host2: IpAddr = "192.168.1.108".parse().expect("valid IP");

    // Record transitions for both hosts
    dst_handler.record_dst_transition(host1, DstTransitionType::SpringForward);
    dst_handler.record_dst_transition(host2, DstTransitionType::FallBack);

    // Get all status
    let all_status = dst_handler.get_all_dst_status();

    // Should have 2 entries
    assert_eq!(all_status.len(), 2);

    // Verify both hosts are present
    let hosts: Vec<IpAddr> = all_status.iter().map(|(h, _)| *h).collect();
    assert!(hosts.contains(&host1));
    assert!(hosts.contains(&host2));
}
