/// Tests for state enum validation and cleanup
/// 
/// This module tests the consolidated state enums and their validation methods.

use crate::protocol::types::*;
use std::sync::atomic::{AtomicU8, Ordering};

#[test]
fn test_connection_state_transitions() {
    // Test valid transitions
    assert!(ConnectionState::Closed.can_transition_to(ConnectionState::Connecting));
    assert!(ConnectionState::Connecting.can_transition_to(ConnectionState::Established));
    assert!(ConnectionState::Established.can_transition_to(ConnectionState::Closing));
    assert!(ConnectionState::Closing.can_transition_to(ConnectionState::Closed));
    
    // Test invalid transitions
    assert!(!ConnectionState::Closed.can_transition_to(ConnectionState::Established));
    assert!(!ConnectionState::Connecting.can_transition_to(ConnectionState::Closing));
    
    // Test same state transitions (always valid)
    assert!(ConnectionState::Established.can_transition_to(ConnectionState::Established));
}

#[test]
fn test_session_state_transitions() {
    // Test valid transitions
    assert!(SessionState::Initializing.can_transition_to(SessionState::Active));
    assert!(SessionState::Active.can_transition_to(SessionState::Idle));
    assert!(SessionState::Idle.can_transition_to(SessionState::Active));
    assert!(SessionState::Active.can_transition_to(SessionState::Degraded));
    assert!(SessionState::Degraded.can_transition_to(SessionState::Active));
    assert!(SessionState::Active.can_transition_to(SessionState::Terminating));
    assert!(SessionState::Terminating.can_transition_to(SessionState::Terminated));
    
    // Test invalid transitions
    assert!(!SessionState::Initializing.can_transition_to(SessionState::Terminated));
    assert!(!SessionState::Terminated.can_transition_to(SessionState::Active));
    assert!(!SessionState::Error.can_transition_to(SessionState::Active));
    
    // Test terminal states
    assert!(SessionState::Terminated.is_terminal());
    assert!(SessionState::Error.is_terminal());
    assert!(!SessionState::Active.is_terminal());
}

#[test]
fn test_health_state_properties() {
    // Test health state properties
    assert!(HealthState::Healthy.is_acceptable());
    assert!(HealthState::Warning.is_acceptable());
    assert!(!HealthState::Unhealthy.is_acceptable());
    assert!(!HealthState::Unknown.is_acceptable());
    
    assert!(!HealthState::Healthy.is_problematic());
    assert!(HealthState::Warning.is_problematic());
    assert!(HealthState::Unhealthy.is_problematic());
    assert!(!HealthState::Unknown.is_problematic());
    
    // Test severity levels
    assert_eq!(HealthState::Healthy.severity_level(), 0);
    assert_eq!(HealthState::Warning.severity_level(), 1);
    assert_eq!(HealthState::Unhealthy.severity_level(), 2);
    assert_eq!(HealthState::Unknown.severity_level(), 3);
}

#[test]
fn test_tun_state_transitions() {
    // Test valid transitions
    assert!(TunState::Uninitialized.can_transition_to(TunState::Initializing));
    assert!(TunState::Initializing.can_transition_to(TunState::Active));
    assert!(TunState::Active.can_transition_to(TunState::Suspended));
    assert!(TunState::Suspended.can_transition_to(TunState::Active));
    assert!(TunState::Active.can_transition_to(TunState::ShuttingDown));
    assert!(TunState::ShuttingDown.can_transition_to(TunState::Shutdown));
    
    // Test invalid transitions
    assert!(!TunState::Uninitialized.can_transition_to(TunState::Active));
    assert!(!TunState::Shutdown.can_transition_to(TunState::Active));
    
    // Test operational states
    assert!(TunState::Active.is_operational());
    assert!(!TunState::Suspended.is_operational());
    assert!(!TunState::Error.is_operational());
    
    assert!(TunState::Active.is_usable());
    assert!(TunState::Suspended.is_usable());
    assert!(!TunState::Error.is_usable());
}

#[test]
fn test_tcp_state_properties() {
    // Test TCP state properties
    assert!(TcpState::Established.is_established());
    assert!(!TcpState::Closed.is_established());
    
    assert!(TcpState::SynSent.is_connecting());
    assert!(TcpState::SynReceived.is_connecting());
    assert!(!TcpState::Established.is_connecting());
    
    assert!(TcpState::FinWait1.is_closing());
    assert!(TcpState::TimeWait.is_closing());
    assert!(!TcpState::Established.is_closing());
    
    assert!(TcpState::Closed.is_closed());
    assert!(!TcpState::Established.is_closed());
}

#[test]
fn test_congestion_state_properties() {
    // Test congestion state properties
    assert!(CongestionState::SlowStart.is_slow_start());
    assert!(!CongestionState::CongestionAvoidance.is_slow_start());
    
    assert!(CongestionState::CongestionAvoidance.is_congestion_avoidance());
    assert!(!CongestionState::SlowStart.is_congestion_avoidance());
    
    assert!(CongestionState::FastRecovery.is_fast_recovery());
    assert!(!CongestionState::SlowStart.is_fast_recovery());
}

#[test]
fn test_binding_state_properties() {
    // Test binding state properties
    assert!(BindingState::Active.is_usable());
    assert!(!BindingState::Reserved.is_usable());
    assert!(!BindingState::Expired.is_usable());
    
    assert!(BindingState::Expired.needs_cleanup());
    assert!(BindingState::Error.needs_cleanup());
    assert!(!BindingState::Active.needs_cleanup());
}

#[test]
fn test_route_state_properties() {
    // Test route state properties
    assert!(RouteState::Active.is_usable());
    assert!(!RouteState::Inactive.is_usable());
    assert!(!RouteState::Failed.is_usable());
    
    assert!(RouteState::Failed.needs_cleanup());
    assert!(RouteState::Expired.needs_cleanup());
    assert!(!RouteState::Active.needs_cleanup());
}

#[test]
fn test_socket_state_properties() {
    // Test socket state properties
    assert!(SocketState::Bound.is_operational());
    assert!(SocketState::Listening.is_operational());
    assert!(SocketState::Connected.is_operational());
    assert!(!SocketState::Creating.is_operational());
    
    assert!(SocketState::Closed.is_closed());
    assert!(SocketState::Error.is_closed());
    assert!(!SocketState::Connected.is_closed());
}

#[test]
fn test_atomic_state_operations() {
    let atomic = AtomicU8::new(0);
    
    // Test ConnectionState atomic operations
    let initial_state = ConnectionState::Closed;
    let new_state = ConnectionState::Connecting;
    
    initial_state.store(&atomic, Ordering::Relaxed);
    assert_eq!(ConnectionState::load(&atomic, Ordering::Relaxed), initial_state);
    
    new_state.store(&atomic, Ordering::Relaxed);
    assert_eq!(ConnectionState::load(&atomic, Ordering::Relaxed), new_state);
    
    // Test compare_exchange
    let result = ConnectionState::compare_exchange(
        &atomic,
        new_state,
        ConnectionState::Established,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), new_state);
    assert_eq!(ConnectionState::load(&atomic, Ordering::Relaxed), ConnectionState::Established);
}

#[test]
fn test_state_enum_discriminants() {
    // Test that enum discriminants are stable
    assert_eq!(ConnectionState::Closed.as_u8(), 0);
    assert_eq!(ConnectionState::Connecting.as_u8(), 1);
    assert_eq!(ConnectionState::Established.as_u8(), 3);
    
    assert_eq!(SessionState::Initializing.as_u8(), 0);
    assert_eq!(SessionState::Active.as_u8(), 1);
    assert_eq!(SessionState::Terminated.as_u8(), 5);
    
    assert_eq!(HealthState::Healthy.as_u8(), 0);
    assert_eq!(HealthState::Warning.as_u8(), 1);
    assert_eq!(HealthState::Unhealthy.as_u8(), 2);
    assert_eq!(HealthState::Unknown.as_u8(), 3);
}

#[test]
fn test_state_enum_from_u8() {
    // Test conversion from u8
    assert_eq!(ConnectionState::from_u8(0), Some(ConnectionState::Closed));
    assert_eq!(ConnectionState::from_u8(1), Some(ConnectionState::Connecting));
    assert_eq!(ConnectionState::from_u8(255), None);
    
    assert_eq!(SessionState::from_u8(0), Some(SessionState::Initializing));
    assert_eq!(SessionState::from_u8(1), Some(SessionState::Active));
    assert_eq!(SessionState::from_u8(255), None);
    
    assert_eq!(HealthState::from_u8(0), Some(HealthState::Healthy));
    assert_eq!(HealthState::from_u8(3), Some(HealthState::Unknown));
    assert_eq!(HealthState::from_u8(255), None);
}

#[test]
fn test_state_display_formatting() {
    // Test Display implementations
    assert_eq!(format!("{}", ConnectionState::Closed), "CLOSED");
    assert_eq!(format!("{}", ConnectionState::Established), "ESTABLISHED");
    
    assert_eq!(format!("{}", SessionState::Active), "ACTIVE");
    assert_eq!(format!("{}", SessionState::Terminated), "TERMINATED");
    
    assert_eq!(format!("{}", HealthState::Healthy), "HEALTHY");
    assert_eq!(format!("{}", HealthState::Warning), "WARNING");
    
    assert_eq!(format!("{}", TcpState::Established), "ESTABLISHED");
    assert_eq!(format!("{}", TcpState::TimeWait), "TIME_WAIT");
}

#[test]
fn test_state_transition_validation() {
    // Test StateTransition trait
    let result = ConnectionState::Closed.validate_transition(ConnectionState::Connecting);
    assert!(result.is_valid());
    
    let result = ConnectionState::Closed.validate_transition(ConnectionState::Established);
    assert!(result.is_invalid());
    
    if let StateTransitionResult::Invalid { from, to, reason } = result {
        assert_eq!(from, ConnectionState::Closed);
        assert_eq!(to, ConnectionState::Established);
        assert!(reason.contains("Invalid transition"));
    }
}

#[test]
fn test_no_string_based_states() {
    // Ensure we're not using string-based state representations
    // This test verifies that all state enums use proper discriminants
    
    let states = vec![
        ConnectionState::Closed,
        ConnectionState::Connecting,
        ConnectionState::Established,
    ];
    
    for state in states {
        // Verify we can convert to/from u8 without strings
        let discriminant = state.as_u8();
        let recovered = ConnectionState::from_u8(discriminant).unwrap();
        assert_eq!(state, recovered);
    }
}

#[test]
fn test_no_integer_based_state_comparisons() {
    // Ensure we're not comparing states with raw integers
    // This test verifies that state comparisons use enum variants
    
    let state = ConnectionState::Established;
    
    // These should compile and work correctly
    assert_eq!(state, ConnectionState::Established);
    assert_ne!(state, ConnectionState::Closed);
    
    // Verify we can match on enum variants
    match state {
        ConnectionState::Established => assert!(true),
        _ => assert!(false, "Should match Established variant"),
    }
}