// Tests for the session module
//
// This file contains tests for the session module, including SessionState and SessionManager.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use buckwild_common::session::{SessionState, SessionStatus, WindowState, SessionManager};
use buckwild_common::protocol::types::{
    SessionId, SequenceNumber, Port, WindowSize, CongestionWindow, 
    RoundTripTime, TimeOffset, MicrosecondTimestamp, SessionCount, Counter
};
use buckwild_common::crypto::SecureBytes;

#[test]
fn test_session_state_basic() {
    let session = SessionState::new();
    
    // Test default values
    assert_eq!(session.status(), SessionStatus::Initializing);
    assert_eq!(session.local_seq(), SequenceNumber::new(0));
    assert_eq!(session.remote_seq(), SequenceNumber::new(0));
    assert_eq!(session.local_port(), Port::new(0));
    assert_eq!(session.remote_port(), Port::new(0));
    assert_eq!(session.time_offset(), TimeOffset::new(0));
    
    // Test setters
    session.set_status(SessionStatus::Established);
    session.set_local_seq(SequenceNumber::new(1000));
    session.set_remote_seq(SequenceNumber::new(2000));
    session.set_local_port(Port::new(8000));
    session.set_remote_port(Port::new(9000));
    session.set_time_offset(TimeOffset::new(50));
    
    assert_eq!(session.status(), SessionStatus::Established);
    assert_eq!(session.local_seq(), SequenceNumber::new(1000));
    assert_eq!(session.remote_seq(), SequenceNumber::new(2000));
    assert_eq!(session.local_port(), Port::new(8000));
    assert_eq!(session.remote_port(), Port::new(9000));
    assert_eq!(session.time_offset(), TimeOffset::new(50));
}

#[test]
fn test_session_state_sequence_numbers() {
    let session = SessionState::new();
    
    // Test sequence number increment
    session.set_local_seq(SequenceNumber::new(1000));
    assert_eq!(session.increment_local_seq(), SequenceNumber::new(1001));
    assert_eq!(session.local_seq(), SequenceNumber::new(1001));
    
    // Test remote sequence update
    session.set_remote_seq(SequenceNumber::new(2000));
    assert!(session.update_remote_seq(SequenceNumber::new(2500)));
    assert_eq!(session.remote_seq(), SequenceNumber::new(2500));
    assert!(!session.update_remote_seq(SequenceNumber::new(2000)));  // Lower value should be ignored
    assert_eq!(session.remote_seq(), SequenceNumber::new(2500));  // Value should not change
}

#[test]
fn test_session_state_activity() {
    let session = SessionState::new();
    
    // Test activity update
    let initial_activity = session.last_activity();
    thread::sleep(Duration::from_secs(1));
    session.update_activity();
    assert!(session.last_activity() > initial_activity);
    
    // Test idle detection
    assert!(!session.is_idle(Duration::from_secs(10)));
    assert!(session.is_idle(Duration::from_millis(1)));
}

#[test]
fn test_window_state() {
    let window = WindowState::new();
    
    // Test default values
    assert_eq!(window.send_window(), WindowSize::new(65535));
    assert_eq!(window.recv_window(), WindowSize::new(65535));
    assert_eq!(window.congestion_window(), CongestionWindow::new(1460));
    assert_eq!(window.ssthresh(), WindowSize::new(65535));
    assert_eq!(window.rtt(), RoundTripTime::new(100_000));
    assert_eq!(window.rtt_var(), RoundTripTime::new(50_000));
    assert_eq!(window.rto(), RoundTripTime::new(300_000));
    
    // Test setters
    window.set_send_window(WindowSize::new(32768));
    window.set_recv_window(WindowSize::new(16384));
    window.set_congestion_window(CongestionWindow::new(2920));
    window.set_ssthresh(WindowSize::new(32768));
    window.set_rtt(RoundTripTime::new(200_000));
    window.set_rtt_var(RoundTripTime::new(100_000));
    window.set_rto(RoundTripTime::new(600_000));
    
    assert_eq!(window.send_window(), WindowSize::new(32768));
    assert_eq!(window.recv_window(), WindowSize::new(16384));
    assert_eq!(window.congestion_window(), CongestionWindow::new(2920));
    assert_eq!(window.ssthresh(), WindowSize::new(32768));
    assert_eq!(window.rtt(), RoundTripTime::new(200_000));
    assert_eq!(window.rtt_var(), RoundTripTime::new(100_000));
    assert_eq!(window.rto(), RoundTripTime::new(600_000));
    
    // Test RTT update
    window.update_rtt(RoundTripTime::new(150_000));
    assert!(window.rtt() < RoundTripTime::new(200_000));  // Should decrease toward 150_000
    assert!(window.rtt() > RoundTripTime::new(150_000));  // But not all the way in one update
    
    // Test RTO backoff
    let initial_rto = window.rto();
    window.backoff_rto();
    assert_eq!(window.rto(), initial_rto * 2);
}

#[test]
fn test_session_manager_basic() {
    let manager = SessionManager::default();
    
    // Test session creation
    let (id, session) = manager.create_session();
    
    // Check that the session exists
    let retrieved = manager.get_session(&id);
    assert!(retrieved.is_some());
    
    // Check that the session is the same
    assert!(Arc::ptr_eq(&session, &retrieved.unwrap()));
    
    // Check session count
    assert_eq!(manager.session_count(), SessionCount::new(1));
    
    // Test session removal
    assert!(manager.remove_session(&id));
    
    // Check that the session no longer exists
    assert!(manager.get_session(&id).is_none());
    
    // Check session count
    assert_eq!(manager.session_count(), SessionCount::new(0));
}

#[test]
fn test_session_manager_cleanup() {
    let mut manager = SessionManager::new(
        Duration::from_millis(10),  // Cleanup every 10ms
        Duration::from_millis(50),  // Idle timeout after 50ms
    );
    
    // Create a session
    let (id, session) = manager.create_session();
    
    // Update activity
    session.update_activity();
    
    // Wait for the session to become idle
    thread::sleep(Duration::from_millis(100));
    
    // Clean up sessions
    let removed = manager.cleanup_sessions();
    assert_eq!(removed, SessionCount::new(1));
    
    // Check that the session no longer exists
    assert!(manager.get_session(&id).is_none());
    
    // Check session count
    assert_eq!(manager.session_count(), SessionCount::new(0));
}

#[test]
fn test_port_calculation() {
    let manager = SessionManager::default();
    
    // Create a session
    let (_, session) = manager.create_session();
    
    // Set port hopping parameters
    session.set_port_hop_param(0, 0x1234);
    session.set_port_hop_param(1, 0x5678);
    session.set_port_hop_param(2, 0x9ABC);
    session.set_port_hop_param(3, 0xDEF0);
    
    // Calculate ports for different time buckets
    let port1_local = manager.calculate_port(&session, 1, true);
    let port1_remote = manager.calculate_port(&session, 1, false);
    let port2_local = manager.calculate_port(&session, 2, true);
    let port2_remote = manager.calculate_port(&session, 2, false);
    
    // Check that ports are in the correct range
    assert!(port1_local.as_u16() >= 49152 && port1_local.as_u16() <= 65535);
    assert!(port1_remote.as_u16() >= 49152 && port1_remote.as_u16() <= 65535);
    assert!(port2_local.as_u16() >= 49152 && port2_local.as_u16() <= 65535);
    assert!(port2_remote.as_u16() >= 49152 && port2_remote.as_u16() <= 65535);
    
    // Check that ports are different
    assert_ne!(port1_local, port1_remote);
    assert_ne!(port1_local, port2_local);
    assert_ne!(port1_remote, port2_remote);
    
    // Check that ports are deterministic
    assert_eq!(port1_local, manager.calculate_port(&session, 1, true));
    assert_eq!(port1_remote, manager.calculate_port(&session, 1, false));
}

#[test]
fn test_concurrent_session_access() {
    let session = Arc::new(SessionState::new());
    let session_clone = session.clone();
    
    // Spawn a thread to update the session
    let thread = thread::spawn(move || {
        for i in 0..1000 {
            session_clone.increment_local_seq();
            session_clone.update_remote_seq(SequenceNumber::new(i + 1));
            
            if i % 100 == 0 {
                session_clone.update_activity();
            }
        }
    });
    
    // Update the session in the main thread
    for i in 0..1000 {
        session.increment_local_seq();
        session.update_remote_seq(SequenceNumber::new(1000 + i + 1));
        
        if i % 100 == 0 {
            session.update_activity();
        }
    }
    
    // Wait for the thread to finish
    thread.join().unwrap();
    
    // Check the final values
    assert_eq!(session.local_seq(), SequenceNumber::new(2000));
    assert!(session.remote_seq() >= SequenceNumber::new(1000));
}

#[test]
fn test_concurrent_session_manager() {
    let manager = Arc::new(SessionManager::default());
    let manager_clone = manager.clone();
    
    // Create some initial sessions
    let mut session_ids = Vec::new();
    for _ in 0..10 {
        let (id, _) = manager.create_session();
        session_ids.push(id);
    }
    
    // Spawn a thread to create and remove sessions
    let thread = thread::spawn(move || {
        for _ in 0..100 {
            let (id, _) = manager_clone.create_session();
            
            // Randomly remove some sessions
            if rand::random::<bool>() {
                manager_clone.remove_session(&id);
            }
        }
    });
    
    // Create and remove sessions in the main thread
    for _ in 0..100 {
        let (id, _) = manager.create_session();
        
        // Randomly remove some sessions
        if rand::random::<bool>() {
            manager.remove_session(&id);
        }
    }
    
    // Wait for the thread to finish
    thread.join().unwrap();
    
    // Check that we can still access the initial sessions
    for id in session_ids {
        // This should not panic even if the session was removed
        let _ = manager.get_session(&id);
    }
}