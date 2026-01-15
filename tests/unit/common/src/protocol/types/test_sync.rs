use buckwild_common::protocol:types::sync::*;
use std::thread;
    use std::time::Duration;

    #[test]
    fn test_aligned_session_state() {
        let session = AlignedSessionState::new(12345);
        
        // Test basic operations
        assert_eq!(session.session_id.load(Ordering::Relaxed), 12345);
        assert!(session.active());
        
        // Test sequence number operations
        let old_seq = session.increment_sequence();
        assert_eq!(old_seq, 0);
        assert_eq!(session.sequence_number.load(Ordering::Relaxed), 1);
        
        // Test activity tracking
        session.touch();
        assert!(!session.is_expired(1_000_000_000)); // 1 second
        
        // Test deactivation
        session.deactivate();
        assert!(!session.active());
    }

    #[test]
    fn test_aligned_port_state() {
        let port_state = AlignedPortState::new(8080, 1000, 500_000_000);
        
        assert_eq!(port_state.current(), 8080);
        assert!(!port_state.should_hop()); // Not hopping initially
        
        port_state.start_hopping();
        port_state.set_next_port(8081);
        
        let old_port = port_state.hop_to_port(8081);
        assert_eq!(old_port, 8080);
        assert_eq!(port_state.current(), 8081);
        assert_eq!(port_state.hop_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_aligned_time_state() {
        let time_state = AlignedTimeState::new();
        
        assert!(!time_state.is_synchronized.load(Ordering::Relaxed));
        assert!(time_state.synchronized_time().is_none());
        
        time_state.update_sync(1000, 2000, 500_000); // 500 microseconds RTT
        
        assert!(time_state.is_synchronized.load(Ordering::Relaxed));
        assert!(time_state.synchronized_time().is_some());
        assert!(time_state.sync_quality.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_aligned_fragment_state() {
        let fragment_state = AlignedFragmentState::new(123, 3, 4500);
        
        assert!(!fragment_state.is_complete());
        assert_eq!(fragment_state.completion_percentage(), 0.0);
        
        // Add fragments
        assert!(!fragment_state.add_fragment(1500)); // Not complete yet
        assert!(!fragment_state.add_fragment(1500)); // Still not complete
        assert!(fragment_state.add_fragment(1500));  // Now complete
        
        assert!(fragment_state.is_complete());
        assert_eq!(fragment_state.completion_percentage(), 1.0);
        assert_eq!(fragment_state.received_size.load(Ordering::Relaxed), 4500);
    }

    #[test]
    fn test_lock_free_session_manager() {
        let manager = LockFreeSessionManager::new(1_000_000_000, 500_000_000);
        
        // Create session
        let session = manager.create_session(12345);
        assert_eq!(session.session_id.load(Ordering::Relaxed), 12345);
        assert_eq!(manager.session_count(), 1);
        
        // Get session
        let retrieved = manager.get_session(12345).unwrap();
        assert_eq!(retrieved.session_id.load(Ordering::Relaxed), 12345);
        
        // Get associated states
        let port_state = manager.get_port_state(12345).unwrap();
        let time_state = manager.get_time_state(12345).unwrap();
        
        assert_eq!(port_state.current(), 8080);
        assert!(!time_state.is_synchronized.load(Ordering::Relaxed));
        
        // Remove session
        assert!(manager.remove_session(12345));
        assert_eq!(manager.session_count(), 0);
        assert!(manager.get_session(12345).is_none());
    }

    #[test]
    fn test_concurrent_access() {
        let session = Arc::new(AlignedSessionState::new(12345));
        let mut handles = vec![];
        
        // Spawn multiple threads to increment sequence number
        for _ in 0..10 {
            let session_clone = session.clone();
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    session_clone.increment_sequence();
                }
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify final sequence number
        assert_eq!(session.sequence_number.load(Ordering::Relaxed), 10000);
    }

    #[test]
    fn test_cache_line_alignment() {
        let session = AlignedSessionState::new(12345);
        let ptr = &session as *const _ as usize;
        assert_eq!(ptr % 64, 0); // Should be 64-byte aligned
        
        let port_state = AlignedPortState::new(8080, 1000, 500_000_000);
        let ptr = &port_state as *const _ as usize;
        assert_eq!(ptr % 64, 0); // Should be 64-byte aligned
        
        let time_state = AlignedTimeState::new();
        let ptr = &time_state as *const _ as usize;
        assert_eq!(ptr % 64, 0); // Should be 64-byte aligned
    }
