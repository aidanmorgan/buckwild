use buckwild_common::protocol::edge_cases::*;
use crate::protocol::packet::PacketBuilder;
    use crate::protocol::types::{SessionIdLength, TimestampConfig};
    
    #[test]
    fn test_packet_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        // Test valid packet
        let packet = PacketBuilder::new(PacketType::Data)
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(1)
            .build()
            .unwrap();
        
        assert!(handler.handle_packet_edge_cases(&packet).is_ok());
        
        // Test invalid version (would need custom packet creation)
        // This test would require creating a packet with version 0
        
        assert_eq!(handler.get_edge_cases_handled(), 1);
    }
    
    #[test]
    fn test_malformed_packet_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        // Test packet too short
        let short_packet = [0x01, 0x02];
        assert_eq!(
            handler.handle_malformed_packet_edge_cases(&short_packet),
            Err(EdgeCaseError::PacketTooShort)
        );
        
        // Test valid minimum packet
        let valid_packet = vec![0u8; EdgeCaseConstants::OPTIMIZED_COMMON_HEADER_SIZE];
        assert!(handler.handle_malformed_packet_edge_cases(&valid_packet).is_ok());
        
        assert_eq!(handler.get_edge_cases_handled(), 2);
    }
    
    #[test]
    fn test_fragmentation_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        // Test fragment index out of bounds
        assert_eq!(
            handler.handle_fragmentation_edge_cases(1, 5, 5, 100, &[1, 2, 3]),
            Err(EdgeCaseError::FragmentIndexOutOfBounds)
        );
        
        // Test too many fragments
        assert_eq!(
            handler.handle_fragmentation_edge_cases(1, 0, EdgeCaseConstants::MAX_FRAGMENTS + 1, 100, &[1, 2, 3]),
            Err(EdgeCaseError::TooManyFragments)
        );
        
        // Test valid fragment
        assert!(handler.handle_fragmentation_edge_cases(1, 0, 5, 100, &[1, 2, 3]).is_ok());
        
        assert_eq!(handler.get_edge_cases_handled(), 3);
    }
    
    #[test]
    fn test_time_sync_edge_cases() {
        let handler = EdgeCaseHandler::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Add session for testing
        handler.add_session(session_id);
        
        // Test normal time sync
        assert!(handler.handle_time_sync_edge_cases(session_id).is_ok());
        
        // Test with extreme time drift
        if let Some(session) = handler.sessions.get(&session_id.as_u64()) {
            session.time_offset.store(EdgeCaseConstants::MAX_EXTREME_TIME_DRIFT + 1000, Ordering::Relaxed);
        }
        
        assert_eq!(
            handler.handle_time_sync_edge_cases(session_id),
            Err(EdgeCaseError::ConnectionTerminate)
        );
        
        assert_eq!(handler.get_edge_cases_handled(), 2);
    }
    
    #[test]
    fn test_flow_control_edge_cases() {
        let handler = EdgeCaseHandler::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Add session for testing
        handler.add_session(session_id);
        
        // Set zero windows to trigger deadlock
        if let Some(session) = handler.sessions.get(&session_id.as_u64()) {
            session.peer_window_size.store(0, Ordering::Relaxed);
            session.local_window_size.store(0, Ordering::Relaxed);
        }
        
        // Should resolve deadlock
        assert!(handler.handle_flow_control_edge_cases(session_id).is_ok());
        
        // Check that deadlock was resolved
        if let Some(session) = handler.sessions.get(&session_id.as_u64()) {
            assert_eq!(session.local_window_size.load(Ordering::Relaxed), EdgeCaseConstants::MIN_DEADLOCK_WINDOW_SIZE);
        }
        
        assert_eq!(handler.get_edge_cases_handled(), 1);
    }
    
    #[test]
    fn test_recovery_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        // Test normal recovery
        assert!(handler.handle_recovery_edge_cases(1).is_ok());
        
        // Test recovery during recovery
        handler.recovery_state.recovery_in_progress.store(1, Ordering::Relaxed);
        handler.recovery_state.current_level.store(5, Ordering::Relaxed);
        
        // Higher priority should succeed
        assert!(handler.handle_recovery_edge_cases(6).is_ok());
        
        // Lower priority should fail
        assert_eq!(
            handler.handle_recovery_edge_cases(4),
            Err(EdgeCaseError::RecoveryInProgress)
        );
        
        assert_eq!(handler.get_edge_cases_handled(), 3);
    }
    
    #[test]
    fn test_connection_edge_cases() {
        let handler = EdgeCaseHandler::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Test normal connection
        assert!(handler.handle_connection_edge_cases(session_id, 0x7F000001).is_ok());
        
        // Test system shutdown
        handler.set_system_shutdown(true);
        assert_eq!(
            handler.handle_connection_edge_cases(session_id, 0x7F000001),
            Err(EdgeCaseError::SystemShuttingDown)
        );
        
        assert_eq!(handler.get_edge_cases_handled(), 2);
    }
    
    #[test]
    fn test_resource_exhaustion() {
        let handler = EdgeCaseHandler::new();
        
        // Test normal resource usage
        assert!(handler.handle_resource_exhaustion().is_ok());
        
        // Test memory exhaustion
        handler.update_memory_usage(EdgeCaseConstants::MIN_REQUIRED_MEMORY + 1000);
        assert_eq!(
            handler.handle_resource_exhaustion(),
            Err(EdgeCaseError::MemoryExhausted)
        );
        
        assert_eq!(handler.get_boundary_conditions_detected(), 2);
    }
    
    #[test]
    fn test_security_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        // Test normal timestamp
        assert!(handler.handle_security_edge_cases(0x7F000001, current_time).is_ok());
        
        // Test timestamp attack
        let attack_timestamp = current_time + EdgeCaseConstants::MAX_LEGITIMATE_CLOCK_SKEW + 1000;
        assert_eq!(
            handler.handle_security_edge_cases(0x7F000001, attack_timestamp),
            Err(EdgeCaseError::TimestampAttackDetected)
        );
        
        assert_eq!(handler.get_edge_cases_handled(), 2);
    }
    
    #[test]
    fn test_error_processing_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        // Test normal error
        assert!(handler.handle_error_processing_edge_cases(1).is_ok());
        
        // Test unknown error code
        assert_eq!(
            handler.handle_error_processing_edge_cases(999),
            Err(EdgeCaseError::UnknownError)
        );
        
        // Test error loop
        for _ in 0..EdgeCaseConstants::MAX_ERROR_RESPONSES {
            let _ = handler.handle_error_processing_edge_cases(1);
        }
        assert_eq!(
            handler.handle_error_processing_edge_cases(1),
            Err(EdgeCaseError::ErrorLoop)
        );
        
        assert!(handler.get_edge_cases_handled() > 10);
    }
    
    #[test]
    fn test_session_management() {
        let handler = EdgeCaseHandler::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Test adding session
        handler.add_session(session_id);
        assert_eq!(handler.get_active_connections(), 1);
        assert!(handler.sessions.contains_key(&session_id.as_u64()));
        
        // Test removing session
        handler.remove_session(session_id);
        assert_eq!(handler.get_active_connections(), 0);
        assert!(!handler.sessions.contains_key(&session_id.as_u64()));
    }
    
    #[test]
    fn test_cleanup_expired_entries() {
        let handler = EdgeCaseHandler::new();
        
        // Add some test data that would expire
        let _ = handler.handle_fragmentation_edge_cases(1, 0, 5, 100, &[1, 2, 3]);
        
        // Cleanup should not crash
        handler.cleanup_expired_entries();
        
        // Should still be able to handle new edge cases
        assert!(handler.handle_error_processing_edge_cases(1).is_ok());
    }
    
    #[test]
    fn test_concurrent_edge_case_handling() {
        use std::sync::Arc;
        use std::thread;
        
        let handler = Arc::new(EdgeCaseHandler::new());
        let mut handles = vec![];
        
        // Spawn multiple threads to handle edge cases concurrently
        for i in 0..10 {
            let handler_clone = Arc::clone(&handler);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let session_id = SessionId::Bits32((i * 1000 + j) as u32);
                    handler_clone.add_session(session_id);
                    let _ = handler_clone.handle_time_sync_edge_cases(session_id);
                    let _ = handler_clone.handle_flow_control_edge_cases(session_id);
                    handler_clone.remove_session(session_id);
                }
                i
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Check that all edge cases were handled
        assert!(handler.get_edge_cases_handled() >= 2000);
        assert_eq!(handler.get_active_connections(), 0);
    }
