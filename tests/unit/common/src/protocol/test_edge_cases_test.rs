use buckwild_common::protocol::edge_cases_test::*;

    use super::super::edge_cases::{EdgeCaseHandler, EdgeCaseError, EdgeCaseConstants};
    use super::super::boundary_conditions::{
        BoundaryConditionManager, BoundaryConditionType, BoundaryConditionSeverity
    };
    use super::super::header::SessionId;
    use std::sync::atomic::Ordering;
    
    #[test]
    fn test_edge_case_handler_creation() {
        let handler = EdgeCaseHandler::new();
        assert_eq!(handler.get_edge_cases_handled(), 0);
        assert_eq!(handler.get_boundary_conditions_detected(), 0);
        assert_eq!(handler.get_active_connections(), 0);
    }
    
    #[test]
    fn test_malformed_packet_handling() {
        let handler = EdgeCaseHandler::new();
        
        // Test packet too short
        let short_packet = [0x01, 0x02];
        assert_eq!(
            handler.handle_malformed_packet_edge_cases(&short_packet),
            Err(EdgeCaseError::PacketTooShort)
        );
        
        // Test minimum valid packet
        let min_packet = vec![0u8; EdgeCaseConstants::OPTIMIZED_COMMON_HEADER_SIZE];
        assert!(handler.handle_malformed_packet_edge_cases(&min_packet).is_ok());
        
        // Verify edge cases were handled
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
        
        // Test empty final fragment
        assert_eq!(
            handler.handle_fragmentation_edge_cases(2, 4, 5, 100, &[]),
            Err(EdgeCaseError::EmptyFinalFragment)
        );
        
        // Verify edge cases were handled
        assert_eq!(handler.get_edge_cases_handled(), 4);
    }
    
    #[test]
    fn test_time_sync_edge_cases() {
        let handler = EdgeCaseHandler::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Add session for testing
        handler.add_session(session_id);
        assert_eq!(handler.get_active_connections(), 1);
        
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
        
        // Verify edge cases were handled
        assert_eq!(handler.get_edge_cases_handled(), 2);
        
        // Remove session
        handler.remove_session(session_id);
        assert_eq!(handler.get_active_connections(), 0);
    }
    
    #[test]
    fn test_flow_control_edge_cases() {
        let handler = EdgeCaseHandler::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Add session
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
            assert_eq!(
                session.local_window_size.load(Ordering::Relaxed),
                EdgeCaseConstants::MIN_DEADLOCK_WINDOW_SIZE
            );
        }
        
        assert_eq!(handler.get_edge_cases_handled(), 1);
    }
    
    #[test]
    fn test_recovery_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        // Test normal recovery
        assert!(handler.handle_recovery_edge_cases(1).is_ok());
        
        // Test recovery during recovery with higher priority
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
        
        // Test send buffer overflow
        handler.update_memory_usage(0);
        handler.update_send_buffer_usage(EdgeCaseConstants::MAX_SEND_BUFFER_SIZE + 1000);
        assert_eq!(
            handler.handle_resource_exhaustion(),
            Err(EdgeCaseError::SendBufferOverflow)
        );
        
        assert_eq!(handler.get_boundary_conditions_detected(), 3);
    }
    
    #[test]
    fn test_security_edge_cases() {
        let handler = EdgeCaseHandler::new();
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
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
    fn test_boundary_condition_manager() {
        let manager = BoundaryConditionManager::new();
        
        // Test boundary condition handling
        assert!(manager.handle_boundary_condition(
            BoundaryConditionType::MemoryExhaustion,
            None,
            BoundaryConditionSeverity::Warning,
            "Test memory condition".to_string(),
        ).is_ok());
        
        // Check statistics
        let stats = manager.get_stats();
        assert_eq!(stats.total_conditions_detected.load(Ordering::Relaxed), 1);
        
        // Test resource boundary checks
        manager.set_memory_thresholds(100, 200);
        manager.set_connection_thresholds(5, 10);
        
        // Should pass with no load
        assert!(manager.check_resource_boundaries().is_ok());
        
        // Add connections to trigger warnings
        for i in 0..6 {
            manager.edge_case_handler.add_session(SessionId::Bits32(i));
        }
        
        // Should trigger warning
        assert!(manager.check_resource_boundaries().is_ok());
        
        // Check that warning was recorded
        let stats = manager.get_stats();
        assert!(stats.total_conditions_detected.load(Ordering::Relaxed) > 1);
    }
    
    #[test]
    fn test_sequence_wraparound_monitoring() {
        let manager = BoundaryConditionManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Normal sequence should pass
        assert!(manager.check_sequence_wraparound(session_id, 1000).is_ok());
        
        // High sequence should trigger warning
        let high_sequence = EdgeCaseConstants::SEQUENCE_WRAP_THRESHOLD + 100;
        assert!(manager.check_sequence_wraparound(session_id, high_sequence).is_ok());
        
        // Check warning was recorded
        let stats = manager.get_stats();
        assert_eq!(stats.total_conditions_detected.load(Ordering::Relaxed), 1);
    }
    
    #[test]
    fn test_cleanup_and_maintenance() {
        let handler = EdgeCaseHandler::new();
        
        // Add some test data
        for i in 0..10 {
            let _ = handler.handle_fragmentation_edge_cases(i, 0, 5, 100, &[1, 2, 3]);
        }
        
        // Cleanup should not crash
        handler.cleanup_expired_entries();
        
        // Should still be able to handle new edge cases
        assert!(handler.handle_error_processing_edge_cases(1).is_ok());
        
        assert!(handler.get_edge_cases_handled() >= 11);
    }
    
    #[test]
    fn test_concurrent_edge_case_handling() {
        use std::sync::Arc;
        use std::thread;
        
        let handler = Arc::new(EdgeCaseHandler::new());
        let mut handles = vec![];
        
        // Spawn multiple threads to handle edge cases concurrently
        for i in 0..5 {
            let handler_clone = Arc::clone(&handler);
            let handle = thread::spawn(move || {
                for j in 0..20 {
                    let session_id = SessionId::Bits32((i * 100 + j) as u32);
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
        assert!(handler.get_edge_cases_handled() >= 200);
        assert_eq!(handler.get_active_connections(), 0);
    }
    
    #[test]
    fn test_boundary_condition_recovery() {
        let manager = BoundaryConditionManager::new();
        
        // Test different severity levels
        let severities = [
            BoundaryConditionSeverity::Info,
            BoundaryConditionSeverity::Warning,
            BoundaryConditionSeverity::Error,
            BoundaryConditionSeverity::Critical,
        ];
        
        for severity in severities {
            let result = manager.handle_boundary_condition(
                BoundaryConditionType::MemoryExhaustion,
                None,
                severity,
                format!("Test {} condition", severity),
            );
            
            // Should handle all non-fatal severities
            assert!(result.is_ok(), "Failed for severity: {:?}", severity);
        }
        
        // Check that all conditions were recorded
        let stats = manager.get_stats();
        assert_eq!(stats.total_conditions_detected.load(Ordering::Relaxed), 4);
    }
    
    #[test]
    fn test_event_history_management() {
        let manager = BoundaryConditionManager::new();
        
        // Add many events
        for i in 0..50 {
            let _ = manager.handle_boundary_condition(
                BoundaryConditionType::MemoryExhaustion,
                Some(SessionId::Bits32(i)),
                BoundaryConditionSeverity::Info,
                format!("Test event {}", i),
            );
        }
        
        // Should be able to retrieve recent events
        let events = manager.get_recent_events(10);
        assert!(events.len() <= 50);
        assert!(events.len() >= 10);
        
        // Cleanup should work
        manager.cleanup_and_maintenance();
        
        // Should still be functional
        assert!(manager.handle_boundary_condition(
            BoundaryConditionType::MemoryExhaustion,
            None,
            BoundaryConditionSeverity::Info,
            "Post-cleanup test".to_string(),
        ).is_ok());
    }
