use buckwild_common::protocol::fragment_reassembly::*;
#[test]
    fn test_fragment_reassembly_manager_creation() {
        let manager = FragmentReassemblyManager::new();
        let stats = manager.get_reassembly_stats();
        
        assert_eq!(stats.total_attempts, 0);
        assert_eq!(stats.successful_reassemblies, 0);
        assert_eq!(stats.active_sessions, 0);
    }
    
    #[test]
    fn test_successful_reassembly() {
        let manager = FragmentReassemblyManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Create two fragments
        let fragment1 = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let fragment2 = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 1,
            fragment_offset: 4,
            payload: vec![0x05, 0x06, 0x07, 0x08],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        // Add first fragment
        let result = manager.add_fragment(&fragment1).unwrap();
        assert_eq!(result, ReassemblyResult::FragmentAdded);
        
        // Add second fragment (should complete reassembly)
        let result = manager.add_fragment(&fragment2).unwrap();
        match result {
            ReassemblyResult::ReassemblyComplete(data) => {
                assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
            }
            _ => panic!("Expected ReassemblyComplete"),
        }
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.successful_reassemblies, 1);
        assert_eq!(stats.total_attempts, 2);
    }
    
    #[test]
    fn test_duplicate_fragment_detection() {
        let manager = FragmentReassemblyManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let fragment = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        // Add fragment first time
        let result = manager.add_fragment(&fragment).unwrap();
        assert_eq!(result, ReassemblyResult::FragmentAdded);
        
        // Add same fragment again (should be detected as duplicate)
        let result = manager.add_fragment(&fragment).unwrap();
        assert_eq!(result, ReassemblyResult::DuplicateFragment);
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.duplicate_fragments, 1);
    }
    
    #[test]
    fn test_conflicting_fragment_detection() {
        let manager = FragmentReassemblyManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let fragment1 = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let fragment2 = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0, // Same index
            fragment_offset: 0,
            payload: vec![0x05, 0x06, 0x07, 0x08], // Different payload
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        // Add first fragment
        let result = manager.add_fragment(&fragment1).unwrap();
        assert_eq!(result, ReassemblyResult::FragmentAdded);
        
        // Add conflicting fragment (should be detected as security violation)
        let result = manager.add_fragment(&fragment2).unwrap();
        assert_eq!(result, ReassemblyResult::SecurityViolation);
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.security_violations, 1);
    }
    
    #[test]
    fn test_bounds_checking() {
        let config = ReassemblyConfig {
            max_reassembled_size: 10, // Very small limit for testing
            ..Default::default()
        };
        
        let manager = FragmentReassemblyManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let fragment = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01; 20], // Exceeds limit
            expected_fragments: 1,
            source_ip,
            arrival_time: current_time,
        };
        
        let result = manager.add_fragment(&fragment).unwrap();
        assert_eq!(result, ReassemblyResult::BoundsCheckFailure);
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.bounds_check_failures, 1);
    }
    
    #[test]
    fn test_source_validation() {
        let manager = FragmentReassemblyManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip1 = 0x7F000001;
        let source_ip2 = 0x7F000002;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let fragment1 = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            expected_fragments: 2,
            source_ip: source_ip1,
            arrival_time: current_time,
        };
        
        let fragment2 = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 1,
            fragment_offset: 4,
            payload: vec![0x05, 0x06, 0x07, 0x08],
            expected_fragments: 2,
            source_ip: source_ip2, // Different source IP
            arrival_time: current_time,
        };
        
        // Add first fragment
        let result = manager.add_fragment(&fragment1).unwrap();
        assert_eq!(result, ReassemblyResult::FragmentAdded);
        
        // Add fragment from different source (should be security violation)
        let result = manager.add_fragment(&fragment2).unwrap();
        assert_eq!(result, ReassemblyResult::SecurityViolation);
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.security_violations, 1);
    }
    
    #[test]
    fn test_invalid_parameters() {
        let manager = FragmentReassemblyManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Empty payload
        let fragment = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![], // Empty payload
            expected_fragments: 1,
            source_ip,
            arrival_time: current_time,
        };
        
        let result = manager.add_fragment(&fragment).unwrap();
        assert_eq!(result, ReassemblyResult::InvalidParameters);
        
        // Fragment index out of range
        let fragment = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 5, // Index >= expected_fragments
            fragment_offset: 0,
            payload: vec![0x01, 0x02],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let result = manager.add_fragment(&fragment).unwrap();
        assert_eq!(result, ReassemblyResult::InvalidParameters);
    }
    
    #[test]
    fn test_session_info_retrieval() {
        let manager = FragmentReassemblyManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Initially no session should exist
        assert!(manager.get_session_info(session_id, fragment_id).is_none());
        
        let fragment = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        // Add fragment to create session
        manager.add_fragment(&fragment).unwrap();
        
        // Now session should exist
        let session_info = manager.get_session_info(session_id, fragment_id).unwrap();
        assert_eq!(session_info.session_id, session_id.as_u64());
        assert_eq!(session_info.fragment_id, fragment_id);
        assert_eq!(session_info.expected_fragments, 2);
        assert_eq!(session_info.received_count, 1);
        assert_eq!(session_info.source_ip, source_ip);
        assert!(!session_info.is_complete);
    }
    
    #[test]
    fn test_cleanup_expired_sessions() {
        let config = ReassemblyConfig {
            reassembly_timeout_s: 1, // 1 second timeout for testing
            enable_automatic_cleanup: false, // Disable automatic cleanup
            ..Default::default()
        };
        
        let manager = FragmentReassemblyManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let fragment = ReassemblyRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        // Add fragment to create session
        manager.add_fragment(&fragment).unwrap();
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.active_sessions, 1);
        
        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Clean up expired sessions
        manager.cleanup_expired_sessions();
        
        let stats = manager.get_reassembly_stats();
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.timeout_cleanups, 1);
    }
