use buckwild_common::protocol::fragment_overlap::*;
#[test]
    fn test_fragment_overlap_detector_creation() {
        let detector = FragmentOverlapDetector::new();
        let stats = detector.get_overlap_stats();
        
        assert_eq!(stats.total_checks, 0);
        assert_eq!(stats.overlaps_detected, 0);
        assert_eq!(stats.active_trackers, 0);
    }
    
    #[test]
    fn test_no_overlap_detection() {
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        let request = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = detector.check_overlap(&request).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.total_checks, 1);
        assert_eq!(stats.active_trackers, 1);
    }
    
    #[test]
    fn test_exact_duplicate_detection() {
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        let request = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First fragment should be accepted
        let result = detector.check_overlap(&request).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        // Second identical fragment should be detected as duplicate
        let result = detector.check_overlap(&request).unwrap();
        assert_eq!(result, OverlapDetectionResult::ExactDuplicate);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.total_checks, 2);
        assert_eq!(stats.constant_time_comparisons, 1);
    }
    
    #[test]
    fn test_conflicting_overlap_detection() {
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        let request1 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First fragment should be accepted
        let result = detector.check_overlap(&request1).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        // Second fragment with same range but different payload
        let request2 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x02; 100], // Different payload
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = detector.check_overlap(&request2).unwrap();
        assert_eq!(result, OverlapDetectionResult::SecurityViolation);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.security_violations, 1);
        assert_eq!(stats.constant_time_comparisons, 1);
    }
    
    #[test]
    fn test_partial_overlap_detection() {
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        let request1 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 3,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First fragment should be accepted
        let result = detector.check_overlap(&request1).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        // Second fragment with partial overlap (same payload in overlap region)
        let mut payload2 = vec![0x01; 50]; // Same as first fragment for overlap
        payload2.extend(vec![0x02; 50]); // Different for non-overlap
        
        let request2 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 1,
            fragment_offset: 50, // Overlaps with first fragment from 50-100
            fragment_length: 100,
            payload: payload2,
            expected_fragments: 3,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = detector.check_overlap(&request2).unwrap();
        assert_eq!(result, OverlapDetectionResult::PartialOverlap);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.overlaps_detected, 1);
        assert_eq!(stats.constant_time_comparisons, 1);
    }
    
    #[test]
    fn test_strict_overlap_detection() {
        let config = OverlapDetectionConfig {
            strict_overlap_detection: true,
            max_overlap_tolerance: 0,
            ..Default::default()
        };
        
        let detector = FragmentOverlapDetector::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        
        let request1 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First fragment should be accepted
        let result = detector.check_overlap(&request1).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        // Second fragment with any overlap should be rejected in strict mode
        let request2 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 1,
            fragment_offset: 50,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = detector.check_overlap(&request2).unwrap();
        assert_eq!(result, OverlapDetectionResult::FragmentRejected);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.fragment_rejections, 1);
    }
    
    #[test]
    fn test_complete_overlap_detection() {
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        let request1 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 200,
            payload: vec![0x01; 200],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First fragment should be accepted
        let result = detector.check_overlap(&request1).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        // Second fragment completely contained within first
        let request2 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 1,
            fragment_offset: 50,
            fragment_length: 100, // Completely within 0-200 range
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = detector.check_overlap(&request2).unwrap();
        assert_eq!(result, OverlapDetectionResult::CompleteOverlap);
    }
    
    #[test]
    fn test_tracker_info_retrieval() {
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 1;
        
        // Initially no tracker should exist
        assert!(detector.get_tracker_info(session_id, fragment_id).is_none());
        
        let request = OverlapCheckRequest {
            session_id,
            fragment_id,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // Add fragment to create tracker
        detector.check_overlap(&request).unwrap();
        
        // Now tracker should exist
        let tracker_info = detector.get_tracker_info(session_id, fragment_id).unwrap();
        assert_eq!(tracker_info.session_id, session_id.as_u64());
        assert_eq!(tracker_info.fragment_id, fragment_id);
        assert_eq!(tracker_info.expected_fragments, 2);
        assert_eq!(tracker_info.received_count, 1);
        assert_eq!(tracker_info.fragment_count, 1);
    }
    
    #[test]
    fn test_cleanup_expired_trackers() {
        let config = OverlapDetectionConfig {
            fragment_tracker_timeout_s: 1, // 1 second timeout for testing
            ..Default::default()
        };
        
        let detector = FragmentOverlapDetector::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        
        let request = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip: 0x7F000001,
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // Add fragment to create tracker
        detector.check_overlap(&request).unwrap();
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.active_trackers, 1);
        
        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Clean up expired trackers
        detector.cleanup_expired_trackers();
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.active_trackers, 0);
    }
