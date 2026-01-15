use buckwild_common::protocol::duplicate_detection::*;
use std::net::IpAddr;

    #[test]
    fn test_unique_packet_detection() {
        let detector = DuplicateDetector::new(1000);
        
        let result = detector.detect_duplicate(
            12345,
            67890,
            1,
            Some(IpAddr::from([192, 168, 1, 1])),
        ).unwrap();

        assert_eq!(result, DuplicateDetectionResult::Unique);
    }

    #[test]
    fn test_duplicate_packet_detection() {
        let detector = DuplicateDetector::new(1000);
        
        // First packet should be unique
        let result1 = detector.detect_duplicate(12345, 67890, 1, None).unwrap();
        assert_eq!(result1, DuplicateDetectionResult::Unique);

        // Second identical packet should be duplicate
        let result2 = detector.detect_duplicate(12345, 67890, 1, None).unwrap();
        assert_eq!(result2, DuplicateDetectionResult::Duplicate);
    }

    #[test]
    fn test_legitimate_reorder_detection() {
        let detector = DuplicateDetector::new(1000);
        
        // Add packet with sequence 100
        detector.detect_duplicate(12345, 67890, 100, None).unwrap();
        
        // Packet with sequence 95 should be legitimate reorder
        let result = detector.detect_duplicate(12346, 67890, 95, None).unwrap();
        assert_eq!(result, DuplicateDetectionResult::LegitimateReorder);
    }

    #[test]
    fn test_sequence_validation() {
        let detector = DuplicateDetector::new(1000);
        
        // Sequence within window should be valid
        assert!(detector.validate_sequence_order(12345, 105, 100).unwrap());
        
        // Sequence far outside window should be invalid
        assert!(!detector.validate_sequence_order(12345, 300, 100).unwrap());
    }

    #[test]
    fn test_cache_cleanup() {
        let detector = DuplicateDetector::new(1000);
        
        // Add some entries
        for i in 0..10 {
            detector.detect_duplicate(i, 12345, i as u32, None).unwrap();
        }

        let info_before = detector.get_cache_info();
        assert_eq!(info_before.current_size, 10);

        // Cleanup with very short max age should remove all entries
        let removed = detector.cleanup_expired_entries(Duration::from_nanos(1)).unwrap();
        assert_eq!(removed, 10);

        let info_after = detector.get_cache_info();
        assert_eq!(info_after.current_size, 0);
    }

    #[test]
    fn test_key_validation() {
        let detector = DuplicateDetector::new(1000);
        
        let valid_key = CompositeKey {
            timestamp: 12345,
            session_id: 67890,
            sequence_number: 1,
        };
        assert!(detector.validate_key_components(&valid_key));

        let invalid_key = CompositeKey {
            timestamp: 0,
            session_id: 0,
            sequence_number: u32::MAX,
        };
        assert!(!detector.validate_key_components(&invalid_key));
    }

    #[test]
    fn test_statistics_tracking() {
        let detector = DuplicateDetector::new(1000);
        
        // Process some packets
        detector.detect_duplicate(1, 1, 1, None).unwrap(); // Unique
        detector.detect_duplicate(1, 1, 1, None).unwrap(); // Duplicate
        detector.detect_duplicate(2, 1, 2, None).unwrap(); // Unique

        let stats = detector.get_stats();
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.duplicates_detected, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 2);
    }
