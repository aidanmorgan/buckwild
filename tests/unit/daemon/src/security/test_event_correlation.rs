use buckwild_daemon::security::event_correlation::*;
use std::net::Ipv4Addr;

    #[test]
    fn test_event_recording() {
        let correlator = SecurityEventCorrelator::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        let event_id = correlator.record_event(
            SecurityEventType::AuthenticationFailure,
            EventSeverity::Medium,
            Some(source_ip),
            Some("test_target".to_string()),
            Some(12345),
            HashMap::new(),
        ).unwrap();

        assert!(!event_id.is_nil());
        
        let stats = correlator.get_stats();
        assert_eq!(stats.total_events, 1);
    }

    #[test]
    fn test_brute_force_detection() {
        let correlator = SecurityEventCorrelator::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Generate multiple authentication failures
        for _ in 0..15 {
            correlator.record_event(
                SecurityEventType::AuthenticationFailure,
                EventSeverity::Medium,
                Some(source_ip),
                None,
                None,
                HashMap::new(),
            ).unwrap();
        }

        let incidents = correlator.get_active_incidents();
        assert!(!incidents.is_empty());
        assert_eq!(incidents[0].incident_type, IncidentType::BruteForce);
    }

    #[test]
    fn test_incident_resolution() {
        let correlator = SecurityEventCorrelator::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Create incident
        for _ in 0..15 {
            correlator.record_event(
                SecurityEventType::AuthenticationFailure,
                EventSeverity::Medium,
                Some(source_ip),
                None,
                None,
                HashMap::new(),
            ).unwrap();
        }

        let incidents = correlator.get_active_incidents();
        assert!(!incidents.is_empty());
        
        let incident_id = incidents[0].incident_id;
        let resolved = correlator.resolve_incident(incident_id, IncidentStatus::Resolved).unwrap();
        assert!(resolved);
    }

    #[test]
    fn test_cleanup() {
        let correlator = SecurityEventCorrelator::new();
        
        // Add some events
        for i in 0..5 {
            correlator.record_event(
                SecurityEventType::AuthenticationFailure,
                EventSeverity::Low,
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8 + 1))),
                None,
                None,
                HashMap::new(),
            ).unwrap();
        }

        let stats_before = correlator.get_stats();
        assert_eq!(stats_before.total_events, 5);

        // Cleanup should not remove recent events
        let (events_removed, incidents_removed) = correlator.cleanup_old_entries().unwrap();
        assert_eq!(events_removed, 0);
        assert_eq!(incidents_removed, 0);
    }
