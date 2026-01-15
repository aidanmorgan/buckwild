use buckwild_common::protocol:types::mod::*;
#[test]
    fn test_generic_id() {
        let conn_id = ConnectionId::generate();
        assert_ne!(conn_id.as_raw(), 0);
        
        let pkt_id = PacketId::new(100);
        let next = pkt_id.next();
        assert_eq!(next.as_raw(), 101);
        
        let frag_id = FragmentId::new(100);
        let next = frag_id.next();
        assert_eq!(next.as_raw(), 101);
        
        let epoch = EpochId::new(100);
        let next = epoch.next();
        let prev = epoch.prev();
        
        assert_eq!(next.as_raw(), 101);
        assert_eq!(prev.as_raw(), 99);
    }
    
    #[test]
    fn test_generic_duration() {
        let timeout = TimeoutMs::new(5000);
        assert_eq!(timeout.as_ms(), 5000);
        assert_eq!(timeout.as_duration(), std::time::Duration::from_millis(5000));
        
        let interval = IntervalMs::new(1000);
        assert_eq!(interval.as_ms(), 1000);
        assert_eq!(interval.as_duration(), std::time::Duration::from_millis(1000));
        
        let duration = DurationSec::new(30);
        assert_eq!(duration.as_sec(), 30);
        assert_eq!(duration.as_duration(), std::time::Duration::from_secs(30));
    }
    
    #[test]
    fn test_generic_limit() {
        let window = WindowSize::new(65536);
        assert_eq!(window.as_u32(), 65536);
        assert!(!window.is_zero());
        
        let threshold = Threshold::new(1000);
        assert!(threshold.is_exceeded(1500));
        assert!(!threshold.is_exceeded(500));
        
        let limit = SizeLimit::new(1000);
        assert!(limit.is_exceeded(1500));
        assert!(!limit.is_exceeded(500));
    }
    
    #[test]
    fn test_atomic_port_number() {
        let port = AtomicPortNumber::new(8080);
        assert_eq!(port.load(Ordering::Relaxed), 8080);
        assert!(AtomicPortNumber::is_valid(8080));
        assert!(!AtomicPortNumber::is_well_known(8080));
        assert!(!AtomicPortNumber::is_ephemeral(8080));
        assert!(AtomicPortNumber::is_registered(8080));
        
        let well_known = AtomicPortNumber::new(80);
        assert!(AtomicPortNumber::is_well_known(80));
        
        let ephemeral = AtomicPortNumber::new(50000);
        assert!(AtomicPortNumber::is_ephemeral(50000));
        
        assert!(!AtomicPortNumber::is_valid(0));
    }
    
    #[test]
    fn test_connection_id() {
        let conn_id = ConnectionId::generate();
        assert_ne!(conn_id.as_raw(), 0);
        
        let conn_id2 = ConnectionId::new(12345);
        assert_eq!(conn_id2.as_raw(), 12345);
    }
    
    #[test]
    fn test_packet_id() {
        let pkt_id = PacketId::new(100);
        let next = pkt_id.next();
        assert_eq!(next.as_raw(), 101);
    }
    
    #[test]
    fn test_fragment_id() {
        let frag_id = FragmentId::new(100);
        let next = frag_id.next();
        assert_eq!(next.as_raw(), 101);
    }
    
    #[test]
    fn test_epoch_id() {
        let epoch = EpochId::new(100);
        let next = epoch.next();
        let prev = epoch.prev();
        
        assert_eq!(next.as_raw(), 101);
        assert_eq!(prev.as_raw(), 99);
    }
    
    #[test]
    fn test_timeout_ms() {
        let timeout = TimeoutMs::new(5000);
        assert_eq!(timeout.as_ms(), 5000);
        assert_eq!(timeout.as_duration(), std::time::Duration::from_millis(5000));
        
        let from_duration = TimeoutMs::from_duration(std::time::Duration::from_secs(10));
        assert_eq!(from_duration.as_ms(), 10000);
    }
    
    #[test]
    fn test_interval_ms() {
        let interval = IntervalMs::new(1000);
        assert_eq!(interval.as_ms(), 1000);
        assert_eq!(interval.as_duration(), std::time::Duration::from_millis(1000));
        
        let from_duration = IntervalMs::from_duration(std::time::Duration::from_secs(5));
        assert_eq!(from_duration.as_ms(), 5000);
    }
    
    #[test]
    fn test_duration_sec() {
        let duration = DurationSec::new(30);
        assert_eq!(duration.as_sec(), 30);
        assert_eq!(duration.as_duration(), std::time::Duration::from_secs(30));
        
        let from_duration = DurationSec::from_duration(std::time::Duration::from_secs(60));
        assert_eq!(from_duration.as_sec(), 60);
    }
    
    #[test]
    fn test_window_size() {
        let window = WindowSize::new(65536);
        assert_eq!(window.as_u32(), 65536);
        assert!(!window.is_zero());
        
        let zero_window = WindowSize::new(0);
        assert!(zero_window.is_zero());
        
        let increased = window.add(1024);
        assert_eq!(increased.as_u32(), 66560);
        
        let decreased = window.sub(1024);
        assert_eq!(decreased.as_u32(), 64512);
    }
    
    #[test]
    fn test_threshold() {
        let threshold = Threshold::new(1000);
        assert_eq!(threshold.as_u32(), 1000);
        assert!(threshold.is_exceeded(1500));
        assert!(!threshold.is_exceeded(500));
        assert!(threshold.is_at_or_below(1000));
        assert!(threshold.is_at_or_below(500));
        assert!(!threshold.is_at_or_below(1500));
    }
    
    #[test]
    fn test_size_limit() {
        let limit = SizeLimit::new(1000);
        assert_eq!(limit.as_usize(), 1000);
        assert!(limit.is_exceeded(1500));
        assert!(!limit.is_exceeded(500));
        assert!(limit.is_within(1000));
        assert!(limit.is_within(500));
        assert!(!limit.is_within(1500));
    }
