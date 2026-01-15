use buckwild_common::protocol::types::{
    TimeoutMs, IntervalMs, DurationSec, WindowSize, Threshold, SizeLimit,
    ConnectionId, AtomicConnectionId, PacketId, FragmentId, EpochId, AtomicPortNumber
};

#[test]
fn test_time_newtypes() {
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
fn test_window_and_limit_newtypes() {
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
fn test_id_newtypes() {
    let conn_id = ConnectionId::generate();
    assert_ne!(conn_id.as_raw(), 0);
    
    let pkt_id = PacketId::new(100);
    let next_pkt = pkt_id.next();
    assert_eq!(next_pkt.as_raw(), 101);
    
    let frag_id = FragmentId::new(100);
    let next_frag = frag_id.next();
    assert_eq!(next_frag.as_raw(), 101);
    
    let epoch = EpochId::new(100);
    let next_epoch = epoch.next();
    assert_eq!(next_epoch.as_raw(), 101);
}

#[test]
fn test_atomic_port_number() {
    let port = AtomicPortNumber::new(8080);
    assert_eq!(port.load(std::sync::atomic::Ordering::Relaxed), 8080);
    assert!(AtomicPortNumber::is_valid(8080));
    assert!(!AtomicPortNumber::is_well_known(8080));
}