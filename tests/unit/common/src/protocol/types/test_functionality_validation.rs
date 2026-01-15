/// Tests to validate that existing functionality still works with consolidated types
/// 
/// This module contains tests that simulate real usage patterns to ensure
/// that the consolidated types work correctly in practical scenarios.

use crate::protocol::types::*;
use crate::protocol::types::atomic::*;
use std::sync::atomic::Ordering;
use std::collections::HashMap;

#[cfg(test)]
mod functionality_tests {
    use super::*;

    #[test]
    fn test_session_management_workflow() {
        // Simulate a typical session management workflow
        let session_id = SessionId::new(0x123456789ABCDEF0, SessionIdLength::Bits64);
        let connection_id = ConnectionId::new(0x987654321);
        let initial_seq = SequenceNumber::new(1000);
        
        // Test session creation
        assert_eq!(session_id.as_u64(), 0x123456789ABCDEF0);
        assert_eq!(connection_id.as_u64(), 0x987654321);
        assert_eq!(initial_seq.as_u32(), 1000);
        
        // Test sequence number progression
        let mut current_seq = initial_seq;
        for i in 1..=10 {
            current_seq = current_seq.next();
            assert_eq!(current_seq.as_u32(), 1000 + i);
        }
        
        // Test sequence number wrapping
        let near_max = SequenceNumber::new(SequenceNumber::MAX - 2);
        let wrapped1 = near_max.next();
        let wrapped2 = wrapped1.next();
        let wrapped3 = wrapped2.next();
        
        assert_eq!(wrapped1.as_u32(), SequenceNumber::MAX - 1);
        assert_eq!(wrapped2.as_u32(), SequenceNumber::MAX);
        assert_eq!(wrapped3.as_u32(), 0); // Wrapped to 0
        
        // Test sequence difference calculation
        let seq1 = SequenceNumber::new(100);
        let seq2 = SequenceNumber::new(50);
        assert_eq!(seq1.diff(&seq2), 50);
        
        // Test wrapping difference
        let seq_high = SequenceNumber::new(0xFFFFFFF0);
        let seq_low = SequenceNumber::new(0x10);
        let diff = seq_low.diff(&seq_high);
        assert_eq!(diff, 0x20); // Should handle wrapping correctly
    }

    #[test]
    fn test_network_communication_workflow() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        
        // Simulate network communication setup
        let local_ip = IpAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 100));
        let local_port = Port::new(8080);
        let local_endpoint = NetworkEndpoint::new(local_ip, local_port);
        
        let remote_ip = IpAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 200));
        let remote_port = Port::new(9090);
        let remote_endpoint = NetworkEndpoint::new(remote_ip, remote_port);
        
        // Test endpoint creation and conversion
        let local_socket = local_endpoint.to_socket_addr();
        let remote_socket = remote_endpoint.to_socket_addr();
        
        assert_eq!(local_socket.port(), 8080);
        assert_eq!(remote_socket.port(), 9090);
        
        // Test port validation
        assert!(local_port.is_valid());
        assert!(remote_port.is_valid());
        assert!(!local_port.is_well_known());
        assert!(!remote_port.is_well_known());
        
        // Test port hopping simulation
        let mut current_port = local_port;
        let mut ports = Vec::new();
        for _ in 0..10 {
            current_port = current_port.next();
            ports.push(current_port.as_u16());
        }
        
        // Verify port progression
        for (i, &port) in ports.iter().enumerate() {
            assert_eq!(port, 8081 + i as u16);
        }
        
        // Test MTU and packet size handling
        let mtu = MtuSize::new(1500);
        let header_size = HeaderSize::new(HeaderSize::BASE);
        let max_payload = mtu.as_u16() - header_size.as_u16();
        
        assert_eq!(mtu.as_u16(), MtuSize::DEFAULT);
        assert_eq!(header_size.as_u16(), HeaderSize::BASE);
        assert_eq!(max_payload, 1500 - 18);
        
        // Test fragmentation threshold
        let frag_threshold = MtuSize::new(MtuSize::FRAGMENTATION_THRESHOLD);
        assert_eq!(frag_threshold.as_u16(), 1400);
    }

    #[test]
    fn test_fragmentation_workflow() {
        // Simulate packet fragmentation
        let fragment_id = FragmentId::new(12345);
        let total_fragments = 5u16;
        
        // Create fragment indices
        let mut fragments = Vec::new();
        for i in 0..total_fragments {
            let index = FragmentIndex::new(i);
            let offset = FragmentOffset::new(i * 1400); // 1400 bytes per fragment
            fragments.push((index, offset));
        }
        
        // Verify fragment creation
        assert_eq!(fragments.len(), 5);
        for (i, (index, offset)) in fragments.iter().enumerate() {
            assert_eq!(index.as_u16(), i as u16);
            assert_eq!(offset.as_u16(), (i as u16) * 1400);
        }
        
        // Test fragment ID space
        assert_eq!(FragmentId::SPACE, 0xFFFF);
        assert!(fragment_id.as_u16() < FragmentId::SPACE);
        
        // Test packet size limits
        let max_packet_size = PacketSize::new(PacketSize::MAX_TOTAL_REASSEMBLED);
        assert_eq!(max_packet_size.as_usize(), 65536);
    }

    #[test]
    fn test_time_synchronization_workflow() {
        // Simulate time synchronization
        let base_timestamp = Timestamp::now();
        let peer_timestamp = Timestamp::from_raw(base_timestamp.as_u64() + 1000000); // +1ms
        
        // Calculate time offset
        let offset_nanos = peer_timestamp.as_u64() as i64 - base_timestamp.as_u64() as i64;
        let time_offset = TimeOffset::new(offset_nanos);
        
        assert_eq!(time_offset.as_i64(), 1000000); // 1ms in nanoseconds
        
        // Test RTT measurement
        let rtt_nanos = 50000000u64; // 50ms
        let rtt = RoundTripTime::new(rtt_nanos);
        assert_eq!(rtt.as_nanos(), rtt_nanos);
        assert_eq!(rtt.as_millis(), 50);
        
        // Test drift rate calculation
        let drift_ppm = 25.5;
        let drift = DriftRate::new(drift_ppm);
        assert_eq!(drift.as_ppm(), drift_ppm);
        
        // Test drift thresholds
        assert!(drift.is_excessive(20.0));
        assert!(!drift.is_excessive(30.0));
        assert!(drift.is_significant(10.0));
        
        // Test microsecond timestamp precision
        let micro_timestamp = MicrosecondTimestamp::now();
        let micro_from_nanos = MicrosecondTimestamp::from_nanos(base_timestamp.as_u64());
        
        assert!(micro_timestamp.as_u64() > 0);
        assert_eq!(micro_from_nanos.as_nanos(), base_timestamp.as_u64());
        
        // Test duration calculations
        let duration_5s = Duration::from_seconds(5);
        let duration_3s = Duration::from_seconds(3);
        
        assert_eq!(duration_5s.as_seconds(), 5);
        assert_eq!(duration_3s.as_millis(), 3000);
        
        // Test interval timing
        let heartbeat_interval = Interval::from_millis(30000); // 30 seconds
        assert_eq!(heartbeat_interval.as_millis(), 30000);
    }

    #[test]
    fn test_flow_control_workflow() {
        // Simulate flow control operations
        let initial_window = WindowSize::new(65535);
        let congestion_window = CongestionWindow::new(1460); // 1 MSS
        let mss = MaxSegmentSize::new(MaxSegmentSize::DEFAULT);
        
        assert_eq!(initial_window.as_u32(), WindowSize::DEFAULT);
        assert_eq!(congestion_window.as_u32(), CongestionWindow::DEFAULT);
        assert_eq!(mss.as_u16(), MaxSegmentSize::DEFAULT);
        
        // Test window calculations
        let effective_window = std::cmp::min(initial_window.as_u32(), congestion_window.as_u32());
        assert_eq!(effective_window, 1460); // Limited by congestion window
        
        // Test connection features
        let mut features = ConnectionFeatures::new(0);
        features.set(ConnectionFeatures::FRAGMENTATION);
        features.set(ConnectionFeatures::FLOW_CONTROL);
        features.set(ConnectionFeatures::WINDOW_SCALING);
        
        assert!(features.is_set(ConnectionFeatures::FRAGMENTATION));
        assert!(features.is_set(ConnectionFeatures::FLOW_CONTROL));
        assert!(features.is_set(ConnectionFeatures::WINDOW_SCALING));
        assert!(!features.is_set(ConnectionFeatures::SELECTIVE_ACK));
        
        // Test feature negotiation
        features.clear(ConnectionFeatures::WINDOW_SCALING);
        assert!(!features.is_set(ConnectionFeatures::WINDOW_SCALING));
    }

    #[test]
    fn test_security_workflow() {
        // Simulate security operations
        let challenge_bytes = [0x42u8; 32];
        let challenge = ChallengeNonce::new(challenge_bytes);
        
        let crypto_nonce_bytes = [0x55u8; 12];
        let crypto_nonce = CryptoNonce::new(crypto_nonce_bytes);
        
        let shared_secret_bytes = [0x33u8; 32];
        let shared_secret = SharedSecret::new(shared_secret_bytes);
        
        // Test nonce creation
        assert_eq!(challenge.as_bytes(), &challenge_bytes);
        assert_eq!(crypto_nonce.as_bytes(), &crypto_nonce_bytes);
        assert_eq!(shared_secret.as_bytes(), &shared_secret_bytes);
        
        // Test key derivation simulation
        let session_key_bytes = [0x44u8; 32];
        let session_key = SessionKey::new(session_key_bytes);
        assert_eq!(session_key.as_bytes(), &session_key_bytes);
        
        let daily_key_bytes = [0x66u8; 32];
        let daily_key = DailyKey::new(daily_key_bytes);
        assert_eq!(daily_key.as_bytes(), &daily_key_bytes);
        
        // Test hash values
        let hash_bytes = [0x77u8; 32];
        let hash_value = HashValue::new(hash_bytes);
        let fingerprint = FingerprintHash::new(hash_bytes);
        let validation = ValidationHash::new(hash_bytes);
        
        assert_eq!(hash_value.as_bytes(), &hash_bytes);
        assert_eq!(fingerprint.as_bytes(), &hash_bytes);
        assert_eq!(validation.as_bytes(), &hash_bytes);
        
        // Test discovery workflow
        let discovery_id = DiscoveryId::new(0x123456789ABCDEF0);
        let session_salt = SessionSalt::new(0x12345678);
        
        assert_eq!(discovery_id.as_u64(), 0x123456789ABCDEF0);
        assert_eq!(session_salt.as_u32(), 0x12345678);
        
        // Test security modes
        let security_mode = SecurityMode::Enhanced;
        let hmac_policy = HmacPolicy::Required;
        
        assert_eq!(security_mode.as_u8(), 2);
        assert_eq!(hmac_policy.as_u8(), 1);
        
        // Test recovery reasons
        let recovery_reason = RecoveryReason::HmacFailure;
        let recovery_strategy = RecoveryStrategy::Retransmit;
        
        assert_eq!(recovery_reason.as_u8(), 3);
        assert_eq!(recovery_strategy.as_u8(), 0x01);
    }

    #[test]
    fn test_atomic_operations_workflow() {
        // Simulate concurrent operations with atomic types
        let session_id = SessionId::new(0x123456789ABCDEF0, SessionIdLength::Bits64);
        let atomic_session = AtomicSessionId::new(session_id);
        
        // Test atomic session ID operations
        let loaded_session = atomic_session.load(Ordering::Relaxed);
        assert_eq!(loaded_session.as_u64(), 0x123456789ABCDEF0);
        
        // Test atomic updates
        let new_session = SessionId::from_raw(0x987654321);
        atomic_session.store(new_session, Ordering::Relaxed);
        
        let updated_session = atomic_session.load(Ordering::Relaxed);
        assert_eq!(updated_session.as_u64(), 0x987654321);
        
        // Test compare-and-swap
        let current = SessionId::from_raw(0x987654321);
        let replacement = SessionId::from_raw(0x111111111);
        let result = atomic_session.compare_exchange(
            current,
            replacement,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        
        assert_eq!(result, Ok(current));
        assert_eq!(atomic_session.load(Ordering::Relaxed).as_u64(), 0x111111111);
        
        // Test atomic counters
        let attempt_count = AttemptCount::new(0);
        let atomic_attempts = AttemptCountAtomic::new(attempt_count);
        
        // Simulate retry attempts
        for i in 1..=5 {
            let old_count = atomic_attempts.fetch_add(1, Ordering::Relaxed);
            assert_eq!(old_count.as_u32(), i - 1);
        }
        
        let final_count = atomic_attempts.load(Ordering::Relaxed);
        assert_eq!(final_count.as_u32(), 5);
        
        // Test atomic sync state
        let sync_state = SyncState::Unsynchronized;
        let atomic_sync = SyncStateAtomic::new(sync_state);
        
        // Simulate synchronization state transitions
        atomic_sync.store(SyncState::Synchronizing, Ordering::Relaxed);
        assert_eq!(atomic_sync.load(Ordering::Relaxed), SyncState::Synchronizing);
        
        atomic_sync.store(SyncState::Synchronized, Ordering::Relaxed);
        assert_eq!(atomic_sync.load(Ordering::Relaxed), SyncState::Synchronized);
        
        // Test state transition with compare-exchange
        let transition_result = atomic_sync.compare_exchange(
            SyncState::Synchronized,
            SyncState::Degraded,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        
        assert_eq!(transition_result, Ok(SyncState::Synchronized));
        assert_eq!(atomic_sync.load(Ordering::Relaxed), SyncState::Degraded);
    }

    #[test]
    fn test_configuration_workflow() {
        use std::path::PathBuf;
        
        // Simulate configuration management
        let daemon_name = DaemonName::new("buckwild-daemon".to_string());
        let tun_device = TunDeviceName::new("tun0".to_string());
        
        assert_eq!(daemon_name.as_str(), "buckwild-daemon");
        assert_eq!(tun_device.as_str(), "tun0");
        
        // Test path configurations
        let log_dir = LogDirectory::new(PathBuf::from("/var/log/buckwild"));
        let psk_dir = PskDirectory::new(PathBuf::from("/etc/buckwild/psk"));
        let config_path = ConfigPath::new(PathBuf::from("/etc/buckwild/config.toml"));
        let state_dir = StateDirectory::new(PathBuf::from("/var/lib/buckwild"));
        
        assert_eq!(log_dir.as_path(), &PathBuf::from("/var/log/buckwild"));
        assert_eq!(psk_dir.as_path(), &PathBuf::from("/etc/buckwild/psk"));
        assert_eq!(config_path.as_path(), &PathBuf::from("/etc/buckwild/config.toml"));
        assert_eq!(state_dir.as_path(), &PathBuf::from("/var/lib/buckwild"));
        
        // Test numeric configurations
        let max_connections = MaxConnections::new(1000);
        let worker_threads = WorkerThreadCount::new(8);
        let crypto_threads = CryptoThreadCount::new(4);
        let max_psk_count = MaxPskCount::new(256);
        let snmp_port = SnmpPort::new(161);
        
        assert_eq!(max_connections.as_u32(), 1000);
        assert_eq!(worker_threads.as_u32(), 8);
        assert_eq!(crypto_threads.as_u32(), 4);
        assert_eq!(max_psk_count.as_u16(), 256);
        assert_eq!(snmp_port.as_u16(), 161);
        
        // Test timeout configurations
        let recovery_timeout = RecoveryTimeout::new(15000); // 15 seconds
        let heartbeat_interval = HeartbeatInterval::new(30000); // 30 seconds
        let discovery_timeout = DiscoveryTimeout::new(10000); // 10 seconds
        
        assert_eq!(recovery_timeout.as_millis(), 15000);
        assert_eq!(heartbeat_interval.as_millis(), 30000);
        assert_eq!(discovery_timeout.as_millis(), 10000);
        
        // Test log configurations
        let log_file_size = LogFileSize::new(10485760); // 10MB
        let log_file_count = LogFileCount::new(5);
        
        assert_eq!(log_file_size.as_u64(), 10485760);
        assert_eq!(log_file_count.as_u32(), 5);
        
        // Test thresholds
        let threshold = Threshold::new(100);
        assert_eq!(threshold.as_u32(), 100);
    }

    #[test]
    fn test_metrics_workflow() {
        // Simulate metrics collection
        let mut attempt_count = AttemptCount::new(0);
        let mut failure_count = FailureCount::new(0);
        let mut session_count = SessionCount::new(0);
        let mut timeout_count = TimeoutCount::new(0);
        
        // Simulate operations with metrics
        for i in 1..=10 {
            attempt_count.increment();
            assert_eq!(attempt_count.as_u32(), i);
            
            if i % 3 == 0 {
                failure_count.increment();
            }
            
            if i % 2 == 0 {
                session_count.increment();
            }
            
            if i % 5 == 0 {
                timeout_count.increment();
            }
        }
        
        assert_eq!(attempt_count.as_u32(), 10);
        assert_eq!(failure_count.as_u32(), 3); // 3, 6, 9
        assert_eq!(session_count.as_u32(), 5); // 2, 4, 6, 8, 10
        assert_eq!(timeout_count.as_u32(), 2); // 5, 10
        
        // Test session count operations
        session_count.add(5);
        assert_eq!(session_count.as_u32(), 10);
        
        session_count.decrement();
        assert_eq!(session_count.as_u32(), 9);
        
        // Test failure count operations
        failure_count.add(2);
        assert_eq!(failure_count.as_u32(), 5);
        
        // Test score calculations
        let success_rate = 1.0 - (failure_count.as_u32() as f32 / attempt_count.as_u32() as f32);
        let score = Score::new(success_rate);
        
        assert_eq!(score.as_f32(), 0.5); // 50% success rate
        
        // Test counter
        let mut counter = Counter::new(0);
        counter.add(100);
        counter.increment();
        assert_eq!(counter.as_u64(), 101);
        
        // Test recovery metrics
        let recovery_nonce = RecoveryNonce::new(0x12345678);
        let recovery_attempts = RecoveryAttemptCount::new(0);
        let max_recovery_attempts = MaxRecoveryAttempts::new(5);
        
        assert_eq!(recovery_nonce.as_u32(), 0x12345678);
        assert_eq!(recovery_attempts.as_u32(), 0);
        assert_eq!(max_recovery_attempts.as_u32(), 5);
        
        // Test retry metrics
        let retry_count = RetryCount::new(0);
        let max_retries = MaxRetries::new(3);
        
        assert_eq!(retry_count.as_u32(), 0);
        assert_eq!(max_retries.as_u32(), 3);
        
        // Test metrics interval
        let interval = MetricsInterval::new(std::time::Duration::from_secs(60));
        assert_eq!(interval.as_duration().as_secs(), 60);
    }

    #[test]
    fn test_hashmap_usage() {
        // Test that types work correctly in HashMap (Hash trait)
        let mut session_map = HashMap::new();
        
        let session1 = SessionId::new(0x111111111, SessionIdLength::Bits64);
        let session2 = SessionId::new(0x222222222, SessionIdLength::Bits64);
        let session3 = SessionId::new(0x333333333, SessionIdLength::Bits64);
        
        session_map.insert(session1, "Session 1");
        session_map.insert(session2, "Session 2");
        session_map.insert(session3, "Session 3");
        
        assert_eq!(session_map.get(&session1), Some(&"Session 1"));
        assert_eq!(session_map.get(&session2), Some(&"Session 2"));
        assert_eq!(session_map.get(&session3), Some(&"Session 3"));
        
        // Test with other types
        let mut port_map = HashMap::new();
        let port1 = Port::new(8080);
        let port2 = Port::new(9090);
        
        port_map.insert(port1, "HTTP Alt");
        port_map.insert(port2, "Custom Service");
        
        assert_eq!(port_map.get(&port1), Some(&"HTTP Alt"));
        assert_eq!(port_map.get(&port2), Some(&"Custom Service"));
        
        // Test with fragment IDs
        let mut fragment_map = HashMap::new();
        let frag1 = FragmentId::new(12345);
        let frag2 = FragmentId::new(54321);
        
        fragment_map.insert(frag1, vec![1, 2, 3, 4]);
        fragment_map.insert(frag2, vec![5, 6, 7, 8]);
        
        assert_eq!(fragment_map.get(&frag1), Some(&vec![1, 2, 3, 4]));
        assert_eq!(fragment_map.get(&frag2), Some(&vec![5, 6, 7, 8]));
    }

    #[test]
    fn test_ordering_and_sorting() {
        // Test that types work correctly with sorting (Ord trait)
        let mut sessions = vec![
            SessionId::new(0x333333333, SessionIdLength::Bits64),
            SessionId::new(0x111111111, SessionIdLength::Bits64),
            SessionId::new(0x222222222, SessionIdLength::Bits64),
        ];
        
        sessions.sort();
        
        assert_eq!(sessions[0].as_u64(), 0x111111111);
        assert_eq!(sessions[1].as_u64(), 0x222222222);
        assert_eq!(sessions[2].as_u64(), 0x333333333);
        
        // Test with ports
        let mut ports = vec![
            Port::new(9090),
            Port::new(8080),
            Port::new(8888),
        ];
        
        ports.sort();
        
        assert_eq!(ports[0].as_u16(), 8080);
        assert_eq!(ports[1].as_u16(), 8888);
        assert_eq!(ports[2].as_u16(), 9090);
        
        // Test with timestamps
        let mut timestamps = vec![
            Timestamp::from_raw(3000000000),
            Timestamp::from_raw(1000000000),
            Timestamp::from_raw(2000000000),
        ];
        
        timestamps.sort();
        
        assert_eq!(timestamps[0].as_u64(), 1000000000);
        assert_eq!(timestamps[1].as_u64(), 2000000000);
        assert_eq!(timestamps[2].as_u64(), 3000000000);
    }
}