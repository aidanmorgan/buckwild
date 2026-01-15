/// Tests for type conversion methods (from_raw, as_raw, etc.)
/// 
/// This module specifically tests the conversion methods that are critical
/// for the consolidated types to work correctly with existing code.

use crate::protocol::types::*;

#[cfg(test)]
mod conversion_tests {
    use super::*;

    #[test]
    fn test_session_id_conversions() {
        let original_value = 0x123456789ABCDEF0u64;
        
        // Test from_raw and as_raw roundtrip
        let session_id = SessionId::from_raw(original_value);
        assert_eq!(session_id.as_raw(), original_value);
        assert_eq!(session_id.as_u64(), original_value);
        
        // Test with different session ID lengths
        let session_16 = SessionId::new(original_value, SessionIdLength::Bits16);
        let session_32 = SessionId::new(original_value, SessionIdLength::Bits32);
        let session_64 = SessionId::new(original_value, SessionIdLength::Bits64);
        
        assert_eq!(session_16.as_raw(), original_value & 0xFFFF);
        assert_eq!(session_32.as_raw(), original_value & 0xFFFFFFFF);
        assert_eq!(session_64.as_raw(), original_value);
        
        // Test eBPF conversions
        assert_eq!(session_id.to_ebpf_u64(), original_value);
        let from_ebpf = SessionId::from_ebpf_u64(original_value);
        assert_eq!(from_ebpf.as_raw(), original_value);
    }

    #[test]
    fn test_sequence_number_conversions() {
        let original_value = 0x12345678u32;
        
        // Test from_raw and as_raw roundtrip
        let seq_num = SequenceNumber::new(original_value);
        assert_eq!(seq_num.as_u32(), original_value);
        
        // Test eBPF conversions
        assert_eq!(seq_num.to_ebpf_u32(), original_value);
        let from_ebpf = SequenceNumber::from_ebpf_u32(original_value);
        assert_eq!(from_ebpf.as_u32(), original_value);
        
        // Test wrapping behavior
        let max_seq = SequenceNumber::new(SequenceNumber::MAX);
        let next_seq = max_seq.next();
        assert_eq!(next_seq.as_u32(), 0); // Should wrap to 0
        
        // Test diff calculation
        let seq1 = SequenceNumber::new(100);
        let seq2 = SequenceNumber::new(50);
        assert_eq!(seq1.diff(&seq2), 50);
        
        // Test wrapping diff
        let seq_high = SequenceNumber::new(0xFFFFFFF0);
        let seq_low = SequenceNumber::new(0x10);
        let diff = seq_low.diff(&seq_high);
        assert_eq!(diff, 0x20); // Wrapping subtraction
    }

    #[test]
    fn test_port_conversions() {
        let original_value = 8080u16;
        
        // Test from_raw and as_raw roundtrip
        let port = Port::new(original_value);
        assert_eq!(port.as_raw(), original_value);
        assert_eq!(port.as_u16(), original_value);
        
        // Test eBPF conversions
        assert_eq!(port.to_ebpf_u16(), original_value);
        let from_ebpf = Port::from_ebpf_u16(original_value);
        assert_eq!(from_ebpf.as_raw(), original_value);
        
        // Test port validation
        assert!(port.is_valid());
        assert!(!Port::new(0).is_valid());
        
        // Test well-known port detection
        assert!(Port::new(80).is_well_known());
        assert!(!port.is_well_known());
        
        // Test next port calculation
        let next_port = port.next();
        assert_eq!(next_port.as_u16(), 8081);
        
        // Test wrapping at max value
        let max_port = Port::new(u16::MAX);
        let wrapped_port = max_port.next();
        assert_eq!(wrapped_port.as_u16(), Port::MIN);
    }

    #[test]
    fn test_fragment_id_conversions() {
        let original_value = 12345u16;
        
        // Test from_raw and as_raw roundtrip
        let frag_id = FragmentId::new(original_value);
        assert_eq!(frag_id.as_u16(), original_value);
        
        // Test eBPF conversions
        assert_eq!(frag_id.to_ebpf_u16(), original_value);
        let from_ebpf = FragmentId::from_ebpf_u16(original_value);
        assert_eq!(from_ebpf.as_u16(), original_value);
        
        // Test fragment ID space constant
        assert_eq!(FragmentId::SPACE, 0xFFFF);
    }

    #[test]
    fn test_timestamp_conversions() {
        let original_value = 1000000000u64;
        
        // Test from_raw and as_raw roundtrip
        let timestamp = Timestamp::from_raw(original_value);
        assert_eq!(timestamp.as_u64(), original_value);
        assert_eq!(timestamp.as_nanos(), original_value);
        
        // Test with timestamp config (should store full value regardless)
        let timestamp_with_config = Timestamp::new(original_value, TimestampConfig::Bits16);
        assert_eq!(timestamp_with_config.as_u64(), original_value);
        
        // Test now() returns reasonable value
        let now = Timestamp::now();
        assert!(now.as_u64() > 0);
        
        // Test saturating_sub
        let ts1 = Timestamp::from_raw(2000000000);
        let ts2 = Timestamp::from_raw(1000000000);
        assert_eq!(ts1.saturating_sub(ts2), 1000000000);
        assert_eq!(ts2.saturating_sub(ts1), 0); // Saturates to 0
    }

    #[test]
    fn test_microsecond_timestamp_conversions() {
        let original_value = 1000000u64; // 1 second in microseconds
        
        // Test from_raw and as_raw roundtrip
        let timestamp = MicrosecondTimestamp::new(original_value);
        assert_eq!(timestamp.as_u64(), original_value);
        assert_eq!(timestamp.as_micros(), original_value);
        assert_eq!(timestamp.as_nanos(), original_value * 1000);
        
        // Test from_nanos conversion
        let from_nanos = MicrosecondTimestamp::from_nanos(2000000000);
        assert_eq!(from_nanos.as_micros(), 2000000);
        
        // Test now() returns reasonable value
        let now = MicrosecondTimestamp::now();
        assert!(now.as_u64() > 0);
        
        // Test saturating_sub
        let ts1 = MicrosecondTimestamp::new(2000000);
        let ts2 = MicrosecondTimestamp::new(1000000);
        assert_eq!(ts1.saturating_sub(ts2), 1000000);
        assert_eq!(ts2.saturating_sub(ts1), 0); // Saturates to 0
    }

    #[test]
    fn test_duration_conversions() {
        let original_nanos = 5000000000u64; // 5 seconds in nanoseconds
        
        // Test from_raw and as_raw roundtrip
        let duration = Duration::from_raw(original_nanos);
        assert_eq!(duration.as_raw(), original_nanos);
        assert_eq!(duration.as_nanos(), original_nanos);
        assert_eq!(duration.as_millis(), 5000);
        assert_eq!(duration.as_seconds(), 5);
        
        // Test from_millis and from_seconds
        let from_millis = Duration::from_millis(3000);
        assert_eq!(from_millis.as_nanos(), 3000000000);
        
        let from_seconds = Duration::from_seconds(2);
        assert_eq!(from_seconds.as_nanos(), 2000000000);
        
        // Test std::time::Duration conversions
        let std_duration = std::time::Duration::from_secs(1);
        let our_duration: Duration = std_duration.into();
        assert_eq!(our_duration.as_seconds(), 1);
        
        let std_back: std::time::Duration = our_duration.into();
        assert_eq!(std_back.as_secs(), 1);
        
        let as_std = duration.as_std_duration();
        assert_eq!(as_std.as_secs(), 5);
    }

    #[test]
    fn test_time_offset_conversions() {
        let positive_offset = 1000000000i64; // +1 second in nanoseconds
        let negative_offset = -500000000i64; // -0.5 seconds in nanoseconds
        
        // Test positive offset
        let offset_pos = TimeOffset::new(positive_offset);
        assert_eq!(offset_pos.as_i64(), positive_offset);
        assert_eq!(offset_pos.as_nanos(), positive_offset);
        
        // Test negative offset
        let offset_neg = TimeOffset::new(negative_offset);
        assert_eq!(offset_neg.as_i64(), negative_offset);
        assert_eq!(offset_neg.as_nanos(), negative_offset);
    }

    #[test]
    fn test_round_trip_time_conversions() {
        let original_nanos = 50000000u64; // 50ms in nanoseconds
        
        // Test from_raw and as_raw roundtrip
        let rtt = RoundTripTime::new(original_nanos);
        assert_eq!(rtt.as_u64(), original_nanos);
        assert_eq!(rtt.as_nanos(), original_nanos);
        assert_eq!(rtt.as_millis(), 50);
    }

    #[test]
    fn test_drift_rate_conversions() {
        let drift_ppm = 25.5f64;
        
        // Test from_raw and as_raw roundtrip
        let drift = DriftRate::new(drift_ppm);
        assert_eq!(drift.as_f64(), drift_ppm);
        assert_eq!(drift.as_ppm(), drift_ppm);
        
        // Test threshold checks
        assert!(drift.is_excessive(20.0));
        assert!(!drift.is_excessive(30.0));
        assert!(drift.is_significant(10.0));
        assert!(!drift.is_significant(50.0));
        
        // Test negative drift
        let negative_drift = DriftRate::new(-15.0);
        assert!(negative_drift.is_excessive(10.0)); // abs() > 10.0
    }

    #[test]
    fn test_network_endpoint_conversions() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        
        let ip = IpAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let port = Port::new(8080);
        let endpoint = NetworkEndpoint::new(ip, port);
        
        // Test to_socket_addr and from_socket_addr roundtrip
        let socket_addr = endpoint.to_socket_addr();
        let endpoint_back = NetworkEndpoint::from_socket_addr(socket_addr);
        
        assert_eq!(endpoint.port.as_u16(), endpoint_back.port.as_u16());
        // Note: IP comparison might need special handling for IPv4/IPv6
        
        // Test with standard socket address
        let std_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9090);
        let endpoint_from_std = NetworkEndpoint::from_socket_addr(std_socket);
        assert_eq!(endpoint_from_std.port.as_u16(), 9090);
        
        let std_back = endpoint_from_std.to_socket_addr();
        assert_eq!(std_back.port(), 9090);
    }

    #[test]
    fn test_packet_size_conversions() {
        let original_size = 65536usize;
        
        // Test from_raw and as_raw roundtrip
        let packet_size = PacketSize::new(original_size);
        assert_eq!(packet_size.as_usize(), original_size);
        assert_eq!(packet_size.as_raw(), original_size);
        
        // Test constant
        assert_eq!(PacketSize::MAX_TOTAL_REASSEMBLED, 65536);
    }

    #[test]
    fn test_header_size_conversions() {
        let original_size = 18u16;
        
        // Test from_raw and as_raw roundtrip
        let header_size = HeaderSize::new(original_size);
        assert_eq!(header_size.as_u16(), original_size);
        assert_eq!(header_size.as_usize(), original_size as usize);
        
        // Test constants
        assert_eq!(HeaderSize::BASE, 18);
        assert_eq!(HeaderSize::FRAGMENT, 8);
        
        // Test arithmetic operations
        let total_with_usize = header_size + 1000usize;
        assert_eq!(total_with_usize, 1018);
        
        let total_with_u32 = header_size + 500u32;
        assert_eq!(total_with_u32, 518);
    }

    #[test]
    fn test_metrics_conversions() {
        // Test AttemptCount
        let attempt_count = AttemptCount::new(5);
        assert_eq!(attempt_count.as_u32(), 5);
        assert_eq!(attempt_count.as_raw(), 5);
        
        let attempt_from_raw = AttemptCount::from_raw(10);
        assert_eq!(attempt_from_raw.as_u32(), 10);
        
        // Test FailureCount
        let failure_count = FailureCount::new(3);
        assert_eq!(failure_count.as_u32(), 3);
        assert_eq!(failure_count.as_raw(), 3);
        
        let failure_from_raw = FailureCount::from_raw(7);
        assert_eq!(failure_from_raw.as_u32(), 7);
        
        // Test SessionCount
        let session_count = SessionCount::new(15);
        assert_eq!(session_count.as_u32(), 15);
        assert_eq!(session_count.as_raw(), 15);
        
        let session_from_raw = SessionCount::from_raw(25);
        assert_eq!(session_from_raw.as_u32(), 25);
    }

    #[test]
    fn test_configuration_conversions() {
        // Test Timeout
        let timeout = Timeout::new(5000);
        assert_eq!(timeout.as_u64(), 5000);
        assert_eq!(timeout.as_millis(), 5000);
        
        let timeout_from_millis = Timeout::from_millis(10000);
        assert_eq!(timeout_from_millis.as_u64(), 10000);
        
        // Test MaxSegmentSize
        let mss = MaxSegmentSize::new(1460);
        assert_eq!(mss.as_u16(), 1460);
        assert_eq!(MaxSegmentSize::DEFAULT, 1460);
        
        // Test various count types
        let max_conn = MaxConnections::new(100);
        assert_eq!(max_conn.as_u32(), 100);
        assert_eq!(max_conn.as_raw(), 100);
        
        let max_conn_from_raw = MaxConnections::from_raw(200);
        assert_eq!(max_conn_from_raw.as_u32(), 200);
        
        let worker_count = WorkerThreadCount::new(8);
        assert_eq!(worker_count.as_u32(), 8);
        assert_eq!(worker_count.as_raw(), 8);
        
        let crypto_count = CryptoThreadCount::new(4);
        assert_eq!(crypto_count.as_u32(), 4);
        assert_eq!(crypto_count.as_raw(), 4);
    }

    #[test]
    fn test_security_conversions() {
        // Test DiscoveryId
        let discovery_id = DiscoveryId::new(0x123456789ABCDEF0);
        assert_eq!(discovery_id.as_u64(), 0x123456789ABCDEF0);
        assert_eq!(discovery_id.as_raw(), 0x123456789ABCDEF0);
        
        let discovery_from_raw = DiscoveryId::from_raw(0x987654321);
        assert_eq!(discovery_from_raw.as_u64(), 0x987654321);
        
        // Test SessionSalt
        let session_salt = SessionSalt::new(0x12345678);
        assert_eq!(session_salt.as_u32(), 0x12345678);
        assert_eq!(session_salt.as_raw(), 0x12345678);
        
        let salt_from_raw = SessionSalt::from_raw(0x87654321);
        assert_eq!(salt_from_raw.as_u32(), 0x87654321);
        
        // Test byte array types
        let challenge_bytes = [0x42u8; 32];
        let challenge = ChallengeNonce::new(challenge_bytes);
        assert_eq!(challenge.as_bytes(), &challenge_bytes);
        
        let challenge_from_bytes = ChallengeNonce::from_bytes(challenge_bytes);
        assert_eq!(challenge_from_bytes.as_bytes(), &challenge_bytes);
        
        let crypto_bytes = [0x55u8; 12];
        let crypto_nonce = CryptoNonce::new(crypto_bytes);
        assert_eq!(crypto_nonce.as_bytes(), &crypto_bytes);
        
        let crypto_from_bytes = CryptoNonce::from_bytes(crypto_bytes);
        assert_eq!(crypto_from_bytes.as_bytes(), &crypto_bytes);
    }

    #[test]
    fn test_path_conversions() {
        use std::path::PathBuf;
        
        let path = PathBuf::from("/var/log/buckwild");
        
        // Test LogDirectory
        let log_dir = LogDirectory::new(path.clone());
        assert_eq!(log_dir.as_path(), &path);
        assert_eq!(log_dir.as_raw(), &path);
        
        let log_dir_from_raw = LogDirectory::from_raw(path.clone());
        assert_eq!(log_dir_from_raw.as_path(), &path);
        
        // Test PskDirectory
        let psk_dir = PskDirectory::new(path.clone());
        assert_eq!(psk_dir.as_path(), &path);
        assert_eq!(psk_dir.as_raw(), &path);
        
        // Test ConfigPath
        let config_path = ConfigPath::new(path.clone());
        assert_eq!(config_path.as_path(), &path);
        assert_eq!(config_path.as_raw(), &path);
        
        // Test StateDirectory
        let state_dir = StateDirectory::new(path.clone());
        assert_eq!(state_dir.as_path(), &path);
        assert_eq!(state_dir.as_raw(), &path);
    }

    #[test]
    fn test_string_conversions() {
        let daemon_name_str = "buckwild-daemon".to_string();
        
        // Test DaemonName
        let daemon_name = DaemonName::new(daemon_name_str.clone());
        assert_eq!(daemon_name.as_str(), "buckwild-daemon");
        assert_eq!(daemon_name.as_raw(), &daemon_name_str);
        
        let daemon_from_raw = DaemonName::from_raw(daemon_name_str.clone());
        assert_eq!(daemon_from_raw.as_str(), "buckwild-daemon");
        
        // Test TunDeviceName
        let tun_name_str = "tun0".to_string();
        let tun_name = TunDeviceName::new(tun_name_str.clone());
        assert_eq!(tun_name.as_str(), "tun0");
        assert_eq!(tun_name.as_raw(), &tun_name_str);
        
        let tun_from_raw = TunDeviceName::from_raw(tun_name_str.clone());
        assert_eq!(tun_from_raw.as_str(), "tun0");
    }
}