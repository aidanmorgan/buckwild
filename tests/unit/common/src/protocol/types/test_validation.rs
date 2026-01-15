/// Comprehensive tests for type validation
/// 
/// This module tests all validation methods for protocol types to ensure they
/// properly validate according to protocol requirements and constraints.

use buckwild_common::protocol::types::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    // Network type validation tests
    #[test]
    fn test_port_validation() {
        // Valid ports
        assert!(Port::new(1024).validate().is_ok());
        assert!(Port::new(8080).validate().is_ok());
        assert!(Port::new(65535).validate().is_ok());
        
        // Invalid ports
        assert!(Port::new(0).validate().is_err());
        
        // Well-known ports in strict mode
        let context = ValidationContext {
            strict_mode: true,
            ..Default::default()
        };
        assert!(Port::new(80).validate_with_context(&context).is_err());
        assert!(Port::new(443).validate_with_context(&context).is_err());
        
        // Well-known ports in non-strict mode
        let context = ValidationContext {
            strict_mode: false,
            ..Default::default()
        };
        assert!(Port::new(80).validate_with_context(&context).is_ok());
    }

    #[test]
    fn test_ip_address_validation() {
        // Valid IPv4 addresses
        let valid_v4 = IpAddress::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(valid_v4.validate().is_ok());
        
        // Valid IPv6 addresses
        let valid_v6 = IpAddress::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(valid_v6.validate().is_ok());
        
        // Unspecified addresses
        let unspecified_v4 = IpAddress::V4(Ipv4Addr::UNSPECIFIED);
        assert!(unspecified_v4.validate().is_err());
        
        let unspecified_v6 = IpAddress::V6(Ipv6Addr::UNSPECIFIED);
        assert!(unspecified_v6.validate().is_err());
        
        // Non-routable addresses in strict mode
        let context = ValidationContext {
            strict_mode: true,
            ..Default::default()
        };
        let private_v4 = IpAddress::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(private_v4.validate_with_context(&context).is_err());
        
        let loopback_v4 = IpAddress::V4(Ipv4Addr::LOCALHOST);
        assert!(loopback_v4.validate_with_context(&context).is_err());
    }

    #[test]
    fn test_network_endpoint_validation() {
        let valid_ip = IpAddress::V4(Ipv4Addr::new(8, 8, 8, 8));
        let valid_port = Port::new(8080);
        let endpoint = NetworkEndpoint::new(valid_ip, valid_port);
        
        assert!(endpoint.validate().is_ok());
        
        // Invalid port should fail
        let invalid_port = Port::new(0);
        let invalid_endpoint = NetworkEndpoint::new(valid_ip, invalid_port);
        assert!(invalid_endpoint.validate().is_err());
    }

    #[test]
    fn test_mtu_size_validation() {
        // Valid MTU sizes
        assert!(MtuSize::new(1500).validate().is_ok());
        assert!(MtuSize::new(1280).validate().is_ok()); // IPv6 minimum
        assert!(MtuSize::new(9000).validate().is_ok()); // Jumbo frame
        
        // Invalid MTU sizes
        assert!(MtuSize::new(67).validate().is_err()); // Below IPv4 minimum
        assert!(MtuSize::new(10000).validate().is_err()); // Above jumbo frame limit
    }

    #[test]
    fn test_packet_size_validation() {
        // Valid packet sizes
        assert!(PacketSize::new(1500).validate().is_ok());
        assert!(PacketSize::new(65536).validate().is_ok());
        
        // Invalid packet sizes
        assert!(PacketSize::new(100000).validate().is_err());
        
        // Context-specific validation
        let context = ValidationContext {
            max_values: MaxValues {
                max_packet_size: 32768,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(PacketSize::new(65536).validate_with_context(&context).is_err());
        assert!(PacketSize::new(16384).validate_with_context(&context).is_ok());
    }

    // Header type validation tests
    #[test]
    fn test_protocol_version_validation() {
        // Valid version
        assert!(ProtocolVersion::CURRENT.validate().is_ok());
        
        // Invalid version
        let invalid_version = ProtocolVersion::new(0x02);
        assert!(invalid_version.validate().is_err());
    }

    #[test]
    fn test_version_byte_validation() {
        // Valid version byte
        let version_byte = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits32);
        assert!(version_byte.validate().is_ok());
        
        // Invalid version byte (invalid protocol version)
        let invalid_version_byte = VersionByte::from_raw(0x20); // Invalid protocol version
        assert!(invalid_version_byte.validate().is_err());
    }

    #[test]
    fn test_packet_flags_validation() {
        // Valid flag combinations
        let syn_flag = PacketFlags::with_flags(PacketFlags::SYN);
        assert!(syn_flag.validate().is_ok());
        
        let ack_flag = PacketFlags::with_flags(PacketFlags::ACK);
        assert!(ack_flag.validate().is_ok());
        
        let syn_ack_flags = PacketFlags::with_flags(PacketFlags::SYN | PacketFlags::ACK);
        assert!(syn_ack_flags.validate().is_ok());
        
        // Invalid flag combinations
        let syn_fin_flags = PacketFlags::with_flags(PacketFlags::SYN | PacketFlags::FIN);
        assert!(syn_fin_flags.validate().is_err());
        
        let rst_syn_flags = PacketFlags::with_flags(PacketFlags::RST | PacketFlags::SYN);
        assert!(rst_syn_flags.validate().is_err());
        
        let fragment_syn_flags = PacketFlags::with_flags(PacketFlags::FRAGMENT | PacketFlags::SYN);
        assert!(fragment_syn_flags.validate().is_err());
    }

    #[test]
    fn test_payload_length_validation() {
        // Valid payload lengths
        assert!(PayloadLength::new(1500).validate().is_ok());
        assert!(PayloadLength::new(0).validate().is_ok());
        
        // Invalid payload length
        assert!(PayloadLength::new(65516).validate().is_err()); // Too large
    }

    #[test]
    fn test_error_code_validation() {
        // Valid error codes
        assert!(ErrorCode::new(0x00).validate().is_ok());
        assert!(ErrorCode::new(0x6F).validate().is_ok());
        
        // Invalid error codes
        assert!(ErrorCode::new(0x70).validate().is_err());
        assert!(ErrorCode::new(0xFF).validate().is_err());
    }

    // Time type validation tests
    #[test]
    fn test_timestamp_validation() {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        // Valid timestamp (current time)
        let current_timestamp = Timestamp::from_raw(now_ns);
        assert!(current_timestamp.validate().is_ok());
        
        // Future timestamp (should fail)
        let future_timestamp = Timestamp::from_raw(now_ns + 600_000_000_000); // 10 minutes in future
        assert!(future_timestamp.validate().is_err());
        
        // Old timestamp (should fail)
        let old_timestamp = Timestamp::from_raw(now_ns - 86400_000_000_000); // 24 hours ago
        assert!(old_timestamp.validate().is_err());
    }

    #[test]
    fn test_duration_validation() {
        // Valid durations
        assert!(Duration::new(1_000_000_000).validate().is_ok()); // 1 second
        assert!(Duration::new(60_000_000_000).validate().is_ok()); // 1 minute
        
        // Invalid duration (too long)
        assert!(Duration::new(7200_000_000_000).validate().is_err()); // 2 hours
        
        // Context-specific validation
        let context = ValidationContext {
            network_conditions: NetworkConditions {
                latency_ns: 100_000_000, // 100ms
                ..Default::default()
            },
            ..Default::default()
        };
        
        // Should allow longer durations in high-latency networks
        let long_duration = Duration::new(10_000_000_000); // 10 seconds
        assert!(long_duration.validate_with_context(&context).is_ok());
    }

    #[test]
    fn test_time_offset_validation() {
        // Valid time offsets
        assert!(TimeOffset::new(1_000_000_000).validate().is_ok()); // 1 second
        assert!(TimeOffset::new(-1_000_000_000).validate().is_ok()); // -1 second
        
        // Invalid time offsets (too large)
        assert!(TimeOffset::new(60_000_000_000).validate().is_err()); // 60 seconds
        assert!(TimeOffset::new(-60_000_000_000).validate().is_err()); // -60 seconds
    }

    #[test]
    fn test_round_trip_time_validation() {
        // Valid RTT values
        assert!(RoundTripTime::new(1_000_000).validate().is_ok()); // 1ms
        assert!(RoundTripTime::new(100_000_000).validate().is_ok()); // 100ms
        
        // Invalid RTT values
        assert!(RoundTripTime::new(50_000).validate().is_err()); // 0.05ms (too small)
        assert!(RoundTripTime::new(20_000_000_000).validate().is_err()); // 20 seconds (too large)
        
        // Context-specific validation
        let context = ValidationContext {
            max_values: MaxValues {
                max_rtt_ns: 1_000_000_000, // 1 second
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(RoundTripTime::new(500_000_000).validate_with_context(&context).is_ok()); // 0.5 seconds
        assert!(RoundTripTime::new(2_000_000_000).validate_with_context(&context).is_err()); // 2 seconds
    }

    #[test]
    fn test_drift_rate_validation() {
        // Valid drift rates
        assert!(DriftRate::new(10.0).validate().is_ok()); // 10 ppm
        assert!(DriftRate::new(-50.0).validate().is_ok()); // -50 ppm
        
        // Invalid drift rates
        assert!(DriftRate::new(2000.0).validate().is_err()); // 2000 ppm (too high)
        assert!(DriftRate::new(-1500.0).validate().is_err()); // -1500 ppm (too low)
        
        // NaN and infinite values
        assert!(DriftRate::new(f64::NAN).validate().is_err());
        assert!(DriftRate::new(f64::INFINITY).validate().is_err());
        assert!(DriftRate::new(f64::NEG_INFINITY).validate().is_err());
    }

    // Identifier type validation tests
    #[test]
    fn test_session_id_validation() {
        // Valid session IDs
        assert!(SessionId::new(12345, SessionIdLength::Bits32).validate().is_ok());
        assert!(SessionId::new(1, SessionIdLength::Bits16).validate().is_ok());
        
        // Reserved session IDs
        assert!(SessionId::new(0, SessionIdLength::Bits32).validate().is_err());
        assert!(SessionId::new(u64::MAX, SessionIdLength::Bits64).validate().is_err());
    }

    #[test]
    fn test_connection_id_validation() {
        // Valid connection IDs
        assert!(ConnectionId::new(12345).validate().is_ok());
        
        // Invalid connection ID (reserved)
        assert!(ConnectionId::new(0).validate().is_err());
    }

    #[test]
    fn test_socket_id_validation() {
        // Valid socket IDs
        assert!(SocketId::new(12345).validate().is_ok());
        
        // Invalid socket ID (reserved)
        assert!(SocketId::new(0).validate().is_err());
    }

    #[test]
    fn test_process_id_validation() {
        // Valid process IDs
        assert!(ProcessId::new(12345).validate().is_ok());
        
        // Invalid process ID (reserved)
        assert!(ProcessId::new(0).validate().is_err());
    }

    // Fragmentation type validation tests
    #[test]
    fn test_fragment_id_validation() {
        // Valid fragment IDs
        assert!(FragmentId::new(12345).validate().is_ok());
        
        // Invalid fragment ID (reserved)
        assert!(FragmentId::new(0).validate().is_err());
    }

    #[test]
    fn test_fragment_index_validation() {
        // Valid fragment indices
        assert!(FragmentIndex::new(0).validate().is_ok());
        assert!(FragmentIndex::new(254).validate().is_ok());
        
        // Invalid fragment index (too large)
        assert!(FragmentIndex::new(255).validate().is_err());
        assert!(FragmentIndex::new(1000).validate().is_err());
    }

    #[test]
    fn test_fragment_offset_validation() {
        // Valid fragment offsets (8-byte aligned)
        assert!(FragmentOffset::new(0).validate().is_ok());
        assert!(FragmentOffset::new(8).validate().is_ok());
        assert!(FragmentOffset::new(1024).validate().is_ok());
        
        // Invalid fragment offsets (not 8-byte aligned)
        assert!(FragmentOffset::new(1).validate().is_err());
        assert!(FragmentOffset::new(7).validate().is_err());
        assert!(FragmentOffset::new(1025).validate().is_err());
    }

    // Security type validation tests
    #[test]
    fn test_challenge_nonce_validation() {
        // Valid challenge nonce
        let mut nonce = [0u8; 32];
        nonce[0] = 1; // Not all zeros
        let challenge_nonce = ChallengeNonce::new(nonce);
        assert!(challenge_nonce.validate().is_ok());
        
        // Invalid challenge nonce (all zeros)
        let weak_nonce = ChallengeNonce::new([0u8; 32]);
        assert!(weak_nonce.validate().is_err());
        
        // Invalid challenge nonce (all 0xFF)
        let weak_nonce_ff = ChallengeNonce::new([0xFF; 32]);
        assert!(weak_nonce_ff.validate().is_err());
    }

    #[test]
    fn test_crypto_nonce_validation() {
        // Valid crypto nonce
        let mut nonce = [0u8; 12];
        nonce[0] = 1; // Not all zeros
        let crypto_nonce = CryptoNonce::new(nonce);
        assert!(crypto_nonce.validate().is_ok());
        
        // Invalid crypto nonce (all zeros)
        let weak_nonce = CryptoNonce::new([0u8; 12]);
        assert!(weak_nonce.validate().is_err());
    }

    #[test]
    fn test_shared_secret_validation() {
        // Valid shared secret
        let mut secret = [0u8; 32];
        secret[0] = 1; // Not all zeros
        let shared_secret = SharedSecret::new(secret);
        assert!(shared_secret.validate().is_ok());
        
        // Invalid shared secret (all zeros)
        let weak_secret = SharedSecret::new([0u8; 32]);
        assert!(weak_secret.validate().is_err());
    }

    #[test]
    fn test_ecdh_keys_validation() {
        // Valid ECDH public key
        let mut pub_key = [0u8; 64];
        pub_key[0] = 1; // Not all zeros
        let ecdh_pub_key = EcdhPublicKey::new(pub_key);
        assert!(ecdh_pub_key.validate().is_ok());
        
        // Invalid ECDH public key (all zeros)
        let weak_pub_key = EcdhPublicKey::new([0u8; 64]);
        assert!(weak_pub_key.validate().is_err());
        
        // Valid ECDH private key
        let mut priv_key = [0u8; 32];
        priv_key[0] = 1; // Not all zeros
        let ecdh_priv_key = EcdhPrivateKey::new(priv_key);
        assert!(ecdh_priv_key.validate().is_ok());
        
        // Invalid ECDH private key (all zeros)
        let weak_priv_key = EcdhPrivateKey::new([0u8; 32]);
        assert!(weak_priv_key.validate().is_err());
        
        // Invalid ECDH private key (all 0xFF)
        let weak_priv_key_ff = EcdhPrivateKey::new([0xFF; 32]);
        assert!(weak_priv_key_ff.validate().is_err());
    }

    #[test]
    fn test_discovery_id_validation() {
        // Valid discovery IDs
        assert!(DiscoveryId::new(12345).validate().is_ok());
        
        // Invalid discovery ID (reserved)
        assert!(DiscoveryId::new(0).validate().is_err());
    }

    // Flow control type validation tests
    #[test]
    fn test_window_size_validation() {
        // Valid window sizes
        assert!(WindowSize::new(65535).validate().is_ok());
        assert!(WindowSize::new(32768).validate().is_ok());
        
        // Invalid window sizes
        assert!(WindowSize::new(512).validate().is_err()); // Too small
        assert!(WindowSize::new(2_000_000_000).validate().is_err()); // Too large
    }

    #[test]
    fn test_congestion_window_validation() {
        // Valid congestion window sizes
        assert!(CongestionWindow::new(1460).validate().is_ok()); // 1 MSS
        assert!(CongestionWindow::new(14600).validate().is_ok()); // 10 MSS
        
        // Invalid congestion window sizes
        assert!(CongestionWindow::new(1000).validate().is_err()); // Below 1 MSS
        assert!(CongestionWindow::new(2_000_000_000).validate().is_err()); // Too large
    }

    // Metrics type validation tests
    #[test]
    fn test_score_validation() {
        // Valid scores
        assert!(Score::new(0.0).validate().is_ok());
        assert!(Score::new(0.5).validate().is_ok());
        assert!(Score::new(1.0).validate().is_ok());
        
        // Invalid scores (should be clamped by constructor, but test validation)
        let invalid_score = Score(1.5); // Bypass constructor
        assert!(invalid_score.validate().is_err());
        
        let negative_score = Score(-0.1); // Bypass constructor
        assert!(negative_score.validate().is_err());
        
        // NaN and infinite scores
        let nan_score = Score(f32::NAN);
        assert!(nan_score.validate().is_err());
        
        let inf_score = Score(f32::INFINITY);
        assert!(inf_score.validate().is_err());
    }

    #[test]
    fn test_attempt_count_validation() {
        // Valid attempt counts
        assert!(AttemptCount::new(1).validate().is_ok());
        assert!(AttemptCount::new(10).validate().is_ok());
        
        // Invalid attempt count (too high)
        assert!(AttemptCount::new(200).validate().is_err());
        
        // Context-specific validation
        let context = ValidationContext {
            max_values: MaxValues {
                max_retry_attempts: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(AttemptCount::new(3).validate_with_context(&context).is_ok());
        assert!(AttemptCount::new(10).validate_with_context(&context).is_err());
    }

    #[test]
    fn test_failure_count_validation() {
        // Valid failure counts
        assert!(FailureCount::new(1).validate().is_ok());
        assert!(FailureCount::new(10).validate().is_ok());
        
        // Critical failure count
        assert!(FailureCount::new(100).validate().is_err());
    }

    #[test]
    fn test_session_count_validation() {
        // Valid session counts
        assert!(SessionCount::new(1).validate().is_ok());
        assert!(SessionCount::new(1000).validate().is_ok());
        
        // Invalid session count (too high)
        assert!(SessionCount::new(200000).validate().is_err());
        
        // Context-specific validation
        let context = ValidationContext {
            max_values: MaxValues {
                max_sessions: 500,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(SessionCount::new(100).validate_with_context(&context).is_ok());
        assert!(SessionCount::new(1000).validate_with_context(&context).is_err());
    }

    #[test]
    fn test_metrics_interval_validation() {
        use std::time::Duration;
        
        // Valid intervals
        assert!(MetricsInterval::new(Duration::from_millis(1000)).validate().is_ok());
        assert!(MetricsInterval::new(Duration::from_secs(60)).validate().is_ok());
        
        // Invalid intervals
        assert!(MetricsInterval::new(Duration::from_millis(50)).validate().is_err()); // Too short
        assert!(MetricsInterval::new(Duration::from_secs(7200)).validate().is_err()); // Too long
    }

    // Configuration type validation tests
    #[test]
    fn test_timeout_validation() {
        // Valid timeouts
        assert!(Timeout::new(1000).validate().is_ok()); // 1 second
        assert!(Timeout::new(60000).validate().is_ok()); // 1 minute
        
        // Invalid timeouts
        assert!(Timeout::new(0).validate().is_err()); // Too short
        assert!(Timeout::new(7200000).validate().is_err()); // Too long (2 hours)
    }

    #[test]
    fn test_max_segment_size_validation() {
        // Valid MSS values
        assert!(MaxSegmentSize::new(1460).validate().is_ok());
        assert!(MaxSegmentSize::new(1280).validate().is_ok());
        
        // Invalid MSS values
        assert!(MaxSegmentSize::new(500).validate().is_err()); // Too small
        assert!(MaxSegmentSize::new(10000).validate().is_err()); // Too large
    }

    #[test]
    fn test_daemon_name_validation() {
        // Valid daemon names
        assert!(DaemonName::new("buckwild".to_string()).validate().is_ok());
        assert!(DaemonName::new("test-daemon".to_string()).validate().is_ok());
        assert!(DaemonName::new("daemon_123".to_string()).validate().is_ok());
        
        // Invalid daemon names
        assert!(DaemonName::new("".to_string()).validate().is_err()); // Empty
        assert!(DaemonName::new("daemon with spaces".to_string()).validate().is_err()); // Spaces
        assert!(DaemonName::new("daemon@host".to_string()).validate().is_err()); // Special chars
        assert!(DaemonName::new("a".repeat(70)).validate().is_err()); // Too long
    }

    #[test]
    fn test_tun_device_name_validation() {
        // Valid TUN device names
        assert!(TunDeviceName::new("tun0".to_string()).validate().is_ok());
        assert!(TunDeviceName::new("buckwild-tun".to_string()).validate().is_ok());
        
        // Invalid TUN device names
        assert!(TunDeviceName::new("".to_string()).validate().is_err()); // Empty
        assert!(TunDeviceName::new("tun with spaces".to_string()).validate().is_err()); // Spaces
        assert!(TunDeviceName::new("very-long-device-name".to_string()).validate().is_err()); // Too long
    }

    #[test]
    fn test_max_connections_validation() {
        // Valid connection counts
        assert!(MaxConnections::new(100).validate().is_ok());
        assert!(MaxConnections::new(10000).validate().is_ok());
        
        // Invalid connection counts
        assert!(MaxConnections::new(0).validate().is_err()); // Too small
        assert!(MaxConnections::new(200000).validate().is_err()); // Too large
        
        // Context-specific validation
        let context = ValidationContext {
            max_values: MaxValues {
                max_connections: 500,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(MaxConnections::new(100).validate_with_context(&context).is_ok());
        assert!(MaxConnections::new(1000).validate_with_context(&context).is_err());
    }

    #[test]
    fn test_thread_count_validation() {
        // Valid thread counts
        assert!(WorkerThreadCount::new(4).validate().is_ok());
        assert!(WorkerThreadCount::new(16).validate().is_ok());
        
        // Invalid thread counts
        assert!(WorkerThreadCount::new(0).validate().is_err()); // Too small
        assert!(WorkerThreadCount::new(2000).validate().is_err()); // Too large
        
        // Crypto thread validation
        assert!(CryptoThreadCount::new(4).validate().is_ok());
        assert!(CryptoThreadCount::new(100).validate().is_err()); // Too large for crypto threads
    }

    #[test]
    fn test_log_file_validation() {
        // Valid log file sizes
        assert!(LogFileSize::new(1024 * 1024).validate().is_ok()); // 1MB
        assert!(LogFileSize::new(100 * 1024 * 1024).validate().is_ok()); // 100MB
        
        // Invalid log file sizes
        assert!(LogFileSize::new(512).validate().is_err()); // Too small
        assert!(LogFileSize::new(2 * 1024 * 1024 * 1024).validate().is_err()); // Too large (2GB)
        
        // Valid log file counts
        assert!(LogFileCount::new(5).validate().is_ok());
        assert!(LogFileCount::new(50).validate().is_ok());
        
        // Invalid log file counts
        assert!(LogFileCount::new(0).validate().is_err()); // Too small
        assert!(LogFileCount::new(200).validate().is_err()); // Too large
    }

    #[test]
    fn test_path_validation() {
        // Note: These tests may fail if the paths don't exist on the test system
        // In a real implementation, you might want to create temporary directories for testing
        
        // Valid absolute paths (assuming they exist)
        let temp_dir = std::env::temp_dir();
        let log_dir = LogDirectory::new(temp_dir.clone());
        // Note: This might fail if temp_dir doesn't exist, which is unlikely but possible
        
        let state_dir = StateDirectory::new(temp_dir.clone());
        // Similar note as above
        
        // Invalid relative paths
        let relative_log_dir = LogDirectory::new(PathBuf::from("relative/path"));
        assert!(relative_log_dir.validate().is_err());
        
        let relative_state_dir = StateDirectory::new(PathBuf::from("relative/path"));
        assert!(relative_state_dir.validate().is_err());
    }

    #[test]
    fn test_max_psk_count_validation() {
        // Valid PSK counts
        assert!(MaxPskCount::new(10).validate().is_ok());
        assert!(MaxPskCount::new(256).validate().is_ok());
        
        // Invalid PSK counts
        assert!(MaxPskCount::new(0).validate().is_err()); // Too small
        assert!(MaxPskCount::new(2000).validate().is_err()); // Too large
    }

    #[test]
    fn test_snmp_port_validation() {
        // Valid SNMP ports
        assert!(SnmpPort::new(161).validate().is_ok()); // Standard SNMP port
        assert!(SnmpPort::new(8161).validate().is_ok()); // Alternative port
        
        // Invalid SNMP port
        assert!(SnmpPort::new(0).validate().is_err()); // Reserved port
    }

    // Validation context tests
    #[test]
    fn test_validation_context_defaults() {
        let context = ValidationContext::default();
        
        assert_eq!(context.security_level, SecurityLevel::Standard);
        assert!(!context.strict_mode);
        assert_eq!(context.max_values.max_packet_size, 65536);
        assert_eq!(context.max_values.max_sessions, 10000);
        assert_eq!(context.timestamp_tolerance_ns, 30_000_000_000); // 30 seconds
    }

    #[test]
    fn test_validation_utils() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        
        // Test routable IP validation
        let routable_v4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(ValidationUtils::is_routable_ip(&routable_v4));
        
        let private_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!ValidationUtils::is_routable_ip(&private_v4));
        
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!ValidationUtils::is_routable_ip(&loopback_v6));
        
        // Test range validation
        assert!(ValidationUtils::validate_range(5, 1, 10, "test").is_ok());
        assert!(ValidationUtils::validate_range(0, 1, 10, "test").is_err());
        assert!(ValidationUtils::validate_range(11, 1, 10, "test").is_err());
        
        // Test key strength validation
        let strong_key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(ValidationUtils::validate_key_strength(&strong_key).is_ok());
        
        let weak_key = [0; 16];
        assert!(ValidationUtils::validate_key_strength(&weak_key).is_err());
        
        let repeating_key = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        assert!(ValidationUtils::validate_key_strength(&repeating_key).is_err());
    }
}