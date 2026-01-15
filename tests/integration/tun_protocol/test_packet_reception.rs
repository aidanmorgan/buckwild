//! TUN Device Packet Reception Integration Tests
//!
//! These tests validate that packets received on the TUN device are correctly
//! parsed into protocol-level structures following the protocol specification.
//!
//! Test-Driven Development: These tests are written FIRST, before implementation.
//! They describe the desired behavior.

#[cfg(test)]
mod tun_reception_tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::time::timeout;

    // Import types from common protocol
    use buckwild_common::protocol::types::*;

    // These will be implemented to make tests pass
    use crate::mock_tun::MockTunDevice;
    use crate::protocol_helpers::{create_protocol_syn_packet, parse_protocol_packet};

    /// Test 1.1: TUN device receives and parses a SYN packet
    ///
    /// This test verifies the complete flow:
    /// 1. Raw IP packet arrives on TUN device
    /// 2. Packet is read from TUN
    /// 3. Packet is parsed according to protocol spec (03-packet-architecture.md)
    /// 4. Session ID, sequence number, and type are extracted
    /// 5. Packet validation (checksum/HMAC) is performed
    #[tokio::test]
    async fn test_tun_receives_and_parses_syn_packet() {
        // ARRANGE: Create mock TUN device
        // This simulates a virtual network interface
        let tun = MockTunDevice::new("test0")
            .await
            .expect("Failed to create mock TUN device");

        // Create a valid SYN packet according to protocol specification
        // See design/protocol/03-packet-architecture.md for packet format
        let syn_packet = create_protocol_syn_packet(
            session_id: SessionId::from_raw(0x1234),
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            dst_ip: Ipv4Addr::new(192, 168, 1, 200),
            src_port: Port::from_raw(5000),
            dst_port: Port::from_raw(5001),
        );

        // ACT: Inject packet into TUN device (simulates network arrival)
        tun.inject_packet(&syn_packet)
            .await
            .expect("Failed to inject packet");

        // Read packet from TUN device with timeout
        let result = timeout(Duration::from_secs(1), tun.read_parsed_packet()).await;

        // ASSERT: Packet was received and parsed
        assert!(result.is_ok(), "Timeout waiting for packet");

        let parsed = result
            .unwrap()
            .expect("Failed to parse packet");

        // Verify packet type
        assert_eq!(
            parsed.packet_type(),
            PacketType::Syn,
            "Expected SYN packet type"
        );

        // Verify session ID
        assert_eq!(
            parsed.session_id(),
            SessionId::from_raw(0x1234),
            "Session ID mismatch"
        );

        // Verify IP addresses
        assert_eq!(
            parsed.src_ip(),
            Ipv4Addr::new(192, 168, 1, 100),
            "Source IP mismatch"
        );
        assert_eq!(
            parsed.dst_ip(),
            Ipv4Addr::new(192, 168, 1, 200),
            "Destination IP mismatch"
        );

        // Verify ports
        assert_eq!(parsed.src_port(), Port::from_raw(5000), "Source port mismatch");
        assert_eq!(parsed.dst_port(), Port::from_raw(5001), "Dest port mismatch");

        // Verify checksum is valid
        assert!(
            parsed.validate_checksum(),
            "Packet checksum validation failed"
        );
    }

    /// Test 1.2: TUN device handles invalid packets gracefully
    ///
    /// This test verifies error handling:
    /// 1. Invalid/malformed packet arrives
    /// 2. Parser detects the error
    /// 3. Appropriate error is returned
    /// 4. System remains stable
    #[tokio::test]
    async fn test_tun_handles_invalid_packet() {
        // ARRANGE: Create mock TUN device
        let tun = MockTunDevice::new("test0")
            .await
            .expect("Failed to create mock TUN device");

        // Create invalid packet (too small, corrupted header, etc.)
        let invalid_packet = vec![0xFF; 16]; // Only 16 bytes, protocol requires minimum 32

        // ACT: Inject invalid packet
        tun.inject_raw_bytes(&invalid_packet)
            .await
            .expect("Failed to inject packet");

        // Try to read and parse
        let result = timeout(Duration::from_millis(500), tun.read_parsed_packet()).await;

        // ASSERT: Either timeout (packet dropped) or explicit error
        match result {
            Ok(Ok(parsed)) => {
                panic!("Invalid packet should not parse successfully: {:?}", parsed);
            }
            Ok(Err(e)) => {
                // Expected: parse error
                println!("Correctly rejected invalid packet: {}", e);
            }
            Err(_) => {
                // Expected: packet was dropped, no event generated
                println!("Invalid packet correctly dropped (timeout)");
            }
        }
    }

    /// Test 1.3: TUN device handles multiple packets in sequence
    ///
    /// This test verifies:
    /// 1. Multiple packets arrive in sequence
    /// 2. Each is processed independently
    /// 3. Order is preserved
    /// 4. No packets are lost
    #[tokio::test]
    async fn test_tun_handles_multiple_packets() {
        // ARRANGE: Create mock TUN device
        let tun = MockTunDevice::new("test0")
            .await
            .expect("Failed to create mock TUN device");

        // Create sequence of different packet types
        let syn_packet = create_protocol_syn_packet(
            session_id: SessionId::from_raw(0x1000),
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            src_port: Port::from_raw(5000),
            dst_port: Port::from_raw(5001),
        );

        let data_packet = create_protocol_data_packet(
            session_id: SessionId::from_raw(0x1000),
            sequence: SequenceNumber::new(1),
            payload: b"test data",
        );

        let ack_packet = create_protocol_ack_packet(
            session_id: SessionId::from_raw(0x1000),
            ack_number: AckNumber::new(1),
        );

        // ACT: Inject all packets
        tun.inject_packet(&syn_packet).await.unwrap();
        tun.inject_packet(&data_packet).await.unwrap();
        tun.inject_packet(&ack_packet).await.unwrap();

        // ASSERT: Read all three packets in order
        let packet1 = timeout(Duration::from_secs(1), tun.read_parsed_packet())
            .await
            .expect("Timeout on packet 1")
            .expect("Failed to parse packet 1");

        assert_eq!(packet1.packet_type(), PacketType::Syn);

        let packet2 = timeout(Duration::from_secs(1), tun.read_parsed_packet())
            .await
            .expect("Timeout on packet 2")
            .expect("Failed to parse packet 2");

        assert_eq!(packet2.packet_type(), PacketType::Data);
        assert_eq!(packet2.sequence_number(), SequenceNumber::new(1));

        let packet3 = timeout(Duration::from_secs(1), tun.read_parsed_packet())
            .await
            .expect("Timeout on packet 3")
            .expect("Failed to parse packet 3");

        assert_eq!(packet3.packet_type(), PacketType::Ack);
        assert_eq!(packet3.ack_number(), AckNumber::new(1));
    }

    /// Test 1.4: TUN device extracts protocol header fields correctly
    ///
    /// This test validates detailed header parsing according to:
    /// design/protocol/03-packet-architecture.md
    ///
    /// Verifies:
    /// - Version byte parsing
    /// - Session ID length detection (16/32/64-bit)
    /// - Timestamp extraction
    /// - Flags parsing
    #[tokio::test]
    async fn test_tun_extracts_protocol_headers_correctly() {
        // ARRANGE: Create mock TUN device
        let tun = MockTunDevice::new("test0")
            .await
            .expect("Failed to create mock TUN device");

        // Create packet with specific header configuration
        // Version byte: 0x71 = v1 + 32-bit ID + 24-bit timestamp
        let packet = create_protocol_packet_with_config(
            version: 0x71,
            session_id: SessionId::from_raw(0x12345678), // 32-bit
            timestamp: Timestamp::from_millis(100000), // 24-bit timestamp
            packet_type: PacketType::Data,
            flags: 0x01, // Some flag set
        );

        // ACT: Inject and parse
        tun.inject_packet(&packet).await.unwrap();
        let parsed = tun.read_parsed_packet().await.unwrap();

        // ASSERT: Header fields extracted correctly
        assert_eq!(parsed.version(), 0x01, "Protocol version should be 1");
        assert_eq!(
            parsed.session_id(),
            SessionId::from_raw(0x12345678),
            "Session ID mismatch"
        );
        assert_eq!(
            parsed.timestamp(),
            Timestamp::from_millis(100000),
            "Timestamp mismatch"
        );
        assert_eq!(parsed.flags(), 0x01, "Flags mismatch");

        // Verify adaptive header was correctly detected
        let config = parsed.header_config();
        assert_eq!(config.session_id_length(), 4, "Should detect 32-bit session ID");
        assert_eq!(config.timestamp_length(), 3, "Should detect 24-bit timestamp");
    }

    /// Test 1.5: TUN device validates HMAC authentication
    ///
    /// Per design/protocol/03-packet-architecture.md section on HMAC Policy:
    /// - Different packet types have different HMAC requirements
    /// - DATA packets require HMAC-SHA256 (256-bit)
    /// - Control packets may use shorter HMACs
    #[tokio::test]
    async fn test_tun_validates_hmac_authentication() {
        // ARRANGE: Create mock TUN device with PSK
        let psk = Psk::generate();
        let tun = MockTunDevice::new_with_psk("test0", psk.clone())
            .await
            .expect("Failed to create mock TUN device");

        // Create DATA packet with valid HMAC
        let data_packet = create_protocol_data_packet_authenticated(
            session_id: SessionId::from_raw(0x1234),
            sequence: SequenceNumber::new(1),
            payload: b"authenticated data",
            psk: &psk,
        );

        // ACT: Inject packet
        tun.inject_packet(&data_packet).await.unwrap();
        let parsed = tun.read_parsed_packet().await.unwrap();

        // ASSERT: HMAC validation passed
        assert!(
            parsed.validate_hmac(&psk),
            "HMAC validation should pass for authenticated packet"
        );

        // Verify HMAC policy
        assert_eq!(
            parsed.hmac_length(),
            32,
            "DATA packets should use 256-bit HMAC"
        );
    }

    /// Test 1.6: TUN device rejects packets with invalid HMAC
    #[tokio::test]
    async fn test_tun_rejects_invalid_hmac() {
        // ARRANGE: Create mock TUN device with PSK
        let psk = Psk::generate();
        let wrong_psk = Psk::generate(); // Different PSK

        let tun = MockTunDevice::new_with_psk("test0", psk.clone())
            .await
            .expect("Failed to create mock TUN device");

        // Create packet authenticated with wrong PSK
        let bad_packet = create_protocol_data_packet_authenticated(
            session_id: SessionId::from_raw(0x1234),
            sequence: SequenceNumber::new(1),
            payload: b"tampered data",
            psk: &wrong_psk, // Wrong PSK!
        );

        // ACT: Inject packet
        tun.inject_packet(&bad_packet).await.unwrap();

        // Try to read - should either timeout or return error
        let result = timeout(Duration::from_millis(500), tun.read_parsed_packet()).await;

        // ASSERT: Packet rejected
        match result {
            Ok(Ok(parsed)) => {
                // If we get a packet, HMAC validation must fail
                assert!(
                    !parsed.validate_hmac(&psk),
                    "HMAC validation should fail for packet with wrong key"
                );
            }
            Ok(Err(e)) => {
                // Expected: HMAC validation error
                println!("Correctly rejected packet with invalid HMAC: {}", e);
            }
            Err(_) => {
                // Expected: packet dropped due to HMAC failure
                println!("Packet with invalid HMAC correctly dropped");
            }
        }
    }
}
