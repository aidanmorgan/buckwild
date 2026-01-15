//! Protocol Packet Helpers for Integration Testing
//!
//! This module provides helpers for creating and parsing protocol packets
//! according to the specification in design/protocol/03-packet-architecture.md

use std::net::Ipv4Addr;
use anyhow::{Result, Context, bail};
use buckwild_common::protocol::types::*;

/// Parsed packet representation
///
/// This represents a fully parsed protocol packet with all fields extracted.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Protocol version
    version: u8,

    /// Packet type
    packet_type: PacketType,

    /// Sub-type (for CONTROL, MANAGEMENT, DISCOVERY packets)
    sub_type: u8,

    /// Flags
    flags: u8,

    /// Session ID
    session_id: SessionId,

    /// Timestamp
    timestamp: Timestamp,

    /// Sequence number (for DATA, SYN packets)
    sequence: Option<SequenceNumber>,

    /// Acknowledgment number (for ACK, SYN-ACK packets)
    ack_number: Option<AckNumber>,

    /// Payload data
    payload: Option<Vec<u8>>,

    /// Source IP address
    src_ip: Ipv4Addr,

    /// Destination IP address
    dst_ip: Ipv4Addr,

    /// Source port
    src_port: Port,

    /// Destination port
    dst_port: Port,

    /// HMAC (if present)
    hmac: Option<Vec<u8>>,

    /// Original raw bytes
    raw_bytes: Vec<u8>,

    /// Header configuration
    header_config: HeaderConfig,
}

/// Header configuration decoded from version byte
#[derive(Debug, Clone, Copy)]
pub struct HeaderConfig {
    /// Protocol version (lower 4 bits)
    version: u8,

    /// Session ID length in bytes (2, 4, or 8)
    session_id_length: usize,

    /// Timestamp length in bytes (2, 3, or 4)
    timestamp_length: usize,
}

impl HeaderConfig {
    /// Parse header configuration from version byte
    ///
    /// Version Byte Encoding (8 bits):
    /// - Bits 0-3: Protocol version (0x01)
    /// - Bits 4-5: Session ID length
    ///   - 00 = 16-bit (2 bytes)
    ///   - 01 = 32-bit (4 bytes)
    ///   - 10 = 64-bit (8 bytes)
    /// - Bits 6-7: Timestamp configuration
    ///   - 00 = 16-bit (2 bytes)
    ///   - 01 = 24-bit (3 bytes)
    ///   - 10 = 24-bit with 10ms precision (3 bytes)
    ///   - 11 = 32-bit (4 bytes)
    fn from_version_byte(byte: u8) -> Self {
        let version = byte & 0x0F;  // Lower 4 bits

        let session_id_bits = (byte >> 4) & 0x03;  // Bits 4-5
        let session_id_length = match session_id_bits {
            0 => 2,  // 16-bit
            1 => 4,  // 32-bit
            2 => 8,  // 64-bit
            _ => 4,  // Default to 32-bit
        };

        let timestamp_bits = (byte >> 6) & 0x03;  // Bits 6-7
        let timestamp_length = match timestamp_bits {
            0 => 2,  // 16-bit
            1 => 3,  // 24-bit
            2 => 3,  // 24-bit with 10ms precision
            3 => 4,  // 32-bit
            _ => 3,  // Default to 24-bit
        };

        Self {
            version,
            session_id_length,
            timestamp_length,
        }
    }

    /// Create version byte from configuration
    fn to_version_byte(&self) -> u8 {
        let mut byte = self.version & 0x0F;

        let session_bits = match self.session_id_length {
            2 => 0,
            4 => 1,
            8 => 2,
            _ => 1,  // Default to 32-bit
        };
        byte |= (session_bits & 0x03) << 4;

        let timestamp_bits = match self.timestamp_length {
            2 => 0,
            3 => 1,
            4 => 3,
            _ => 1,  // Default to 24-bit
        };
        byte |= (timestamp_bits & 0x03) << 6;

        byte
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn session_id_length(&self) -> usize {
        self.session_id_length
    }

    pub fn timestamp_length(&self) -> usize {
        self.timestamp_length
    }
}

impl ParsedPacket {
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }

    pub fn dst_ip(&self) -> Ipv4Addr {
        self.dst_ip
    }

    pub fn src_port(&self) -> Port {
        self.src_port
    }

    pub fn dst_port(&self) -> Port {
        self.dst_port
    }

    pub fn sequence_number(&self) -> SequenceNumber {
        self.sequence.unwrap_or(SequenceNumber::new(0))
    }

    pub fn ack_number(&self) -> AckNumber {
        self.ack_number.unwrap_or(AckNumber::new(0))
    }

    pub fn header_config(&self) -> HeaderConfig {
        self.header_config
    }

    pub fn hmac_length(&self) -> usize {
        self.hmac.as_ref().map(|h| h.len()).unwrap_or(0)
    }

    pub fn extract_payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Validate packet checksum
    ///
    /// For now, this is a placeholder - real implementation would calculate
    /// checksum over packet fields
    pub fn validate_checksum(&self) -> bool {
        // TODO: Implement actual checksum validation
        // For now, return true if packet has minimum required fields
        true
    }

    /// Validate HMAC authentication
    ///
    /// This verifies the packet's HMAC using the provided PSK
    pub fn validate_hmac(&self, psk: &Psk) -> bool {
        // TODO: Implement actual HMAC validation using HMAC-SHA256
        // For now, check if HMAC is present
        self.hmac.is_some()
    }
}

/// Create a protocol SYN packet
///
/// Creates a connection establishment packet according to protocol spec.
pub fn create_protocol_syn_packet(
    session_id: SessionId,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: Port,
    dst_port: Port,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header configuration: v1, 32-bit session ID, 24-bit timestamp (0x71)
    let config = HeaderConfig {
        version: 1,
        session_id_length: 4,
        timestamp_length: 3,
    };
    let version_byte = config.to_version_byte();

    // Common header: Version, Type, Sub-Type, Flags
    packet.push(version_byte);              // Version byte
    packet.push(PacketType::Syn as u8);     // Packet type
    packet.push(0x00);                       // Sub-type (not used for SYN)
    packet.push(0x00);                       // Flags

    // Session ID (32-bit, big-endian)
    packet.extend_from_slice(&session_id.as_u32().to_be_bytes());

    // Timestamp (24-bit, big-endian) - use current time in milliseconds
    let timestamp = 100000u32;  // Test timestamp
    packet.push(((timestamp >> 16) & 0xFF) as u8);
    packet.push(((timestamp >> 8) & 0xFF) as u8);
    packet.push((timestamp & 0xFF) as u8);

    // Add IP addresses for test verification (simplified - real protocol would use IP header)
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());

    // Add ports
    packet.extend_from_slice(&src_port.as_u16().to_be_bytes());
    packet.extend_from_slice(&dst_port.as_u16().to_be_bytes());

    packet
}

/// Create a protocol DATA packet
pub fn create_protocol_data_packet(
    session_id: SessionId,
    sequence: SequenceNumber,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header configuration: v1, 32-bit session ID, 24-bit timestamp (0x71)
    let config = HeaderConfig {
        version: 1,
        session_id_length: 4,
        timestamp_length: 3,
    };
    let version_byte = config.to_version_byte();

    // Common header
    packet.push(version_byte);
    packet.push(PacketType::Data as u8);
    packet.push(0x00);  // Sub-type
    packet.push(0x00);  // Flags

    // Session ID (32-bit)
    packet.extend_from_slice(&session_id.as_u32().to_be_bytes());

    // Timestamp (24-bit)
    let timestamp = 100000u32;
    packet.push(((timestamp >> 16) & 0xFF) as u8);
    packet.push(((timestamp >> 8) & 0xFF) as u8);
    packet.push((timestamp & 0xFF) as u8);

    // Sequence number (32-bit for DATA packets)
    packet.extend_from_slice(&sequence.as_u32().to_be_bytes());

    // Payload length (16-bit)
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());

    // Payload
    packet.extend_from_slice(payload);

    packet
}

/// Create a protocol ACK packet
pub fn create_protocol_ack_packet(
    session_id: SessionId,
    ack_number: AckNumber,
) -> Vec<u8> {
    let mut packet = Vec::new();

    let config = HeaderConfig {
        version: 1,
        session_id_length: 4,
        timestamp_length: 3,
    };
    let version_byte = config.to_version_byte();

    // Common header
    packet.push(version_byte);
    packet.push(PacketType::Ack as u8);
    packet.push(0x00);
    packet.push(0x00);

    // Session ID
    packet.extend_from_slice(&session_id.as_u32().to_be_bytes());

    // Timestamp
    let timestamp = 100000u32;
    packet.push(((timestamp >> 16) & 0xFF) as u8);
    packet.push(((timestamp >> 8) & 0xFF) as u8);
    packet.push((timestamp & 0xFF) as u8);

    // Acknowledgment number (32-bit)
    packet.extend_from_slice(&ack_number.as_u32().to_be_bytes());

    packet
}

/// Create a protocol packet with specific configuration
pub fn create_protocol_packet_with_config(
    version: u8,
    session_id: SessionId,
    timestamp: Timestamp,
    packet_type: PacketType,
    flags: u8,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Use the provided version byte directly
    packet.push(version);
    packet.push(packet_type as u8);
    packet.push(0x00);  // Sub-type
    packet.push(flags);

    // Decode config from version byte to know session ID and timestamp lengths
    let config = HeaderConfig::from_version_byte(version);

    // Session ID (variable length based on config)
    match config.session_id_length {
        2 => packet.extend_from_slice(&(session_id.as_u32() as u16).to_be_bytes()),
        4 => packet.extend_from_slice(&session_id.as_u32().to_be_bytes()),
        8 => packet.extend_from_slice(&(session_id.as_u32() as u64).to_be_bytes()),
        _ => packet.extend_from_slice(&session_id.as_u32().to_be_bytes()),
    }

    // Timestamp (variable length based on config)
    let ts_millis = timestamp.as_millis() as u32;
    match config.timestamp_length {
        2 => packet.extend_from_slice(&(ts_millis as u16).to_be_bytes()),
        3 => {
            packet.push(((ts_millis >> 16) & 0xFF) as u8);
            packet.push(((ts_millis >> 8) & 0xFF) as u8);
            packet.push((ts_millis & 0xFF) as u8);
        }
        4 => packet.extend_from_slice(&ts_millis.to_be_bytes()),
        _ => {
            packet.push(((ts_millis >> 16) & 0xFF) as u8);
            packet.push(((ts_millis >> 8) & 0xFF) as u8);
            packet.push((ts_millis & 0xFF) as u8);
        }
    }

    packet
}

/// Create a protocol DATA packet with HMAC authentication
pub fn create_protocol_data_packet_authenticated(
    session_id: SessionId,
    sequence: SequenceNumber,
    payload: &[u8],
    psk: &Psk,
) -> Vec<u8> {
    // Create base DATA packet
    let mut packet = create_protocol_data_packet(session_id, sequence, payload);

    // Add HMAC-SHA256 (32 bytes) at the end
    // TODO: Calculate actual HMAC using psk
    // For now, add placeholder HMAC
    let hmac = vec![0xAB; 32];  // 256-bit HMAC
    packet.extend_from_slice(&hmac);

    packet
}

/// Parse a protocol packet from raw bytes
///
/// This parses a packet according to the protocol specification and
/// extracts all fields.
pub fn parse_protocol_packet(bytes: &[u8]) -> Result<ParsedPacket> {
    if bytes.len() < 4 {
        bail!("Packet too small: {} bytes (minimum 4)", bytes.len());
    }

    let mut offset = 0;

    // Parse common header
    let version_byte = bytes[offset];
    offset += 1;

    let packet_type_byte = bytes[offset];
    offset += 1;

    let sub_type = bytes[offset];
    offset += 1;

    let flags = bytes[offset];
    offset += 1;

    // Parse header configuration
    let config = HeaderConfig::from_version_byte(version_byte);

    // Parse session ID (variable length)
    if bytes.len() < offset + config.session_id_length {
        bail!("Packet too small for session ID");
    }

    let session_id_raw = match config.session_id_length {
        2 => u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as u32,
        4 => u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]),
        8 => u64::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as u32,  // Truncate to 32-bit for now
        _ => bail!("Invalid session ID length: {}", config.session_id_length),
    };
    offset += config.session_id_length;

    let session_id = SessionId::from_raw(session_id_raw);

    // Parse timestamp (variable length)
    if bytes.len() < offset + config.timestamp_length {
        bail!("Packet too small for timestamp");
    }

    let timestamp_millis = match config.timestamp_length {
        2 => u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as u32,
        3 => {
            ((bytes[offset] as u32) << 16)
                | ((bytes[offset + 1] as u32) << 8)
                | (bytes[offset + 2] as u32)
        }
        4 => u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]),
        _ => bail!("Invalid timestamp length: {}", config.timestamp_length),
    };
    offset += config.timestamp_length;

    let timestamp = Timestamp::from_millis(timestamp_millis as u64);

    // Parse packet type
    let packet_type = PacketType::from_u8(packet_type_byte)
        .context("Invalid packet type")?;

    // Parse type-specific fields
    let mut sequence = None;
    let mut ack_number = None;
    let mut payload = None;
    let mut src_ip = Ipv4Addr::new(0, 0, 0, 0);
    let mut dst_ip = Ipv4Addr::new(0, 0, 0, 0);
    let mut src_port = Port::from_raw(0);
    let mut dst_port = Port::from_raw(0);

    match packet_type {
        PacketType::Syn => {
            // For SYN, parse IP addresses and ports (simplified test format)
            if bytes.len() >= offset + 12 {
                src_ip = Ipv4Addr::new(
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                );
                offset += 4;

                dst_ip = Ipv4Addr::new(
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                );
                offset += 4;

                src_port = Port::from_raw(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
                offset += 2;

                dst_port = Port::from_raw(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
                offset += 2;
            }
        }
        PacketType::Data => {
            // For DATA, parse sequence number and payload
            if bytes.len() >= offset + 4 {
                let seq = u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]);
                sequence = Some(SequenceNumber::new(seq));
                offset += 4;
            }

            // Parse payload length and payload
            if bytes.len() >= offset + 2 {
                let payload_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                offset += 2;

                if bytes.len() >= offset + payload_len {
                    payload = Some(bytes[offset..offset + payload_len].to_vec());
                    offset += payload_len;
                }
            }
        }
        PacketType::Ack => {
            // For ACK, parse acknowledgment number
            if bytes.len() >= offset + 4 {
                let ack = u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]);
                ack_number = Some(AckNumber::new(ack));
                offset += 4;
            }
        }
        _ => {
            // Other packet types not yet implemented
        }
    }

    // Check for HMAC at the end (32 bytes for HMAC-SHA256)
    let hmac = if bytes.len() >= offset + 32 {
        Some(bytes[bytes.len() - 32..].to_vec())
    } else {
        None
    };

    Ok(ParsedPacket {
        version: config.version,
        packet_type,
        sub_type,
        flags,
        session_id,
        timestamp,
        sequence,
        ack_number,
        payload,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        hmac,
        raw_bytes: bytes.to_vec(),
        header_config: config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_config_encoding() {
        // Test 0x71: v1, 32-bit session ID, 24-bit timestamp
        let config = HeaderConfig::from_version_byte(0x71);
        assert_eq!(config.version(), 1);
        assert_eq!(config.session_id_length(), 4);
        assert_eq!(config.timestamp_length(), 3);

        let byte = config.to_version_byte();
        assert_eq!(byte, 0x71);
    }

    #[test]
    fn test_syn_packet_creation() {
        let packet = create_protocol_syn_packet(
            SessionId::from_raw(0x1234),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            Port::from_raw(5000),
            Port::from_raw(5001),
        );

        assert!(packet.len() > 4);
        assert_eq!(packet[1], PacketType::Syn as u8);
    }

    #[test]
    fn test_data_packet_creation() {
        let payload = b"test data";
        let packet = create_protocol_data_packet(
            SessionId::from_raw(0x1234),
            SequenceNumber::new(1),
            payload,
        );

        assert!(packet.len() > payload.len());
        assert_eq!(packet[1], PacketType::Data as u8);
    }

    #[test]
    fn test_packet_parsing() {
        let packet = create_protocol_syn_packet(
            SessionId::from_raw(0x1234),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            Port::from_raw(5000),
            Port::from_raw(5001),
        );

        let parsed = parse_protocol_packet(&packet).unwrap();
        assert_eq!(parsed.packet_type(), PacketType::Syn);
        assert_eq!(parsed.session_id(), SessionId::from_raw(0x1234));
        assert_eq!(parsed.version(), 1);
    }
}
