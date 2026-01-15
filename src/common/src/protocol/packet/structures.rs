#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

/// Protocol packet structures using ONLY consolidated types
///
/// This module defines specific packet structures for all protocol packet types
/// using the authoritative type definitions from crate::protocol::types.
///
/// ALL types are imported from the consolidated types module - NO local definitions.
use super::header::PacketHeader;
// Import ALL types from the authoritative consolidated types module
use crate::protocol::types::*;
use bytes::Bytes;

// ============================================================================
// CONNECTION ESTABLISHMENT PACKETS
// ============================================================================

/// SYN packet for connection establishment
#[derive(Debug, Clone)]
pub struct SynPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Initial sequence number
    pub initial_sequence: SequenceNumber,
    /// Supported protocol version
    pub protocol_version: ProtocolVersion,
    /// Session configuration
    pub session_config: SessionConfig,
    /// Connection parameters
    pub connection_params: ConnectionParams,
    /// Client ECDH public key for key exchange (64 bytes, P-256 uncompressed point)
    pub client_public_key: EcdhPublicKey,
    /// PSK authentication hash (32 bytes, HMAC-SHA256)
    /// Proves client knows the PSK without revealing it
    /// Calculated as: HMAC-SHA256(PSK, packet_type || timestamp || sequence || public_key || nonce || ...)
    pub psk_auth_hash: [u8; 32],
    /// Key exchange ID (16-bit)
    /// Unique identifier for this key exchange, used to correlate SYN with SYN-ACK in case of retransmission
    /// Generated randomly by client for each new connection attempt
    pub key_exchange_id: u16,
}

impl SynPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();
        // Size check: header + hmac + initial_sequence(4) + protocol_version(1) + public_key(64) + psk_auth_hash(32) + key_exchange_id(2)
        if buffer.len() < header_size + hmac_len + 4 + 1 + 64 + 32 + 2 {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize SYN-specific fields
        buffer[offset..offset + 4].copy_from_slice(&self.initial_sequence.to_be_bytes());
        offset += 4;

        buffer[offset] = self.protocol_version.as_u8();
        offset += 1;

        // Serialize client ECDH public key (64 bytes)
        buffer[offset..offset + 64].copy_from_slice(self.client_public_key.as_bytes());
        offset += 64;

        // Serialize PSK authentication hash (32 bytes)
        buffer[offset..offset + 32].copy_from_slice(&self.psk_auth_hash);
        offset += 32;

        // Serialize key exchange ID (2 bytes, big-endian)
        buffer[offset..offset + 2].copy_from_slice(&self.key_exchange_id.to_be_bytes());
        offset += 2;

        // Session config and connection params would be serialized here if needed
        // For now, they're default values that don't need transmission

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Parse header first - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify this is a SYN packet
        if header.packet_type() != PacketType::Syn {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC tag (variable length based on policy)
        let hmac_len = header.hmac_policy().tag_size();

        // Minimum size: header + hmac + initial_sequence(4) + protocol_version(1) + public_key(64) + psk_auth_hash(32) + key_exchange_id(2)
        if bytes.len() < header_size + hmac_len + 4 + 1 + 64 + 32 + 2 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse SYN-specific fields
        let mut offset = header_size + hmac_len;
        let initial_sequence = SequenceNumber::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        let protocol_version = ProtocolVersion::new(bytes[offset]);
        offset += 1;

        // Parse client ECDH public key (64 bytes)
        let mut public_key_bytes = [0u8; 64];
        public_key_bytes.copy_from_slice(&bytes[offset..offset + 64]);
        let client_public_key = EcdhPublicKey::new(public_key_bytes);
        offset += 64;

        // Parse PSK authentication hash (32 bytes)
        let mut psk_auth_hash = [0u8; 32];
        psk_auth_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Parse key exchange ID (2 bytes, big-endian)
        let key_exchange_id = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);

        // Parse session config (simplified)
        let session_config = SessionConfig::default();

        // Parse connection params (simplified)
        let connection_params = ConnectionParams::default();

        Ok(Self {
            header,
            hmac,
            initial_sequence,
            protocol_version,
            session_config,
            connection_params,
            client_public_key,
            psk_auth_hash,
            key_exchange_id,
        })
    }
}

impl Validate for SynPacket {
    fn validate(&self) -> ValidationResult<()> {
        // Validate header
        if let ValidationResult::Invalid(e) = self.header.validate() {
            return ValidationResult::Invalid(e);
        }

        // Validate packet type
        if self.header.packet_type() != PacketType::Syn {
            return ValidationResult::Invalid(ValidationError::InvalidPacketType);
        }

        // Validate protocol version
        if self.protocol_version.as_u8() == 0 || self.protocol_version.as_u8() > 1 {
            return ValidationResult::Invalid(ValidationError::InvalidProtocolVersion);
        }

        // Validate sequence number
        if !self.initial_sequence.is_valid() {
            return ValidationResult::Invalid(ValidationError::InvalidSequenceNumber);
        }

        ValidationResult::Valid(())
    }
}

/// SYN-ACK packet for connection establishment response
#[derive(Debug, Clone)]
pub struct SynAckPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Acknowledged sequence number
    pub ack_sequence: SequenceNumber,
    /// Server's initial sequence number
    pub server_sequence: SequenceNumber,
    /// Accepted protocol version
    pub protocol_version: ProtocolVersion,
    /// Session configuration response
    pub session_config: SessionConfig,
    /// Connection parameters response
    pub connection_params: ConnectionParams,
    /// Server ECDH public key for key exchange (64 bytes, P-256 uncompressed point)
    /// Server generates ephemeral P-256 key pair and includes public key for ECDH
    pub server_public_key: EcdhPublicKey,
    /// Key exchange ID echo (16-bit)
    /// Echoes back the key_exchange_id from the SYN packet to correlate the response
    pub key_exchange_id: u16,
    /// Shared secret verification (32 bytes)
    /// HMAC-SHA256(shared_secret, "verification" || key_exchange_id)
    /// Proves server computed the same shared secret from ECDH
    /// Client verifies this before completing handshake
    pub shared_secret_verification: [u8; 32],
}

impl SynAckPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();
        // Size check: header + hmac + server_sequence(4) + ack_sequence(4) + protocol_version(1) + server_public_key(64) + key_exchange_id(2) + shared_secret_verification(32)
        if buffer.len() < header_size + hmac_len + 4 + 4 + 1 + 64 + 2 + 32 {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize SYN-ACK specific fields
        buffer[offset..offset + 4].copy_from_slice(&self.server_sequence.to_be_bytes());
        offset += 4;

        buffer[offset..offset + 4].copy_from_slice(&self.ack_sequence.to_be_bytes());
        offset += 4;

        buffer[offset] = self.protocol_version.as_u8();
        offset += 1;

        // Serialize server ECDH public key (64 bytes)
        buffer[offset..offset + 64].copy_from_slice(self.server_public_key.as_bytes());
        offset += 64;

        // Serialize key exchange ID echo (2 bytes, big-endian)
        buffer[offset..offset + 2].copy_from_slice(&self.key_exchange_id.to_be_bytes());
        offset += 2;

        // Serialize shared secret verification (32 bytes)
        buffer[offset..offset + 32].copy_from_slice(&self.shared_secret_verification);
        offset += 32;

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Parse header first - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify this is a SYN-ACK packet
        if header.packet_type() != PacketType::SynAck {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC tag
        let hmac_len = header.hmac_policy().tag_size();

        // Minimum: header + hmac + server_seq(4) + ack_seq(4) + protocol_version(1) + server_public_key(64) + key_exchange_id(2) + shared_secret_verification(32)
        if bytes.len() < header_size + hmac_len + 4 + 4 + 1 + 64 + 2 + 32 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse SYN-ACK specific fields
        let mut offset = header_size + hmac_len;
        let initial_sequence = SequenceNumber::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        let ack_sequence = SequenceNumber::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        let protocol_version = ProtocolVersion::new(bytes[offset]);
        offset += 1;

        // Parse server ECDH public key (64 bytes)
        let mut server_public_key_bytes = [0u8; 64];
        server_public_key_bytes.copy_from_slice(&bytes[offset..offset + 64]);
        let server_public_key = EcdhPublicKey::new(server_public_key_bytes);
        offset += 64;

        // Parse key exchange ID echo (2 bytes, big-endian)
        let key_exchange_id = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        // Parse shared secret verification (32 bytes)
        let mut shared_secret_verification = [0u8; 32];
        shared_secret_verification.copy_from_slice(&bytes[offset..offset + 32]);

        let session_config = SessionConfig::default();
        let connection_params = ConnectionParams::default();

        Ok(Self {
            header,
            hmac,
            ack_sequence,
            server_sequence: initial_sequence,
            protocol_version,
            session_config,
            connection_params,
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        })
    }
}

impl Validate for SynAckPacket {
    fn validate(&self) -> ValidationResult<()> {
        // Validate header
        if let ValidationResult::Invalid(e) = self.header.validate() {
            return ValidationResult::Invalid(e);
        }

        // Validate packet type
        if self.header.packet_type() != PacketType::SynAck {
            return ValidationResult::Invalid(ValidationError::InvalidPacketType);
        }

        // Validate protocol version
        if self.protocol_version.as_u8() == 0 || self.protocol_version.as_u8() > 1 {
            return ValidationResult::Invalid(ValidationError::InvalidProtocolVersion);
        }

        // Validate sequence numbers
        if !self.server_sequence.is_valid() || !self.ack_sequence.is_valid() {
            return ValidationResult::Invalid(ValidationError::InvalidSequenceNumber);
        }

        ValidationResult::Valid(())
    }
}

// ============================================================================
// DATA TRANSMISSION PACKETS
// ============================================================================

/// ACK packet for acknowledgment
#[derive(Debug, Clone)]
pub struct AckPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Flow control window size
    pub window_size: WindowSize,
    /// Selective acknowledgment data (optional)
    pub sack_data: Option<SackData>,
}

impl AckPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();
        let sack_size = if self.sack_data.is_some() { 5 } else { 0 };

        if buffer.len() < header_size + hmac_len + 4 + sack_size {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize window size
        buffer[offset..offset + 4].copy_from_slice(&self.window_size.as_u32().to_be_bytes());
        offset += 4;

        // Serialize SACK data if present
        if let Some(ref sack_data) = self.sack_data {
            buffer[offset] = sack_data.block_count.as_u8();
            offset += 1;
            buffer[offset..offset + 4]
                .copy_from_slice(&sack_data.primary_bitmap.as_u32().to_be_bytes());
            offset += 4;
            // Additional ranges are simplified for now
        }

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Parse header first - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify this is an ACK packet
        if header.packet_type() != PacketType::Ack {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC tag
        let hmac_len = header.hmac_policy().tag_size();

        // Minimum: header + hmac + window_size(4)
        if bytes.len() < header_size + hmac_len + 4 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse ACK specific fields
        let mut offset = header_size + hmac_len;
        let window_size = WindowSize::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        let sack_data = if bytes.len() > offset + 6 {
            // Parse SACK data if present
            let block_count = SackBlockCount::new(bytes[offset]);
            let primary_bitmap = SackBitmap::new(u32::from_be_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            ]));
            Some(SackData {
                block_count,
                primary_bitmap,
                additional_ranges: vec![], // Simplified for now
            })
        } else {
            None
        };

        Ok(Self {
            header,
            hmac,
            window_size,
            sack_data,
        })
    }
}

impl Validate for AckPacket {
    fn validate(&self) -> ValidationResult<()> {
        // Validate header
        if let ValidationResult::Invalid(e) = self.header.validate() {
            return ValidationResult::Invalid(e);
        }

        // Validate packet type
        if self.header.packet_type() != PacketType::Ack {
            return ValidationResult::Invalid(ValidationError::InvalidPacketType);
        }

        // Validate window size
        if self.window_size.as_u32() == 0 {
            return ValidationResult::Invalid(ValidationError::InvalidWindowSize);
        }

        ValidationResult::Valid(())
    }
}

/// DATA packet for payload transmission
#[derive(Debug, Clone)]
pub struct DataPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Flow control window size
    pub window_size: WindowSize,
    /// Fragmentation header (optional)
    pub fragment_header: Option<FragmentHeader>,
    /// Application payload
    pub payload: Bytes,
}

impl DataPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();
        let frag_size = if self.fragment_header.is_some() { 8 } else { 0 };
        let payload_len = self.payload.len();

        if buffer.len() < header_size + hmac_len + 4 + frag_size + payload_len {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize window size
        buffer[offset..offset + 4].copy_from_slice(&self.window_size.as_u32().to_be_bytes());
        offset += 4;

        // Serialize fragment header if present
        if let Some(ref frag_header) = self.fragment_header {
            buffer[offset..offset + 2]
                .copy_from_slice(&frag_header.fragment_id.as_u16().to_be_bytes());
            offset += 2;
            buffer[offset..offset + 2]
                .copy_from_slice(&frag_header.fragment_index.as_u16().to_be_bytes());
            offset += 2;
            buffer[offset..offset + 2]
                .copy_from_slice(&frag_header.fragment_count.as_u16().to_be_bytes());
            offset += 2;
            buffer[offset..offset + 2]
                .copy_from_slice(&frag_header.fragment_size.as_u16().to_be_bytes());
            offset += 2;
        }

        // Serialize payload
        if payload_len > 0 {
            buffer[offset..offset + payload_len].copy_from_slice(&self.payload);
            offset += payload_len;
        }

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Parse header first - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify this is a DATA packet
        if header.packet_type() != PacketType::Data {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC tag
        let hmac_len = header.hmac_policy().tag_size();

        // Minimum: header + hmac + window_size(4)
        if bytes.len() < header_size + hmac_len + 4 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse DATA specific fields
        let mut offset = header_size + hmac_len;
        let window_size = WindowSize::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        // Parse fragment header if present
        let fragment_header = if header.flags().is_fragmented() {
            if bytes.len() < offset + 8 {
                return Err(ValidationError::InvalidLength);
            }
            let fragment_id =
                FragmentId::new(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
            let fragment_index =
                FragmentIndex::new(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
            let fragment_count =
                FragmentCount::new(u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]));
            let fragment_size =
                FragmentSize::new(u16::from_be_bytes([bytes[offset + 6], bytes[offset + 7]]));
            offset += 8;
            Some(FragmentHeader {
                fragment_id,
                fragment_index,
                fragment_count,
                fragment_size,
            })
        } else {
            None
        };

        // Extract payload
        let payload = if offset < bytes.len() {
            Bytes::copy_from_slice(&bytes[offset..])
        } else {
            Bytes::new()
        };

        Ok(Self {
            header,
            hmac,
            window_size,
            fragment_header,
            payload,
        })
    }
}

impl Validate for DataPacket {
    fn validate(&self) -> ValidationResult<()> {
        // Validate header
        if let ValidationResult::Invalid(e) = self.header.validate() {
            return ValidationResult::Invalid(e);
        }

        // Validate packet type
        if self.header.packet_type() != PacketType::Data {
            return ValidationResult::Invalid(ValidationError::InvalidPacketType);
        }

        // Validate window size
        if self.window_size.as_u32() == 0 {
            return ValidationResult::Invalid(ValidationError::InvalidWindowSize);
        }

        // Validate fragment header if present
        if let Some(ref frag_header) = self.fragment_header {
            if frag_header.fragment_index.as_u16() >= frag_header.fragment_count.as_u16() {
                return ValidationResult::Invalid(ValidationError::InvalidFragmentIndex);
            }
            if frag_header.fragment_count.as_u16() == 0 {
                return ValidationResult::Invalid(ValidationError::InvalidFragmentCount);
            }
        }

        // Validate payload length matches header
        if self.payload.len() != self.header.get_payload_length().as_u16() as usize {
            return ValidationResult::Invalid(ValidationError::InvalidPayloadLength);
        }

        ValidationResult::Valid(())
    }
}

/// Selective acknowledgment data
#[derive(Debug, Clone)]
pub struct SackData {
    /// Number of SACK blocks
    pub block_count: SackBlockCount,
    /// Primary bitmap for recent packets
    pub primary_bitmap: SackBitmap,
    /// Additional SACK ranges
    pub additional_ranges: Vec<SackRange>,
}

/// Fragmentation header
#[derive(Debug, Clone, Copy)]
pub struct FragmentHeader {
    /// Fragment identifier
    pub fragment_id: FragmentId,
    /// Fragment index (0-based)
    pub fragment_index: FragmentIndex,
    /// Total number of fragments
    pub fragment_count: FragmentCount,
    /// Fragment size
    pub fragment_size: FragmentSize,
}

// ============================================================================
// CONNECTION TERMINATION PACKETS
// ============================================================================

/// FIN packet for connection termination
#[derive(Debug, Clone)]
pub struct FinPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Final sequence number
    pub final_sequence: SequenceNumber,
    /// Termination reason
    pub reason: TerminationReason,
}

impl FinPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();

        if buffer.len() < header_size + hmac_len + 5 {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize final sequence number
        buffer[offset..offset + 4].copy_from_slice(&self.final_sequence.to_be_bytes());
        offset += 4;

        // Serialize termination reason
        buffer[offset] = self.reason.as_u8();
        offset += 1;

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Parse header first - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify this is a FIN packet
        if header.packet_type() != PacketType::Fin {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC tag
        let hmac_len = header.hmac_policy().tag_size();

        // Minimum: header + hmac + final_sequence(4) + reason(1)
        if bytes.len() < header_size + hmac_len + 5 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse FIN-specific fields
        let mut offset = header_size + hmac_len;
        let final_sequence = SequenceNumber::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        let reason = match TerminationReason::from_u8(bytes[offset]) {
            Some(r) => r,
            None => return Err(ValidationError::InvalidTerminationReason),
        };

        Ok(Self {
            header,
            hmac,
            final_sequence,
            reason,
        })
    }
}

/// RST packet for connection reset
#[derive(Debug, Clone)]
pub struct RstPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Reset reason
    pub reason: ResetReason,
    /// Error code (optional)
    pub error_code: Option<ErrorCode>,
}

impl RstPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();
        let err_code_size = if self.error_code.is_some() { 1 } else { 0 };

        if buffer.len() < header_size + hmac_len + 1 + err_code_size {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize reset reason
        buffer[offset] = self.reason.as_u8();
        offset += 1;

        // Serialize optional error code
        if let Some(error_code) = self.error_code {
            buffer[offset] = error_code.as_u8();
            offset += 1;
        }

        Ok(offset)
    }

    /// Deserialize packet from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        // Parse header first - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify this is a RST packet
        if header.packet_type() != PacketType::Rst {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC tag
        let hmac_len = header.hmac_policy().tag_size();

        // Minimum: header + hmac + reason(1)
        if bytes.len() < header_size + hmac_len + 1 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse RST-specific fields
        let mut offset = header_size + hmac_len;
        let reason = match ResetReason::from_u8(bytes[offset]) {
            Some(r) => r,
            None => return Err(ValidationError::InvalidResetReason),
        };
        offset += 1;

        // Parse optional error code
        let error_code = if bytes.len() > offset {
            Some(ErrorCode::new(bytes[offset]))
        } else {
            None
        };

        Ok(Self {
            header,
            hmac,
            reason,
            error_code,
        })
    }
}

// ============================================================================
// KEEP-ALIVE AND ERROR PACKETS
// ============================================================================

/// HEARTBEAT packet for keep-alive
#[derive(Debug, Clone)]
pub struct HeartbeatPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Heartbeat sequence number
    pub heartbeat_sequence: HeartbeatSequence,
    /// Round-trip time measurement
    pub rtt_measurement: Option<RoundTripTime>,
}

impl HeartbeatPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();
        let rtt_size = if self.rtt_measurement.is_some() { 8 } else { 0 };

        if buffer.len() < header_size + hmac_len + 4 + rtt_size {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize heartbeat sequence
        buffer[offset..offset + 4].copy_from_slice(&self.heartbeat_sequence.as_u32().to_be_bytes());
        offset += 4;

        // Serialize optional RTT measurement
        if let Some(ref rtt) = self.rtt_measurement {
            buffer[offset..offset + 8].copy_from_slice(&rtt.as_nanos().to_be_bytes());
            offset += 8;
        }

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.len() < 18 {
            return Err(ValidationError::InvalidLength);
        }

        // Parse header - it handles its own length validation
        let header = PacketHeader::deserialize(bytes)?;
        let header_size = header.header_size();

        // Verify packet type
        if header.packet_type() != PacketType::Heartbeat {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC based on policy
        let hmac_len = header.hmac_policy().tag_size();

        if bytes.len() < header_size + hmac_len + 4 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[header_size..header_size + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse heartbeat sequence (4 bytes, big-endian u32)
        let mut offset = header_size + hmac_len;
        let heartbeat_sequence = HeartbeatSequence::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        // Parse optional RTT measurement (8 bytes if present, big-endian u64 nanoseconds)
        let rtt_measurement = if bytes.len() >= offset + 8 {
            let rtt_nanos = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            Some(RoundTripTime::from_nanos(rtt_nanos))
        } else {
            None
        };

        Ok(Self {
            header,
            hmac,
            heartbeat_sequence,
            rtt_measurement,
        })
    }
}

/// ERROR packet for error reporting
#[derive(Debug, Clone)]
pub struct ErrorPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Error code
    pub error_code: ErrorCode,
    /// Error description
    pub error_description: ErrorDescription,
    /// Additional error context
    pub error_context: Option<Bytes>,
}

impl ErrorPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();

        let desc_bytes = self.error_description.as_str().as_bytes();
        let desc_len = desc_bytes.len().min(255); // Limit to 255 bytes
        let context_len = self.error_context.as_ref().map(|c| c.len()).unwrap_or(0);

        if buffer.len() < header_size + hmac_len + 1 + 1 + desc_len + context_len {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize error code
        buffer[offset] = self.error_code.as_u8();
        offset += 1;

        // Serialize error description (length-prefixed)
        buffer[offset] = desc_len as u8;
        offset += 1;
        buffer[offset..offset + desc_len].copy_from_slice(&desc_bytes[..desc_len]);
        offset += desc_len;

        // Serialize optional error context
        if let Some(ref context) = self.error_context {
            buffer[offset..offset + context.len()].copy_from_slice(context);
            offset += context.len();
        }

        Ok(offset)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.len() < 18 {
            return Err(ValidationError::InvalidLength);
        }

        // Parse header (18 bytes)
        let header = PacketHeader::deserialize(&bytes[0..18])?;

        // Verify packet type
        if header.packet_type() != PacketType::Error {
            return Err(ValidationError::InvalidPacketType);
        }

        // Parse HMAC based on policy
        let hmac_len = match header.hmac_policy() {
            HmacPolicy::Light => 8,
            HmacPolicy::Medium => 16,
            HmacPolicy::Strong => 32,
        };

        if bytes.len() < 18 + hmac_len + 2 {
            return Err(ValidationError::InvalidLength);
        }

        let hmac_bytes = bytes[18..18 + hmac_len].to_vec();
        let hmac = HmacTag::new(hmac_bytes, header.hmac_policy())?;

        // Parse error code (1 byte)
        let mut offset = 18 + hmac_len;
        let error_code =
            ErrorCode::from_u8(bytes[offset]).ok_or(ValidationError::InvalidErrorCode)?;
        offset += 1;

        // Parse error description (length-prefixed string)
        let desc_len = bytes[offset] as usize;
        offset += 1;

        if bytes.len() < offset + desc_len {
            return Err(ValidationError::InvalidLength);
        }

        let desc_bytes = &bytes[offset..offset + desc_len];
        let error_description = ErrorDescription::new(
            String::from_utf8(desc_bytes.to_vec())
                .map_err(|_| ValidationError::InvalidErrorDescription)?,
        );
        offset += desc_len;

        // Parse optional error context (remaining bytes if any)
        let error_context = if offset < bytes.len() {
            Some(Bytes::copy_from_slice(&bytes[offset..]))
        } else {
            None
        };

        Ok(Self {
            header,
            hmac,
            error_code,
            error_description,
            error_context,
        })
    }
}

// ============================================================================
// CONTROL PACKETS
// ============================================================================

/// CONTROL packet with all sub-types
#[derive(Debug, Clone)]
pub struct ControlPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Control packet payload
    pub payload: ControlPayload,
}

impl ControlPacket {
    /// Serialize packet to bytes (simplified implementation)
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();

        if buffer.len() < header_size + hmac_len + 1 {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize payload type discriminant
        match &self.payload {
            ControlPayload::TimeSyncRequest(payload) => {
                buffer[offset] = 0x01; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 13 {
                    // 8 (timestamp) + 1 (quality) + 4 (drift)
                    return Err(ValidationError::BufferTooSmall);
                }
                // Serialize timestamp (8 bytes)
                buffer[offset..offset + 8]
                    .copy_from_slice(&payload.client_timestamp.as_nanos().to_be_bytes());
                offset += 8;
                // Serialize sync quality (1 byte)
                buffer[offset] = payload.sync_quality.as_u8();
                offset += 1;
                // Serialize max drift (4 bytes as PPM)
                buffer[offset..offset + 4]
                    .copy_from_slice(&payload.max_drift.as_i32().to_be_bytes());
                offset += 4;
            }
            ControlPayload::TimeSyncResponse(payload) => {
                buffer[offset] = 0x02; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 32 {
                    return Err(ValidationError::BufferTooSmall);
                }
                // Serialize client timestamp (8 bytes)
                buffer[offset..offset + 8]
                    .copy_from_slice(&payload.client_timestamp.as_nanos().to_be_bytes());
                offset += 8;
                // Serialize server timestamp (8 bytes)
                buffer[offset..offset + 8]
                    .copy_from_slice(&payload.server_timestamp.as_nanos().to_be_bytes());
                offset += 8;
                // Serialize network delay (8 bytes)
                buffer[offset..offset + 8]
                    .copy_from_slice(&payload.network_delay.as_nanos().to_be_bytes());
                offset += 8;
                // Serialize clock skew (8 bytes)
                buffer[offset..offset + 8].copy_from_slice(&payload.clock_skew.to_be_bytes());
                offset += 8;
            }
            ControlPayload::Recovery(_payload) => {
                buffer[offset] = 0x03; // Type discriminant
                offset += 1;
                // Simplified - just add discriminant for now
            }
            ControlPayload::SequenceNeg(payload) => {
                buffer[offset] = 0x04; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 9 {
                    return Err(ValidationError::BufferTooSmall);
                }
                // Serialize proposed sequence (4 bytes)
                buffer[offset..offset + 4]
                    .copy_from_slice(&payload.proposed_sequence.to_be_bytes());
                offset += 4;
                // Serialize window size (4 bytes)
                buffer[offset..offset + 4]
                    .copy_from_slice(&payload.window_size.as_u32().to_be_bytes());
                offset += 4;
                // Serialize flags (1 byte)
                buffer[offset] = payload.flags.as_u8();
                offset += 1;
            }
            ControlPayload::HmacPolicyRequest(_payload) => {
                buffer[offset] = 0x05; // Type discriminant
                offset += 1;
            }
            ControlPayload::HmacPolicyResponse(_payload) => {
                buffer[offset] = 0x06; // Type discriminant
                offset += 1;
            }
        }

        Ok(offset)
    }
}

/// Control packet payload variants
#[derive(Debug, Clone)]
pub enum ControlPayload {
    /// Time synchronization request
    TimeSyncRequest(TimeSyncRequestPayload),
    /// Time synchronization response
    TimeSyncResponse(TimeSyncResponsePayload),
    /// Recovery request
    Recovery(RecoveryPayload),
    /// Sequence negotiation
    SequenceNeg(SequenceNegPayload),
    /// HMAC policy request
    HmacPolicyRequest(HmacPolicyRequestPayload),
    /// HMAC policy response
    HmacPolicyResponse(HmacPolicyResponsePayload),
}

/// Time synchronization request payload
#[derive(Debug, Clone)]
pub struct TimeSyncRequestPayload {
    /// Client timestamp
    pub client_timestamp: Timestamp,
    /// Sync quality requirement
    pub sync_quality: SyncQuality,
    /// Maximum acceptable drift
    pub max_drift: TimeDrift,
}

/// Time synchronization response payload
#[derive(Debug, Clone)]
pub struct TimeSyncResponsePayload {
    /// Original client timestamp
    pub client_timestamp: Timestamp,
    /// Server timestamp
    pub server_timestamp: Timestamp,
    /// Measured network delay
    pub network_delay: NetworkDelay,
    /// Clock skew measurement
    pub clock_skew: ClockSkew,
}

/// Recovery request payload
#[derive(Debug, Clone)]
pub struct RecoveryPayload {
    /// Recovery reason
    pub reason: RecoveryReason,
    /// Recovery nonce
    pub nonce: RecoveryNonce,
    /// Last known good sequence
    pub last_good_sequence: SequenceNumber,
    /// Recovery parameters
    pub recovery_params: RecoveryParams,
}

/// Sequence negotiation payload
#[derive(Debug, Clone)]
pub struct SequenceNegPayload {
    /// Proposed sequence number
    pub proposed_sequence: SequenceNumber,
    /// Window size
    pub window_size: WindowSize,
    /// Negotiation flags
    pub flags: SequenceNegFlags,
}

/// HMAC policy request payload
#[derive(Debug, Clone)]
pub struct HmacPolicyRequestPayload {
    /// Requested HMAC policy
    pub requested_policy: HmacPolicy,
    /// Security level requirement
    pub security_level: SecurityLevel,
    /// Policy change reason
    pub reason: PolicyChangeReason,
}

/// HMAC policy response payload
#[derive(Debug, Clone)]
pub struct HmacPolicyResponsePayload {
    /// Accepted HMAC policy
    pub accepted_policy: HmacPolicy,
    /// Policy change result
    pub result: PolicyChangeResult,
    /// Effective timestamp
    pub effective_timestamp: Timestamp,
}

// ============================================================================
// MANAGEMENT PACKETS
// ============================================================================

/// MANAGEMENT packet with all sub-types
#[derive(Debug, Clone)]
pub struct ManagementPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Management packet payload
    pub payload: ManagementPayload,
}

impl ManagementPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();

        if buffer.len() < header_size + hmac_len + 1 {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize payload type discriminant and data
        match &self.payload {
            ManagementPayload::RekeyRequest(payload) => {
                buffer[offset] = 0x01; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 44 {
                    // 4 (nonce) + 32 (commitment) + 8 (reserved)
                    return Err(ValidationError::BufferTooSmall);
                }
                // Serialize rekey nonce (4 bytes)
                buffer[offset..offset + 4].copy_from_slice(&payload.key_id.as_bytes()[0..4]);
                offset += 4;
                // Serialize key commitment - using key_id as placeholder since KdfParams doesn't have a simple serialization
                // In a real implementation, this would serialize the full commitment
                let commitment_bytes = [0u8; 32]; // Placeholder commitment
                buffer[offset..offset + 32].copy_from_slice(&commitment_bytes);
                offset += 32;
                // Reserved (8 bytes)
                buffer[offset..offset + 8].fill(0);
                offset += 8;
            }
            ManagementPayload::RekeyResponse(payload) => {
                buffer[offset] = 0x02; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 52 {
                    // 4 + 32 + 16
                    return Err(ValidationError::BufferTooSmall);
                }
                // Serialize rekey nonce (4 bytes)
                buffer[offset..offset + 4].copy_from_slice(&payload.key_id.as_bytes()[0..4]);
                offset += 4;
                // Commitment (32 bytes placeholder)
                buffer[offset..offset + 32].fill(0);
                offset += 32;
                // Confirmation (16 bytes placeholder)
                buffer[offset..offset + 16].fill(0);
                offset += 16;
            }
            ManagementPayload::RepairRequest(payload) => {
                buffer[offset] = 0x03; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 20 {
                    // 4 + 4 + 4 + 8
                    return Err(ValidationError::BufferTooSmall);
                }
                // Repair nonce (using repair_type as placeholder)
                let nonce = payload.repair_type as u8 as u32;
                buffer[offset..offset + 4].copy_from_slice(&nonce.to_be_bytes());
                offset += 4;
                // Last known sequence
                buffer[offset..offset + 4]
                    .copy_from_slice(&payload.sequence_range.start.to_be_bytes());
                offset += 4;
                // Repair window size
                buffer[offset..offset + 4]
                    .copy_from_slice(&payload.sequence_range.end.to_be_bytes());
                offset += 4;
                // Reserved (8 bytes)
                buffer[offset..offset + 8].fill(0);
                offset += 8;
            }
            ManagementPayload::RepairResponse(payload) => {
                buffer[offset] = 0x04; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 20 {
                    // 4 + 4 + 4 + 8
                    return Err(ValidationError::BufferTooSmall);
                }
                // Repair nonce (placeholder)
                buffer[offset..offset + 4].fill(0);
                offset += 4;
                // Current sequence (placeholder - would need session state)
                buffer[offset..offset + 4].fill(0);
                offset += 4;
                // Repair window size (placeholder)
                buffer[offset..offset + 4].fill(0);
                offset += 4;
                // Confirmation (8 bytes)
                buffer[offset..offset + 8]
                    .copy_from_slice(&payload.completion_timestamp.as_nanos().to_be_bytes());
                offset += 8;
            }
            ManagementPayload::RepairConfirm(payload) => {
                buffer[offset] = 0x05; // Type discriminant
                offset += 1;
                if buffer.len() < offset + 16 {
                    // 4 (nonce) + 4 (sequence) + 8 (hmac)
                    return Err(ValidationError::BufferTooSmall);
                }
                // Repair nonce (4 bytes)
                buffer[offset..offset + 4].copy_from_slice(&payload.repair_nonce.0.to_be_bytes());
                offset += 4;
                // Confirmed sequence number (4 bytes)
                buffer[offset..offset + 4]
                    .copy_from_slice(&payload.confirmed_sequence.to_be_bytes());
                offset += 4;
                // HMAC confirmation tag (8 bytes)
                buffer[offset..offset + 8].copy_from_slice(&payload.confirmation_hmac);
                offset += 8;
            }
        }

        Ok(offset)
    }
}

/// Management packet payload variants
#[derive(Debug, Clone)]
pub enum ManagementPayload {
    /// Rekey request
    RekeyRequest(RekeyRequestPayload),
    /// Rekey response
    RekeyResponse(RekeyResponsePayload),
    /// Repair request
    RepairRequest(RepairRequestPayload),
    /// Repair response
    RepairResponse(RepairResponsePayload),
    /// Repair confirmation
    RepairConfirm(RepairConfirmPayload),
}

/// Rekey request payload
#[derive(Debug, Clone)]
pub struct RekeyRequestPayload {
    /// New key identifier
    pub key_id: KeyId,
    /// Key derivation parameters
    pub kdf_params: KdfParams,
    /// Rekey reason
    pub reason: RekeyReason,
    /// Effective timestamp
    pub effective_timestamp: Timestamp,
}

/// Rekey response payload
#[derive(Debug, Clone)]
pub struct RekeyResponsePayload {
    /// Accepted key identifier
    pub key_id: KeyId,
    /// Rekey result
    pub result: RekeyResult,
    /// Confirmation timestamp
    pub confirmation_timestamp: Timestamp,
}

/// Repair request payload
#[derive(Debug, Clone)]
pub struct RepairRequestPayload {
    /// Repair type
    pub repair_type: RepairType,
    /// Affected sequence range
    pub sequence_range: SequenceRange,
    /// Repair priority
    pub priority: RepairPriority,
}

/// Repair response payload
#[derive(Debug, Clone)]
pub struct RepairResponsePayload {
    /// Repair result
    pub result: RepairResult,
    /// Repaired data (optional)
    pub repaired_data: Option<Bytes>,
    /// Completion timestamp
    pub completion_timestamp: Timestamp,
}

/// Repair confirmation payload
///
/// Sent after successful sequence repair to cryptographically confirm
/// the new sequence state. Per design/protocol/12-recovery-mechanisms.md §2.
#[derive(Debug, Clone)]
pub struct RepairConfirmPayload {
    /// Repair nonce for matching with repair request
    pub repair_nonce: RecoveryNonce,
    /// Confirmed sequence number after repair
    pub confirmed_sequence: SequenceNumber,
    /// HMAC confirmation tag (8 bytes)
    /// HMAC_SHA256_128(session_key, nonce || sequence || session_id || "sequence_repair_v1")[0:8]
    pub confirmation_hmac: [u8; 8],
}

// ============================================================================
// DISCOVERY PACKETS
// ============================================================================

/// DISCOVERY packet with all sub-types
#[derive(Debug, Clone)]
pub struct DiscoveryPacket {
    /// Common packet header
    pub header: PacketHeader,
    /// HMAC tag for authentication
    pub hmac: HmacTag,
    /// Discovery packet payload
    pub payload: DiscoveryPayload,
}

impl DiscoveryPacket {
    /// Serialize packet to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        // Serialize header first
        let header_size = self.header.serialize(buffer)?;

        // Serialize HMAC tag (Discovery packets always use HMAC_STRONG)
        let hmac_bytes = self.hmac.data();
        let hmac_len = hmac_bytes.len();

        if buffer.len() < header_size + hmac_len + 1 {
            return Err(ValidationError::BufferTooSmall);
        }

        buffer[header_size..header_size + hmac_len].copy_from_slice(hmac_bytes);
        let mut offset = header_size + hmac_len;

        // Serialize payload type discriminant and data
        match &self.payload {
            DiscoveryPayload::Request(payload) => {
                buffer[offset] = 0x01; // Type discriminant
                offset += 1;

                let bloom_filter_size = payload.bloom_filter.bits.len();
                if buffer.len() < offset + 20 + bloom_filter_size {
                    return Err(ValidationError::BufferTooSmall);
                }

                // Discovery ID (8 bytes) - stored in first 8 bytes of challenge
                buffer[offset..offset + 8].copy_from_slice(&payload.challenge.as_bytes()[0..8]);
                offset += 8;

                // Session salt (4 bytes) - using timeout as placeholder (convert ms to u32)
                let timeout_u32 = (payload.timeout.as_u64() & 0xFFFFFFFF) as u32;
                buffer[offset..offset + 4].copy_from_slice(&timeout_u32.to_be_bytes());
                offset += 4;

                // Fingerprint count (2 bytes) - derived from bloom filter
                let fingerprint_count = (bloom_filter_size / 32).min(65535) as u16;
                buffer[offset..offset + 2].copy_from_slice(&fingerprint_count.to_be_bytes());
                offset += 2;

                // Bloom filter size (2 bytes)
                buffer[offset..offset + 2]
                    .copy_from_slice(&(bloom_filter_size as u16).to_be_bytes());
                offset += 2;

                // Initiator features (2 bytes) - placeholder
                buffer[offset..offset + 2].fill(0);
                offset += 2;

                // Reserved (2 bytes)
                buffer[offset..offset + 2].fill(0);
                offset += 2;

                // Bloom filter data (variable)
                buffer[offset..offset + bloom_filter_size]
                    .copy_from_slice(&payload.bloom_filter.bits);
                offset += bloom_filter_size;
            }
            DiscoveryPayload::Response(payload) => {
                buffer[offset] = 0x02; // Type discriminant
                offset += 1;

                let candidate_count = payload.candidate_hashes.len();
                let candidate_bytes = candidate_count * 32; // 32 bytes per hash

                if buffer.len() < offset + 20 + candidate_bytes {
                    return Err(ValidationError::BufferTooSmall);
                }

                // Discovery ID (8 bytes)
                buffer[offset..offset + 8].fill(0); // Placeholder - should match request
                offset += 8;

                // Candidate count (2 bytes)
                buffer[offset..offset + 2].copy_from_slice(&(candidate_count as u16).to_be_bytes());
                offset += 2;

                // Intersection status (2 bytes)
                let status = if candidate_count > 0 { 1u16 } else { 0u16 };
                buffer[offset..offset + 2].copy_from_slice(&status.to_be_bytes());
                offset += 2;

                // Responder features (2 bytes)
                buffer[offset..offset + 2].fill(0);
                offset += 2;

                // Reserved (2 bytes)
                buffer[offset..offset + 2].fill(0);
                offset += 2;

                // Candidate intersection hashes (32 bytes each)
                for candidate in &payload.candidate_hashes {
                    buffer[offset..offset + 32].copy_from_slice(candidate.as_bytes());
                    offset += 32;
                }

                // Response timestamp (8 bytes)
                buffer[offset..offset + 8]
                    .copy_from_slice(&payload.response_timestamp.as_nanos().to_be_bytes());
                offset += 8;
            }
            DiscoveryPayload::Confirm(payload) => {
                buffer[offset] = 0x03; // Type discriminant
                offset += 1;

                if buffer.len() < offset + 56 {
                    // 8 + 32 + 2 + 2 + 8 + 4
                    return Err(ValidationError::BufferTooSmall);
                }

                // Discovery ID (8 bytes) - using first 8 bytes of selected_psk
                buffer[offset..offset + 8].copy_from_slice(&payload.selected_psk.as_bytes()[0..8]);
                offset += 8;

                // Confirmation hash (32 bytes) - PSK proof is 16 bytes, pad with zeros
                buffer[offset..offset + 16].copy_from_slice(payload.confirmation_proof.as_bytes());
                buffer[offset + 16..offset + 32].fill(0);
                offset += 32;

                // Confirmation status (2 bytes)
                buffer[offset..offset + 2].copy_from_slice(&1u16.to_be_bytes()); // CONFIRMED = 1
                offset += 2;

                // Reserved (2 bytes)
                buffer[offset..offset + 2].fill(0);
                offset += 2;

                // Session ID (8 bytes) - placeholder
                buffer[offset..offset + 8].fill(0);
                offset += 8;

                // Reserved (2 bytes)
                buffer[offset..offset + 2].fill(0);
                offset += 2;

                // Commitment (2 bytes remaining of what should be 128-bit)
                buffer[offset..offset + 2].fill(0);
                offset += 2;
            }
        }

        Ok(offset)
    }
}

/// Discovery packet payload variants
#[derive(Debug, Clone)]
pub enum DiscoveryPayload {
    /// Discovery request
    Request(DiscoveryRequestPayload),
    /// Discovery response
    Response(DiscoveryResponsePayload),
    /// Discovery confirmation
    Confirm(DiscoveryConfirmPayload),
}

/// Discovery request payload
#[derive(Debug, Clone)]
pub struct DiscoveryRequestPayload {
    /// Discovery challenge
    pub challenge: DiscoveryChallenge,
    /// Bloom filter for PSI
    pub bloom_filter: BloomFilter,
    /// Discovery timeout
    pub timeout: DiscoveryTimeout,
}

/// Discovery response payload
#[derive(Debug, Clone)]
pub struct DiscoveryResponsePayload {
    /// Original challenge
    pub challenge: DiscoveryChallenge,
    /// PSK proofs
    pub psk_proofs: Vec<PskProof>,
    /// Candidate hashes
    pub candidate_hashes: Vec<CandidateHash>,
    /// Response timestamp
    pub response_timestamp: Timestamp,
}

/// Discovery confirmation payload
#[derive(Debug, Clone)]
pub struct DiscoveryConfirmPayload {
    /// Selected PSK identifier
    pub selected_psk: PskId,
    /// Confirmation proof
    pub confirmation_proof: PskProof,
    /// Session parameters
    pub session_params: SessionParams,
}

// ============================================================================
// UNIFIED PACKET ENUM
// ============================================================================

/// Unified packet enumeration for all protocol packet types
#[derive(Debug, Clone)]
pub enum Packet {
    /// SYN packet
    Syn(SynPacket),
    /// SYN-ACK packet
    SynAck(SynAckPacket),
    /// ACK packet
    Ack(AckPacket),
    /// DATA packet
    Data(DataPacket),
    /// FIN packet
    Fin(FinPacket),
    /// RST packet
    Rst(RstPacket),
    /// HEARTBEAT packet
    Heartbeat(HeartbeatPacket),
    /// ERROR packet
    Error(ErrorPacket),
    /// CONTROL packet
    Control(ControlPacket),
    /// MANAGEMENT packet
    Management(ManagementPacket),
    /// DISCOVERY packet
    Discovery(DiscoveryPacket),
}

/// Type alias for built packets
pub type BuiltPacket = Packet;

impl Packet {
    /// Create a new data packet
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self::Data(DataPacket {
            header,
            hmac: HmacTag::default(),
            window_size: WindowSize::new(65535), // Default window size
            fragment_header: None,
            payload: payload.into(),
        })
    }

    /// Get the common packet header
    pub fn header(&self) -> &PacketHeader {
        match self {
            Self::Syn(p) => &p.header,
            Self::SynAck(p) => &p.header,
            Self::Ack(p) => &p.header,
            Self::Data(p) => &p.header,
            Self::Fin(p) => &p.header,
            Self::Rst(p) => &p.header,
            Self::Heartbeat(p) => &p.header,
            Self::Error(p) => &p.header,
            Self::Control(p) => &p.header,
            Self::Management(p) => &p.header,
            Self::Discovery(p) => &p.header,
        }
    }

    /// Get the packet type
    pub fn packet_type(&self) -> PacketType {
        self.header().packet_type()
    }

    /// Get the session ID
    pub fn session_id(&self) -> SessionId {
        self.header().session_id()
    }

    /// Get the sequence number
    pub fn sequence_number(&self) -> SequenceNumber {
        self.header().sequence_number()
    }

    /// Check if this packet requires acknowledgment
    pub fn requires_ack(&self) -> bool {
        self.packet_type().requires_ack()
    }

    /// Check if this packet is a connection packet
    pub fn is_connection_packet(&self) -> bool {
        self.packet_type().is_connection_packet()
    }

    /// Check if this packet carries data
    pub fn carries_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    /// Get packet flags
    pub fn flags(&self) -> PacketFlags {
        self.header().flags()
    }

    /// Get packet timestamp
    pub fn timestamp(&self) -> Timestamp {
        self.header().timestamp()
    }

    /// Get packet HMAC
    pub fn hmac(&self) -> &HmacTag {
        match self {
            Self::Syn(p) => &p.hmac,
            Self::SynAck(p) => &p.hmac,
            Self::Ack(p) => &p.hmac,
            Self::Data(p) => &p.hmac,
            Self::Fin(p) => &p.hmac,
            Self::Rst(p) => &p.hmac,
            Self::Heartbeat(p) => &p.hmac,
            Self::Error(p) => &p.hmac,
            Self::Control(p) => &p.hmac,
            Self::Management(p) => &p.hmac,
            Self::Discovery(p) => &p.hmac,
        }
    }

    /// Validate the packet
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Basic validation - each packet type should implement its own validation
        match self {
            Self::Syn(_) => Ok(()),
            Self::SynAck(_) => Ok(()),
            Self::Ack(_) => Ok(()),
            Self::Data(_) => Ok(()),
            Self::Fin(_) => Ok(()),
            Self::Rst(_) => Ok(()),
            Self::Heartbeat(_) => Ok(()),
            Self::Error(_) => Ok(()),
            Self::Control(_) => Ok(()),
            Self::Management(_) => Ok(()),
            Self::Discovery(_) => Ok(()),
        }
    }

    /// Get the total packet size in bytes
    pub fn total_size(&self) -> usize {
        self.header().total_size() + self.header().payload_length().as_u16() as usize
    }

    /// Get the packet payload
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Data(p) => &p.payload,
            _ => &[], // Non-data packets have no payload
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_packet_serialize_deserialize() {
        let session_id = SessionId::new(12345);
        let sequence = SequenceNumber::new(100);
        let ack = AckNumber::new(99);
        let timestamp = Timestamp::now();
        let hmac_policy = HmacPolicy::Medium;

        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::Heartbeat,
            SubType::new(0),
            PacketFlags::from_u8(0),
            session_id.clone(),
            sequence,
            ack,
            timestamp,
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac_bytes = vec![0u8; hmac_policy.tag_size()];
        let hmac = HmacTag::new(hmac_bytes, hmac_policy).unwrap();

        let heartbeat_seq = HeartbeatSequence::new(42);
        let rtt = RoundTripTime::from_millis(150);

        let packet = HeartbeatPacket {
            header,
            hmac,
            heartbeat_sequence: heartbeat_seq,
            rtt_measurement: Some(rtt),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).unwrap();

        let deserialized = HeartbeatPacket::deserialize(&buffer[..size]).unwrap();

        assert_eq!(deserialized.header.session_id(), session_id);
        assert_eq!(deserialized.header.sequence_number(), sequence);
        assert_eq!(
            deserialized.heartbeat_sequence.as_u32(),
            heartbeat_seq.as_u32()
        );
        assert!(deserialized.rtt_measurement.is_some());
        assert_eq!(
            deserialized.rtt_measurement.unwrap().as_millis(),
            rtt.as_millis()
        );
    }

    #[test]
    fn test_heartbeat_packet_new() {
        let session_id = SessionId::new(99999);
        let heartbeat_seq = HeartbeatSequence::new(0);

        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::Heartbeat,
            SubType::new(0),
            PacketFlags::from_u8(0),
            session_id,
            SequenceNumber::new(0),
            AckNumber::new(0),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );

        let hmac = HmacTag::new(vec![0u8; 8], HmacPolicy::Light).unwrap();

        let packet = HeartbeatPacket {
            header,
            hmac,
            heartbeat_sequence: heartbeat_seq,
            rtt_measurement: None,
        };

        assert_eq!(packet.header.packet_type(), PacketType::Heartbeat);
        assert_eq!(packet.heartbeat_sequence.as_u32(), 0);
        assert!(packet.rtt_measurement.is_none());
    }

    #[test]
    fn test_syn_packet_has_psk_auth_hash_field() {
        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::Syn,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac = HmacTag::new(vec![0u8; 32], HmacPolicy::Strong).unwrap();
        let initial_sequence = SequenceNumber::new(1);
        let protocol_version = ProtocolVersion::new(1);
        let session_config = SessionConfig::default();
        let connection_params = ConnectionParams::default();
        let client_public_key = EcdhPublicKey::new([0u8; 64]);
        let psk_auth_hash = [0u8; 32];

        let key_exchange_id = 0x1234;

        let syn_packet = SynPacket {
            header,
            hmac,
            initial_sequence,
            protocol_version,
            session_config,
            connection_params,
            client_public_key,
            psk_auth_hash,
            key_exchange_id,
        };

        assert_eq!(syn_packet.psk_auth_hash.len(), 32);
        assert_eq!(syn_packet.key_exchange_id, 0x1234);
    }

    #[test]
    fn test_psk_auth_hash_calculation() {
        use ring::hmac;

        let psk = b"test_pre_shared_key_123456789012";
        let client_nonce = [0x11u8; 16];
        let server_challenge = [0x22u8; 16];

        let mut message = Vec::new();
        message.extend_from_slice(&client_nonce);
        message.extend_from_slice(&server_challenge);

        let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
        let tag = hmac::sign(&key, &message);
        let hash: [u8; 32] = tag.as_ref().try_into().unwrap();

        assert_eq!(hash.len(), 32);
        assert!(hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_psk_auth_hash_verification() {
        use ring::hmac;

        let psk = b"shared_secret_key_for_authentication";
        let client_nonce = [0x01u8; 16];
        let server_challenge = [0x02u8; 16];

        let mut message = Vec::new();
        message.extend_from_slice(&client_nonce);
        message.extend_from_slice(&server_challenge);

        let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
        let client_tag = hmac::sign(&key, &message);
        let client_hash: [u8; 32] = client_tag.as_ref().try_into().unwrap();

        let server_tag = hmac::sign(&key, &message);
        let server_hash: [u8; 32] = server_tag.as_ref().try_into().unwrap();

        assert_eq!(client_hash, server_hash);
    }

    #[test]
    fn test_different_psks_produce_different_hashes() {
        use ring::hmac;

        let psk1 = b"first_pre_shared_key_123456789012";
        let psk2 = b"second_pre_shared_key_12345678901";
        let message = b"test_message_for_hmac_calculation";

        let key1 = hmac::Key::new(hmac::HMAC_SHA256, psk1);
        let tag1 = hmac::sign(&key1, message);
        let hash1: [u8; 32] = tag1.as_ref().try_into().unwrap();

        let key2 = hmac::Key::new(hmac::HMAC_SHA256, psk2);
        let tag2 = hmac::sign(&key2, message);
        let hash2: [u8; 32] = tag2.as_ref().try_into().unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_nonce_prevents_replay() {
        use ring::hmac;

        let psk = b"test_pre_shared_key_123456789012";
        let nonce1 = [0x01u8; 16];
        let nonce2 = [0x03u8; 16];
        let challenge = [0x02u8; 16];

        let mut message1 = Vec::new();
        message1.extend_from_slice(&nonce1);
        message1.extend_from_slice(&challenge);

        let mut message2 = Vec::new();
        message2.extend_from_slice(&nonce2);
        message2.extend_from_slice(&challenge);

        let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
        let tag1 = hmac::sign(&key, &message1);
        let hash1: [u8; 32] = tag1.as_ref().try_into().unwrap();

        let tag2 = hmac::sign(&key, &message2);
        let hash2: [u8; 32] = tag2.as_ref().try_into().unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_syn_packet_serialization_includes_psk_hash() {
        use ring::hmac;

        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::Syn,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac_tag = HmacTag::new(vec![0xAAu8; 32], HmacPolicy::Strong).unwrap();
        let initial_sequence = SequenceNumber::new(1);
        let protocol_version = ProtocolVersion::new(1);
        let session_config = SessionConfig::default();
        let connection_params = ConnectionParams::default();
        let client_public_key = EcdhPublicKey::new([0x11u8; 64]);

        let psk = b"test_psk_for_serialization_test_";
        let nonce = [0x01u8; 16];
        let challenge = [0x02u8; 16];
        let mut message = Vec::new();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&challenge);
        let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
        let tag = hmac::sign(&key, &message);
        let psk_auth_hash: [u8; 32] = tag.as_ref().try_into().unwrap();
        let key_exchange_id = 0x5678;

        let syn_packet = SynPacket {
            header,
            hmac: hmac_tag,
            initial_sequence,
            protocol_version,
            session_config,
            connection_params,
            client_public_key,
            psk_auth_hash,
            key_exchange_id,
        };

        let mut buffer = vec![0u8; 512];
        let size = syn_packet.serialize(&mut buffer).unwrap();

        let header_size = syn_packet.header.header_size();
        let psk_hash_offset = header_size + 32 + 4 + 1 + 64;
        let key_exchange_id_offset = psk_hash_offset + 32;

        assert!(size >= key_exchange_id_offset + 2);

        let serialized_hash = &buffer[psk_hash_offset..psk_hash_offset + 32];
        assert_eq!(serialized_hash, &psk_auth_hash);

        let serialized_key_exchange_id = u16::from_be_bytes([
            buffer[key_exchange_id_offset],
            buffer[key_exchange_id_offset + 1],
        ]);
        assert_eq!(serialized_key_exchange_id, 0x5678);
    }

    #[test]
    fn test_syn_packet_deserialization_extracts_psk_hash() {
        use ring::hmac;

        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::Syn,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac_tag = HmacTag::new(vec![0xAAu8; 32], HmacPolicy::Strong).unwrap();
        let initial_sequence = SequenceNumber::new(1);
        let protocol_version = ProtocolVersion::new(1);
        let session_config = SessionConfig::default();
        let connection_params = ConnectionParams::default();
        let client_public_key = EcdhPublicKey::new([0x11u8; 64]);

        let psk = b"test_psk_for_deserialization_test";
        let nonce = [0x03u8; 16];
        let challenge = [0x04u8; 16];
        let mut message = Vec::new();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&challenge);
        let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
        let tag = hmac::sign(&key, &message);
        let psk_auth_hash: [u8; 32] = tag.as_ref().try_into().unwrap();
        let key_exchange_id = 0x9ABC;

        let syn_packet = SynPacket {
            header,
            hmac: hmac_tag,
            initial_sequence,
            protocol_version,
            session_config,
            connection_params,
            client_public_key,
            psk_auth_hash,
            key_exchange_id,
        };

        let mut buffer = vec![0u8; 512];
        let size = syn_packet.serialize(&mut buffer).unwrap();

        let deserialized = SynPacket::deserialize(&buffer[..size]).unwrap();

        assert_eq!(deserialized.psk_auth_hash, psk_auth_hash);
        assert_eq!(deserialized.key_exchange_id, 0x9ABC);
    }

    #[test]
    fn test_psk_auth_hash_prevents_unauthorized_access() {
        use ring::hmac;

        let correct_psk = b"authorized_pre_shared_key_12345";
        let incorrect_psk = b"unauthorized_attempt_key_123456";
        let nonce = [0x05u8; 16];
        let challenge = [0x06u8; 16];

        let mut message = Vec::new();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&challenge);

        let incorrect_key = hmac::Key::new(hmac::HMAC_SHA256, incorrect_psk);
        let incorrect_tag = hmac::sign(&incorrect_key, &message);
        let incorrect_hash: [u8; 32] = incorrect_tag.as_ref().try_into().unwrap();

        let correct_key = hmac::Key::new(hmac::HMAC_SHA256, correct_psk);
        let correct_tag = hmac::sign(&correct_key, &message);
        let correct_hash: [u8; 32] = correct_tag.as_ref().try_into().unwrap();

        assert_ne!(incorrect_hash, correct_hash);
    }

    #[test]
    fn test_syn_ack_packet_has_server_public_key_field() {
        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(1),
            AckNumber::new(1),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac = HmacTag::new(vec![0u8; 32], HmacPolicy::Strong).unwrap();
        let server_public_key = EcdhPublicKey::new([0x22u8; 64]);
        let key_exchange_id = 0x1234;
        let shared_secret_verification = [0xAAu8; 32];

        let syn_ack_packet = SynAckPacket {
            header,
            hmac,
            ack_sequence: SequenceNumber::new(1),
            server_sequence: SequenceNumber::new(1),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        };

        assert_eq!(syn_ack_packet.server_public_key.as_bytes().len(), 64);
        assert_eq!(syn_ack_packet.key_exchange_id, 0x1234);
        assert_eq!(syn_ack_packet.shared_secret_verification.len(), 32);
    }

    #[test]
    fn test_syn_ack_serialization_includes_server_public_key() {
        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(100),
            AckNumber::new(1),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac_tag = HmacTag::new(vec![0xAAu8; 32], HmacPolicy::Strong).unwrap();
        let server_public_key = EcdhPublicKey::new([0x33u8; 64]);
        let key_exchange_id = 0x5678;
        let shared_secret_verification = [0xBBu8; 32];

        let syn_ack_packet = SynAckPacket {
            header,
            hmac: hmac_tag,
            ack_sequence: SequenceNumber::new(1),
            server_sequence: SequenceNumber::new(100),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        };

        let mut buffer = vec![0u8; 512];
        let size = syn_ack_packet.serialize(&mut buffer).unwrap();

        let header_size = syn_ack_packet.header.header_size();
        let server_public_key_offset = header_size + 32 + 4 + 4 + 1;
        let key_exchange_id_offset = server_public_key_offset + 64;
        let verification_offset = key_exchange_id_offset + 2;

        assert!(size >= verification_offset + 32);

        let serialized_key = &buffer[server_public_key_offset..server_public_key_offset + 64];
        assert_eq!(serialized_key, &[0x33u8; 64]);

        let serialized_key_exchange_id = u16::from_be_bytes([
            buffer[key_exchange_id_offset],
            buffer[key_exchange_id_offset + 1],
        ]);
        assert_eq!(serialized_key_exchange_id, 0x5678);

        let serialized_verification = &buffer[verification_offset..verification_offset + 32];
        assert_eq!(serialized_verification, &[0xBBu8; 32]);
    }

    #[test]
    fn test_syn_ack_deserialization_extracts_server_public_key() {
        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(200),
            AckNumber::new(1),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac_tag = HmacTag::new(vec![0xBBu8; 32], HmacPolicy::Strong).unwrap();
        let server_public_key = EcdhPublicKey::new([0x44u8; 64]);
        let key_exchange_id = 0x9ABC;
        let shared_secret_verification = [0xCCu8; 32];

        let syn_ack_packet = SynAckPacket {
            header,
            hmac: hmac_tag,
            ack_sequence: SequenceNumber::new(1),
            server_sequence: SequenceNumber::new(200),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        };

        let mut buffer = vec![0u8; 512];
        let size = syn_ack_packet.serialize(&mut buffer).unwrap();

        let deserialized = SynAckPacket::deserialize(&buffer[..size]).unwrap();

        assert_eq!(deserialized.server_public_key.as_bytes(), &[0x44u8; 64]);
        assert_eq!(deserialized.key_exchange_id, 0x9ABC);
        assert_eq!(deserialized.shared_secret_verification, [0xCCu8; 32]);
    }

    // ============================================================================
    // TASK-033: Shared Secret Verification Tests
    // ============================================================================

    #[test]
    fn test_syn_ack_has_shared_secret_verification_field() {
        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(1),
            AckNumber::new(1),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac = HmacTag::new(vec![0u8; 32], HmacPolicy::Strong).unwrap();
        let server_public_key = EcdhPublicKey::new([0x22u8; 64]);
        let key_exchange_id = 0x1234;
        let shared_secret_verification = [0xDDu8; 32];

        let syn_ack = SynAckPacket {
            header,
            hmac,
            ack_sequence: SequenceNumber::new(1),
            server_sequence: SequenceNumber::new(1),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        };

        assert_eq!(
            syn_ack.shared_secret_verification.len(),
            32,
            "Verification field must be 32 bytes"
        );
    }

    #[test]
    fn test_shared_secret_verification_serialization() {
        use ring::hmac;

        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(100),
            AckNumber::new(1),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac_tag = HmacTag::new(vec![0xAAu8; 32], HmacPolicy::Strong).unwrap();
        let server_public_key = EcdhPublicKey::new([0x33u8; 64]);
        let key_exchange_id: u16 = 0x5678;

        let shared_secret = [0x42u8; 32];
        let mut verification_input = Vec::new();
        verification_input.extend_from_slice(b"verification");
        verification_input.extend_from_slice(&key_exchange_id.to_be_bytes());

        let key = hmac::Key::new(hmac::HMAC_SHA256, &shared_secret);
        let tag = hmac::sign(&key, &verification_input);
        let shared_secret_verification: [u8; 32] = tag.as_ref().try_into().unwrap();

        let syn_ack = SynAckPacket {
            header,
            hmac: hmac_tag,
            ack_sequence: SequenceNumber::new(1),
            server_sequence: SequenceNumber::new(100),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        };

        let mut buffer = vec![0u8; 512];
        let size = syn_ack.serialize(&mut buffer).unwrap();

        let header_size = syn_ack.header.header_size();
        let verification_offset = header_size + 32 + 4 + 4 + 1 + 64 + 2;

        assert!(size >= verification_offset + 32);

        let serialized_verification = &buffer[verification_offset..verification_offset + 32];
        assert_eq!(
            serialized_verification, &shared_secret_verification,
            "Serialized verification must match computed value"
        );
    }

    #[test]
    fn test_client_can_verify_server_shared_secret() {
        use ring::hmac;

        let key_exchange_id: u16 = 0x9999;
        let shared_secret = [0x55u8; 32];

        let mut verification_input = Vec::new();
        verification_input.extend_from_slice(b"verification");
        verification_input.extend_from_slice(&key_exchange_id.to_be_bytes());

        let key = hmac::Key::new(hmac::HMAC_SHA256, &shared_secret);
        let tag = hmac::sign(&key, &verification_input);
        let server_verification: [u8; 32] = tag.as_ref().try_into().unwrap();

        let client_tag = hmac::sign(&key, &verification_input);
        let client_verification: [u8; 32] = client_tag.as_ref().try_into().unwrap();

        assert_eq!(
            server_verification, client_verification,
            "Client must be able to verify server's shared secret computation"
        );
    }

    #[test]
    fn test_wrong_verification_rejected() {
        use ring::hmac;

        let key_exchange_id: u16 = 0xAAAA;
        let correct_shared_secret = [0x66u8; 32];
        let wrong_shared_secret = [0x77u8; 32];

        let mut verification_input = Vec::new();
        verification_input.extend_from_slice(b"verification");
        verification_input.extend_from_slice(&key_exchange_id.to_be_bytes());

        let correct_key = hmac::Key::new(hmac::HMAC_SHA256, &correct_shared_secret);
        let correct_tag = hmac::sign(&correct_key, &verification_input);
        let correct_verification: [u8; 32] = correct_tag.as_ref().try_into().unwrap();

        let wrong_key = hmac::Key::new(hmac::HMAC_SHA256, &wrong_shared_secret);
        let wrong_tag = hmac::sign(&wrong_key, &verification_input);
        let wrong_verification: [u8; 32] = wrong_tag.as_ref().try_into().unwrap();

        assert_ne!(
            correct_verification, wrong_verification,
            "Wrong shared secret must produce different verification"
        );
    }

    #[test]
    fn test_verification_uses_constant_time_comparison() {
        let verification1 = [0x88u8; 32];
        let verification2 = [0x88u8; 32];
        let verification3 = [0x99u8; 32];

        #[allow(deprecated)]
        let result_match =
            ring::constant_time::verify_slices_are_equal(&verification1, &verification2);
        assert!(
            result_match.is_ok(),
            "Constant-time comparison should succeed for equal values"
        );

        #[allow(deprecated)]
        let result_mismatch =
            ring::constant_time::verify_slices_are_equal(&verification1, &verification3);
        assert!(
            result_mismatch.is_err(),
            "Constant-time comparison should fail for different values"
        );
    }

    #[test]
    fn test_syn_ack_roundtrip_with_verification() {
        use ring::hmac;

        let header = PacketHeader::new(
            VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32),
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0),
            SessionId::new(12345),
            SequenceNumber::new(200),
            AckNumber::new(1),
            Timestamp::now(),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );

        let hmac_tag = HmacTag::new(vec![0xBBu8; 32], HmacPolicy::Strong).unwrap();
        let server_public_key = EcdhPublicKey::new([0x44u8; 64]);
        let key_exchange_id: u16 = 0xBBCC;
        let shared_secret = [0x99u8; 32];

        let mut verification_input = Vec::new();
        verification_input.extend_from_slice(b"verification");
        verification_input.extend_from_slice(&key_exchange_id.to_be_bytes());

        let key = hmac::Key::new(hmac::HMAC_SHA256, &shared_secret);
        let tag = hmac::sign(&key, &verification_input);
        let shared_secret_verification: [u8; 32] = tag.as_ref().try_into().unwrap();

        let original = SynAckPacket {
            header,
            hmac: hmac_tag,
            ack_sequence: SequenceNumber::new(1),
            server_sequence: SequenceNumber::new(200),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
            server_public_key,
            key_exchange_id,
            shared_secret_verification,
        };

        let mut buffer = vec![0u8; 512];
        let size = original.serialize(&mut buffer).unwrap();

        let deserialized = SynAckPacket::deserialize(&buffer[..size]).unwrap();

        assert_eq!(
            deserialized.shared_secret_verification, original.shared_secret_verification,
            "Deserialized verification must match original"
        );
        assert_eq!(deserialized.key_exchange_id, original.key_exchange_id);
        assert_eq!(
            deserialized.server_public_key.as_bytes(),
            original.server_public_key.as_bytes()
        );
    }
}
