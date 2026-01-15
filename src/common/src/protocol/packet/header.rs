#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

/// Protocol header implementation using ONLY consolidated types
///
/// This module implements the adaptive header format with cache-line aligned
/// atomic fields for concurrent access using consolidated types from protocol/types.
use std::fmt;

// Import ALL types from the authoritative consolidated types module
use crate::protocol::types::*;

// Cache line size (64 bytes on most architectures)
#[allow(dead_code)]
const CACHE_LINE_SIZE: usize = 64;

/// Cache-line aligned packet header with atomic fields for concurrent access and adaptive sizing
#[derive(Clone)]
#[repr(align(64))] // Align to cache line boundary
pub struct PacketHeader {
    // First cache line: Core header fields using consolidated newtypes
    version_byte: VersionByte,
    packet_type: PacketType,
    sub_type: SubType,
    flags: PacketFlags,

    // Session ID using consolidated SessionId newtype
    session_id: SessionId,

    // Sequence and acknowledgment numbers using consolidated newtypes
    sequence_number: SequenceNumber,
    ack_number: AckNumber,

    // Timestamp using consolidated Timestamp newtype
    timestamp: Timestamp,

    // Payload length using consolidated PayloadLength newtype
    payload_length: PayloadLength,

    // Security validation flags
    #[allow(dead_code)]
    security_validated: bool,

    // Padding to fill the first cache line
    _padding1: [u8; 31],

    // Second cache line: Configuration and metadata
    // Configuration cache for adaptive header format
    session_id_length: SessionIdLength,
    timestamp_config: TimestampConfig,
    hmac_policy: HmacPolicy,

    // Dual-epoch timestamp metadata
    #[allow(dead_code)]
    epoch_type: EpochType,

    // Security hardening flags
    #[allow(dead_code)]
    requires_strong_hmac: bool,

    // Padding to fill the second cache line
    _padding2: [u8; 58],
}

// EpochType is imported from consolidated types - no local definition needed

impl PacketHeader {
    /// Create a new PacketHeader with the specified configuration and enhanced security features
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version_byte: VersionByte,
        packet_type: PacketType,
        sub_type: SubType,
        flags: PacketFlags,
        session_id: SessionId,
        sequence_number: SequenceNumber,
        ack_number: AckNumber,
        timestamp: Timestamp,
        payload_length: PayloadLength,
        hmac_policy: HmacPolicy,
    ) -> Self {
        let session_id_length = version_byte.session_id_length();
        let timestamp_config = version_byte.timestamp_config();

        // Determine epoch type based on packet type and connection state
        let epoch_type = if packet_type == PacketType::Syn || packet_type == PacketType::SynAck {
            EpochType::Daily // Base port hopping for connection establishment
        } else {
            EpochType::Monthly // Session packets use monthly epoch
        };

        // Determine if strong HMAC is required based on packet class
        let requires_strong_hmac = packet_type.requires_strong_hmac();

        Self {
            version_byte,
            packet_type,
            sub_type,
            flags,
            session_id,
            sequence_number,
            ack_number,
            timestamp,
            payload_length,
            security_validated: false,
            _padding1: [0; 31],
            session_id_length,
            timestamp_config,
            hmac_policy,
            epoch_type,
            requires_strong_hmac,
            _padding2: [0; 58],
        }
    }

    /// Get the version byte
    pub fn version_byte(&self) -> VersionByte {
        self.version_byte
    }

    /// Get the packet type
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }

    /// Get the sub-type
    pub fn sub_type(&self) -> SubType {
        self.sub_type
    }

    /// Get the flags
    pub fn flags(&self) -> PacketFlags {
        self.flags
    }

    /// Get the session ID
    pub fn session_id(&self) -> SessionId {
        self.session_id.clone()
    }

    /// Get the sequence number
    pub fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Get the acknowledgment number
    pub fn ack_number(&self) -> AckNumber {
        self.ack_number.clone()
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Get the payload length
    pub fn payload_length(&self) -> PayloadLength {
        self.payload_length
    }

    /// Get the payload length (alias for compatibility)
    pub fn get_payload_length(&self) -> PayloadLength {
        self.payload_length
    }

    /// Get the HMAC policy
    pub fn hmac_policy(&self) -> HmacPolicy {
        self.hmac_policy
    }

    /// Calculate the total header size in bytes (excluding HMAC)
    pub fn header_size(&self) -> usize {
        // Base header size (4 bytes) + session ID + sequence + ack + timestamp + payload length
        4 + self.session_id_length.len() + 4 + 4 + self.timestamp_config.len() + 2
    }

    /// Calculate the total size including HMAC
    pub fn total_size(&self) -> usize {
        self.header_size() + self.hmac_policy.tag_size()
    }

    /// Serialize packet header to bytes
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, ValidationError> {
        if buffer.len() < self.header_size() {
            return Err(ValidationError::BufferTooSmall);
        }

        let mut offset = 0;

        // Write version byte
        buffer[offset] = self.version_byte.as_u8();
        offset += 1;

        // Write packet type
        buffer[offset] = self.packet_type as u8;
        offset += 1;

        // Write sub-type
        buffer[offset] = self.sub_type.as_u8();
        offset += 1;

        // Write flags
        buffer[offset] = self.flags.as_u8();
        offset += 1;

        // Write session ID (length depends on version byte config)
        let session_id_bytes = (self.session_id.as_u64()).to_be_bytes();
        let session_id_len = self.version_byte.session_id_length().byte_size();
        buffer[offset..offset + session_id_len]
            .copy_from_slice(&session_id_bytes[8 - session_id_len..]);
        offset += session_id_len;

        // Write sequence number
        let seq_bytes = self.sequence_number.as_u32().to_be_bytes();
        buffer[offset..offset + 4].copy_from_slice(&seq_bytes);
        offset += 4;

        // Write ack number
        let ack_bytes = self.ack_number.as_u32().to_be_bytes();
        buffer[offset..offset + 4].copy_from_slice(&ack_bytes);
        offset += 4;

        // Write timestamp (length depends on config)
        // For smaller formats, use milliseconds to fit meaningful values
        let timestamp_value = match self.version_byte.timestamp_config() {
            TimestampConfig::Bits16 => self.timestamp.as_millis() as u64, // Milliseconds for 16-bit
            TimestampConfig::Bits24 | TimestampConfig::Bits24High => {
                self.timestamp.as_millis() as u64
            } // Milliseconds for 24-bit
            TimestampConfig::Bits32 => self.timestamp.as_millis() as u64, // Milliseconds for 32-bit
        };
        let timestamp_bytes = timestamp_value.to_be_bytes();
        let timestamp_len = self.version_byte.timestamp_config().byte_size();
        buffer[offset..offset + timestamp_len]
            .copy_from_slice(&timestamp_bytes[8 - timestamp_len..]);
        offset += timestamp_len;

        // Write payload length
        let payload_len_bytes = self.payload_length.as_u16().to_be_bytes();
        buffer[offset..offset + 2].copy_from_slice(&payload_len_bytes);
        offset += 2;

        Ok(offset)
    }

    /// Deserialize packet header from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.len() < 4 {
            return Err(ValidationError::InvalidLength);
        }

        // Parse version byte
        let version_byte = VersionByte::from_raw(bytes[0]);

        // Parse packet type
        let packet_type =
            PacketType::from_u8(bytes[1]).ok_or(ValidationError::InvalidPacketType)?;

        // Parse sub-type
        let sub_type = SubType::new(bytes[2]);

        // Parse flags
        let flags = PacketFlags::from_u8(bytes[3]);

        // Calculate expected header size based on configuration
        let session_id_length = version_byte.session_id_length();
        let timestamp_config = version_byte.timestamp_config();
        let expected_size = 4 + session_id_length.len() + 4 + 4 + timestamp_config.len() + 2;

        if bytes.len() < expected_size {
            return Err(ValidationError::InvalidLength);
        }

        // Parse variable-length fields
        let mut offset = 4;

        // Parse session ID
        let session_id = match session_id_length {
            SessionIdLength::Bits16 => {
                let id = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as u64;
                SessionId::new(id)
            }
            SessionIdLength::Bits32 => {
                let id = u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]) as u64;
                SessionId::new(id)
            }
            SessionIdLength::Bits64 => {
                let id = u64::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]);
                SessionId::new(id)
            }
            SessionIdLength::Bits128 => {
                if bytes.len() < offset + 16 {
                    return Err(ValidationError::InvalidLength);
                }
                // We currently only support 64-bit session IDs internally.
                // Use the lower 64 bits (last 8 bytes in BE)
                let mut id_bytes = [0u8; 8];
                id_bytes.copy_from_slice(&bytes[offset + 8..offset + 16]);
                let id = u64::from_be_bytes(id_bytes);
                SessionId::new(id)
            }
        };
        offset += session_id_length.len();

        // Parse sequence number
        let sequence_number = SequenceNumber::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        // Parse ack number
        let ack_number = AckNumber::new(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]));
        offset += 4;

        // Parse timestamp
        // For smaller formats, values are in milliseconds (matching serialization)
        let timestamp = match timestamp_config {
            TimestampConfig::Bits16 => {
                let ts = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as u64;
                Timestamp::from_millis(ts) // Milliseconds for 16-bit
            }
            TimestampConfig::Bits24 | TimestampConfig::Bits24High => {
                let ts =
                    u32::from_be_bytes([0, bytes[offset], bytes[offset + 1], bytes[offset + 2]])
                        as u64;
                Timestamp::from_millis(ts) // Milliseconds for 24-bit
            }
            TimestampConfig::Bits32 => {
                let ts = u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]) as u64;
                Timestamp::from_millis(ts) // Milliseconds for 32-bit
            }
        };
        offset += timestamp_config.len();

        // Parse payload length
        let payload_length =
            PayloadLength::new(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));

        // Determine HMAC policy based on packet class
        let hmac_policy = if packet_type.requires_strong_hmac() {
            HmacPolicy::Strong
        } else {
            HmacPolicy::Medium
        };

        Ok(Self::new(
            version_byte,
            packet_type,
            sub_type,
            flags,
            session_id,
            sequence_number,
            ack_number,
            timestamp,
            payload_length,
            hmac_policy,
        ))
    }

    /// Validate the packet header
    pub fn validate(&self) -> ValidationResult<()> {
        // Validate protocol version
        if self.version_byte.protocol_version() == 0 || self.version_byte.protocol_version() > 1 {
            return ValidationResult::Invalid(ValidationError::InvalidProtocolVersion);
        }

        // Validate session ID
        if !self.session_id.is_valid() {
            return ValidationResult::Invalid(ValidationError::InvalidSessionId);
        }

        // Payload length is u16, so it's always valid (0-65535)

        ValidationResult::Valid(())
    }
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketHeader")
            .field(
                "version_byte",
                &format_args!("{:#04x}", self.version_byte.as_u8()),
            )
            .field("packet_type", &self.packet_type)
            .field("sub_type", &format_args!("{:#04x}", self.sub_type.as_u8()))
            .field("flags", &self.flags)
            .field("session_id", &self.session_id)
            .field("sequence_number", &self.sequence_number)
            .field("ack_number", &self.ack_number)
            .field("timestamp", &self.timestamp)
            .field("payload_length", &self.payload_length)
            .field("hmac_policy", &self.hmac_policy)
            .finish()
    }
}
