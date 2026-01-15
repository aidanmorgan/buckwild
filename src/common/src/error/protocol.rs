#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Protocol layer errors
//!
//! This module defines errors for packet parsing, serialization, validation,
//! fragmentation, and session management. Errors include context such as
//! SessionId, SequenceNumber, and packet details.

use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Protocol layer error types
#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    #[error("Packet parse error at offset {offset}: {reason}")]
    ParseError { offset: usize, reason: String },

    #[error("Invalid packet: {reason}")]
    InvalidPacket { reason: String },

    #[error("Invalid packet format: {reason}")]
    InvalidPacketFormat { reason: String },

    #[error("Buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    #[error("Packet too large: {size} bytes (max: {max})")]
    PacketTooLarge { size: PacketSize, max: PacketSize },

    #[error("Packet too small: {size} bytes (min: {min})")]
    PacketTooSmall { size: PacketSize, min: PacketSize },

    #[error("Invalid header: {field}")]
    InvalidHeader { field: String },

    #[error("Invalid header version: {version}")]
    InvalidVersion { version: u8 },

    #[error("Unsupported protocol version: {version}")]
    UnsupportedVersion { version: ProtocolVersion },

    #[error("Invalid sequence number: {seq} (expected: {expected})")]
    InvalidSequenceNumber {
        seq: SequenceNumber,
        expected: SequenceNumber,
    },

    #[error("Sequence number out of window: {seq} (window: {window_start}-{window_end})")]
    SequenceOutOfWindow {
        seq: SequenceNumber,
        window_start: SequenceNumber,
        window_end: SequenceNumber,
    },

    #[error("Fragmentation error: {reason}")]
    FragmentationError { reason: String },

    #[error("Fragment reassembly failed: {reason}")]
    ReassemblyFailed { reason: String },

    #[error("Fragment overlap detected: offset {offset}, length {length}")]
    FragmentOverlap {
        offset: FragmentIndex,
        length: FragmentSize,
    },

    #[error("Fragment timeout: fragment {fragment_id}")]
    FragmentTimeout { fragment_id: FragmentId },

    #[error("Invalid session: {session_id}")]
    InvalidSession { session_id: SessionId },

    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: SessionId },

    #[error("Protocol state error: {state} -> {attempted_transition}")]
    InvalidStateTransition {
        state: String,
        attempted_transition: String,
    },

    #[error("Checksum mismatch: expected {expected:x}, got {actual:x}")]
    ChecksumMismatch {
        expected: Checksum,
        actual: Checksum,
    },

    #[error("Serialization error: {reason}")]
    SerializationError { reason: String },

    #[error("Deserialization error: {reason}")]
    DeserializationError { reason: String },

    #[error("Packet validation failed: {reason}")]
    ValidationFailed { reason: String },

    #[error("Unsupported protocol feature: {feature}")]
    UnsupportedFeature { feature: String },
}

impl ProtocolError {
    /// Create a parse error at a specific offset
    pub fn parse_error(offset: usize, reason: impl Into<String>) -> Self {
        Self::ParseError {
            offset,
            reason: reason.into(),
        }
    }

    /// Create an invalid packet error
    pub fn invalid_packet(reason: impl Into<String>) -> Self {
        Self::InvalidPacket {
            reason: reason.into(),
        }
    }

    /// Create an invalid packet format error
    pub fn invalid_format(reason: impl Into<String>) -> Self {
        Self::InvalidPacketFormat {
            reason: reason.into(),
        }
    }

    /// Create a buffer too small error
    pub fn buffer_too_small(needed: usize, available: usize) -> Self {
        Self::BufferTooSmall { needed, available }
    }

    /// Create a packet size error
    pub fn packet_size_error(size: PacketSize, max_size: PacketSize) -> Self {
        if size > max_size {
            Self::PacketTooLarge {
                size,
                max: max_size,
            }
        } else {
            Self::PacketTooSmall {
                size,
                min: PacketSize::from_raw(1),
            }
        }
    }

    /// Create an invalid header error
    pub fn invalid_header(field: impl Into<String>) -> Self {
        Self::InvalidHeader {
            field: field.into(),
        }
    }

    /// Create an invalid version error
    pub fn invalid_version(version: u8) -> Self {
        Self::InvalidVersion { version }
    }

    /// Create a fragmentation error
    pub fn fragmentation_error(reason: impl Into<String>) -> Self {
        Self::FragmentationError {
            reason: reason.into(),
        }
    }

    /// Create a reassembly error
    pub fn reassembly_failed(reason: impl Into<String>) -> Self {
        Self::ReassemblyFailed {
            reason: reason.into(),
        }
    }

    /// Create a serialization error
    pub fn serialization_error(reason: impl Into<String>) -> Self {
        Self::SerializationError {
            reason: reason.into(),
        }
    }

    /// Create a deserialization error
    pub fn deserialization_error(reason: impl Into<String>) -> Self {
        Self::DeserializationError {
            reason: reason.into(),
        }
    }

    /// Create a validation failed error
    pub fn validation_failed(reason: impl Into<String>) -> Self {
        Self::ValidationFailed {
            reason: reason.into(),
        }
    }

    /// Create an unsupported feature error
    pub fn unsupported_feature(feature: impl Into<String>) -> Self {
        Self::UnsupportedFeature {
            feature: feature.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ParseError { .. } => false,
            Self::InvalidPacket { .. } => false,
            Self::InvalidPacketFormat { .. } => false,
            Self::BufferTooSmall { .. } => true,
            Self::PacketTooLarge { .. } => false,
            Self::PacketTooSmall { .. } => false,
            Self::InvalidHeader { .. } => false,
            Self::InvalidVersion { .. } => false,
            Self::UnsupportedVersion { .. } => false,
            Self::InvalidSequenceNumber { .. } => true,
            Self::SequenceOutOfWindow { .. } => true,
            Self::FragmentationError { .. } => true,
            Self::ReassemblyFailed { .. } => true,
            Self::FragmentOverlap { .. } => false,
            Self::FragmentTimeout { .. } => true,
            Self::InvalidSession { .. } => false,
            Self::SessionNotFound { .. } => true,
            Self::InvalidStateTransition { .. } => false,
            Self::ChecksumMismatch { .. } => false,
            Self::SerializationError { .. } => false,
            Self::DeserializationError { .. } => false,
            Self::ValidationFailed { .. } => false,
            Self::UnsupportedFeature { .. } => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::BufferTooSmall { .. } => Some("Allocate larger buffer"),
            Self::InvalidSequenceNumber { .. } => Some("Resynchronize sequence numbers"),
            Self::SequenceOutOfWindow { .. } => Some("Adjust sequence window"),
            Self::FragmentationError { .. } => Some("Retry with smaller fragments"),
            Self::ReassemblyFailed { .. } => Some("Request retransmission"),
            Self::FragmentTimeout { .. } => Some("Request fragment retransmission"),
            Self::SessionNotFound { .. } => Some("Reinitialize session"),
            _ => None,
        }
    }
}

/// Protocol layer result type
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<TypeValidationError> for ProtocolError {
    fn from(err: TypeValidationError) -> Self {
        Self::InvalidPacketFormat {
            reason: err.to_string(),
        }
    }
}

impl From<crate::protocol::types::ValidationError> for ProtocolError {
    fn from(err: crate::protocol::types::ValidationError) -> Self {
        Self::InvalidPacketFormat {
            reason: err.to_string(),
        }
    }
}
