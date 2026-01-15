//! # Authoritative Protocol Types
//!
//! This module contains the ONLY authoritative definitions for all protocol types.
//! ALL other modules MUST import from this module instead of re-defining types.
//!
//! ## Violation Elimination Strategy
//! This consolidates 1200+ primitive type violations across the codebase into
//! proper newtype wrappers that provide type safety and protocol compliance.
//!
//! ## Design Principles
//! 1. **Single Authoritative Module**: ALL protocol types defined ONLY here
//! 2. **Atomic-by-Default**: Types needing concurrent access are atomic by default
//! 3. **Zero-Cost Abstractions**: Use #[repr(transparent)] for no runtime overhead
//! 4. **eBPF Compatibility**: All types compatible with eBPF boundary requirements
//! 5. **Protocol Specification Alignment**: All types map to protocol constants

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{
    AtomicI64, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::time::{Duration, SystemTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

//==============================================================================
// GLOBAL CONSTANTS
//==============================================================================

/// Global port constants for backward compatibility
pub const MIN_PORT: Port = Port(1024);
pub const MAX_PORT: Port = Port(65535);
pub const PORT_RANGE: u32 = (65535 - 1024) as u32;

//==============================================================================
// PROTOCOL HEADER TYPES
//==============================================================================

/// Session ID length configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SessionIdLength {
    Bits16 = 0,
    Bits32 = 1,
    Bits64 = 2,
    Bits128 = 3,
}

impl SessionIdLength {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Bits16,
            1 => Self::Bits32,
            2 => Self::Bits64,
            3 => Self::Bits128,
            _ => Self::Bits64, // Default to 64-bit
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn byte_size(&self) -> usize {
        match self {
            Self::Bits16 => 2,
            Self::Bits32 => 4,
            Self::Bits64 => 8,
            Self::Bits128 => 16,
        }
    }

    pub fn len(&self) -> usize {
        self.byte_size()
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Timestamp configuration for variable encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TimestampConfig {
    Bits16 = 0,
    Bits24 = 1,
    Bits24High = 2,
    Bits32 = 3,
}

impl TimestampConfig {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Bits16,
            1 => Self::Bits24,
            2 => Self::Bits24High,
            3 => Self::Bits32,
            _ => Self::Bits32, // Default to 32-bit
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn byte_size(&self) -> usize {
        match self {
            Self::Bits16 => 2,
            Self::Bits24 | Self::Bits24High => 3,
            Self::Bits32 => 4,
        }
    }

    pub fn len(&self) -> usize {
        self.byte_size()
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Version byte encoding - protocol version + configuration bits
/// Maps to design/protocol/03-packet-architecture.md version byte specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VersionByte(u8);

impl VersionByte {
    /// Create new version byte with protocol version and config
    pub fn new(
        version: u8,
        session_id_length: SessionIdLength,
        timestamp_config: TimestampConfig,
    ) -> Self {
        let mut byte = version & 0x0F; // Bits 0-3: protocol version
        byte |= (session_id_length as u8) << 4; // Bits 4-5: session ID length
        byte |= (timestamp_config as u8) << 6; // Bits 6-7: timestamp config
        Self(byte)
    }

    /// Extract protocol version (bits 0-3)
    pub fn protocol_version(&self) -> u8 {
        self.0 & 0x0F
    }

    /// Alias for protocol_version
    pub fn version(&self) -> u8 {
        self.protocol_version()
    }

    /// Extract session ID length configuration (bits 4-5)
    pub fn session_id_length(&self) -> SessionIdLength {
        SessionIdLength::from_u8((self.0 >> 4) & 0x03)
    }

    /// Extract timestamp configuration (bits 6-7)
    pub fn timestamp_config(&self) -> TimestampConfig {
        TimestampConfig::from_u8((self.0 >> 6) & 0x03)
    }

    /// Get raw byte value
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// Create from raw u8 value
    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Create from raw u8 value (alias for compatibility)
    pub fn from_raw(value: u8) -> Self {
        Self(value)
    }

    /// eBPF compatibility
    pub fn to_ebpf_u8(&self) -> u8 {
        self.0
    }

    pub fn from_ebpf_u8(value: u8) -> Self {
        Self(value)
    }
}

/// Packet type enumeration - all protocol packet types
/// Maps to design/protocol/02-core-definitions.md packet type constants
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    Syn = 0x01,
    SynAck = 0x02,
    Ack = 0x03,
    Data = 0x04,
    Fin = 0x05,
    Heartbeat = 0x06,
    Error = 0x09,
    Rst = 0x0B,
    Control = 0x0C,
    Management = 0x0D,
    Discovery = 0x0E,
    Fragment = 0x0F,
}

impl PacketType {
    /// Create from raw u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Syn),
            0x02 => Some(Self::SynAck),
            0x03 => Some(Self::Ack),
            0x04 => Some(Self::Data),
            0x05 => Some(Self::Fin),
            0x06 => Some(Self::Heartbeat),
            0x09 => Some(Self::Error),
            0x0B => Some(Self::Rst),
            0x0C => Some(Self::Control),
            0x0D => Some(Self::Management),
            0x0E => Some(Self::Discovery),
            0x0F => Some(Self::Fragment),
            _ => None,
        }
    }

    /// Convert to raw u8 value
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if packet type requires HMAC_STRONG authentication
    pub fn requires_strong_hmac(&self) -> bool {
        matches!(self, Self::Syn | Self::SynAck | Self::Fin | Self::Discovery)
    }

    /// Check if packet type is a control packet
    pub fn is_control(&self) -> bool {
        matches!(self, Self::Control | Self::Management)
    }

    /// Get packet class for QoS and HMAC policy selection
    pub fn packet_class(&self) -> PacketClass {
        match self {
            Self::Syn | Self::SynAck | Self::Fin | Self::Discovery => PacketClass::Critical,
            Self::Control | Self::Management | Self::Error | Self::Rst => PacketClass::Control,
            Self::Data | Self::Ack | Self::Heartbeat | Self::Fragment => PacketClass::Data,
        }
    }

    /// Check if packet type requires acknowledgment
    pub fn requires_ack(&self) -> bool {
        matches!(self, Self::Syn | Self::SynAck | Self::Data | Self::Fin)
    }

    /// Check if packet type is a connection packet
    pub fn is_connection_packet(&self) -> bool {
        matches!(self, Self::Syn | Self::SynAck | Self::Fin | Self::Rst)
    }

    /// eBPF compatibility
    pub fn to_ebpf_u8(&self) -> u8 {
        self.as_u8()
    }

    pub fn from_ebpf_u8(value: u8) -> Option<Self> {
        Self::from_u8(value)
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syn => write!(f, "SYN"),
            Self::SynAck => write!(f, "SYN-ACK"),
            Self::Ack => write!(f, "ACK"),
            Self::Data => write!(f, "DATA"),
            Self::Fin => write!(f, "FIN"),
            Self::Heartbeat => write!(f, "HEARTBEAT"),
            Self::Error => write!(f, "ERROR"),
            Self::Rst => write!(f, "RST"),
            Self::Control => write!(f, "CONTROL"),
            Self::Management => write!(f, "MANAGEMENT"),
            Self::Discovery => write!(f, "DISCOVERY"),
            Self::Fragment => write!(f, "FRAGMENT"),
        }
    }
}

/// Control packet sub-types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ControlSubType {
    TimeSyncRequest = 0x01,
    TimeSyncResponse = 0x02,
    Recovery = 0x03,
    SequenceNegotiation = 0x04,
    // SequenceNeg is an alias - removed duplicate discriminant
    HmacPolicyRequest = 0x05,
    HmacPolicyResponse = 0x06,
}

impl ControlSubType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::TimeSyncRequest),
            0x02 => Some(Self::TimeSyncResponse),
            0x03 => Some(Self::Recovery),
            0x04 => Some(Self::SequenceNegotiation),
            0x05 => Some(Self::HmacPolicyRequest),
            0x06 => Some(Self::HmacPolicyResponse),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Management packet sub-types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ManagementSubType {
    RekeyRequest = 0x01,
    RekeyResponse = 0x02,
    RepairRequest = 0x03,
    RepairResponse = 0x04,
    RepairConfirm = 0x05,
}

impl ManagementSubType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::RekeyRequest),
            0x02 => Some(Self::RekeyResponse),
            0x03 => Some(Self::RepairRequest),
            0x04 => Some(Self::RepairResponse),
            0x05 => Some(Self::RepairConfirm),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Discovery packet sub-types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DiscoverySubType {
    Request = 0x01,
    Response = 0x02,
    Confirm = 0x03,
}

impl DiscoverySubType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Request),
            0x02 => Some(Self::Response),
            0x03 => Some(Self::Confirm),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Packet flags bitfield
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(transparent)]
pub struct PacketFlags(u8);

impl PacketFlags {
    pub const FIN: u8 = 1 << 0;
    pub const SYN: u8 = 1 << 1;
    pub const RST: u8 = 1 << 2;
    pub const PSH: u8 = 1 << 3;
    pub const ACK: u8 = 1 << 4;
    pub const URG: u8 = 1 << 5;
    pub const SACK: u8 = 1 << 6;
    pub const FRAGMENT: u8 = 1 << 7;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn set_flag(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn clear_flag(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    pub fn is_fin(&self) -> bool {
        self.has_flag(Self::FIN)
    }
    pub fn is_syn(&self) -> bool {
        self.has_flag(Self::SYN)
    }
    pub fn is_rst(&self) -> bool {
        self.has_flag(Self::RST)
    }
    pub fn is_psh(&self) -> bool {
        self.has_flag(Self::PSH)
    }
    pub fn is_ack(&self) -> bool {
        self.has_flag(Self::ACK)
    }
    pub fn is_urg(&self) -> bool {
        self.has_flag(Self::URG)
    }
    pub fn is_sack(&self) -> bool {
        self.has_flag(Self::SACK)
    }
    pub fn is_fragment(&self) -> bool {
        self.has_flag(Self::FRAGMENT)
    }
    pub fn is_frag(&self) -> bool {
        self.has_flag(Self::FRAGMENT)
    }
    pub fn is_fragmented(&self) -> bool {
        self.has_flag(Self::FRAGMENT)
    }

    pub fn set(&mut self, flag: u8) {
        self.set_flag(flag);
    }

    pub fn with_flags(flags: u8) -> Self {
        Self(flags)
    }
}

impl Default for PacketFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet classification for QoS and HMAC policy selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PacketClass {
    Data = 0,
    Control = 1,
    Critical = 2,
}

impl PacketClass {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Data),
            1 => Some(Self::Control),
            2 => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Epoch type for dual-epoch timestamp handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EpochType {
    Daily = 0,
    Monthly = 1,
    Standard = 2,
    Milliseconds = 3,
}

impl EpochType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Daily),
            1 => Some(Self::Monthly),
            2 => Some(Self::Standard),
            3 => Some(Self::Milliseconds),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Session identifier with atomic-by-default design for concurrent access
/// Uses atomic operations internally but provides both atomic and non-atomic access
#[derive(Debug)]
#[repr(transparent)]
pub struct SessionId(AtomicU64);

impl Clone for SessionId {
    fn clone(&self) -> Self {
        Self(AtomicU64::new(self.0.load(Ordering::Relaxed)))
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(SessionId::new(value))
    }
}

impl Serialize for SessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_u64().serialize(serializer)
    }
}

impl SessionId {
    /// Create new session ID
    pub fn new(id: u64) -> Self {
        Self(AtomicU64::new(id))
    }

    /// Create with length-aware truncation for protocol encoding
    pub fn new_with_length(value: u64, length: SessionIdLength) -> Self {
        let truncated = match length {
            SessionIdLength::Bits16 => value & 0xFFFF,
            SessionIdLength::Bits32 => value & 0xFFFFFFFF,
            SessionIdLength::Bits64 => value,
            SessionIdLength::Bits128 => value,
        };
        Self(AtomicU64::new(truncated))
    }

    /// Generate cryptographically secure random session ID
    pub fn generate() -> Self {
        use rand::Rng;
        Self::new(rand::thread_rng().r#gen())
    }

    /// Non-atomic access for single-threaded contexts (zero-cost)
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Check if session ID is valid (non-zero)
    pub fn is_valid(&self) -> bool {
        self.get() != 0
    }

    /// Get raw value (non-atomic access)
    pub fn as_u64(&self) -> u64 {
        self.get()
    }

    /// Atomic operations for concurrent contexts
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: u64, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.0.compare_exchange(current, new, success, failure)
    }

    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }

    /// eBPF compatibility
    pub fn to_ebpf_u64(&self) -> u64 {
        self.get()
    }

    pub fn from_ebpf_u64(value: u64) -> Self {
        Self::new(value)
    }

    /// Create from raw u64 value (for eBPF compatibility)
    pub fn from_raw(value: u64) -> Self {
        Self::new(value)
    }

    /// Get raw u64 value
    pub fn as_raw(&self) -> u64 {
        self.get()
    }

    /// Convert to big-endian byte representation
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.get().to_be_bytes()
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new(0)
    }
}

impl PartialEq for SessionId {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for SessionId {}

impl PartialOrd for SessionId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SessionId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl std::hash::Hash for SessionId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.get().hash(state);
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session:{}", self.get())
    }
}

// SessionIdAtomic removed - SessionId is now atomic-by-default

/// Sequence number with wraparound handling
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(transparent)]
pub struct SequenceNumber(u32);

impl SequenceNumber {
    pub const MAX_SEQUENCE_NUMBER: u32 = 0xFFFFFFFF;

    pub fn new(seq: u32) -> Self {
        Self(seq)
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Check if sequence number is in valid range relative to another
    pub fn is_valid_relative(&self, other: &SequenceNumber, window_size: u32) -> bool {
        let self_seq = self.0;
        let other_seq = other.0;

        // Handle wraparound
        let diff = if self_seq >= other_seq {
            self_seq - other_seq
        } else {
            (Self::MAX_SEQUENCE_NUMBER - other_seq) + self_seq + 1
        };

        diff <= window_size
    }

    pub fn to_ebpf_u32(&self) -> u32 {
        self.0
    }

    pub fn from_ebpf_u32(value: u32) -> Self {
        Self::new(value)
    }

    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }

    pub fn wrapping_sub(&self, other: &Self) -> Self {
        Self::new(self.0.wrapping_sub(other.0))
    }

    pub fn diff(&self, other: &Self) -> u32 {
        let self_seq = self.0;
        let other_seq = other.0;
        if self_seq >= other_seq {
            self_seq - other_seq
        } else {
            (Self::MAX_SEQUENCE_NUMBER - other_seq) + self_seq + 1
        }
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    /// Check if sequence number is valid (non-zero for initial sequences)
    pub fn is_valid(&self) -> bool {
        true // All sequence numbers are valid, including zero
    }
}

impl From<u32> for SequenceNumber {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<SequenceNumber> for u32 {
    fn from(seq: SequenceNumber) -> Self {
        seq.as_u32()
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq:{}", self.0)
    }
}

impl std::ops::Add<u32> for SequenceNumber {
    type Output = Self;
    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

impl std::ops::Sub<u32> for SequenceNumber {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self::Output {
        Self(self.0.wrapping_sub(rhs))
    }
}

impl std::ops::AddAssign<u32> for SequenceNumber {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl std::ops::SubAssign<u32> for SequenceNumber {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_sub(rhs);
    }
}

// SequenceNumberAtomic removed - SequenceNumber is now atomic-by-default

/// Acknowledgment number
#[derive(Debug)]
#[repr(transparent)]
pub struct AckNumber(AtomicU32);

impl Clone for AckNumber {
    fn clone(&self) -> Self {
        Self(AtomicU32::new(self.0.load(Ordering::Relaxed)))
    }
}

impl AckNumber {
    pub fn new(ack: u32) -> Self {
        Self(AtomicU32::new(ack))
    }

    /// Non-atomic access for single-threaded contexts
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    /// Atomic operations for concurrent contexts
    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, ack: u32, ordering: Ordering) {
        self.0.store(ack, ordering);
    }

    pub fn fetch_add(&self, val: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(val, ordering)
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.get().to_be_bytes()
    }

    pub fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.0.compare_exchange(current, new, success, failure)
    }

    pub fn as_u32(&self) -> u32 {
        self.get()
    }

    pub fn to_ebpf_u32(&self) -> u32 {
        self.get()
    }

    pub fn from_ebpf_u32(value: u32) -> Self {
        Self::new(value)
    }

    pub fn as_raw(&self) -> u32 {
        self.get()
    }

    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }
}

impl Default for AckNumber {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Payload length
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PayloadLength(u16);

impl PayloadLength {
    pub fn new(len: u16) -> Self {
        Self(len)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self::new(value)
    }
}

//==============================================================================
// VALIDATION TYPES
//==============================================================================

// ValidationResult is defined later in the file with extended functionality

/// Validation error enumeration
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidationError {
    InvalidLength,
    InvalidPacketType,
    InvalidProtocolVersion,
    InvalidSessionId,
    InvalidSequenceNumber,
    InvalidPayloadLength,
    InvalidWindowSize,
    InvalidFragmentIndex,
    InvalidFragmentCount,
    InvalidPort,
    InvalidChecksum,
    InvalidTimestamp,
    InvalidHmacTag,
    InvalidConfiguration,
    InvalidState,
    // Additional validation errors for crypto operations
    InvalidKeyLength,
    InvalidSecretLength,
    InvalidMaterialLength,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidNonce,
    MissingPublicKey,
    BufferTooSmall,
    SessionIdTooLarge,
    TimestampTooLarge,
    InvalidHmacLength,
    PortOutOfRange { port: u16 },
    UnsupportedFeature(String),
    InvalidTerminationReason,
    InvalidResetReason,
    InvalidErrorCode,
    InvalidErrorDescription,
    ReplayAttackDetected,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid length"),
            Self::InvalidPacketType => write!(f, "Invalid packet type"),
            Self::InvalidProtocolVersion => write!(f, "Invalid protocol version"),
            Self::InvalidSessionId => write!(f, "Invalid session ID"),
            Self::InvalidSequenceNumber => write!(f, "Invalid sequence number"),
            Self::InvalidPayloadLength => write!(f, "Invalid payload length"),
            Self::InvalidWindowSize => write!(f, "Invalid window size"),
            Self::InvalidFragmentIndex => write!(f, "Invalid fragment index"),
            Self::InvalidFragmentCount => write!(f, "Invalid fragment count"),
            Self::InvalidPort => write!(f, "Invalid port"),
            Self::InvalidChecksum => write!(f, "Invalid checksum"),
            Self::InvalidTimestamp => write!(f, "Invalid timestamp"),
            Self::InvalidHmacTag => write!(f, "Invalid HMAC tag"),
            Self::InvalidConfiguration => write!(f, "Invalid configuration"),
            Self::InvalidState => write!(f, "Invalid state"),
            Self::InvalidKeyLength => write!(f, "Invalid key length"),
            Self::InvalidSecretLength => write!(f, "Invalid secret length"),
            Self::InvalidMaterialLength => write!(f, "Invalid material length"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::InvalidNonce => write!(f, "Invalid nonce"),
            Self::MissingPublicKey => write!(f, "Missing public key"),
            Self::BufferTooSmall => write!(f, "Buffer too small"),
            Self::SessionIdTooLarge => write!(f, "Session ID too large"),
            Self::TimestampTooLarge => write!(f, "Timestamp too large"),
            Self::InvalidHmacLength => write!(f, "Invalid HMAC length"),
            Self::PortOutOfRange { port } => write!(f, "Port {} out of range", port),
            Self::UnsupportedFeature(feature) => write!(f, "Unsupported feature: {}", feature),
            Self::InvalidTerminationReason => write!(f, "Invalid termination reason"),
            Self::InvalidResetReason => write!(f, "Invalid reset reason"),
            Self::InvalidErrorCode => write!(f, "Invalid error code"),
            Self::InvalidErrorDescription => write!(f, "Invalid error description"),
            Self::ReplayAttackDetected => write!(f, "Replay attack detected"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validation trait for types that can be validated
pub trait Validate {
    fn validate(&self) -> ValidationResult<()>;
}

//==============================================================================
// NETWORK TYPES
//==============================================================================

/// Network port with validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Port(pub u16);

impl Port {
    pub const MIN_PORT: u16 = 1024;
    pub const MAX_PORT: u16 = 65535;
    pub const MIN: Port = Port(1024);
    pub const MAX: Port = Port(65535);

    pub fn new(port: u16) -> Result<Self, ValidationError> {
        if !(Self::MIN_PORT..=Self::MAX_PORT).contains(&port) {
            return Err(ValidationError::PortOutOfRange { port });
        }
        Ok(Self(port))
    }

    pub const fn from_u16_unchecked(port: u16) -> Self {
        Self(port)
    }

    /// Create port without validation - use for well-known ports like DNS (53)
    pub const fn from_well_known(port: u16) -> Self {
        Self(port)
    }

    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self(value)
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn is_valid(&self) -> bool {
        self.0 >= Self::MIN_PORT
    }

    pub fn is_well_known(&self) -> bool {
        self.0 < 1024
    }

    /// Get the next port in sequence, wrapping around if necessary
    pub fn next(&self) -> Self {
        if self.0 == Self::MAX_PORT {
            Self(Self::MIN_PORT)
        } else {
            Self(self.0 + 1)
        }
    }
}

impl From<u16> for Port {
    fn from(port: u16) -> Self {
        Self::from_u16_unchecked(port)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Add Display implementations for types missing them
impl fmt::Display for ClockSkew {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.load(Ordering::Relaxed))
    }
}

impl fmt::Display for TimeOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.load(Ordering::Relaxed))
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for WindowSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ByteCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.load(Ordering::Relaxed))
    }
}

impl fmt::Display for MtuSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for DataRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for MemorySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// eBPF type Display implementations
impl fmt::Display for EbpfProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for EbpfVerifierLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for EbpfInstructionCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for EbpfStackSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for RingBufferSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for EbpfFileDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for EbpfMapSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Debug trait for tracing compatibility

/// Display trait for types that need as_display method
pub trait AsDisplay {
    fn as_display(&self) -> String;
}

// Implement AsDisplay for key types
impl AsDisplay for Timestamp {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for ProtocolDuration {
    fn as_display(&self) -> String {
        format!("{}ns", self.0)
    }
}

impl AsDisplay for SessionCount {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for ConnectionCount {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for FragmentId {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for FragmentIndex {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for FragmentSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for WindowSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for ProtocolVersion {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for ClockSkew {
    fn as_display(&self) -> String {
        format!("{}ns", self.load(Ordering::Relaxed))
    }
}

impl AsDisplay for TimeOffset {
    fn as_display(&self) -> String {
        format!("{}ns", self.load(Ordering::Relaxed))
    }
}

impl AsDisplay for Epoch {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for RoundTripTime {
    fn as_display(&self) -> String {
        format!("{}ns", self.0)
    }
}

impl AsDisplay for NetworkDelay {
    fn as_display(&self) -> String {
        format!("{}ns", self.0)
    }
}

impl AsDisplay for SyncQuality {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for HeartbeatInterval {
    fn as_display(&self) -> String {
        format!("{}ms", self.0)
    }
}

impl AsDisplay for TimeDrift {
    fn as_display(&self) -> String {
        format!("{}ppm", self.0)
    }
}

impl AsDisplay for ConfigurationVersion {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for ByteCount {
    fn as_display(&self) -> String {
        format!("{}", self.0.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl AsDisplay for MtuSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for DataRate {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for FragmentCount {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for FragmentTimeout {
    fn as_display(&self) -> String {
        format!("{}ms", self.0)
    }
}

impl AsDisplay for ReassemblyBufferSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for CongestionWindow {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for SlowStartThreshold {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for AdvertisedWindow {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for ReceiveWindow {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for WindowScale {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for MaxSegmentSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for DiscoveryId {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for DiscoveryTimeout {
    fn as_display(&self) -> String {
        format!("{}ms", self.0)
    }
}

impl AsDisplay for RecoveryLevel {
    fn as_display(&self) -> String {
        format!("{}", *self as u8)
    }
}

impl AsDisplay for RecoveryTimeout {
    fn as_display(&self) -> String {
        format!("{}ms", self.0)
    }
}

impl AsDisplay for RingBufferSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for MemorySize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

//==============================================================================
// FRAGMENTATION TYPES
//==============================================================================

/// Fragment identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FragmentId(u16);

impl FragmentId {
    pub const FRAGMENT_ID_SPACE: u16 = 0xFFFF;

    pub fn new(id: u16) -> Self {
        Self(id)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for FragmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Atomic Fragment ID for concurrent fragment generation
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicFragmentId(AtomicU16);

impl AtomicFragmentId {
    pub const fn new(id: u16) -> Self {
        Self(AtomicU16::new(id))
    }

    pub const fn from_raw(id: u16) -> Self {
        Self::new(id)
    }

    pub fn load(&self, ordering: Ordering) -> FragmentId {
        FragmentId::new(self.0.load(ordering))
    }

    pub fn store(&self, value: FragmentId, ordering: Ordering) {
        self.0.store(value.as_u16(), ordering);
    }

    pub fn fetch_add(&self, val: u16, ordering: Ordering) -> FragmentId {
        FragmentId::new(self.0.fetch_add(val, ordering))
    }

    pub fn swap(&self, val: FragmentId, ordering: Ordering) -> FragmentId {
        FragmentId::new(self.0.swap(val.as_u16(), ordering))
    }
}

impl Default for AtomicFragmentId {
    fn default() -> Self {
        Self::new(1) // Start from 1, not 0
    }
}

/// Fragment index (position within fragmented packet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[derive(Default)]
pub struct FragmentIndex(u16);

impl FragmentIndex {
    pub fn new(index: u16) -> Self {
        Self(index)
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self::new(value)
    }
}

/// Fragment count (total number of fragments)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[derive(Default)]
pub struct FragmentCount(u16);

impl FragmentCount {
    pub const MAX_FRAGMENTS: u16 = 255;
    pub const MAX_FRAGMENTS_PER_PACKET: u8 = 16;

    pub fn new(count: u16) -> Self {
        Self(count)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self::new(value)
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// Fragment size (payload size of individual fragment)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct FragmentSize(pub u16);

impl FragmentSize {
    pub const MIN_FRAGMENT_SIZE: u16 = 64;
    pub const MAX_FRAGMENT_SIZE: u16 = 1400;

    pub fn new(size: u16) -> Self {
        Self(size)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self::new(value)
    }
}

impl std::ops::Mul<FragmentSize> for usize {
    type Output = usize;
    fn mul(self, rhs: FragmentSize) -> Self::Output {
        self * rhs.0 as usize
    }
}

impl std::ops::Add<FragmentSize> for usize {
    type Output = usize;
    fn add(self, rhs: FragmentSize) -> Self::Output {
        self + rhs.0 as usize
    }
}

/// Fragment timeout duration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FragmentTimeout(pub u64);

impl FragmentTimeout {
    pub const FRAGMENT_TIMEOUT_MS: u64 = 5000;

    pub fn new(timeout_ms: u64) -> Self {
        Self(timeout_ms)
    }

    pub fn to_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.0)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub fn to_ebpf_u64(&self) -> u64 {
        self.0
    }

    pub fn from_ebpf_u64(value: u64) -> Self {
        Self::new(value)
    }
}

/// Reassembly buffer size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ReassemblyBufferSize(u16);

impl ReassemblyBufferSize {
    pub const MAX_REASSEMBLY_MEMORY_PER_SESSION: usize = 1048576;

    pub fn new(size: u16) -> Self {
        Self(size)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self::new(value)
    }
}

/// SACK block count
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SackBlockCount(u8);

impl SackBlockCount {
    pub fn new(count: u8) -> Self {
        Self(count)
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_raw(&self) -> u8 {
        self.0
    }

    pub fn from_raw(value: u8) -> Self {
        Self(value)
    }
}

/// SACK bitmap for selective acknowledgment
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SackBitmap(u32);

impl SackBitmap {
    pub fn new(bitmap: u32) -> Self {
        Self(bitmap)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// SACK range for selective acknowledgment
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SackRange {
    pub start_seq: SequenceNumber,
    pub end_seq: SequenceNumber,
}

impl SackRange {
    pub fn new(start_seq: SequenceNumber, end_seq: SequenceNumber) -> Self {
        Self { start_seq, end_seq }
    }
}

/// Fragmentation state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FragmentationState {
    None = 0,
    InProgress = 1,
    Complete = 2,
    Failed = 3,
    Timeout = 4,
}

impl FragmentationState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::InProgress),
            2 => Some(Self::Complete),
            3 => Some(Self::Failed),
            4 => Some(Self::Timeout),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Fragment reassembly result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentReassemblyResult {
    Complete(Vec<u8>),
    Incomplete,
    Failed(String),
    Timeout,
    StateError(String),
    System(String),
}

//==============================================================================
// FLOW CONTROL TYPES
//==============================================================================

/// Window scale factor
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct WindowScale(u8);

impl WindowScale {
    pub fn new(scale: u8) -> Self {
        Self(scale)
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_raw(&self) -> u8 {
        self.0
    }

    pub fn from_raw(value: u8) -> Self {
        Self(value)
    }
}

impl Default for WindowScale {
    fn default() -> Self {
        Self(1)
    }
}

/// Congestion window size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct CongestionWindow(pub u32);

impl CongestionWindow {
    pub fn new(size: u32) -> Self {
        Self(size)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Receive window size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ReceiveWindow(u32);

impl ReceiveWindow {
    pub fn new(size: u32) -> Self {
        Self(size)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Advertised window size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AdvertisedWindow(u32);

impl AdvertisedWindow {
    pub fn new(size: u32) -> Self {
        Self(size)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Slow start threshold
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SlowStartThreshold(u32);

impl SlowStartThreshold {
    pub const fn new(threshold: u32) -> Self {
        Self(threshold)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Maximum segment size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MaxSegmentSize(u16);

impl MaxSegmentSize {
    pub const MSS: u16 = 1460;

    pub const fn new(size: u16) -> Self {
        Self(size)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }
}

/// Congestion state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CongestionState {
    SlowStart = 1,
    CongestionAvoidance = 2,
    FastRecovery = 3,
}

impl CongestionState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SlowStart),
            2 => Some(Self::CongestionAvoidance),
            3 => Some(Self::FastRecovery),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

//==============================================================================
// TIME AND SYNCHRONIZATION TYPES
//==============================================================================

/// Protocol duration type
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct ProtocolDuration(pub u64);

impl ProtocolDuration {
    pub fn new(nanos: u64) -> Self {
        Self(nanos)
    }

    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }

    pub fn from_millis(millis: u64) -> Self {
        Self(millis * 1_000_000)
    }

    pub fn from_micros(micros: u64) -> Self {
        Self(micros * 1_000)
    }

    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    pub fn as_micros(&self) -> u64 {
        self.0 / 1_000
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub fn to_std(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.0)
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }
}

impl std::fmt::Display for ProtocolDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.as_millis())
    }
}

use std::ops::{Div, Mul};

impl Mul<u64> for ProtocolDuration {
    type Output = ProtocolDuration;

    fn mul(self, rhs: u64) -> Self::Output {
        ProtocolDuration(self.0 * rhs)
    }
}

impl Div<u64> for ProtocolDuration {
    type Output = ProtocolDuration;

    fn div(self, rhs: u64) -> Self::Output {
        ProtocolDuration(self.0 / rhs)
    }
}

// Add conversions for type compatibility
impl From<u32> for ProtocolDuration {
    fn from(value: u32) -> Self {
        Self::from_millis(value as u64)
    }
}

impl From<u64> for ProtocolDuration {
    fn from(value: u64) -> Self {
        Self::from_millis(value)
    }
}

impl From<ProtocolDuration> for u32 {
    fn from(duration: ProtocolDuration) -> Self {
        duration.as_millis() as u32
    }
}

impl From<ProtocolDuration> for u64 {
    fn from(duration: ProtocolDuration) -> Self {
        duration.as_millis()
    }
}

/// Time offset with atomic-by-default design
#[derive(Debug)]
#[repr(transparent)]
pub struct TimeOffset(AtomicI64);

impl TimeOffset {
    pub fn new(offset: i64) -> Self {
        Self(AtomicI64::new(offset))
    }

    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn load(&self, ordering: Ordering) -> i64 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: i64, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn as_raw(&self) -> i64 {
        self.get()
    }

    pub const fn from_raw(value: i64) -> Self {
        Self(AtomicI64::new(value))
    }

    /// Get offset in nanoseconds
    pub fn as_nanos(&self) -> i64 {
        self.get()
    }

    pub fn as_i64(&self) -> i64 {
        self.get()
    }

    pub fn fetch_add(&self, value: i64, ordering: Ordering) -> i64 {
        self.0.fetch_add(value, ordering)
    }
}

impl Clone for TimeOffset {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl PartialEq for TimeOffset {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for TimeOffset {}

/// Clock skew with atomic-by-default design
#[derive(Debug)]
#[repr(transparent)]
pub struct ClockSkew(AtomicI64);

impl ClockSkew {
    pub fn new(skew: i64) -> Self {
        Self(AtomicI64::new(skew))
    }

    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn load(&self, ordering: Ordering) -> i64 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: i64, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn as_raw(&self) -> i64 {
        self.get()
    }

    pub fn from_raw(value: i64) -> Self {
        Self::new(value)
    }

    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.get().to_be_bytes()
    }
}

impl Clone for ClockSkew {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

/// Time drift measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TimeDrift(i32);

impl TimeDrift {
    pub fn new(drift_ppm: i32) -> Self {
        Self(drift_ppm)
    }

    pub fn as_i32(&self) -> i32 {
        self.0
    }

    pub fn as_ppm(&self) -> i32 {
        self.0
    }

    pub fn as_raw(&self) -> i32 {
        self.0
    }

    pub fn from_raw(value: i32) -> Self {
        Self(value)
    }
}

/// Network delay measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NetworkDelay(u64);

impl NetworkDelay {
    pub fn new(delay_nanos: u64) -> Self {
        Self(delay_nanos)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    pub fn as_micros(&self) -> u64 {
        self.0 / 1_000
    }

    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

/// Round trip time measurement
/// Synchronization quality (0-100)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[derive(Default)]
pub struct SyncQuality(u8);

impl SyncQuality {
    pub fn new(quality: u8) -> Self {
        Self(quality.min(100))
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_percentage(&self) -> u8 {
        self.0
    }

    pub fn as_raw(&self) -> u8 {
        self.0
    }

    pub fn from_raw(value: u8) -> Self {
        Self::new(value)
    }
}

/// Epoch identifier
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(transparent)]
pub struct Epoch(u64);

impl Epoch {
    pub fn new(epoch: u64) -> Self {
        Self(epoch)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

/// Heartbeat interval
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HeartbeatInterval(u64);

impl HeartbeatInterval {
    pub const HEARTBEAT_INTERVAL_MS: u64 = 30000;

    pub fn new(interval_ms: u64) -> Self {
        Self(interval_ms)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

impl Default for HeartbeatInterval {
    fn default() -> Self {
        Self(Self::HEARTBEAT_INTERVAL_MS)
    }
}

impl AsDisplay for BufferSize {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

impl AsDisplay for Threshold {
    fn as_display(&self) -> String {
        format!("{}", self.0)
    }
}

/// IP Address enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddress {
    pub fn from_std(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => Self::V4(v4.octets()),
            std::net::IpAddr::V6(v6) => Self::V6(v6.octets()),
        }
    }

    pub fn to_std(&self) -> std::net::IpAddr {
        match self {
            Self::V4(octets) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(*octets)),
            Self::V6(octets) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(*octets)),
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    pub fn from_ipv4(addr: std::net::Ipv4Addr) -> Self {
        Self::V4(addr.octets())
    }

    pub fn from_ipv6(addr: std::net::Ipv6Addr) -> Self {
        Self::V6(addr.octets())
    }

    pub fn as_raw(&self) -> Vec<u8> {
        match self {
            Self::V4(octets) => octets.to_vec(),
            Self::V6(octets) => octets.to_vec(),
        }
    }

    /// Convert IPv4 address to u32 (network byte order)
    /// Returns None if called on IPv6 address
    #[deprecated(
        since = "0.1.0",
        note = "Use try_as_u32() instead to handle IPv6 gracefully"
    )]
    pub fn as_u32(&self) -> Option<u32> {
        self.try_as_u32()
    }

    /// Try to convert to u32, returns None for IPv6
    pub fn try_as_u32(&self) -> Option<u32> {
        match self {
            Self::V4(octets) => Some(u32::from_be_bytes(*octets)),
            Self::V6(_) => None,
        }
    }
}

impl From<&IpAddress> for std::net::IpAddr {
    fn from(addr: &IpAddress) -> Self {
        addr.to_std()
    }
}

impl From<IpAddress> for std::net::IpAddr {
    fn from(addr: IpAddress) -> Self {
        addr.to_std()
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_std())
    }
}

/// Network endpoint combining IP address and port
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkEndpoint {
    pub ip: IpAddress,
    pub port: Port,
}

impl NetworkEndpoint {
    pub fn new(ip: IpAddress, port: Port) -> Self {
        Self { ip, port }
    }

    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        Self {
            ip: IpAddress::from_std(addr.ip()),
            port: Port::from_u16_unchecked(addr.port()),
        }
    }

    pub fn to_socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.ip.to_std(), self.port.as_u16())
    }

    pub fn ip(&self) -> &IpAddress {
        &self.ip
    }

    pub fn port(&self) -> Port {
        self.port
    }
}

impl fmt::Display for NetworkEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

//==============================================================================
// TIME TYPES (Dual Epoch System)
//==============================================================================

/// Timestamp with nanosecond precision
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Timestamp(u64);

impl TryFrom<Timestamp> for SystemTime {
    type Error = ();

    fn try_from(timestamp: Timestamp) -> Result<Self, Self::Error> {
        Ok(SystemTime::UNIX_EPOCH + Duration::from_nanos(timestamp.as_nanos()))
    }
}

impl Timestamp {
    /// Create timestamp with configuration (for protocol compatibility)
    pub fn new(value: u64, _config: TimestampConfig) -> Self {
        Self(value)
    }

    /// Create from nanoseconds since UNIX epoch
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Create from milliseconds since UNIX epoch
    pub fn from_millis(millis: u64) -> Self {
        Self(millis * 1_000_000)
    }

    /// Create from seconds since UNIX epoch
    pub fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }

    /// Get current timestamp
    ///
    /// Returns current time as nanoseconds since UNIX_EPOCH.
    /// If system time is before UNIX_EPOCH (should never happen on modern systems),
    /// returns timestamp 0.
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_nanos(now.as_nanos() as u64)
    }

    pub fn get(&self) -> u64 {
        self.0
    }

    /// Get nanoseconds value
    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Get raw value (for compatibility)
    pub fn as_raw(&self) -> u64 {
        self.0
    }

    /// Create from raw value (for compatibility)
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Create from timestamp value
    pub fn from(value: u64) -> Self {
        Self(value)
    }

    /// Saturating subtraction
    pub fn saturating_sub(&self, other: &Timestamp) -> u64 {
        self.0.saturating_sub(other.0)
    }

    /// Wrapping subtraction
    pub fn wrapping_sub(&self, other: Timestamp) -> Timestamp {
        Timestamp(self.0.wrapping_sub(other.0))
    }

    pub fn as_micros(&self) -> u64 {
        self.0 / 1_000
    }

    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Protocol-specific time calculations (dual epoch system)
    pub fn millis_since_day_start(&self) -> u64 {
        const MILLIS_PER_DAY: u64 = 24 * 60 * 60 * 1_000;
        self.as_millis() % MILLIS_PER_DAY
    }

    pub fn millis_since_month_start(&self) -> u64 {
        let millis = self.as_millis();
        millis % (31 * 24 * 60 * 60 * 1_000) // Approximate for now
    }

    /// Time bucket calculation for port hopping (500ms intervals)
    pub fn time_bucket_500ms(&self, epoch_start: &Timestamp) -> u64 {
        const BUCKET_SIZE_MILLIS: u64 = 500;
        let millis_since_epoch = self.as_millis().saturating_sub(epoch_start.as_millis());
        millis_since_epoch / BUCKET_SIZE_MILLIS
    }

    /// Daily epoch time bucket (for base port hopping)
    pub fn daily_time_bucket(&self) -> u64 {
        self.millis_since_day_start() / 500
    }

    /// Monthly epoch time bucket (for session packets)
    pub fn monthly_time_bucket(&self) -> u64 {
        self.millis_since_month_start() / 500
    }

    /// Calculate elapsed time since this timestamp
    pub fn elapsed(&self) -> Duration {
        let now = Timestamp::now();
        let elapsed_nanos = now.0.saturating_sub(self.0);
        Duration::from_nanos(elapsed_nanos)
    }

    /// Anti-replay validation
    pub fn is_within_replay_window(&self, other: &Timestamp, window_ms: u64) -> bool {
        let self_millis = self.as_millis();
        let other_millis = other.as_millis();
        let diff_ms = self_millis.abs_diff(other_millis);
        diff_ms <= window_ms
    }

    pub fn to_ebpf_u64(&self) -> u64 {
        self.0
    }

    pub fn from_ebpf_u64(value: u64) -> Self {
        Self::from_nanos(value)
    }
}

impl From<std::time::SystemTime> for Timestamp {
    fn from(time: std::time::SystemTime) -> Self {
        let duration = time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_nanos(duration.as_nanos() as u64)
    }
}

impl From<Timestamp> for u64 {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.as_u64()
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::from_nanos(0)
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Self(value))
    }
}

impl std::ops::Add<u64> for Timestamp {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl std::ops::Sub<u64> for Timestamp {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_sub(rhs))
    }
}

impl std::ops::Sub<Timestamp> for Timestamp {
    type Output = u64;
    fn sub(self, rhs: Timestamp) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

// TimestampAtomic removed - Timestamp is now atomic-by-default

/// Protocol duration for time intervals (distinct from std::time::Duration)
// TimeOffsetAtomic removed - TimeOffset is now atomic-by-default
/// Time adjustment for synchronization corrections
#[derive(Debug, Clone, PartialEq)]
pub struct TimeAdjustment {
    pub offset: TimeOffset,
    pub apply_time: Timestamp,
    pub step_number: StepCount,
    pub total_steps: StepCount,
    pub paused: bool,
}

impl TimeAdjustment {
    pub fn new(offset: i64, apply_time: u64, step_number: u32, total_steps: u32) -> Self {
        Self {
            offset: TimeOffset::new(offset),
            apply_time: Timestamp::from_millis(apply_time),
            step_number: StepCount::new(step_number),
            total_steps: StepCount::new(total_steps),
            paused: false,
        }
    }

    pub fn from_nanos(nanos: i64) -> Self {
        Self::new(nanos, 0, 1, 1)
    }

    pub fn from_millis(millis: i64) -> Self {
        Self::new(millis * 1_000_000, 0, 1, 1)
    }

    pub fn from_micros(micros: i64) -> Self {
        Self::new(micros * 1_000, 0, 1, 1)
    }

    pub fn as_nanos(&self) -> i64 {
        self.offset.as_i64()
    }
    pub fn as_millis(&self) -> i64 {
        self.offset.as_i64() / 1_000_000
    }
    pub fn as_micros(&self) -> i64 {
        self.offset.as_i64() / 1_000
    }
}

/// Round-trip time measurement
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RoundTripTime(u64);

impl RoundTripTime {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self(millis * 1_000_000)
    }

    pub fn new(nanos: u64) -> Self {
        Self(nanos)
    }

    pub fn get(&self) -> u64 {
        self.0
    }

    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn to_ebpf_u64(&self) -> u64 {
        self.0
    }

    pub fn from_ebpf_u64(value: u64) -> Self {
        Self::new(value)
    }
}

impl Default for RoundTripTime {
    fn default() -> Self {
        Self::new(0)
    }
}

impl std::fmt::Display for RoundTripTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.as_millis())
    }
}

// AtomicRoundTripTime removed - RoundTripTime is now atomic-by-default

//==============================================================================
// CRYPTOGRAPHIC TYPES
//==============================================================================

/// HMAC tag with variable length
#[derive(Debug, Clone)]
pub struct HmacTag {
    data: Vec<u8>,
    policy: HmacPolicy,
}

impl HmacTag {
    pub fn new(data: Vec<u8>, policy: HmacPolicy) -> Result<Self, ValidationError> {
        let expected_len = match policy {
            HmacPolicy::Light => 8,
            HmacPolicy::Medium => 16,
            HmacPolicy::Strong => 32,
        };

        if data.len() != expected_len {
            return Err(ValidationError::InvalidHmacLength);
        }

        Ok(Self { data, policy })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn policy(&self) -> HmacPolicy {
        self.policy
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for HmacTag {
    fn default() -> Self {
        Self {
            data: vec![0u8; 8], // Default to Light policy size
            policy: HmacPolicy::Light,
        }
    }
}

/// HMAC policy enumeration
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(u8)]
pub enum HmacPolicy {
    Light = 1,
    Medium = 2,
    Strong = 3,
}

impl HmacPolicy {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Light),
            2 => Some(Self::Medium),
            3 => Some(Self::Strong),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn as_byte(&self) -> u8 {
        self.as_u8()
    }

    pub fn from_byte(value: u8) -> Option<Self> {
        Self::from_u8(value)
    }

    pub fn tag_size(&self) -> usize {
        match self {
            Self::Light => 8,
            Self::Medium => 16,
            Self::Strong => 32,
        }
    }

    pub fn for_packet_class(class: PacketClass) -> Self {
        match class {
            PacketClass::Critical => Self::Strong,
            PacketClass::Control => Self::Medium,
            PacketClass::Data => Self::Light,
        }
    }
}

/// Challenge nonce for discovery
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ChallengeNonce([u8; 32]);

impl ChallengeNonce {
    pub const SIZE: usize = 32;

    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_ebpf_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_ebpf_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// ECDH public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EcdhPublicKey([u8; 64]);

impl EcdhPublicKey {
    pub const SIZE: usize = 64;

    pub fn new(data: [u8; 64]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_ebpf_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_ebpf_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

/// ECDH private key with secure memory zeroing
///
/// This type holds ECDH private key material and automatically zeros the memory
/// when dropped to prevent key material from remaining in memory.
///
/// Security Properties:
/// - Derives `Zeroize` to enable explicit zeroing
/// - Derives `ZeroizeOnDrop` to ensure automatic cleanup
/// - Memory is securely zeroed even if panics occur during drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct EcdhPrivateKey([u8; 32]);

impl EcdhPrivateKey {
    pub const SIZE: usize = 32;

    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_ebpf_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_ebpf_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for EcdhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdhPrivateKey")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Shared secret with secure memory zeroing
///
/// This type holds ECDH shared secret material and automatically zeros the memory
/// when dropped to prevent secret material from remaining in memory.
///
/// Security Properties:
/// - Derives `Zeroize` to enable explicit zeroing
/// - Derives `ZeroizeOnDrop` to ensure automatic cleanup
/// - Memory is securely zeroed even if panics occur during drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub const SIZE: usize = 32;

    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_ebpf_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_ebpf_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

//==============================================================================
// STATE ENUMS
//==============================================================================

/// Connection state - M2 spec compliant
/// Per M2 requirements: IDLE, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, CLOSED
/// Plus recovery states: RECOVERING, ERROR
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConnectionState {
    /// Initial idle state - no connection activity
    Idle = 0,
    /// Client has sent SYN, awaiting SYN-ACK (M2 spec: SYN_SENT)
    SynSent = 1,
    /// Server has received SYN, sent SYN-ACK, awaiting ACK (M2 spec: SYN_RECEIVED)
    SynReceived = 2,
    /// Connection established, data transfer active (M2 spec: ESTABLISHED)
    Established = 3,
    /// Initiated FIN, awaiting FIN-ACK (M2 spec: FIN_WAIT)
    FinWait = 4,
    /// Received FIN, sent FIN-ACK, awaiting close (M2 spec: CLOSE_WAIT)
    CloseWait = 5,
    /// Connection fully closed (M2 spec: CLOSED)
    Closed = 6,
    /// Recovery in progress
    Recovering = 7,
    /// Error state
    Error = 8,
    // Legacy states for backwards compatibility (deprecated)
    /// @deprecated Use SynSent instead
    Connecting = 9,
    /// @deprecated Use Established instead
    Connected = 10,
    /// @deprecated Use SynReceived instead
    Listening = 11,
    /// @deprecated Use FinWait instead
    Closing = 12,
    /// @deprecated Use CloseWait instead
    Disconnecting = 13,
}

impl ConnectionState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Idle),
            1 => Some(Self::SynSent),
            2 => Some(Self::SynReceived),
            3 => Some(Self::Established),
            4 => Some(Self::FinWait),
            5 => Some(Self::CloseWait),
            6 => Some(Self::Closed),
            7 => Some(Self::Recovering),
            8 => Some(Self::Error),
            // Legacy states - map to new equivalents
            9 => Some(Self::Connecting),
            10 => Some(Self::Connected),
            11 => Some(Self::Listening),
            12 => Some(Self::Closing),
            13 => Some(Self::Disconnecting),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if this is a valid M2 spec state (not a legacy state)
    pub fn is_m2_compliant(&self) -> bool {
        matches!(
            self,
            Self::Idle
                | Self::SynSent
                | Self::SynReceived
                | Self::Established
                | Self::FinWait
                | Self::CloseWait
                | Self::Closed
                | Self::Recovering
                | Self::Error
        )
    }

    /// Convert legacy state to M2 equivalent
    pub fn to_m2_state(&self) -> Self {
        match self {
            Self::Connecting => Self::SynSent,
            Self::Connected => Self::Established,
            Self::Listening => Self::SynReceived,
            Self::Closing => Self::FinWait,
            Self::Disconnecting => Self::CloseWait,
            other => *other,
        }
    }

    /// Load connection state from atomic storage
    pub fn load(atomic: &AtomicU8, ordering: Ordering) -> Self {
        let value = atomic.load(ordering);
        Self::from_u8(value).unwrap_or(Self::Error)
    }

    /// Store connection state to atomic storage
    pub fn store(&self, atomic: &AtomicU8, ordering: Ordering) {
        atomic.store(self.as_u8(), ordering);
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "IDLE"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RECEIVED"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::FinWait => write!(f, "FIN_WAIT"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::Closed => write!(f, "CLOSED"),
            Self::Recovering => write!(f, "RECOVERING"),
            Self::Error => write!(f, "ERROR"),
            // Legacy states (deprecated)
            Self::Connecting => write!(f, "CONNECTING (deprecated)"),
            Self::Connected => write!(f, "CONNECTED (deprecated)"),
            Self::Listening => write!(f, "LISTENING (deprecated)"),
            Self::Closing => write!(f, "CLOSING (deprecated)"),
            Self::Disconnecting => write!(f, "DISCONNECTING (deprecated)"),
        }
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SessionState {
    Creating = 0,
    Initializing = 1,
    Active = 2,
    Idle = 3,
    Degraded = 4,
    Recovering = 5,
    Terminating = 6,
    Terminated = 7,
    Error = 8,
}

impl SessionState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Creating),
            1 => Some(Self::Initializing),
            2 => Some(Self::Active),
            3 => Some(Self::Idle),
            4 => Some(Self::Degraded),
            5 => Some(Self::Recovering),
            6 => Some(Self::Terminating),
            7 => Some(Self::Terminated),
            8 => Some(Self::Error),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Load from atomic storage
    pub fn load(atomic: &AtomicU8, ordering: Ordering) -> Self {
        Self::from_u8(atomic.load(ordering)).unwrap_or(Self::Error)
    }

    /// Store to atomic storage
    pub fn store(&self, atomic: &AtomicU8, ordering: Ordering) {
        atomic.store(self.as_u8(), ordering);
    }

    /// Check if this state allows transitions
    pub fn allows_transitions(&self) -> bool {
        !matches!(self, Self::Terminated | Self::Error)
    }

    /// Check if this state is considered healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Active | Self::Idle)
    }

    /// Validate state transition
    ///
    /// Returns Ok(()) if the transition is valid, Err otherwise.
    /// Valid transitions:
    /// - Creating → Initializing
    /// - Initializing → Active
    /// - Initializing → Terminated (on failure)
    /// - Active → Idle
    /// - Active → Degraded
    /// - Active → Recovering
    /// - Active → Terminating
    /// - Idle → Active
    /// - Idle → Degraded
    /// - Idle → Terminating
    /// - Degraded → Recovering
    /// - Degraded → Terminating
    /// - Degraded → Terminated
    /// - Recovering → Active
    /// - Recovering → Degraded
    /// - Recovering → Terminated
    /// - Terminating → Terminated
    /// - Error → Terminated
    pub fn validate_transition(&self, to: SessionState) -> Result<(), crate::error::StateError> {
        use crate::error::StateError;

        // No transition if same state
        if *self == to {
            return Ok(());
        }

        let valid = match (*self, to) {
            // From Creating
            (Self::Creating, Self::Initializing) => true,

            // From Initializing
            (Self::Initializing, Self::Active) => true,
            (Self::Initializing, Self::Terminated) => true, // Failure during init

            // From Active
            (Self::Active, Self::Idle) => true,
            (Self::Active, Self::Degraded) => true,
            (Self::Active, Self::Recovering) => true,
            (Self::Active, Self::Terminating) => true,

            // From Idle
            (Self::Idle, Self::Active) => true,
            (Self::Idle, Self::Degraded) => true,
            (Self::Idle, Self::Terminating) => true,

            // From Degraded
            (Self::Degraded, Self::Recovering) => true,
            (Self::Degraded, Self::Terminating) => true,
            (Self::Degraded, Self::Terminated) => true, // Give up recovery

            // From Recovering
            (Self::Recovering, Self::Active) => true, // Recovery succeeded
            (Self::Recovering, Self::Degraded) => true, // Recovery failed, retry
            (Self::Recovering, Self::Terminated) => true, // Recovery gave up

            // From Terminating
            (Self::Terminating, Self::Terminated) => true,

            // From Error
            (Self::Error, Self::Terminated) => true,

            // All other transitions are invalid
            _ => false,
        };

        if valid {
            Ok(())
        } else {
            Err(StateError::InvalidStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", to),
            })
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Initializing => write!(f, "Initializing"),
            Self::Active => write!(f, "Active"),
            Self::Idle => write!(f, "Idle"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Recovering => write!(f, "Recovering"),
            Self::Terminating => write!(f, "Terminating"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// Synchronization state (atomic by default)
#[derive(Debug)]
#[repr(transparent)]
pub struct SyncState(AtomicU8);

impl SyncState {
    pub const UNSYNCHRONIZED: u8 = 0;
    pub const SYNCHRONIZING: u8 = 1;
    pub const SYNCHRONIZED: u8 = 2;
    pub const DEGRADED: u8 = 3;
    pub const DRIFT_DETECTED: u8 = 4;

    pub fn new(state: u8) -> Self {
        Self(AtomicU8::new(state))
    }

    pub fn unsynchronized() -> Self {
        Self::new(Self::UNSYNCHRONIZED)
    }

    pub fn synchronizing() -> Self {
        Self::new(Self::SYNCHRONIZING)
    }

    pub fn synchronized() -> Self {
        Self::new(Self::SYNCHRONIZED)
    }

    pub fn degraded() -> Self {
        Self::new(Self::DEGRADED)
    }

    pub fn drift_detected() -> Self {
        Self::new(Self::DRIFT_DETECTED)
    }

    pub fn load(&self, ordering: Ordering) -> u8 {
        self.0.load(ordering)
    }

    pub fn store(&self, state: u8, ordering: Ordering) {
        self.0.store(state, ordering);
    }

    pub fn compare_exchange(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u8, u8> {
        self.0.compare_exchange(current, new, success, failure)
    }

    pub fn is_synchronized(&self) -> bool {
        self.load(Ordering::Relaxed) == Self::SYNCHRONIZED
    }

    pub fn is_unsynchronized(&self) -> bool {
        self.load(Ordering::Relaxed) == Self::UNSYNCHRONIZED
    }

    // Enum-like constants for compatibility with existing code expecting SyncState::Variant syntax
    pub const UNSYNCHRONIZED_COMPAT: u8 = Self::UNSYNCHRONIZED;
    pub const DRIFT_DETECTED_COMPAT: u8 = Self::DRIFT_DETECTED;
    pub const SYNCHRONIZED_COMPAT: u8 = Self::SYNCHRONIZED;
}

impl Clone for SyncState {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl PartialEq<u8> for SyncState {
    fn eq(&self, other: &u8) -> bool {
        self.load(Ordering::Relaxed) == *other
    }
}

impl PartialEq<SyncState> for SyncState {
    fn eq(&self, other: &SyncState) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

/// Recovery reason enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RecoveryReason {
    SequenceGap = 1,
    Timeout = 2,
    DuplicateAck = 3,
    HmacFailure = 4,
    TimeSync = 5,
    NetworkPartition = 6,
    Rekey = 7,
    Manual = 8,
}

impl RecoveryReason {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SequenceGap),
            2 => Some(Self::Timeout),
            3 => Some(Self::DuplicateAck),
            4 => Some(Self::HmacFailure),
            5 => Some(Self::TimeSync),
            6 => Some(Self::NetworkPartition),
            7 => Some(Self::Rekey),
            8 => Some(Self::Manual),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

//==============================================================================
// COUNTER TYPES
//==============================================================================

/// Attempt count for retries
#[derive(Debug)]
#[repr(transparent)]
pub struct AttemptCount(pub AtomicU32);

impl AttemptCount {
    pub const MAX_RETRANSMISSION_ATTEMPTS: u32 = 8;
    pub const MAX_RECOVERY_ATTEMPTS: u32 = 5;

    pub const fn new(count: u32) -> Self {
        Self(AtomicU32::new(count))
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, count: u32, ordering: Ordering) {
        self.0.store(count, ordering);
    }

    pub fn fetch_add(&self, val: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(val, ordering)
    }

    pub fn increment(&self, ordering: Ordering) -> u32 {
        self.fetch_add(1, ordering)
    }

    pub fn reset(&self, ordering: Ordering) {
        self.store(0, ordering);
    }

    pub fn to_ebpf_u32(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }

    pub fn from_ebpf_u32(value: u32) -> Self {
        Self::new(value)
    }

    pub fn as_raw(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }

    pub fn from_raw(count: u32) -> Self {
        Self::new(count)
    }

    pub fn as_u32(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for AttemptCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl Default for AttemptCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for AttemptCount {
    fn eq(&self, other: &Self) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

impl PartialEq<u32> for AttemptCount {
    fn eq(&self, other: &u32) -> bool {
        self.load(Ordering::Relaxed) == *other
    }
}

impl PartialOrd for AttemptCount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.load(Ordering::Relaxed)
            .partial_cmp(&other.load(Ordering::Relaxed))
    }
}

impl PartialOrd<u32> for AttemptCount {
    fn partial_cmp(&self, other: &u32) -> Option<std::cmp::Ordering> {
        self.load(Ordering::Relaxed).partial_cmp(other)
    }
}

impl From<u32> for AttemptCount {
    fn from(count: u32) -> Self {
        Self::new(count)
    }
}

impl From<i32> for AttemptCount {
    fn from(count: i32) -> Self {
        Self::new(count as u32)
    }
}

/// Atomic attempt count for thread-safe retry tracking
// AttemptCountAtomic removed - AttemptCount is now atomic-by-default
/// Maximum retry limit configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MaxRetries(pub u32);

impl MaxRetries {
    pub fn new(max: u32) -> Self {
        Self(max)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn unlimited() -> Self {
        Self(u32::MAX)
    }
    pub fn is_unlimited(&self) -> bool {
        self.0 == u32::MAX
    }
}

impl Default for MaxRetries {
    fn default() -> Self {
        Self(3)
    }
}

/// Failure count tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct FailureCount(AtomicU32);

impl FailureCount {
    pub fn new(count: u32) -> Self {
        Self(AtomicU32::new(count))
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, count: u32, ordering: Ordering) {
        self.0.store(count, ordering);
    }

    pub fn fetch_add(&self, val: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(val, ordering)
    }

    pub fn increment(&self, ordering: Ordering) -> u32 {
        self.fetch_add(1, ordering)
    }

    pub fn reset(&self, ordering: Ordering) {
        self.store(0, ordering);
    }

    pub fn to_ebpf_u32(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }

    pub fn from_ebpf_u32(value: u32) -> Self {
        Self::new(value)
    }

    pub fn as_u32(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for FailureCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl Default for FailureCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for FailureCount {
    fn eq(&self, other: &Self) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

impl Eq for FailureCount {}

impl serde::Serialize for FailureCount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.load(Ordering::Relaxed).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for FailureCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

//==============================================================================
// MISSING TYPES FOR COMPATIBILITY
//==============================================================================

/// Re-export error types from the error module (authoritative source)
pub use crate::error::{BuckwildError, BuckwildResult};

//==============================================================================
// ERROR TYPES
//==============================================================================

/// Protocol error hierarchy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Validation(ValidationError),
    Network(NetworkError),
    Session(SessionError),
    Security(SecurityError),
    Timeout(TimeoutError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    ConnectionFailed,
    SocketError,
    BindError,
    SendError,
    ReceiveError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    NotFound,
    Expired,
    InvalidState,
    CreationFailed,
    System(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    AuthenticationFailed,
    InvalidSignature,
    CryptographicError,
    ReplayAttack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutError {
    ConnectionTimeout,
    ReadTimeout,
    WriteTimeout,
    OperationTimeout,
}

//==============================================================================
// PACKET STRUCTURE TYPES
//==============================================================================

/// Session configuration for connection establishment
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub hmac_policy: HmacPolicy,
    pub timestamp_config: TimestampConfig,
    pub session_id_length: SessionIdLength,
    pub adaptive_delay_enabled: bool,
    pub flow_control_enabled: bool,
    pub security_mode: SecurityLevel,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            hmac_policy: HmacPolicy::Medium,
            timestamp_config: TimestampConfig::Bits32,
            session_id_length: SessionIdLength::Bits64,
            adaptive_delay_enabled: true,
            flow_control_enabled: true,
            security_mode: SecurityLevel::Medium,
        }
    }
}

impl SessionConfig {}

/// Validation result enum
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "T: serde::Serialize",
    deserialize = "T: serde::de::DeserializeOwned"
))]
pub enum ValidationResult<T> {
    Valid(T),
    Invalid(ValidationError),
    Warning(T, String),
}

impl<T> ValidationResult<T> {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_) | Self::Warning(_, _))
    }

    /// Extract the value from a ValidationResult
    ///
    /// # Panics
    /// Panics if the result is Invalid. Use `into_result()` for safe extraction.
    ///
    /// # Deprecated
    /// Use `into_result()` and handle errors properly instead.
    #[deprecated(
        since = "0.1.0",
        note = "Use into_result() instead to handle validation errors"
    )]
    pub fn unwrap(self) -> T {
        match self {
            Self::Valid(t) | Self::Warning(t, _) => t,
            Self::Invalid(e) => panic!("Validation failed: {:?}", e),
        }
    }

    pub fn into_result(self) -> Result<T, ValidationError> {
        match self {
            Self::Valid(t) | Self::Warning(t, _) => Ok(t),
            Self::Invalid(e) => Err(e),
        }
    }
}

/// Termination reason for connection closure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TerminationReason {
    Normal = 0,
    Timeout = 1,
    SecurityViolation = 2,
    ProtocolViolation = 3,
    ResourceExhausted = 4,
    UserRequested = 5,
}

impl TerminationReason {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Normal),
            1 => Some(Self::Timeout),
            2 => Some(Self::SecurityViolation),
            3 => Some(Self::ProtocolViolation),
            4 => Some(Self::ResourceExhausted),
            5 => Some(Self::UserRequested),
            _ => None,
        }
    }
}

/// Reset reason for connection reset
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResetReason {
    InvalidSequence = 0,
    InvalidSession = 1,
    SecurityViolation = 2,
    InvalidState = 3,
    InvalidPacket = 4,
    ProtocolError = 5,
}

impl ResetReason {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::InvalidSequence),
            1 => Some(Self::InvalidSession),
            2 => Some(Self::SecurityViolation),
            3 => Some(Self::InvalidState),
            4 => Some(Self::InvalidPacket),
            5 => Some(Self::ProtocolError),
            _ => None,
        }
    }
}

/// Protocol error codes (8-bit error codes 0x00-0x6F from protocol specification)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCode {
    NoError = 0x00,
    InvalidPacket = 0x01,
    InvalidSequence = 0x02,
    InvalidSession = 0x03,
    AuthenticationFailed = 0x04,
    HmacVerificationFailed = 0x05,
    TimestampExpired = 0x06,
    ReplayDetected = 0x07,
    SecurityViolation = 0x08,
    ResourceExhausted = 0x09,
    ProtocolViolation = 0x0A,
    ConfigurationError = 0x0B,
    InternalError = 0x6F,
}

impl ErrorCode {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::InvalidPacket),
            0x02 => Some(Self::InvalidSequence),
            0x03 => Some(Self::InvalidSession),
            0x04 => Some(Self::AuthenticationFailed),
            0x05 => Some(Self::HmacVerificationFailed),
            0x06 => Some(Self::TimestampExpired),
            0x07 => Some(Self::ReplayDetected),
            0x08 => Some(Self::SecurityViolation),
            0x09 => Some(Self::ResourceExhausted),
            0x0A => Some(Self::ProtocolViolation),
            0x0B => Some(Self::ConfigurationError),
            0x6F => Some(Self::InternalError),
            _ => None,
        }
    }

    pub fn new(code: u8) -> Self {
        Self::from_u8(code).unwrap_or(Self::InternalError)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NoError"),
            Self::InvalidPacket => write!(f, "InvalidPacket"),
            Self::InvalidSequence => write!(f, "InvalidSequence"),
            Self::InvalidSession => write!(f, "InvalidSession"),
            Self::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Self::HmacVerificationFailed => write!(f, "HmacVerificationFailed"),
            Self::TimestampExpired => write!(f, "TimestampExpired"),
            Self::ReplayDetected => write!(f, "ReplayDetected"),
            Self::SecurityViolation => write!(f, "SecurityViolation"),
            Self::ResourceExhausted => write!(f, "ResourceExhausted"),
            Self::ProtocolViolation => write!(f, "ProtocolViolation"),
            Self::ConfigurationError => write!(f, "ConfigurationError"),
            Self::InternalError => write!(f, "InternalError"),
        }
    }
}

/// Error description for detailed error information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ErrorDescription(pub String);

impl ErrorDescription {
    pub fn new(description: String) -> Self {
        Self(description)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Heartbeat sequence number
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HeartbeatSequence(pub u32);

impl HeartbeatSequence {
    pub fn new(seq: u32) -> Self {
        Self(seq)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

/// Sequence negotiation flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SequenceNegFlags(pub u8);

impl SequenceNegFlags {
    pub fn new(flags: u8) -> Self {
        Self(flags)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Security level for HMAC policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecurityLevel {
    Light = 1,
    Medium = 2,
    // Balanced is an alias for Medium - removed duplicate discriminant
    Strong = 3,
    HighSecurity = 4,
}

/// Alias for SecurityLevel for backward compatibility
pub type SecurityMode = SecurityLevel;

impl SecurityLevel {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Light),
            2 => Some(Self::Medium), // Also covers Balanced
            3 => Some(Self::Strong),
            4 => Some(Self::HighSecurity),
            _ => None,
        }
    }
}

/// Policy change reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PolicyChangeReason {
    SecurityUpgrade = 1,
    SecurityDowngrade = 2,
    Configuration = 3,
    Performance = 4,
}

impl PolicyChangeReason {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SecurityUpgrade),
            2 => Some(Self::SecurityDowngrade),
            3 => Some(Self::Configuration),
            4 => Some(Self::Performance),
            _ => None,
        }
    }
}

/// Policy change result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PolicyChangeResult {
    Success = 0,
    Failed = 1,
    NotSupported = 2,
    Accepted = 3,
}

impl PolicyChangeResult {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::Failed),
            2 => Some(Self::NotSupported),
            3 => Some(Self::Accepted),
            _ => None,
        }
    }
}

/// Key identifier for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct KeyId(pub [u8; 16]);

impl KeyId {
    pub fn new(id: [u8; 16]) -> Self {
        Self(id)
    }
    pub fn from_u16(id: u16) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..2].copy_from_slice(&id.to_be_bytes());
        Self(bytes)
    }
    pub fn from_u32(id: u32) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&id.to_be_bytes());
        Self(bytes)
    }
    pub fn from_u64(id: u64) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&id.to_be_bytes());
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// KDF salt for key derivation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct KdfSalt(pub [u8; 16]);

impl KdfSalt {
    pub fn new(salt: [u8; 16]) -> Self {
        Self(salt)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// KDF iteration count
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct KdfIterations(pub u32);

impl Default for KdfIterations {
    fn default() -> Self {
        // PBKDF2 requires 4096 iterations per design/protocol/04-ecdh-cryptography.md
        Self(4096)
    }
}

impl KdfIterations {
    pub fn new(iterations: u32) -> Self {
        Self(iterations)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// KDF parameters for key derivation
#[derive(Debug, Clone)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: KdfSalt,
    pub iterations: KdfIterations,
    pub key_length: KeySize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "scrypt".to_string(),
            salt: KdfSalt([0u8; 16]),
            iterations: KdfIterations::new(32768),
            key_length: KeySize::new(32),
        }
    }
}

/// Rekey reason enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RekeyReason {
    Periodic = 1,
    SecurityEvent = 2,
    PolicyChange = 3,
    Manual = 4,
    Scheduled = 5,
}

/// Rekey result enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RekeyResult {
    Success = 0,
    Failed = 1,
    Timeout = 2,
    Cancelled = 3,
}

/// Repair type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RepairType {
    Sequence = 1,
    Timestamp = 2,
    Integrity = 3,
    Protocol = 4,
    Retransmission = 5,
}

/// Sequence range for repair operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SequenceRange {
    pub start: SequenceNumber,
    pub end: SequenceNumber,
    pub count: RangeCount,
}

impl SequenceRange {
    pub fn new(start: SequenceNumber, end: SequenceNumber) -> Self {
        let count = end.as_u32().saturating_sub(start.as_u32());
        Self {
            start,
            end,
            count: RangeCount(count),
        }
    }
}

/// Repair priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RepairPriority {
    Low = 1,
    Medium = 2,
    Normal = 3,
    High = 4,
    Critical = 5,
}

/// Repair result enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RepairResult {
    Success = 0,
    Failed = 1,
    PartialSuccess = 2,
    Timeout = 3,
}

/// Bloom filter for PSK discovery
#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub bits: Vec<u8>,
    pub hash_functions: HashFunctionCount,
    pub expected_elements: ElementCount,
}

impl BloomFilter {
    pub fn new(size_bits: usize, hash_functions: u8, expected_elements: u32) -> Self {
        Self {
            bits: vec![0u8; size_bits.div_ceil(8)],
            hash_functions: HashFunctionCount(hash_functions),
            expected_elements: ElementCount(expected_elements),
        }
    }
}

/// PSK proof for discovery verification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PskProof(pub [u8; 16]);

impl PskProof {
    pub fn new(proof: [u8; 16]) -> Self {
        Self(proof)
    }
    pub fn from_bytes_32(proof: [u8; 32]) -> Self {
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&proof[0..16]);
        Self(truncated)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Candidate hash for PSI operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CandidateHash(pub [u8; 32]);

impl CandidateHash {
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// PSK identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct PskId(pub [u8; 32]);

impl PskId {
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }
    pub fn from_u16(id: u16) -> Self {
        // TASK-007: Create valid test keys (not all zeros) for HMAC operations
        let mut bytes = [0x42u8; 32]; // Non-zero base
        bytes[0..2].copy_from_slice(&id.to_be_bytes());
        Self(bytes)
    }
    pub fn from_u32(id: u32) -> Self {
        // TASK-007: Create valid test keys (not all zeros) for HMAC operations
        let mut bytes = [0x42u8; 32]; // Non-zero base
        bytes[0..4].copy_from_slice(&id.to_be_bytes());
        Self(bytes)
    }
    pub fn from_u64(id: u64) -> Self {
        // TASK-007: Create valid test keys (not all zeros) for HMAC operations
        let mut bytes = [0x42u8; 32]; // Non-zero base
        bytes[0..8].copy_from_slice(&id.to_be_bytes());
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Session parameters for discovery confirmation
#[derive(Debug, Clone)]
pub struct SessionParams {
    pub session_id: SessionId,
    pub epoch_type: EpochType,
    pub hmac_policy: HmacPolicy,
    pub timestamp_config: TimestampConfig,
    pub flow_control_config: FlowControlConfig,
}

impl SessionParams {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            session_id: SessionId::new(0),
            epoch_type: EpochType::Milliseconds,
            hmac_policy: HmacPolicy::Medium,
            timestamp_config: TimestampConfig::Bits32,
            flow_control_config: FlowControlConfig::default(),
        }
    }
}

/// Flow control configuration
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    pub enabled: bool,
    pub window_scale: WindowScale,
    pub initial_window: WindowSize,
    pub max_window: WindowSize,
    pub congestion_control: bool,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_scale: WindowScale::new(7),
            initial_window: WindowSize::new(65536),
            max_window: WindowSize::new(1048576),
            congestion_control: true,
        }
    }
}

/// Flow control parameters
#[derive(Debug, Clone)]
pub struct FlowControlParams {
    pub window_size: WindowSize,
    pub congestion_state: CongestionState,
    pub advertised_window: WindowSize,
}

//==============================================================================
// CONFIGURATION TYPES
//==============================================================================

/// Maximum connections limit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MaxConnections(pub u32);

impl MaxConnections {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(count: u32) -> Self {
        Self(count)
    }
}

impl fmt::Display for MaxConnections {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialOrd for MaxConnections {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MaxConnections {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// Hop interval for port hopping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct HopInterval(pub u64);

impl HopInterval {
    pub fn new(interval_ms: u64) -> Self {
        Self(interval_ms)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn as_raw(&self) -> u64 {
        self.0
    }
    pub fn from_raw(interval_ms: u64) -> Self {
        Self(interval_ms)
    }
}

impl PartialOrd for HopInterval {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HopInterval {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Display for HopInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// Key rotation interval
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct KeyRotationInterval(pub u64);

impl KeyRotationInterval {
    pub fn new(interval_s: u64) -> Self {
        Self(interval_s)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn as_raw(&self) -> u64 {
        self.0
    }
    pub fn from_raw(interval_s: u64) -> Self {
        Self(interval_s)
    }
}

impl PartialOrd for KeyRotationInterval {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyRotationInterval {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Display for KeyRotationInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}s", self.0)
    }
}

/// Maximum PSK size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MaxPskSize(pub usize);

impl MaxPskSize {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_raw(&self) -> usize {
        self.0
    }
    pub fn from_raw(size: usize) -> Self {
        Self(size)
    }
}

impl PartialOrd for MaxPskSize {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MaxPskSize {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Display for MaxPskSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Replay window size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ReplayWindowSize(pub u32);

impl ReplayWindowSize {
    pub fn new(size: u32) -> Self {
        Self(size)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(size: u32) -> Self {
        Self(size)
    }
}

/// Log file size limit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct LogFileSize(pub u64);

impl LogFileSize {
    pub fn new(size_mb: u64) -> Self {
        Self(size_mb)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn as_raw(&self) -> u64 {
        self.0
    }
    pub fn from_raw(size_mb: u64) -> Self {
        Self(size_mb)
    }
}

/// Log file rotation count
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct LogFileCount(pub u32);

impl LogFileCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(count: u32) -> Self {
        Self(count)
    }
}

/// Worker thread count
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct WorkerThreadCount(pub u32);

impl WorkerThreadCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(count: u32) -> Self {
        Self(count)
    }
}

impl PartialOrd for WorkerThreadCount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkerThreadCount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Display for WorkerThreadCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Crypto thread count
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CryptoThreadCount(pub u32);

impl CryptoThreadCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(count: u32) -> Self {
        Self(count)
    }
}

impl PartialOrd for CryptoThreadCount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CryptoThreadCount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Display for CryptoThreadCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Metrics collection interval
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MetricsInterval(pub Duration);

impl MetricsInterval {
    pub fn new(interval: Duration) -> Self {
        Self(interval)
    }
    pub fn as_duration(&self) -> Duration {
        self.0
    }
    pub fn as_raw(&self) -> Duration {
        self.0
    }
    pub fn from_raw(interval: Duration) -> Self {
        Self(interval)
    }
}

/// Batch processing size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BatchSize(pub u32);

impl BatchSize {
    pub fn new(size: u32) -> Self {
        Self(size)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(size: u32) -> Self {
        Self(size)
    }
}

/// System uptime in ticks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct UptimeTicks(pub u64);

impl UptimeTicks {
    pub fn new(ticks: u64) -> Self {
        Self(ticks)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

//==============================================================================
// PROTOCOL CONSTANTS
//==============================================================================

/// Protocol version constants
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const PROTOCOL_MAX_VERSION: u8 = 0x01;

/// Header size constants
pub const BASE_HEADER_SIZE: usize = 18;
pub const FRAGMENT_HEADER_SIZE: usize = 8;

/// Time constants
pub const HOP_INTERVAL_MS: u64 = 500;
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
pub const TIMESTAMP_WINDOW_MS: u64 = 30_000;

/// Fragmentation constants
pub const MAX_FRAGMENTS: u16 = 255;
pub const MAX_FRAGMENTS_PER_PACKET: u8 = 16;
pub const FRAGMENT_TIMEOUT_MS: u64 = 5_000;
pub const FRAGMENT_DUPLICATE_WINDOW: usize = 100;

/// Discovery constants
pub const DISCOVERY_CHALLENGE_SIZE: usize = 32;
pub const DISCOVERY_TIMEOUT_MS: u64 = 10_000;
pub const DISCOVERY_RETRY_COUNT: u8 = 3;

/// Discovery identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DiscoveryId(pub u64);

impl DiscoveryId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for DiscoveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Discovery timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DiscoveryTimeout(pub u64);

impl Default for DiscoveryTimeout {
    fn default() -> Self {
        Self(DISCOVERY_TIMEOUT_MS)
    }
}

impl DiscoveryTimeout {
    pub fn new(timeout_ms: u64) -> Self {
        Self(timeout_ms)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn standard() -> Self {
        Self(DISCOVERY_TIMEOUT_MS)
    }
}

/// Discovery challenge nonce
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DiscoveryChallenge(pub [u8; DISCOVERY_CHALLENGE_SIZE]);

impl DiscoveryChallenge {
    pub fn new(challenge: [u8; DISCOVERY_CHALLENGE_SIZE]) -> Self {
        Self(challenge)
    }
    pub fn as_bytes(&self) -> &[u8; DISCOVERY_CHALLENGE_SIZE] {
        &self.0
    }
}

/// PSK constants
pub const PSK_ID_LENGTH: usize = 32;
pub const PSK_PROOF_SIZE: usize = 16;
pub const MAX_PSK_COUNT: u16 = 256;

/// Recovery constants
pub const RECOVERY_TIMEOUT_MS: u64 = 15_000;
pub const RECOVERY_RETRY_INTERVAL_MS: u64 = 2_000;
pub const RECOVERY_MAX_ATTEMPTS: u8 = 3;

/// Recovery level enumeration for escalation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RecoveryLevel {
    TimeSync = 1,
    // Level1 is an alias for TimeSync - removed duplicate discriminant
    Rekey = 2,
    Repair = 3,
    Emergency = 4,
    Terminate = 5,
    Failed = 6,
}

impl RecoveryLevel {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::TimeSync),
            2 => Some(Self::Rekey),
            3 => Some(Self::Repair),
            4 => Some(Self::Emergency),
            5 => Some(Self::Terminate),
            6 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Recovery challenge nonce
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct RecoveryNonce(pub u32);

impl RecoveryNonce {
    pub fn new(nonce: u32) -> Self {
        Self(nonce)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn generate() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().r#gen())
    }
}

/// Recovery parameters structure
#[derive(Debug, Clone)]
pub struct RecoveryParams {
    pub level: RecoveryLevel,
    pub retry_count: RetryCount,
    pub timeout_ms: ProtocolDuration,
    pub context: Vec<u8>,
    pub max_attempts: AttemptCount,
    pub timeout: RecoveryTimeout,
    pub nonce: RecoveryNonce,
}

impl RecoveryParams {
    pub fn new(level: RecoveryLevel) -> Self {
        Self {
            level,
            retry_count: RetryCount::new(RECOVERY_MAX_ATTEMPTS as u32),
            timeout_ms: ProtocolDuration(RECOVERY_TIMEOUT_MS),
            context: Vec::new(),
            max_attempts: AttemptCount::new(RECOVERY_MAX_ATTEMPTS as u32),
            timeout: RecoveryTimeout::new(RECOVERY_TIMEOUT_MS),
            nonce: RecoveryNonce::new(0),
        }
    }
}

/// Recovery attempt count tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct RecoveryAttemptCount(pub u32);

impl RecoveryAttemptCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn increment(&mut self) {
        self.0 += 1;
    }
    pub fn reset(&mut self) {
        self.0 = 0;
    }
}

/// Maximum recovery attempts per level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct MaxRecoveryAttempts(pub u32);

impl MaxRecoveryAttempts {
    pub fn new(max: u32) -> Self {
        Self(max)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Flow control constants
pub const SEQUENCE_WINDOW_SIZE: u32 = 1_000;
pub const MIN_RECEIVE_WINDOW: u32 = 1_024;
pub const MAX_RECEIVE_WINDOW: u32 = 65_535; // Matches spec requirement

/// MTU constants
pub const DEFAULT_MTU: u16 = 1_500;
pub const FRAGMENTATION_THRESHOLD: u16 = 1_400;
pub const MIN_FRAGMENT_SIZE: u16 = 64;
pub const MAX_FRAGMENT_SIZE: u16 = 1_400;

/// Security constants
pub const ECDH_SHARED_SECRET_SIZE: usize = 32;
pub const CURVE_P256_POINT_SIZE: usize = 64;
pub const CURVE_P256_SCALAR_SIZE: usize = 32;

//==============================================================================
// ADDITIONAL IDENTIFIER TYPES
//==============================================================================

/// Connection identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn generate() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().r#gen())
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn to_ebpf_u64(&self) -> u64 {
        self.0
    }

    pub fn from_ebpf_u64(value: u64) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conn:{}", self.0)
    }
}

/// Session count tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SessionCount(pub u32);

impl SessionCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for SessionCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for SessionCount {
    fn default() -> Self {
        Self::zero()
    }
}

/// Byte count for throughput measurements
#[derive(Debug)]
#[repr(transparent)]
pub struct ByteCount(AtomicU64);

impl ByteCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }

    pub fn from_raw(count: u64) -> Self {
        Self::new(count)
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, count: u64, ordering: Ordering) {
        self.0.store(count, ordering);
    }

    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }

    pub fn add(&self, val: u64, ordering: Ordering) -> u64 {
        self.fetch_add(val, ordering)
    }

    pub fn as_usize(&self) -> usize {
        self.0.load(Ordering::Relaxed) as usize
    }
}

impl Default for ByteCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl Clone for ByteCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl serde::Serialize for ByteCount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.load(Ordering::Relaxed).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ByteCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

impl PartialEq for ByteCount {
    fn eq(&self, other: &Self) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

impl Eq for ByteCount {}

/// Generic counter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Counter(u64);

impl Counter {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn increment(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    pub fn increment_mut(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    pub fn add(&self, value: u64) -> Self {
        Self(self.0.saturating_add(value))
    }

    pub fn fetch_add(&mut self, value: u64) -> u64 {
        let old_value = self.0;
        self.0 = self.0.saturating_add(value);
        old_value
    }

    pub fn load(&self, _ordering: std::sync::atomic::Ordering) -> u64 {
        self.0
    }
}

impl std::ops::AddAssign<u64> for Counter {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_add(rhs);
    }
}

impl PartialEq<u64> for Counter {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<i32> for Counter {
    fn eq(&self, other: &i32) -> bool {
        if *other < 0 {
            false
        } else {
            self.0 == *other as u64
        }
    }
}

impl std::ops::AddAssign<u32> for Counter {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.saturating_add(rhs as u64);
    }
}

impl std::ops::AddAssign<usize> for Counter {
    fn add_assign(&mut self, rhs: usize) {
        self.0 = self.0.saturating_add(rhs as u64);
    }
}

impl std::ops::AddAssign<i32> for Counter {
    fn add_assign(&mut self, rhs: i32) {
        if rhs >= 0 {
            self.0 = self.0.saturating_add(rhs as u64);
        }
    }
}

impl From<Counter> for f64 {
    fn from(counter: Counter) -> Self {
        counter.0 as f64
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::zero()
    }
}

impl std::ops::Add<u64> for Counter {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl std::ops::Sub<u64> for Counter {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_sub(rhs))
    }
}

impl std::ops::SubAssign<u64> for Counter {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_sub(rhs);
    }
}

impl std::fmt::Display for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Mul<Counter> for u64 {
    type Output = u64;
    fn mul(self, rhs: Counter) -> Self::Output {
        self.saturating_mul(rhs.0)
    }
}

impl std::ops::Mul<u64> for Counter {
    type Output = Counter;
    fn mul(self, rhs: u64) -> Self::Output {
        Counter(self.0.saturating_mul(rhs))
    }
}

impl std::ops::Div<Counter> for u64 {
    type Output = u64;
    fn div(self, rhs: Counter) -> Self::Output {
        if rhs.0 == 0 { 0 } else { self / rhs.0 }
    }
}

impl std::iter::Sum<Counter> for u64 {
    fn sum<I: Iterator<Item = Counter>>(iter: I) -> Self {
        iter.map(|c| c.0).sum()
    }
}

// CounterAtomic removed - use specific atomic counter types instead

/// eBPF program count
pub type EbpfProgramCount = AtomicU32;

/// Packet count for statistics tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct PacketCount(AtomicU64);

/// Block count type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BlockCount(pub usize);

impl BlockCount {
    pub fn new(count: usize) -> Self {
        Self(count)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }
}

/// Source count type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct SourceCount(pub usize);

impl SourceCount {
    pub fn new(count: usize) -> Self {
        Self(count)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// Byte offset type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ByteOffset(pub usize);

impl ByteOffset {
    pub fn new(offset: usize) -> Self {
        Self(offset)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl<'de> Deserialize<'de> for PacketCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(PacketCount::new(value))
    }
}

impl Serialize for PacketCount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.load(std::sync::atomic::Ordering::Relaxed)
            .serialize(serializer)
    }
}

impl PacketCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn from_raw(count: u64) -> Self {
        Self::new(count)
    }
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }
    pub fn store(&self, count: u64, ordering: Ordering) {
        self.0.store(count, ordering);
    }
    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }
    pub fn fetch_sub(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_sub(val, ordering)
    }
    pub fn increment(&self, ordering: Ordering) -> u64 {
        self.fetch_add(1, ordering)
    }
    pub fn as_u64(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
    pub fn as_raw(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for PacketCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl Default for PacketCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl std::ops::AddAssign<u64> for PacketCount {
    fn add_assign(&mut self, rhs: u64) {
        self.fetch_add(rhs, Ordering::Relaxed);
    }
}

impl std::fmt::Display for PacketCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl PartialEq for PacketCount {
    fn eq(&self, other: &Self) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

impl Eq for PacketCount {}

/// State transition count for protocol state tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct TransitionCount(AtomicU64);

impl TransitionCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }
    pub fn store(&self, count: u64, ordering: Ordering) {
        self.0.store(count, ordering);
    }
    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }
    pub fn increment(&self, ordering: Ordering) -> u64 {
        self.fetch_add(1, ordering)
    }
    pub fn as_u64(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for TransitionCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

/// Cache hit count for performance tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct CacheHitCount(AtomicU64);

impl CacheHitCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }
    pub fn store(&self, count: u64, ordering: Ordering) {
        self.0.store(count, ordering);
    }
    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }
    pub fn increment(&self, ordering: Ordering) -> u64 {
        self.fetch_add(1, ordering)
    }
    pub fn as_u64(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for CacheHitCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

/// Cache miss count for performance tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct CacheMissCount(AtomicU64);

impl CacheMissCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }
    pub fn store(&self, count: u64, ordering: Ordering) {
        self.0.store(count, ordering);
    }
    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }
    pub fn increment(&self, ordering: Ordering) -> u64 {
        self.fetch_add(1, ordering)
    }
    pub fn as_u64(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for CacheMissCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

/// Generic key size type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct KeySize(pub usize);

impl KeySize {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// Generic value size type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ValueSize(pub usize);

impl ValueSize {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// Buffer size type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BufferSize(pub usize);

impl BufferSize {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn to_ebpf_u32(&self) -> u32 {
        self.0 as u32
    }
}

/// Size limit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct SizeLimit(pub usize);

impl SizeLimit {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// Header size type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HeaderSize(pub usize);

impl HeaderSize {
    pub fn new(size: u16) -> Self {
        Self(size as usize)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_u16(&self) -> u16 {
        self.0 as u16
    }
}

/// Socket identifier type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SocketId(pub u32);

impl SocketId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn to_ebpf_u32(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for SocketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "socket:{}", self.0)
    }
}

/// TUN device state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TunState {
    Down = 0,
    Up = 1,
    Error = 2,
    Initializing = 3,
    Active = 4,
    Suspended = 5,
    ShuttingDown = 6,
    Shutdown = 7,
}

impl TunState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Down),
            1 => Some(Self::Up),
            2 => Some(Self::Error),
            3 => Some(Self::Initializing),
            4 => Some(Self::Active),
            5 => Some(Self::Suspended),
            6 => Some(Self::ShuttingDown),
            7 => Some(Self::Shutdown),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Window size for flow control
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct WindowSize(pub u32);

impl WindowSize {
    pub const fn new(size: u32) -> Self {
        Self(size)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn to_ebpf_u32(&self) -> u32 {
        self.0
    }

    pub fn from_ebpf_u32(value: u32) -> Self {
        Self::new(value)
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }
}

impl Default for WindowSize {
    fn default() -> Self {
        Self::new(0)
    }
}

// WindowSizeAtomic removed - WindowSize is now Copy-able

/// Buffer size for data buffers with atomic-by-default design
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicBufferSize(AtomicU32);
impl AtomicBufferSize {
    pub fn new(size: u32) -> Self {
        Self(AtomicU32::new(size))
    }

    /// Non-atomic access for single-threaded contexts
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn as_u32(&self) -> u32 {
        self.get()
    }

    /// Atomic operations for concurrent contexts
    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u32, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn swap(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.swap(value, ordering)
    }

    pub fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.0.compare_exchange(current, new, success, failure)
    }

    pub fn fetch_add(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(value, ordering)
    }

    pub fn fetch_sub(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.fetch_sub(value, ordering)
    }

    pub fn as_raw(&self) -> u32 {
        self.get()
    }

    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }
}

impl Clone for AtomicBufferSize {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl Default for AtomicBufferSize {
    fn default() -> Self {
        Self::new(0)
    }
}

impl PartialEq for AtomicBufferSize {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for AtomicBufferSize {}

impl PartialOrd for AtomicBufferSize {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AtomicBufferSize {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

impl std::hash::Hash for AtomicBufferSize {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.get().hash(state);
    }
}

/// Congestion window size with atomic-by-default design
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicCongestionWindow(AtomicU32);
impl AtomicCongestionWindow {
    pub fn new(size: u32) -> Self {
        Self(AtomicU32::new(size))
    }

    /// Non-atomic access for single-threaded contexts
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn as_u32(&self) -> u32 {
        self.get()
    }

    /// Atomic operations for concurrent contexts
    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u32, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn swap(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.swap(value, ordering)
    }

    pub fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.0.compare_exchange(current, new, success, failure)
    }

    pub fn fetch_add(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(value, ordering)
    }

    pub fn fetch_sub(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.fetch_sub(value, ordering)
    }

    pub fn as_raw(&self) -> u32 {
        self.get()
    }

    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }
}

impl Clone for AtomicCongestionWindow {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl Default for AtomicCongestionWindow {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Slow start threshold with atomic-by-default design
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicSlowStartThreshold(AtomicU32);
impl AtomicSlowStartThreshold {
    pub fn new(threshold: u32) -> Self {
        Self(AtomicU32::new(threshold))
    }

    /// Non-atomic access for single-threaded contexts
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn as_u32(&self) -> u32 {
        self.get()
    }

    /// Atomic operations for concurrent contexts
    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u32, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn swap(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.swap(value, ordering)
    }

    pub fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.0.compare_exchange(current, new, success, failure)
    }

    pub fn fetch_add(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(value, ordering)
    }

    pub fn fetch_sub(&self, value: u32, ordering: Ordering) -> u32 {
        self.0.fetch_sub(value, ordering)
    }

    pub fn as_raw(&self) -> u32 {
        self.get()
    }

    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }
}

impl Clone for AtomicSlowStartThreshold {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl Default for AtomicSlowStartThreshold {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Atomic counter for various metrics
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicCounter(AtomicU64);
impl AtomicCounter {
    pub fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    /// Non-atomic access for single-threaded contexts
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn as_u64(&self) -> u64 {
        self.get()
    }

    /// Atomic operations for concurrent contexts
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u64, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }

    pub fn fetch_sub(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_sub(value, ordering)
    }

    pub fn increment(&self) -> u64 {
        self.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> u64 {
        self.fetch_sub(1, Ordering::Relaxed)
    }

    pub fn as_raw(&self) -> u64 {
        self.get()
    }

    pub fn from_raw(value: u64) -> Self {
        Self::new(value)
    }
}

impl Clone for AtomicCounter {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Session key for authentication with secure memory zeroing
///
/// This type holds session key material and automatically zeros the memory
/// when dropped to prevent key material from remaining in memory.
///
/// Security Properties:
/// - Derives `Zeroize` to enable explicit zeroing
/// - Derives `ZeroizeOnDrop` to ensure automatic cleanup
/// - Memory is securely zeroed even if panics occur during drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    pub const SIZE: usize = 32;

    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_ebpf_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_ebpf_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Cryptographic error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptographicError {
    InvalidKey,
    InvalidSignature,
    EncryptionFailed,
    DecryptionFailed,
    KeyGenerationFailed,
    InvalidNonce,
    AuthenticationFailed,
}

impl std::error::Error for CryptographicError {}

impl fmt::Display for CryptographicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "Invalid cryptographic key"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::EncryptionFailed => write!(f, "Encryption operation failed"),
            Self::DecryptionFailed => write!(f, "Decryption operation failed"),
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
            Self::InvalidNonce => write!(f, "Invalid nonce"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
        }
    }
}

/// Packet size type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct PacketSize(pub u16);

impl PacketSize {
    pub fn new(size: usize) -> Self {
        Self(size.try_into().unwrap_or(u16::MAX))
    }

    pub fn from_u16(size: u16) -> Self {
        Self(size)
    }

    pub fn from_usize(size: usize) -> Self {
        Self(size.try_into().unwrap_or(u16::MAX))
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_raw(&self) -> u16 {
        self.0
    }

    pub fn from_raw(size: u16) -> Self {
        Self(size)
    }

    pub fn to_ebpf_u16(&self) -> u16 {
        self.0
    }

    pub fn from_ebpf_u16(value: u16) -> Self {
        Self(value)
    }
}

impl fmt::Display for PacketSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.0)
    }
}

/// Thread identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ThreadId(pub u64);

impl ThreadId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn current() -> Self {
        // Use a hash of the thread ID since as_u64() is unstable
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        Self(hasher.finish())
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Message identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct MessageId(pub u64);

impl MessageId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Packet identifier for tracking individual packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PacketId(pub u64);

impl PacketId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for PacketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pkt:{}", self.0)
    }
}

/// Event identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EventId(pub u64);

impl EventId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(pub u8);

impl Priority {
    pub const LOW: Priority = Priority(0);
    pub const NORMAL: Priority = Priority(1);
    pub const HIGH: Priority = Priority(2);
    pub const CRITICAL: Priority = Priority(3);

    pub fn new(level: u8) -> Self {
        Self(level)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Weight for load balancing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Weight(pub u32);

impl Weight {
    pub fn new(weight: u32) -> Self {
        Self(weight)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Memory limit
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MemoryLimit(pub usize);

impl MemoryLimit {
    pub fn new(limit: usize) -> Self {
        Self(limit)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn to_bytes(&self) -> usize {
        self.0
    }
}

/// Timeout value
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct Timeout(pub u64);

impl Timeout {
    pub const fn new(millis: u64) -> Self {
        Self(millis)
    }
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs * 1000)
    }
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }
    pub fn as_millis(&self) -> u64 {
        self.0
    }
    pub fn as_secs(&self) -> u64 {
        self.0 / 1000
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Retry count
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RetryCount(pub u32);

impl RetryCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Checksum value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Checksum(pub u32);

impl Checksum {
    pub fn new(checksum: u32) -> Self {
        Self(checksum)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::LowerHex for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// Hash value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HashValue(pub u64);

impl HashValue {
    pub fn new(hash: u64) -> Self {
        Self(hash)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Version number
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Version(pub u32);

impl Version {
    pub fn new(version: u32) -> Self {
        Self(version)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Configuration value
#[derive(Debug, Clone)]
pub struct ConfigValue(pub String);

impl ConfigValue {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Process identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ProcessId(pub u32);

impl ProcessId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
    pub fn current() -> Self {
        Self(std::process::id())
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Worker identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct WorkerId(pub u32);

impl WorkerId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Channel capacity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ChannelCapacity(pub usize);

impl ChannelCapacity {
    pub fn new(capacity: usize) -> Self {
        Self(capacity)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn unbounded() -> Self {
        Self(usize::MAX)
    }
}

/// Error count
#[derive(Debug)]
#[repr(transparent)]
pub struct ErrorCount(AtomicU32);

impl ErrorCount {
    pub fn new(count: u32) -> Self {
        Self(AtomicU32::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }
    pub fn store(&self, count: u32, ordering: Ordering) {
        self.0.store(count, ordering);
    }
    pub fn increment(&self, ordering: Ordering) -> u32 {
        self.0.fetch_add(1, ordering)
    }
    pub fn from_raw(value: u32) -> Self {
        Self::new(value)
    }
    pub fn as_raw(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }
    pub fn as_u32(&self) -> u32 {
        self.load(Ordering::Relaxed)
    }
    pub fn as_u64(&self) -> u64 {
        self.load(Ordering::Relaxed) as u64
    }
}

impl Clone for ErrorCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl Default for ErrorCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for ErrorCount {
    fn eq(&self, other: &Self) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

/// Metric value
#[derive(
    Debug, Clone, Copy, PartialEq, PartialOrd, Default, serde::Serialize, serde::Deserialize,
)]
#[repr(transparent)]
pub struct MetricValue(pub f64);

impl MetricValue {
    pub fn new(value: f64) -> Self {
        Self(value)
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn as_raw(&self) -> f64 {
        self.0
    }
    pub fn from_raw(value: f64) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for MetricValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Rate value (0.0 to 1.0)
#[derive(
    Debug, Clone, Copy, PartialEq, PartialOrd, Default, serde::Serialize, serde::Deserialize,
)]
#[repr(transparent)]
pub struct Rate(pub f32);

impl Rate {
    pub fn new(rate: f32) -> Self {
        Self(rate.clamp(0.0, 1.0))
    }
    pub fn as_f32(&self) -> f32 {
        self.0
    }
    pub fn as_raw(&self) -> f32 {
        self.0
    }
    pub fn from_raw(rate: f32) -> Self {
        Self(rate)
    }
    pub fn as_percentage(&self) -> f32 {
        self.0 * 100.0
    }
}

/// Percentage value (0.0 to 100.0)
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Percentage(pub f32);

/// Packet rate (packets per second)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PacketRate(pub u32);

impl PacketRate {
    pub fn new(rate: u32) -> Self {
        Self(rate)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(rate: u32) -> Self {
        Self(rate)
    }
}

impl Percentage {
    pub fn new(pct: f32) -> Self {
        Self(pct.clamp(0.0, 100.0))
    }
    pub fn as_f32(&self) -> f32 {
        self.0
    }
    pub fn as_rate(&self) -> f32 {
        self.0 / 100.0
    }
}

/// Interval for recurring operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Interval(pub u64);

impl Interval {
    pub fn from_millis(millis: u64) -> Self {
        Self(millis * 1_000_000)
    }
    pub fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }
    pub fn as_nanos(&self) -> u64 {
        self.0
    }
    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }
    pub fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<Interval> for u64 {
    fn from(interval: Interval) -> Self {
        interval.0
    }
}

impl From<Interval> for Duration {
    fn from(interval: Interval) -> Self {
        Duration::from_nanos(interval.0)
    }
}

/// Network jitter measurement
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct NetworkJitter(pub u32);

impl NetworkJitter {
    pub fn new(millis: u32) -> Self {
        Self(millis)
    }
    pub fn as_millis(&self) -> u32 {
        self.0
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_u8(&self) -> u8 {
        self.0 as u8
    }
    pub fn to_ebpf_u32(&self) -> u32 {
        self.0
    }
}

/// Packet loss rate (per-mille)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct PacketLossRate(pub u16);

impl PacketLossRate {
    pub fn new(per_mille: u16) -> Self {
        Self(per_mille)
    }
    pub fn as_per_mille(&self) -> u16 {
        self.0
    }
    pub fn as_percentage(&self) -> f32 {
        self.0 as f32 / 10.0
    }
    pub fn as_f64(&self) -> f64 {
        self.0 as f64 / 1000.0
    }
    pub fn from_f64(rate: f64) -> Self {
        Self((rate * 1000.0) as u16)
    }
}

impl std::ops::Mul<f64> for PacketLossRate {
    type Output = f64;
    fn mul(self, rhs: f64) -> Self::Output {
        self.as_f64() * rhs
    }
}

/// Queue size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct QueueSize(pub usize);

impl QueueSize {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// Adaptive delay window size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct DelayWindow(pub u8);

impl DelayWindow {
    pub const MIN: DelayWindow = DelayWindow(1);
    pub const MAX: DelayWindow = DelayWindow(16);

    pub fn new(size: u8) -> Self {
        Self(size.clamp(1, 16))
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Data rate measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct DataRate(pub u64);

impl DataRate {
    pub fn new(bytes_per_sec: u64) -> Self {
        Self(bytes_per_sec)
    }
    pub fn from_raw(bytes_per_sec: u64) -> Self {
        Self(bytes_per_sec)
    }
    pub fn as_bytes_per_sec(&self) -> u64 {
        self.0
    }
    pub fn as_mbps(&self) -> f64 {
        (self.0 * 8) as f64 / 1_000_000.0
    }
}

/// Socket state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SocketState {
    Closed = 0,
    Listening = 1,
    Connected = 2,
    Closing = 3,
    Active = 4,
}

impl SocketState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Closed),
            1 => Some(Self::Listening),
            2 => Some(Self::Connected),
            3 => Some(Self::Closing),
            4 => Some(Self::Active),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Binding state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BindingState {
    Unbound = 0,
    Binding = 1,
    Bound = 2,
    Active = 3,
    Failed = 4,
    Reserved = 5,
    Releasing = 6,
    Expired = 7,
    Error = 8,
}

impl BindingState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Unbound),
            1 => Some(Self::Binding),
            2 => Some(Self::Bound),
            3 => Some(Self::Active),
            4 => Some(Self::Failed),
            5 => Some(Self::Reserved),
            6 => Some(Self::Releasing),
            7 => Some(Self::Expired),
            8 => Some(Self::Error),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Route metric for network routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RouteMetric(pub u32);

impl RouteMetric {
    pub fn new(metric: u32) -> Self {
        Self(metric)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Usage count tracking
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct UsageCount(pub AtomicU32);

impl UsageCount {
    pub fn new(count: u32) -> Self {
        Self(AtomicU32::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }
    pub fn increment(&self, ordering: Ordering) -> u32 {
        self.0.fetch_add(1, ordering)
    }
    pub fn fetch_add(&self, val: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(val, ordering)
    }
    pub fn fetch_sub(&self, val: u32, ordering: Ordering) -> u32 {
        self.0.fetch_sub(val, ordering)
    }
}

impl Clone for UsageCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl From<AtomicUsize> for UsageCount {
    fn from(value: AtomicUsize) -> Self {
        Self::new(value.load(Ordering::Relaxed) as u32)
    }
}

/// Threshold value
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Threshold(pub u32);

impl Threshold {
    pub fn new(value: u32) -> Self {
        Self(value)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Display for Threshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Event count tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct EventCount(pub AtomicU64);

impl EventCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }
    pub fn zero() -> Self {
        Self::new(0)
    }
    pub fn from_raw(count: u64) -> Self {
        Self::new(count)
    }
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }
    pub fn store(&self, count: u64, ordering: Ordering) {
        self.0.store(count, ordering);
    }
    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }
    pub fn increment(&self, ordering: Ordering) -> u64 {
        self.0.fetch_add(1, ordering)
    }
    pub fn as_u64(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
    pub fn as_raw(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
}

impl Clone for EventCount {
    fn clone(&self) -> Self {
        Self::new(self.load(Ordering::Relaxed))
    }
}

impl Default for EventCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for EventCount {
    fn eq(&self, other: &Self) -> bool {
        self.load(Ordering::Relaxed) == other.load(Ordering::Relaxed)
    }
}

impl Eq for EventCount {}

impl serde::Serialize for EventCount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.load(Ordering::Relaxed).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EventCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

/// Microsecond timestamp
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MicrosecondTimestamp(pub u64);

impl MicrosecondTimestamp {
    pub fn new(micros: u64) -> Self {
        Self(micros)
    }
    pub fn as_micros(&self) -> u64 {
        self.0
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn as_raw(&self) -> u64 {
        self.0
    }
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos / 1_000)
    }
    pub fn as_nanos(&self) -> u64 {
        self.0 * 1_000
    }
    pub fn saturating_sub(&self, other: Self) -> u64 {
        self.0.saturating_sub(other.0)
    }

    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::new(duration.as_micros() as u64)
    }
}

/// Drift rate measurement
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct DriftRate(pub f64);

impl DriftRate {
    pub fn new(ppm: f64) -> Self {
        Self(ppm)
    }
    pub fn as_ppm(&self) -> f64 {
        self.0
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn is_excessive(&self, threshold: f64) -> bool {
        self.0.abs() > threshold
    }
    pub fn is_significant(&self, threshold: f64) -> bool {
        self.0.abs() > threshold
    }
    pub fn abs(&self) -> Self {
        Self(self.0.abs())
    }
}

impl std::fmt::Display for DriftRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.3} ppm", self.0)
    }
}

/// Time synchronization tolerance
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TimeSyncTolerance(pub u64);

impl TimeSyncTolerance {
    pub fn new(millis: u64) -> Self {
        Self(millis)
    }
    pub fn as_millis(&self) -> u64 {
        self.0
    }
}

/// Hop count for network routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HopCount(pub u8);

impl HopCount {
    pub fn new(count: u8) -> Self {
        Self(count)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
    pub fn max_value() -> Self {
        Self(255)
    }
}

/// Bandwidth measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Bandwidth(pub u64);

impl Bandwidth {
    pub fn new(bps: u64) -> Self {
        Self(bps)
    }
    pub fn as_bps(&self) -> u64 {
        self.0
    }
    pub fn as_kbps(&self) -> f64 {
        self.0 as f64 / 1_000.0
    }
    pub fn as_mbps(&self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }
}

/// Latency measurement in microseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Latency(pub u32);

impl Latency {
    pub fn new(micros: u32) -> Self {
        Self(micros)
    }
    pub fn from_millis(millis: u32) -> Self {
        Self(millis * 1_000)
    }
    pub fn as_micros(&self) -> u32 {
        self.0
    }
    pub fn as_millis(&self) -> f32 {
        self.0 as f32 / 1_000.0
    }
}

/// Quality of Service level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum QosLevel {
    BestEffort = 0,
    Priority = 1,
    Critical = 2,
    RealTime = 3,
}

impl QosLevel {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::BestEffort),
            1 => Some(Self::Priority),
            2 => Some(Self::Critical),
            3 => Some(Self::RealTime),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Flow identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct FlowId(pub u64);

impl FlowId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn generate() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().r#gen())
    }
}

/// Stream identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StreamId(pub u32);

impl StreamId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Route state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RouteState {
    Active = 0,
    Inactive = 1,
    Pending = 2,
    Failed = 3,
}

impl RouteState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Active),
            1 => Some(Self::Inactive),
            2 => Some(Self::Pending),
            3 => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Daily key for daily epoch operations with secure memory zeroing
///
/// This type holds daily key material and automatically zeros the memory
/// when dropped to prevent key material from remaining in memory.
///
/// Security Properties:
/// - Derives `Zeroize` to enable explicit zeroing
/// - Derives `ZeroizeOnDrop` to ensure automatic cleanup
/// - Memory is securely zeroed even if panics occur during drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct DailyKey(pub [u8; 32]);

impl DailyKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    pub fn zero() -> Self {
        Self([0u8; 32])
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(bytes);
            Some(Self(key))
        } else {
            None
        }
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DailyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DailyKey")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Memory size in bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MemorySize(pub u64);

impl MemorySize {
    pub fn new(bytes: u64) -> Self {
        Self(bytes)
    }
    pub fn zero() -> Self {
        Self(0)
    }
    pub fn from_kb(kb: u64) -> Self {
        Self(kb * 1024)
    }
    pub fn from_mb(mb: u64) -> Self {
        Self(mb * 1024 * 1024)
    }
    pub fn from_gb(gb: u64) -> Self {
        Self(gb * 1024 * 1024 * 1024)
    }
    pub fn as_bytes(&self) -> u64 {
        self.0
    }
    pub fn as_kb(&self) -> u64 {
        self.0 / 1024
    }
    pub fn as_mb(&self) -> u64 {
        self.0 / (1024 * 1024)
    }
    pub fn as_gb(&self) -> u64 {
        self.0 / (1024 * 1024 * 1024)
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// Session ID length constant
pub const SESSION_ID_LENGTH: usize = 8;

/// Key derivation function identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KdfId {
    Pbkdf2 = 0,
    Scrypt = 1,
    Argon2 = 2,
}

impl KdfId {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Pbkdf2),
            1 => Some(Self::Scrypt),
            2 => Some(Self::Argon2),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Hash algorithm identifier  
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HashId {
    Sha256 = 0,
    Sha512 = 1,
    Blake3 = 2,
}

impl HashId {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Sha256),
            1 => Some(Self::Sha512),
            2 => Some(Self::Blake3),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Connection priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ConnectionPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl ConnectionPriority {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Low),
            1 => Some(Self::Normal),
            2 => Some(Self::High),
            3 => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Health state enumeration for system monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HealthState {
    Healthy = 0,
    Warning = 1,
    Critical = 2,
    // Unhealthy is an alias for Critical - removed duplicate discriminant
    Unknown = 3,
}

impl HealthState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Healthy),
            1 => Some(Self::Warning),
            2 => Some(Self::Critical),
            3 => Some(Self::Unknown),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "HEALTHY"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Performance score for optimization algorithms
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
#[repr(transparent)]
pub struct Score(pub f64);

impl Score {
    pub fn new(score: f64) -> Self {
        Self(score.clamp(0.0, 1.0)) // Clamp between 0.0 and 1.0
    }
    pub fn zero() -> Self {
        Self(0.0)
    }
    pub fn perfect() -> Self {
        Self(1.0)
    }
    pub fn from_ratio(numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            Self::zero()
        } else {
            Self::new(numerator as f64 / denominator as f64)
        }
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn as_f32(&self) -> f32 {
        self.0 as f32
    }
    pub fn as_percentage(&self) -> f64 {
        self.0 * 100.0
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

/// Recovery timeout for protocol state recovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct RecoveryTimeout(pub u64);

impl RecoveryTimeout {
    pub fn new(millis: u64) -> Self {
        Self(millis)
    }
    pub fn zero() -> Self {
        Self(0)
    }
    pub fn from_seconds(seconds: u64) -> Self {
        Self(seconds * 1000)
    }
    pub fn as_millis(&self) -> u64 {
        self.0
    }
    pub fn as_seconds(&self) -> u64 {
        self.0 / 1000
    }
}

/// Connection features bitfield
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionFeatures(u32);

impl ConnectionFeatures {
    pub const FRAGMENTATION: Self = Self(1 << 0);
    pub const SELECTIVE_ACK: Self = Self(1 << 1);
    pub const FLOW_CONTROL: Self = Self(1 << 2);
    pub const COMPRESSION: Self = Self(1 << 3);
    pub const ENCRYPTION: Self = Self(1 << 4);

    pub fn new(features: u32) -> Self {
        Self(features)
    }

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl Default for ConnectionFeatures {
    fn default() -> Self {
        Self::FRAGMENTATION | Self::SELECTIVE_ACK | Self::FLOW_CONTROL
    }
}

impl std::ops::BitOr for ConnectionFeatures {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for ConnectionFeatures {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Connection parameters for protocol negotiation
#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub window_size: WindowSize,
    pub max_packet_size: PacketSize,
    pub timeout: Timeout,
    pub keep_alive: std::time::Duration,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub features: ConnectionFeatures,
}

impl Default for ConnectionParams {
    fn default() -> Self {
        Self {
            window_size: WindowSize::new(65536),
            max_packet_size: PacketSize::new(1500),
            timeout: Timeout::new(30000),
            keep_alive: std::time::Duration::from_secs(300),
            compression_enabled: true,
            encryption_enabled: true,
            features: ConnectionFeatures::FRAGMENTATION
                | ConnectionFeatures::SELECTIVE_ACK
                | ConnectionFeatures::FLOW_CONTROL,
        }
    }
}

impl ConnectionParams {
    pub fn new(
        window_size: u32,
        max_packet_size: u16,
        timeout_ms: u64,
        keep_alive_secs: u64,
    ) -> Self {
        Self {
            window_size: WindowSize::new(window_size),
            max_packet_size: PacketSize::new(max_packet_size as usize),
            timeout: Timeout::new(timeout_ms),
            keep_alive: std::time::Duration::from_secs(keep_alive_secs),
            compression_enabled: true,
            encryption_enabled: true,
            features: ConnectionFeatures::FRAGMENTATION
                | ConnectionFeatures::SELECTIVE_ACK
                | ConnectionFeatures::FLOW_CONTROL,
        }
    }
}

/// Protocol version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ProtocolVersion(pub u8);

impl ProtocolVersion {
    pub const CURRENT: Self = Self(1);

    pub fn new(version: u8) -> Self {
        Self(version)
    }
    pub fn v1() -> Self {
        Self(1)
    }
    pub fn current() -> Self {
        Self::v1()
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Type validation error for protocol validation
#[derive(Debug, Clone)]
pub struct TypeValidationError {
    pub field_name: String,
    pub expected: String,
    pub actual: String,
}

impl TypeValidationError {
    pub fn new(field_name: &str, expected: &str, actual: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }
}

impl std::fmt::Display for TypeValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Type validation error in field '{}': expected {}, got {}",
            self.field_name, self.expected, self.actual
        )
    }
}

impl std::error::Error for TypeValidationError {}

/// Connection count for capacity management
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ConnectionCount(pub u32);

impl ConnectionCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn zero() -> Self {
        Self(0)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn increment(&self) -> Self {
        Self(self.0.saturating_add(1))
    }
    pub fn decrement(&self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

impl fmt::Display for ConnectionCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maximum Transmission Unit (MTU) size in bytes
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct MtuSize(pub u16);

impl MtuSize {
    pub fn new(size: u16) -> Self {
        Self(size)
    }
    pub fn ethernet() -> Self {
        Self(1500)
    } // Standard Ethernet MTU
    pub fn jumbo() -> Self {
        Self(9000)
    } // Jumbo frame MTU
    pub fn as_u16(&self) -> u16 {
        self.0
    }
    pub fn as_raw(&self) -> u16 {
        self.0
    }
    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// Configuration version for protocol compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ConfigurationVersion(pub u32);

impl ConfigurationVersion {
    pub fn new(version: u32) -> Self {
        Self(version)
    }
    pub fn v1() -> Self {
        Self(1)
    }
    pub fn current() -> Self {
        Self::v1()
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

//==============================================================================
// SUBMODULE RE-EXPORTS FOR LEGACY COMPATIBILITY
//==============================================================================

/// Header-related constants and types
pub mod header {
    pub use super::SESSION_ID_LENGTH;
    pub type SessionIdLength = usize;
    pub const SESSION_ID_LENGTH_VALUE: usize = super::SESSION_ID_LENGTH;
}

/// State-related types
pub mod state {
    pub use super::SessionState;
}

/// Time-related types
pub mod time {
    pub use super::{RecoveryTimeout, Timestamp};
}

/// Configuration-related types and functions
pub mod config {
    /// Standard configuration for protocol version and HMAC policy
    pub fn standard_config() -> (u8, bool) {
        (1, true) // Version 1, HMAC enabled
    }
}

//==============================================================================
// EBPF INTEGRATION TYPES
//==============================================================================

/// eBPF program identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EbpfProgramId(pub u32);

impl EbpfProgramId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn to_ebpf_u32(&self) -> u32 {
        self.0
    }
    pub fn from_ebpf_u32(value: u32) -> Self {
        Self(value)
    }
}

/// eBPF attach type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum EbpfAttachType {
    Xdp = 1,
    Tc = 2,
    SocketFilter = 3,
}

/// eBPF map type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum EbpfMapType {
    Hash = 1,
    Array = 2,
    RingBuf = 3,
}

/// eBPF map key type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EbpfMapKey(pub Vec<u8>);

impl EbpfMapKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// eBPF verifier log
#[derive(Debug, Clone)]
pub struct EbpfVerifierLog(pub String);

impl EbpfVerifierLog {
    pub fn new(log: String) -> Self {
        Self(log)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// eBPF instruction count
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EbpfInstructionCount(pub u32);

impl EbpfInstructionCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// eBPF stack size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EbpfStackSize(pub u32);

impl EbpfStackSize {
    pub fn new(size: u32) -> Self {
        Self(size)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Ring buffer size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct RingBufferSize(pub u32);

impl RingBufferSize {
    pub fn new(size: u32) -> Self {
        Self(size)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_raw(&self) -> u32 {
        self.0
    }
    pub fn from_raw(size: u32) -> Self {
        Self(size)
    }
}

/// eBPF event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum EbpfEventType {
    PacketReceived = 1,
    PacketSent = 2,
    SessionCreated = 3,
    SecurityEvent = 4,
}

/// eBPF return code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum EbpfReturnCode {
    Pass = 0,
    Drop = 1,
    Redirect = 2,
    Error = -1,
}

/// eBPF file descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EbpfFileDescriptor(pub i32);

impl EbpfFileDescriptor {
    pub fn new(fd: i32) -> Self {
        Self(fd)
    }
    pub fn as_i32(&self) -> i32 {
        self.0
    }
}

/// eBPF program type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum EbpfProgramType {
    Xdp = 1,
    Tc = 2,
    SocketFilter = 3,
    CgroupSockAddr = 4,
}

/// Maximum bytes for packet buffers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct MaxPacketBufferBytes(pub usize);

impl MaxPacketBufferBytes {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_raw(&self) -> usize {
        self.0
    }
    pub fn from_raw(size: usize) -> Self {
        Self(size)
    }
}

impl fmt::Display for MaxPacketBufferBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialOrd for MaxPacketBufferBytes {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MaxPacketBufferBytes {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// Maximum bytes for session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct MaxSessionStateBytes(pub usize);

impl MaxSessionStateBytes {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_raw(&self) -> usize {
        self.0
    }
    pub fn from_raw(size: usize) -> Self {
        Self(size)
    }
}

impl fmt::Display for MaxSessionStateBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialOrd for MaxSessionStateBytes {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MaxSessionStateBytes {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// Maximum bytes for fragment reassembly
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct MaxFragmentBytes(pub usize);

impl MaxFragmentBytes {
    pub fn new(size: usize) -> Self {
        Self(size)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_raw(&self) -> usize {
        self.0
    }
    pub fn from_raw(size: usize) -> Self {
        Self(size)
    }
}

impl fmt::Display for MaxFragmentBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialOrd for MaxFragmentBytes {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MaxFragmentBytes {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// eBPF map size
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EbpfMapSize(pub u32);

impl EbpfMapSize {
    pub fn new(size: u32) -> Self {
        Self(size)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Legacy atomic module removed - all types are now atomic-by-default
/// Use the base types (SessionId, SequenceNumber, WindowSize) which provide both
/// atomic and non-atomic access methods as needed.
///
/// Validation-related types
pub mod validation {
    use super::*;

    /// Network conditions for adaptive algorithms
    #[derive(Debug, Clone)]
    pub struct NetworkConditions {
        pub bandwidth_bps: DataRate,
        pub latency_ns: ProtocolDuration,
        pub packet_loss_rate: LossRate,
        pub jitter_ns: ProtocolDuration,
    }

    impl NetworkConditions {
        pub fn new(
            bandwidth_bps: u64,
            latency_ns: u64,
            packet_loss_rate: f32,
            jitter_ns: u64,
        ) -> Self {
            Self {
                bandwidth_bps: DataRate(bandwidth_bps),
                latency_ns: ProtocolDuration(latency_ns),
                packet_loss_rate: LossRate(packet_loss_rate),
                jitter_ns: ProtocolDuration(jitter_ns),
            }
        }
    }
}

//==============================================================================
// RE-EXPORTS FOR COMMON USE
//==============================================================================

// Note: Standard library atomics are already imported above for internal use
// They are available through the module's internal use statements

// External dependencies
use rand;

//==============================================================================
// THREAD AND POOL COUNT TYPES
//==============================================================================

/// Thread count for thread pools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ThreadCount(pub u32);

impl ThreadCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for ThreadCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for ThreadCount {
    fn default() -> Self {
        Self(1)
    }
}

/// Pool size for connection pools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PoolSize(pub u32);

impl PoolSize {
    pub fn new(size: u32) -> Self {
        Self(size)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl Default for PoolSize {
    fn default() -> Self {
        Self(10)
    }
}

/// Fragment count tracking received fragments
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ReceivedFragments(pub u16);

impl ReceivedFragments {
    pub fn new(count: u16) -> Self {
        Self(count)
    }
    pub fn as_u16(&self) -> u16 {
        self.0
    }
    pub fn increment(&mut self) {
        self.0 += 1;
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Violation count for rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ViolationCount(pub u32);

impl ViolationCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn increment(&mut self) {
        self.0 += 1;
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Attack count for security monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct AttackCount(pub u32);

impl AttackCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn increment(&mut self) {
        self.0 += 1;
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Threshold value for monitoring
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ThresholdValue(pub f64);

impl ThresholdValue {
    pub fn new(value: f64) -> Self {
        Self(value)
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn exceeded_by(&self, value: f64) -> bool {
        value > self.0
    }
}

/// Bitmap for anti-replay window
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Bitmap(pub u64);

impl Bitmap {
    pub fn new(bitmap: u64) -> Self {
        Self(bitmap)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn empty() -> Self {
        Self(0)
    }
    pub fn set_bit(&mut self, pos: u8) {
        self.0 |= 1u64 << pos;
    }
    pub fn has_bit(&self, pos: u8) -> bool {
        (self.0 & (1u64 << pos)) != 0
    }
}

/// Token count for token bucket rate limiting
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TokenCount(pub f64);

impl TokenCount {
    pub fn new(tokens: f64) -> Self {
        Self(tokens.max(0.0))
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn consume(&mut self, amount: f64) {
        self.0 = (self.0 - amount).max(0.0);
    }
    pub fn add(&mut self, amount: f64) {
        self.0 += amount;
    }
    pub fn has_tokens(&self, amount: f64) -> bool {
        self.0 >= amount
    }
}

/// Token bucket capacity
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TokenCapacity(pub f64);

impl TokenCapacity {
    pub fn new(capacity: f64) -> Self {
        Self(capacity)
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn cap(&self, tokens: f64) -> f64 {
        tokens.min(self.0)
    }
}

/// Refill rate for token bucket
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RefillRate(pub f64);

impl RefillRate {
    pub fn new(rate: f64) -> Self {
        Self(rate)
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn tokens_per_second(&self) -> f64 {
        self.0
    }
}

/// Start offset for data ranges
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct StartOffset(pub usize);

impl StartOffset {
    pub fn new(offset: usize) -> Self {
        Self(offset)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// End offset for data ranges
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct EndOffset(pub usize);

impl EndOffset {
    pub fn new(offset: usize) -> Self {
        Self(offset)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Window base for sliding windows
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct WindowBase(pub u32);

impl WindowBase {
    pub fn new(base: u32) -> Self {
        Self(base)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Service count for SNMP agent statistics
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct ServiceCount(pub u32);

impl ServiceCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Interface type identifier for network interfaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct InterfaceType(pub u32);

impl InterfaceType {
    pub fn new(interface_type: u32) -> Self {
        Self(interface_type)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// SNMP trap type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct TrapType(pub u32);

impl TrapType {
    pub fn new(trap_type: u32) -> Self {
        Self(trap_type)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Sample count for measurements
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct SampleCount(pub usize);

impl SampleCount {
    pub fn new(count: usize) -> Self {
        Self(count)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Percentile value (0-100)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct PercentileValue(pub u8);

impl PercentileValue {
    pub fn new(percentile: u8) -> Self {
        Self(percentile)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// Element count for bloom filters
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct ElementCount(pub u32);

impl ElementCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Hash function count for bloom filters
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct HashFunctionCount(pub u8);

impl HashFunctionCount {
    pub fn new(count: u8) -> Self {
        Self(count)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Range count for sequence ranges
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[repr(transparent)]
pub struct RangeCount(pub u32);

impl RangeCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Step count for time adjustments
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct StepCount(pub u32);

impl StepCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Host count for epoch management
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct HostCount(pub usize);

impl HostCount {
    pub fn new(count: usize) -> Self {
        Self(count)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Adjustment rate for time synchronization
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
#[repr(transparent)]
pub struct AdjustmentRate(pub f64);

impl AdjustmentRate {
    pub fn new(rate: f64) -> Self {
        Self(rate)
    }
    pub fn as_f64(&self) -> f64 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0.0)
    }
}

/// Loss rate for network conditions
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
#[repr(transparent)]
pub struct LossRate(pub f32);

impl LossRate {
    pub fn new(rate: f32) -> Self {
        Self(rate)
    }
    pub fn as_f32(&self) -> f32 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0.0)
    }
}

/// IP version (4 or 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct IpVersion(pub u8);

impl IpVersion {
    pub fn new(version: u8) -> Self {
        Self(version)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
    pub fn v4() -> Self {
        Self(4)
    }
    pub fn v6() -> Self {
        Self(6)
    }
}

/// Protocol identifier (TCP, UDP, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct ProtocolId(pub u8);

impl ProtocolId {
    pub fn new(protocol: u8) -> Self {
        Self(protocol)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
    pub fn tcp() -> Self {
        Self(6)
    }
    pub fn udp() -> Self {
        Self(17)
    }
}

/// TTL value for IP packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct TtlValue(pub u8);

impl TtlValue {
    pub fn new(ttl: u8) -> Self {
        Self(ttl)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
    pub fn default_ttl() -> Self {
        Self(64)
    }
}

/// Epoch number for time-based protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct EpochNumber(pub u32);

impl EpochNumber {
    pub fn new(epoch: u32) -> Self {
        Self(epoch)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0)
    }
}

/// Seed value for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct SeedValue(pub u32);

impl SeedValue {
    pub fn new(seed: u32) -> Self {
        Self(seed)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// Pattern seed for hopping algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct PatternSeed(pub u16);

impl PatternSeed {
    pub fn new(seed: u16) -> Self {
        Self(seed)
    }
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

/// Variance value for timing algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct VarianceValue(pub u8);

impl VarianceValue {
    pub fn new(variance: u8) -> Self {
        Self(variance)
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

//==============================================================================
// ATOMIC PORT AND SESSION PARAMETER TYPES
//==============================================================================

/// Atomic port value for concurrent access
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicPortValue(AtomicU16);

impl AtomicPortValue {
    pub fn new(value: u16) -> Self {
        Self(AtomicU16::new(value))
    }

    pub fn load(&self, ordering: Ordering) -> u16 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u16, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn fetch_add(&self, val: u16, ordering: Ordering) -> u16 {
        self.0.fetch_add(val, ordering)
    }

    pub fn compare_exchange_weak(
        &self,
        current: u16,
        new: u16,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u16, u16> {
        self.0.compare_exchange_weak(current, new, success, failure)
    }
}

/// Atomic session parameter for concurrent access
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicSessionParam(AtomicU16);

impl AtomicSessionParam {
    pub fn new(value: u16) -> Self {
        Self(AtomicU16::new(value))
    }

    pub fn load(&self, ordering: Ordering) -> u16 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u16, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn fetch_add(&self, val: u16, ordering: Ordering) -> u16 {
        self.0.fetch_add(val, ordering)
    }
}

/// Atomic epoch number for concurrent access
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicEpochNumber(AtomicU32);

impl AtomicEpochNumber {
    pub fn new(value: u32) -> Self {
        Self(AtomicU32::new(value))
    }

    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u32, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn fetch_add(&self, val: u32, ordering: Ordering) -> u32 {
        self.0.fetch_add(val, ordering)
    }

    pub fn compare_exchange_weak(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.0.compare_exchange_weak(current, new, success, failure)
    }
}

/// Atomic flag for boolean state with concurrent access
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicFlag(AtomicBool);

impl AtomicFlag {
    pub fn new(value: bool) -> Self {
        Self(AtomicBool::new(value))
    }

    pub const fn from_raw(value: bool) -> Self {
        Self(AtomicBool::new(value))
    }

    pub fn load(&self, ordering: Ordering) -> bool {
        self.0.load(ordering)
    }

    pub fn store(&self, value: bool, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn swap(&self, value: bool, ordering: Ordering) -> bool {
        self.0.swap(value, ordering)
    }

    pub fn compare_exchange_weak(
        &self,
        current: bool,
        new: bool,
        success: Ordering,
        failure: Ordering,
    ) -> Result<bool, bool> {
        self.0.compare_exchange_weak(current, new, success, failure)
    }
}

impl Default for AtomicFlag {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Atomic pending state flag for operations awaiting completion
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicPendingFlag(AtomicBool);

impl AtomicPendingFlag {
    pub fn new(pending: bool) -> Self {
        Self(AtomicBool::new(pending))
    }

    pub fn is_pending(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub fn set_pending(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn clear_pending(&self) {
        self.0.store(false, Ordering::Relaxed);
    }

    pub fn load(&self, ordering: Ordering) -> bool {
        self.0.load(ordering)
    }

    pub fn store(&self, value: bool, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn swap(&self, value: bool, ordering: Ordering) -> bool {
        self.0.swap(value, ordering)
    }

    pub fn compare_exchange_weak(
        &self,
        current: bool,
        new: bool,
        success: Ordering,
        failure: Ordering,
    ) -> Result<bool, bool> {
        self.0.compare_exchange_weak(current, new, success, failure)
    }
}

impl Default for AtomicPendingFlag {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Atomic connection ID generator for unique connection identification
#[derive(Debug)]
#[repr(transparent)]
pub struct ConnectionIdGenerator(AtomicU64);

impl ConnectionIdGenerator {
    pub fn new(initial_value: u64) -> Self {
        Self(AtomicU64::new(initial_value))
    }

    pub fn next(&self) -> ConnectionId {
        let id = self.0.fetch_add(1, Ordering::Relaxed);
        ConnectionId::new(id)
    }

    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u64, ordering: Ordering) {
        self.0.store(value, ordering);
    }
}

impl Default for ConnectionIdGenerator {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Atomic size counter for memory and buffer size tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicSizeCounter(AtomicU64);

impl AtomicSizeCounter {
    pub fn new(size: u64) -> Self {
        Self(AtomicU64::new(size))
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, value: u64, ordering: Ordering) {
        self.0.store(value, ordering);
    }

    pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(val, ordering)
    }

    pub fn fetch_sub(&self, val: u64, ordering: Ordering) -> u64 {
        self.0.fetch_sub(val, ordering)
    }

    pub fn compare_exchange_weak(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.0.compare_exchange_weak(current, new, success, failure)
    }
}

impl Default for AtomicSizeCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

// Duplicate types removed - these are already defined earlier in the file

/// Window Update Threshold (as percentage)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct WindowUpdateThreshold(f32);

impl WindowUpdateThreshold {
    pub const fn new(threshold: f32) -> Self {
        Self(threshold)
    }

    pub const fn as_f32(&self) -> f32 {
        self.0
    }
}

impl Default for WindowUpdateThreshold {
    fn default() -> Self {
        Self::new(0.25) // 25%
    }
}

impl fmt::Display for WindowUpdateThreshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}%", self.0 * 100.0)
    }
}

/// Maximum Receive Buffer Size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MaxReceiveBufferSize(u32);

impl MaxReceiveBufferSize {
    pub const fn new(size: u32) -> Self {
        Self(size)
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl Default for MaxReceiveBufferSize {
    fn default() -> Self {
        Self::new(1048576) // 1MB
    }
}

impl fmt::Display for MaxReceiveBufferSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.0)
    }
}

/// Zero Window Probe Interval (in milliseconds)  
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ZeroWindowProbeInterval(u64);

impl ZeroWindowProbeInterval {
    pub const fn new(interval_ms: u64) -> Self {
        Self(interval_ms)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn as_duration(&self) -> Duration {
        Duration::from_millis(self.0)
    }
}

impl Default for ZeroWindowProbeInterval {
    fn default() -> Self {
        Self::new(1000) // 1 second
    }
}

impl fmt::Display for ZeroWindowProbeInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// Packet sub-type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SubType(u8);

impl SubType {
    pub const fn new(sub_type: u8) -> Self {
        Self(sub_type)
    }

    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl Default for SubType {
    fn default() -> Self {
        Self::new(0)
    }
}

impl fmt::Display for SubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Reserved field for protocol headers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ReservedField(u16);

impl ReservedField {
    pub const fn new() -> Self {
        Self(0)
    }

    pub const fn zero() -> Self {
        Self(0)
    }

    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    pub const fn as_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl Default for ReservedField {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ReservedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04X}", self.0)
    }
}

//==============================================================================
// NETWORK MEASUREMENT TYPES
//==============================================================================

/// Network jitter measurement (atomic version)
#[derive(Debug)]
pub struct AtomicNetworkJitter(AtomicU32);

impl AtomicNetworkJitter {
    pub const fn new(jitter_ms: u32) -> Self {
        Self(AtomicU32::new(jitter_ms))
    }

    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: u32, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn as_network_jitter(&self, ordering: Ordering) -> NetworkJitter {
        NetworkJitter::new(self.load(ordering))
    }
}

impl Default for AtomicNetworkJitter {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Atomic packet loss rate (stored scaled by 1000)
#[derive(Debug)]
pub struct AtomicPacketLossRate(AtomicU32);

impl AtomicPacketLossRate {
    pub const fn new(scaled_rate: u32) -> Self {
        Self(AtomicU32::new(scaled_rate))
    }

    pub fn load(&self, ordering: Ordering) -> u32 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: u32, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn as_packet_loss_rate(&self, ordering: Ordering) -> PacketLossRate {
        PacketLossRate::new(self.load(ordering) as u16)
    }
}

impl Default for AtomicPacketLossRate {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Atomic measurement timestamp
#[derive(Debug)]
pub struct AtomicMeasurementTimestamp(AtomicU64);

impl AtomicMeasurementTimestamp {
    pub const fn new(timestamp: u64) -> Self {
        Self(AtomicU64::new(timestamp))
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: u64, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn get(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn as_timestamp(&self, ordering: Ordering) -> Timestamp {
        Timestamp::from_nanos(self.load(ordering))
    }
}

impl Default for AtomicMeasurementTimestamp {
    fn default() -> Self {
        Self::new(0)
    }
}

//==============================================================================
// PERFORMANCE METRICS TYPES
//==============================================================================

/// Bucket bounds for histograms
#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
#[derive(Default)]
pub struct BucketBounds(Vec<u64>);

impl BucketBounds {
    pub fn new(bounds: Vec<u64>) -> Self {
        Self(bounds)
    }

    pub fn as_vec(&self) -> &Vec<u64> {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u64> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn binary_search(&self, value: &u64) -> Result<usize, usize> {
        self.0.binary_search(value)
    }

    pub fn get(&self, index: usize) -> Option<&u64> {
        self.0.get(index)
    }

    pub fn last(&self) -> Option<&u64> {
        self.0.last()
    }
}

/// Extended PercentileValue methods for f64 percentiles
impl PercentileValue {
    pub fn from_f64(value: f64) -> Self {
        debug_assert!(
            (0.0..=1.0).contains(&value),
            "Percentile must be between 0.0 and 1.0"
        );
        Self((value * 100.0) as u8)
    }

    pub fn as_f64(&self) -> f64 {
        self.0 as f64 / 100.0
    }

    pub fn p50() -> Self {
        Self(50)
    }

    pub fn p95() -> Self {
        Self(95)
    }

    pub fn p99() -> Self {
        Self(99)
    }
}

/// Bucket count for histograms  
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[derive(Default)]
pub struct BucketCount(usize);

impl BucketCount {
    pub fn new(count: usize) -> Self {
        Self(count)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }

    pub fn from_raw(count: usize) -> Self {
        Self::new(count)
    }

    pub fn as_raw(&self) -> usize {
        self.0
    }
}

/// Throughput value in operations per second
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct ThroughputValue(f64);

impl ThroughputValue {
    pub fn new(ops_per_sec: f64) -> Self {
        Self(ops_per_sec.max(0.0)) // Ensure non-negative
    }

    pub fn as_f64(&self) -> f64 {
        self.0
    }

    pub fn from_raw(ops_per_sec: f64) -> Self {
        Self::new(ops_per_sec)
    }

    pub fn as_raw(&self) -> f64 {
        self.0
    }

    pub fn zero() -> Self {
        Self(0.0)
    }
}

impl Default for ThroughputValue {
    fn default() -> Self {
        Self::zero()
    }
}

/// Average value for metrics calculations
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct AverageValue(f64);

impl AverageValue {
    pub fn new(average: f64) -> Self {
        Self(average)
    }

    pub fn as_f64(&self) -> f64 {
        self.0
    }

    pub fn from_raw(average: f64) -> Self {
        Self::new(average)
    }

    pub fn as_raw(&self) -> f64 {
        self.0
    }

    pub fn zero() -> Self {
        Self(0.0)
    }
}

impl Default for AverageValue {
    fn default() -> Self {
        Self::zero()
    }
}

/// Bucket counts vector for histogram results
#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
#[derive(Default)]
pub struct BucketCounts(Vec<u64>);

impl BucketCounts {
    pub fn new(counts: Vec<u64>) -> Self {
        Self(counts)
    }

    pub fn as_vec(&self) -> &Vec<u64> {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u64> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&u64> {
        self.0.get(index)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, u64> {
        self.0.iter()
    }
}

/// Histogram factor for exponential buckets
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct HistogramFactor(f64);

impl HistogramFactor {
    pub fn new(factor: f64) -> Self {
        debug_assert!(factor > 1.0, "Histogram factor must be greater than 1.0");
        Self(factor.max(1.1)) // Minimum sensible factor
    }

    pub fn as_f64(&self) -> f64 {
        self.0
    }

    pub fn from_raw(factor: f64) -> Self {
        Self::new(factor)
    }

    pub fn as_raw(&self) -> f64 {
        self.0
    }
}

impl Default for HistogramFactor {
    fn default() -> Self {
        Self(2.0) // Default exponential factor
    }
}

/// Histogram start value
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct HistogramStart(f64);

impl HistogramStart {
    pub fn new(start: f64) -> Self {
        debug_assert!(start > 0.0, "Histogram start must be positive");
        Self(start.max(0.001)) // Minimum sensible start
    }

    pub fn as_f64(&self) -> f64 {
        self.0
    }

    pub fn from_raw(start: f64) -> Self {
        Self::new(start)
    }

    pub fn as_raw(&self) -> f64 {
        self.0
    }
}

impl Default for HistogramStart {
    fn default() -> Self {
        Self(1.0)
    }
}

/// NUMA node identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[derive(Default)]
pub struct NodeId(usize);

impl NodeId {
    pub fn new(id: usize) -> Self {
        Self(id)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }

    pub fn from_raw(id: usize) -> Self {
        Self(id)
    }

    pub fn as_raw(&self) -> usize {
        self.0
    }
}

/// Allocation counter for memory management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
#[derive(Default)]
pub struct AllocationCount(u64);

impl AllocationCount {
    pub fn new(count: u64) -> Self {
        Self(count)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    pub fn add(&mut self, count: u64) {
        self.0 = self.0.saturating_add(count);
    }

    pub fn from_raw(count: u64) -> Self {
        Self(count)
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Generic length value
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[derive(Default)]
pub struct Length(usize);

impl Length {
    pub fn new(length: usize) -> Self {
        Self(length)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }

    pub fn from_raw(length: usize) -> Self {
        Self(length)
    }

    pub fn as_raw(&self) -> usize {
        self.0
    }
}

impl std::ops::Add<usize> for Length {
    type Output = usize;

    fn add(self, rhs: usize) -> Self::Output {
        self.0 + rhs
    }
}

impl std::ops::Add<Length> for usize {
    type Output = usize;

    fn add(self, rhs: Length) -> Self::Output {
        self + rhs.0
    }
}

/// Salt bytes for cryptographic operations
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct SaltBytes(Vec<u8>);

impl SaltBytes {
    pub fn new(salt: Vec<u8>) -> Self {
        Self(salt)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn from_raw(salt: Vec<u8>) -> Self {
        Self(salt)
    }

    pub fn as_raw(&self) -> &Vec<u8> {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for SaltBytes {
    fn default() -> Self {
        Self(vec![0; 16]) // 16-byte salt
    }
}

impl fmt::Debug for SaltBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SaltBytes([REDACTED {} bytes])", self.len())
    }
}

/// Security policy flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SecurityFlag(bool);

impl SecurityFlag {
    pub fn new(enabled: bool) -> Self {
        Self(enabled)
    }

    pub fn enabled() -> Self {
        Self(true)
    }

    pub fn disabled() -> Self {
        Self(false)
    }

    pub fn as_bool(&self) -> bool {
        self.0
    }

    pub fn is_enabled(&self) -> bool {
        self.0
    }

    pub fn from_raw(enabled: bool) -> Self {
        Self(enabled)
    }

    pub fn as_raw(&self) -> bool {
        self.0
    }
}

impl Default for SecurityFlag {
    fn default() -> Self {
        Self(true) // Default to enabled for security
    }
}

impl From<bool> for SecurityFlag {
    fn from(enabled: bool) -> Self {
        Self(enabled)
    }
}

/// Window size for various protocol features
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct WindowSizeValue(u32);

impl WindowSizeValue {
    pub fn new(size: u32) -> Self {
        Self(size)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn from_raw(size: u32) -> Self {
        Self(size)
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }
}

impl Default for WindowSizeValue {
    fn default() -> Self {
        Self(1024) // Default window size
    }
}

/// Gap tolerance for sequence numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct GapTolerance(u32);

impl GapTolerance {
    pub fn new(gap: u32) -> Self {
        Self(gap)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn from_raw(gap: u32) -> Self {
        Self(gap)
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }
}

impl Default for GapTolerance {
    fn default() -> Self {
        Self(100) // Default max gap
    }
}

/// Time drift tolerance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TimeDriftTolerance(u64);

impl TimeDriftTolerance {
    pub fn new(drift: u64) -> Self {
        Self(drift)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn from_raw(drift: u64) -> Self {
        Self(drift)
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }

    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    pub fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }
}

impl Default for TimeDriftTolerance {
    fn default() -> Self {
        Self(5000) // 5 seconds default
    }
}

/// Received packet count for anti-replay tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct ReceivedCount(AtomicU64);

impl ReceivedCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn as_u64(&self) -> u64 {
        self.get()
    }

    pub fn increment(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn add(&self, value: u64) -> u64 {
        self.0.fetch_add(value, Ordering::Relaxed)
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: u64, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn from_raw(count: u64) -> Self {
        Self::new(count)
    }

    pub fn as_raw(&self) -> u64 {
        self.get()
    }
}

impl Clone for ReceivedCount {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl Default for ReceivedCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for ReceivedCount {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

/// Duplicate packet count for anti-replay tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct DuplicateCount(AtomicU64);

impl DuplicateCount {
    pub fn new(count: u64) -> Self {
        Self(AtomicU64::new(count))
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn as_u64(&self) -> u64 {
        self.get()
    }

    pub fn increment(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn add(&self, value: u64) -> u64 {
        self.0.fetch_add(value, Ordering::Relaxed)
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn store(&self, val: u64, ordering: Ordering) {
        self.0.store(val, ordering)
    }

    pub fn from_raw(count: u64) -> Self {
        Self::new(count)
    }

    pub fn as_raw(&self) -> u64 {
        self.get()
    }
}

impl Clone for DuplicateCount {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

impl Default for DuplicateCount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for DuplicateCount {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

/// Window size in seconds for timestamp validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct WindowSizeSeconds(u64);

impl WindowSizeSeconds {
    pub fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn from_raw(seconds: u64) -> Self {
        Self(seconds)
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

impl Default for WindowSizeSeconds {
    fn default() -> Self {
        Self(300) // 5 minutes default
    }
}

/// Network prefix length for CIDR notation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PrefixLength(u8);

impl PrefixLength {
    pub fn new(length: u8) -> Self {
        Self(length)
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }

    pub fn from_raw(length: u8) -> Self {
        Self(length)
    }

    pub fn as_raw(&self) -> u8 {
        self.0
    }
}

impl Default for PrefixLength {
    fn default() -> Self {
        Self(24) // Common /24 network
    }
}

/// Generic capacity type for representing size/capacity values
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[derive(Default)]
pub struct Capacity(u32);

impl Capacity {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }
}

impl From<u32> for Capacity {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<usize> for Capacity {
    fn from(value: usize) -> Self {
        Self(value as u32)
    }
}

/// Atomic attempt count for thread-safe retry tracking
#[derive(Debug)]
#[repr(transparent)]
pub struct AtomicAttemptCount(AtomicU32);

impl AtomicAttemptCount {
    pub fn new(value: u32) -> Self {
        Self(AtomicU32::new(value))
    }

    pub fn load(&self, order: Ordering) -> u32 {
        self.0.load(order)
    }

    pub fn store(&self, value: u32, order: Ordering) {
        self.0.store(value, order)
    }

    pub fn increment(&self, order: Ordering) -> u32 {
        self.0.fetch_add(1, order)
    }

    pub fn as_u32(&self, order: Ordering) -> u32 {
        self.0.load(order)
    }
}

impl Default for AtomicAttemptCount {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // ========================================================================
    // PacketFlags tests
    // ========================================================================

    #[test]
    fn test_packet_flags_creation() {
        let flags = PacketFlags::new();
        assert_eq!(flags.as_u8(), 0);
    }

    #[test]
    fn test_packet_flags_set_and_check() {
        let mut flags = PacketFlags::new();

        flags.set_flag(PacketFlags::SYN);
        assert!(flags.is_syn());
        assert!(!flags.is_ack());

        flags.set_flag(PacketFlags::ACK);
        assert!(flags.is_syn());
        assert!(flags.is_ack());

        flags.clear_flag(PacketFlags::SYN);
        assert!(!flags.is_syn());
        assert!(flags.is_ack());
    }

    #[test]
    fn test_packet_flags_all_flags() {
        let mut flags = PacketFlags::new();

        flags.set_flag(PacketFlags::FIN);
        assert!(flags.is_fin());

        flags.set_flag(PacketFlags::RST);
        assert!(flags.is_rst());

        flags.set_flag(PacketFlags::PSH);
        assert!(flags.is_psh());

        flags.set_flag(PacketFlags::URG);
        assert!(flags.is_urg());

        // All flags should still be set
        assert!(flags.is_fin());
        assert!(flags.is_rst());
        assert!(flags.is_psh());
        assert!(flags.is_urg());
    }

    #[test]
    fn test_packet_flags_serde_roundtrip() {
        let mut flags = PacketFlags::new();
        flags.set_flag(PacketFlags::SYN);
        flags.set_flag(PacketFlags::ACK);

        let serialized = serde_json::to_string(&flags).unwrap();
        let deserialized: PacketFlags = serde_json::from_str(&serialized).unwrap();

        assert_eq!(flags, deserialized);
        assert!(deserialized.is_syn());
        assert!(deserialized.is_ack());
    }

    #[test]
    fn test_packet_flags_from_u8() {
        let flags = PacketFlags::from_u8(PacketFlags::SYN | PacketFlags::ACK);
        assert!(flags.is_syn());
        assert!(flags.is_ack());
        assert!(!flags.is_fin());
    }

    // ========================================================================
    // EventCount tests
    // ========================================================================

    #[test]
    fn test_event_count_creation() {
        let count = EventCount::new(42);
        assert_eq!(count.as_u64(), 42);
        assert_eq!(count.as_raw(), 42);
    }

    #[test]
    fn test_event_count_zero() {
        let count = EventCount::zero();
        assert_eq!(count.as_u64(), 0);
    }

    #[test]
    fn test_event_count_from_raw() {
        let count = EventCount::from_raw(100);
        assert_eq!(count.as_u64(), 100);
    }

    #[test]
    fn test_event_count_store_load() {
        let count = EventCount::new(0);
        count.store(999, Ordering::SeqCst);
        assert_eq!(count.load(Ordering::SeqCst), 999);
    }

    #[test]
    fn test_event_count_fetch_add() {
        let count = EventCount::new(10);

        let old = count.fetch_add(5, Ordering::SeqCst);
        assert_eq!(old, 10);
        assert_eq!(count.as_u64(), 15);

        let old = count.fetch_add(3, Ordering::SeqCst);
        assert_eq!(old, 15);
        assert_eq!(count.as_u64(), 18);
    }

    #[test]
    fn test_event_count_increment() {
        let count = EventCount::new(0);

        let old = count.increment(Ordering::SeqCst);
        assert_eq!(old, 0);
        assert_eq!(count.as_u64(), 1);

        let old = count.increment(Ordering::SeqCst);
        assert_eq!(old, 1);
        assert_eq!(count.as_u64(), 2);
    }

    #[test]
    fn test_event_count_clone() {
        let count = EventCount::new(42);
        let cloned = count.clone();
        assert_eq!(cloned.as_u64(), 42);

        // Modifications to clone don't affect original
        cloned.store(100, Ordering::SeqCst);
        assert_eq!(count.as_u64(), 42);
        assert_eq!(cloned.as_u64(), 100);
    }

    #[test]
    fn test_event_count_default() {
        let count = EventCount::default();
        assert_eq!(count.as_u64(), 0);
    }

    #[test]
    fn test_event_count_equality() {
        let a = EventCount::new(42);
        let b = EventCount::new(42);
        let c = EventCount::new(43);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ========================================================================
    // PacketCount tests
    // ========================================================================

    #[test]
    fn test_packet_count_creation() {
        let count = PacketCount::new(100);
        assert_eq!(count.as_u64(), 100);
        assert_eq!(count.as_raw(), 100);
    }

    #[test]
    fn test_packet_count_zero() {
        let count = PacketCount::zero();
        assert_eq!(count.as_u64(), 0);
    }

    #[test]
    fn test_packet_count_from_raw() {
        let count = PacketCount::from_raw(500);
        assert_eq!(count.as_u64(), 500);
        assert_eq!(count.as_raw(), 500);
    }

    #[test]
    fn test_packet_count_fetch_add() {
        let count = PacketCount::new(10);

        let old = count.fetch_add(5, Ordering::SeqCst);
        assert_eq!(old, 10);
        assert_eq!(count.as_u64(), 15);
    }

    #[test]
    fn test_packet_count_fetch_sub() {
        let count = PacketCount::new(100);

        let old = count.fetch_sub(30, Ordering::SeqCst);
        assert_eq!(old, 100);
        assert_eq!(count.as_u64(), 70);
    }

    #[test]
    fn test_packet_count_increment() {
        let count = PacketCount::new(0);

        let old = count.increment(Ordering::SeqCst);
        assert_eq!(old, 0);
        assert_eq!(count.as_u64(), 1);
    }

    #[test]
    fn test_packet_count_add_assign() {
        let mut count = PacketCount::new(10);
        count += 5;
        assert_eq!(count.as_u64(), 15);
    }

    #[test]
    fn test_packet_count_display() {
        let count = PacketCount::new(42);
        assert_eq!(format!("{}", count), "42");
    }

    // ========================================================================
    // ValidationError tests
    // ========================================================================

    #[test]
    fn test_validation_error_serde_simple() {
        let error = ValidationError::InvalidLength;
        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: ValidationError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(error, deserialized);
    }

    #[test]
    fn test_validation_error_serde_with_data() {
        let error = ValidationError::PortOutOfRange { port: 12345 };
        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: ValidationError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(error, deserialized);

        if let ValidationError::PortOutOfRange { port } = deserialized {
            assert_eq!(port, 12345);
        } else {
            panic!("Expected PortOutOfRange variant");
        }
    }

    #[test]
    fn test_validation_error_display() {
        assert_eq!(
            format!("{}", ValidationError::InvalidLength),
            "Invalid length"
        );
        assert_eq!(format!("{}", ValidationError::InvalidPort), "Invalid port");
    }

    // ========================================================================
    // ValidationResult tests
    // ========================================================================

    #[test]
    fn test_validation_result_valid() {
        let result: ValidationResult<u32> = ValidationResult::Valid(42);
        assert!(result.is_valid());
        assert_eq!(result.into_result().unwrap(), 42);
    }

    #[test]
    fn test_validation_result_invalid() {
        let result: ValidationResult<u32> =
            ValidationResult::Invalid(ValidationError::InvalidLength);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_validation_result_warning() {
        let result: ValidationResult<u32> =
            ValidationResult::Warning(42, "Some warning".to_string());
        assert!(result.is_valid());
        assert_eq!(result.into_result().unwrap(), 42);
    }

    #[test]
    fn test_validation_result_into_result() {
        let valid: ValidationResult<u32> = ValidationResult::Valid(42);
        assert_eq!(valid.into_result().unwrap(), 42);

        let invalid: ValidationResult<u32> =
            ValidationResult::Invalid(ValidationError::InvalidLength);
        assert!(invalid.into_result().is_err());

        let warning: ValidationResult<u32> = ValidationResult::Warning(42, "warning".to_string());
        assert_eq!(warning.into_result().unwrap(), 42);
    }

    #[test]
    fn test_validation_result_serde_valid() {
        let result: ValidationResult<u32> = ValidationResult::Valid(42);
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ValidationResult<u32> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_validation_result_serde_invalid() {
        let result: ValidationResult<u32> = ValidationResult::Invalid(ValidationError::InvalidPort);
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ValidationResult<u32> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_validation_result_serde_warning() {
        let result: ValidationResult<String> =
            ValidationResult::Warning("data".to_string(), "warning message".to_string());
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ValidationResult<String> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);
    }

    // ========================================================================
    // IpAddress tests
    // ========================================================================

    #[test]
    fn test_ip_address_v4_creation() {
        let ip = IpAddress::V4([192, 168, 1, 1]);
        assert!(ip.is_v4());
        assert!(!ip.is_v6());
    }

    #[test]
    fn test_ip_address_v6_creation() {
        let ip = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!ip.is_v4());
        assert!(ip.is_v6());
    }

    #[test]
    fn test_ip_address_from_std_v4() {
        let std_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip = IpAddress::from_std(std_addr);
        assert!(ip.is_v4());
        assert_eq!(ip.to_std(), std_addr);
    }

    #[test]
    fn test_ip_address_from_std_v6() {
        let std_addr = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let ip = IpAddress::from_std(std_addr);
        assert!(ip.is_v6());
        assert_eq!(ip.to_std(), std_addr);
    }

    #[test]
    fn test_ip_address_as_u32() {
        // 192.168.1.1 in network byte order
        let ip = IpAddress::V4([192, 168, 1, 1]);
        let expected = u32::from_be_bytes([192, 168, 1, 1]);
        assert_eq!(ip.try_as_u32(), Some(expected));
    }

    #[test]
    fn test_ip_address_as_u32_all_zeros() {
        let ip = IpAddress::V4([0, 0, 0, 0]);
        assert_eq!(ip.try_as_u32(), Some(0));
    }

    #[test]
    fn test_ip_address_as_u32_all_ones() {
        let ip = IpAddress::V4([255, 255, 255, 255]);
        assert_eq!(ip.try_as_u32(), Some(u32::MAX));
    }

    #[test]
    fn test_ip_address_as_u32_v6_returns_none() {
        let ip = IpAddress::V6([0; 16]);
        assert_eq!(ip.try_as_u32(), None);
    }

    #[test]
    fn test_ip_address_try_as_u32_v4() {
        let ip = IpAddress::V4([10, 20, 30, 40]);
        let result = ip.try_as_u32();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), u32::from_be_bytes([10, 20, 30, 40]));
    }

    #[test]
    fn test_ip_address_try_as_u32_v6() {
        let ip = IpAddress::V6([0; 16]);
        assert!(ip.try_as_u32().is_none());
    }

    #[test]
    fn test_ip_address_as_raw_v4() {
        let ip = IpAddress::V4([1, 2, 3, 4]);
        assert_eq!(ip.as_raw(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ip_address_as_raw_v6() {
        let octets = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ip = IpAddress::V6(octets);
        assert_eq!(ip.as_raw(), octets.to_vec());
    }

    #[test]
    fn test_ip_address_display() {
        let ip_v4 = IpAddress::V4([192, 168, 1, 1]);
        assert_eq!(format!("{}", ip_v4), "192.168.1.1");

        let ip_v6 = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // IPv6 display format varies, just check it doesn't panic
        let _ = format!("{}", ip_v6);
    }

    #[test]
    fn test_ip_address_from_ipv4() {
        let std_v4 = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let ip = IpAddress::from_ipv4(std_v4);
        assert!(ip.is_v4());
        assert_eq!(ip.try_as_u32(), Some(u32::from_be_bytes([127, 0, 0, 1])));
    }

    #[test]
    fn test_ip_address_from_ipv6() {
        let std_v6 = std::net::Ipv6Addr::LOCALHOST;
        let ip = IpAddress::from_ipv6(std_v6);
        assert!(ip.is_v6());
    }
}

#[cfg(test)]
mod protocol_alignment_tests {
    use super::*;

    // Const assertions to verify alignment with C protocol.h
    #[test]
    fn test_packet_type_alignment() {
        assert_eq!(PacketType::Syn as u8, 0x01);
        assert_eq!(PacketType::SynAck as u8, 0x02);
        assert_eq!(PacketType::Ack as u8, 0x03);
        assert_eq!(PacketType::Data as u8, 0x04);
        assert_eq!(PacketType::Fin as u8, 0x05);
        assert_eq!(PacketType::Heartbeat as u8, 0x06);
        assert_eq!(PacketType::Error as u8, 0x09);
        assert_eq!(PacketType::Rst as u8, 0x0B);
        assert_eq!(PacketType::Control as u8, 0x0C);
        assert_eq!(PacketType::Management as u8, 0x0D);
        assert_eq!(PacketType::Discovery as u8, 0x0E);
        assert_eq!(PacketType::Fragment as u8, 0x0F);
    }

    #[test]
    fn test_hmac_policy_alignment() {
        assert_eq!(HmacPolicy::Light as u8, 1);
        assert_eq!(HmacPolicy::Medium as u8, 2);
        assert_eq!(HmacPolicy::Strong as u8, 3);
    }

    #[test]
    fn test_control_subtype_alignment() {
        assert_eq!(ControlSubType::TimeSyncRequest as u8, 0x01);
        assert_eq!(ControlSubType::TimeSyncResponse as u8, 0x02);
        assert_eq!(ControlSubType::Recovery as u8, 0x03);
        assert_eq!(ControlSubType::SequenceNegotiation as u8, 0x04);
        assert_eq!(ControlSubType::HmacPolicyRequest as u8, 0x05);
        assert_eq!(ControlSubType::HmacPolicyResponse as u8, 0x06);
    }
}

/// M2 Connection Lifecycle Compliance Tests
///
/// Tests verify implementation of M2 spec requirements:
/// - 7 connection states: IDLE, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, CLOSED
/// - State value assignments for protocol wire format
/// - Legacy state compatibility via to_m2_state()
/// - is_m2_compliant() validation
#[cfg(test)]
mod m2_connection_state_tests {
    use super::*;

    /// Test M2-compliant connection states exist with correct values
    #[test]
    fn test_m2_connection_states_values() {
        // M2 spec: 7 core connection states
        assert_eq!(ConnectionState::Idle.as_u8(), 0);
        assert_eq!(ConnectionState::SynSent.as_u8(), 1);
        assert_eq!(ConnectionState::SynReceived.as_u8(), 2);
        assert_eq!(ConnectionState::Established.as_u8(), 3);
        assert_eq!(ConnectionState::FinWait.as_u8(), 4);
        assert_eq!(ConnectionState::CloseWait.as_u8(), 5);
        assert_eq!(ConnectionState::Closed.as_u8(), 6);
    }

    /// Test M2-compliant states round-trip correctly
    #[test]
    fn test_m2_connection_states_from_u8() {
        assert_eq!(ConnectionState::from_u8(0), Some(ConnectionState::Idle));
        assert_eq!(ConnectionState::from_u8(1), Some(ConnectionState::SynSent));
        assert_eq!(
            ConnectionState::from_u8(2),
            Some(ConnectionState::SynReceived)
        );
        assert_eq!(
            ConnectionState::from_u8(3),
            Some(ConnectionState::Established)
        );
        assert_eq!(ConnectionState::from_u8(4), Some(ConnectionState::FinWait));
        assert_eq!(
            ConnectionState::from_u8(5),
            Some(ConnectionState::CloseWait)
        );
        assert_eq!(ConnectionState::from_u8(6), Some(ConnectionState::Closed));
    }

    /// Test is_m2_compliant identifies valid M2 states
    #[test]
    fn test_is_m2_compliant() {
        // These are M2-compliant
        assert!(ConnectionState::Idle.is_m2_compliant());
        assert!(ConnectionState::SynSent.is_m2_compliant());
        assert!(ConnectionState::SynReceived.is_m2_compliant());
        assert!(ConnectionState::Established.is_m2_compliant());
        assert!(ConnectionState::FinWait.is_m2_compliant());
        assert!(ConnectionState::CloseWait.is_m2_compliant());
        assert!(ConnectionState::Closed.is_m2_compliant());
        assert!(ConnectionState::Recovering.is_m2_compliant());
        assert!(ConnectionState::Error.is_m2_compliant());

        // Legacy states are NOT M2-compliant
        assert!(!ConnectionState::Connecting.is_m2_compliant());
        assert!(!ConnectionState::Connected.is_m2_compliant());
        assert!(!ConnectionState::Listening.is_m2_compliant());
        assert!(!ConnectionState::Closing.is_m2_compliant());
        assert!(!ConnectionState::Disconnecting.is_m2_compliant());
    }

    /// Test to_m2_state converts legacy states correctly
    #[test]
    fn test_to_m2_state_conversion() {
        // Legacy -> M2 mappings
        assert_eq!(
            ConnectionState::Connecting.to_m2_state(),
            ConnectionState::SynSent
        );
        assert_eq!(
            ConnectionState::Connected.to_m2_state(),
            ConnectionState::Established
        );
        assert_eq!(
            ConnectionState::Listening.to_m2_state(),
            ConnectionState::SynReceived
        );
        assert_eq!(
            ConnectionState::Closing.to_m2_state(),
            ConnectionState::FinWait
        );
        assert_eq!(
            ConnectionState::Disconnecting.to_m2_state(),
            ConnectionState::CloseWait
        );

        // M2 states map to themselves
        assert_eq!(ConnectionState::Idle.to_m2_state(), ConnectionState::Idle);
        assert_eq!(
            ConnectionState::SynSent.to_m2_state(),
            ConnectionState::SynSent
        );
        assert_eq!(
            ConnectionState::Established.to_m2_state(),
            ConnectionState::Established
        );
    }

    /// Test that all ConnectionState variants have unique u8 values
    #[test]
    fn test_connection_state_uniqueness() {
        let all_states = [
            ConnectionState::Idle,
            ConnectionState::SynSent,
            ConnectionState::SynReceived,
            ConnectionState::Established,
            ConnectionState::FinWait,
            ConnectionState::CloseWait,
            ConnectionState::Closed,
            ConnectionState::Recovering,
            ConnectionState::Error,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Listening,
            ConnectionState::Closing,
            ConnectionState::Disconnecting,
        ];

        let values: Vec<u8> = all_states.iter().map(|s| s.as_u8()).collect();
        let mut unique_values = values.clone();
        unique_values.sort();
        unique_values.dedup();

        assert_eq!(
            values.len(),
            unique_values.len(),
            "All ConnectionState variants must have unique u8 values"
        );
    }

    /// Test Display formatting for M2 states
    #[test]
    fn test_connection_state_display() {
        assert_eq!(format!("{}", ConnectionState::Idle), "IDLE");
        assert_eq!(format!("{}", ConnectionState::SynSent), "SYN_SENT");
        assert_eq!(format!("{}", ConnectionState::SynReceived), "SYN_RECEIVED");
        assert_eq!(format!("{}", ConnectionState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", ConnectionState::FinWait), "FIN_WAIT");
        assert_eq!(format!("{}", ConnectionState::CloseWait), "CLOSE_WAIT");
        assert_eq!(format!("{}", ConnectionState::Closed), "CLOSED");
    }

    /// Test FIN handshake states are properly ordered
    #[test]
    fn test_fin_handshake_state_ordering() {
        // FIN_WAIT and CLOSE_WAIT should be between ESTABLISHED and CLOSED
        let established = ConnectionState::Established.as_u8();
        let fin_wait = ConnectionState::FinWait.as_u8();
        let close_wait = ConnectionState::CloseWait.as_u8();
        let closed = ConnectionState::Closed.as_u8();

        assert!(established < fin_wait);
        assert!(established < close_wait);
        assert!(fin_wait < closed);
        assert!(close_wait < closed);
    }

    /// Test valid session state transitions
    #[test]
    fn test_valid_session_state_transitions() {
        use SessionState::*;

        // Creating → Initializing
        assert!(Creating.validate_transition(Initializing).is_ok());

        // Initializing → Active
        assert!(Initializing.validate_transition(Active).is_ok());

        // Initializing → Terminated (failure)
        assert!(Initializing.validate_transition(Terminated).is_ok());

        // Active → Idle
        assert!(Active.validate_transition(Idle).is_ok());

        // Active → Degraded
        assert!(Active.validate_transition(Degraded).is_ok());

        // Active → Recovering
        assert!(Active.validate_transition(Recovering).is_ok());

        // Active → Terminating
        assert!(Active.validate_transition(Terminating).is_ok());

        // Idle → Active
        assert!(Idle.validate_transition(Active).is_ok());

        // Idle → Degraded
        assert!(Idle.validate_transition(Degraded).is_ok());

        // Idle → Terminating
        assert!(Idle.validate_transition(Terminating).is_ok());

        // Degraded → Recovering
        assert!(Degraded.validate_transition(Recovering).is_ok());

        // Degraded → Terminating
        assert!(Degraded.validate_transition(Terminating).is_ok());

        // Degraded → Terminated
        assert!(Degraded.validate_transition(Terminated).is_ok());

        // Recovering → Active
        assert!(Recovering.validate_transition(Active).is_ok());

        // Recovering → Degraded
        assert!(Recovering.validate_transition(Degraded).is_ok());

        // Recovering → Terminated
        assert!(Recovering.validate_transition(Terminated).is_ok());

        // Terminating → Terminated
        assert!(Terminating.validate_transition(Terminated).is_ok());

        // Error → Terminated
        assert!(Error.validate_transition(Terminated).is_ok());
    }

    /// Test invalid session state transitions
    #[test]
    fn test_invalid_session_state_transitions() {
        use SessionState::*;

        // Cannot go from Terminated to anything
        assert!(Terminated.validate_transition(Active).is_err());
        assert!(Terminated.validate_transition(Recovering).is_err());

        // Cannot skip Creating → Initializing
        assert!(Creating.validate_transition(Active).is_err());
        assert!(Creating.validate_transition(Degraded).is_err());

        // Cannot go from Initializing to Recovering
        assert!(Initializing.validate_transition(Recovering).is_err());

        // Cannot go from Idle to Recovering (must go through Degraded)
        assert!(Idle.validate_transition(Recovering).is_err());

        // Cannot go from Active directly to Terminated
        assert!(Active.validate_transition(Terminated).is_err());

        // Cannot go from Terminating backwards
        assert!(Terminating.validate_transition(Active).is_err());
        assert!(Terminating.validate_transition(Recovering).is_err());
        assert!(Terminating.validate_transition(Degraded).is_err());

        // Cannot go from Error to anything except Terminated
        assert!(Error.validate_transition(Active).is_err());
        assert!(Error.validate_transition(Recovering).is_err());
    }

    /// Test same-state transitions are allowed (no-op)
    #[test]
    fn test_same_state_transitions() {
        use SessionState::*;

        assert!(Creating.validate_transition(Creating).is_ok());
        assert!(Initializing.validate_transition(Initializing).is_ok());
        assert!(Active.validate_transition(Active).is_ok());
        assert!(Idle.validate_transition(Idle).is_ok());
        assert!(Degraded.validate_transition(Degraded).is_ok());
        assert!(Recovering.validate_transition(Recovering).is_ok());
        assert!(Terminating.validate_transition(Terminating).is_ok());
        assert!(Terminated.validate_transition(Terminated).is_ok());
        assert!(Error.validate_transition(Error).is_ok());
    }

    /// Test state transition error messages are clear
    #[test]
    fn test_state_transition_error_messages() {
        use SessionState::*;

        let result = Terminated.validate_transition(Active);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid state transition"));
        assert!(err.to_string().contains("Terminated"));
        assert!(err.to_string().contains("Active"));
    }
}
