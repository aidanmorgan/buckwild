//! TUN device and translator error types
//!
//! This module defines typed errors for TUN device operations and protocol
//! translation following the layered error handling approach specified in
//! design/rules.md.

use thiserror::Error;

// Import protocol types for TranslatorError
use crate::protocol::types::{FragmentId, SessionId};

/// Errors that can occur during TUN device operations
#[derive(Error, Debug)]
pub enum TunError {
    /// Insufficient system capabilities to create TUN device
    #[error("insufficient capabilities: {capability} required")]
    InsufficientCapabilities {
        /// The capability that is required (e.g., "CAP_NET_ADMIN")
        capability: String,
    },

    /// TUN device with the given name already exists
    #[error("device {name} already exists")]
    DeviceExists {
        /// Name of the device that already exists
        name: String,
    },

    /// Invalid IP address provided in configuration
    #[error("invalid IP address: {value}")]
    InvalidIpAddress {
        /// The invalid IP address string
        value: String,
        /// The underlying parse error
        #[source]
        source: std::net::AddrParseError,
    },

    /// Invalid device name
    #[error("invalid device name: {reason}")]
    InvalidDeviceName {
        /// Reason why the device name is invalid
        reason: String,
    },

    /// Invalid MTU value
    #[error("invalid MTU: {value} - {reason}")]
    InvalidMtu {
        /// The invalid MTU value
        value: u16,
        /// Reason why the MTU is invalid
        reason: String,
    },

    /// ioctl system call failed
    /// ioctl system call failed
    #[cfg(target_os = "linux")]
    #[error("ioctl operation failed: {operation}")]
    IoctlFailed {
        /// The ioctl operation that failed
        operation: String,
        /// The underlying nix error
        #[source]
        source: nix::Error,
    },

    /// rtnetlink operation failed
    /// rtnetlink operation failed
    #[cfg(target_os = "linux")]
    #[error("netlink operation failed: {operation}")]
    NetlinkFailed {
        /// The netlink operation that failed
        operation: String,
        /// The underlying rtnetlink error
        #[source]
        source: rtnetlink::Error,
    },

    /// TUN device not found
    #[error("device {name} not found")]
    DeviceNotFound {
        /// Name of the device that was not found
        name: String,
    },

    /// I/O error during TUN device operations
    #[error("I/O error: {operation}")]
    Io {
        /// The I/O operation that failed
        operation: String,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// TUN device is not in the expected state
    #[error("invalid device state: {reason}")]
    InvalidState {
        /// Description of why the state is invalid
        reason: String,
    },
}

/// Result type for TUN device operations
pub type TunResult<T> = Result<T, TunError>;

/// Errors that can occur during protocol translation operations
///
/// These errors cover packet translation, fragmentation, and reassembly
/// operations as specified in REQ-TRANS-017 of TUN_EBPF_IMPLEMENTATION_GUIDE.md.
#[derive(Error, Debug)]
pub enum TranslatorError {
    /// Invalid packet format or content
    #[error("invalid packet: {reason}")]
    InvalidPacket {
        /// Reason why the packet is invalid
        reason: String,
    },

    /// Fragment session binding violation (REQ-TRANS-012)
    #[error("session mismatch for fragment {fragment_id}")]
    SessionMismatch {
        /// Fragment ID that had mismatched session
        fragment_id: FragmentId,
    },

    /// Fragment overlap detected (REQ-TRANS-014)
    #[error("fragment overlap detected: fragment {fragment_id} index {index}")]
    FragmentOverlap {
        /// Fragment ID with overlapping data
        fragment_id: FragmentId,
        /// Fragment index where overlap occurred
        index: u16,
    },

    /// Fragment bomb attack detected (REQ-TRANS-015)
    #[error("fragment bomb: {total_fragments} fragments exceeds max {max_allowed}")]
    FragmentBomb {
        /// Number of fragments in the attack
        total_fragments: u16,
        /// Maximum allowed fragments
        max_allowed: u16,
    },

    /// Fragment rate limit exceeded (REQ-TRANS-013)
    #[error("rate limit exceeded for session {session_id}")]
    RateLimitExceeded {
        /// Session ID that exceeded rate limit
        session_id: SessionId,
    },

    /// Reassembly buffer size limit exceeded (REQ-TRANS-015)
    #[error(
        "reassembly buffer exceeded for session {session_id}: {current_size} + {attempted_add} > {max_size}"
    )]
    ReassemblyBufferExceeded {
        /// Session ID that exceeded buffer limit
        session_id: SessionId,
        /// Current buffer size in bytes
        current_size: usize,
        /// Size of fragment attempting to add
        attempted_add: usize,
        /// Maximum allowed buffer size
        max_size: usize,
    },

    /// Fragment set timeout (REQ-TRANS-016)
    #[error("fragment timeout: fragment set {fragment_id} exceeded {timeout_ms}ms")]
    FragmentTimeout {
        /// Fragment ID that timed out
        fragment_id: FragmentId,
        /// Timeout threshold in milliseconds
        timeout_ms: u64,
    },

    /// Session not found in connection table
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// Session ID that was not found
        session_id: SessionId,
    },

    /// I/O error during translation operations
    #[error("I/O error during translation: {operation}")]
    Io {
        /// The I/O operation that failed
        operation: String,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },
}

/// Result type for protocol translation operations
pub type TranslatorResult<T> = Result<T, TranslatorError>;

/// Errors that can occur during TUN device manager operations
///
/// These errors cover manager lifecycle, packet processing, and resource management
/// as specified in REQ-MGR-001 through REQ-MGR-010.
#[derive(Error, Debug)]
pub enum ManagerError {
    /// Manager is already running
    #[error("manager already running")]
    AlreadyRunning,

    /// Manager is not running
    #[error("manager not running")]
    NotRunning,

    /// TUN device error
    #[error("tun device error")]
    TunDevice {
        /// The underlying TUN error
        #[from]
        source: TunError,
    },

    /// Translator error during packet processing
    #[error("translator error")]
    Translator {
        /// The underlying translator error
        #[from]
        source: TranslatorError,
    },

    /// I/O error during manager operations
    #[error("I/O error: {operation}")]
    Io {
        /// The I/O operation that failed
        operation: String,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },
}

/// Result type for TUN device manager operations
pub type ManagerResult<T> = Result<T, ManagerError>;
