//! Daemon-specific types
//!
//! This module defines types specific to the daemon's operation.

use serde::{Deserialize, Serialize};

// Note: ConnectionState and CongestionState are now imported from buckwild_common::protocol::types

/// TUN device name type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunDeviceName(String);

impl TunDeviceName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TunDeviceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for TunDeviceName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// PSK fingerprint type
pub type PskFingerprint = String;

/// Session salt for PSK discovery blinding
pub type SessionSalt = u32;

/// Blinded fingerprint for private set intersection
pub type BlindedFingerprint = [u8; 16];

/// TCP connection states for flow tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECEIVED"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT_1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT_2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
        }
    }
}
