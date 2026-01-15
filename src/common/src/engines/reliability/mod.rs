// Transport reliability engine - packet-level retransmission and loss detection
//
// This module implements Level 1 transport reliability:
// - RTT measurement and RTO calculation per RFC 6298
// - Selective retransmission with SACK-style acknowledgments
// - Packet loss detection via timeout
// - Retransmission statistics tracking
//
// CRITICAL: This is SEPARATE from the protocol recovery system (engines/recovery/).
// - Transport reliability: packet-level concerns (retransmission, loss detection)
// - Protocol recovery: protocol-level concerns (time sync, rekeying)
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

pub mod congestion_window;
pub mod engine;
pub mod retransmission;
pub mod rto;
pub mod sack;
pub mod statistics;

#[cfg(test)]
mod tests;

// Re-export key types
pub use congestion_window::{
    CongestionWindowController, CongestionWindowState, CongestionWindowStats,
};
pub use engine::ReliabilityEngine;
pub use retransmission::{PacketTimingInfo, RetransmissionEngine, RetransmissionState};
pub use rto::{RtoCalculator, RtoState};
pub use sack::{SackBlock, SackProcessor};
pub use statistics::{PacketStats, RetransmissionStats};
