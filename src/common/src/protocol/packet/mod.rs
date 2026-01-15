#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

pub mod builder;
pub mod header;
pub mod parser;
pub mod structures;
/// Packet handling module using ONLY consolidated types
///
/// This module provides a unified interface for packet handling including:
/// - Packet types and flags (using consolidated types)
/// - Packet structures for all protocol packet types
/// - Packet headers with adaptive format
/// - Packet parsing engine for all packet types
/// - Packet building engine for all packet types
///
/// ALL types are imported from the consolidated types module - NO local definitions.
pub mod types;

#[cfg(test)]
mod proptest_roundtrip;

// Re-export all packet functionality using consolidated types
pub use builder::{
    AckPacketBuilder, ControlPacketBuilder, DataPacketBuilder, DiscoveryPacketBuilder,
    ErrorPacketBuilder, FinPacketBuilder, HeartbeatPacketBuilder, ManagementPacketBuilder,
    PacketBuilder, PacketBuilderEngine, RstPacketBuilder, SynAckPacketBuilder, SynPacketBuilder,
};
pub use header::PacketHeader;
pub use parser::{PacketParserEngine, ParsedPacketWithSource};
pub use structures::*;
pub use types::*;
