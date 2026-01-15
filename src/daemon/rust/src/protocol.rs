//! Protocol type imports for daemon
//!
//! This module imports the protocol-compliant types from the common crate.
//! All duplicate definitions have been removed.

// Import protocol-compliant types from common crate
pub use buckwild_common::protocol::packet::types::DiscoverySubType;

pub mod types {
    // Re-export common protocol types
    pub use buckwild_common::protocol::types::*;
}
