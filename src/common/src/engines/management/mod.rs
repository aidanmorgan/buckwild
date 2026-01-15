#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Management Engine - Session key rotation and sequence repair
//
// This module implements session management operations including:
// - Session key rotation (rekey operations)
// - Sequence number repair
// - Session recovery and repair operations

pub mod rekey;
pub mod repair;

pub use rekey::RekeyEngine;
pub use repair::RepairEngine;

use crate::protocol::types::*;

/// Rekey result
#[derive(Debug, Clone)]
pub enum RekeyResult {
    /// Rekey succeeded with new key
    Success { key_id: KeyId },
    /// Rekey failed
    Failed { reason: String },
    /// Rekey timeout
    Timeout,
}

/// Repair result
#[derive(Debug, Clone)]
pub enum RepairResult {
    /// Repair succeeded
    Success { repaired_count: u32 },
    /// Repair failed
    Failed { reason: String },
    /// Repair timeout
    Timeout,
}
