/// Packet type definitions using ONLY consolidated types from protocol/types
///
/// This module provides ONLY re-exports from the authoritative type definitions.
/// NO local type definitions are allowed - all types come from protocol/types.
///
/// This ensures compliance with the single authoritative source principle.
// Re-export ALL types from the authoritative consolidated types module
pub use crate::protocol::types::*;
