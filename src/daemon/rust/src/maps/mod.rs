//! Map management module
//!
//! Provides cleanup and management for eBPF maps.

pub mod cleanup;

pub use cleanup::{CleanupConfig, MapCleanup};
