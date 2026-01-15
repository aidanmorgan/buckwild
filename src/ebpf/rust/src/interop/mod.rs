//! eBPF interoperability module
//!
//! This module provides interoperability between eBPF programs and Rust userspace code,
//! enabling efficient communication and data sharing.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;

pub mod ffi;
pub mod maps;
pub mod shared;

// Re-export interop types
pub use ffi::*;
pub use maps::*;
pub use shared::*;
