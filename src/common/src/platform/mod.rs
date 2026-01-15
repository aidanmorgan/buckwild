//! Platform abstraction layer for OS-specific functionality
//!
//! This module provides a unified interface for platform-specific operations,
//! with real implementations on Linux and stub implementations on other platforms.
//!
//! ## Design Philosophy
//!
//! - **Compile-time platform detection**: Use `#[cfg(target_os = "linux")]` to select
//!   the appropriate implementation at compile time
//! - **Clear error messages**: Non-Linux platforms return descriptive errors explaining
//!   the platform requirement
//! - **Zero runtime overhead**: No runtime checks, all platform selection at compile time
//! - **Type safety**: Use traits to define platform-agnostic interfaces
//!
//! ## Supported Platforms
//!
//! - **Linux**: Full implementation using kernel APIs (TUN, eBPF, netlink)
//! - **macOS/Windows/Other**: Stub implementations that compile but return errors at runtime

pub mod capabilities;
pub mod error;
pub mod tun;

#[cfg(target_os = "linux")]
pub mod ebpf;

pub use capabilities::PlatformCapabilities;
pub use error::{PlatformError, PlatformResult};
