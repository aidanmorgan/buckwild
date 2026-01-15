//! eBPF program loader and management
//!
//! This module provides APIs for loading XDP and TC eBPF programs,
//! managing eBPF maps, and handling port hopping updates.
//!
//! ## Architecture
//!
//! The eBPF integration layer consists of:
//! - Program loading and attachment (XDP, TC)
//! - Map management (port validity, session routing)
//! - Port hopping with HMAC-SHA256
//! - Adaptive delay window configuration
//! - Periodic port table updates
//!
//! ## Design Note
//!
//! This is currently a stub/mock implementation that provides the API
//! surface without requiring actual eBPF programs. When .o files are
//! available, the loader can be extended to use aya for real loading.

pub mod error;
pub mod loader;
pub mod manager;
pub mod port_hopping;
pub mod types;

// Re-export public types
pub use error::{LoaderError, LoaderResult};
pub use loader::{EbpfLoader, LoaderConfig};
pub use manager::EbpfManager;
pub use types::{AdaptiveStats, AdaptiveWindowConfig, PortHoppingConfig, TimeBucket};
