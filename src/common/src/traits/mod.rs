//! Traits for dependency injection and testing
//!
//! This module contains traits that enable dependency injection,
//! particularly for testing with mock implementations.

pub mod clock;

pub use clock::{Clock, SystemClock};

// Re-export MockClock for testing
#[cfg(test)]
pub use clock::MockClock;
