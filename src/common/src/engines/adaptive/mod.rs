#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Adaptive networking
pub mod engine;
pub mod heartbeat;
pub mod measurement;
pub mod optimization;

// Import consolidated types

// Re-export adaptive types
pub use engine::*;
pub use heartbeat::*;
pub use measurement::*;
pub use optimization::*;

// Tests
#[cfg(test)]
mod tests;
