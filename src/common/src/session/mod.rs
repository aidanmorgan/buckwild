// Session layer
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

pub mod coordination;
pub mod engine;
pub mod lifecycle;
pub mod manager;
pub mod state;

#[cfg(test)]
mod tests;

// Re-export session types
pub use coordination::*;
pub use engine::*;
pub use lifecycle::*;
pub use manager::*;
pub use state::*;
