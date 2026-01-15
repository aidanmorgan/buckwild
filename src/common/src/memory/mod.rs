#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Memory management and zero-copy
pub mod pool;
pub mod secure;
pub mod zero_copy;

// Re-export memory management types
pub use pool::*;
pub use secure::*;
pub use zero_copy::*;
