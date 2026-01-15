// Performance optimizations
// NOTE: Use tracing directly per design/rules.md - no custom metrics abstraction
pub mod lock_free;
pub mod queues;

// Re-export performance types
pub use lock_free::*;
pub use queues::*;
