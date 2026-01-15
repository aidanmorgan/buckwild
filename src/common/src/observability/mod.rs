// Cross-cutting observability
// NOTE: Use tokio-tracing directly per design/rules.md - no custom metrics abstraction
// Health monitoring is application functionality, not metrics infrastructure
pub mod health;
pub mod syslog;

// Re-export health monitoring types
pub use health::*;
pub use syslog::*;
