// Connection management
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

#[allow(clippy::module_inception)]
pub mod cleanup;
pub mod connection;
pub mod coordinator;
pub mod establishment;
pub mod handshake;
pub mod lifecycle;
pub mod manager;
pub mod termination;
pub mod thread_pools;

// Re-export connection types
pub use cleanup::*;
pub use connection::*;
pub use establishment::*;
pub use handshake::*;
pub use lifecycle::*;
pub use manager::*;
pub use termination::*;
