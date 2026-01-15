#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]
// Integration layer for session and connection orchestration
//
// This module provides the integration boundary between the protocol layer
// and external engines, coordinating sessions across connections and
// propagating lifecycle events.

pub mod connection_coordinator;
pub mod session_manager;

pub use connection_coordinator::{ConnectionCoordinator, ConnectionEvent, EngineEventHandler};
pub use session_manager::{IntegrationConfig, SessionManager};
