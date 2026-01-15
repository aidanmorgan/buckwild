#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]
// Connection coordinator for engine lifecycle orchestration
//
// Coordinates connection lifecycle events across multiple engines,
// ensuring proper event propagation and cleanup.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info, instrument, warn};

use crate::error::SessionResult;
use crate::protocol::types::{ConnectionId, SessionId, Timestamp};

/// Connection event types
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Connection established
    Connected {
        connection_id: ConnectionId,
        timestamp: Timestamp,
    },

    /// Data transfer on connection
    DataTransfer {
        connection_id: ConnectionId,
        session_id: SessionId,
        bytes_transferred: u64,
        timestamp: Timestamp,
    },

    /// Connection closing
    Disconnecting {
        connection_id: ConnectionId,
        reason: String,
        timestamp: Timestamp,
    },

    /// Connection closed
    Disconnected {
        connection_id: ConnectionId,
        timestamp: Timestamp,
    },

    /// Connection error
    Error {
        connection_id: ConnectionId,
        error: String,
        timestamp: Timestamp,
    },
}

impl ConnectionEvent {
    /// Get the connection ID for this event
    pub fn connection_id(&self) -> ConnectionId {
        match self {
            Self::Connected { connection_id, .. } => *connection_id,
            Self::DataTransfer { connection_id, .. } => *connection_id,
            Self::Disconnecting { connection_id, .. } => *connection_id,
            Self::Disconnected { connection_id, .. } => *connection_id,
            Self::Error { connection_id, .. } => *connection_id,
        }
    }

    /// Get the timestamp for this event
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::Connected { timestamp, .. } => *timestamp,
            Self::DataTransfer { timestamp, .. } => *timestamp,
            Self::Disconnecting { timestamp, .. } => *timestamp,
            Self::Disconnected { timestamp, .. } => *timestamp,
            Self::Error { timestamp, .. } => *timestamp,
        }
    }
}

/// Engine event handler trait
///
/// Engines implement this trait to receive connection lifecycle events
#[async_trait::async_trait]
pub trait EngineEventHandler: Send + Sync {
    /// Handle a connection event
    async fn handle_event(&self, event: ConnectionEvent) -> SessionResult<()>;

    /// Get the engine name for logging
    fn name(&self) -> &str;
}

/// Connection state tracking
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Connection ID - kept for future audit/monitoring features
    #[allow(dead_code)]
    connection_id: ConnectionId,
    /// Connection timestamp - kept for future audit/monitoring features
    #[allow(dead_code)]
    connected_at: Timestamp,
    last_activity: Timestamp,
    active_sessions: Vec<SessionId>,
}

/// Connection coordinator statistics
#[derive(Debug, Default, Clone)]
pub struct CoordinatorStats {
    total_connections: u64,
    total_disconnections: u64,
    total_events_dispatched: u64,
    active_connections: usize,
}

/// Connection coordinator
///
/// Orchestrates connection lifecycle across registered engines,
/// ensuring all engines receive connection events in proper order.
pub struct ConnectionCoordinator {
    /// Registered engine handlers
    engines: RwLock<Vec<Arc<dyn EngineEventHandler>>>,

    /// Active connection states
    connections: DashMap<ConnectionId, ConnectionState>,

    /// Event broadcast channel
    event_tx: broadcast::Sender<ConnectionEvent>,

    /// Statistics
    stats: RwLock<CoordinatorStats>,
}

impl ConnectionCoordinator {
    /// Create a new connection coordinator
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1024);

        info!("Connection coordinator created");

        Self {
            engines: RwLock::new(Vec::new()),
            connections: DashMap::new(),
            event_tx,
            stats: RwLock::new(CoordinatorStats::default()),
        }
    }

    /// Register an engine to receive connection events
    #[instrument(skip(self, handler))]
    pub async fn register_engine(&self, handler: Arc<dyn EngineEventHandler>) -> SessionResult<()> {
        let engine_name = handler.name().to_string();

        let mut engines = self.engines.write().await;
        engines.push(handler);

        info!(
            engine = %engine_name,
            total_engines = engines.len(),
            "Engine registered"
        );

        Ok(())
    }

    /// Emit a connection event to all registered engines
    #[instrument(skip(self))]
    pub async fn emit_event(&self, event: ConnectionEvent) -> SessionResult<()> {
        let connection_id = event.connection_id();

        debug!(
            connection_id = %connection_id,
            event_type = ?event,
            "Emitting connection event"
        );

        // Update connection state based on event type
        match &event {
            ConnectionEvent::Connected { timestamp, .. } => {
                self.connections.insert(
                    connection_id,
                    ConnectionState {
                        connection_id,
                        connected_at: *timestamp,
                        last_activity: *timestamp,
                        active_sessions: Vec::new(),
                    },
                );

                let mut stats = self.stats.write().await;
                stats.total_connections += 1;
                stats.active_connections = self.connections.len();
            }

            ConnectionEvent::DataTransfer {
                session_id,
                timestamp,
                ..
            } => {
                if let Some(mut state) = self.connections.get_mut(&connection_id) {
                    state.last_activity = *timestamp;
                    if !state.active_sessions.contains(session_id) {
                        state.active_sessions.push(session_id.clone());
                    }
                }
            }

            ConnectionEvent::Disconnecting { .. } => {
                // Keep state for now, will remove on Disconnected
            }

            ConnectionEvent::Disconnected { .. } => {
                self.connections.remove(&connection_id);

                let mut stats = self.stats.write().await;
                stats.total_disconnections += 1;
                stats.active_connections = self.connections.len();
            }

            ConnectionEvent::Error { .. } => {
                // Keep state, error doesn't necessarily close connection
            }
        }

        // Dispatch to all engines
        let engines = self.engines.read().await;
        let mut dispatch_errors = Vec::new();

        for engine in engines.iter() {
            let engine_name = engine.name();
            match engine.handle_event(event.clone()).await {
                Ok(()) => {
                    debug!(
                        connection_id = %connection_id,
                        engine = %engine_name,
                        "Event dispatched to engine"
                    );
                }
                Err(e) => {
                    warn!(
                        connection_id = %connection_id,
                        engine = %engine_name,
                        error = %e,
                        "Engine failed to handle event"
                    );
                    dispatch_errors.push((engine_name.to_string(), e));
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_events_dispatched += 1;
        }

        // Broadcast to subscribers
        let _ = self.event_tx.send(event);

        // Report dispatch errors
        if !dispatch_errors.is_empty() {
            warn!(
                connection_id = %connection_id,
                failed_engines = dispatch_errors.len(),
                "Some engines failed to handle event"
            );
        }

        Ok(())
    }

    /// Subscribe to connection events
    pub fn subscribe(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    /// Get active connection IDs
    pub fn active_connections(&self) -> Vec<ConnectionId> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }

    /// Get connection state
    pub fn get_connection_state(&self, connection_id: ConnectionId) -> Option<ConnectionState> {
        self.connections
            .get(&connection_id)
            .map(|entry| entry.value().clone())
    }

    /// Get statistics
    pub async fn get_stats(&self) -> CoordinatorStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_connections = self.connections.len();
        stats
    }

    /// Shutdown the coordinator and notify all engines
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> SessionResult<()> {
        info!("Shutting down connection coordinator");

        let connection_ids: Vec<ConnectionId> =
            self.connections.iter().map(|entry| *entry.key()).collect();

        // Emit disconnect events for all active connections
        for connection_id in connection_ids {
            let event = ConnectionEvent::Disconnected {
                connection_id,
                timestamp: Timestamp::now(),
            };

            if let Err(e) = self.emit_event(event).await {
                warn!(
                    connection_id = %connection_id,
                    error = %e,
                    "Failed to emit disconnect event during shutdown"
                );
            }
        }

        info!("Connection coordinator shutdown complete");
        Ok(())
    }
}

impl Default for ConnectionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestEngine {
        name: String,
        events_received: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl EngineEventHandler for TestEngine {
        async fn handle_event(&self, _event: ConnectionEvent) -> SessionResult<()> {
            self.events_received.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_engine_registration_and_event_dispatch() {
        let coordinator = ConnectionCoordinator::new();

        let engine1_counter = Arc::new(AtomicUsize::new(0));
        let engine2_counter = Arc::new(AtomicUsize::new(0));

        let engine1 = Arc::new(TestEngine {
            name: "engine1".to_string(),
            events_received: engine1_counter.clone(),
        });

        let engine2 = Arc::new(TestEngine {
            name: "engine2".to_string(),
            events_received: engine2_counter.clone(),
        });

        coordinator
            .register_engine(engine1)
            .await
            .expect("Failed to register engine1");

        coordinator
            .register_engine(engine2)
            .await
            .expect("Failed to register engine2");

        let conn_id = ConnectionId::new(1);
        let event = ConnectionEvent::Connected {
            connection_id: conn_id,
            timestamp: Timestamp::now(),
        };

        coordinator
            .emit_event(event)
            .await
            .expect("Failed to emit event");

        // Both engines should have received the event
        assert_eq!(engine1_counter.load(Ordering::SeqCst), 1);
        assert_eq!(engine2_counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_connection_lifecycle() {
        let coordinator = ConnectionCoordinator::new();

        let conn_id = ConnectionId::new(1);

        // Connect
        coordinator
            .emit_event(ConnectionEvent::Connected {
                connection_id: conn_id,
                timestamp: Timestamp::now(),
            })
            .await
            .expect("Failed to emit connect");

        assert!(coordinator.get_connection_state(conn_id).is_some());
        assert_eq!(coordinator.active_connections().len(), 1);

        // Data transfer
        coordinator
            .emit_event(ConnectionEvent::DataTransfer {
                connection_id: conn_id,
                session_id: SessionId::new(100),
                bytes_transferred: 1024,
                timestamp: Timestamp::now(),
            })
            .await
            .expect("Failed to emit data transfer");

        // Disconnect
        coordinator
            .emit_event(ConnectionEvent::Disconnected {
                connection_id: conn_id,
                timestamp: Timestamp::now(),
            })
            .await
            .expect("Failed to emit disconnect");

        assert!(coordinator.get_connection_state(conn_id).is_none());
        assert_eq!(coordinator.active_connections().len(), 0);
    }

    #[tokio::test]
    async fn test_shutdown_notifies_all_connections() {
        let coordinator = ConnectionCoordinator::new();

        let engine_counter = Arc::new(AtomicUsize::new(0));
        let engine = Arc::new(TestEngine {
            name: "test_engine".to_string(),
            events_received: engine_counter.clone(),
        });

        coordinator
            .register_engine(engine)
            .await
            .expect("Failed to register engine");

        // Create multiple connections
        for i in 1..=3 {
            coordinator
                .emit_event(ConnectionEvent::Connected {
                    connection_id: ConnectionId::new(i),
                    timestamp: Timestamp::now(),
                })
                .await
                .expect("Failed to emit connect");
        }

        assert_eq!(coordinator.active_connections().len(), 3);
        assert_eq!(engine_counter.load(Ordering::SeqCst), 3);

        // Shutdown
        coordinator.shutdown().await.expect("Failed to shutdown");

        // All connections should be closed (3 connect + 3 disconnect = 6 events)
        assert_eq!(coordinator.active_connections().len(), 0);
        assert_eq!(engine_counter.load(Ordering::SeqCst), 6);
    }
}
