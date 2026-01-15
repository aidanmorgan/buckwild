#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]
// Session manager for integration layer - orchestrates sessions across connections
//
// This is a lightweight wrapper around the core SessionManager that provides
// multi-connection session orchestration and packet routing.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::error::{SessionError, SessionResult};
use crate::protocol::types::{ConnectionId, SessionId, Threshold, Timeout};
use crate::session::{
    SessionManager as CoreSessionManager, SessionManagerConfig as CoreSessionManagerConfig,
    SessionState,
};

/// Integration session manager configuration
#[derive(Debug, Clone)]
pub struct IntegrationConfig {
    /// Maximum concurrent sessions per connection
    pub max_sessions_per_connection: Threshold,

    /// Session cleanup interval
    pub cleanup_interval: Timeout,

    /// Default session timeout
    pub default_session_timeout: Timeout,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            max_sessions_per_connection: Threshold::from_raw(100),
            cleanup_interval: Timeout::new(30_000), // 30 seconds
            default_session_timeout: Timeout::new(300_000), // 5 minutes
        }
    }
}

/// Session manager for integration layer
///
/// Orchestrates sessions across multiple connections, providing routing
/// and lifecycle management at the integration boundary.
pub struct SessionManager {
    /// Configuration
    config: IntegrationConfig,

    /// Core session managers by connection ID
    managers: DashMap<ConnectionId, Arc<CoreSessionManager>>,

    /// Session to connection mapping for routing
    session_routing: DashMap<SessionId, ConnectionId>,

    /// Statistics
    stats: RwLock<SessionManagerStats>,

    /// Cleanup callback invoked when a session is closed
    #[allow(clippy::type_complexity)]
    cleanup_callback: RwLock<Option<Arc<dyn Fn(SessionId) + Send + Sync>>>,
}

/// Session manager statistics
#[derive(Debug, Default, Clone)]
struct SessionManagerStats {
    total_connections: u64,
    total_sessions_created: u64,
    total_sessions_closed: u64,
}

impl SessionManager {
    /// Create a new integration session manager
    pub fn new(config: IntegrationConfig) -> Self {
        info!("Creating integration session manager");

        Self {
            config,
            managers: DashMap::new(),
            session_routing: DashMap::new(),
            stats: RwLock::new(SessionManagerStats::default()),
            cleanup_callback: RwLock::new(None),
        }
    }

    /// Set cleanup callback that will be invoked when sessions are closed
    pub async fn set_cleanup_callback<F>(&self, callback: F)
    where
        F: Fn(SessionId) + Send + Sync + 'static,
    {
        *self.cleanup_callback.write().await = Some(Arc::new(callback));
    }

    /// Register a connection and create its session manager
    #[instrument(skip(self))]
    pub async fn register_connection(&self, connection_id: ConnectionId) -> SessionResult<()> {
        if self.managers.contains_key(&connection_id) {
            return Err(SessionError::session_management_error(
                "Connection already registered",
            ));
        }

        // Create core session manager config
        let core_config = CoreSessionManagerConfig {
            max_sessions: self.config.max_sessions_per_connection,
            cleanup_interval: self.config.cleanup_interval,
            default_session_timeout: self.config.default_session_timeout,
            enable_session_pooling: true,
            session_pool_size: Threshold::from_raw(10),
            enable_auto_recovery: true,
            heartbeat_interval: Timeout::new(30_000),
            enable_state_persistence: false,
            local_endpoint: None,
            remote_endpoint: None,
        };

        let manager = Arc::new(CoreSessionManager::new(connection_id, core_config));
        manager.start().await?;

        self.managers.insert(connection_id, manager);

        let mut stats = self.stats.write().await;
        stats.total_connections += 1;

        info!(
            connection_id = %connection_id,
            total_connections = stats.total_connections,
            "Connection registered"
        );

        Ok(())
    }

    /// Unregister a connection and cleanup its sessions
    #[instrument(skip(self))]
    pub async fn unregister_connection(&self, connection_id: ConnectionId) -> SessionResult<()> {
        let manager = self
            .managers
            .get(&connection_id)
            .ok_or_else(|| SessionError::session_management_error("Connection not found"))?
            .clone();

        // Stop the manager (this closes all sessions)
        manager.stop().await?;

        // Remove from managers
        self.managers.remove(&connection_id);

        // Clean up routing table
        self.session_routing
            .retain(|_, conn_id| *conn_id != connection_id);

        info!(
            connection_id = %connection_id,
            "Connection unregistered"
        );

        Ok(())
    }

    /// Create a new session for a connection
    #[instrument(skip(self))]
    pub async fn create_session(
        &self,
        connection_id: ConnectionId,
    ) -> SessionResult<(SessionId, Arc<SessionState>)> {
        let manager = self
            .managers
            .get(&connection_id)
            .ok_or_else(|| SessionError::session_management_error("Connection not found"))?
            .clone();

        let (session_id, session_state) = manager.create_session().await?;

        // Add to routing table
        self.session_routing
            .insert(session_id.clone(), connection_id);

        let mut stats = self.stats.write().await;
        stats.total_sessions_created += 1;

        debug!(
            connection_id = %connection_id,
            session_id = %session_id,
            total_sessions = stats.total_sessions_created,
            "Session created"
        );

        Ok((session_id, session_state))
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: SessionId) -> Option<Arc<SessionState>> {
        let connection_id = self.session_routing.get(&session_id)?;
        let manager = self.managers.get(&*connection_id)?;
        manager.get_session(session_id)
    }

    /// Route a packet to the appropriate session
    #[instrument(skip(self))]
    pub async fn route_packet(&self, session_id: SessionId) -> SessionResult<Arc<SessionState>> {
        let connection_id =
            *self
                .session_routing
                .get(&session_id)
                .ok_or(SessionError::SessionNotFound {
                    session_id: session_id.clone(),
                })?;

        let manager = self
            .managers
            .get(&connection_id)
            .ok_or_else(|| SessionError::session_management_error("Connection manager not found"))?
            .clone();

        manager
            .get_session(session_id.clone())
            .ok_or(SessionError::SessionNotFound { session_id })
    }

    /// Close a session
    #[instrument(skip(self))]
    pub async fn close_session(&self, session_id: SessionId) -> SessionResult<bool> {
        let connection_id =
            *self
                .session_routing
                .get(&session_id)
                .ok_or(SessionError::SessionNotFound {
                    session_id: session_id.clone(),
                })?;

        let manager = self
            .managers
            .get(&connection_id)
            .ok_or_else(|| SessionError::session_management_error("Connection manager not found"))?
            .clone();

        let closed = manager.close_session(session_id.clone()).await?;

        if closed {
            self.session_routing.remove(&session_id);

            let mut stats = self.stats.write().await;
            stats.total_sessions_closed += 1;

            debug!(
                connection_id = %connection_id,
                session_id = %session_id,
                "Session closed"
            );

            // Invoke cleanup callback if registered
            if let Some(callback) = self.cleanup_callback.read().await.as_ref() {
                callback(session_id.clone());
            }
        }

        Ok(closed)
    }

    /// Get all active session IDs for a connection
    pub fn get_connection_sessions(&self, connection_id: ConnectionId) -> Vec<SessionId> {
        match self.managers.get(&connection_id) {
            Some(manager) => manager.get_active_session_ids(),
            None => Vec::new(),
        }
    }

    /// Get total session count across all connections
    pub fn total_session_count(&self) -> usize {
        self.managers
            .iter()
            .map(|entry| entry.value().session_count())
            .sum()
    }

    /// Get session count for a specific connection
    pub fn connection_session_count(&self, connection_id: ConnectionId) -> usize {
        self.managers
            .get(&connection_id)
            .map(|m| m.session_count())
            .unwrap_or(0)
    }

    /// Shutdown all connections and sessions
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> SessionResult<()> {
        info!("Shutting down integration session manager");

        let connection_ids: Vec<ConnectionId> =
            self.managers.iter().map(|entry| *entry.key()).collect();

        for connection_id in connection_ids {
            if let Err(e) = self.unregister_connection(connection_id).await {
                warn!(
                    connection_id = %connection_id,
                    error = %e,
                    "Failed to unregister connection during shutdown"
                );
            }
        }

        info!("Integration session manager shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation_and_routing() {
        let config = IntegrationConfig::default();
        let manager = SessionManager::new(config);

        let conn_id = ConnectionId::new(1);

        // Register connection
        manager
            .register_connection(conn_id)
            .await
            .expect("Failed to register connection");

        // Create session
        let (session_id, _state) = manager
            .create_session(conn_id)
            .await
            .expect("Failed to create session");

        // Route packet to session
        let routed_state = manager
            .route_packet(session_id.clone())
            .await
            .expect("Failed to route packet");

        assert!(Arc::strong_count(&routed_state) >= 1);

        // Verify session accessible
        let session = manager.get_session(session_id.clone());
        assert!(session.is_some());

        // Close session
        let closed = manager
            .close_session(session_id)
            .await
            .expect("Failed to close session");
        assert!(closed);

        // Cleanup
        manager
            .unregister_connection(conn_id)
            .await
            .expect("Failed to unregister connection");
    }

    #[tokio::test]
    async fn test_connection_close_notifies_all_sessions() {
        let config = IntegrationConfig::default();
        let manager = SessionManager::new(config);

        let conn_id = ConnectionId::new(1);

        // Register connection
        manager
            .register_connection(conn_id)
            .await
            .expect("Failed to register connection");

        // Create a session
        let (session_id1, _) = manager
            .create_session(conn_id)
            .await
            .expect("Failed to create session 1");

        // Verify session is tracked
        assert_eq!(manager.connection_session_count(conn_id), 1);

        // Unregister connection (should close all sessions)
        manager
            .unregister_connection(conn_id)
            .await
            .expect("Failed to unregister connection");

        // Verify session no longer exists
        assert_eq!(manager.connection_session_count(conn_id), 0);
        assert!(manager.get_session(session_id1).is_none());
    }

    #[tokio::test]
    async fn test_no_resource_leaks_after_shutdown() {
        let config = IntegrationConfig::default();
        let manager = SessionManager::new(config);

        let conn_id1 = ConnectionId::new(1);
        let conn_id2 = ConnectionId::new(2);

        // Register connections and create sessions
        manager
            .register_connection(conn_id1)
            .await
            .expect("Failed to register connection 1");
        manager
            .register_connection(conn_id2)
            .await
            .expect("Failed to register connection 2");

        manager
            .create_session(conn_id1)
            .await
            .expect("Failed to create session on conn1");
        manager
            .create_session(conn_id2)
            .await
            .expect("Failed to create session on conn2");

        assert_eq!(manager.total_session_count(), 2);

        // Shutdown
        manager.shutdown().await.expect("Failed to shutdown");

        // Verify all resources cleaned up
        assert_eq!(manager.total_session_count(), 0);
        assert_eq!(manager.managers.len(), 0);
        assert_eq!(manager.session_routing.len(), 0);
    }
}
