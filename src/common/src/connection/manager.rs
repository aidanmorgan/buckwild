// Connection Manager - owns and coordinates all connections
//
// This implements the corrected architecture where ConnectionManager is the
// primary coordinator that owns connections, with SessionManager operating
// as an engine within each connection.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

use crate::connection::connection::ConnectionConfig;
use ring::rand::{SecureRandom, SystemRandom};

use super::connection::Connection;
use super::thread_pools::ConnectionThreadPools;

// Import required protocol types
use super::coordinator::ConnectionEngineCoordinator;
use crate::protocol::fragmentation::FragmentationEngine;
use crate::protocol::packet::Packet;
use crate::protocol::types::{BuckwildError, ConnectionId, Counter, SessionId, Timestamp};
use crate::session::SessionState;
// Use consolidated types
use crate::protocol::types::*;

/// Connection manager configuration
#[derive(Debug, Clone)]
pub struct ConnectionManagerConfig {
    /// Maximum concurrent connections
    pub max_connections: MaxConnections,

    /// Connection cleanup interval
    pub cleanup_interval: Timeout,

    /// Default connection timeout
    pub default_connection_timeout: Timeout,

    /// Enable connection pooling
    pub enable_connection_pooling: bool,

    /// Connection pool size per endpoint pair
    pub connection_pool_size: PoolSize,

    /// Enable automatic connection recovery
    pub enable_auto_recovery: bool,

    /// Thread pool configuration
    pub thread_pool_size: ThreadCount,

    /// Enable CPU affinity
    pub enable_cpu_affinity: bool,
}

impl Default for ConnectionManagerConfig {
    fn default() -> Self {
        Self {
            max_connections: MaxConnections::new(10000),
            cleanup_interval: Timeout::from_millis(30_000), // 30 seconds
            default_connection_timeout: Timeout::from_millis(300_000), // 5 minutes
            enable_connection_pooling: true,
            connection_pool_size: PoolSize::new(4),
            enable_auto_recovery: true,
            thread_pool_size: ThreadCount::new(num_cpus::get() as u32),
            enable_cpu_affinity: true,
        }
    }
}

/// Connection manager statistics
#[derive(Debug, Default, Clone)]
pub struct ConnectionManagerStats {
    pub total_connections_created: Counter,
    pub total_connections_closed: Counter,
    pub active_connections: Counter,
    pub total_sessions_created: Counter,
    pub total_sessions_closed: Counter,
    pub active_sessions: Counter,
    pub packets_processed: Counter,
    pub bytes_processed: Counter,
    pub recovery_attempts: Counter,
    pub cleanup_runs: Counter,
    pub last_cleanup: Timestamp,
}

/// Connection Manager - primary coordinator for all connections
pub struct ConnectionManager {
    /// Configuration
    config: ConnectionManagerConfig,

    /// Active connections by ID
    connections: DashMap<ConnectionId, Arc<Connection>>,

    /// Endpoint pair to connection mapping
    endpoint_to_connections: DashMap<(SocketAddr, SocketAddr), Vec<ConnectionId>>,

    /// Session to connection mapping
    session_to_connection: DashMap<SessionId, ConnectionId>,

    /// Connection ID generator
    connection_id_generator: ConnectionIdGenerator,

    /// Thread pools for connection processing
    thread_pools: Arc<ConnectionThreadPools>,

    /// Engine coordinators per connection
    coordinators: DashMap<ConnectionId, Arc<ConnectionEngineCoordinator>>,

    /// Shared fragmentation engine
    fragmentation_engine: Arc<FragmentationEngine>,

    /// Random number generator
    rng: SystemRandom,

    /// Statistics
    stats: RwLock<ConnectionManagerStats>,

    /// Cleanup task handle
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(config: ConnectionManagerConfig) -> Result<Self, BuckwildError> {
        let thread_pools = Arc::new(ConnectionThreadPools::new(
            config.thread_pool_size.as_u32(),
            config.enable_cpu_affinity,
        )?);

        let fragmentation_engine = Arc::new(FragmentationEngine::new());

        Ok(Self {
            config,
            connections: DashMap::new(),
            endpoint_to_connections: DashMap::new(),
            session_to_connection: DashMap::new(),
            connection_id_generator: ConnectionIdGenerator::new(1),
            thread_pools,
            coordinators: DashMap::new(),
            fragmentation_engine,
            rng: SystemRandom::new(),
            stats: RwLock::new(ConnectionManagerStats::default()),
            cleanup_handle: Mutex::new(None),
        })
    }

    /// Start the connection manager
    pub async fn start(self: &Arc<Self>) -> Result<(), BuckwildError> {
        // Start cleanup task
        self.start_cleanup_task().await;

        info!(
            max_connections = self.config.max_connections.as_usize(),
            thread_pool_size = self.config.thread_pool_size.as_usize(),
            "Connection manager started"
        );

        Ok(())
    }

    /// Stop the connection manager
    pub async fn stop(&self) -> Result<(), BuckwildError> {
        // Stop cleanup task
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            handle.abort();
        }

        // Close all connections
        let connection_ids: Vec<ConnectionId> =
            self.connections.iter().map(|entry| *entry.key()).collect();

        for connection_id in connection_ids {
            if let Err(e) = self.close_connection(connection_id).await {
                warn!(
                    connection_id = %connection_id,
                    error = %e,
                    "Failed to close connection during shutdown"
                );
            }
        }

        // Shutdown thread pools
        self.thread_pools.shutdown().await;

        info!("Connection manager stopped");
        Ok(())
    }

    /// Create a new connection
    #[instrument(skip(self), fields(local = %local_endpoint, remote = %remote_endpoint))]
    pub async fn create_connection(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        connection_config: Option<ConnectionConfig>,
    ) -> Result<ConnectionId, BuckwildError> {
        // Check connection limit
        if self.connections.len() >= self.config.max_connections.as_usize() {
            warn!(
                current_connections = self.connections.len(),
                max_connections = self.config.max_connections.as_usize(),
                "Connection limit exceeded"
            );
            return Err(BuckwildError::network_error("Connection limit exceeded"));
        }

        // Generate unique connection ID
        let connection_id = self.generate_connection_id();

        // Use provided config or default
        let config = connection_config.unwrap_or_else(|| ConnectionConfig {
            connection_timeout: self.config.default_connection_timeout,
            ..Default::default()
        });

        // Create connection
        let connection = Arc::new(Connection::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            config,
        ));

        // Create engine coordinator for this connection
        let coordinator = Arc::new(ConnectionEngineCoordinator::new(
            connection_id,
            connection.clone(),
            self.fragmentation_engine.clone(),
        ));

        // Store connection and coordinator
        self.connections.insert(connection_id, connection);
        self.coordinators.insert(connection_id, coordinator);

        // Update endpoint mapping
        self.endpoint_to_connections
            .entry((local_endpoint, remote_endpoint))
            .or_default()
            .push(connection_id);

        // Assign thread pools to connection
        self.thread_pools.assign_connection(connection_id).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_connections_created += 1;
            stats.active_connections += 1;
        }

        info!(
            connection_id = %connection_id,
            local = %local_endpoint,
            remote = %remote_endpoint,
            total_connections = self.connections.len(),
            "Connection created"
        );

        Ok(connection_id)
    }

    /// Get connection by ID
    pub fn get_connection(&self, connection_id: ConnectionId) -> Option<Arc<Connection>> {
        self.connections
            .get(&connection_id)
            .map(|entry| entry.clone())
    }

    /// Get connections for endpoint pair
    pub fn get_connections_for_endpoints(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Vec<Arc<Connection>> {
        if let Some(connection_ids) = self
            .endpoint_to_connections
            .get(&(local_endpoint, remote_endpoint))
        {
            connection_ids
                .iter()
                .filter_map(|&id| self.get_connection(id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get connection for session
    pub fn get_connection_for_session(&self, session_id: SessionId) -> Option<Arc<Connection>> {
        self.session_to_connection
            .get(&session_id)
            .and_then(|entry| self.get_connection(*entry))
    }

    /// Create session in connection
    pub async fn create_session_in_connection(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(SessionId, Arc<SessionState>), BuckwildError> {
        let connection = self
            .get_connection(connection_id)
            .ok_or_else(|| BuckwildError::network_error("Connection not found"))?;

        let (session_id, session_state) = connection.create_session().await?;

        // Update session to connection mapping
        self.session_to_connection
            .insert(session_id.clone(), connection_id);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_sessions_created += 1;
            stats.active_sessions += 1;
        }

        debug!(
            connection_id = %connection_id,
            session_id = %session_id,
            "Session created in connection"
        );

        Ok((session_id, session_state))
    }

    /// Remove session from connection
    pub async fn remove_session_from_connection(
        &self,
        session_id: SessionId,
    ) -> Result<bool, BuckwildError> {
        if let Some(connection_id) = self.session_to_connection.remove(&session_id) {
            let connection_id = connection_id.1;

            if let Some(connection) = self.get_connection(connection_id) {
                let removed = connection.remove_session(&session_id).await;

                if removed {
                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    tracing::trace!(
                        session_id = %session_id,
                        connection_id = %connection_id,
                        "Session removed from connection"
                    );
                }

                return Ok(removed);
            }
        }

        Ok(false)
    }

    /// Process incoming packet
    #[instrument(skip(self, packet), fields(src = %source_addr))]
    pub async fn process_packet(
        &self,
        packet: Packet,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
    ) -> Result<(), BuckwildError> {
        // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
        tracing::trace!(
            src = %source_addr,
            dest = %dest_addr,
            bytes = packet.total_size(),
            packet_type = ?packet.packet_type(),
            "Packet received by manager"
        );

        // Find appropriate connection(s) for this packet
        let connections = self.get_connections_for_endpoints(dest_addr, source_addr);

        if connections.is_empty() {
            // No existing connection, create one if this is a SYN packet
            if packet.packet_type() == crate::protocol::types::PacketType::Syn {
                let connection_id = self.create_connection(dest_addr, source_addr, None).await?;
                let connection = self.get_connection(connection_id).ok_or_else(|| {
                    BuckwildError::network_error("Connection not found after creation")
                })?;

                // Process packet in new connection
                return connection.process_packet(packet, source_addr).await;
            }
            debug!(
                src = %source_addr,
                dest = %dest_addr,
                packet_type = ?packet.packet_type(),
                "No connection found for packet, dropping"
            );
            return Ok(());
        }

        // For existing connections, route packet to appropriate connection
        // based on session ID or other criteria
        let session_id = packet.session_id();

        if let Some(connection) = self.get_connection_for_session(session_id) {
            // Route to specific connection that owns this session
            connection.process_packet(packet, source_addr).await
        } else {
            // Route to first available connection (for new sessions)
            connections[0].process_packet(packet, source_addr).await
        }
    }

    /// Send data through connection
    pub async fn send_data(
        &self,
        session_id: SessionId,
        data: bytes::Bytes,
    ) -> Result<(), BuckwildError> {
        let connection = self
            .get_connection_for_session(session_id.clone())
            .ok_or_else(|| BuckwildError::invalid_state("Session not found"))?;

        connection.send_data(session_id, data).await
    }

    /// Close connection
    pub async fn close_connection(&self, connection_id: ConnectionId) -> Result<(), BuckwildError> {
        if let Some((_, connection)) = self.connections.remove(&connection_id) {
            // Remove from coordinators
            self.coordinators.remove(&connection_id);

            // Remove from thread pools
            self.thread_pools.remove_connection(connection_id).await;

            // Remove session mappings
            let session_ids = connection.get_active_session_ids();
            for session_id in session_ids {
                self.session_to_connection.remove(&session_id);
            }

            // Remove from endpoint mapping
            let local = connection.local_endpoint();
            let remote = connection.remote_endpoint();
            if let Some(mut connection_ids) = self.endpoint_to_connections.get_mut(&(local, remote))
            {
                connection_ids.retain(|&id| id != connection_id);
                if connection_ids.is_empty() {
                    drop(connection_ids);
                    self.endpoint_to_connections.remove(&(local, remote));
                }
            }

            // Close the connection
            connection.close().await?;

            // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
            info!(
                connection_id = %connection_id,
                remaining_connections = self.connections.len(),
                "Connection closed"
            );

            Ok(())
        } else {
            Err(BuckwildError::network_error("Connection not found"))
        }
    }

    /// Get all active connection IDs
    pub fn get_active_connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get total session count across all connections
    pub fn total_session_count(&self) -> usize {
        self.connections
            .iter()
            .map(|entry| entry.session_count())
            .sum()
    }

    /// Generate unique connection ID
    fn generate_connection_id(&self) -> ConnectionId {
        let attempts = crate::protocol::types::AttemptCount::new(0);
        const MAX_ATTEMPTS: u32 = 1000;

        loop {
            // Generate base ID from atomic counter
            let base_id = self
                .connection_id_generator
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Add some randomness to prevent predictability
            let mut random_bytes = [0u8; 8];
            if self.rng.fill(&mut random_bytes).is_ok() {
                let random_part = u64::from_be_bytes(random_bytes);
                let connection_id = ConnectionId::new(base_id ^ (random_part >> 32));

                // Ensure uniqueness
                if !self.connections.contains_key(&connection_id) {
                    return connection_id;
                }
            }

            attempts.increment(Ordering::Relaxed);
            if attempts >= MAX_ATTEMPTS {
                // Fallback to simple counter if randomization fails
                return ConnectionId::new(base_id);
            }
        }
    }

    /// Start cleanup task
    async fn start_cleanup_task(self: &Arc<Self>) {
        let manager_weak = Arc::downgrade(self);
        let cleanup_interval = Duration::from_millis(self.config.cleanup_interval.as_millis());

        let handle = tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                if let Some(manager) = manager_weak.upgrade() {
                    if let Err(e) = manager.cleanup_connections().await {
                        error!(error = %e, "Connection cleanup failed");
                    }
                } else {
                    break; // Manager was dropped
                }
            }
        });

        *self.cleanup_handle.lock().await = Some(handle);
    }

    /// Clean up idle and closed connections
    async fn cleanup_connections(&self) -> Result<(), BuckwildError> {
        let current_time = Timestamp::now();

        let mut connections_to_close = Vec::new();

        // Find connections that should be cleaned up
        for entry in self.connections.iter() {
            let connection_id = *entry.key();
            let connection = entry.value();

            if connection.should_cleanup() {
                connections_to_close.push(connection_id);
            }
        }

        // Close identified connections
        for connection_id in &connections_to_close {
            if let Err(e) = self.close_connection(*connection_id).await {
                warn!(
                    connection_id = %connection_id,
                    error = %e,
                    "Failed to close connection during cleanup"
                );
            }
        }

        // Update cleanup statistics
        {
            let mut stats = self.stats.write().await;
            stats.cleanup_runs += 1;
            stats.last_cleanup = current_time;
        }

        if !connections_to_close.is_empty() {
            debug!(
                cleaned_connections = connections_to_close.len(),
                remaining_connections = self.connections.len(),
                "Connection cleanup completed"
            );
        }

        Ok(())
    }

    /// Get connection manager statistics
    pub async fn get_stats(&self) -> ConnectionManagerStats {
        let mut stats = self.stats.read().await.clone();

        // Update current counts
        stats.active_connections = Counter::new(self.connections.len() as u64);
        stats.active_sessions = Counter::new(self.total_session_count() as u64);

        stats
    }

    /// Get detailed connection information
    pub async fn get_connection_info(&self) -> HashMap<ConnectionId, serde_json::Value> {
        let mut info = HashMap::new();

        for entry in self.connections.iter() {
            let connection_id = *entry.key();
            let connection = entry.value();
            // Stats removed per design
            // let connection_stats = connection.get_stats().await;

            info.insert(
                connection_id,
                serde_json::json!({
                    "connection_id": connection_id.to_string(),
                    "local_endpoint": connection.local_endpoint().to_string(),
                    "remote_endpoint": connection.remote_endpoint().to_string(),
                    "state": format!("{:?}", connection.state()),
                    "session_count": connection.session_count(),
                    "age_ms": connection.age().as_millis(),
                    // "stats": connection_stats,
                }),
            );
        }

        info
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd use a proper shutdown mechanism
        // This is a simplified version for demonstration
        if let Ok(mut handle) = self.cleanup_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}
