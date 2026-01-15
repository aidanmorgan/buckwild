use anyhow::Result;
use buckwild_common::protocol::types::SessionId;
use buckwild_common::types::time::Timestamp;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, instrument, warn};

use super::flow_tracker::FlowId;

/// Bidirectional mapping between TCP flows and session IDs
pub struct ConnectionMap {
    flow_to_session: DashMap<u64, SessionMapping>,
    session_to_flow: DashMap<SessionId, FlowMapping>,
    next_session_id: SessionId,
    cleanup_interval: Duration,
    mapping_timeout: Duration,
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Session mapping information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMapping {
    pub session_id: SessionId,
    pub flow_id: FlowId,
    pub created_at: Timestamp,
    pub last_activity: Timestamp,
    pub bytes_transferred: u64,
    pub packets_transferred: u32,
    pub state: ConnectionState,
}

/// Flow mapping information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMapping {
    pub flow_id: FlowId,
    pub session_id: SessionId,
    pub created_at: Timestamp,
    pub last_activity: Timestamp,
    pub reverse_flow_id: Option<FlowId>,
    pub state: ConnectionState,
}

// Use consolidated ConnectionState from protocol types
use crate::protocol::types::ConnectionState;

/// Connection statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConnectionStatistics {
    pub total_connections: u32,
    pub active_connections: u32,
    pub establishing_connections: u32,
    pub closing_connections: u32,
    pub total_bytes_transferred: u64,
    pub total_packets_transferred: u64,
}

impl ConnectionMap {
    /// Create a new connection map
    #[instrument]
    pub fn new(cleanup_interval: Duration, mapping_timeout: Duration) -> Self {
        info!(
            "Creating connection map with cleanup interval: {:?}, timeout: {:?}",
            cleanup_interval, mapping_timeout
        );

        ConnectionMap {
            flow_to_session: DashMap::new(),
            session_to_flow: DashMap::new(),
            next_session_id: SessionId::new(1),
            cleanup_interval,
            mapping_timeout,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the connection map with automatic cleanup
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            warn!("Connection map already running");
            return Ok(());
        }

        info!("Starting connection map");
        self.running.store(true, Ordering::Release);

        // Start cleanup task
        let flow_to_session = self.flow_to_session.clone();
        let session_to_flow = self.session_to_flow.clone();
        let timeout = self.mapping_timeout;
        let running = Arc::clone(&self.running);
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            while running.load(Ordering::Acquire) {
                interval.tick().await;

                let now = Timestamp::now();
                let mut expired_flows = Vec::new();
                let mut expired_sessions = Vec::new();

                // Collect expired flow mappings
                for entry in flow_to_session.iter() {
                    let flow_hash = *entry.key();
                    let mapping = entry.value();

                    if Duration::from_nanos(
                        now.as_nanos()
                            .saturating_sub(mapping.last_activity.as_nanos()),
                    ) > timeout
                    {
                        expired_flows.push(flow_hash);
                    }
                }

                // Collect expired session mappings
                for entry in session_to_flow.iter() {
                    let session_id = entry.key().clone();
                    let mapping = entry.value();

                    if Duration::from_nanos(
                        now.as_nanos()
                            .saturating_sub(mapping.last_activity.as_nanos()),
                    ) > timeout
                    {
                        expired_sessions.push(session_id);
                    }
                }

                // Remove expired mappings
                for flow_hash in expired_flows {
                    if let Some((_, mapping)) = flow_to_session.remove(&flow_hash) {
                        debug!("Cleaning up expired flow mapping: {:?}", mapping.flow_id);
                    }
                }

                for session_id in expired_sessions {
                    if let Some((_, _mapping)) = session_to_flow.remove(&session_id) {
                        debug!("Cleaning up expired session mapping: {}", session_id);
                    }
                }

                debug!(
                    "Connection cleanup completed, active mappings: flow={}, session={}",
                    flow_to_session.len(),
                    session_to_flow.len()
                );
            }

            info!("Connection map cleanup task terminated");
        });

        Ok(())
    }

    /// Stop the connection map
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping connection map");
        self.running.store(false, Ordering::Release);

        // Clear all mappings
        self.flow_to_session.clear();
        self.session_to_flow.clear();

        info!("Connection map stopped");
    }

    /// Create a new connection mapping
    #[instrument(skip(self))]
    pub async fn create_connection(&self, flow_id: FlowId) -> Result<SessionId> {
        let session_id = SessionId::new(self.next_session_id.fetch_add(1, Ordering::Relaxed));
        let now = Timestamp::now();
        let flow_hash = self.hash_flow_id(&flow_id);

        debug!(
            "Creating connection mapping: {} -> {:?}",
            flow_id, session_id
        );

        // Create session mapping
        let session_mapping = SessionMapping {
            session_id: session_id.clone(),
            flow_id: flow_id.clone(),
            created_at: now,
            last_activity: now,
            bytes_transferred: 0,
            packets_transferred: 0,
            state: ConnectionState::Connecting,
        };

        // Create flow mapping
        let flow_mapping = FlowMapping {
            flow_id: flow_id.clone(),
            session_id: session_id.clone(),
            created_at: now,
            last_activity: now,
            reverse_flow_id: Some(flow_id.reverse()),
            state: ConnectionState::Connecting,
        };

        // Insert mappings atomically
        self.flow_to_session.insert(flow_hash, session_mapping);
        self.session_to_flow
            .insert(session_id.clone(), flow_mapping);

        info!("Created connection mapping: {} -> {}", flow_id, session_id);
        Ok(session_id)
    }

    /// Get session ID for flow
    #[instrument(skip(self))]
    pub fn get_session_for_flow(&self, flow_id: &FlowId) -> Option<SessionId> {
        let flow_hash = self.hash_flow_id(flow_id);

        if let Some(mapping) = self.flow_to_session.get(&flow_hash) {
            // Update last activity
            let mut mapping = mapping.clone();
            mapping.last_activity = Timestamp::now();
            self.flow_to_session.insert(flow_hash, mapping.clone());

            debug!(
                "Found session {:?} for flow: {}",
                mapping.session_id, flow_id
            );
            Some(mapping.session_id)
        } else {
            debug!("No session found for flow: {}", flow_id);
            None
        }
    }

    /// Get flow ID for session
    #[instrument(skip(self))]
    pub fn get_flow_for_session(&self, session_id: SessionId) -> Option<FlowId> {
        if let Some(mapping) = self.session_to_flow.get(&session_id) {
            // Update last activity
            let mut mapping = mapping.clone();
            mapping.last_activity = Timestamp::now();
            self.session_to_flow
                .insert(session_id.clone(), mapping.clone());

            debug!("Found flow {} for session: {}", mapping.flow_id, session_id);
            Some(mapping.flow_id)
        } else {
            debug!("No flow found for session: {}", session_id);
            None
        }
    }

    /// Update connection state
    #[instrument(skip(self))]
    pub async fn update_connection_state(
        &self,
        session_id: SessionId,
        state: ConnectionState,
    ) -> Result<()> {
        if let Some(mut flow_mapping) = self.session_to_flow.get_mut(&session_id) {
            flow_mapping.state = state;
            flow_mapping.last_activity = Timestamp::now();

            let flow_hash = self.hash_flow_id(&flow_mapping.flow_id);
            if let Some(mut session_mapping) = self.flow_to_session.get_mut(&flow_hash) {
                session_mapping.state = state;
                session_mapping.last_activity = Timestamp::now();
            }

            debug!(
                "Updated connection state for session {}: {:?}",
                session_id, state
            );
        } else {
            warn!(
                "Attempted to update state for unknown session: {}",
                session_id
            );
        }

        Ok(())
    }

    /// Update connection statistics
    #[instrument(skip(self))]
    pub async fn update_connection_stats(
        &self,
        session_id: SessionId,
        bytes: u64,
        packets: u32,
    ) -> Result<()> {
        if let Some(mut flow_mapping) = self.session_to_flow.get_mut(&session_id) {
            flow_mapping.last_activity = Timestamp::now();

            let flow_hash = self.hash_flow_id(&flow_mapping.flow_id);
            if let Some(mut session_mapping) = self.flow_to_session.get_mut(&flow_hash) {
                session_mapping.bytes_transferred += bytes;
                session_mapping.packets_transferred += packets;
                session_mapping.last_activity = Timestamp::now();
            }

            debug!(
                "Updated connection stats for session {}: +{} bytes, +{} packets",
                session_id, bytes, packets
            );
        }

        Ok(())
    }

    /// Remove connection mapping
    #[instrument(skip(self))]
    pub async fn remove_connection(&self, session_id: SessionId) -> Result<()> {
        if let Some((_, flow_mapping)) = self.session_to_flow.remove(&session_id) {
            let flow_hash = self.hash_flow_id(&flow_mapping.flow_id);
            self.flow_to_session.remove(&flow_hash);

            info!("Removed connection mapping for session: {}", session_id);
        } else {
            warn!("Attempted to remove unknown session: {}", session_id);
        }

        Ok(())
    }

    /// Get all active connections
    pub fn get_active_connections(&self) -> Vec<(u64, FlowId, ConnectionState)> {
        self.session_to_flow
            .iter()
            .map(|entry| {
                let session_id = entry.key().clone();
                let mapping = entry.value();
                (session_id.as_u64(), mapping.flow_id.clone(), mapping.state)
            })
            .collect()
    }

    /// Get connection statistics
    pub async fn get_statistics(&self) -> ConnectionStatistics {
        let mut stats = ConnectionStatistics::default();

        for entry in self.session_to_flow.iter() {
            let mapping = entry.value();
            stats.total_connections += 1;

            match mapping.state {
                ConnectionState::Connecting => stats.establishing_connections += 1,
                ConnectionState::Established => stats.active_connections += 1,
                ConnectionState::Closing => stats.closing_connections += 1,
                ConnectionState::Closed => {}
                _ => {} // Handle other states
            }
        }

        for entry in self.flow_to_session.iter() {
            let mapping = entry.value();
            stats.total_bytes_transferred += mapping.bytes_transferred;
            stats.total_packets_transferred += mapping.packets_transferred as u64;
        }

        stats
    }

    /// Check if connection exists
    pub fn connection_exists(&self, session_id: SessionId) -> bool {
        self.session_to_flow.contains_key(&session_id)
    }

    /// Get connection info
    pub fn get_connection_info(
        &self,
        session_id: SessionId,
    ) -> Option<(FlowId, ConnectionState, Timestamp)> {
        self.session_to_flow.get(&session_id).map(|mapping| {
            (
                mapping.flow_id.clone(),
                mapping.state,
                mapping.last_activity,
            )
        })
    }

    /// Hash flow ID for efficient lookup
    fn hash_flow_id(&self, flow_id: &FlowId) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        flow_id.hash(&mut hasher);
        hasher.finish()
    }

    /// Get next session ID (for testing)
    pub fn peek_next_session_id(&self) -> SessionId {
        SessionId::new(self.next_session_id.load(Ordering::Relaxed))
    }
}

// Display implementation is provided by the consolidated ConnectionState type
