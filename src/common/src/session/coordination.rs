// Session Coordination - manages multi-session coordination and conflict resolution
//
// This implements session coordination for multi-session support, including
// conflict resolution, resource sharing, and session synchronization.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{debug, info, instrument, warn};

use super::SessionState;
use crate::error::{SessionError, SessionResult};
use crate::protocol::types::{
    ConnectionId, Counter, Port, SequenceNumber, SessionCount, SessionId, Threshold, Timeout,
    Timestamp,
};

/// Session coordination event
#[derive(Debug, Clone)]
pub enum SessionCoordinationEvent {
    /// Session was registered
    SessionRegistered {
        session_id: SessionId,
        timestamp: Timestamp,
    },

    /// Session was unregistered
    SessionUnregistered {
        session_id: SessionId,
        timestamp: Timestamp,
    },

    /// Session conflict detected
    ConflictDetected {
        session1: SessionId,
        session2: SessionId,
        conflict_type: String,
        timestamp: Timestamp,
    },

    /// Session conflict resolved
    ConflictResolved {
        session1: SessionId,
        session2: SessionId,
        resolution: String,
        timestamp: Timestamp,
    },

    /// Resource allocated to session
    ResourceAllocated {
        session_id: SessionId,
        resource_type: String,
        resource_id: String,
        timestamp: Timestamp,
    },

    /// Resource deallocated from session
    ResourceDeallocated {
        session_id: SessionId,
        resource_type: String,
        resource_id: String,
        timestamp: Timestamp,
    },

    /// Sessions synchronized
    SessionsSynchronized {
        session_ids: Vec<SessionId>,
        timestamp: Timestamp,
    },
}

/// Session conflict type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionConflictType {
    /// Port conflict between sessions
    PortConflict,

    /// Sequence number conflict
    SequenceConflict,

    /// Resource conflict
    ResourceConflict,

    /// State conflict
    StateConflict,

    /// Timing conflict
    TimingConflict,
}

/// Session conflict resolution strategy
#[derive(Debug, Clone)]
pub enum ConflictResolutionStrategy {
    /// Prefer older session
    PreferOlder,

    /// Prefer newer session
    PreferNewer,

    /// Prefer session with higher priority
    PreferHigherPriority,

    /// Custom resolution logic
    Custom(String),
}

/// Session resource type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SessionResourceType {
    /// Port resource
    Port,

    /// Memory buffer
    MemoryBuffer,

    /// Crypto context
    CryptoContext,

    /// Network socket
    NetworkSocket,

    /// Custom resource
    Custom(String),
}

/// Session resource allocation
#[derive(Debug, Clone)]
pub struct SessionResourceAllocation {
    /// Resource type
    pub resource_type: SessionResourceType,

    /// Resource identifier
    pub resource_id: String,

    /// Allocated to session
    pub session_id: SessionId,

    /// Allocation timestamp
    pub allocated_at: Timestamp,

    /// Resource metadata
    pub metadata: HashMap<String, String>,
}

/// Session coordination configuration
#[derive(Debug, Clone)]
pub struct SessionCoordinationConfig {
    /// Maximum sessions per connection
    pub max_sessions_per_connection: Threshold,

    /// Enable conflict detection
    pub enable_conflict_detection: bool,

    /// Conflict resolution strategy
    pub conflict_resolution_strategy: ConflictResolutionStrategy,

    /// Enable resource management
    pub enable_resource_management: bool,

    /// Resource allocation timeout
    pub resource_allocation_timeout: Timeout,

    /// Enable session synchronization
    pub enable_session_synchronization: bool,

    /// Synchronization interval
    pub synchronization_interval: Timeout,
}

impl Default for SessionCoordinationConfig {
    fn default() -> Self {
        Self {
            max_sessions_per_connection: Threshold::from_raw(100),
            enable_conflict_detection: true,
            conflict_resolution_strategy: ConflictResolutionStrategy::PreferOlder,
            enable_resource_management: true,
            resource_allocation_timeout: Timeout::new(5000), // 5 seconds
            enable_session_synchronization: true,
            synchronization_interval: Timeout::new(30000), // 30 seconds
        }
    }
}

/// Session coordination statistics
#[derive(Debug, Default, Clone)]
pub struct SessionCoordinationStats {
    pub registered_sessions: Counter,
    pub unregistered_sessions: Counter,
    pub conflicts_detected: Counter,
    pub conflicts_resolved: Counter,
    pub resources_allocated: Counter,
    pub resources_deallocated: Counter,
    pub synchronizations_performed: Counter,
    pub last_synchronization: Timestamp,
}

/// Session Coordination - manages multi-session coordination and conflict resolution
pub struct SessionCoordination {
    /// Connection ID this coordination belongs to
    connection_id: ConnectionId,

    /// Configuration
    config: SessionCoordinationConfig,

    /// Registered sessions
    sessions: DashMap<SessionId, Arc<SessionState>>,

    /// Session metadata
    session_metadata: DashMap<SessionId, HashMap<String, String>>,

    /// Session priorities
    session_priorities: DashMap<SessionId, Threshold>,

    /// Resource allocations
    resource_allocations: DashMap<String, SessionResourceAllocation>,

    /// Resource semaphores for limiting concurrent access
    resource_semaphores: DashMap<SessionResourceType, Arc<Semaphore>>,

    /// Active conflicts
    active_conflicts: DashMap<(SessionId, SessionId), SessionConflictType>,

    /// Event history
    events: RwLock<Vec<SessionCoordinationEvent>>,

    /// Statistics
    stats: RwLock<SessionCoordinationStats>,

    /// Synchronization task handle
    sync_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Session creation order
    session_creation_order: RwLock<Vec<SessionId>>,
}

impl SessionCoordination {
    /// Create a new session coordination
    pub fn new(connection_id: ConnectionId) -> Self {
        let config = SessionCoordinationConfig::default();

        // Initialize resource semaphores
        let resource_semaphores = DashMap::new();
        resource_semaphores.insert(SessionResourceType::Port, Arc::new(Semaphore::new(65536)));
        resource_semaphores.insert(
            SessionResourceType::MemoryBuffer,
            Arc::new(Semaphore::new(1000)),
        );
        resource_semaphores.insert(
            SessionResourceType::CryptoContext,
            Arc::new(Semaphore::new(100)),
        );
        resource_semaphores.insert(
            SessionResourceType::NetworkSocket,
            Arc::new(Semaphore::new(1000)),
        );

        Self {
            connection_id,
            config,
            sessions: DashMap::new(),
            session_metadata: DashMap::new(),
            session_priorities: DashMap::new(),
            resource_allocations: DashMap::new(),
            resource_semaphores,
            active_conflicts: DashMap::new(),
            events: RwLock::new(Vec::new()),
            stats: RwLock::new(SessionCoordinationStats::default()),
            sync_handle: Mutex::new(None),
            session_creation_order: RwLock::new(Vec::new()),
        }
    }

    /// Start session coordination
    pub async fn start(&self) -> SessionResult<()> {
        // Start synchronization task if enabled
        if self.config.enable_session_synchronization {
            self.start_synchronization_task().await;
        }

        info!(
            connection_id = %self.connection_id,
            "Session coordination started"
        );

        Ok(())
    }

    /// Stop session coordination
    pub async fn stop(&self) -> SessionResult<()> {
        // Stop synchronization task
        if let Some(handle) = self.sync_handle.lock().await.take() {
            handle.abort();
        }

        // Unregister all sessions
        let session_ids: Vec<SessionId> = self
            .sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for session_id in session_ids {
            if let Err(e) = self.unregister_session(session_id.clone()).await {
                warn!(
                    connection_id = %self.connection_id,
                    session_id = %session_id,
                    error = %e,
                    "Failed to unregister session during shutdown"
                );
            }
        }

        info!(
            connection_id = %self.connection_id,
            "Session coordination stopped"
        );

        Ok(())
    }

    /// Register a session
    #[instrument(skip(self, session_state), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn register_session(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
    ) -> SessionResult<()> {
        // Check session limit
        if self.sessions.len() >= self.config.max_sessions_per_connection.0 as usize {
            return Err(SessionError::SessionCapacityExceeded {
                current: SessionCount::new(self.sessions.len() as u32),
                max: SessionCount::new(self.config.max_sessions_per_connection.as_u32()),
            });
        }

        // Check for existing session
        if self.sessions.contains_key(&session_id) {
            return Err(SessionError::SessionAlreadyExists { session_id });
        }

        // Register session
        self.sessions
            .insert(session_id.clone(), session_state.clone());

        // Initialize metadata
        self.session_metadata
            .insert(session_id.clone(), HashMap::new());

        // Set default priority
        self.session_priorities
            .insert(session_id.clone(), Threshold::from_raw(100));

        // Update creation order
        {
            let mut creation_order = self.session_creation_order.write().await;
            creation_order.push(session_id.clone());
        }

        // Detect conflicts with existing sessions
        if self.config.enable_conflict_detection {
            self.detect_conflicts(session_id.clone()).await?;
        }

        // Record event
        self.record_event(SessionCoordinationEvent::SessionRegistered {
            session_id: session_id.clone(),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.registered_sessions += 1;
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            total_sessions = self.sessions.len(),
            "Session registered"
        );

        Ok(())
    }

    /// Unregister a session
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn unregister_session(&self, session_id: SessionId) -> SessionResult<()> {
        // Remove session
        let session_removed = self.sessions.remove(&session_id).is_some();

        if !session_removed {
            return Err(SessionError::SessionNotFound { session_id });
        }

        // Clean up metadata
        self.session_metadata.remove(&session_id);
        self.session_priorities.remove(&session_id);

        // Update creation order
        {
            let mut creation_order = self.session_creation_order.write().await;
            creation_order.retain(|id| *id != session_id);
        }

        // Deallocate resources
        self.deallocate_session_resources(session_id.clone())
            .await?;

        // Remove from active conflicts
        let conflicts_to_remove: Vec<(SessionId, SessionId)> = self
            .active_conflicts
            .iter()
            .filter_map(|entry| {
                let (session1, session2) = entry.key();
                if *session1 == session_id || *session2 == session_id {
                    Some((session1.clone(), session2.clone()))
                } else {
                    None
                }
            })
            .collect();

        for conflict_key in conflicts_to_remove {
            self.active_conflicts.remove(&conflict_key);
        }

        // Record event
        self.record_event(SessionCoordinationEvent::SessionUnregistered {
            session_id: session_id.clone(),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.unregistered_sessions += 1;
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            remaining_sessions = self.sessions.len(),
            "Session unregistered"
        );

        Ok(())
    }

    /// Allocate resource to session
    pub async fn allocate_resource(
        &self,
        session_id: SessionId,
        resource_type: SessionResourceType,
        resource_id: String,
        metadata: HashMap<String, String>,
    ) -> SessionResult<()> {
        // Check if session is registered
        if !self.sessions.contains_key(&session_id) {
            return Err(SessionError::SessionNotFound { session_id });
        }

        // Check if resource is already allocated
        if self.resource_allocations.contains_key(&resource_id) {
            return Err(SessionError::session_resource_exhaustion(format!(
                "Resource {} already allocated",
                resource_id
            )));
        }

        // Acquire semaphore permit
        let semaphore = self
            .resource_semaphores
            .get(&resource_type)
            .ok_or_else(|| {
                SessionError::session_resource_exhaustion(format!(
                    "No semaphore for resource type {:?}",
                    resource_type
                ))
            })?;

        let _permit = tokio::time::timeout(
            Duration::from_millis(self.config.resource_allocation_timeout.as_millis()),
            semaphore.acquire(),
        )
        .await
        .map_err(|_| SessionError::session_resource_exhaustion("Resource allocation timeout"))?
        .map_err(|_| SessionError::session_resource_exhaustion("Semaphore closed"))?;

        // Create allocation
        let allocation = SessionResourceAllocation {
            resource_type: resource_type.clone(),
            resource_id: resource_id.clone(),
            session_id: session_id.clone(),
            allocated_at: self.current_timestamp(),
            metadata,
        };

        // Store allocation
        self.resource_allocations
            .insert(resource_id.clone(), allocation);

        // Record event
        self.record_event(SessionCoordinationEvent::ResourceAllocated {
            session_id: session_id.clone(),
            resource_type: format!("{:?}", resource_type),
            resource_id: resource_id.clone(),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.resources_allocated += 1;
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            resource_type = ?resource_type,
            resource_id = %resource_id,
            "Resource allocated"
        );

        Ok(())
    }

    /// Deallocate resource from session
    pub async fn deallocate_resource(&self, resource_id: &str) -> SessionResult<()> {
        // Get allocation
        let allocation = self
            .resource_allocations
            .remove(resource_id)
            .ok_or_else(|| {
                SessionError::session_resource_exhaustion(format!(
                    "Resource {} not found",
                    resource_id
                ))
            })?;

        let allocation = allocation.1;

        // Record event
        self.record_event(SessionCoordinationEvent::ResourceDeallocated {
            session_id: allocation.session_id.clone(),
            resource_type: format!("{:?}", allocation.resource_type),
            resource_id: resource_id.to_string(),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.resources_deallocated += 1;
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %allocation.session_id,
            resource_type = ?allocation.resource_type,
            resource_id,
            "Resource deallocated"
        );

        Ok(())
    }

    /// Set session priority
    pub async fn set_session_priority(
        &self,
        session_id: SessionId,
        priority: Threshold,
    ) -> SessionResult<()> {
        if !self.sessions.contains_key(&session_id) {
            return Err(SessionError::SessionNotFound { session_id });
        }

        self.session_priorities.insert(session_id.clone(), priority);

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            priority = priority.as_u32(),
            "Session priority updated"
        );

        Ok(())
    }

    /// Get session priority
    pub fn get_session_priority(&self, session_id: SessionId) -> Option<Threshold> {
        self.session_priorities.get(&session_id).map(|entry| *entry)
    }

    /// Get registered session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get all registered session IDs
    pub fn get_session_ids(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Synchronize sessions
    pub async fn synchronize_sessions(&self) -> SessionResult<()> {
        let session_ids = self.get_session_ids();

        if session_ids.is_empty() {
            return Ok(());
        }

        // Perform synchronization logic here
        // This could include state synchronization, conflict resolution, etc.

        // Record event
        self.record_event(SessionCoordinationEvent::SessionsSynchronized {
            session_ids: session_ids.clone(),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.synchronizations_performed += 1;
            stats.last_synchronization = self.current_timestamp();
        }

        debug!(
            connection_id = %self.connection_id,
            session_count = session_ids.len(),
            "Sessions synchronized"
        );

        Ok(())
    }

    /// Detect conflicts for a session
    async fn detect_conflicts(&self, session_id: SessionId) -> SessionResult<()> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(SessionError::SessionNotFound {
                session_id: session_id.clone(),
            })?;

        // Check for port conflicts
        for other_entry in self.sessions.iter() {
            let other_session_id = other_entry.key().clone();
            let other_session = other_entry.value();

            if other_session_id == session_id {
                continue;
            }

            // Check port conflict
            if session.local_port().as_u16() == other_session.local_port().as_u16()
                && session.local_port().as_u16() != 0
            {
                self.handle_conflict(
                    session_id.clone(),
                    other_session_id.clone(),
                    SessionConflictType::PortConflict,
                )
                .await?;
            }

            // Check sequence number conflict
            if session.local_seq().as_u32() == other_session.local_seq().as_u32()
                && session.local_seq().as_u32() != 0
            {
                self.handle_conflict(
                    session_id.clone(),
                    other_session_id.clone(),
                    SessionConflictType::SequenceConflict,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Handle session conflict
    async fn handle_conflict(
        &self,
        session1: SessionId,
        session2: SessionId,
        conflict_type: SessionConflictType,
    ) -> SessionResult<()> {
        let conflict_key = if session1 < session2 {
            (session1.clone(), session2.clone())
        } else {
            (session2.clone(), session1.clone())
        };

        // Check if conflict is already being handled
        if self.active_conflicts.contains_key(&conflict_key) {
            return Ok(());
        }

        // Record active conflict
        self.active_conflicts
            .insert(conflict_key.clone(), conflict_type.clone());

        // Record event
        self.record_event(SessionCoordinationEvent::ConflictDetected {
            session1: session1.clone(),
            session2: session2.clone(),
            conflict_type: format!("{:?}", conflict_type),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Resolve conflict
        let resolution = self
            .resolve_conflict(session1.clone(), session2.clone(), &conflict_type)
            .await?;

        // Remove from active conflicts
        self.active_conflicts.remove(&conflict_key);

        // Record resolution
        self.record_event(SessionCoordinationEvent::ConflictResolved {
            session1: session1.clone(),
            session2: session2.clone(),
            resolution: resolution.clone(),
            timestamp: self.current_timestamp(),
        })
        .await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.conflicts_detected += 1;
            stats.conflicts_resolved += 1;
        }

        warn!(
            connection_id = %self.connection_id,
            session1 = %session1,
            session2 = %session2,
            conflict_type = ?conflict_type,
            resolution,
            "Session conflict resolved"
        );

        Ok(())
    }

    /// Resolve session conflict
    async fn resolve_conflict(
        &self,
        session1: SessionId,
        session2: SessionId,
        conflict_type: &SessionConflictType,
    ) -> SessionResult<String> {
        match &self.config.conflict_resolution_strategy {
            ConflictResolutionStrategy::PreferOlder => {
                let creation_order = self.session_creation_order.read().await;
                let pos1 = creation_order.iter().position(|id| *id == session1);
                let pos2 = creation_order.iter().position(|id| *id == session2);

                match (pos1, pos2) {
                    (Some(p1), Some(p2)) => {
                        if p1 < p2 {
                            self.resolve_in_favor_of(session1, session2, conflict_type)
                                .await
                        } else {
                            self.resolve_in_favor_of(session2, session1, conflict_type)
                                .await
                        }
                    }
                    _ => Ok("Unable to determine age".to_string()),
                }
            }
            ConflictResolutionStrategy::PreferNewer => {
                let creation_order = self.session_creation_order.read().await;
                let pos1 = creation_order.iter().position(|id| *id == session1);
                let pos2 = creation_order.iter().position(|id| *id == session2);

                match (pos1, pos2) {
                    (Some(p1), Some(p2)) => {
                        if p1 > p2 {
                            self.resolve_in_favor_of(session1, session2, conflict_type)
                                .await
                        } else {
                            self.resolve_in_favor_of(session2, session1, conflict_type)
                                .await
                        }
                    }
                    _ => Ok("Unable to determine age".to_string()),
                }
            }
            ConflictResolutionStrategy::PreferHigherPriority => {
                let priority1 = self
                    .get_session_priority(session1.clone())
                    .unwrap_or(Threshold::from_raw(0));
                let priority2 = self
                    .get_session_priority(session2.clone())
                    .unwrap_or(Threshold::from_raw(0));

                if priority1.as_u32() > priority2.as_u32() {
                    self.resolve_in_favor_of(session1, session2, conflict_type)
                        .await
                } else {
                    self.resolve_in_favor_of(session2, session1, conflict_type)
                        .await
                }
            }
            ConflictResolutionStrategy::Custom(strategy) => {
                Ok(format!("Custom resolution: {}", strategy))
            }
        }
    }

    /// Resolve conflict in favor of a specific session
    async fn resolve_in_favor_of(
        &self,
        winner: SessionId,
        loser: SessionId,
        conflict_type: &SessionConflictType,
    ) -> SessionResult<String> {
        match conflict_type {
            SessionConflictType::PortConflict => {
                // Reassign port for the losing session
                if let Some(loser_session) = self.sessions.get(&loser) {
                    // Generate new port (simplified)
                    let new_port = Port::new((loser.as_u64() % 65535) as u16 + 1024)?;
                    loser_session.set_local_port(new_port);
                    Ok(format!(
                        "Reassigned port {} to session {}",
                        new_port.as_u16(),
                        loser
                    ))
                } else {
                    Ok("Loser session not found".to_string())
                }
            }
            SessionConflictType::SequenceConflict => {
                // Adjust sequence number for the losing session
                if let Some(loser_session) = self.sessions.get(&loser) {
                    let new_seq = SequenceNumber::new(loser_session.local_seq().as_u32() + 1000);
                    let new_seq_value = new_seq.as_u32();
                    loser_session.set_local_seq(new_seq);
                    Ok(format!(
                        "Adjusted sequence to {} for session {}",
                        new_seq_value, loser
                    ))
                } else {
                    Ok("Loser session not found".to_string())
                }
            }
            _ => Ok(format!(
                "Resolved {:?} in favor of session {}",
                conflict_type, winner
            )),
        }
    }

    /// Deallocate all resources for a session
    async fn deallocate_session_resources(&self, session_id: SessionId) -> SessionResult<()> {
        let resources_to_deallocate: Vec<String> = self
            .resource_allocations
            .iter()
            .filter_map(|entry| {
                if entry.value().session_id == session_id {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        for resource_id in resources_to_deallocate {
            if let Err(e) = self.deallocate_resource(&resource_id).await {
                warn!(
                    connection_id = %self.connection_id,
                    session_id = %session_id,
                    resource_id,
                    error = %e,
                    "Failed to deallocate resource"
                );
            }
        }

        Ok(())
    }

    /// Start synchronization task
    async fn start_synchronization_task(&self) {
        let connection_id = self.connection_id;
        let sync_interval = Duration::from_millis(self.config.synchronization_interval.as_millis());

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(sync_interval);

            loop {
                interval.tick().await;

                // Simple synchronization monitoring without self reference
                // In a real implementation, this would perform actual synchronization
                debug!(
                    connection_id = %connection_id,
                    "Session synchronization tick"
                );

                // Break after some time to avoid infinite loops in tests
                // In production, this would run until the coordination is dropped
            }
        });

        *self.sync_handle.lock().await = Some(handle);
    }

    /// Record coordination event
    async fn record_event(&self, event: SessionCoordinationEvent) {
        let mut events = self.events.write().await;
        events.push(event);

        // Limit event history size
        const MAX_EVENTS: usize = 1000;
        if events.len() > MAX_EVENTS {
            let drain_count = events.len() - MAX_EVENTS;
            events.drain(0..drain_count);
        }
    }

    /// Get current timestamp
    fn current_timestamp(&self) -> Timestamp {
        Timestamp::now()
    }

    /// Get coordination statistics
    pub async fn get_stats(&self) -> SessionCoordinationStats {
        self.stats.read().await.clone()
    }

    /// Get event history
    pub async fn get_events(&self) -> Vec<SessionCoordinationEvent> {
        self.events.read().await.clone()
    }
}

impl Drop for SessionCoordination {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd use a proper shutdown mechanism
        if let Ok(mut handle) = self.sync_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}
