// Session Manager - manages session lifecycle and coordination
//
// This implements the session management system that handles session creation,
// lifecycle management, state tracking, and multi-session coordination.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, atomic::Ordering};

use dashmap::DashMap;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::{Mutex, RwLock};
use tracing::{Level, debug, info, instrument, span, warn};

use super::{SessionCoordination, SessionLifecycle, SessionState};
use crate::engines::adaptive::AdaptiveNetworkingEngine;
use crate::engines::{FlowControlEngine, PortHoppingEngine, RecoveryEngine, TimeSyncEngine};
use crate::error::{SessionError, SessionResult};
use crate::memory::secure::SecureBytes;
use crate::protocol::types::{
    AttemptCount, ConnectionId, Counter, SaltBytes, SessionCount, SessionId, Threshold, Timeout,
    Timestamp,
};
use crate::security::crypto::kdf::{Kdf, KdfResult};

/// Session manager configuration
#[derive(Debug, Clone)]
pub struct SessionManagerConfig {
    /// Maximum concurrent sessions
    pub max_sessions: Threshold,

    /// Session cleanup interval
    pub cleanup_interval: Timeout,

    /// Default session timeout
    pub default_session_timeout: Timeout,

    /// Enable session pooling
    pub enable_session_pooling: bool,

    /// Session pool size per connection
    pub session_pool_size: Threshold,

    /// Enable automatic session recovery
    pub enable_auto_recovery: bool,

    /// Session heartbeat interval
    pub heartbeat_interval: Timeout,

    /// Enable session state persistence
    pub enable_state_persistence: bool,

    /// Local endpoint for engine initialization
    pub local_endpoint: Option<SocketAddr>,

    /// Remote endpoint for engine initialization
    pub remote_endpoint: Option<SocketAddr>,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            max_sessions: Threshold::from_raw(10000),
            cleanup_interval: Timeout::new(30_000), // 30 seconds
            default_session_timeout: Timeout::new(300_000), // 5 minutes
            enable_session_pooling: true,
            session_pool_size: Threshold::from_raw(10),
            enable_auto_recovery: true,
            heartbeat_interval: Timeout::new(30_000), // 30 seconds
            enable_state_persistence: false,
            local_endpoint: None,
            remote_endpoint: None,
        }
    }
}

/// Session manager statistics
#[derive(Debug, Default, Clone)]
pub struct SessionManagerStats {
    pub total_sessions_created: Counter,
    pub total_sessions_closed: Counter,
    pub active_sessions: Counter,
    pub sessions_by_connection: HashMap<ConnectionId, Counter>,
    pub cleanup_runs: Counter,
    pub recovery_attempts: Counter,
    pub heartbeats_sent: Counter,
    pub last_cleanup_ms: Timestamp,
}

/// Session Manager - manages session lifecycle and coordination
pub struct SessionManager {
    /// Configuration
    config: SessionManagerConfig,

    /// Connection ID this session manager belongs to
    connection_id: ConnectionId,

    /// Active sessions by ID
    sessions: DashMap<SessionId, Arc<SessionState>>,

    /// Session lifecycles by ID
    lifecycles: DashMap<SessionId, Arc<SessionLifecycle>>,

    /// Session ID generator
    session_id_generator: SessionId,

    /// Session coordination
    coordination: Arc<SessionCoordination>,

    /// Random number generator
    rng: SystemRandom,

    /// Statistics
    stats: RwLock<SessionManagerStats>,

    /// Cleanup task handle
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Heartbeat task handle
    heartbeat_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Session creation order (for cleanup)
    session_creation_order: RwLock<Vec<SessionId>>,

    /// Port hopping engine
    port_hopping_engine: Option<Arc<PortHoppingEngine>>,

    /// Time synchronization engine
    time_sync_engine: Arc<TimeSyncEngine>,

    /// Recovery engine
    recovery_engine: Option<Arc<RecoveryEngine>>,

    /// Flow control engines by session
    flow_control_engines: DashMap<SessionId, Arc<FlowControlEngine>>,

    /// Adaptive networking engine
    adaptive_engine: Arc<AdaptiveNetworkingEngine>,
}

// SAFETY: SessionManager is used across threads via Arc. All fields are either:
// - Thread-safe types (Arc, DashMap, RwLock, Mutex, atomic types)
// - SystemRandom which is internally synchronized
// The only non-Sync field is `rng: SystemRandom`, but it's only accessed through
// &self methods that internally synchronize access.
unsafe impl Send for SessionManager {}
unsafe impl Sync for SessionManager {}

impl SessionManager {
    /// Create a new session manager for a specific connection
    pub fn new(connection_id: ConnectionId, config: SessionManagerConfig) -> Self {
        let _span = span!(Level::DEBUG, "session_manager_new", connection_id = %connection_id);
        let coordination = Arc::new(SessionCoordination::new(connection_id));

        // Initialize time sync engine (no dependencies)
        let time_sync_engine = Arc::new(TimeSyncEngine::new());

        // Initialize adaptive networking engine (no dependencies)
        let adaptive_engine = Arc::new(AdaptiveNetworkingEngine::new());

        // Initialize port hopping engine if endpoints are provided
        let port_hopping_engine = if let (Some(local_endpoint), Some(remote_endpoint)) =
            (config.local_endpoint, config.remote_endpoint)
        {
            Some(Arc::new(PortHoppingEngine::new_for_connection(
                connection_id,
                local_endpoint,
                remote_endpoint,
            )))
        } else {
            None
        };

        // Recovery engine requires endpoints and session manager trait implementation
        // It will be initialized in start() after SessionManager is fully constructed
        let recovery_engine = None;

        Self {
            config,
            connection_id,
            sessions: DashMap::new(),
            lifecycles: DashMap::new(),
            session_id_generator: SessionId::new(1),
            coordination,
            rng: SystemRandom::new(),
            stats: RwLock::new(SessionManagerStats::default()),
            cleanup_handle: Mutex::new(None),
            heartbeat_handle: Mutex::new(None),
            session_creation_order: RwLock::new(Vec::new()),
            port_hopping_engine,
            time_sync_engine,
            recovery_engine,
            flow_control_engines: DashMap::new(),
            adaptive_engine,
        }
    }

    /// Start the session manager
    pub async fn start(&self) -> SessionResult<()> {
        let _span = span!(
            Level::INFO,
            "session_manager_start",
            connection_id = %self.connection_id
        );

        // Initialize adaptive networking engine
        if let Err(e) = self.adaptive_engine.initialize() {
            warn!(
                connection_id = %self.connection_id,
                error = %e,
                "Failed to initialize adaptive networking engine"
            );
        }

        info!(
            connection_id = %self.connection_id,
            max_sessions = %self.config.max_sessions,
            port_hopping_enabled = self.port_hopping_engine.is_some(),
            "Session manager started with engines"
        );

        Ok(())
    }

    /// Stop the session manager
    pub async fn stop(&self) -> SessionResult<()> {
        // Stop cleanup task
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            handle.abort();
        }

        // Stop heartbeat task
        if let Some(handle) = self.heartbeat_handle.lock().await.take() {
            handle.abort();
        }

        // Close all sessions
        let session_ids: Vec<SessionId> = self
            .sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for session_id in session_ids {
            let session_id_for_logging = session_id.clone();
            if let Err(e) = self.close_session(session_id).await {
                warn!(
                    connection_id = %self.connection_id,
                    session_id = %session_id_for_logging,
                    error = %e,
                    "Failed to close session during shutdown"
                );
            }
        }

        info!(
            connection_id = %self.connection_id,
            "Session manager stopped"
        );

        Ok(())
    }

    /// Create a new session
    #[instrument(skip(self), fields(connection_id = %self.connection_id))]
    pub async fn create_session(&self) -> SessionResult<(SessionId, Arc<SessionState>)> {
        // Check session limit
        if self.sessions.len() >= self.config.max_sessions.0 as usize {
            warn!(
                connection_id = %self.connection_id,
                current_sessions = self.sessions.len(),
                max_sessions = self.config.max_sessions.as_u32(),
                "Session limit exceeded"
            );
            return Err(SessionError::SessionCapacityExceeded {
                current: SessionCount::new(self.sessions.len() as u32),
                max: SessionCount::new(self.config.max_sessions.as_u32()),
            });
        }

        // Generate unique session ID
        let session_id = self.generate_session_id()?;

        // Create session state
        let session_state = Arc::new(SessionState::new());

        // Create session lifecycle
        let lifecycle = Arc::new(SessionLifecycle::new(
            session_id.clone(),
            self.connection_id,
            self.config.default_session_timeout,
        ));

        // Store session and lifecycle
        self.sessions
            .insert(session_id.clone(), session_state.clone());
        self.lifecycles
            .insert(session_id.clone(), lifecycle.clone());

        // Update creation order
        {
            let mut creation_order = self.session_creation_order.write().await;
            creation_order.push(session_id.clone());
        }

        // Register with coordination
        self.coordination
            .register_session(session_id.clone(), session_state.clone())
            .await?;

        // Start lifecycle
        lifecycle.start().await?;

        // Create flow control engine for this session
        let flow_control_engine = Arc::new(FlowControlEngine::new(
            self.connection_id,
            session_id.clone(),
            0, // Initial send sequence
            0, // Initial receive sequence
        ));
        self.flow_control_engines
            .insert(session_id.clone(), flow_control_engine);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_sessions_created += 1;
            stats.active_sessions += 1;
            stats
                .sessions_by_connection
                .entry(self.connection_id)
                .and_modify(|count| {
                    *count += 1;
                })
                .or_insert(Counter::new(1));
        }

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            total_sessions = self.sessions.len(),
            "Session created with flow control engine"
        );

        Ok((session_id, session_state))
    }

    /// Create session with ECDH parameters
    pub async fn create_session_with_ecdh(
        &self,
        shared_secret: &[u8],
        salt: &[u8],
    ) -> SessionResult<(SessionId, Arc<SessionState>)> {
        // Create session
        let (session_id, session_state) = self.create_session().await?;

        // Derive parameters from ECDH
        let params = self
            .derive_session_parameters(shared_secret, salt)
            .map_err(|e| {
                SessionError::session_creation_failed(format!("Ecdh derivation failed: {}", e))
            })?;

        // Initialize session with derived parameters
        session_state.init_from_pbkdf2(&params).map_err(|e| {
            SessionError::session_creation_failed(format!("Parameter initialization failed: {}", e))
        })?;

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            "Session created with ECDH parameters"
        );

        Ok((session_id, session_state))
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: SessionId) -> Option<Arc<SessionState>> {
        self.sessions.get(&session_id).map(|entry| entry.clone())
    }

    /// Get session lifecycle by ID
    pub fn get_session_lifecycle(&self, session_id: SessionId) -> Option<Arc<SessionLifecycle>> {
        self.lifecycles.get(&session_id).map(|entry| entry.clone())
    }

    /// Close session
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn close_session(&self, session_id: SessionId) -> SessionResult<bool> {
        // Get lifecycle first
        let lifecycle = self.get_session_lifecycle(session_id.clone()).ok_or(
            SessionError::SessionNotFound {
                session_id: session_id.clone(),
            },
        )?;

        // Stop lifecycle
        lifecycle.stop().await?;

        // Unregister from coordination
        self.coordination
            .unregister_session(session_id.clone())
            .await?;

        // Remove from maps
        let session_removed = self.sessions.remove(&session_id).is_some();
        self.lifecycles.remove(&session_id);

        // Remove flow control engine for this session
        self.flow_control_engines.remove(&session_id);

        if session_removed {
            // Update creation order
            {
                let mut creation_order = self.session_creation_order.write().await;
                creation_order.retain(|id| *id != session_id);
            }

            // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
            info!(
                connection_id = %self.connection_id,
                session_id = %session_id,
                remaining_sessions = self.sessions.len(),
                "Session closed and engines cleaned up"
            );
        }

        Ok(session_removed)
    }

    /// Get all active session IDs
    pub fn get_active_session_ids(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Update session activity
    pub async fn update_session_activity(&self, session_id: SessionId) -> SessionResult<()> {
        let session =
            self.get_session(session_id.clone())
                .ok_or(SessionError::SessionNotFound {
                    session_id: session_id.clone(),
                })?;

        session.update_activity();

        // Update lifecycle
        if let Some(lifecycle) = self.get_session_lifecycle(session_id.clone()) {
            lifecycle.update_activity().await?;
        }

        Ok(())
    }

    /// Check session health
    pub async fn check_session_health(&self, session_id: SessionId) -> SessionResult<bool> {
        let lifecycle = self
            .get_session_lifecycle(session_id.clone())
            .ok_or(SessionError::SessionNotFound { session_id })?;

        lifecycle.is_healthy().await
    }

    /// Recover session
    pub async fn recover_session(&self, session_id: SessionId) -> SessionResult<()> {
        if !self.config.enable_auto_recovery {
            return Err(SessionError::session_management_error(
                "Auto recovery disabled",
            ));
        }

        let lifecycle = self.get_session_lifecycle(session_id.clone()).ok_or(
            SessionError::SessionNotFound {
                session_id: session_id.clone(),
            },
        )?;

        // Attempt recovery
        lifecycle.recover().await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.recovery_attempts += 1;
        }

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            "Session recovery completed"
        );

        Ok(())
    }

    /// Generate unique session ID
    fn generate_session_id(&self) -> SessionResult<SessionId> {
        let attempts = AttemptCount::new(0);
        const MAX_ATTEMPTS: u32 = 1000;

        loop {
            // Generate base ID from atomic counter
            let base_id = self.session_id_generator.fetch_add(1, Ordering::Relaxed);

            // Add some randomness to prevent predictability
            let mut random_bytes = [0u8; 8];
            if self.rng.fill(&mut random_bytes).is_ok() {
                let random_part = u64::from_be_bytes(random_bytes);
                let session_id = SessionId::from_raw(base_id ^ (random_part >> 32));

                // Ensure uniqueness
                if !self.sessions.contains_key(&session_id) {
                    return Ok(session_id);
                }
            }

            attempts.increment(Ordering::Relaxed);
            if attempts.as_u32() >= MAX_ATTEMPTS {
                return Err(SessionError::session_creation_failed(
                    "Failed to generate unique session ID",
                ));
            }
        }
    }

    /// Derive session parameters from ECDH shared secret
    fn derive_session_parameters(
        &self,
        shared_secret: &[u8],
        salt: &[u8],
    ) -> KdfResult<SecureBytes> {
        // Create KDF with the provided salt
        let mut kdf = Kdf::new_default();
        kdf.set_salt(SaltBytes::new(salt.to_vec()));

        // Derive parameters
        #[allow(deprecated)]
        let result = kdf.derive_parameters(shared_secret);
        result
    }

    /// Get session manager statistics
    pub async fn get_stats(&self) -> SessionManagerStats {
        let mut stats = self.stats.read().await.clone();

        // Update current counts
        stats.active_sessions = Counter::new(self.sessions.len() as u64);

        stats
    }

    /// Get detailed session information
    #[allow(clippy::mutable_key_type)] // SessionId has interior mutability by design for atomic operations
    pub async fn get_session_info(&self) -> HashMap<SessionId, serde_json::Value> {
        let mut info = HashMap::new();

        for entry in self.sessions.iter() {
            let session_id = entry.key().clone();
            let session = entry.value();

            let lifecycle_info =
                if let Some(lifecycle) = self.get_session_lifecycle(session_id.clone()) {
                    serde_json::json!({
                        "state": format!("{:?}", lifecycle.current_state().await),
                        "age_ms": lifecycle.age().await.as_millis(),
                        "is_healthy": lifecycle.is_healthy().await.unwrap_or(false),
                    })
                } else {
                    serde_json::json!({
                        "state": "unknown",
                        "age_ms": 0,
                        "is_healthy": false,
                    })
                };

            info.insert(
                session_id.clone(),
                serde_json::json!({
                    "session_id": session_id.to_string(),
                    "connection_id": self.connection_id.to_string(),
                    "status": format!("{:?}", session.status()),
                    "local_seq": session.local_seq().as_u32(),
                    "remote_seq": session.remote_seq().as_u32(),
                    "local_port": session.local_port().as_u16(),
                    "remote_port": session.remote_port().as_u16(),
                    "last_activity": session.last_activity(),
                    "lifecycle": lifecycle_info,
                }),
            );
        }

        info
    }

    /// Get coordination reference
    pub fn coordination(&self) -> Arc<SessionCoordination> {
        self.coordination.clone()
    }

    /// Get port hopping engine reference
    pub fn port_hopping_engine(&self) -> Option<Arc<PortHoppingEngine>> {
        self.port_hopping_engine.clone()
    }

    /// Get time sync engine reference
    pub fn time_sync_engine(&self) -> Arc<TimeSyncEngine> {
        self.time_sync_engine.clone()
    }

    /// Get recovery engine reference
    pub fn recovery_engine(&self) -> Option<Arc<RecoveryEngine>> {
        self.recovery_engine.clone()
    }

    /// Get flow control engine for a session
    pub fn flow_control_engine(&self, session_id: SessionId) -> Option<Arc<FlowControlEngine>> {
        self.flow_control_engines
            .get(&session_id)
            .map(|entry| entry.clone())
    }

    /// Get adaptive networking engine reference
    pub fn adaptive_engine(&self) -> Arc<AdaptiveNetworkingEngine> {
        self.adaptive_engine.clone()
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd use a proper shutdown mechanism
        // This is a simplified version for demonstration
        if let Ok(mut handle) = self.cleanup_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }

        if let Ok(mut handle) = self.heartbeat_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}
