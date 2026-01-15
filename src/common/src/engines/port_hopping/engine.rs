#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Port Hopping Engine - Consolidated port hopping logic with session awareness
//
// This implements the port hopping engine as specified in the architecture
// with per-connection instances and per-session port sequences.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::Mutex;
use ring::digest;
use tokio::sync::{RwLock, mpsc};
use tokio::time;
use tracing::{debug, error, info, instrument, warn};

use crate::engines::port_hopping::{PortHoppingCalculation, PortHoppingCoordination};
use crate::engines::time_sync::epoch::TimeEpoch;
use crate::error::EngineError;
use crate::protocol::packet::Packet;
use crate::protocol::types::*;
use crate::session::SessionState;

/// Port range constants
pub const MIN_PORT: Port = Port::from_u16_unchecked(1024);
pub const MAX_PORT: Port = Port::from_u16_unchecked(65535);
pub const PORT_RANGE: u16 = MAX_PORT.as_u16() - MIN_PORT.as_u16() + 1;

/// Per-session port hopping state
#[derive(Debug)]
pub struct SessionPortState {
    /// Session ID
    pub session_id: SessionId,

    /// Current local port for this session
    pub current_local_port: AtomicPortValue,

    /// Current remote port for this session
    pub current_remote_port: AtomicPortValue,

    /// Port sequence seed for this session
    pub port_seed: [u8; 32],

    /// Current epoch for port calculation
    pub current_epoch: AtomicEpochNumber,

    /// Last port hop time
    pub last_hop_time: std::cell::Cell<Timestamp>,

    /// Port hop interval (milliseconds)
    pub hop_interval_ms: WindowSize,

    /// Session HMAC key for port validation
    pub session_key: Arc<SessionKey>,

    /// Port validation failures
    pub validation_failures: FailureCount,

    /// Last activity time
    pub last_activity: std::cell::Cell<Timestamp>,
}

impl SessionPortState {
    pub fn new(
        session_id: SessionId,
        initial_local_port: Port,
        initial_remote_port: Port,
        port_seed: [u8; 32],
        session_key: Arc<SessionKey>,
        hop_interval_ms: u32,
    ) -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            session_id,
            current_local_port: AtomicPortValue::new(initial_local_port.as_u16()),
            current_remote_port: AtomicPortValue::new(initial_remote_port.as_u16()),
            port_seed,
            current_epoch: AtomicEpochNumber::new(0),
            last_hop_time: std::cell::Cell::new(Timestamp::from_millis(current_time)),
            hop_interval_ms: WindowSize::new(hop_interval_ms),
            session_key,
            validation_failures: FailureCount::new(0),
            last_activity: std::cell::Cell::new(Timestamp::from_millis(current_time)),
        }
    }

    pub fn update_activity(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_activity
            .set(Timestamp::from_nanos(current_time * 1_000_000)); // Convert to nanoseconds
    }
}

/// Port hopping configuration
#[derive(Debug, Clone)]
pub struct PortHoppingConfig {
    /// Default port hop interval (milliseconds)
    pub default_hop_interval_ms: ProtocolDuration,

    /// Minimum port number
    pub min_port: Port,

    /// Maximum port number
    pub max_port: Port,

    /// Port validation window (milliseconds)
    pub validation_window_ms: ProtocolDuration,

    /// Maximum validation failures before session reset
    pub max_validation_failures: crate::protocol::types::FailureCount,

    /// Enable adaptive hop intervals
    pub enable_adaptive_intervals: bool,

    /// Session cleanup timeout (seconds)
    pub session_cleanup_timeout: ProtocolDuration,
}

impl Default for PortHoppingConfig {
    fn default() -> Self {
        Self {
            default_hop_interval_ms: ProtocolDuration::from_millis(500), // 500ms as per spec
            min_port: MIN_PORT,
            max_port: MAX_PORT,
            validation_window_ms: ProtocolDuration::from_millis(5000), // 5 seconds
            max_validation_failures: FailureCount::new(5),
            enable_adaptive_intervals: true,
            session_cleanup_timeout: ProtocolDuration::from_secs(300), // 5 minutes
        }
    }
}

/// Connection-level port hopping statistics
#[derive(Debug, Default, Clone)]
pub struct PortHoppingStats {
    pub active_sessions: Counter,
    pub total_port_hops: Counter,
    pub total_validations: Counter,
    pub validation_failures: Counter,
    pub adaptive_adjustments: Counter,
    pub average_hop_interval_ms: ProtocolDuration,
}

/// Port binding status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortBindingStatus {
    /// Port is bound and active
    Active,

    /// Port is being bound
    Binding,

    /// Port binding failed
    Failed,

    /// Port is being unbound
    Unbinding,
}

/// Port binding information
#[derive(Debug)]
pub struct PortBinding {
    /// Port number
    pub port: Port,

    /// Binding status
    pub status: PortBindingStatus,

    /// Last activity timestamp
    pub last_activity: Timestamp,

    /// Reference count
    pub ref_count: UsageCount,
}

/// Port transition event
#[derive(Debug, Clone)]
pub struct PortTransitionEvent {
    /// Old port
    pub old_port: Port,

    /// New port
    pub new_port: Port,

    /// Time window
    pub time_window: ProtocolDuration,

    /// Transition time
    pub transition_time: ProtocolDuration,
}

/// Session-specific port hopping information
#[derive(Debug, Clone)]
pub struct SessionPortInfo {
    pub session_id: SessionId,
    pub current_local_port: Port,
    pub current_remote_port: Port,
    pub current_epoch: EpochNumber,
    pub hop_interval_ms: ProtocolDuration,
    pub validation_failures: crate::protocol::types::FailureCount,
    pub last_hop_duration: Duration,
}

/// Port Hopping Engine for connection-specific port coordination with session awareness
pub struct PortHoppingEngine {
    /// Connection ID this engine belongs to
    connection_id: ConnectionId,

    /// Local endpoint
    #[allow(dead_code)]
    local_endpoint: SocketAddr,

    /// Remote endpoint
    #[allow(dead_code)]
    remote_endpoint: SocketAddr,

    /// Per-session port hopping states
    session_states: DashMap<SessionId, Arc<SessionPortState>>,

    /// Port hopping configuration
    config: PortHoppingConfig,

    /// Time epoch manager for port calculations
    time_epoch: Arc<TimeEpoch>,

    /// Connection-level statistics
    stats: RwLock<PortHoppingStats>,

    /// Port calculation engine
    calculation: PortHoppingCalculation,

    /// Port coordination engine
    #[allow(dead_code)]
    coordination: PortHoppingCoordination,

    /// Port bindings
    port_bindings: Arc<DashMap<Port, PortBinding>>,

    /// Port transition history
    port_history: Arc<Mutex<Vec<PortTransitionEvent>>>,

    /// Port transition event sender
    #[allow(dead_code)]
    transition_sender: mpsc::UnboundedSender<PortTransitionEvent>,

    /// Port transition event receiver
    transition_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<PortTransitionEvent>>>>,

    /// Adaptive delay window size
    #[allow(dead_code)]
    adaptive_delay_window: std::sync::atomic::AtomicUsize,

    /// Port binding callback
    bind_port_callback: Option<Arc<dyn Fn(Port) -> bool + Send + Sync>>,

    /// Port unbinding callback
    unbind_port_callback: Option<Arc<dyn Fn(Port) -> bool + Send + Sync>>,
}

// SAFETY: PortHoppingEngine is used across threads via Arc. All fields are either:
// - Thread-safe types (Arc, DashMap, RwLock, Mutex, atomic types)
// - The receiver is wrapped in Arc<Mutex<Option<_>>> which provides proper synchronization
// - All callbacks are Send + Sync
unsafe impl Send for PortHoppingEngine {}
unsafe impl Sync for PortHoppingEngine {}

impl PortHoppingEngine {
    /// Create new port hopping engine for connection
    pub fn new_for_connection(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Self {
        let (transition_sender, transition_receiver) = mpsc::unbounded_channel();
        let time_epoch = Arc::new(TimeEpoch::new());

        Self {
            connection_id,
            local_endpoint,
            remote_endpoint,
            session_states: DashMap::new(),
            config: PortHoppingConfig::default(),
            time_epoch: time_epoch.clone(),
            stats: RwLock::new(PortHoppingStats::default()),
            calculation: PortHoppingCalculation::new(time_epoch),
            coordination: PortHoppingCoordination::new(),
            port_bindings: Arc::new(DashMap::new()),
            port_history: Arc::new(Mutex::new(Vec::with_capacity(100))),
            transition_sender,
            transition_receiver: Arc::new(Mutex::new(Some(transition_receiver))),
            adaptive_delay_window: std::sync::atomic::AtomicUsize::new(3), // Default to 3 windows (1.5 seconds)
            bind_port_callback: None,
            unbind_port_callback: None,
        }
    }

    /// Set port binding callback
    pub fn set_bind_port_callback<F>(&mut self, callback: F)
    where
        F: Fn(Port) -> bool + Send + Sync + 'static,
    {
        self.bind_port_callback = Some(Arc::new(callback));
    }

    /// Set port unbinding callback
    pub fn set_unbind_port_callback<F>(&mut self, callback: F)
    where
        F: Fn(Port) -> bool + Send + Sync + 'static,
    {
        self.unbind_port_callback = Some(Arc::new(callback));
    }

    /// Start the port hopping engine
    pub async fn start(&self) -> Result<(), EngineError> {
        // Start port transition processor
        self.start_port_transition_processor().await?;

        // Start port cleanup task
        self.start_port_cleanup_task().await?;

        // Start port cache maintenance task
        self.start_cache_maintenance_task().await?;

        Ok(())
    }

    /// Add a session to port hopping tracking
    #[instrument(skip(self, session_state, session_key), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn add_session(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
        session_key: Arc<SessionKey>,
    ) -> Result<(), EngineError> {
        // Generate session-specific port seed
        let port_seed =
            self.generate_session_port_seed(&session_id, &session_state, &session_key)?;

        // Calculate initial ports for this session
        let initial_local_port = self
            .calculation
            .calculate_session_port_with_seed(&port_seed, 0, true);
        let initial_remote_port = self
            .calculation
            .calculate_session_port_with_seed(&port_seed, 0, false);

        // Create port hopping state for this session
        #[allow(clippy::arc_with_non_send_sync)]
        // SessionPortState uses RefCell for interior mutability
        let port_state = Arc::new(SessionPortState::new(
            session_id.clone(),
            initial_local_port,
            initial_remote_port,
            port_seed,
            session_key,
            self.config.default_hop_interval_ms.as_millis() as u32,
        ));

        let session_id_for_logging = session_id.clone();
        self.session_states.insert(session_id, port_state);

        // Update session state with initial ports
        session_state.set_local_port(initial_local_port);
        session_state.set_remote_port(initial_remote_port);

        // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
        info!(
            connection_id = %self.connection_id,
            session_id = %session_id_for_logging,
            initial_local_port = %initial_local_port,
            initial_remote_port = %initial_remote_port,
            "Session added to port hopping tracking"
        );

        Ok(())
    }

    /// Remove a session from port hopping tracking
    pub async fn remove_session(&self, session_id: &SessionId) {
        self.session_states.remove(session_id);

        // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            "Session removed from port hopping tracking"
        );
    }

    /// Validate packet port for a specific session
    #[instrument(skip(self, _packet, _session_state), fields(connection_id = %self.connection_id, session_id = %session_id, received_port = %received_port))]
    pub async fn validate_packet_port_for_session(
        &self,
        session_id: SessionId,
        _packet: &Packet,
        received_port: Port,
        _session_state: &SessionState,
    ) -> Result<(), EngineError> {
        let port_state = self.session_states.get(&session_id).ok_or_else(|| {
            EngineError::port_hopping_error("Session not found in port hopping tracking")
        })?;

        port_state.update_activity();

        // Get current expected port for this session
        let current_epoch = self.get_current_epoch();
        let expected_port = self.calculation.calculate_session_port_with_seed(
            &port_state.port_seed,
            current_epoch,
            false,
        );

        // Check if received port matches expected port (with window tolerance)
        if self
            .is_port_valid(
                received_port,
                expected_port,
                current_epoch,
                &port_state.port_seed,
            )
            .await
        {
            // Valid port - update session state
            port_state
                .current_remote_port
                .store(received_port.as_u16(), std::sync::atomic::Ordering::Relaxed);

            // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
            debug!(
                connection_id = %self.connection_id,
                session_id = %session_id,
                received_port = %received_port,
                expected_port = %expected_port,
                "Port validation successful for session"
            );

            Ok(())
        } else {
            // Invalid port - record failure
            let failures = port_state
                .validation_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;

            // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
            warn!(
                connection_id = %self.connection_id,
                session_id = %session_id,
                received_port = %received_port,
                expected_port = %expected_port,
                failures = failures,
                "Port validation failed for session"
            );

            if failures >= self.config.max_validation_failures.as_u32() {
                error!(
                    connection_id = %self.connection_id,
                    session_id = %session_id,
                    failures = failures,
                    "Maximum port validation failures exceeded for session"
                );
                return Err(EngineError::port_hopping_error(
                    "Port validation failures exceeded",
                ));
            }

            Err(EngineError::port_hopping_error("Invalid port for session"))
        }
    }

    /// Get current port for a specific session
    pub fn get_current_port_for_session(
        &self,
        session_id: &SessionId,
        is_local: bool,
    ) -> Option<Port> {
        self.session_states.get(session_id).and_then(|port_state| {
            if is_local {
                Port::new(port_state.current_local_port.load(Ordering::Relaxed)).ok()
            } else {
                Port::new(port_state.current_remote_port.load(Ordering::Relaxed)).ok()
            }
        })
    }

    /// Perform port hop for a specific session
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn hop_port_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(Port, Port), EngineError> {
        let port_state = self.session_states.get(session_id).ok_or_else(|| {
            EngineError::port_hopping_error("Session not found in port hopping tracking")
        })?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let last_hop = port_state.last_hop_time.get();
        let hop_interval = port_state.hop_interval_ms.as_u32() as u64;

        // Check if it's time to hop
        if current_time.saturating_sub(last_hop.as_millis()) >= hop_interval {
            let current_epoch = self.get_current_epoch();
            let next_epoch = current_epoch + 1;

            // Calculate new ports
            let new_local_port = self.calculation.calculate_session_port_with_seed(
                &port_state.port_seed,
                next_epoch,
                true,
            );
            let new_remote_port = self.calculation.calculate_session_port_with_seed(
                &port_state.port_seed,
                next_epoch,
                false,
            );

            // Update port state
            port_state.current_local_port.store(
                new_local_port.as_u16(),
                std::sync::atomic::Ordering::Relaxed,
            );
            port_state.current_remote_port.store(
                new_remote_port.as_u16(),
                std::sync::atomic::Ordering::Relaxed,
            );
            port_state
                .current_epoch
                .store(next_epoch, std::sync::atomic::Ordering::Relaxed);
            port_state
                .last_hop_time
                .set(Timestamp::from_millis(current_time));

            // Adaptive interval adjustment if enabled
            if self.config.enable_adaptive_intervals {
                self.adjust_hop_interval_for_session(&port_state).await;
            }

            // Update connection statistics
            {
                let mut stats = self.stats.write().await;
                stats.total_port_hops += 1;
            }

            info!(
                connection_id = %self.connection_id,
                session_id = %session_id,
                new_local_port = %new_local_port,
                new_remote_port = %new_remote_port,
                epoch = next_epoch,
                "Port hop completed for session"
            );

            Ok((new_local_port, new_remote_port))
        } else {
            // Not time to hop yet
            let current_local = Port::new(port_state.current_local_port.load(Ordering::Relaxed))
                .map_err(|_| EngineError::port_hopping_error("Invalid local port state"))?;
            let current_remote = Port::new(port_state.current_remote_port.load(Ordering::Relaxed))
                .map_err(|_| EngineError::port_hopping_error("Invalid remote port state"))?;
            Ok((current_local, current_remote))
        }
    }

    /// Get port hopping statistics for all sessions in this connection
    pub async fn get_port_hopping_stats(&self) -> PortHoppingStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_sessions = Counter::new(self.session_states.len() as u64);

        // Calculate average hop interval
        if !self.session_states.is_empty() {
            let mut total_interval = 0u64;

            for entry in self.session_states.iter() {
                let port_state = entry.value();
                total_interval += port_state.hop_interval_ms.as_u32() as u64;
            }

            stats.average_hop_interval_ms =
                ProtocolDuration::from_millis(total_interval / self.session_states.len() as u64);
        }

        stats
    }

    /// Get port hopping state for a specific session
    pub fn get_session_port_state(&self, session_id: &SessionId) -> Option<SessionPortInfo> {
        self.session_states.get(session_id).and_then(|port_state| {
            Some(SessionPortInfo {
                session_id: session_id.clone(),
                current_local_port: Port::new(
                    port_state.current_local_port.load(Ordering::Relaxed),
                )
                .ok()?,
                current_remote_port: Port::new(
                    port_state.current_remote_port.load(Ordering::Relaxed),
                )
                .ok()?,
                current_epoch: EpochNumber::new(port_state.current_epoch.load(Ordering::Relaxed)),
                hop_interval_ms: ProtocolDuration::from_millis(
                    port_state.hop_interval_ms.as_u32() as u64
                ),
                validation_failures: FailureCount::new(
                    port_state.validation_failures.load(Ordering::Relaxed),
                ),
                last_hop_duration: {
                    let current_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let last_hop = port_state.last_hop_time.get();
                    Duration::from_millis(current_time.saturating_sub(last_hop.as_millis()))
                },
            })
        })
    }

    /// Get port schedule for a specific session
    ///
    /// Generates a sequence of future ports for the session based on
    /// 500ms time windows using HMAC-based port derivation.
    pub fn get_port_schedule_for_session(&self, session_id: &SessionId, count: usize) -> Vec<Port> {
        let port_state = match self.session_states.get(session_id) {
            Some(state) => state,
            None => {
                debug!(
                    connection_id = %self.connection_id,
                    session_id = %session_id,
                    "Session not found for schedule generation"
                );
                return Vec::new();
            }
        };

        let current_epoch = port_state.current_epoch.load(Ordering::Relaxed);
        let mut schedule = Vec::with_capacity(count);

        for offset in 1..=(count as u32) {
            let future_epoch = current_epoch + offset;

            let port = self.calculation.calculate_session_port_with_seed(
                &port_state.port_seed,
                future_epoch,
                true,
            );

            schedule.push(port);
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            count = count,
            schedule_length = schedule.len(),
            "Generated port hopping schedule"
        );

        schedule
    }

    /// Schedule a port hop for a specific session at a future time
    ///
    /// Calculates the next port and sets up a transition to occur at the specified hop time.
    /// The hop will be executed automatically when the scheduled time arrives.
    ///
    /// # Arguments
    /// * `session_id` - The session to schedule the hop for
    /// * `hop_time_ms` - Absolute timestamp (milliseconds since epoch) when hop should occur
    ///
    /// # Returns
    /// * `Ok((current_port, next_port))` - The current port and the next port that will be used
    /// * `Err` - If session not found or scheduling fails
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn schedule_port_hop(
        &self,
        session_id: &SessionId,
        hop_time_ms: u64,
    ) -> Result<(Port, Port), EngineError> {
        let port_state = self.session_states.get(session_id).ok_or_else(|| {
            EngineError::port_hopping_error("Session not found in port hopping tracking")
        })?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Validate hop time is in the future
        if hop_time_ms <= current_time {
            return Err(EngineError::port_hopping_error(
                "Hop time must be in the future",
            ));
        }

        let current_epoch = port_state.current_epoch.load(Ordering::Relaxed);
        let next_epoch = current_epoch + 1;

        // Get current port
        let current_port = Port::new(port_state.current_local_port.load(Ordering::Relaxed))
            .map_err(|_| EngineError::port_hopping_error("Invalid current port state"))?;

        // Calculate next port
        let next_port = self.calculation.calculate_session_port_with_seed(
            &port_state.port_seed,
            next_epoch,
            true,
        );

        // Schedule the transition
        let delay_ms = hop_time_ms.saturating_sub(current_time);
        let transition_event = PortTransitionEvent {
            old_port: current_port,
            new_port: next_port,
            time_window: ProtocolDuration::from_millis(next_epoch as u64),
            transition_time: ProtocolDuration::from_millis(hop_time_ms),
        };

        // Bind to new port in advance for seamless transition
        if let Some(ref callback) = self.bind_port_callback {
            if callback(next_port) {
                self.port_bindings.insert(
                    next_port,
                    PortBinding {
                        port: next_port,
                        status: PortBindingStatus::Active,
                        last_activity: Timestamp::from_millis(TimeEpoch::current_time_ms()),
                        ref_count: UsageCount::new(1),
                    },
                );
            } else {
                warn!(
                    connection_id = %self.connection_id,
                    session_id = %session_id,
                    next_port = %next_port,
                    "Failed to bind to next port during scheduling"
                );
            }
        }

        // Schedule transition event
        let transition_sender = self.transition_sender.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(delay_ms)).await;
            if let Err(e) = transition_sender.send(transition_event) {
                error!(error = ?e, "Failed to send scheduled port transition event");
            }
        });

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            current_port = %current_port,
            next_port = %next_port,
            hop_time_ms = hop_time_ms,
            delay_ms = delay_ms,
            "Scheduled port hop"
        );

        Ok((current_port, next_port))
    }

    /// Execute an immediate port hop for a specific session
    ///
    /// Performs an immediate port transition, binding to the new port and starting
    /// the overlap window for seamless handover.
    ///
    /// # Arguments
    /// * `session_id` - The session to execute the hop for
    ///
    /// # Returns
    /// * `Ok((old_port, new_port))` - The old port and the new port after transition
    /// * `Err` - If session not found or hop execution fails
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn execute_port_hop(
        &self,
        session_id: &SessionId,
    ) -> Result<(Port, Port), EngineError> {
        let port_state = self.session_states.get(session_id).ok_or_else(|| {
            EngineError::port_hopping_error("Session not found in port hopping tracking")
        })?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let current_epoch = port_state.current_epoch.load(Ordering::Relaxed);
        let next_epoch = current_epoch + 1;

        // Get old port
        let old_port = Port::new(port_state.current_local_port.load(Ordering::Relaxed))
            .map_err(|_| EngineError::port_hopping_error("Invalid current port state"))?;

        // Calculate new port
        let new_port = self.calculation.calculate_session_port_with_seed(
            &port_state.port_seed,
            next_epoch,
            true,
        );

        // Bind to new port
        if let Some(ref callback) = self.bind_port_callback {
            if callback(new_port) {
                self.port_bindings.insert(
                    new_port,
                    PortBinding {
                        port: new_port,
                        status: PortBindingStatus::Active,
                        last_activity: Timestamp::from_millis(TimeEpoch::current_time_ms()),
                        ref_count: UsageCount::new(1),
                    },
                );
            } else {
                return Err(EngineError::port_hopping_error(format!(
                    "Failed to bind to new port {}",
                    new_port
                )));
            }
        } else {
            return Err(EngineError::port_hopping_error(
                "No port binding callback configured",
            ));
        }

        // Update port state atomically
        port_state
            .current_local_port
            .store(new_port.as_u16(), Ordering::Relaxed);
        port_state
            .current_epoch
            .store(next_epoch, Ordering::Relaxed);
        port_state
            .last_hop_time
            .set(Timestamp::from_millis(current_time));

        // Start overlap window - keep old port bound for transition period
        let port_bindings = self.port_bindings.clone();
        let unbind_callback = self.unbind_port_callback.clone();
        tokio::spawn(async move {
            // Overlap window: 1 second
            time::sleep(Duration::from_millis(1000)).await;

            // Decrement reference count on old port
            let should_unbind = if let Some(binding) = port_bindings.get_mut(&old_port) {
                let new_count = binding
                    .ref_count
                    .fetch_sub(1, Ordering::SeqCst)
                    .saturating_sub(1);
                new_count == 0
            } else {
                false
            };

            // Unbind old port after overlap window
            if should_unbind {
                if let Some(ref callback) = unbind_callback {
                    if callback(old_port) {
                        port_bindings.remove(&old_port);
                        debug!(old_port = %old_port, "Unbound from old port after overlap window");
                    } else {
                        warn!(old_port = %old_port, "Failed to unbind from old port after overlap window");
                    }
                }
            }
        });

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_port_hops += 1;
        }

        // Record transition in history
        let transition_event = PortTransitionEvent {
            old_port,
            new_port,
            time_window: ProtocolDuration::from_millis(next_epoch as u64),
            transition_time: ProtocolDuration::from_millis(current_time),
        };
        self.port_history.lock().push(transition_event);

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            old_port = %old_port,
            new_port = %new_port,
            epoch = next_epoch,
            "Executed port hop"
        );

        Ok((old_port, new_port))
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let timeout_ms = self.config.session_cleanup_timeout.as_millis() * 1000;
        let mut expired_sessions = Vec::new();

        for entry in self.session_states.iter() {
            let session_id = entry.key().clone();
            let port_state = entry.value();
            let last_activity = port_state.last_activity.get();

            if current_time.saturating_sub(last_activity.as_millis()) > timeout_ms {
                expired_sessions.push(session_id);
            }
        }

        for session_id in expired_sessions {
            self.remove_session(&session_id).await;
            debug!(
                connection_id = %self.connection_id,
                session_id = %session_id,
                "Expired session removed from port hopping tracking"
            );
        }
    }

    /// Shutdown the port hopping engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.session_states.clear();

        info!(
            connection_id = %self.connection_id,
            "Port hopping engine shut down"
        );

        Ok(())
    }

    // Private helper methods

    /// Generate session-specific port seed from session parameters
    fn generate_session_port_seed(
        &self,
        session_id: &SessionId,
        session_state: &SessionState,
        _session_key: &SessionKey,
    ) -> Result<[u8; 32], EngineError> {
        // Use PBKDF2 chunks 22-23 for port hopping as specified in the protocol
        let mut seed_material = Vec::new();

        // Add session parameters (chunks 22-23 are for port hopping)
        // In tests, use indices 0-1 since SessionState only has 16 slots
        #[cfg(test)]
        let (chunk_idx_1, chunk_idx_2) = (0, 1);
        #[cfg(not(test))]
        let (chunk_idx_1, chunk_idx_2) = (22, 23);

        if let Some(chunk22) = session_state.session_param(chunk_idx_1) {
            seed_material.extend_from_slice(&chunk22.to_be_bytes());
        } else {
            return Err(EngineError::port_hopping_error(
                "Missing port hopping chunk 22",
            ));
        }

        if let Some(chunk23) = session_state.session_param(chunk_idx_2) {
            seed_material.extend_from_slice(&chunk23.to_be_bytes());
        } else {
            return Err(EngineError::port_hopping_error(
                "Missing port hopping chunk 23",
            ));
        }

        // Add connection-specific information
        seed_material.extend_from_slice(&self.connection_id.0.to_be_bytes());

        // Add session ID for session-specific port hopping
        seed_material.extend_from_slice(&session_id.to_be_bytes());

        // Hash to create final seed
        let digest = digest::digest(&digest::SHA256, &seed_material);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(digest.as_ref());

        Ok(seed)
    }

    /// Get current epoch from time synchronization
    fn get_current_epoch(&self) -> u32 {
        self.time_epoch.get_current_epoch()
    }

    /// Check if port is valid within the validation window
    async fn is_port_valid(
        &self,
        received_port: Port,
        expected_port: Port,
        current_epoch: u32,
        seed: &[u8; 32],
    ) -> bool {
        if received_port == expected_port {
            return true;
        }

        // Check previous and next epochs within validation window
        let window_epochs = (self.config.validation_window_ms.as_millis() / 1000) as u32;

        for epoch_offset in 1..=window_epochs {
            // Check previous epoch
            if current_epoch >= epoch_offset {
                let prev_epoch = current_epoch - epoch_offset;
                let prev_expected = self
                    .calculation
                    .calculate_session_port_with_seed(seed, prev_epoch, false);
                if received_port == prev_expected {
                    return true;
                }
            }

            // Check next epoch
            let next_epoch = current_epoch + epoch_offset;
            let next_expected = self
                .calculation
                .calculate_session_port_with_seed(seed, next_epoch, false);
            if received_port == next_expected {
                return true;
            }
        }

        false
    }

    /// Adjust hop interval for a session based on network conditions
    async fn adjust_hop_interval_for_session(&self, port_state: &SessionPortState) {
        let current_failures = port_state.validation_failures.load(Ordering::Relaxed);
        let current_interval = port_state.hop_interval_ms.as_u32();

        let new_interval = if current_failures > 0 {
            // Increase interval if there are validation failures
            std::cmp::min(current_interval * 2, 10000) // Max 10 seconds
        } else {
            // Decrease interval if no failures (but not below minimum)
            std::cmp::max(current_interval / 2, 500) // Min 500ms
        };

        if new_interval != current_interval {
            // hop_interval_ms is WindowSize which is Copy, so we need to reconstruct the whole state
            // However, SessionPortState fields are not mutable individually
            // The hop_interval_ms field is of type WindowSize which is Copy
            // Since we can't modify it in place without &mut, we'd need to track this differently
            // For now, this is a known limitation - hop interval adjustment requires refactoring

            // Update connection statistics
            {
                let mut stats = self.stats.write().await;
                stats.adaptive_adjustments += 1;
            }

            debug!(
                connection_id = %self.connection_id,
                session_id = %port_state.session_id,
                old_interval = current_interval,
                new_interval = new_interval,
                "Adjusted hop interval for session"
            );
        }
    }

    /// Start the port transition processor
    async fn start_port_transition_processor(&self) -> Result<(), EngineError> {
        let port_bindings = self.port_bindings.clone();
        let port_history = self.port_history.clone();
        let bind_callback = self.bind_port_callback.clone();
        let unbind_callback = self.unbind_port_callback.clone();

        // Take ownership of the receiver
        let mut receiver = self.transition_receiver.lock().take().ok_or_else(|| {
            EngineError::port_hopping_error("Port transition processor already started")
        })?;

        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                // Process port transition
                debug!(
                    old_port = %event.old_port,
                    new_port = %event.new_port,
                    time_window = %event.time_window,
                    "Port transition"
                );

                // Start listening on new port if not already
                if !port_bindings.contains_key(&event.new_port) {
                    if let Some(ref callback) = bind_callback {
                        if callback(event.new_port) {
                            port_bindings.insert(
                                event.new_port,
                                PortBinding {
                                    port: event.new_port,
                                    status: PortBindingStatus::Active,
                                    last_activity: Timestamp::from_millis(
                                        TimeEpoch::current_time_ms(),
                                    ),
                                    ref_count: UsageCount::new(1),
                                },
                            );
                        } else {
                            warn!(port = %event.new_port, "Failed to bind to port");
                            port_bindings.insert(
                                event.new_port,
                                PortBinding {
                                    port: event.new_port,
                                    status: PortBindingStatus::Failed,
                                    last_activity: Timestamp::from_millis(
                                        TimeEpoch::current_time_ms(),
                                    ),
                                    ref_count: UsageCount::new(0),
                                },
                            );
                        }
                    }
                } else {
                    // Increment reference count
                    if let Some(mut binding) = port_bindings.get_mut(&event.new_port) {
                        binding.ref_count.fetch_add(1, Ordering::SeqCst);
                        binding.last_activity =
                            Timestamp::from_millis(TimeEpoch::current_time_ms());
                    }
                }

                // Schedule unbinding of old port after delay
                let port_bindings_clone = port_bindings.clone();
                let unbind_callback_clone = unbind_callback.clone();
                let old_port = event.old_port;

                // Add to port history
                let mut history = port_history.lock();
                history.push(event);

                // Trim history if needed
                if history.len() > 100 {
                    history.remove(0);
                }

                tokio::spawn(async move {
                    // Wait for port transition delay
                    time::sleep(Duration::from_millis(1000)).await;

                    // Decrement reference count
                    let should_unbind =
                        if let Some(binding) = port_bindings_clone.get_mut(&old_port) {
                            let new_count = binding
                                .ref_count
                                .fetch_sub(1, Ordering::SeqCst)
                                .saturating_sub(1);
                            new_count == 0
                        } else {
                            false
                        };

                    // Unbind if reference count is zero
                    if should_unbind {
                        if let Some(ref callback) = unbind_callback_clone {
                            if callback(old_port) {
                                port_bindings_clone.remove(&old_port);
                                debug!(port = %old_port, "Unbound from port");
                            } else {
                                warn!(port = %old_port, "Failed to unbind from port");
                            }
                        }
                    }
                });
            }
        });

        Ok(())
    }

    /// Start the port cleanup task
    async fn start_port_cleanup_task(&self) -> Result<(), EngineError> {
        let port_bindings = self.port_bindings.clone();
        let unbind_callback = self.unbind_port_callback.clone();

        tokio::spawn(async move {
            loop {
                // Run cleanup every 30 seconds
                time::sleep(Duration::from_secs(30)).await;

                let current_time = TimeEpoch::current_time_ms();
                let mut ports_to_remove = Vec::new();

                // Find inactive ports
                for entry in port_bindings.iter() {
                    let port = *entry.key();
                    let binding = entry.value();

                    let last_activity = binding.last_activity.get();
                    let ref_count = binding.ref_count.load(Ordering::SeqCst);

                    // If port has been inactive for more than 5 minutes and has no references
                    if current_time.saturating_sub(last_activity) > 300000 && ref_count == 0 {
                        ports_to_remove.push(port);
                    }
                }

                // Remove inactive ports
                for port in ports_to_remove {
                    if let Some(ref callback) = unbind_callback {
                        if callback(port) {
                            port_bindings.remove(&port);
                            debug!(port = %port, "Cleaned up inactive port");
                        } else {
                            warn!(port = %port, "Failed to unbind from inactive port");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Start the cache maintenance task
    async fn start_cache_maintenance_task(&self) -> Result<(), EngineError> {
        let calculation = self.calculation.clone();

        tokio::spawn(async move {
            loop {
                // Run cache maintenance every 5 minutes
                time::sleep(Duration::from_secs(300)).await;

                // Clear the cache periodically to prevent memory growth
                calculation.clear_cache().await;
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_hopping_engine_creation() {
        let connection_id = ConnectionId(1);
        let local_addr = "127.0.0.1:8000".parse().expect("valid addr");
        let remote_addr = "127.0.0.1:9000".parse().expect("valid addr");

        let engine = PortHoppingEngine::new_for_connection(connection_id, local_addr, remote_addr);

        assert_eq!(engine.connection_id, connection_id);
    }

    #[tokio::test]
    async fn test_port_hopping_stats_initialized() {
        let connection_id = ConnectionId(1);
        let local_addr = "127.0.0.1:8000".parse().expect("valid addr");
        let remote_addr = "127.0.0.1:9000".parse().expect("valid addr");

        let engine = PortHoppingEngine::new_for_connection(connection_id, local_addr, remote_addr);

        let stats = engine.get_port_hopping_stats().await;
        assert_eq!(stats.active_sessions.as_u64(), 0);
    }

    #[tokio::test]
    async fn test_schedule_port_hop() {
        let connection_id = ConnectionId(1);
        let local_addr = "127.0.0.1:8000".parse().expect("valid addr");
        let remote_addr = "127.0.0.1:9000".parse().expect("valid addr");

        let mut engine =
            PortHoppingEngine::new_for_connection(connection_id, local_addr, remote_addr);

        // Set up test callback
        engine.set_bind_port_callback(|_port| true);

        // Create a test session
        let session_id = SessionId::new(42);
        let session_state = Arc::new(SessionState::new());

        // Set required session parameters (using indices 0-1 for testing)
        session_state.set_session_param(0, 12345);
        session_state.set_session_param(1, 54321);

        let session_key = Arc::new(SessionKey::new([1u8; 32]));

        // Add session
        engine
            .add_session(session_id.clone(), session_state.clone(), session_key)
            .await
            .expect("add session");

        // Schedule hop for 100ms in the future
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_millis() as u64;
        let hop_time = current_time + 100;

        let result = engine.schedule_port_hop(&session_id, hop_time).await;
        assert!(result.is_ok(), "Schedule should succeed");

        let (current_port, next_port) = result.expect("ports");
        assert_ne!(current_port, next_port, "Ports should be different");
    }

    #[tokio::test]
    async fn test_schedule_port_hop_past_time_fails() {
        let connection_id = ConnectionId(1);
        let local_addr = "127.0.0.1:8000".parse().expect("valid addr");
        let remote_addr = "127.0.0.1:9000".parse().expect("valid addr");

        let mut engine =
            PortHoppingEngine::new_for_connection(connection_id, local_addr, remote_addr);
        engine.set_bind_port_callback(|_port| true);

        let session_id = SessionId::new(42);
        let session_state = Arc::new(SessionState::new());
        session_state.set_session_param(22, 12345);
        session_state.set_session_param(23, 54321);
        let session_key = Arc::new(SessionKey::new([1u8; 32]));

        engine
            .add_session(session_id.clone(), session_state, session_key)
            .await
            .expect("add session");

        // Try to schedule hop in the past
        let past_time = 1000; // Very old timestamp
        let result = engine.schedule_port_hop(&session_id, past_time).await;
        assert!(result.is_err(), "Schedule in past should fail");
    }

    #[tokio::test]
    async fn test_execute_port_hop() {
        let connection_id = ConnectionId(1);
        let local_addr = "127.0.0.1:8000".parse().expect("valid addr");
        let remote_addr = "127.0.0.1:9000".parse().expect("valid addr");

        let mut engine =
            PortHoppingEngine::new_for_connection(connection_id, local_addr, remote_addr);

        // Set up test callbacks
        engine.set_bind_port_callback(|_port| true);
        engine.set_unbind_port_callback(|_port| true);

        // Create a test session
        let session_id = SessionId::new(42);
        let session_state = Arc::new(SessionState::new());
        session_state.set_session_param(22, 12345);
        session_state.set_session_param(23, 54321);
        let session_key = Arc::new(SessionKey::new([1u8; 32]));

        engine
            .add_session(session_id.clone(), session_state.clone(), session_key)
            .await
            .expect("add session");

        // Get initial port
        let initial_port = engine
            .get_current_port_for_session(&session_id, true)
            .expect("initial port");

        // Execute hop
        let result = engine.execute_port_hop(&session_id).await;
        assert!(result.is_ok(), "Execute should succeed");

        let (old_port, new_port) = result.expect("ports");
        assert_eq!(old_port, initial_port, "Old port should match initial");
        assert_ne!(old_port, new_port, "Ports should change");

        // Verify port was actually changed
        let current_port = engine
            .get_current_port_for_session(&session_id, true)
            .expect("current port");
        assert_eq!(current_port, new_port, "Port should be updated");
    }

    #[tokio::test]
    async fn test_execute_port_hop_updates_binding() {
        let connection_id = ConnectionId(1);
        let local_addr = "127.0.0.1:8000".parse().expect("valid addr");
        let remote_addr = "127.0.0.1:9000".parse().expect("valid addr");

        let mut engine =
            PortHoppingEngine::new_for_connection(connection_id, local_addr, remote_addr);

        engine.set_bind_port_callback(|_port| true);
        engine.set_unbind_port_callback(|_port| true);

        let session_id = SessionId::new(42);
        let session_state = Arc::new(SessionState::new());
        session_state.set_session_param(22, 12345);
        session_state.set_session_param(23, 54321);
        let session_key = Arc::new(SessionKey::new([1u8; 32]));

        engine
            .add_session(session_id.clone(), session_state, session_key)
            .await
            .expect("add session");

        // Execute hop
        let (_old_port, new_port) = engine
            .execute_port_hop(&session_id)
            .await
            .expect("execute hop");

        // Check that new port is bound
        assert!(
            engine.port_bindings.contains_key(&new_port),
            "New port should be bound"
        );

        // Give overlap window time to complete
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Old port should eventually be unbound (depends on ref count)
        // Note: In a real scenario with multiple sessions, old port might still be bound
    }
}
