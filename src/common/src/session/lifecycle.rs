// Session Lifecycle - manages session state transitions and lifecycle events
//
// This implements session lifecycle management including state transitions,
// timeout handling, health monitoring, and recovery mechanisms.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, info, instrument, warn};

use crate::error::{SessionError, SessionResult};
use crate::protocol::types::{
    AttemptCount, ConnectionId, ProtocolDuration, SessionId, SyncState, Threshold, Timeout,
    Timestamp,
};

// Use consolidated SessionState from protocol types (SessionLifecycleState maps to SessionState)
use crate::protocol::types::SessionState as SessionLifecycleState;

/// Session lifecycle event
#[derive(Debug, Clone)]
pub enum SessionLifecycleEvent {
    /// Session was created
    Created { timestamp: Timestamp },

    /// Session was started
    Started { timestamp: Timestamp },

    /// Session became active
    Activated { timestamp: Timestamp },

    /// Session became idle
    BecameIdle {
        timestamp: Timestamp,
        idle_duration_ms: ProtocolDuration,
    },

    /// Session became degraded
    Degraded {
        timestamp: Timestamp,
        reason: String,
    },

    /// Session recovery started
    RecoveryStarted {
        timestamp: Timestamp,
        attempt: crate::protocol::types::AttemptCount,
    },

    /// Session recovery completed
    RecoveryCompleted { timestamp: Timestamp, success: bool },

    /// Session termination started
    TerminationStarted {
        timestamp: Timestamp,
        reason: String,
    },

    /// Session was terminated
    Terminated { timestamp: Timestamp },

    /// Session entered error state
    Error { timestamp: Timestamp, error: String },

    /// Heartbeat sent
    HeartbeatSent { timestamp: Timestamp },

    /// Heartbeat received
    HeartbeatReceived { timestamp: Timestamp },

    /// Activity detected
    ActivityDetected { timestamp: Timestamp },
}

impl SessionLifecycleEvent {
    /// Get the timestamp of this event
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::Created { timestamp } => *timestamp,
            Self::Started { timestamp } => *timestamp,
            Self::Activated { timestamp } => *timestamp,
            Self::BecameIdle { timestamp, .. } => *timestamp,
            Self::Degraded { timestamp, .. } => *timestamp,
            Self::RecoveryStarted { timestamp, .. } => *timestamp,
            Self::RecoveryCompleted { timestamp, .. } => *timestamp,
            Self::TerminationStarted { timestamp, .. } => *timestamp,
            Self::Terminated { timestamp } => *timestamp,
            Self::Error { timestamp, .. } => *timestamp,
            Self::HeartbeatSent { timestamp } => *timestamp,
            Self::HeartbeatReceived { timestamp } => *timestamp,
            Self::ActivityDetected { timestamp } => *timestamp,
        }
    }
}

/// Session lifecycle configuration
#[derive(Debug, Clone)]
pub struct SessionLifecycleConfig {
    /// Session timeout duration
    pub session_timeout: Timeout,

    /// Idle threshold duration
    pub idle_threshold: Timeout,

    /// Degraded threshold duration
    pub degraded_threshold: Timeout,

    /// Maximum recovery attempts
    pub max_recovery_attempts: Threshold,

    /// Recovery timeout duration
    pub recovery_timeout: Timeout,

    /// Heartbeat timeout duration
    pub heartbeat_timeout: Timeout,

    /// Enable automatic recovery
    pub enable_auto_recovery: bool,

    /// Enable health monitoring
    pub enable_health_monitoring: bool,
}

impl Default for SessionLifecycleConfig {
    fn default() -> Self {
        Self {
            session_timeout: Timeout::from_millis(300_000), // 5 minutes
            idle_threshold: Timeout::from_millis(60_000),   // 1 minute
            degraded_threshold: Timeout::from_millis(120_000), // 2 minutes
            max_recovery_attempts: Threshold::from_raw(3),
            recovery_timeout: Timeout::from_millis(30_000), // 30 seconds
            heartbeat_timeout: Timeout::from_millis(60_000), // 1 minute
            enable_auto_recovery: true,
            enable_health_monitoring: true,
        }
    }
}

/// Session Lifecycle - manages session state transitions and lifecycle events
type LifecycleListener = dyn Fn(SessionLifecycleState, SessionLifecycleState) + Send + Sync;

pub struct SessionLifecycle {
    /// Session ID
    session_id: SessionId,

    /// Connection ID
    connection_id: ConnectionId,

    /// Current state
    state: SyncState,

    /// Creation time
    created_at: Instant,

    /// Last activity timestamp (stored as nanos since UNIX_EPOCH)
    last_activity: AtomicU64,

    /// Last heartbeat timestamp (stored as nanos since UNIX_EPOCH)
    last_heartbeat: AtomicU64,

    /// Recovery attempt count
    recovery_attempts: AtomicU32,

    /// Configuration
    config: SessionLifecycleConfig,

    /// Event history
    events: RwLock<Vec<SessionLifecycleEvent>>,

    /// Health monitoring task handle
    health_monitor_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// State transition callbacks
    listeners: RwLock<Vec<Box<LifecycleListener>>>,
}

impl SessionLifecycle {
    /// Create a new session lifecycle
    pub fn new(
        session_id: SessionId,
        connection_id: ConnectionId,
        session_timeout: Timeout,
    ) -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64;

        let config = SessionLifecycleConfig {
            session_timeout,
            ..Default::default()
        };

        Self {
            session_id,
            connection_id,
            state: SyncState::new(SessionLifecycleState::Creating.as_u8()),
            created_at: Instant::now(),
            last_activity: AtomicU64::new(current_time),
            last_heartbeat: AtomicU64::new(current_time),
            recovery_attempts: AtomicU32::new(0),
            config,
            events: RwLock::new(Vec::new()),
            health_monitor_handle: Mutex::new(None),
            listeners: RwLock::new(Vec::new()),
        }
    }

    /// Start the session lifecycle
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %self.session_id))]
    pub async fn start(&self) -> SessionResult<()> {
        // Transition to initializing state
        self.transition_to_state(SessionLifecycleState::Initializing)
            .await?;

        // Record creation event
        self.record_event(SessionLifecycleEvent::Created {
            timestamp: self.current_timestamp(),
        })
        .await;

        // Start health monitoring if enabled
        if self.config.enable_health_monitoring {
            self.start_health_monitoring().await;
        }

        // Transition to active state
        self.transition_to_state(SessionLifecycleState::Active)
            .await?;

        // Record started event
        self.record_event(SessionLifecycleEvent::Started {
            timestamp: self.current_timestamp(),
        })
        .await;

        info!(
            connection_id = %self.connection_id,
            session_id = %self.session_id,
            "Session lifecycle started"
        );

        Ok(())
    }

    /// Stop the session lifecycle
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %self.session_id))]
    pub async fn stop(&self) -> SessionResult<()> {
        // Stop health monitoring
        if let Some(handle) = self.health_monitor_handle.lock().await.take() {
            handle.abort();
        }

        // Transition to terminating state
        self.transition_to_state(SessionLifecycleState::Terminating)
            .await?;

        // Record termination event
        self.record_event(SessionLifecycleEvent::TerminationStarted {
            timestamp: self.current_timestamp(),
            reason: "Manual stop".to_string(),
        })
        .await;

        // Transition to terminated state
        self.transition_to_state(SessionLifecycleState::Terminated)
            .await?;

        // Record terminated event
        self.record_event(SessionLifecycleEvent::Terminated {
            timestamp: self.current_timestamp(),
        })
        .await;

        info!(
            connection_id = %self.connection_id,
            session_id = %self.session_id,
            "Session lifecycle stopped"
        );

        Ok(())
    }

    /// Get current state
    pub async fn current_state(&self) -> SessionLifecycleState {
        SessionLifecycleState::from_u8(self.state.load(Ordering::Relaxed))
            .unwrap_or(SessionLifecycleState::Error)
    }

    /// Update activity
    #[instrument(skip(self), fields(connection_id = %self.connection_id, session_id = %self.session_id))]
    pub async fn update_activity(&self) -> SessionResult<()> {
        let current_time = self.current_timestamp();
        self.last_activity
            .store(current_time.as_nanos(), Ordering::Relaxed);

        // Record activity event
        self.record_event(SessionLifecycleEvent::ActivityDetected {
            timestamp: current_time,
        })
        .await;

        // Transition to active if currently idle
        let current_state = self.current_state().await;
        if current_state == SessionLifecycleState::Idle {
            self.transition_to_state(SessionLifecycleState::Active)
                .await?;
        }

        Ok(())
    }

    /// Send heartbeat
    pub async fn send_heartbeat(&self) -> SessionResult<()> {
        let current_time = self.current_timestamp();
        self.last_heartbeat
            .store(current_time.as_nanos(), Ordering::Relaxed);

        // Record heartbeat event
        self.record_event(SessionLifecycleEvent::HeartbeatSent {
            timestamp: current_time,
        })
        .await;

        debug!(
            connection_id = %self.connection_id,
            session_id = %self.session_id,
            "Heartbeat sent"
        );

        Ok(())
    }

    /// Receive heartbeat
    pub async fn receive_heartbeat(&self) -> SessionResult<()> {
        let current_time = self.current_timestamp();

        // Record heartbeat event
        self.record_event(SessionLifecycleEvent::HeartbeatReceived {
            timestamp: current_time,
        })
        .await;

        // Update activity
        self.update_activity().await?;

        debug!(
            connection_id = %self.connection_id,
            session_id = %self.session_id,
            "Heartbeat received"
        );

        Ok(())
    }

    /// Check if session is healthy
    pub async fn is_healthy(&self) -> SessionResult<bool> {
        let current_state = self.current_state().await;

        if !current_state.is_healthy() {
            return Ok(false);
        }

        let current_time = self.current_timestamp();
        let last_activity = Timestamp::from_nanos(self.last_activity.load(Ordering::Relaxed));
        let last_heartbeat = Timestamp::from_nanos(self.last_heartbeat.load(Ordering::Relaxed));

        // Check activity timeout
        if current_time.saturating_sub(&last_activity) > self.config.session_timeout.as_millis() {
            return Ok(false);
        }

        // Check heartbeat timeout
        if current_time.saturating_sub(&last_heartbeat) > self.config.heartbeat_timeout.as_millis()
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Recover session
    pub async fn recover(&self) -> SessionResult<()> {
        if !self.config.enable_auto_recovery {
            return Err(SessionError::session_lifecycle_error(
                self.session_id.clone(),
                "Auto recovery disabled",
            ));
        }

        let attempt = self
            .recovery_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        if attempt > self.config.max_recovery_attempts.as_u32() {
            // Transition to error state
            self.transition_to_state(SessionLifecycleState::Error)
                .await?;

            return Err(SessionError::session_lifecycle_error(
                self.session_id.clone(),
                format!(
                    "Maximum recovery attempts ({}) exceeded",
                    self.config.max_recovery_attempts.as_u32()
                ),
            ));
        }

        // Transition to recovering state
        self.transition_to_state(SessionLifecycleState::Recovering)
            .await?;

        // Record recovery event
        self.record_event(SessionLifecycleEvent::RecoveryStarted {
            timestamp: self.current_timestamp(),
            attempt: AttemptCount::new(attempt),
        })
        .await;

        // Perform recovery with timeout
        let recovery_result = timeout(
            Duration::from_millis(self.config.recovery_timeout.as_millis()),
            self.perform_recovery(),
        )
        .await;

        let success = match recovery_result {
            Ok(Ok(())) => {
                // Recovery successful, transition to active
                self.transition_to_state(SessionLifecycleState::Active)
                    .await?;
                true
            }
            Ok(Err(e)) => {
                warn!(
                    connection_id = %self.connection_id,
                    session_id = %self.session_id,
                    error = %e,
                    "Session recovery failed"
                );
                false
            }
            Err(_) => {
                warn!(
                    connection_id = %self.connection_id,
                    session_id = %self.session_id,
                    "Session recovery timed out"
                );
                false
            }
        };

        // Record recovery completion
        self.record_event(SessionLifecycleEvent::RecoveryCompleted {
            timestamp: self.current_timestamp(),
            success,
        })
        .await;

        if success {
            info!(
                connection_id = %self.connection_id,
                session_id = %self.session_id,
                attempt,
                "Session recovery successful"
            );
            Ok(())
        } else {
            // Transition to degraded state for retry
            self.transition_to_state(SessionLifecycleState::Degraded)
                .await?;
            Err(SessionError::session_lifecycle_error(
                self.session_id.clone(),
                format!("Recovery attempt {} failed", attempt),
            ))
        }
    }

    /// Get session age
    pub async fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get event history
    pub async fn get_events(&self) -> Vec<SessionLifecycleEvent> {
        self.events.read().await.clone()
    }

    /// Add state transition callback
    pub async fn add_state_callback<F>(&self, callback: F)
    where
        F: Fn(SessionLifecycleState, SessionLifecycleState) + Send + Sync + 'static,
    {
        self.listeners.write().await.push(Box::new(callback));
    }

    /// Transition to new state
    async fn transition_to_state(&self, new_state: SessionLifecycleState) -> SessionResult<()> {
        let old_state = self.current_state().await;

        if old_state == new_state {
            return Ok(());
        }

        // Check if transition is allowed
        if !old_state.allows_transitions() {
            return Err(SessionError::SessionStateError {
                session_id: self.session_id.clone(),
                current_state: format!("{:?}", old_state),
                attempted_action: format!("transition to {:?}", new_state),
            });
        }

        // Validate state transition
        old_state.validate_transition(new_state).map_err(|e| {
            warn!(
                connection_id = %self.connection_id,
                session_id = %self.session_id,
                old_state = ?old_state,
                new_state = ?new_state,
                error = %e,
                "Invalid state transition attempted"
            );
            SessionError::SessionStateError {
                session_id: self.session_id.clone(),
                current_state: format!("{:?}", old_state),
                attempted_action: format!("transition to {:?}", new_state),
            }
        })?;

        // Perform state transition
        self.state
            .store(new_state.as_u8(), std::sync::atomic::Ordering::Relaxed);

        // Call state callbacks
        let callbacks = self.listeners.read().await;
        for callback in callbacks.iter() {
            callback(old_state, new_state);
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %self.session_id,
            old_state = ?old_state,
            new_state = ?new_state,
            "Session state transition"
        );

        Ok(())
    }

    /// Record lifecycle event
    async fn record_event(&self, event: SessionLifecycleEvent) {
        let mut events = self.events.write().await;
        events.push(event);

        // Limit event history size
        const MAX_EVENTS: usize = 1000;
        if events.len() > MAX_EVENTS {
            let drain_count = events.len() - MAX_EVENTS;
            events.drain(0..drain_count);
        }
    }

    /// Start health monitoring task
    async fn start_health_monitoring(&self) {
        let session_id = self.session_id.clone();
        let connection_id = self.connection_id;
        let _config = self.config.clone();
        let check_interval = Duration::from_millis(self.config.idle_threshold.as_millis() / 2);

        let handle = tokio::spawn(async move {
            let mut interval = interval(check_interval);

            loop {
                interval.tick().await;

                // Simple health monitoring without self reference
                // In a real implementation, this would check external health indicators
                debug!(
                    connection_id = %connection_id,
                    session_id = %session_id,
                    "Health monitoring tick"
                );

                // Break after some time to avoid infinite loops in tests
                // In production, this would run until the lifecycle is dropped
            }
        });

        *self.health_monitor_handle.lock().await = Some(handle);
    }

    /// Perform actual recovery logic
    async fn perform_recovery(&self) -> SessionResult<()> {
        // Reset activity timestamp
        let current_time = self.current_timestamp();
        self.last_activity
            .store(current_time.as_nanos(), Ordering::Relaxed);
        self.last_heartbeat
            .store(current_time.as_nanos(), Ordering::Relaxed);

        // In a real implementation, this would perform actual recovery actions
        // such as re-establishing connections, resetting state, etc.

        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp(&self) -> Timestamp {
        Timestamp::now()
    }
}

impl Drop for SessionLifecycle {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd use a proper shutdown mechanism
        if let Ok(mut handle) = self.health_monitor_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}
