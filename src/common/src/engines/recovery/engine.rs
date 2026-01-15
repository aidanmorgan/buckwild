#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Recovery Engine - Consolidated recovery logic with strategy pattern
//
// This implements the comprehensive recovery system with graduated escalation,
// time synchronization recovery, sequence repair, and session rekeying.

use std::boxed::Box;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ring::rand::SystemRandom;
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

use crate::error::CryptographicError as CryptoError;
use crate::error::EngineError;
use crate::protocol::types::*;
use crate::session::SessionState;
#[allow(dead_code)]
type CryptoResult<T> = Result<T, CryptoError>;
use crate::security::crypto::ecdh::ThreadSafeEcdhManager;
use crate::security::crypto::hmac::HmacCalculator;
// Use constant time comparison from a crypto library
use crate::engines::recovery::triggers::{
    detect_sequence_mismatch, determine_recovery_level_needed,
};
use crate::engines::recovery::{RecoveryCoordination, RecoveryStrategies};

/// Recovery engine state for state machine tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEngineState {
    /// Engine is idle, monitoring for triggers
    Idle,
    /// Recovery needed, awaiting initiation
    RecoveryNeeded,
    /// Recovery in progress
    Recovering,
    /// Recovery completed successfully
    Recovered,
}

/// Recovery escalation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecoveryLevel {
    /// No recovery needed
    None = 0,
    /// Time synchronization recovery
    TimeSync = 1,
    /// Session key rotation/recovery
    SessionRekey = 2,
    /// Sequence number repair
    SequenceRepair = 3,
    /// Emergency recovery
    Emergency = 4,
    /// Force connection termination
    ConnectionTerminate = 5,
    /// Recovery completely failed
    Failed = 6,
}

impl RecoveryLevel {
    /// Get the next escalation level
    pub fn escalate(&self) -> Self {
        match self {
            Self::None => Self::TimeSync,
            Self::TimeSync => Self::SessionRekey,
            Self::SessionRekey => Self::SequenceRepair,
            Self::SequenceRepair => Self::Emergency,
            Self::Emergency => Self::ConnectionTerminate,
            Self::ConnectionTerminate => Self::Failed,
            Self::Failed => Self::Failed,
        }
    }

    /// Check if this level requires immediate action
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::Emergency | Self::ConnectionTerminate | Self::Failed
        )
    }

    /// Get timeout for this recovery level
    pub fn timeout_ms(&self) -> RecoveryTimeout {
        match self {
            Self::None => RecoveryTimeout::new(0),
            Self::TimeSync => RecoveryTimeout::new(10000), // 10 seconds
            Self::SequenceRepair => RecoveryTimeout::new(15000), // 15 seconds
            Self::SessionRekey => RecoveryTimeout::new(20000), // 20 seconds
            Self::Emergency => RecoveryTimeout::new(30000), // 30 seconds
            Self::ConnectionTerminate => RecoveryTimeout::new(5000), // 5 seconds
            Self::Failed => RecoveryTimeout::new(0),
        }
    }
}

/// Recovery result enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryResult {
    Success,
    Timeout,
    InvalidNonce,
    InvalidKey,
    SharedSecretMismatch,
    VerificationFailed,
    NetworkError,
    CryptoError,
    Failed,
}

/// Recovery failure conditions for analysis and optimization
#[derive(Debug, Clone)]
pub struct FailureCondition {
    /// Condition type
    pub condition: String,
    /// Additional details
    pub details: String,
    /// Timestamp when condition was recorded
    pub timestamp: Instant,
    /// Session state snapshot at time of failure
    pub session_state_snapshot: Option<String>,
    /// Network conditions at time of failure
    pub network_conditions: Option<String>,
}

/// Recovery attempt record for analysis
#[derive(Debug, Clone)]
pub struct RecoveryAttempt {
    /// Recovery level attempted
    pub level: RecoveryLevel,
    /// Result of the attempt
    pub result: RecoveryResult,
    /// Timestamp of attempt
    pub timestamp: Instant,
    /// Failure conditions at time of attempt
    pub failure_conditions: Vec<FailureCondition>,
    /// Network conditions at time of attempt
    pub network_conditions: Option<String>,
    /// Session age at time of attempt
    pub session_age: Duration,
}

/// Pending recovery request tracking
#[derive(Debug, Clone)]
pub struct PendingRecoveryRequest {
    /// Request type
    pub request_type: String,
    /// Nonce for request verification
    pub nonce: RecoveryNonce,
    /// Request data
    pub data: Vec<u8>,
    /// Timeout for request
    pub timeout: Instant,
}

/// Per-session recovery state with comprehensive tracking
#[derive(Debug)]
pub struct SessionRecoveryState {
    /// Session ID
    pub session_id: SessionId,

    /// Current recovery level
    pub current_level: RecoveryLevel,

    /// Attempts at current level
    pub attempts_at_current_level: RecoveryAttemptCount,

    /// Total recovery attempts
    pub total_recovery_attempts: RecoveryAttemptCount,

    /// Recovery escalation history
    pub escalation_history: Vec<RecoveryAttempt>,

    /// Last recovery time
    pub last_recovery_time: Instant,

    /// Failure conditions
    pub failure_conditions: Vec<FailureCondition>,

    /// Recovery in progress flag
    pub recovery_in_progress: bool,

    /// Recovery start time
    pub recovery_start_time: Instant,

    /// Last known good sequence number
    pub last_known_sequence: SequenceNumber,

    /// Congestion window at recovery start
    pub recovery_cwnd: CongestionWindow,

    /// Send window at recovery start
    pub recovery_send_window: WindowSize,

    /// Pending recovery requests
    pub pending_requests: HashMap<String, PendingRecoveryRequest>,

    /// Recovery engine state
    pub engine_state: RecoveryEngineState,

    /// Last trigger check time
    pub last_trigger_check: Instant,

    /// Recent authentication failures count
    pub recent_auth_failures: u32,

    /// Last auth failure time
    pub last_auth_failure_time: Instant,
}

impl SessionRecoveryState {
    /// Create new session recovery state
    pub fn new(session_id: SessionId) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            current_level: RecoveryLevel::None,
            attempts_at_current_level: RecoveryAttemptCount::new(0),
            total_recovery_attempts: RecoveryAttemptCount::new(0),
            escalation_history: Vec::new(),
            last_recovery_time: now,
            failure_conditions: Vec::new(),
            recovery_in_progress: false,
            recovery_start_time: now,
            last_known_sequence: SequenceNumber::new(0),
            recovery_cwnd: CongestionWindow::new(0),
            recovery_send_window: WindowSize::new(0),
            pending_requests: HashMap::new(),
            engine_state: RecoveryEngineState::Idle,
            last_trigger_check: now,
            recent_auth_failures: 0,
            last_auth_failure_time: now,
        }
    }

    /// Record a failure condition
    pub fn record_failure_condition(&mut self, condition: String, details: String) {
        let failure = FailureCondition {
            condition,
            details,
            timestamp: Instant::now(),
            session_state_snapshot: None,
            network_conditions: None,
        };

        self.failure_conditions.push(failure);

        // Limit failure condition history
        if self.failure_conditions.len() > 100 {
            self.failure_conditions.remove(0);
        }
    }

    /// Escalate to next recovery level
    pub fn escalate(&mut self) -> RecoveryLevel {
        let new_level = self.current_level.escalate();

        // Record the escalation attempt
        let attempt = RecoveryAttempt {
            level: self.current_level,
            result: RecoveryResult::Failed,
            timestamp: Instant::now(),
            failure_conditions: self.failure_conditions.clone(),
            network_conditions: None,
            session_age: self.recovery_start_time.elapsed(),
        };

        self.escalation_history.push(attempt);
        self.current_level = new_level;
        self.attempts_at_current_level = RecoveryAttemptCount::new(0);

        debug!(
            session_id = %self.session_id,
            old_level = ?self.current_level,
            new_level = ?new_level,
            "Recovery level escalated"
        );

        new_level
    }

    /// Check if recovery should be escalated
    pub fn should_escalate(&self, max_attempts: MaxRecoveryAttempts) -> bool {
        self.attempts_at_current_level.as_u32() >= max_attempts.as_u32()
    }

    /// Reset recovery state after successful recovery
    pub fn reset(&mut self) {
        self.current_level = RecoveryLevel::None;
        self.attempts_at_current_level = RecoveryAttemptCount::new(0);
        self.recovery_in_progress = false;
        self.pending_requests.clear();
        self.engine_state = RecoveryEngineState::Recovered;

        debug!(
            session_id = %self.session_id,
            "Recovery state reset after successful recovery"
        );
    }
}

/// Recovery configuration with comprehensive settings
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Maximum recovery attempts per level
    pub max_recovery_attempts_per_level: MaxRecoveryAttempts,

    /// Base retry interval (milliseconds)
    pub recovery_retry_interval_ms: RecoveryTimeout,

    /// Maximum time drift interval (milliseconds)
    pub max_time_drift_interval: RecoveryTimeout,

    /// Authentication failures before rekeying
    pub max_auth_failures_before_rekey: MaxRecoveryAttempts,

    /// Maximum HMAC failure rate
    pub max_hmac_failure_rate: f64,

    /// Maximum sequence repair window
    pub max_repair_window_size: WindowSize,

    /// Failure condition retention (milliseconds)
    pub failure_condition_retention_ms: RecoveryTimeout,

    /// Time sync tolerance (milliseconds)
    pub time_sync_tolerance_ms: TimeSyncTolerance,

    /// Session cleanup timeout (seconds)
    pub session_cleanup_timeout: RecoveryTimeout,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_recovery_attempts_per_level: MaxRecoveryAttempts::new(3),
            recovery_retry_interval_ms: RecoveryTimeout::new(2000),
            max_time_drift_interval: RecoveryTimeout::new(60000),
            max_auth_failures_before_rekey: MaxRecoveryAttempts::new(3),
            max_hmac_failure_rate: 0.1,
            max_repair_window_size: WindowSize::new(1000),
            failure_condition_retention_ms: RecoveryTimeout::new(300000),
            time_sync_tolerance_ms: TimeSyncTolerance::new(1000),
            session_cleanup_timeout: RecoveryTimeout::new(300000),
        }
    }
}

/// Connection-level recovery statistics
#[derive(Debug, Default, Clone)]
pub struct RecoveryStats {
    pub active_sessions: Counter,
    pub total_recovery_attempts: Counter,
    pub successful_recoveries: Counter,
    pub failed_recoveries: Counter,
    pub time_sync_recoveries: Counter,
    pub sequence_repair_recoveries: Counter,
    pub session_rekey_recoveries: Counter,
    pub emergency_recoveries: Counter,
    pub connection_terminations: Counter,
    pub average_recovery_time_ms: RecoveryTimeout,
    pub time_sync_success_rate: f64,
    pub sequence_repair_success_rate: f64,
    pub session_rekey_success_rate: f64,
    pub emergency_success_rate: f64,
}

/// Session manager trait for recovery engine
pub trait SessionManagerTrait: Send + Sync {
    fn get_session_state(&self, session_id: &SessionId) -> Option<Arc<SessionState>>;
    fn update_session_state(
        &self,
        session_id: &SessionId,
        state: Arc<SessionState>,
    ) -> Result<(), EngineError>;

    /// Get the session key for HMAC operations
    ///
    /// Returns the session key derived from ECDH handshake for the given session.
    /// This key is used for packet authentication and repair confirmations.
    ///
    /// # Security Requirements
    ///
    /// The returned session key MUST:
    /// - Be derived from a completed ECDH handshake
    /// - Not be all zeros
    /// - Not be empty
    ///
    /// Returns None if:
    /// - Session doesn't exist
    /// - Session handshake not complete
    /// - Session key not yet derived
    fn get_session_key(&self, session_id: &SessionId) -> Option<SessionKey>;

    /// Check if the connection is in ESTABLISHED state.
    /// Per M2 spec, recovery sub-states (TIME_SYNC, REKEY, REPAIR, EMERGENCY, FAILED)
    /// are only accessible from the ESTABLISHED connection state.
    fn is_connection_established(&self) -> bool;
}

/// Multi-Layer Recovery Engine for comprehensive failure recovery
pub struct RecoveryEngine {
    /// Connection ID this engine belongs to
    connection_id: ConnectionId,

    /// Local endpoint
    #[allow(dead_code)]
    local_endpoint: SocketAddr,

    /// Remote endpoint
    #[allow(dead_code)]
    remote_endpoint: SocketAddr,

    /// Per-session recovery states
    session_states: DashMap<SessionId, Arc<Mutex<SessionRecoveryState>>>,

    /// Recovery configuration
    config: RecoveryConfig,

    /// Connection-level recovery statistics
    stats: RwLock<RecoveryStats>,

    /// Recovery strategies
    strategies: RecoveryStrategies,

    /// Recovery coordination
    coordination: RecoveryCoordination,

    /// ECDH manager for session rekeying
    ecdh_manager: Arc<ThreadSafeEcdhManager>,

    /// HMAC calculator for cryptographic operations
    #[allow(dead_code)]
    hmac_calculator: Arc<HmacCalculator>,

    /// Random number generator
    #[allow(dead_code)]
    rng: SystemRandom,

    /// Session manager for state access
    #[allow(dead_code)]
    session_manager: Arc<dyn SessionManagerTrait>,
}

impl RecoveryEngine {
    /// Create new recovery engine for connection
    pub fn new_for_connection(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        ecdh_manager: Arc<ThreadSafeEcdhManager>,
        hmac_calculator: Arc<HmacCalculator>,
        session_manager: Arc<dyn SessionManagerTrait>,
    ) -> Self {
        Self {
            connection_id,
            local_endpoint,
            remote_endpoint,
            session_states: DashMap::new(),
            config: RecoveryConfig::default(),
            stats: RwLock::new(RecoveryStats::default()),
            strategies: RecoveryStrategies::new(),
            coordination: RecoveryCoordination::new(),
            ecdh_manager,
            hmac_calculator,
            rng: SystemRandom::new(),
            session_manager,
        }
    }

    /// Add a session to recovery tracking
    pub async fn add_session(&self, session_id: SessionId) -> Result<(), EngineError> {
        let recovery_state = Arc::new(Mutex::new(SessionRecoveryState::new(session_id.clone())));
        let session_id_for_logging = session_id.clone();
        self.session_states.insert(session_id, recovery_state);

        // Update connection statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_sessions += 1;
        }

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id_for_logging,
            "Session added to recovery tracking"
        );

        Ok(())
    }

    /// Remove a session from recovery tracking
    pub async fn remove_session(&self, session_id: &SessionId) {
        self.session_states.remove(session_id);

        // Update connection statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_sessions = Counter::new(stats.active_sessions.as_u64().saturating_sub(1));
        }

        debug!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            "Session removed from recovery tracking"
        );
    }

    /// Initiate recovery for a session
    ///
    /// Per M2 spec, recovery sub-states (TIME_SYNC, REKEY, REPAIR, EMERGENCY, FAILED)
    /// are only accessible from the ESTABLISHED connection state. This method will
    /// return an error if the connection is not in ESTABLISHED state.
    #[instrument(skip(self, session_state), fields(connection_id = %self.connection_id, session_id = %session_id))]
    pub async fn initiate_recovery(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
        failure_reason: String,
    ) -> Result<RecoveryResult, EngineError> {
        // M2 spec enforcement: Recovery is only allowed from ESTABLISHED state
        if !self.session_manager.is_connection_established() {
            warn!(
                session_id = %session_id,
                failure_reason = %failure_reason,
                "Recovery rejected: connection not in ESTABLISHED state (M2 spec requirement)"
            );
            return Err(EngineError::recovery_error(
                "Recovery only allowed from ESTABLISHED connection state",
            ));
        }

        let recovery_state = self
            .session_states
            .get(&session_id)
            .ok_or_else(|| EngineError::recovery_error("Session not found in recovery tracking"))?;

        let mut state = recovery_state.lock().await;

        // Check if recovery is already in progress
        if state.recovery_in_progress {
            warn!(
                session_id = %session_id,
                current_level = ?state.current_level,
                "Recovery already in progress for session"
            );
            return Ok(RecoveryResult::Failed);
        }

        // Determine initial recovery level based on failure reason
        let initial_level = self.determine_initial_recovery_level(&failure_reason, &session_state);

        info!(
            session_id = %session_id,
            failure_reason,
            initial_level = ?initial_level,
            "Recovery initiated for session"
        );

        // Record failure condition
        state.record_failure_condition(failure_reason, "Recovery initiated".to_string());
        state.recovery_in_progress = true;
        state.recovery_start_time = Instant::now();
        state.current_level = initial_level;
        state.engine_state = RecoveryEngineState::Recovering;

        // Execute recovery strategy
        let result = self
            .execute_recovery_strategy(&mut state, session_state)
            .await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_recovery_attempts += 1;

            match result {
                RecoveryResult::Success => {
                    stats.successful_recoveries += 1;
                    match state.current_level {
                        RecoveryLevel::TimeSync => {
                            stats.time_sync_recoveries += 1;
                        }
                        RecoveryLevel::SequenceRepair => {
                            stats.sequence_repair_recoveries += 1;
                        }
                        RecoveryLevel::SessionRekey => {
                            stats.session_rekey_recoveries += 1;
                        }
                        RecoveryLevel::Emergency => {
                            stats.emergency_recoveries += 1;
                        }
                        RecoveryLevel::ConnectionTerminate => {
                            stats.connection_terminations += 1;
                        }
                        RecoveryLevel::Failed => {
                            stats.failed_recoveries += 1;
                        }
                        RecoveryLevel::None => {} // No recovery needed, no stats to update
                    }
                }
                _ => {
                    stats.failed_recoveries += 1;
                }
            }
        }

        // Reset recovery state if successful
        if result == RecoveryResult::Success {
            state.reset();
        }

        Ok(result)
    }

    /// Execute recovery strategy for current level
    async fn execute_recovery_strategy(
        &self,
        recovery_state: &mut SessionRecoveryState,
        session_state: Arc<SessionState>,
    ) -> Result<RecoveryResult, EngineError> {
        let mut attempts = 0;
        let max_attempts = self.config.max_recovery_attempts_per_level.as_u32();

        while attempts < max_attempts {
            recovery_state.attempts_at_current_level.increment();
            attempts += 1;

            let result = match recovery_state.current_level {
                RecoveryLevel::TimeSync => {
                    self.strategies
                        .execute_time_sync_recovery(
                            recovery_state.session_id.clone(),
                            session_state.clone(),
                            &self.coordination,
                        )
                        .await
                }
                RecoveryLevel::SequenceRepair => {
                    // Get session key from session manager
                    let session_key = self
                        .session_manager
                        .get_session_key(&recovery_state.session_id)
                        .ok_or_else(|| EngineError::RecoveryError {
                            reason: "Session key not available for repair confirmation".to_string(),
                        })?;

                    self.strategies
                        .execute_sequence_repair_recovery(
                            recovery_state.session_id.clone(),
                            session_state.clone(),
                            &session_key,
                            &self.coordination,
                        )
                        .await
                }
                RecoveryLevel::SessionRekey => {
                    self.strategies
                        .execute_session_rekey_recovery(
                            recovery_state.session_id.clone(),
                            session_state.clone(),
                            &self.ecdh_manager,
                            &self.coordination,
                        )
                        .await
                }
                RecoveryLevel::Emergency => {
                    self.strategies
                        .execute_emergency_recovery(
                            recovery_state.session_id.clone(),
                            session_state.clone(),
                            &self.coordination,
                        )
                        .await
                }
                RecoveryLevel::ConnectionTerminate => {
                    self.strategies
                        .execute_connection_termination(
                            recovery_state.session_id.clone(),
                            session_state.clone(),
                            &self.coordination,
                        )
                        .await
                }
                RecoveryLevel::None | RecoveryLevel::Failed => {
                    return Ok(RecoveryResult::Failed);
                }
            };

            // Record the attempt
            let result_for_record = match &result {
                Ok(r) => *r,
                Err(_) => RecoveryResult::Failed,
            };

            let attempt = RecoveryAttempt {
                level: recovery_state.current_level,
                result: result_for_record,
                timestamp: Instant::now(),
                failure_conditions: recovery_state.failure_conditions.clone(),
                network_conditions: None,
                session_age: recovery_state.recovery_start_time.elapsed(),
            };

            recovery_state.escalation_history.push(attempt);

            match result {
                Ok(RecoveryResult::Success) => {
                    info!(
                        session_id = %recovery_state.session_id,
                        level = ?recovery_state.current_level,
                        attempts,
                        "Recovery successful"
                    );
                    return Ok(RecoveryResult::Success);
                }
                Ok(RecoveryResult::Failed) | Err(_) => {
                    // Escalate to next level
                    if recovery_state.current_level.is_critical() {
                        error!(
                            session_id = %recovery_state.session_id,
                            level = ?recovery_state.current_level,
                            "Critical recovery level failed - initiating terminal failure handling"
                        );

                        // Terminal failure handling: Emergency layer has failed
                        // Per design/protocol/12-recovery-mechanisms.md, when Emergency recovery fails:
                        // 1. Connection is unrecoverable
                        // 2. Tear down connection and clear session state
                        // 3. Trigger automatic fresh handshake attempt
                        // 4. Log terminal failure event for operator visibility

                        self.handle_terminal_failure(
                            &recovery_state.session_id,
                            session_state.clone(),
                        )
                        .await;
                        return Ok(RecoveryResult::Failed);
                    }

                    recovery_state.escalate();
                    break; // Try next level
                }
                _ => {
                    // Retry at current level
                    warn!(
                        session_id = %recovery_state.session_id,
                        level = ?recovery_state.current_level,
                        result = ?result,
                        attempt = attempts,
                        "Recovery attempt failed, retrying"
                    );

                    // Wait before retry
                    sleep(Duration::from_millis(
                        self.config.recovery_retry_interval_ms.as_millis(),
                    ))
                    .await;
                }
            }
        }

        // If we've exhausted attempts at current level, escalate
        if recovery_state.should_escalate(MaxRecoveryAttempts::new(max_attempts)) {
            recovery_state.escalate();

            // Try the next level
            return Box::pin(self.execute_recovery_strategy(recovery_state, session_state)).await;
        }

        Ok(RecoveryResult::Failed)
    }

    /// Determine initial recovery level based on failure reason
    fn determine_initial_recovery_level(
        &self,
        failure_reason: &str,
        _session_state: &SessionState,
    ) -> RecoveryLevel {
        match failure_reason {
            reason if reason.contains("time") || reason.contains("sync") => RecoveryLevel::TimeSync,
            reason if reason.contains("sequence") || reason.contains("order") => {
                RecoveryLevel::SequenceRepair
            }
            reason
                if reason.contains("auth") || reason.contains("hmac") || reason.contains("key") =>
            {
                RecoveryLevel::SessionRekey
            }
            reason if reason.contains("emergency") || reason.contains("critical") => {
                RecoveryLevel::Emergency
            }
            _ => RecoveryLevel::TimeSync, // Default to time sync
        }
    }

    /// Get recovery statistics for all sessions in this connection
    pub async fn get_recovery_stats(&self) -> RecoveryStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_sessions = Counter::new(self.session_states.len() as u64);

        // Calculate success rates
        if stats.total_recovery_attempts.as_u64() > 0 {
            let total = stats.total_recovery_attempts.as_u64() as f64;
            stats.time_sync_success_rate = stats.time_sync_recoveries.as_u64() as f64 / total;
            stats.sequence_repair_success_rate =
                stats.sequence_repair_recoveries.as_u64() as f64 / total;
            stats.session_rekey_success_rate =
                stats.session_rekey_recoveries.as_u64() as f64 / total;
            stats.emergency_success_rate = stats.emergency_recoveries.as_u64() as f64 / total;
        }

        stats
    }

    /// Get recovery state for a specific session
    pub async fn get_session_recovery_state(
        &self,
        session_id: &SessionId,
    ) -> Option<SessionRecoveryInfo> {
        let recovery_state = self.session_states.get(session_id)?;
        let state = recovery_state.lock().await;

        Some(SessionRecoveryInfo {
            session_id: session_id.clone(),
            current_level: state.current_level,
            attempts_at_current_level: state.attempts_at_current_level,
            total_recovery_attempts: state.total_recovery_attempts,
            recovery_in_progress: state.recovery_in_progress,
            last_recovery_time: state.last_recovery_time,
            failure_conditions_count: state.failure_conditions.len(),
            escalation_history_count: state.escalation_history.len(),
        })
    }

    /// Cleanup expired sessions and failure conditions
    pub async fn cleanup_expired_data(&self) {
        let current_time = Instant::now();
        let retention_duration =
            Duration::from_millis(self.config.failure_condition_retention_ms.as_millis());

        for entry in self.session_states.iter() {
            let mut state = entry.value().lock().await;

            // Clean up old failure conditions
            state.failure_conditions.retain(|condition| {
                current_time.duration_since(condition.timestamp) < retention_duration
            });

            // Clean up old escalation history
            state.escalation_history.retain(|attempt| {
                current_time.duration_since(attempt.timestamp) < retention_duration
            });
        }

        debug!(
            connection_id = %self.connection_id,
            "Cleaned up expired recovery data"
        );
    }

    /// Handle terminal failure when Emergency recovery exhausts all attempts
    ///
    /// Per design/protocol/12-recovery-mechanisms.md:
    /// When Emergency recovery fails, the connection is unrecoverable. This method:
    /// 1. Tears down the connection
    /// 2. Clears all session state
    /// 3. Logs terminal failure event for operator visibility
    /// 4. Triggers automatic fresh handshake attempt (if connection policy allows)
    ///
    /// This provides a deterministic recovery path when all recovery mechanisms
    /// have been exhausted.
    #[instrument(skip(self, session_state), fields(connection_id = %self.connection_id, session_id = %session_id))]
    async fn handle_terminal_failure(
        &self,
        session_id: &SessionId,
        session_state: Arc<SessionState>,
    ) {
        error!(
            session_id = %session_id,
            connection_id = %self.connection_id,
            "Terminal failure: All recovery mechanisms exhausted - tearing down connection"
        );

        // Step 1: Tear down connection
        // Send termination packet to peer (best-effort, may fail)
        if let Ok(termination_packet) = self
            .create_terminal_failure_packet(session_id.clone())
            .await
        {
            let _ = self
                .coordination
                .send_recovery_packet(termination_packet)
                .await;
            info!(
                session_id = %session_id,
                "Sent terminal failure notification to peer"
            );
        }

        // Step 2: Clear session state
        session_state.set_terminated();
        session_state.cleanup_resources();

        // Remove from recovery tracking
        self.session_states.remove(session_id);

        // Step 3: Log terminal failure event
        error!(
            session_id = %session_id,
            connection_id = %self.connection_id,
            recovery_stats = ?self.get_recovery_stats().await,
            "Terminal failure logged - connection torn down, session state cleared"
        );

        // Step 4: Signal for fresh handshake attempt
        // This is handled at a higher layer (connection coordinator)
        // but we log the event here for operator visibility
        info!(
            session_id = %session_id,
            connection_id = %self.connection_id,
            "Terminal failure complete - fresh handshake should be initiated by connection coordinator"
        );
    }

    /// Create terminal failure packet for notification
    async fn create_terminal_failure_packet(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<u8>, EngineError> {
        // This delegates to the strategies layer for packet creation
        self.strategies.create_termination_packet(session_id).await
    }

    /// Check for recovery triggers across all sessions
    ///
    /// This method should be called periodically (every 100ms) to monitor for
    /// conditions requiring recovery. When triggers are detected, the engine
    /// transitions to RECOVERY_NEEDED state.
    #[instrument(skip(self), fields(connection_id = %self.connection_id))]
    pub async fn check_recovery_triggers(&self) -> Result<(), EngineError> {
        let now = Instant::now();

        for entry in self.session_states.iter() {
            let session_id = entry.key();
            let recovery_state_arc = entry.value();
            let mut recovery_state = recovery_state_arc.lock().await;

            // Only check triggers if engine is idle or recovered
            if !matches!(
                recovery_state.engine_state,
                RecoveryEngineState::Idle | RecoveryEngineState::Recovered
            ) {
                continue;
            }

            // Check if enough time has passed since last check (100ms interval)
            if now.duration_since(recovery_state.last_trigger_check) < Duration::from_millis(100) {
                continue;
            }

            recovery_state.last_trigger_check = now;

            // Get session state for trigger checks
            let session_state = match self.session_manager.get_session_state(session_id) {
                Some(state) => state,
                None => {
                    warn!(
                        session_id = %session_id,
                        "Session not found in session manager during trigger check"
                    );
                    continue;
                }
            };

            // Check if connection is established (recovery only allowed in established state)
            if !self.session_manager.is_connection_established() {
                continue;
            }

            // Use ConnectionState::Established as default since we checked above
            let connection_state = crate::protocol::types::ConnectionState::Established;

            // Check time drift using time offset from session state
            let time_offset_ms = session_state.time_offset().abs() as u64;
            let time_drift = if time_offset_ms > self.config.time_sync_tolerance_ms.as_millis() {
                Some(Duration::from_millis(time_offset_ms))
            } else {
                None
            };

            // Check sequence mismatch using local and remote sequence numbers
            let expected_seq = recovery_state.last_known_sequence.as_u32();
            let received_seq = session_state.remote_seq().as_u32();
            let sequence_gap = detect_sequence_mismatch(
                expected_seq,
                received_seq,
                self.config.max_repair_window_size.as_u32(),
            );

            // Update last known sequence if ahead
            if received_seq > expected_seq {
                recovery_state.last_known_sequence = session_state.remote_seq();
            }

            // Check authentication failures
            let auth_failure_window = Duration::from_secs(60);
            let auth_failures_in_window = if now
                .duration_since(recovery_state.last_auth_failure_time)
                < auth_failure_window
            {
                recovery_state.recent_auth_failures
            } else {
                0
            };

            // Determine recovery level needed
            let recovery_level = determine_recovery_level_needed(
                time_drift,
                sequence_gap,
                auth_failures_in_window,
                &connection_state,
            );

            // If recovery is needed, transition to RECOVERY_NEEDED state
            if recovery_level != RecoveryLevel::None {
                recovery_state.engine_state = RecoveryEngineState::RecoveryNeeded;
                recovery_state.current_level = recovery_level;

                info!(
                    session_id = %session_id,
                    recovery_level = ?recovery_level,
                    time_drift_ms = ?time_drift.map(|d| d.as_millis()),
                    sequence_gap,
                    auth_failures = auth_failures_in_window,
                    "Recovery trigger detected"
                );

                // Record failure condition
                let failure_reason = match recovery_level {
                    RecoveryLevel::TimeSync => format!("Time drift detected: {:?}", time_drift),
                    RecoveryLevel::SessionRekey => {
                        format!("Auth failures: {}", auth_failures_in_window)
                    }
                    RecoveryLevel::SequenceRepair => {
                        format!("Sequence gap detected: {:?}", sequence_gap)
                    }
                    RecoveryLevel::Emergency => "Multiple failure conditions detected".to_string(),
                    RecoveryLevel::ConnectionTerminate => {
                        "Connection in unrecoverable state".to_string()
                    }
                    _ => "Unknown failure condition".to_string(),
                };

                recovery_state
                    .record_failure_condition("Trigger detected".to_string(), failure_reason);
            }
        }

        Ok(())
    }

    /// Record an authentication failure for a session
    ///
    /// This should be called by the packet validation layer when HMAC verification fails.
    pub async fn record_auth_failure(&self, session_id: &SessionId) -> Result<(), EngineError> {
        let recovery_state = self
            .session_states
            .get(session_id)
            .ok_or_else(|| EngineError::recovery_error("Session not found in recovery tracking"))?;

        let mut state = recovery_state.lock().await;
        let now = Instant::now();

        // Reset counter if window has expired
        if now.duration_since(state.last_auth_failure_time) > Duration::from_secs(60) {
            state.recent_auth_failures = 0;
        }

        state.recent_auth_failures += 1;
        state.last_auth_failure_time = now;

        debug!(
            session_id = %session_id,
            auth_failures = state.recent_auth_failures,
            "Authentication failure recorded"
        );

        Ok(())
    }

    /// Start a background task that periodically checks for recovery triggers
    ///
    /// This spawns a tokio task that runs until the engine is shut down.
    /// Call this once when the engine is initialized.
    pub fn start_periodic_trigger_check(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                if let Err(e) = self.check_recovery_triggers().await {
                    error!(
                        connection_id = %self.connection_id,
                        error = %e,
                        "Error checking recovery triggers"
                    );
                }
            }
        })
    }

    /// Shutdown the recovery engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.session_states.clear();

        info!(
            connection_id = %self.connection_id,
            "Recovery engine shut down"
        );

        Ok(())
    }
}

/// Session-specific recovery information
#[derive(Debug, Clone)]
pub struct SessionRecoveryInfo {
    pub session_id: SessionId,
    pub current_level: RecoveryLevel,
    pub attempts_at_current_level: RecoveryAttemptCount,
    pub total_recovery_attempts: RecoveryAttemptCount,
    pub recovery_in_progress: bool,
    pub last_recovery_time: Instant,
    pub failure_conditions_count: usize,
    pub escalation_history_count: usize,
}
