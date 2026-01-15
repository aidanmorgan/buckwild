// Protocol state management
//
// This module provides state machines and state tracking for protocol connections
// and sessions, ensuring proper state transitions and validation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use tracing::{info, instrument, warn};

// Import ALL types from the authoritative consolidated types module
use crate::error::ProtocolError;
use crate::protocol::packet::Packet;
use crate::protocol::types::*;

/// Helper to handle RwLock poisoning errors
fn lock_poisoned() -> ProtocolError {
    ProtocolError::invalid_format("Lock poisoned - concurrent panic detected")
}

/// Connection information structure
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub session_id: SessionId,
    pub state: ConnectionState,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub local_sequence: SequenceNumber,
    pub remote_sequence: SequenceNumber,
    pub flags: ConnectionFlags,
}

/// Session information structure
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub state: SessionState,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub connection_count: ConnectionCount,
    pub flags: SessionFlags,
    pub metrics: SessionMetrics,
}

/// Protocol state manager
pub struct ProtocolStateManager {
    /// Connection states
    connection_states: Arc<RwLock<HashMap<SessionId, ConnectionStateInfo>>>,
    /// Session states
    session_states: Arc<RwLock<HashMap<SessionId, SessionStateInfo>>>,
    /// Configuration
    config: StateConfig,
    /// Statistics
    stats: Arc<RwLock<StateStats>>,
}

/// State management configuration
#[derive(Debug, Clone)]
pub struct StateConfig {
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Session timeout
    pub session_timeout: Duration,
    /// Maximum concurrent connections
    pub max_connections: ConnectionCount,
    /// Maximum concurrent sessions
    pub max_sessions: SessionCount,
    /// Enable strict state validation
    pub strict_validation: bool,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_millis(300_000), // 5 minutes
            session_timeout: Duration::from_millis(3_600_000),  // 1 hour
            max_connections: ConnectionCount::new(10000),
            max_sessions: SessionCount::new(10000),
            strict_validation: true,
        }
    }
}

/// Connection state information
#[derive(Debug, Clone)]
pub struct ConnectionStateInfo {
    /// Session ID
    pub session_id: SessionId,
    /// Current connection state
    pub state: ConnectionState,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last activity timestamp
    pub last_activity: Timestamp,
    /// Sequence numbers
    pub local_sequence: SequenceNumber,
    pub remote_sequence: SequenceNumber,
    /// Connection flags
    pub flags: ConnectionFlags,
}

/// Connection flags
#[derive(Debug, Clone)]
pub struct ConnectionFlags {
    /// Connection is secure
    pub secure: bool,
    /// Connection supports fragmentation
    pub fragmentation_enabled: bool,
    /// Connection has flow control
    pub flow_control_enabled: bool,
    /// Connection is authenticated
    pub authenticated: bool,
}

impl Default for ConnectionFlags {
    fn default() -> Self {
        Self {
            secure: false,
            fragmentation_enabled: true,
            flow_control_enabled: true,
            authenticated: false,
        }
    }
}

/// Session flags
#[derive(Debug, Clone)]
pub struct SessionFlags {
    /// Session is authenticated
    pub authenticated: bool,
    /// Session is encrypted
    pub encrypted: bool,
    /// Session has recovery enabled
    pub recovery_enabled: bool,
}

impl Default for SessionFlags {
    fn default() -> Self {
        Self {
            authenticated: false,
            encrypted: false,
            recovery_enabled: true,
        }
    }
}

/// Session state information
#[derive(Debug, Clone)]
pub struct SessionStateInfo {
    /// Session ID
    pub session_id: SessionId,
    /// Current session state
    pub state: SessionState,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last activity timestamp
    pub last_activity: Timestamp,
    /// Session metrics
    pub metrics: SessionMetrics,
}

/// Session metrics
#[derive(Debug, Clone)]
pub struct SessionMetrics {
    /// Packets sent
    pub packets_sent: PacketCount,
    /// Packets received
    pub packets_received: PacketCount,
    /// Bytes sent
    pub bytes_sent: ByteCount,
    /// Bytes received
    pub bytes_received: ByteCount,
    /// Errors encountered
    pub errors: ErrorCount,
}

impl Default for SessionMetrics {
    fn default() -> Self {
        Self {
            packets_sent: PacketCount::new(0),
            packets_received: PacketCount::new(0),
            bytes_sent: ByteCount::new(0),
            bytes_received: ByteCount::new(0),
            errors: ErrorCount::new(0),
        }
    }
}

/// State transition request
#[derive(Debug)]
pub struct StateTransitionRequest {
    /// Session ID
    pub session_id: SessionId,
    /// Packet that triggered the transition
    pub packet: Packet,
    /// Source of the packet (true if local, false if remote)
    pub is_local: bool,
}

/// State transition result
#[derive(Debug)]
pub enum StateTransitionResult {
    /// Transition successful
    Success {
        old_state: ConnectionState,
        new_state: ConnectionState,
    },
    /// Transition not allowed
    InvalidTransition {
        current_state: ConnectionState,
        attempted_packet_type: PacketType,
        reason: String,
    },
    /// State not found
    StateNotFound { session_id: SessionId },
}

/// State management statistics
#[derive(Debug, Clone)]
pub struct StateStats {
    /// Active connections
    pub active_connections: ConnectionCount,
    /// Active sessions
    pub active_sessions: SessionCount,
    /// Total state transitions
    pub total_transitions: TransitionCount,
    /// Invalid transitions
    pub invalid_transitions: TransitionCount,
    /// Expired connections
    pub expired_connections: ConnectionCount,
    /// Expired sessions
    pub expired_sessions: SessionCount,
}

impl ProtocolStateManager {
    /// Create a new protocol state manager
    pub fn new() -> Self {
        Self::with_config(StateConfig::default())
    }

    /// Create a new protocol state manager with custom configuration
    pub fn with_config(config: StateConfig) -> Self {
        Self {
            connection_states: Arc::new(RwLock::new(HashMap::new())),
            session_states: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(StateStats {
                active_connections: ConnectionCount::new(0),
                active_sessions: SessionCount::new(0),
                total_transitions: TransitionCount::new(0),
                invalid_transitions: TransitionCount::new(0),
                expired_connections: ConnectionCount::new(0),
                expired_sessions: SessionCount::new(0),
            })),
        }
    }

    /// Process a state transition
    ///
    /// M2 spec: State transitions are logged with structured tracing for observability.
    /// Spans include session_id, packet_type, old_state, new_state, and is_local.
    #[instrument(
        skip(self, request),
        fields(
            session_id = %request.session_id,
            packet_type = ?request.packet.packet_type(),
            is_local = request.is_local,
        )
    )]
    pub fn process_transition(
        &self,
        request: StateTransitionRequest,
    ) -> Result<StateTransitionResult, ProtocolError> {
        let packet_type = request.packet.packet_type();

        let mut connections = self
            .connection_states
            .write()
            .map_err(|_| lock_poisoned())?;
        let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
        stats.total_transitions = TransitionCount::new(stats.total_transitions.as_u64() + 1);

        // Get or create connection state
        let session_id = request.session_id;
        let connection_state =
            connections
                .entry(session_id.clone())
                .or_insert_with(|| ConnectionStateInfo {
                    session_id: session_id.clone(),
                    state: ConnectionState::Closed,
                    created_at: Timestamp::now(),
                    last_activity: Timestamp::now(),
                    local_sequence: SequenceNumber::new(0),
                    remote_sequence: SequenceNumber::new(0),
                    flags: ConnectionFlags::default(),
                });

        let old_state = connection_state.state;
        let new_state = self.calculate_new_state(&old_state, packet_type, request.is_local)?;

        // Validate transition
        if self.config.strict_validation
            && !self.is_valid_transition(&old_state, &new_state, packet_type)
        {
            stats.invalid_transitions =
                TransitionCount::new(stats.invalid_transitions.as_u64() + 1);
            warn!(
                old_state = ?old_state,
                packet_type = ?packet_type,
                "Invalid state transition rejected"
            );
            return Ok(StateTransitionResult::InvalidTransition {
                current_state: old_state,
                attempted_packet_type: packet_type,
                reason: format!(
                    "Invalid transition from {:?} with {:?}",
                    old_state, packet_type
                ),
            });
        }

        // Update connection state
        connection_state.state = new_state;
        connection_state.last_activity = SystemTime::now().into();

        // Update sequence numbers
        if request.is_local {
            connection_state.local_sequence = request.packet.sequence_number();
        } else {
            connection_state.remote_sequence = request.packet.sequence_number();
        }

        // Log state transition with M2-compliant structured fields
        info!(
            old_state = ?old_state,
            new_state = ?new_state,
            m2_old = ?old_state.to_m2_state(),
            m2_new = ?new_state.to_m2_state(),
            "Connection state transition"
        );

        // Update session state if needed
        self.update_session_state(session_id, &new_state)?;

        stats.active_connections = ConnectionCount::new(connections.len() as u32);

        Ok(StateTransitionResult::Success {
            old_state,
            new_state,
        })
    }

    /// Calculate new state based on current state and packet type
    /// M2 spec compliant state transitions
    fn calculate_new_state(
        &self,
        current_state: &ConnectionState,
        packet_type: PacketType,
        is_local: bool,
    ) -> Result<ConnectionState, ProtocolError> {
        use ConnectionState::*;
        use PacketType::*;

        // Convert legacy states to M2 equivalents
        let current = current_state.to_m2_state();

        let new_state = match (current, packet_type, is_local) {
            // Connection establishment (M2: 3-way handshake)
            // Client: IDLE/CLOSED -> SYN_SENT (send SYN)
            (Idle, Syn, true) => SynSent,
            (Closed, Syn, true) => SynSent,
            // Server: IDLE/CLOSED -> SYN_RECEIVED (receive SYN)
            (Idle, Syn, false) => SynReceived,
            (Closed, Syn, false) => SynReceived,
            // Client: SYN_SENT -> ESTABLISHED (receive SYN-ACK)
            (SynSent, SynAck, false) => Established,
            // Server: SYN_RECEIVED -> ESTABLISHED (receive ACK)
            (SynReceived, Ack, false) => Established,

            // Data transfer (stay in ESTABLISHED)
            (Established, Data, _) => Established,
            (Established, Ack, _) => Established,
            (Established, Heartbeat, _) => Established,

            // Connection termination (M2: FIN handshake)
            // Initiator: ESTABLISHED -> FIN_WAIT (send FIN)
            (Established, Fin, true) => FinWait,
            // Receiver: ESTABLISHED -> CLOSE_WAIT (receive FIN)
            (Established, Fin, false) => CloseWait,
            // FIN_WAIT -> CLOSED (receive FIN-ACK)
            (FinWait, Ack, false) => Closed,
            (FinWait, Fin, false) => Closed, // Simultaneous close
            // CLOSE_WAIT -> CLOSED (send FIN-ACK, receive ACK)
            (CloseWait, Ack, _) => Closed,

            // RST handling (M2: immediate transition to CLOSED)
            (_, Rst, _) => Closed,

            // Error handling
            (_, PacketType::Error, _) => ConnectionState::Error,

            // Recovery (M2: only from ESTABLISHED)
            (ConnectionState::Error, _, _) => Recovering,
            (Recovering, Ack, _) => Established,

            // Legacy state handling - convert and re-evaluate
            (Connecting, SynAck, _) => Established,
            (Listening, Syn, _) => SynReceived,
            (Closing, Ack, _) => Closed,

            // Invalid transitions - return current state
            _ => *current_state,
        };

        Ok(new_state)
    }

    /// Check if a state transition is valid
    /// M2 spec compliant validation
    fn is_valid_transition(
        &self,
        old_state: &ConnectionState,
        new_state: &ConnectionState,
        packet_type: PacketType,
    ) -> bool {
        use ConnectionState::*;
        use PacketType::*;

        // Convert legacy states to M2 equivalents for validation
        let old = old_state.to_m2_state();
        let new = new_state.to_m2_state();

        match (old, new, packet_type) {
            // Valid M2 establishment transitions (3-way handshake)
            (Idle | Closed, SynSent, Syn) => true, // Client sends SYN
            (Idle | Closed, SynReceived, Syn) => true, // Server receives SYN
            (SynSent, Established, SynAck) => true, // Client receives SYN-ACK
            (SynReceived, Established, Ack) => true, // Server receives ACK

            // Valid data transfer transitions (no state change)
            (Established, Established, Data | Ack | Heartbeat) => true,

            // Valid M2 termination transitions (FIN handshake)
            (Established, FinWait, Fin) => true, // Initiator sends FIN
            (Established, CloseWait, Fin) => true, // Receiver gets FIN
            (FinWait, Closed, Ack | Fin) => true, // FIN-ACK or simultaneous close
            (CloseWait, Closed, Ack) => true,    // Final ACK

            // RST is always valid (M2: immediate CLOSED)
            (_, Closed, Rst) => true,

            // Error state transitions
            (_, ConnectionState::Error, PacketType::Error) => true,

            // Recovery transitions (M2: only from ERROR state)
            (ConnectionState::Error, Recovering, _) => true,
            (Recovering, Established, Ack) => true,

            // Legacy state compatibility
            (Connecting, Established, SynAck) => true,
            (Listening, SynReceived, Syn) => true,
            (Closing, Closed, Ack) => true,

            // Same state transitions (no change)
            (old, new, _) if old == new => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    /// Update session state based on connection state
    fn update_session_state(
        &self,
        session_id: SessionId,
        connection_state: &ConnectionState,
    ) -> Result<(), ProtocolError> {
        let mut sessions = self.session_states.write().map_err(|_| lock_poisoned())?;

        let session_state =
            sessions
                .entry(session_id.clone())
                .or_insert_with(|| SessionStateInfo {
                    session_id,
                    state: SessionState::Initializing,
                    created_at: Timestamp::now(),
                    last_activity: Timestamp::now(),
                    metrics: SessionMetrics::default(),
                });

        // Update session state based on connection state (M2 compliant)
        session_state.state = match connection_state.to_m2_state() {
            ConnectionState::Idle => SessionState::Initializing,
            ConnectionState::Closed => SessionState::Terminated,
            ConnectionState::SynSent | ConnectionState::SynReceived => SessionState::Initializing,
            ConnectionState::Established => SessionState::Active,
            ConnectionState::FinWait | ConnectionState::CloseWait => SessionState::Terminating,
            ConnectionState::Recovering => SessionState::Degraded,
            ConnectionState::Error => SessionState::Terminated,
            // Legacy states (convert to M2 equivalents above handles these)
            _ => SessionState::Initializing,
        };

        session_state.last_activity = SystemTime::now().into();
        Ok(())
    }

    /// Get connection state
    pub fn get_connection_state(
        &self,
        session_id: SessionId,
    ) -> Result<Option<ConnectionState>, ProtocolError> {
        let connections = self.connection_states.read().map_err(|_| lock_poisoned())?;
        Ok(connections.get(&session_id).map(|info| info.state))
    }

    /// Get session state
    pub fn get_session_state(
        &self,
        session_id: SessionId,
    ) -> Result<Option<SessionState>, ProtocolError> {
        let sessions = self.session_states.read().map_err(|_| lock_poisoned())?;
        Ok(sessions.get(&session_id).map(|info| info.state))
    }

    /// Update session metrics
    pub fn update_session_metrics<F>(
        &self,
        session_id: SessionId,
        updater: F,
    ) -> Result<(), ProtocolError>
    where
        F: FnOnce(&mut SessionMetrics),
    {
        let mut sessions = self.session_states.write().map_err(|_| lock_poisoned())?;
        if let Some(session_state) = sessions.get_mut(&session_id) {
            updater(&mut session_state.metrics);
            session_state.last_activity = SystemTime::now().into();
        }
        Ok(())
    }

    /// Clean up expired states
    pub fn cleanup_expired_states(&self) -> Result<(), ProtocolError> {
        let connection_timeout = self.config.connection_timeout;
        let session_timeout = self.config.session_timeout;
        let now = SystemTime::now();

        let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;

        // Clean up expired connections
        {
            let mut connections = self
                .connection_states
                .write()
                .map_err(|_| lock_poisoned())?;
            let initial_count = connections.len();

            connections.retain(|_, state| {
                let last_activity_sys: SystemTime = state
                    .last_activity
                    .try_into()
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                let expired =
                    now.duration_since(last_activity_sys).unwrap_or_default() < connection_timeout;
                // Also remove closed connections that have been in TimeWait long enough
                let time_wait_expired = state.state == ConnectionState::Closed
                    && now.duration_since(last_activity_sys).unwrap_or_default()
                        > std::time::Duration::from_secs(60);

                expired && !time_wait_expired
            });

            stats.expired_connections = ConnectionCount::new(
                stats.expired_connections.as_u32() + (initial_count - connections.len()) as u32,
            );
            stats.active_connections = ConnectionCount::new(connections.len() as u32);
        }

        // Clean up expired sessions
        {
            let mut sessions = self.session_states.write().map_err(|_| lock_poisoned())?;
            let initial_count = sessions.len();

            sessions.retain(|_, state| {
                let last_activity_sys: SystemTime = state
                    .last_activity
                    .try_into()
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                now.duration_since(last_activity_sys).unwrap_or_default() < session_timeout
            });

            stats.expired_sessions = SessionCount::new(
                stats.expired_sessions.as_u32() + (initial_count - sessions.len()) as u32,
            );
            stats.active_sessions = SessionCount::new(sessions.len() as u32);
        }
        Ok(())
    }

    /// Get all active connections
    pub fn get_active_connections(&self) -> Result<Vec<ConnectionStateInfo>, ProtocolError> {
        let connections = self.connection_states.read().map_err(|_| lock_poisoned())?;
        Ok(connections.values().cloned().collect())
    }

    /// Get all active sessions
    pub fn get_active_sessions(&self) -> Result<Vec<SessionInfo>, ProtocolError> {
        let sessions = self.session_states.read().map_err(|_| lock_poisoned())?;
        Ok(sessions
            .values()
            .map(|info| SessionInfo {
                session_id: info.session_id.clone(),
                state: info.state,
                created_at: SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_nanos(info.created_at.as_nanos()),
                last_activity: SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_nanos(info.last_activity.as_nanos()),
                connection_count: ConnectionCount::new(1), // Default value
                flags: SessionFlags::default(),            // Default value
                metrics: info.metrics.clone(),
            })
            .collect())
    }

    /// Get state management statistics
    pub fn get_stats(&self) -> Result<StateStats, ProtocolError> {
        let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
        stats.active_connections = ConnectionCount::new(
            self.connection_states
                .read()
                .map_err(|_| lock_poisoned())?
                .len() as u32,
        );
        stats.active_sessions = SessionCount::new(
            self.session_states
                .read()
                .map_err(|_| lock_poisoned())?
                .len() as u32,
        );
        Ok(stats.clone())
    }

    /// Reset statistics
    pub fn reset_stats(&self) -> Result<(), ProtocolError> {
        let (active_connections, active_sessions) = {
            let stats_guard = self.stats.read().map_err(|_| lock_poisoned())?;
            (
                stats_guard.active_connections,
                SessionCount::new(stats_guard.active_sessions.as_u32()),
            )
        };

        let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;

        *stats = StateStats {
            active_connections,
            active_sessions,
            total_transitions: TransitionCount::new(0),
            invalid_transitions: TransitionCount::new(0),
            expired_connections: ConnectionCount::new(0),
            expired_sessions: SessionCount::new(0),
        };
        Ok(())
    }
}

impl Default for ProtocolStateManager {
    fn default() -> Self {
        Self::new()
    }
}
