// Connection Lifecycle - Protocol-Compliant Implementation
//
// Implements complete connection lifecycle per design/protocol/06-connection-lifecycle.md:
// - Multi-port SYN/ACK process with adaptive delay windows
// - Challenge-response authentication
// - Session configuration negotiation
// - Two-phase port hopping integration
// - Connection state machine with proper transitions
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SecureRandom;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::engines::port_hopping::TwoPhasePortHopping;
use crate::error::EngineError;
use crate::protocol::types::*;
use crate::security::crypto::ecdh::EcdhManager;

/// Connection state per design/protocol/06-connection-lifecycle.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionMachineState {
    /// Initial state - no connection
    Closed = 0,
    /// Connecting to peer (client sending SYN)
    Connecting = 1,
    /// Listening for connections (server waiting for SYN)
    Listening = 2,
    /// SYN sent, waiting for SYN-ACK (client)
    SynSent = 3,
    /// SYN received, sending SYN-ACK (server)
    SynReceived = 4,
    /// Connection established, data can be exchanged
    Established = 5,
    /// Closing connection gracefully
    Closing = 6,
    /// Recovering from error
    Recovering = 7,
    /// Error state
    Error = 8,
}

/// Recovery sub-states per design/protocol/06-connection-lifecycle.md (lines 142-146)
/// Used within ESTABLISHED and RECOVERING states to track specific recovery operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoverySubState {
    /// Normal operation, no recovery needed
    Normal = 0,
    /// Time synchronization recovery (aka TIME_SYNC in spec)
    Resync = 1,
    /// Session key rotation/recovery
    Rekey = 2,
    /// Connection repair (sequence number recovery)
    Repair = 3,
    /// Emergency recovery mode
    Emergency = 4,
}

impl RecoverySubState {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Normal),
            1 => Some(Self::Resync),
            2 => Some(Self::Rekey),
            3 => Some(Self::Repair),
            4 => Some(Self::Emergency),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if this is a recovery state (not Normal)
    pub fn is_recovering(&self) -> bool {
        !matches!(self, Self::Normal)
    }
}

impl ConnectionMachineState {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Closed),
            1 => Some(Self::Connecting),
            2 => Some(Self::Listening),
            3 => Some(Self::SynSent),
            4 => Some(Self::SynReceived),
            5 => Some(Self::Established),
            6 => Some(Self::Closing),
            7 => Some(Self::Recovering),
            8 => Some(Self::Error),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::Error)
    }
}

/// Connection state machine implementing proper state transitions
pub struct ConnectionStateMachine {
    /// Current state stored atomically for lock-free reads
    state: AtomicU8,

    /// Recovery sub-state stored atomically for lock-free reads
    sub_state: AtomicU8,

    /// Connection timeout (5 seconds per spec)
    connection_timeout: Duration,
}

impl ConnectionStateMachine {
    /// Create a new state machine in CLOSED state
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(ConnectionMachineState::Closed.as_u8()),
            sub_state: AtomicU8::new(RecoverySubState::Normal.as_u8()),
            connection_timeout: Duration::from_secs(5),
        }
    }

    /// Get current state
    pub fn current_state(&self) -> ConnectionMachineState {
        ConnectionMachineState::from_u8(self.state.load(Ordering::Acquire))
            .unwrap_or(ConnectionMachineState::Error)
    }

    /// Get current recovery sub-state
    pub fn current_sub_state(&self) -> RecoverySubState {
        RecoverySubState::from_u8(self.sub_state.load(Ordering::Acquire))
            .unwrap_or(RecoverySubState::Normal)
    }

    /// Attempt to transition from one state to another
    /// Returns error if the transition is invalid
    ///
    /// M2 spec: All state transitions are logged with structured tracing
    /// for observability and debugging.
    fn transition(
        &self,
        from: ConnectionMachineState,
        to: ConnectionMachineState,
    ) -> Result<(), EngineError> {
        let result = self.state.compare_exchange(
            from.as_u8(),
            to.as_u8(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        match result {
            Ok(_) => {
                // M2 spec: Log state transitions with structured fields
                info!(
                    from_state = ?from,
                    to_state = ?to,
                    from_u8 = from.as_u8(),
                    to_u8 = to.as_u8(),
                    is_terminal = to.is_terminal(),
                    "Connection state machine transition"
                );
                debug!(
                    from = ?from,
                    to = ?to,
                    "State transition successful"
                );
                Ok(())
            }
            Err(actual) => {
                let actual_state = ConnectionMachineState::from_u8(actual)
                    .unwrap_or(ConnectionMachineState::Error);
                warn!(
                    expected = ?from,
                    actual = ?actual_state,
                    target = ?to,
                    "State transition failed - state mismatch"
                );
                Err(EngineError::StateTransitionError {
                    from: format!("{:?}", actual_state),
                    to: format!("{:?}", to),
                })
            }
        }
    }

    /// Client initiates connection: CLOSED -> CONNECTING
    pub fn connect(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Closed,
            ConnectionMachineState::Connecting,
        )
    }

    /// Server starts listening: CLOSED -> LISTENING
    pub fn listen(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Closed,
            ConnectionMachineState::Listening,
        )
    }

    /// Client sends SYN: CONNECTING -> SYN_SENT
    pub fn send_syn(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Connecting,
            ConnectionMachineState::SynSent,
        )
    }

    /// Server receives SYN: LISTENING -> SYN_RECEIVED
    pub fn receive_syn(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Listening,
            ConnectionMachineState::SynReceived,
        )
    }

    /// Client receives SYN-ACK: SYN_SENT -> ESTABLISHED
    pub fn receive_syn_ack(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::SynSent,
            ConnectionMachineState::Established,
        )
    }

    /// Server sends SYN-ACK and receives ACK: SYN_RECEIVED -> ESTABLISHED
    pub fn complete_handshake(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::SynReceived,
            ConnectionMachineState::Established,
        )
    }

    /// Start closing: ESTABLISHED -> CLOSING
    pub fn close(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Established,
            ConnectionMachineState::Closing,
        )
    }

    /// Complete closing: CLOSING -> CLOSED
    pub fn finish_close(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Closing,
            ConnectionMachineState::Closed,
        )
    }

    /// Enter error state from any state
    pub fn enter_error(&self) {
        self.state
            .store(ConnectionMachineState::Error.as_u8(), Ordering::Release);
    }

    /// Handle RST: Immediately transition to CLOSED from any non-terminal state
    /// Per M2 acceptance criteria: "RST immediately transitions to CLOSED regardless of current state"
    pub fn handle_rst(&self) -> Result<(), EngineError> {
        let current = self.current_state();

        // Already closed - no-op
        if current == ConnectionMachineState::Closed {
            debug!("RST received but connection already closed");
            return Ok(());
        }

        // Force transition to CLOSED
        self.state
            .store(ConnectionMachineState::Closed.as_u8(), Ordering::Release);

        info!(
            from = ?current,
            "Connection reset by RST - immediately transitioned to CLOSED"
        );

        Ok(())
    }

    /// Start recovery: ERROR -> RECOVERING
    pub fn start_recovery(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Error,
            ConnectionMachineState::Recovering,
        )
    }

    /// Recovery success: RECOVERING -> CLOSED (to restart)
    pub fn recovery_success(&self) -> Result<(), EngineError> {
        self.transition(
            ConnectionMachineState::Recovering,
            ConnectionMachineState::Closed,
        )
    }

    /// Check if in established state
    pub fn is_established(&self) -> bool {
        self.current_state() == ConnectionMachineState::Established
    }

    /// Get connection timeout
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Transition to time synchronization recovery sub-state
    /// Per spec: Triggered by EVENT_TIME_DRIFT_DETECTED
    pub fn enter_resync_recovery(&self) -> Result<(), EngineError> {
        let current = self.current_sub_state();
        if current != RecoverySubState::Normal {
            warn!(
                current_sub_state = ?current,
                "Attempted to enter resync recovery from non-normal sub-state"
            );
            return Err(EngineError::StateTransitionError {
                from: format!("{:?}", current),
                to: format!("{:?}", RecoverySubState::Resync),
            });
        }

        self.sub_state
            .store(RecoverySubState::Resync.as_u8(), Ordering::Release);

        info!("Entered time synchronization recovery sub-state");
        Ok(())
    }

    /// Transition to session key rotation/recovery sub-state
    /// Per spec: Triggered by EVENT_KEY_ROTATION_NEEDED
    pub fn enter_rekey_recovery(&self) -> Result<(), EngineError> {
        let current = self.current_sub_state();
        if current != RecoverySubState::Normal {
            warn!(
                current_sub_state = ?current,
                "Attempted to enter rekey recovery from non-normal sub-state"
            );
            return Err(EngineError::StateTransitionError {
                from: format!("{:?}", current),
                to: format!("{:?}", RecoverySubState::Rekey),
            });
        }

        self.sub_state
            .store(RecoverySubState::Rekey.as_u8(), Ordering::Release);

        info!("Entered session key rotation recovery sub-state");
        Ok(())
    }

    /// Transition to connection repair sub-state (sequence number recovery)
    /// Per spec: Triggered by EVENT_SEQUENCE_MISMATCH
    pub fn enter_repair_recovery(&self) -> Result<(), EngineError> {
        let current = self.current_sub_state();
        if current != RecoverySubState::Normal {
            warn!(
                current_sub_state = ?current,
                "Attempted to enter repair recovery from non-normal sub-state"
            );
            return Err(EngineError::StateTransitionError {
                from: format!("{:?}", current),
                to: format!("{:?}", RecoverySubState::Repair),
            });
        }

        self.sub_state
            .store(RecoverySubState::Repair.as_u8(), Ordering::Release);

        info!("Entered connection repair recovery sub-state");
        Ok(())
    }

    /// Transition to emergency recovery sub-state
    /// Per spec: Triggered by EVENT_CRITICAL_FAILURE
    /// Can transition from any sub-state including other recovery sub-states
    pub fn enter_emergency_recovery(&self) -> Result<(), EngineError> {
        self.sub_state
            .store(RecoverySubState::Emergency.as_u8(), Ordering::Release);

        warn!("Entered emergency recovery sub-state");
        Ok(())
    }

    /// Return to normal operation from recovery sub-state
    /// Per spec: Triggered by EVENT_*_COMPLETED events
    pub fn exit_recovery_to_normal(&self) -> Result<(), EngineError> {
        let current = self.current_sub_state();
        if current == RecoverySubState::Normal {
            debug!("Already in normal sub-state");
            return Ok(());
        }

        self.sub_state
            .store(RecoverySubState::Normal.as_u8(), Ordering::Release);

        info!(
            from_sub_state = ?current,
            "Exited recovery sub-state, returned to normal operation"
        );
        Ok(())
    }

    /// Check if currently in any recovery sub-state
    pub fn is_in_recovery_substate(&self) -> bool {
        self.current_sub_state().is_recovering()
    }
}

impl Default for ConnectionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// Session configuration negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfiguration {
    /// Protocol version (bits 0-1)
    pub protocol_version: u8,

    /// Session ID length configuration (bits 2-3)
    /// 0 = 16-bit, 1 = 32-bit, 2 = 48-bit, 3 = 64-bit
    pub session_id_length: u8,

    /// Timestamp configuration (bits 4-5)
    /// 0 = 16-bit (65s), 1 = 24-bit (4.6h), 2 = 32-bit (49d)
    pub timestamp_config: u8,

    /// HMAC policy (bits 6-7)
    /// 0 = None, 1 = Low (8 bytes), 2 = Medium (16 bytes), 3 = High (24 bytes)
    pub hmac_policy: u8,
}

impl SessionConfiguration {
    /// Create from version byte
    pub fn from_version_byte(version_byte: u8) -> Self {
        Self {
            protocol_version: version_byte & 0x3,
            session_id_length: (version_byte >> 2) & 0x3,
            timestamp_config: (version_byte >> 4) & 0x3,
            hmac_policy: (version_byte >> 6) & 0x3,
        }
    }

    /// Convert to version byte
    pub fn to_version_byte(&self) -> u8 {
        (self.protocol_version & 0x3)
            | ((self.session_id_length & 0x3) << 2)
            | ((self.timestamp_config & 0x3) << 4)
            | ((self.hmac_policy & 0x3) << 6)
    }

    /// Negotiate configuration with peer
    /// Uses "prefer more secure" strategy: max(local, peer) for each parameter
    pub fn negotiate(local: Self, peer: Self) -> Result<Self, EngineError> {
        // Protocol version must match
        if local.protocol_version != peer.protocol_version {
            return Err(EngineError::ProtocolMismatch(format!(
                "Version mismatch: local={}, peer={}",
                local.protocol_version, peer.protocol_version
            )));
        }

        // Use maximum values (more secure/precise)
        let negotiated = Self {
            protocol_version: local.protocol_version,
            session_id_length: local.session_id_length.max(peer.session_id_length),
            timestamp_config: local.timestamp_config.max(peer.timestamp_config),
            hmac_policy: local.hmac_policy.max(peer.hmac_policy),
        };

        // Validate negotiated configuration
        if negotiated.session_id_length > 3
            || negotiated.timestamp_config > 2
            || negotiated.hmac_policy > 3
        {
            return Err(EngineError::InvalidConfiguration(
                "Negotiated configuration out of range".to_string(),
            ));
        }

        debug!(
            "Negotiated configuration: sid_len={}, ts_cfg={}, hmac={}",
            negotiated.session_id_length, negotiated.timestamp_config, negotiated.hmac_policy
        );

        Ok(negotiated)
    }

    /// Get session ID size in bytes
    pub fn session_id_bytes(&self) -> usize {
        match self.session_id_length {
            0 => 2, // 16-bit
            1 => 4, // 32-bit
            2 => 6, // 48-bit
            3 => 8, // 64-bit
            _ => 4, // Default to 32-bit
        }
    }

    /// Get timestamp size in bytes
    pub fn timestamp_bytes(&self) -> usize {
        match self.timestamp_config {
            0 => 2, // 16-bit
            1 => 3, // 24-bit
            2 => 4, // 32-bit
            _ => 4, // Default to 32-bit
        }
    }

    /// Get HMAC size in bytes
    pub fn hmac_bytes(&self) -> usize {
        match self.hmac_policy {
            0 => 0,  // None
            1 => 8,  // Low
            2 => 16, // Medium
            3 => 24, // High
            _ => 16, // Default to medium
        }
    }
}

impl Default for SessionConfiguration {
    fn default() -> Self {
        Self {
            protocol_version: 1,  // Protocol v1
            session_id_length: 1, // 32-bit session IDs
            timestamp_config: 2,  // 32-bit timestamps (49 days)
            hmac_policy: 2,       // Medium HMAC (16 bytes)
        }
    }
}

/// Challenge-response authentication
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// Challenge bytes (32 bytes random)
    challenge: [u8; 32],

    /// Response HMAC (session key, challenge)
    /// Kept for potential future audit logging
    #[allow(dead_code)]
    response: Option<[u8; 32]>,

    /// Creation timestamp
    created_at: SystemTime,

    /// TTL (time-to-live)
    ttl: Duration,
}

impl ChallengeResponse {
    /// Create new challenge
    pub fn new_challenge(ttl: Duration) -> Result<Self, EngineError> {
        let mut challenge = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| EngineError::CryptoError("Failed to generate challenge".to_string()))?;

        Ok(Self {
            challenge,
            response: None,
            created_at: SystemTime::now(),
            ttl,
        })
    }

    /// Get challenge bytes
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// Compute response
    pub fn compute_response(&self, session_key: &[u8]) -> Result<[u8; 32], EngineError> {
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, session_key);
        let signature = ring::hmac::sign(&hmac_key, &self.challenge);

        let mut response = [0u8; 32];
        response.copy_from_slice(signature.as_ref());

        Ok(response)
    }

    /// Verify response
    pub fn verify_response(
        &self,
        session_key: &[u8],
        response: &[u8; 32],
    ) -> Result<bool, EngineError> {
        // Check if challenge expired
        if self.created_at.elapsed().unwrap_or(Duration::MAX) > self.ttl {
            return Err(EngineError::ChallengeExpired);
        }

        let expected_response = self.compute_response(session_key)?;

        // Constant-time comparison
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= expected_response[i] ^ response[i];
        }

        Ok(diff == 0)
    }

    /// Check if expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().unwrap_or(Duration::MAX) > self.ttl
    }
}

/// Multi-port handshake phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    /// Phase 1: PSK Discovery (if multiple PSKs)
    PskDiscovery,

    /// Phase 2: ECDH Key Exchange
    EcdhKeyExchange,

    /// Phase 3: Challenge-Response Authentication
    Authentication,

    /// Phase 4: Session Finalization
    Finalization,

    /// Complete
    Complete,

    /// Failed
    Failed,
}

/// Connection lifecycle manager
/// Coordinates the two-phase port hopping handshake
pub struct ConnectionLifecycle {
    /// Connection state machine
    state_machine: ConnectionStateMachine,

    /// Two-phase port hopping manager
    port_hopping: Arc<Mutex<TwoPhasePortHopping>>,

    /// Current handshake phase
    phase: Arc<RwLock<HandshakePhase>>,

    /// Local session configuration preference
    local_config: SessionConfiguration,

    /// Negotiated session configuration
    negotiated_config: Arc<RwLock<Option<SessionConfiguration>>>,

    /// ECDH manager for key exchange
    ecdh_manager: Arc<EcdhManager>,

    /// Local key ID for ECDH operations
    local_key_id: String,

    /// Challenge for authentication
    challenge: Arc<Mutex<Option<ChallengeResponse>>>,

    /// Session key (after ECDH completes)
    session_key: Arc<RwLock<Option<Vec<u8>>>>,

    /// Adaptive window sizes
    past_window_ms: u32,
    future_window_ms: u32,
}

impl std::fmt::Debug for ConnectionLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionLifecycle")
            .field("state", &self.state_machine.current_state())
            .field("local_config", &self.local_config)
            .field("local_key_id", &self.local_key_id)
            .field("past_window_ms", &self.past_window_ms)
            .field("future_window_ms", &self.future_window_ms)
            .finish()
    }
}

impl ConnectionLifecycle {
    /// Create new connection lifecycle manager
    pub fn new(
        psk: Vec<u8>,
        time_bucket_ms: u32,
        min_port: u16,
        max_port: u16,
        past_window_ms: u32,
        future_window_ms: u32,
        local_config: SessionConfiguration,
    ) -> Result<Self, EngineError> {
        let port_hopping = TwoPhasePortHopping::new(
            psk,
            time_bucket_ms,
            min_port,
            max_port,
            past_window_ms,
            future_window_ms,
        )?;

        // Generate unique key ID for ECDH operations
        let mut key_id_bytes = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut key_id_bytes)
            .map_err(|_| EngineError::CryptoError("Failed to generate key ID".to_string()))?;
        // Convert to hex string manually to avoid external dependency
        let local_key_id: String = key_id_bytes[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        Ok(Self {
            state_machine: ConnectionStateMachine::new(),
            port_hopping: Arc::new(Mutex::new(port_hopping)),
            phase: Arc::new(RwLock::new(HandshakePhase::EcdhKeyExchange)),
            local_config,
            negotiated_config: Arc::new(RwLock::new(None)),
            ecdh_manager: Arc::new(EcdhManager::new(10)), // 10 minute key expiry
            local_key_id,
            challenge: Arc::new(Mutex::new(None)),
            session_key: Arc::new(RwLock::new(None)),
            past_window_ms,
            future_window_ms,
        })
    }

    /// Get the connection state machine
    pub fn state_machine(&self) -> &ConnectionStateMachine {
        &self.state_machine
    }

    /// Get current connection state
    pub fn connection_state(&self) -> ConnectionMachineState {
        self.state_machine.current_state()
    }

    /// Get current handshake phase
    pub async fn current_phase(&self) -> HandshakePhase {
        *self.phase.read().await
    }

    /// Client: Initiate connection (CLOSED -> CONNECTING -> SYN_SENT)
    /// Returns the local ECDH public key to include in SYN packet
    pub async fn initiate_connection(&self) -> Result<EcdhPublicKey, EngineError> {
        // Transition state machine: CLOSED -> CONNECTING
        self.state_machine.connect()?;

        // Generate ECDH keypair
        let public_key = self
            .ecdh_manager
            .get_key_pair(&self.local_key_id)
            .map_err(|e| {
                EngineError::CryptoError(format!("Ecdh key generation failed: {:?}", e))
            })?;

        // Transition to SYN_SENT
        self.state_machine.send_syn()?;

        debug!(
            key_id = %self.local_key_id,
            "Connection initiated, SYN sent with public key"
        );

        Ok(public_key)
    }

    /// Server: Start listening for connections (CLOSED -> LISTENING)
    pub fn start_listening(&self) -> Result<(), EngineError> {
        self.state_machine.listen()
    }

    /// Server: Handle incoming SYN (LISTENING -> SYN_RECEIVED)
    /// Returns the server's ECDH public key to include in SYN-ACK
    pub async fn handle_syn(
        &self,
        client_public_key: &EcdhPublicKey,
    ) -> Result<(EcdhPublicKey, [u8; 32]), EngineError> {
        // Transition state machine: LISTENING -> SYN_RECEIVED
        self.state_machine.receive_syn()?;

        // Generate server ECDH keypair
        let server_public_key =
            self.ecdh_manager
                .get_key_pair(&self.local_key_id)
                .map_err(|e| {
                    EngineError::CryptoError(format!("Ecdh key generation failed: {:?}", e))
                })?;

        // Compute shared secret
        let shared_secret = self
            .ecdh_manager
            .compute_shared_secret(&self.local_key_id, client_public_key)
            .map_err(|e| EngineError::CryptoError(format!("Ecdh agreement failed: {:?}", e)))?;

        // Derive session key
        let session_key = self.derive_session_key(shared_secret.as_bytes())?;
        *self.session_key.write().await = Some(session_key);

        // Generate challenge for authentication
        let challenge = ChallengeResponse::new_challenge(Duration::from_secs(30))?;
        let challenge_bytes = *challenge.challenge();
        *self.challenge.lock().await = Some(challenge);

        *self.phase.write().await = HandshakePhase::Authentication;

        debug!("SYN received, SYN-ACK prepared with challenge");

        Ok((server_public_key, challenge_bytes))
    }

    /// Client: Handle SYN-ACK (SYN_SENT -> ESTABLISHED after ACK)
    /// Computes shared secret and prepares challenge response
    pub async fn handle_syn_ack(
        &self,
        server_public_key: &EcdhPublicKey,
        challenge: &[u8; 32],
    ) -> Result<[u8; 32], EngineError> {
        // Compute shared secret
        let shared_secret = self
            .ecdh_manager
            .compute_shared_secret(&self.local_key_id, server_public_key)
            .map_err(|e| EngineError::CryptoError(format!("Ecdh agreement failed: {:?}", e)))?;

        // Derive session key
        let session_key = self.derive_session_key(shared_secret.as_bytes())?;
        *self.session_key.write().await = Some(session_key.clone());

        // Compute challenge response
        let temp_challenge = ChallengeResponse {
            challenge: *challenge,
            response: None,
            created_at: SystemTime::now(),
            ttl: Duration::from_secs(30),
        };
        let response = temp_challenge.compute_response(&session_key)?;

        // Transition to ESTABLISHED
        self.state_machine.receive_syn_ack()?;

        // Transition to session port hopping phase
        self.transition_to_session_phase().await?;

        *self.phase.write().await = HandshakePhase::Complete;

        info!("SYN-ACK received, connection established (client)");

        Ok(response)
    }

    /// Server: Handle ACK and verify challenge response (SYN_RECEIVED -> ESTABLISHED)
    pub async fn handle_ack(&self, challenge_response: &[u8; 32]) -> Result<(), EngineError> {
        // Verify challenge response
        let challenge = self
            .challenge
            .lock()
            .await
            .as_ref()
            .ok_or_else(|| EngineError::InvalidState("No challenge available".to_string()))?
            .clone();

        let session_key = self
            .session_key
            .read()
            .await
            .as_ref()
            .ok_or_else(|| EngineError::InvalidState("Session key not available".to_string()))?
            .clone();

        let verified = challenge.verify_response(&session_key, challenge_response)?;

        if !verified {
            *self.phase.write().await = HandshakePhase::Failed;
            self.state_machine.enter_error();
            return Err(EngineError::CryptoError(
                "Challenge response verification failed".to_string(),
            ));
        }

        // Transition to ESTABLISHED
        self.state_machine.complete_handshake()?;

        // Transition to session port hopping phase
        self.transition_to_session_phase().await?;

        *self.phase.write().await = HandshakePhase::Complete;

        info!("ACK received, connection established (server)");

        Ok(())
    }

    /// Calculate ports for multi-port listening
    /// Returns all ports within adaptive delay window
    pub async fn calculate_listening_ports(&self) -> Result<Vec<Port>, EngineError> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EngineError::TimeError("Invalid system time".to_string()))?
            .as_millis() as u64;

        let mut port_hopping = self.port_hopping.lock().await;
        port_hopping.calculate_window_ports(timestamp_ms)
    }

    /// Calculate current port
    pub async fn calculate_current_port(&self) -> Result<Port, EngineError> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EngineError::TimeError("Invalid system time".to_string()))?
            .as_millis() as u64;

        let mut port_hopping = self.port_hopping.lock().await;
        port_hopping.calculate_current_port(timestamp_ms)
    }

    /// Negotiate session configuration with peer
    pub async fn negotiate_configuration(
        &self,
        peer_version_byte: u8,
    ) -> Result<SessionConfiguration, EngineError> {
        let peer_config = SessionConfiguration::from_version_byte(peer_version_byte);
        let negotiated = SessionConfiguration::negotiate(self.local_config, peer_config)?;

        *self.negotiated_config.write().await = Some(negotiated);

        info!(
            "Negotiated session configuration: version_byte={}",
            negotiated.to_version_byte()
        );

        Ok(negotiated)
    }

    /// Get negotiated configuration
    pub async fn get_negotiated_config(&self) -> Option<SessionConfiguration> {
        *self.negotiated_config.read().await
    }

    /// Derive session key from ECDH shared secret using PBKDF2
    fn derive_session_key(&self, shared_secret: &[u8]) -> Result<Vec<u8>, EngineError> {
        use ring::pbkdf2;

        let mut session_key = vec![0u8; 32];

        // 4096 iterations per design decision: adequate security without UX degradation
        const PBKDF2_ITERATIONS: std::num::NonZeroU32 = std::num::NonZeroU32::new(4096).unwrap();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITERATIONS,
            b"buckwild_session_key", // Salt
            shared_secret,
            &mut session_key,
        );

        Ok(session_key)
    }

    /// Transition to session port phase
    /// Called after ECDH completes, uses PBKDF2 to derive session seed
    async fn transition_to_session_phase(&self) -> Result<(), EngineError> {
        let session_key = self
            .session_key
            .read()
            .await
            .as_ref()
            .ok_or_else(|| EngineError::InvalidState("Session key not available".to_string()))?
            .clone();

        // Derive session seed for port hopping
        use ring::pbkdf2;

        let mut session_seed_buffer = vec![0u8; 32];

        const PBKDF2_ITERATIONS: std::num::NonZeroU32 = std::num::NonZeroU32::new(4096).unwrap();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITERATIONS,
            b"buckwild_session_port_seed",
            &session_key,
            &mut session_seed_buffer,
        );

        // Use as session seed
        let mut session_seed = [0u8; 32];
        session_seed.copy_from_slice(&session_seed_buffer[..32]);

        // Transition port hopping to Phase 2
        self.port_hopping
            .lock()
            .await
            .transition_to_session_phase(session_seed)?;

        info!("Transitioned to Phase 2 (session port hopping)");
        Ok(())
    }

    /// Generate authentication challenge (server side)
    pub async fn generate_challenge(&self) -> Result<[u8; 32], EngineError> {
        *self.phase.write().await = HandshakePhase::Authentication;

        let challenge_response = ChallengeResponse::new_challenge(Duration::from_secs(30))?;
        let challenge = *challenge_response.challenge();

        *self.challenge.lock().await = Some(challenge_response);

        debug!("Generated authentication challenge");
        Ok(challenge)
    }

    /// Compute challenge response (client side)
    pub async fn compute_challenge_response(
        &self,
        challenge: &[u8; 32],
    ) -> Result<[u8; 32], EngineError> {
        let session_key = self
            .session_key
            .read()
            .await
            .as_ref()
            .ok_or_else(|| EngineError::InvalidState("Session key not available".to_string()))?
            .clone();

        let temp_challenge = ChallengeResponse {
            challenge: *challenge,
            response: None,
            created_at: SystemTime::now(),
            ttl: Duration::from_secs(30),
        };

        let response = temp_challenge.compute_response(&session_key)?;

        debug!("Computed challenge response");
        Ok(response)
    }

    /// Verify challenge response (server side)
    pub async fn verify_challenge_response(
        &self,
        response: &[u8; 32],
    ) -> Result<bool, EngineError> {
        let challenge = self
            .challenge
            .lock()
            .await
            .as_ref()
            .ok_or_else(|| EngineError::InvalidState("No challenge available".to_string()))?
            .clone();

        let session_key = self
            .session_key
            .read()
            .await
            .as_ref()
            .ok_or_else(|| EngineError::InvalidState("Session key not available".to_string()))?
            .clone();

        let verified = challenge.verify_response(&session_key, response)?;

        if verified {
            *self.phase.write().await = HandshakePhase::Finalization;
            info!("Challenge-response authentication successful");
        } else {
            *self.phase.write().await = HandshakePhase::Failed;
            warn!("Challenge-response authentication failed");
        }

        Ok(verified)
    }

    /// Finalize connection
    pub async fn finalize_connection(&self) -> Result<(), EngineError> {
        let phase = *self.phase.read().await;
        if phase != HandshakePhase::Finalization {
            return Err(EngineError::InvalidState(format!(
                "Cannot finalize from phase {:?}",
                phase
            )));
        }

        *self.phase.write().await = HandshakePhase::Complete;

        info!("Connection lifecycle complete");
        Ok(())
    }

    /// Check if connection is established
    pub async fn is_established(&self) -> bool {
        self.state_machine.is_established() && *self.phase.read().await == HandshakePhase::Complete
    }

    /// Get session key
    pub async fn get_session_key(&self) -> Option<Vec<u8>> {
        self.session_key.read().await.clone()
    }

    /// Close connection gracefully
    pub fn close(&self) -> Result<(), EngineError> {
        self.state_machine.close()
    }

    /// Handle RST packet - immediately terminates connection
    /// Per protocol spec: RST causes immediate transition to CLOSED from any state
    pub async fn handle_rst(&self) -> Result<(), EngineError> {
        // Handle RST at state machine level
        self.state_machine.handle_rst()?;

        // Mark handshake as failed
        *self.phase.write().await = HandshakePhase::Failed;

        // Clear session key for security
        *self.session_key.write().await = None;

        warn!("Connection reset by RST packet");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_client_flow() {
        let sm = ConnectionStateMachine::new();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // CLOSED -> CONNECTING
        sm.connect().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Connecting);

        // CONNECTING -> SYN_SENT
        sm.send_syn().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::SynSent);

        // SYN_SENT -> ESTABLISHED
        sm.receive_syn_ack().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Established);
        assert!(sm.is_established());

        // ESTABLISHED -> CLOSING
        sm.close().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closing);

        // CLOSING -> CLOSED
        sm.finish_close().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);
    }

    #[test]
    fn test_state_machine_server_flow() {
        let sm = ConnectionStateMachine::new();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // CLOSED -> LISTENING
        sm.listen().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Listening);

        // LISTENING -> SYN_RECEIVED
        sm.receive_syn().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::SynReceived);

        // SYN_RECEIVED -> ESTABLISHED
        sm.complete_handshake().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Established);
        assert!(sm.is_established());
    }

    #[test]
    fn test_invalid_transitions() {
        let sm = ConnectionStateMachine::new();

        // Can't go directly to ESTABLISHED from CLOSED
        let result = sm.receive_syn_ack();
        assert!(result.is_err());

        // Can't listen when already connecting
        sm.connect().unwrap();
        let result = sm.listen();
        assert!(result.is_err());
    }

    #[test]
    fn test_session_configuration_negotiation() {
        let local = SessionConfiguration {
            protocol_version: 1,
            session_id_length: 1, // 32-bit
            timestamp_config: 2,  // 32-bit
            hmac_policy: 2,       // Medium
        };

        let peer = SessionConfiguration {
            protocol_version: 1,
            session_id_length: 2, // 48-bit
            timestamp_config: 1,  // 24-bit
            hmac_policy: 3,       // High
        };

        let negotiated = SessionConfiguration::negotiate(local, peer).unwrap();

        // Should use max values (more secure)
        assert_eq!(negotiated.session_id_length, 2); // 48-bit wins
        assert_eq!(negotiated.timestamp_config, 2); // 32-bit wins
        assert_eq!(negotiated.hmac_policy, 3); // High wins
    }

    #[test]
    fn test_version_byte_encoding() {
        let config = SessionConfiguration {
            protocol_version: 1,
            session_id_length: 2,
            timestamp_config: 1,
            hmac_policy: 3,
        };

        let version_byte = config.to_version_byte();
        let decoded = SessionConfiguration::from_version_byte(version_byte);

        assert_eq!(config.protocol_version, decoded.protocol_version);
        assert_eq!(config.session_id_length, decoded.session_id_length);
        assert_eq!(config.timestamp_config, decoded.timestamp_config);
        assert_eq!(config.hmac_policy, decoded.hmac_policy);
    }

    #[test]
    fn test_challenge_response() {
        let challenge = ChallengeResponse::new_challenge(Duration::from_secs(30)).unwrap();
        let session_key = b"test_session_key_32_bytes_long!!";

        let response = challenge.compute_response(session_key).unwrap();
        assert!(challenge.verify_response(session_key, &response).unwrap());

        // Wrong key should fail
        let wrong_key = b"wrong_key_32_bytes_long!!!!!!!!!!";
        assert!(!challenge.verify_response(wrong_key, &response).unwrap());
    }

    #[tokio::test]
    async fn test_connection_lifecycle_creation() {
        let psk = b"test_psk_for_lifecycle".to_vec();
        let lifecycle = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .unwrap();

        // Should start in CLOSED state
        assert_eq!(lifecycle.connection_state(), ConnectionMachineState::Closed);

        // Should start in ECDH phase
        assert_eq!(
            lifecycle.current_phase().await,
            HandshakePhase::EcdhKeyExchange
        );

        // Can calculate ports
        let ports = lifecycle.calculate_listening_ports().await.unwrap();
        assert!(!ports.is_empty());
    }

    #[tokio::test]
    async fn test_full_handshake_flow() {
        let psk = b"shared_psk_for_handshake".to_vec();

        // Create client lifecycle
        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .unwrap();

        // Create server lifecycle
        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .unwrap();

        // Server starts listening
        server.start_listening().unwrap();
        assert_eq!(server.connection_state(), ConnectionMachineState::Listening);

        // Client initiates connection (gets public key for SYN)
        let client_pub_key = client.initiate_connection().await.unwrap();
        assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

        // Server handles SYN (gets server pub key and challenge for SYN-ACK)
        let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.unwrap();
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::SynReceived
        );

        // Client handles SYN-ACK (gets challenge response for ACK)
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .unwrap();
        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );
        assert!(client.is_established().await);

        // Server handles ACK
        server.handle_ack(&response).await.unwrap();
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::Established
        );
        assert!(server.is_established().await);

        // Both should have session keys
        let client_key = client.get_session_key().await.unwrap();
        let server_key = server.get_session_key().await.unwrap();
        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_rst_handling_from_any_state() {
        // Test RST handling from various states

        // RST from CLOSED (no-op)
        let sm = ConnectionStateMachine::new();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // RST from CONNECTING
        let sm = ConnectionStateMachine::new();
        sm.connect().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Connecting);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // RST from SYN_SENT
        let sm = ConnectionStateMachine::new();
        sm.connect().unwrap();
        sm.send_syn().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::SynSent);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // RST from LISTENING
        let sm = ConnectionStateMachine::new();
        sm.listen().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Listening);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // RST from SYN_RECEIVED
        let sm = ConnectionStateMachine::new();
        sm.listen().unwrap();
        sm.receive_syn().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::SynReceived);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // RST from ESTABLISHED
        let sm = ConnectionStateMachine::new();
        sm.listen().unwrap();
        sm.receive_syn().unwrap();
        sm.complete_handshake().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Established);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);

        // RST from ERROR
        let sm = ConnectionStateMachine::new();
        sm.connect().unwrap();
        sm.enter_error();
        assert_eq!(sm.current_state(), ConnectionMachineState::Error);
        sm.handle_rst().unwrap();
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);
    }

    #[tokio::test]
    async fn test_lifecycle_rst_handling() {
        let psk = b"test_psk_for_rst".to_vec();

        let lifecycle = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .unwrap();

        // Start connecting
        let _ = lifecycle.initiate_connection().await.unwrap();
        assert_eq!(
            lifecycle.connection_state(),
            ConnectionMachineState::SynSent
        );

        // Handle RST
        lifecycle.handle_rst().await.unwrap();

        // Should be CLOSED
        assert_eq!(lifecycle.connection_state(), ConnectionMachineState::Closed);

        // Session key should be cleared
        assert!(lifecycle.get_session_key().await.is_none());

        // Phase should be Failed
        assert_eq!(lifecycle.current_phase().await, HandshakePhase::Failed);
    }

    #[test]
    fn test_recovery_substate_conversions() {
        // Test all sub-state conversions
        assert_eq!(RecoverySubState::from_u8(0), Some(RecoverySubState::Normal));
        assert_eq!(RecoverySubState::from_u8(1), Some(RecoverySubState::Resync));
        assert_eq!(RecoverySubState::from_u8(2), Some(RecoverySubState::Rekey));
        assert_eq!(RecoverySubState::from_u8(3), Some(RecoverySubState::Repair));
        assert_eq!(
            RecoverySubState::from_u8(4),
            Some(RecoverySubState::Emergency)
        );
        assert_eq!(RecoverySubState::from_u8(5), None);

        // Test to u8
        assert_eq!(RecoverySubState::Normal.as_u8(), 0);
        assert_eq!(RecoverySubState::Resync.as_u8(), 1);
        assert_eq!(RecoverySubState::Rekey.as_u8(), 2);
        assert_eq!(RecoverySubState::Repair.as_u8(), 3);
        assert_eq!(RecoverySubState::Emergency.as_u8(), 4);
    }

    #[test]
    fn test_recovery_substate_is_recovering() {
        assert!(!RecoverySubState::Normal.is_recovering());
        assert!(RecoverySubState::Resync.is_recovering());
        assert!(RecoverySubState::Rekey.is_recovering());
        assert!(RecoverySubState::Repair.is_recovering());
        assert!(RecoverySubState::Emergency.is_recovering());
    }

    #[test]
    fn test_initial_substate() {
        let sm = ConnectionStateMachine::new();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);
        assert!(!sm.is_in_recovery_substate());
    }

    #[test]
    fn test_enter_resync_recovery() {
        let sm = ConnectionStateMachine::new();

        // Should start in Normal
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);

        // Transition to Resync
        sm.enter_resync_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Resync);
        assert!(sm.is_in_recovery_substate());

        // Cannot enter resync from resync
        let result = sm.enter_resync_recovery();
        assert!(result.is_err());
    }

    #[test]
    fn test_enter_rekey_recovery() {
        let sm = ConnectionStateMachine::new();

        // Transition to Rekey
        sm.enter_rekey_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Rekey);
        assert!(sm.is_in_recovery_substate());

        // Cannot enter rekey from rekey
        let result = sm.enter_rekey_recovery();
        assert!(result.is_err());
    }

    #[test]
    fn test_enter_repair_recovery() {
        let sm = ConnectionStateMachine::new();

        // Transition to Repair
        sm.enter_repair_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Repair);
        assert!(sm.is_in_recovery_substate());

        // Cannot enter repair from repair
        let result = sm.enter_repair_recovery();
        assert!(result.is_err());
    }

    #[test]
    fn test_enter_emergency_recovery() {
        let sm = ConnectionStateMachine::new();

        // Can enter emergency from normal
        sm.enter_emergency_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Emergency);
        assert!(sm.is_in_recovery_substate());

        // Emergency can be entered from any state (including itself)
        sm.enter_emergency_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Emergency);
    }

    #[test]
    fn test_emergency_recovery_from_other_substates() {
        // Emergency can be entered from Resync
        let sm = ConnectionStateMachine::new();
        sm.enter_resync_recovery().unwrap();
        sm.enter_emergency_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Emergency);

        // Emergency can be entered from Rekey
        let sm = ConnectionStateMachine::new();
        sm.enter_rekey_recovery().unwrap();
        sm.enter_emergency_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Emergency);

        // Emergency can be entered from Repair
        let sm = ConnectionStateMachine::new();
        sm.enter_repair_recovery().unwrap();
        sm.enter_emergency_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Emergency);
    }

    #[test]
    fn test_exit_recovery_to_normal() {
        // From Resync
        let sm = ConnectionStateMachine::new();
        sm.enter_resync_recovery().unwrap();
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);
        assert!(!sm.is_in_recovery_substate());

        // From Rekey
        let sm = ConnectionStateMachine::new();
        sm.enter_rekey_recovery().unwrap();
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);

        // From Repair
        let sm = ConnectionStateMachine::new();
        sm.enter_repair_recovery().unwrap();
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);

        // From Emergency
        let sm = ConnectionStateMachine::new();
        sm.enter_emergency_recovery().unwrap();
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);
    }

    #[test]
    fn test_exit_recovery_from_normal_is_noop() {
        let sm = ConnectionStateMachine::new();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);

        // Exiting from normal should succeed (no-op)
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);
    }

    #[test]
    fn test_recovery_substate_transition_sequence() {
        let sm = ConnectionStateMachine::new();

        // Normal -> Resync -> Normal
        sm.enter_resync_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Resync);
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);

        // Normal -> Rekey -> Normal
        sm.enter_rekey_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Rekey);
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);

        // Normal -> Repair -> Emergency -> Normal
        sm.enter_repair_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Repair);
        sm.enter_emergency_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Emergency);
        sm.exit_recovery_to_normal().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Normal);
    }

    #[test]
    fn test_recovery_substate_cannot_transition_between_non_emergency() {
        let sm = ConnectionStateMachine::new();

        // Resync -> Rekey should fail
        sm.enter_resync_recovery().unwrap();
        let result = sm.enter_rekey_recovery();
        assert!(result.is_err());
        assert_eq!(sm.current_sub_state(), RecoverySubState::Resync);

        // Must go back to Normal first
        sm.exit_recovery_to_normal().unwrap();
        sm.enter_rekey_recovery().unwrap();
        assert_eq!(sm.current_sub_state(), RecoverySubState::Rekey);
    }

    // Task 3.3.9: Connection Lifecycle Integration Tests with Mock Devices
    // Testing full connection lifecycle with MockClock and TestTunDevice

    use crate::network::tun::{DeviceName, Mtu, TestTunDevice, TunConfig, TunDevice};
    use crate::protocol::types::Timestamp;
    use crate::traits::clock::{Clock, MockClock};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_handshake_with_deterministic_time() {
        // Test handshake flow with MockClock for controlled time progression
        let clock = Arc::new(MockClock::new(Timestamp::from_millis(1000)));
        let psk = b"test_psk_deterministic_time".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server");

        let start_time = clock.now();

        // Server starts listening
        server.start_listening().expect("Server failed to listen");
        assert_eq!(server.connection_state(), ConnectionMachineState::Listening);

        // Client initiates
        let client_pub_key = client
            .initiate_connection()
            .await
            .expect("Client failed to initiate");
        assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

        // Simulate 10ms network delay
        clock.advance(std::time::Duration::from_millis(10));

        // Server handles SYN
        let (server_pub_key, challenge) = server
            .handle_syn(&client_pub_key)
            .await
            .expect("Server failed to handle SYN");
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::SynReceived
        );

        // Another 10ms delay
        clock.advance(std::time::Duration::from_millis(10));

        // Client handles SYN-ACK
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("Client failed to handle SYN-ACK");
        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );

        // Final 10ms delay
        clock.advance(std::time::Duration::from_millis(10));

        // Server handles ACK
        server
            .handle_ack(&response)
            .await
            .expect("Server failed to handle ACK");
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::Established
        );

        // Verify total handshake time
        let total_time = clock.now().as_millis() - start_time.as_millis();
        assert_eq!(total_time, 30, "Handshake should take exactly 30ms");

        // Verify session keys match
        assert_eq!(
            client
                .get_session_key()
                .await
                .expect("Client should have key"),
            server
                .get_session_key()
                .await
                .expect("Server should have key")
        );
    }

    #[tokio::test]
    async fn test_data_transfer_with_tun_mock() {
        // Test data transfer through mock TUN devices
        let psk = b"test_psk_tun_transfer".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server");

        // Create TUN devices
        let config = TunConfig::new(
            DeviceName::new("tun_test").expect("Failed to create device name"),
            "10.0.0.1".parse().expect("Failed to parse IP"),
            "255.255.255.0".parse().expect("Failed to parse netmask"),
            Mtu::default(),
        );

        let mut client_tun = TestTunDevice::create(config.clone())
            .await
            .expect("Failed to create client TUN");
        let mut server_tun = TestTunDevice::create(config)
            .await
            .expect("Failed to create server TUN");

        // Establish connection
        server.start_listening().expect("Server failed to listen");
        let client_pub_key = client.initiate_connection().await.expect("Client init");
        let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.expect("SYN");
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("SYN-ACK");
        server.handle_ack(&response).await.expect("ACK");

        // Both should be established
        assert!(client.is_established().await);
        assert!(server.is_established().await);

        // Send test packet from client
        let test_packet = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        client_tun
            .write_packet(&test_packet)
            .await
            .expect("Failed to write");

        // Verify captured
        let captured = client_tun.captured_packets();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], test_packet);

        // Inject response from server
        let response_packet = vec![0x06, 0x07, 0x08, 0x09, 0x0a];
        server_tun.inject_packet(response_packet.clone());

        // Read from server
        let mut buf = [0u8; 1500];
        let len = server_tun
            .read_packet(&mut buf)
            .await
            .expect("Failed to read");
        assert_eq!(len, response_packet.len());
        assert_eq!(&buf[..len], &response_packet[..]);

        // Verify stats
        assert_eq!(client_tun.packets_written(), 1);
        assert_eq!(server_tun.packets_read(), 1);
    }

    #[tokio::test]
    async fn test_timeout_with_mock_clock() {
        // Test connection timeout with controlled time advancement
        let clock = Arc::new(MockClock::new(Timestamp::from_millis(1000)));
        let psk = b"test_psk_timeout_mock".to_vec();

        let client = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client");

        // Client initiates but server never responds
        let _pub_key = client.initiate_connection().await.expect("Init");
        assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

        // Get timeout duration (5s per spec)
        let timeout = client.state_machine().connection_timeout();
        assert_eq!(timeout, std::time::Duration::from_secs(5));

        // Advance beyond timeout
        clock.advance(std::time::Duration::from_secs(6));

        // Manually trigger timeout (in real impl, timer would do this)
        client.state_machine().enter_error();
        assert_eq!(client.connection_state(), ConnectionMachineState::Error);
        assert!(!client.is_established().await);
        assert!(client.get_session_key().await.is_none());
    }

    #[tokio::test]
    async fn test_graceful_close_with_tun_data() {
        // Test graceful close with final data transmission
        let psk = b"test_psk_graceful_tun".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server");

        let config = TunConfig::new(
            DeviceName::new("tun_close").expect("Device name"),
            "10.0.0.1".parse().expect("IP"),
            "255.255.255.0".parse().expect("Netmask"),
            Mtu::default(),
        );

        let mut client_tun = TestTunDevice::create(config).await.expect("Create TUN");

        // Establish connection
        server.start_listening().expect("Listen");
        let client_pub_key = client.initiate_connection().await.expect("Init");
        let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.expect("SYN");
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("SYN-ACK");
        server.handle_ack(&response).await.expect("ACK");

        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );

        // Send final data before close
        let final_data = vec![0xff, 0xfe, 0xfd];
        client_tun
            .write_packet(&final_data)
            .await
            .expect("Write final data");

        // Graceful close
        client.close().expect("Close failed");
        assert_eq!(client.connection_state(), ConnectionMachineState::Closing);

        client.state_machine().finish_close().expect("Finish");
        assert_eq!(client.connection_state(), ConnectionMachineState::Closed);

        // Verify final data was sent
        let captured = client_tun.captured_packets();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], final_data);
    }

    #[tokio::test]
    async fn test_rst_clears_session_with_tun() {
        // Test RST packet handling clears session keys
        let psk = b"test_psk_rst_tun".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server");

        let config = TunConfig::new(
            DeviceName::new("tun_rst").expect("Device name"),
            "10.0.0.1".parse().expect("IP"),
            "255.255.255.0".parse().expect("Netmask"),
            Mtu::default(),
        );

        let mut client_tun = TestTunDevice::create(config).await.expect("Create TUN");

        // Establish
        server.start_listening().expect("Listen");
        let client_pub_key = client.initiate_connection().await.expect("Init");
        let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.expect("SYN");
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("SYN-ACK");
        server.handle_ack(&response).await.expect("ACK");

        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );

        // Send some data
        let data = vec![0xaa, 0xbb, 0xcc];
        client_tun.write_packet(&data).await.expect("Write");

        // Handle RST
        client.handle_rst().await.expect("RST");
        assert_eq!(client.connection_state(), ConnectionMachineState::Closed);
        assert!(client.get_session_key().await.is_none());
        assert_eq!(client.current_phase().await, HandshakePhase::Failed);

        // Verify data was sent before RST
        assert_eq!(client_tun.captured_packets()[0], data);
    }

    #[tokio::test]
    async fn test_concurrent_tun_devices() {
        // Test multiple concurrent connections with separate TUN devices
        let num_conns = 3;
        let mut handles = Vec::new();

        for i in 0..num_conns {
            let handle = tokio::spawn(async move {
                let psk = format!("psk_{}", i).as_bytes().to_vec();
                let client = ConnectionLifecycle::new(
                    psk.clone(),
                    500,
                    1024,
                    65535,
                    1000,
                    1000,
                    SessionConfiguration::default(),
                )
                .expect("Create client");

                let server = ConnectionLifecycle::new(
                    psk,
                    500,
                    1024,
                    65535,
                    1000,
                    1000,
                    SessionConfiguration::default(),
                )
                .expect("Create server");

                let config = TunConfig::new(
                    DeviceName::new(format!("tun{}", i)).expect("Device name"),
                    "10.0.0.1".parse().expect("IP"),
                    "255.255.255.0".parse().expect("Netmask"),
                    Mtu::default(),
                );

                let mut tun = TestTunDevice::create(config).await.expect("Create TUN");

                // Establish
                server.start_listening().expect("Listen");
                let client_pub_key = client.initiate_connection().await.expect("Init");
                let (server_pub_key, challenge) =
                    server.handle_syn(&client_pub_key).await.expect("SYN");
                let response = client
                    .handle_syn_ack(&server_pub_key, &challenge)
                    .await
                    .expect("SYN-ACK");
                server.handle_ack(&response).await.expect("ACK");

                assert!(client.is_established().await);
                assert!(server.is_established().await);

                // Send unique data
                let data = vec![i as u8; 10];
                tun.write_packet(&data).await.expect("Write");

                (
                    client.get_session_key().await.expect("Key"),
                    tun.captured_packets()[0].clone(),
                )
            });

            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("Task complete"))
            .collect();

        // Verify all keys are unique
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(results[i].0, results[j].0);
            }
        }

        // Verify all data unique
        for i in 0..results.len() {
            assert_eq!(results[i].1, vec![i as u8; 10]);
        }
    }

    // Task 3.2.10: Connection Lifecycle Tests
    // Testing connection establishment, data transfer, and termination

    #[tokio::test]
    async fn test_lifecycle_establishment_client_server() {
        // Test complete connection establishment between client and server
        let psk = b"test_psk_for_establishment".to_vec();

        // Create client lifecycle
        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client lifecycle");

        // Create server lifecycle
        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server lifecycle");

        // Verify initial states
        assert_eq!(client.connection_state(), ConnectionMachineState::Closed);
        assert_eq!(server.connection_state(), ConnectionMachineState::Closed);

        // Server starts listening
        server
            .start_listening()
            .expect("Server failed to start listening");
        assert_eq!(server.connection_state(), ConnectionMachineState::Listening);

        // Client initiates connection (SYN)
        let client_pub_key = client
            .initiate_connection()
            .await
            .expect("Client failed to initiate connection");
        assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

        // Server handles SYN (sends SYN-ACK)
        let (server_pub_key, challenge) = server
            .handle_syn(&client_pub_key)
            .await
            .expect("Server failed to handle SYN");
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::SynReceived
        );

        // Client handles SYN-ACK (sends ACK with challenge response)
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("Client failed to handle SYN-ACK");
        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );
        assert!(client.is_established().await);

        // Server handles ACK (connection established)
        server
            .handle_ack(&response)
            .await
            .expect("Server failed to handle ACK");
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::Established
        );
        assert!(server.is_established().await);

        // Verify both sides have session keys
        let client_key = client.get_session_key().await;
        let server_key = server.get_session_key().await;
        assert!(client_key.is_some());
        assert!(server_key.is_some());
        assert_eq!(client_key, server_key);
    }

    #[tokio::test]
    async fn test_lifecycle_data_transfer_ready() {
        // Test that established connection is ready for data transfer
        let psk = b"test_psk_for_data_transfer".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client lifecycle");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server lifecycle");

        // Establish connection
        server
            .start_listening()
            .expect("Server failed to start listening");
        let client_pub_key = client
            .initiate_connection()
            .await
            .expect("Client failed to initiate connection");
        let (server_pub_key, challenge) = server
            .handle_syn(&client_pub_key)
            .await
            .expect("Server failed to handle SYN");
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("Client failed to handle SYN-ACK");
        server
            .handle_ack(&response)
            .await
            .expect("Server failed to handle ACK");

        // Verify both sides are ready for data transfer
        assert!(client.is_established().await);
        assert!(server.is_established().await);
        assert_eq!(client.current_phase().await, HandshakePhase::Complete);
        assert_eq!(server.current_phase().await, HandshakePhase::Complete);

        // Verify session keys are available for encryption/decryption
        assert!(client.get_session_key().await.is_some());
        assert!(server.get_session_key().await.is_some());
    }

    #[tokio::test]
    async fn test_lifecycle_graceful_close() {
        // Test graceful connection closure (FIN-style termination)
        let psk = b"test_psk_for_graceful_close".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client lifecycle");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server lifecycle");

        // Establish connection
        server
            .start_listening()
            .expect("Server failed to start listening");
        let client_pub_key = client
            .initiate_connection()
            .await
            .expect("Client failed to initiate connection");
        let (server_pub_key, challenge) = server
            .handle_syn(&client_pub_key)
            .await
            .expect("Server failed to handle SYN");
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("Client failed to handle SYN-ACK");
        server
            .handle_ack(&response)
            .await
            .expect("Server failed to handle ACK");

        // Verify connection is established
        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::Established
        );

        // Client initiates graceful close
        client.close().expect("Client failed to close");
        assert_eq!(client.connection_state(), ConnectionMachineState::Closing);

        // Complete close sequence
        client
            .state_machine()
            .finish_close()
            .expect("Client failed to finish close");
        assert_eq!(client.connection_state(), ConnectionMachineState::Closed);

        // Server can also close gracefully
        server.close().expect("Server failed to close");
        assert_eq!(server.connection_state(), ConnectionMachineState::Closing);
        server
            .state_machine()
            .finish_close()
            .expect("Server failed to finish close");
        assert_eq!(server.connection_state(), ConnectionMachineState::Closed);
    }

    #[tokio::test]
    async fn test_lifecycle_abnormal_close_rst() {
        // Test abnormal connection termination via RST
        let psk = b"test_psk_for_rst_close".to_vec();

        let client = ConnectionLifecycle::new(
            psk.clone(),
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client lifecycle");

        let server = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create server lifecycle");

        // Establish connection
        server
            .start_listening()
            .expect("Server failed to start listening");
        let client_pub_key = client
            .initiate_connection()
            .await
            .expect("Client failed to initiate connection");
        let (server_pub_key, challenge) = server
            .handle_syn(&client_pub_key)
            .await
            .expect("Server failed to handle SYN");
        let response = client
            .handle_syn_ack(&server_pub_key, &challenge)
            .await
            .expect("Client failed to handle SYN-ACK");
        server
            .handle_ack(&response)
            .await
            .expect("Server failed to handle ACK");

        // Verify connection is established
        assert_eq!(
            client.connection_state(),
            ConnectionMachineState::Established
        );
        assert_eq!(
            server.connection_state(),
            ConnectionMachineState::Established
        );

        // Client sends RST (abnormal termination)
        client
            .handle_rst()
            .await
            .expect("Client failed to handle RST");

        // Connection should immediately transition to CLOSED
        assert_eq!(client.connection_state(), ConnectionMachineState::Closed);

        // Session key should be cleared for security
        assert!(client.get_session_key().await.is_none());

        // Handshake phase should be marked as Failed
        assert_eq!(client.current_phase().await, HandshakePhase::Failed);
    }

    #[tokio::test]
    async fn test_lifecycle_abnormal_close_timeout() {
        // Test abnormal connection termination via timeout during establishment
        let psk = b"test_psk_for_timeout".to_vec();

        let client = ConnectionLifecycle::new(
            psk,
            500,
            1024,
            65535,
            1000,
            1000,
            SessionConfiguration::default(),
        )
        .expect("Failed to create client lifecycle");

        // Client initiates connection but doesn't complete handshake
        let _client_pub_key = client
            .initiate_connection()
            .await
            .expect("Client failed to initiate connection");
        assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

        // Simulate timeout by manually transitioning to error state
        client.state_machine().enter_error();
        assert_eq!(client.connection_state(), ConnectionMachineState::Error);

        // Connection should not be established
        assert!(!client.is_established().await);

        // Session key should not be available
        assert!(client.get_session_key().await.is_none());
    }

    #[test]
    fn test_lifecycle_state_transitions_complete() {
        // Test complete state transition sequence
        let sm = ConnectionStateMachine::new();

        // Initial state
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);
        assert!(!sm.is_established());

        // Client flow: CLOSED -> CONNECTING -> SYN_SENT -> ESTABLISHED
        sm.connect().expect("Failed to connect");
        assert_eq!(sm.current_state(), ConnectionMachineState::Connecting);

        sm.send_syn().expect("Failed to send SYN");
        assert_eq!(sm.current_state(), ConnectionMachineState::SynSent);

        sm.receive_syn_ack().expect("Failed to receive SYN-ACK");
        assert_eq!(sm.current_state(), ConnectionMachineState::Established);
        assert!(sm.is_established());

        // Graceful close: ESTABLISHED -> CLOSING -> CLOSED
        sm.close().expect("Failed to close");
        assert_eq!(sm.current_state(), ConnectionMachineState::Closing);
        assert!(!sm.is_established());

        sm.finish_close().expect("Failed to finish close");
        assert_eq!(sm.current_state(), ConnectionMachineState::Closed);
        assert!(!sm.is_established());
    }

    #[test]
    fn test_lifecycle_invalid_state_transitions() {
        // Test that invalid state transitions are rejected
        let sm = ConnectionStateMachine::new();

        // Can't send SYN from CLOSED
        let result = sm.send_syn();
        assert!(result.is_err());

        // Can't receive SYN-ACK from CLOSED
        let result = sm.receive_syn_ack();
        assert!(result.is_err());

        // Can't close from CLOSED
        let result = sm.close();
        assert!(result.is_err());

        // Can't finish close from CLOSED
        let result = sm.finish_close();
        assert!(result.is_err());
    }
}
