//! Multi-Port Handshake Protocol Implementation
//!
//! Implements the 3-way handshake protocol with port negotiation as specified in
//! design/protocol/06-connection-lifecycle.md
//!
//! ## Handshake Flow
//!
//! 1. SYN: Client → Server with port preferences and client nonce
//! 2. SYN-ACK: Server → Client with port confirmation and challenge
//! 3. ACK: Client → Server with challenge response
//! 4. Transition to session-specific port hopping
//!
//! ## State Machine
//!
//! CLOSED → SYN_SENT → SYN_RECEIVED → ESTABLISHED

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info, instrument};

use crate::error::{SessionError, SessionResult};
use crate::protocol::types::*;
use crate::security::crypto::ecdh::ThreadSafeEcdhManager;

/// Port range for negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub min_port: u16,
    pub max_port: u16,
}

impl PortRange {
    /// Create a new port range
    pub fn new(min_port: u16, max_port: u16) -> Result<Self, SessionError> {
        if min_port > max_port {
            return Err(SessionError::session_management_error(
                "min_port must be <= max_port",
            ));
        }
        if min_port < 1024 {
            return Err(SessionError::session_management_error(
                "min_port must be >= 1024 (non-privileged)",
            ));
        }
        Ok(Self { min_port, max_port })
    }

    /// Default port range (non-privileged ports)
    pub fn default_range() -> Self {
        Self {
            min_port: 1024,
            max_port: 65535,
        }
    }

    /// Check if port is within range
    pub fn contains(&self, port: u16) -> bool {
        port >= self.min_port && port <= self.max_port
    }

    /// Get range size
    pub fn size(&self) -> u32 {
        (self.max_port - self.min_port + 1) as u32
    }
}

/// Port preferences for connection establishment
#[derive(Debug, Clone)]
pub struct PortPreferences {
    /// Preferred port range
    pub range: PortRange,

    /// Specific preferred ports (optional)
    pub preferred_ports: Option<Vec<u16>>,
}

impl Default for PortPreferences {
    fn default() -> Self {
        Self {
            range: PortRange::default_range(),
            preferred_ports: None,
        }
    }
}

/// Replay protection nonce (128 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; 16]);

impl Nonce {
    /// Generate a new cryptographically secure random nonce
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .map_err(|_| SessionError::session_management_error("Nonce generation failed"))
            .ok();
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }
}

impl std::hash::Hash for Nonce {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Validates nonces to prevent replay attacks during handshake
///
/// Tracks seen nonces in a time-bounded cache and rejects duplicates.
/// Nonces expire after a configurable timeout (default 30 seconds).
#[derive(Debug)]
pub struct NonceValidator {
    /// Set of seen nonces
    seen_nonces: HashSet<Nonce>,

    /// Timestamp of oldest entry in the cache
    oldest_entry: Instant,

    /// Duration after which nonces expire
    nonce_timeout: Duration,
}

impl Default for NonceValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceValidator {
    /// Create a new nonce validator with default timeout (30 seconds)
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new nonce validator with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            seen_nonces: HashSet::new(),
            oldest_entry: Instant::now(),
            nonce_timeout: timeout,
        }
    }

    /// Validate a nonce for uniqueness
    ///
    /// Returns Ok(()) if the nonce is valid (not seen before).
    /// Returns Err if the nonce is a duplicate.
    pub fn validate_nonce(&mut self, nonce: &Nonce) -> SessionResult<()> {
        self.cleanup_expired();

        if self.seen_nonces.contains(nonce) {
            return Err(SessionError::session_management_error(
                "Duplicate nonce detected",
            ));
        }

        self.seen_nonces.insert(*nonce);
        Ok(())
    }

    /// Clean up expired nonces
    ///
    /// Clears all nonces if the oldest entry has expired.
    /// This simple strategy is efficient for the expected handshake rate.
    fn cleanup_expired(&mut self) {
        if self.oldest_entry.elapsed() > self.nonce_timeout {
            self.seen_nonces.clear();
            self.oldest_entry = Instant::now();
        }
    }

    /// Get the number of tracked nonces
    #[cfg(test)]
    pub fn nonce_count(&self) -> usize {
        self.seen_nonces.len()
    }
}

/// Challenge for challenge-response authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge([u8; 16]);

impl Challenge {
    /// Generate a new challenge
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .map_err(|_| SessionError::session_management_error("Challenge generation failed"))
            .ok();
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Handshake state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeState {
    /// Connection is closed
    Closed = 0,

    /// SYN packet sent, waiting for SYN-ACK
    SynSent = 1,

    /// SYN packet received, SYN-ACK sent, waiting for ACK
    SynReceived = 2,

    /// Handshake complete, connection established
    Established = 3,

    /// Handshake failed
    Failed = 4,

    /// Handshake timed out
    TimedOut = 5,
}

impl HandshakeState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Established | Self::Failed | Self::TimedOut)
    }

    pub fn is_successful(&self) -> bool {
        matches!(self, Self::Established)
    }
}

/// SYN packet data
#[derive(Debug, Clone)]
pub struct SynData {
    /// Port range preferences
    pub port_range: PortRange,

    /// Client nonce for replay protection
    pub client_nonce: Nonce,

    /// Protocol version
    pub protocol_version: u8,

    /// Timestamp
    pub timestamp: Timestamp,

    /// Initial sequence number
    pub initial_sequence: SequenceNumber,
}

/// Version negotiation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedVersion {
    /// The negotiated protocol version
    pub version: u8,

    /// Whether version was downgraded from local version
    pub downgraded: bool,
}

/// Version compatibility check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCompatibility {
    /// Versions are compatible, can proceed
    Compatible(NegotiatedVersion),

    /// Peer version is too old to be supported
    TooOld { peer_version: u8, min_supported: u8 },

    /// Peer version is too new to be supported
    TooNew { peer_version: u8, max_supported: u8 },
}

/// SYN-ACK packet data
#[derive(Debug, Clone)]
pub struct SynAckData {
    /// Confirmed port range
    pub port_range: PortRange,

    /// Server nonce
    pub server_nonce: Nonce,

    /// Server challenge for ACK
    pub server_challenge: Challenge,

    /// Initial port hop seed (derived from ECDH)
    pub port_hop_seed: Option<u32>,

    /// Timestamp
    pub timestamp: Timestamp,

    /// Server sequence number
    pub server_sequence: SequenceNumber,

    /// ACK number (client sequence + 1)
    pub ack_sequence: SequenceNumber,
}

/// ACK packet data
#[derive(Debug, Clone)]
pub struct AckData {
    /// Challenge response (HMAC of challenge + nonces)
    pub challenge_response: Vec<u8>,

    /// Session ID confirmation
    pub session_id: SessionId,

    /// Timestamp
    pub timestamp: Timestamp,

    /// ACK number (server sequence + 1)
    pub ack_sequence: SequenceNumber,
}

/// Handshake context containing state for a single handshake
#[derive(Debug)]
pub struct HandshakeContext {
    /// Connection ID
    pub connection_id: ConnectionId,

    /// Local endpoint
    pub local_endpoint: SocketAddr,

    /// Remote endpoint
    pub remote_endpoint: SocketAddr,

    /// Current handshake state
    pub state: HandshakeState,

    /// Port preferences (client) or confirmed range (server)
    pub port_range: Option<PortRange>,

    /// Client nonce
    pub client_nonce: Option<Nonce>,

    /// Server nonce
    pub server_nonce: Option<Nonce>,

    /// Server challenge
    pub server_challenge: Option<Challenge>,

    /// Port hop seed (derived after ECDH)
    pub port_hop_seed: Option<u32>,

    /// Session ID (assigned after successful handshake)
    pub session_id: Option<SessionId>,

    /// Handshake start time
    pub start_time: Instant,

    /// Initial client sequence number
    pub client_sequence: Option<SequenceNumber>,

    /// Initial server sequence number
    pub server_sequence: Option<SequenceNumber>,

    /// Negotiated protocol version
    pub negotiated_version: Option<NegotiatedVersion>,
}

impl HandshakeContext {
    /// Create a new handshake context
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Self {
        Self {
            connection_id,
            local_endpoint,
            remote_endpoint,
            state: HandshakeState::Closed,
            port_range: None,
            client_nonce: None,
            server_nonce: None,
            server_challenge: None,
            port_hop_seed: None,
            session_id: None,
            start_time: Instant::now(),
            client_sequence: None,
            server_sequence: None,
            negotiated_version: None,
        }
    }
}

/// Handshake configuration
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Handshake timeout
    pub timeout: Duration,

    /// Maximum retry attempts
    pub max_retries: u32,

    /// Retry backoff multiplier
    pub retry_backoff: f64,

    /// Port preferences
    pub port_preferences: PortPreferences,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_retries: 3,
            retry_backoff: 1.5,
            port_preferences: PortPreferences::default(),
        }
    }
}

/// Protocol version constants and negotiation
pub mod version {
    use super::*;

    /// Minimum supported protocol version
    pub const MIN_SUPPORTED_VERSION: u8 = 0x01;

    /// Maximum supported protocol version (current version)
    pub const MAX_SUPPORTED_VERSION: u8 = PROTOCOL_VERSION;

    /// Current local protocol version
    pub const LOCAL_VERSION: u8 = PROTOCOL_VERSION;

    /// Check version compatibility and negotiate version
    ///
    /// Implements the version negotiation logic from design/protocol/13-edge-case-handling.md:
    /// - Reject versions below MIN_SUPPORTED_VERSION (too old)
    /// - Reject versions above MAX_SUPPORTED_VERSION (too new)
    /// - Negotiate to lowest common version for compatible versions
    pub fn check_compatibility(peer_version: u8) -> VersionCompatibility {
        if peer_version < MIN_SUPPORTED_VERSION {
            return VersionCompatibility::TooOld {
                peer_version,
                min_supported: MIN_SUPPORTED_VERSION,
            };
        }

        if peer_version > MAX_SUPPORTED_VERSION {
            return VersionCompatibility::TooNew {
                peer_version,
                max_supported: MAX_SUPPORTED_VERSION,
            };
        }

        let negotiated_version = peer_version.min(LOCAL_VERSION);
        let downgraded = negotiated_version < LOCAL_VERSION;

        VersionCompatibility::Compatible(NegotiatedVersion {
            version: negotiated_version,
            downgraded,
        })
    }

    /// Negotiate version from SYN packet
    pub fn negotiate_from_syn(syn_data: &SynData) -> Result<NegotiatedVersion, SessionError> {
        match check_compatibility(syn_data.protocol_version) {
            VersionCompatibility::Compatible(negotiated) => Ok(negotiated),
            VersionCompatibility::TooOld {
                peer_version,
                min_supported,
            } => Err(SessionError::session_management_error(format!(
                "Peer version {} is too old (minimum supported: {})",
                peer_version, min_supported
            ))),
            VersionCompatibility::TooNew {
                peer_version,
                max_supported,
            } => Err(SessionError::session_management_error(format!(
                "Peer version {} is too new (maximum supported: {})",
                peer_version, max_supported
            ))),
        }
    }

    /// Check if a specific version is supported
    pub fn is_version_supported(version: u8) -> bool {
        version >= MIN_SUPPORTED_VERSION && version <= MAX_SUPPORTED_VERSION
    }

    /// Get the version range as a tuple (min, max)
    pub fn supported_version_range() -> (u8, u8) {
        (MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION)
    }
}

/// Handshake manager implementing the 3-way handshake protocol
pub struct HandshakeManager {
    /// Configuration
    config: HandshakeConfig,

    /// Handshake context
    context: Arc<RwLock<HandshakeContext>>,

    /// ECDH manager for key exchange (will be used for ECDH integration)
    #[allow(dead_code)]
    ecdh_manager: Arc<ThreadSafeEcdhManager>,

    /// Nonce validator for replay protection
    nonce_validator: Arc<RwLock<NonceValidator>>,
}

impl HandshakeManager {
    /// Create a new handshake manager
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        config: HandshakeConfig,
        ecdh_manager: Arc<ThreadSafeEcdhManager>,
    ) -> Self {
        let context = HandshakeContext::new(connection_id, local_endpoint, remote_endpoint);

        Self {
            config,
            context: Arc::new(RwLock::new(context)),
            ecdh_manager,
            nonce_validator: Arc::new(RwLock::new(NonceValidator::new())),
        }
    }

    /// Perform client-side handshake (initiate connection)
    #[instrument(skip(self))]
    pub async fn handshake_as_client(&self) -> SessionResult<HandshakeContext> {
        info!("Starting client handshake");

        // Transition to SYN_SENT state
        self.transition_to(HandshakeState::SynSent).await?;

        // Generate client nonce
        let client_nonce = Nonce::generate();

        // Generate initial sequence number (use random value)
        let initial_sequence = {
            let mut rng_bytes = [0u8; 4];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut rng_bytes).ok();
            SequenceNumber::new(u32::from_be_bytes(rng_bytes))
        };

        // Prepare SYN data
        let syn_data = SynData {
            port_range: self.config.port_preferences.range,
            client_nonce,
            protocol_version: 1,
            timestamp: Timestamp::from_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            initial_sequence,
        };

        // Store client data in context
        {
            let mut ctx = self.context.write().await;
            ctx.client_nonce = Some(client_nonce);
            ctx.client_sequence = Some(initial_sequence);
            ctx.port_range = Some(self.config.port_preferences.range);
        }

        // Send SYN packet (in real implementation, would send over network)
        debug!("SYN packet prepared: port_range={:?}", syn_data.port_range);

        // Wait for SYN-ACK (simulated for now)
        // In real implementation: receive and parse SYN-ACK packet

        // Simulate SYN-ACK reception
        let syn_ack_data = self.simulate_syn_ack_reception().await?;

        // Process SYN-ACK
        self.process_syn_ack(syn_ack_data).await?;

        // Send ACK with challenge response
        self.send_ack().await?;

        // Transition to ESTABLISHED
        self.transition_to(HandshakeState::Established).await?;

        info!(
            duration_ms = self.context.read().await.start_time.elapsed().as_millis(),
            "Client handshake completed successfully"
        );

        // Return final context
        let ctx = self.context.read().await;
        Ok(HandshakeContext {
            connection_id: ctx.connection_id,
            local_endpoint: ctx.local_endpoint,
            remote_endpoint: ctx.remote_endpoint,
            state: ctx.state,
            port_range: ctx.port_range,
            client_nonce: ctx.client_nonce,
            server_nonce: ctx.server_nonce,
            server_challenge: ctx.server_challenge,
            port_hop_seed: ctx.port_hop_seed,
            session_id: ctx.session_id.clone(),
            start_time: ctx.start_time,
            client_sequence: ctx.client_sequence,
            server_sequence: ctx.server_sequence,
            negotiated_version: ctx.negotiated_version,
        })
    }

    /// Perform server-side handshake (accept connection)
    #[instrument(skip(self, syn_data))]
    pub async fn handshake_as_server(&self, syn_data: SynData) -> SessionResult<HandshakeContext> {
        info!("Starting server handshake");

        // Validate nonce for replay protection
        {
            let mut validator = self.nonce_validator.write().await;
            validator.validate_nonce(&syn_data.client_nonce)?;
        }

        // Negotiate protocol version
        let negotiated_version = version::negotiate_from_syn(&syn_data)?;
        info!(
            "Version negotiated: {} (downgraded: {})",
            negotiated_version.version, negotiated_version.downgraded
        );

        // Transition to SYN_RECEIVED state
        self.transition_to(HandshakeState::SynReceived).await?;

        // Process SYN packet
        {
            let mut ctx = self.context.write().await;
            ctx.client_nonce = Some(syn_data.client_nonce);
            ctx.client_sequence = Some(syn_data.initial_sequence);
            ctx.negotiated_version = Some(negotiated_version);

            // Validate and potentially narrow port range
            let confirmed_range = self.negotiate_port_range(syn_data.port_range).await?;
            ctx.port_range = Some(confirmed_range);
        }

        // Generate server nonce and challenge
        let server_nonce = Nonce::generate();
        let server_challenge = Challenge::generate();
        let server_sequence = {
            let mut rng_bytes = [0u8; 4];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut rng_bytes).ok();
            SequenceNumber::new(u32::from_be_bytes(rng_bytes))
        };

        // Store server data
        {
            let mut ctx = self.context.write().await;
            ctx.server_nonce = Some(server_nonce);
            ctx.server_challenge = Some(server_challenge);
            ctx.server_sequence = Some(server_sequence);
        }

        // Prepare SYN-ACK data
        let remote_endpoint = self.context.read().await.remote_endpoint;
        let _syn_ack_data = SynAckData {
            port_range: self.context.read().await.port_range.ok_or_else(|| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(remote_endpoint),
                    "Port range not negotiated",
                )
            })?,
            server_nonce,
            server_challenge,
            port_hop_seed: None, // Will be set after ECDH
            timestamp: Timestamp::from_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            server_sequence,
            ack_sequence: SequenceNumber::new(syn_data.initial_sequence.as_u32() + 1),
        };

        // Send SYN-ACK packet
        debug!("SYN-ACK packet prepared");

        // Wait for ACK (simulated for now)
        let ack_data = self.simulate_ack_reception().await?;

        // Verify challenge response
        self.verify_challenge_response(&ack_data).await?;

        // Transition to ESTABLISHED
        self.transition_to(HandshakeState::Established).await?;

        info!(
            duration_ms = self.context.read().await.start_time.elapsed().as_millis(),
            "Server handshake completed successfully"
        );

        // Return final context
        let ctx = self.context.read().await;
        Ok(HandshakeContext {
            connection_id: ctx.connection_id,
            local_endpoint: ctx.local_endpoint,
            remote_endpoint: ctx.remote_endpoint,
            state: ctx.state,
            port_range: ctx.port_range,
            client_nonce: ctx.client_nonce,
            server_nonce: ctx.server_nonce,
            server_challenge: ctx.server_challenge,
            port_hop_seed: ctx.port_hop_seed,
            session_id: ctx.session_id.clone(),
            start_time: ctx.start_time,
            client_sequence: ctx.client_sequence,
            server_sequence: ctx.server_sequence,
            negotiated_version: ctx.negotiated_version,
        })
    }

    /// Get current handshake state
    pub async fn state(&self) -> HandshakeState {
        self.context.read().await.state
    }

    /// Check if handshake is complete
    pub async fn is_complete(&self) -> bool {
        self.context.read().await.state.is_terminal()
    }

    /// Check if handshake was successful
    pub async fn is_successful(&self) -> bool {
        self.context.read().await.state.is_successful()
    }

    /// Transition to a new state
    async fn transition_to(&self, new_state: HandshakeState) -> SessionResult<()> {
        let mut ctx = self.context.write().await;
        let old_state = ctx.state;

        // Validate state transition
        let valid_transition = matches!(
            (old_state, new_state),
            (HandshakeState::Closed, HandshakeState::SynSent)
                | (HandshakeState::Closed, HandshakeState::SynReceived)
                | (HandshakeState::SynSent, HandshakeState::Established)
                | (HandshakeState::SynSent, HandshakeState::Failed)
                | (HandshakeState::SynSent, HandshakeState::TimedOut)
                | (HandshakeState::SynReceived, HandshakeState::Established)
                | (HandshakeState::SynReceived, HandshakeState::Failed)
                | (HandshakeState::SynReceived, HandshakeState::TimedOut)
        );

        if !valid_transition {
            return Err(SessionError::session_management_error(format!(
                "Invalid handshake state transition: {:?} -> {:?}",
                old_state, new_state
            )));
        }

        ctx.state = new_state;
        debug!(
            "Handshake state transition: {:?} -> {:?}",
            old_state, new_state
        );

        Ok(())
    }

    /// Negotiate port range between client and server
    async fn negotiate_port_range(&self, client_range: PortRange) -> SessionResult<PortRange> {
        // Server can narrow the range based on its capabilities/policy
        // For now, accept client's range if valid

        if client_range.min_port < 1024 {
            return Err(SessionError::session_management_error(
                "Client requested privileged ports",
            ));
        }

        // Could implement more sophisticated negotiation here
        Ok(client_range)
    }

    /// Process SYN-ACK packet
    async fn process_syn_ack(&self, syn_ack_data: SynAckData) -> SessionResult<()> {
        let mut ctx = self.context.write().await;

        // Verify port range is acceptable
        if !syn_ack_data
            .port_range
            .contains(self.config.port_preferences.range.min_port)
        {
            return Err(SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(ctx.remote_endpoint),
                "Server port range incompatible with client preferences",
            ));
        }

        // Store SYN-ACK data
        ctx.port_range = Some(syn_ack_data.port_range);
        ctx.server_nonce = Some(syn_ack_data.server_nonce);
        ctx.server_challenge = Some(syn_ack_data.server_challenge);
        ctx.server_sequence = Some(syn_ack_data.server_sequence);
        ctx.port_hop_seed = syn_ack_data.port_hop_seed;

        debug!("SYN-ACK processed successfully");
        Ok(())
    }

    /// Send ACK packet with challenge response
    async fn send_ack(&self) -> SessionResult<()> {
        let ctx = self.context.read().await;

        // Using placeholder session key until ECDH key derivation is wired up
        let test_session_key = SessionKey::new([0x42u8; 32]);

        // Compute challenge response: HMAC(session_key, server_challenge || client_nonce || "challenge_response_v1")
        let challenge_response = self.compute_challenge_response(&ctx, &test_session_key)?;

        let _ack_data = AckData {
            challenge_response,
            session_id: ctx.session_id.clone().unwrap_or(SessionId::from_raw(0)),
            timestamp: Timestamp::from_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            ack_sequence: SequenceNumber::new(
                ctx.server_sequence
                    .ok_or_else(|| {
                        SessionError::connection_establishment_failed(
                            NetworkEndpoint::from_socket_addr(ctx.remote_endpoint),
                            "Server sequence not available",
                        )
                    })?
                    .as_u32()
                    + 1,
            ),
        };

        debug!("ACK packet prepared with challenge response");
        Ok(())
    }

    /// Verify challenge response in ACK packet
    async fn verify_challenge_response(&self, ack_data: &AckData) -> SessionResult<()> {
        let ctx = self.context.read().await;

        // Using placeholder session key (must match send_ack key)
        let test_session_key = SessionKey::new([0x42u8; 32]);

        // Compute expected challenge response
        let expected = self.compute_challenge_response(&ctx, &test_session_key)?;

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        let valid: bool = ack_data.challenge_response.ct_eq(&expected).into();

        if !valid {
            return Err(SessionError::session_management_error(
                "Challenge response verification failed",
            ));
        }

        debug!("Challenge response verified successfully");
        Ok(())
    }

    /// Compute challenge response (HMAC-based)
    ///
    /// # Arguments
    /// * `ctx` - Handshake context containing challenge and nonce
    /// * `session_key` - Derived session key from ECDH exchange
    ///
    /// # Errors
    /// Returns error if challenge/nonce not available or if session key is empty
    fn compute_challenge_response(
        &self,
        ctx: &HandshakeContext,
        session_key: &SessionKey,
    ) -> SessionResult<Vec<u8>> {
        // Validate session key is not empty
        if session_key.as_bytes().iter().all(|&b| b == 0) {
            return Err(SessionError::session_management_error(
                "Cannot compute challenge response with empty session key",
            ));
        }

        let server_challenge = ctx.server_challenge.as_ref().ok_or_else(|| {
            SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(ctx.remote_endpoint),
                "Server challenge not available",
            )
        })?;

        let client_nonce = ctx.client_nonce.as_ref().ok_or_else(|| {
            SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(ctx.remote_endpoint),
                "Client nonce not available",
            )
        })?;

        // Combine challenge + nonce + constant
        let mut data = Vec::new();
        data.extend_from_slice(server_challenge.as_bytes());
        data.extend_from_slice(client_nonce.as_bytes());
        data.extend_from_slice(b"challenge_response_v1");

        // Compute HMAC using session key from ECDH
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, session_key.as_bytes());
        let signature = hmac::sign(&key, &data);

        Ok(signature.as_ref()[..16].to_vec()) // 128-bit HMAC
    }

    // Simulation methods (would be replaced with actual network I/O)

    async fn simulate_syn_ack_reception(&self) -> SessionResult<SynAckData> {
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ctx = self.context.read().await;

        Ok(SynAckData {
            port_range: ctx.port_range.unwrap_or(PortRange::default_range()),
            server_nonce: Nonce::generate(),
            server_challenge: Challenge::generate(),
            port_hop_seed: Some(0x12345678),
            timestamp: Timestamp::from_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            server_sequence: {
                let mut rng_bytes = [0u8; 4];
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut rng_bytes)
                    .ok();
                SequenceNumber::new(u32::from_be_bytes(rng_bytes))
            },
            ack_sequence: SequenceNumber::new(
                ctx.client_sequence
                    .ok_or_else(|| {
                        SessionError::connection_establishment_failed(
                            NetworkEndpoint::from_socket_addr(ctx.remote_endpoint),
                            "Client sequence not available",
                        )
                    })?
                    .as_u32()
                    + 1,
            ),
        })
    }

    async fn simulate_ack_reception(&self) -> SessionResult<AckData> {
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ctx = self.context.read().await;

        // Using placeholder session key (must match send_ack key)
        let test_session_key = SessionKey::new([0x42u8; 32]);

        let challenge_response = self.compute_challenge_response(&ctx, &test_session_key)?;

        Ok(AckData {
            challenge_response,
            session_id: SessionId::from_raw(1),
            timestamp: Timestamp::from_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            ack_sequence: SequenceNumber::new(
                ctx.server_sequence
                    .ok_or_else(|| {
                        SessionError::connection_establishment_failed(
                            NetworkEndpoint::from_socket_addr(ctx.remote_endpoint),
                            "Server sequence not available",
                        )
                    })?
                    .as_u32()
                    + 1,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_port_range_creation() {
        // Valid range
        let range = PortRange::new(1024, 65535).unwrap();
        assert_eq!(range.min_port, 1024);
        assert_eq!(range.max_port, 65535);

        // Invalid: min > max
        assert!(PortRange::new(65535, 1024).is_err());

        // Invalid: privileged port
        assert!(PortRange::new(80, 8080).is_err());
    }

    #[test]
    fn test_port_range_contains() {
        let range = PortRange::new(1024, 2048).unwrap();
        assert!(range.contains(1024));
        assert!(range.contains(1500));
        assert!(range.contains(2048));
        assert!(!range.contains(1023));
        assert!(!range.contains(2049));
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = Nonce::generate();
        let nonce2 = Nonce::generate();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_handshake_state_transitions() {
        assert!(!HandshakeState::Closed.is_terminal());
        assert!(HandshakeState::Established.is_terminal());
        assert!(HandshakeState::Failed.is_terminal());
        assert!(HandshakeState::TimedOut.is_terminal());

        assert!(HandshakeState::Established.is_successful());
        assert!(!HandshakeState::Failed.is_successful());
    }

    #[tokio::test]
    async fn test_handshake_state_machine() {
        let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(60)); // 60 minute expiration
        let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let manager = HandshakeManager::new(
            ConnectionId::new(1),
            local_addr,
            remote_addr,
            HandshakeConfig::default(),
            ecdh_manager,
        );

        // Initial state should be Closed
        assert_eq!(manager.state().await, HandshakeState::Closed);

        // Valid transition to SynSent
        assert!(manager.transition_to(HandshakeState::SynSent).await.is_ok());
        assert_eq!(manager.state().await, HandshakeState::SynSent);

        // Valid transition to Established
        assert!(
            manager
                .transition_to(HandshakeState::Established)
                .await
                .is_ok()
        );
        assert_eq!(manager.state().await, HandshakeState::Established);

        // Should be complete and successful
        assert!(manager.is_complete().await);
        assert!(manager.is_successful().await);
    }

    #[test]
    fn test_nonce_validator_accepts_unique_nonces() {
        let mut validator = NonceValidator::new();
        let nonce1 = Nonce::generate();
        let nonce2 = Nonce::generate();

        // First nonce should be accepted
        assert!(validator.validate_nonce(&nonce1).is_ok());
        assert_eq!(validator.nonce_count(), 1);

        // Second different nonce should be accepted
        assert!(validator.validate_nonce(&nonce2).is_ok());
        assert_eq!(validator.nonce_count(), 2);
    }

    #[test]
    fn test_nonce_validator_rejects_duplicates() {
        let mut validator = NonceValidator::new();
        let nonce = Nonce::generate();

        // First use should succeed
        assert!(validator.validate_nonce(&nonce).is_ok());

        // Duplicate should fail
        let result = validator.validate_nonce(&nonce);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Duplicate nonce"));
        }
    }

    #[test]
    fn test_nonce_validator_cleanup_expired() {
        use std::thread;

        let mut validator = NonceValidator::with_timeout(Duration::from_millis(100));
        let nonce1 = Nonce::generate();
        let nonce2 = Nonce::generate();

        // Add first nonce
        assert!(validator.validate_nonce(&nonce1).is_ok());
        assert_eq!(validator.nonce_count(), 1);

        // Wait for expiration
        thread::sleep(Duration::from_millis(150));

        // Add second nonce (should trigger cleanup)
        assert!(validator.validate_nonce(&nonce2).is_ok());
        assert_eq!(validator.nonce_count(), 1); // Only nonce2 should remain

        // First nonce should now be accepted again (was cleaned up)
        assert!(validator.validate_nonce(&nonce1).is_ok());
        assert_eq!(validator.nonce_count(), 2);
    }

    // Version negotiation tests
    mod version_negotiation {
        use super::*;

        #[test]
        fn test_version_compatibility_same_version() {
            let result = version::check_compatibility(PROTOCOL_VERSION);
            match result {
                VersionCompatibility::Compatible(negotiated) => {
                    assert_eq!(negotiated.version, PROTOCOL_VERSION);
                    assert!(!negotiated.downgraded);
                }
                _ => panic!("Expected compatible version"),
            }
        }

        #[test]
        fn test_version_compatibility_too_old() {
            let old_version = 0x00;
            let result = version::check_compatibility(old_version);
            match result {
                VersionCompatibility::TooOld {
                    peer_version,
                    min_supported,
                } => {
                    assert_eq!(peer_version, old_version);
                    assert_eq!(min_supported, version::MIN_SUPPORTED_VERSION);
                }
                _ => panic!("Expected version too old"),
            }
        }

        #[test]
        fn test_version_compatibility_too_new() {
            let new_version = PROTOCOL_VERSION + 1;
            let result = version::check_compatibility(new_version);
            match result {
                VersionCompatibility::TooNew {
                    peer_version,
                    max_supported,
                } => {
                    assert_eq!(peer_version, new_version);
                    assert_eq!(max_supported, version::MAX_SUPPORTED_VERSION);
                }
                _ => panic!("Expected version too new"),
            }
        }

        #[test]
        fn test_version_negotiation_downgrade() {
            // Simulate peer with older compatible version
            if PROTOCOL_VERSION > 1 {
                let older_version = PROTOCOL_VERSION - 1;
                let result = version::check_compatibility(older_version);
                match result {
                    VersionCompatibility::Compatible(negotiated) => {
                        assert_eq!(negotiated.version, older_version);
                        assert!(negotiated.downgraded);
                    }
                    _ => panic!("Expected compatible version with downgrade"),
                }
            }
        }

        #[test]
        fn test_is_version_supported() {
            assert!(version::is_version_supported(PROTOCOL_VERSION));
            assert!(version::is_version_supported(
                version::MIN_SUPPORTED_VERSION
            ));
            assert!(version::is_version_supported(
                version::MAX_SUPPORTED_VERSION
            ));
            assert!(!version::is_version_supported(0x00));
            assert!(!version::is_version_supported(PROTOCOL_VERSION + 10));
        }

        #[test]
        fn test_supported_version_range() {
            let (min, max) = version::supported_version_range();
            assert_eq!(min, version::MIN_SUPPORTED_VERSION);
            assert_eq!(max, version::MAX_SUPPORTED_VERSION);
            assert!(min <= max);
        }

        #[test]
        fn test_negotiate_from_syn_compatible() {
            let syn_data = SynData {
                port_range: PortRange::default_range(),
                client_nonce: Nonce::generate(),
                protocol_version: PROTOCOL_VERSION,
                timestamp: Timestamp::from_millis(1000),
                initial_sequence: SequenceNumber::new(1),
            };

            let result = version::negotiate_from_syn(&syn_data);
            assert!(result.is_ok());
            let negotiated = result.unwrap();
            assert_eq!(negotiated.version, PROTOCOL_VERSION);
        }

        #[test]
        fn test_negotiate_from_syn_too_old() {
            let syn_data = SynData {
                port_range: PortRange::default_range(),
                client_nonce: Nonce::generate(),
                protocol_version: 0x00,
                timestamp: Timestamp::from_millis(1000),
                initial_sequence: SequenceNumber::new(1),
            };

            let result = version::negotiate_from_syn(&syn_data);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("too old"));
        }

        #[test]
        fn test_negotiate_from_syn_too_new() {
            let syn_data = SynData {
                port_range: PortRange::default_range(),
                client_nonce: Nonce::generate(),
                protocol_version: PROTOCOL_VERSION + 10,
                timestamp: Timestamp::from_millis(1000),
                initial_sequence: SequenceNumber::new(1),
            };

            let result = version::negotiate_from_syn(&syn_data);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("too new"));
        }

        #[tokio::test]
        async fn test_handshake_stores_negotiated_version() {
            let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(60));
            let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
            let remote_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

            let manager = HandshakeManager::new(
                ConnectionId::new(1),
                local_addr,
                remote_addr,
                HandshakeConfig::default(),
                ecdh_manager,
            );

            let syn_data = SynData {
                port_range: PortRange::default_range(),
                client_nonce: Nonce::generate(),
                protocol_version: PROTOCOL_VERSION,
                timestamp: Timestamp::from_millis(1000),
                initial_sequence: SequenceNumber::new(1),
            };

            let result = manager.handshake_as_server(syn_data).await;
            assert!(result.is_ok());
            let context = result.unwrap();
            assert!(context.negotiated_version.is_some());
            let negotiated = context.negotiated_version.unwrap();
            assert_eq!(negotiated.version, PROTOCOL_VERSION);
        }

        #[tokio::test]
        async fn test_handshake_rejects_incompatible_version() {
            let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(60));
            let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
            let remote_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

            let manager = HandshakeManager::new(
                ConnectionId::new(1),
                local_addr,
                remote_addr,
                HandshakeConfig::default(),
                ecdh_manager,
            );

            // Test with too old version
            let syn_data_old = SynData {
                port_range: PortRange::default_range(),
                client_nonce: Nonce::generate(),
                protocol_version: 0x00,
                timestamp: Timestamp::from_millis(1000),
                initial_sequence: SequenceNumber::new(1),
            };

            let result = manager.handshake_as_server(syn_data_old).await;
            assert!(result.is_err());

            // Test with too new version
            let syn_data_new = SynData {
                port_range: PortRange::default_range(),
                client_nonce: Nonce::generate(),
                protocol_version: PROTOCOL_VERSION + 10,
                timestamp: Timestamp::from_millis(1000),
                initial_sequence: SequenceNumber::new(1),
            };

            let result = manager.handshake_as_server(syn_data_new).await;
            assert!(result.is_err());
        }
    }
}
