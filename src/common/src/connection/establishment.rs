// Connection Establishment - handles connection setup and handshake
//
// This implements connection establishment including handshake protocols,
// authentication, key exchange, and initial session setup.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::net::SocketAddr;
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, instrument};

use crate::error::{SessionError, SessionResult};
use crate::protocol::packet::Packet;
use crate::protocol::packet::builder::PacketBuilderEngine;
use crate::protocol::types::SessionKey;
use crate::protocol::types::*;
use crate::protocol::types::{EcdhPrivateKey, EcdhPublicKey, SharedSecret};
use crate::security::crypto::ecdh::ThreadSafeEcdhManager;
use crate::security::crypto::hmac::HmacCalculator;

// Use consolidated types
use crate::protocol::types::{ConnectionId, Counter, NetworkEndpoint, SyncState, Timeout};

// Fallback socket address for error reporting when actual address unavailable
const FALLBACK_SOCKET_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);

/// Connection establishment state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstablishmentState {
    /// Initial state
    Initial = 0,

    /// Sending SYN packet
    SynSent = 1,

    /// Received SYN, sending SYN-ACK
    SynReceived = 2,

    /// Performing key exchange
    KeyExchange = 3,

    /// Authenticating
    Authenticating = 4,

    /// Finalizing connection
    Finalizing = 5,

    /// Connection established
    Established = 6,

    /// Connection failed
    Failed = 7,

    /// Connection timeout
    Timeout = 8,
}

impl EstablishmentState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Initial),
            1 => Some(Self::SynSent),
            2 => Some(Self::SynReceived),
            3 => Some(Self::KeyExchange),
            4 => Some(Self::Authenticating),
            5 => Some(Self::Finalizing),
            6 => Some(Self::Established),
            7 => Some(Self::Failed),
            8 => Some(Self::Timeout),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Store to atomic storage
    pub fn store(&self, atomic: &SyncState, ordering: std::sync::atomic::Ordering) {
        atomic.store(self.as_u8(), ordering);
    }

    /// Load from atomic storage
    pub fn load(atomic: &SyncState, ordering: std::sync::atomic::Ordering) -> Self {
        Self::from_u8(atomic.load(ordering)).unwrap_or(Self::Failed)
    }

    /// Check if this state is terminal
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Established | Self::Failed | Self::Timeout)
    }

    /// Check if this state indicates success
    pub fn is_successful(&self) -> bool {
        matches!(self, Self::Established)
    }
}

/// Connection establishment configuration
#[derive(Debug, Clone)]
pub struct EstablishmentConfig {
    /// Connection timeout
    pub connection_timeout: Timeout,

    /// Handshake timeout
    pub handshake_timeout: Timeout,

    /// Key exchange timeout
    pub key_exchange_timeout: Timeout,

    /// Authentication timeout
    pub authentication_timeout: Timeout,

    /// Maximum retry attempts
    pub max_retry_attempts: MaxRetries,

    /// Retry delay
    pub retry_delay: Timeout,

    /// Enable mutual authentication
    pub enable_mutual_auth: bool,

    /// Enable perfect forward secrecy
    pub enable_pfs: bool,

    /// Default HMAC policy for connection establishment
    pub hmac_policy: HmacPolicy,
}

impl Default for EstablishmentConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Timeout::from_millis(30_000), // 30 seconds
            handshake_timeout: Timeout::from_millis(10_000),  // 10 seconds
            key_exchange_timeout: Timeout::from_millis(5_000), // 5 seconds
            authentication_timeout: Timeout::from_millis(5_000), // 5 seconds
            max_retry_attempts: MaxRetries::new(3),
            retry_delay: Timeout::from_millis(1_000), // 1 second
            enable_mutual_auth: true,
            enable_pfs: true,
            hmac_policy: HmacPolicy::Medium,
        }
    }
}

/// Connection establishment context
#[derive(Debug)]
pub struct EstablishmentContext {
    /// Connection ID
    pub connection_id: ConnectionId,

    /// Local endpoint
    pub local_endpoint: SocketAddr,

    /// Remote endpoint
    pub remote_endpoint: SocketAddr,

    /// Local ECDH key pair
    pub local_keypair: Option<(EcdhPrivateKey, EcdhPublicKey)>,

    /// Remote ECDH public key
    pub remote_public_key: Option<EcdhPublicKey>,

    /// Shared secret
    pub shared_secret: Option<SharedSecret>,

    /// Session key
    pub session_key: Option<Arc<SessionKey>>,

    /// Challenge nonce
    pub challenge_nonce: Option<Vec<u8>>,

    /// Response nonce
    pub response_nonce: Option<Vec<u8>>,

    /// Authentication token
    pub auth_token: Option<Vec<u8>>,
}

impl EstablishmentContext {
    /// Create a new establishment context
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Self {
        Self {
            connection_id,
            local_endpoint,
            remote_endpoint,
            local_keypair: None,
            remote_public_key: None,
            shared_secret: None,
            session_key: None,
            challenge_nonce: None,
            response_nonce: None,
            auth_token: None,
        }
    }
}

/// Connection establishment statistics
#[derive(Debug, Default, Clone)]
pub struct EstablishmentStats {
    pub attempts_started: Counter,
    pub attempts_completed: Counter,
    pub attempts_failed: Counter,
    pub attempts_timeout: Counter,
    pub handshakes_completed: Counter,
    pub key_exchanges_completed: Counter,
    pub authentications_completed: Counter,
    pub average_establishment_time: Timeout,
    pub last_establishment_time: Timeout,
}

/// Connection Establishment - handles connection setup and handshake
pub struct ConnectionEstablishment {
    /// Configuration
    config: EstablishmentConfig,

    /// Current state
    state: SyncState,

    /// Establishment context
    context: RwLock<EstablishmentContext>,

    /// Start time
    start_time: Instant,

    /// Statistics
    stats: RwLock<EstablishmentStats>,

    /// Timeout handle
    timeout_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// ECDH manager for key generation and agreement
    ecdh_manager: Arc<ThreadSafeEcdhManager>,
}

impl ConnectionEstablishment {
    /// Create a new connection establishment
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        config: EstablishmentConfig,
        ecdh_manager: Arc<ThreadSafeEcdhManager>,
    ) -> Self {
        let context = EstablishmentContext::new(connection_id, local_endpoint, remote_endpoint);

        Self {
            config,
            state: SyncState::new(EstablishmentState::Initial.as_u8()),
            context: RwLock::new(context),
            start_time: Instant::now(),
            stats: RwLock::new(EstablishmentStats::default()),
            timeout_handle: Mutex::new(None),
            ecdh_manager,
        }
    }

    /// Start connection establishment as client
    #[instrument(skip(self))]
    pub async fn establish_as_client(&self) -> SessionResult<EstablishmentContext> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.attempts_started += 1;
        }

        // Start timeout task to abort establishment if it takes too long
        self.start_timeout_task().await;

        // Transition to SynSent state
        self.transition_to_state(EstablishmentState::SynSent)
            .await?;

        // Generate local key pair
        self.generate_local_keypair().await?;

        // Send SYN packet
        self.send_syn_packet().await?;

        // Wait for SYN-ACK
        self.wait_for_syn_ack().await?;

        // Perform key exchange
        self.perform_key_exchange().await?;

        // Authenticate
        if self.config.enable_mutual_auth {
            self.perform_authentication().await?;
        }

        // Finalize connection
        self.finalize_connection().await?;

        // Transition to established state
        self.transition_to_state(EstablishmentState::Established)
            .await?;

        // Stop timeout
        self.stop_timeout().await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.attempts_completed += 1;
            stats.handshakes_completed += 1;

            let establishment_time = self.start_time.elapsed().as_millis() as u64;
            stats.last_establishment_time = Timeout::from_millis(establishment_time);

            // Update average (simple moving average)
            if stats.attempts_completed == 1 {
                stats.average_establishment_time = Timeout::from_millis(establishment_time);
            } else {
                let avg_time =
                    (stats.average_establishment_time.as_millis() + establishment_time) / 2;
                stats.average_establishment_time = Timeout::from_millis(avg_time);
            }
        }

        info!(
            connection_id = %self.context.read().await.connection_id,
            establishment_time_ms = self.start_time.elapsed().as_millis(),
            "Connection established as client"
        );

        // Return context
        let context = self.context.read().await;
        Ok(EstablishmentContext {
            connection_id: context.connection_id,
            local_endpoint: context.local_endpoint,
            remote_endpoint: context.remote_endpoint,
            local_keypair: context.local_keypair.clone(),
            remote_public_key: context.remote_public_key,
            shared_secret: context.shared_secret.clone(),
            session_key: context.session_key.clone(),
            challenge_nonce: context.challenge_nonce.clone(),
            response_nonce: context.response_nonce.clone(),
            auth_token: context.auth_token.clone(),
        })
    }

    /// Start connection establishment as server
    #[instrument(skip(self))]
    pub async fn establish_as_server(
        &self,
        syn_packet: Packet,
    ) -> SessionResult<EstablishmentContext> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.attempts_started += 1;
        }

        // Start timeout task to abort establishment if it takes too long
        self.start_timeout_task().await;

        // Transition to SynReceived state
        self.transition_to_state(EstablishmentState::SynReceived)
            .await?;

        // Process SYN packet
        self.process_syn_packet(syn_packet).await?;

        // Generate local key pair
        self.generate_local_keypair().await?;

        // Send SYN-ACK packet
        self.send_syn_ack_packet().await?;

        // Perform key exchange
        self.perform_key_exchange().await?;

        // Authenticate
        if self.config.enable_mutual_auth {
            self.perform_authentication().await?;
        }

        // Finalize connection
        self.finalize_connection().await?;

        // Transition to established state
        self.transition_to_state(EstablishmentState::Established)
            .await?;

        // Stop timeout
        self.stop_timeout().await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.attempts_completed += 1;
            stats.handshakes_completed += 1;

            let establishment_time = self.start_time.elapsed().as_millis() as u64;
            stats.last_establishment_time = Timeout::from_millis(establishment_time);

            // Update average
            if stats.attempts_completed == 1 {
                stats.average_establishment_time = Timeout::from_millis(establishment_time);
            } else {
                let avg_time =
                    (stats.average_establishment_time.as_millis() + establishment_time) / 2;
                stats.average_establishment_time = Timeout::from_millis(avg_time);
            }
        }

        info!(
            connection_id = %self.context.read().await.connection_id,
            establishment_time_ms = self.start_time.elapsed().as_millis(),
            "Connection established as server"
        );

        // Return context
        let context = self.context.read().await;
        Ok(EstablishmentContext {
            connection_id: context.connection_id,
            local_endpoint: context.local_endpoint,
            remote_endpoint: context.remote_endpoint,
            local_keypair: context.local_keypair.clone(),
            remote_public_key: context.remote_public_key,
            shared_secret: context.shared_secret.clone(),
            session_key: context.session_key.clone(),
            challenge_nonce: context.challenge_nonce.clone(),
            response_nonce: context.response_nonce.clone(),
            auth_token: context.auth_token.clone(),
        })
    }

    /// Get current state
    pub async fn current_state(&self) -> EstablishmentState {
        EstablishmentState::load(&self.state, Ordering::Relaxed)
    }

    /// Check if establishment is complete
    pub async fn is_complete(&self) -> bool {
        self.current_state().await.is_terminal()
    }

    /// Check if establishment was successful
    pub async fn is_successful(&self) -> bool {
        self.current_state().await.is_successful()
    }

    /// Generate local ECDH key pair using ECDH manager
    async fn generate_local_keypair(&self) -> SessionResult<()> {
        let context = self.context.read().await;
        let key_id = format!("conn_{}", context.connection_id.0);
        drop(context);

        // Generate proper P-256 keypair using ECDH manager
        let public_key = self.ecdh_manager.get_key_pair(&key_id).map_err(|e| {
            let remote_endpoint = self
                .context
                .try_read()
                .ok()
                .map(|ctx| ctx.remote_endpoint)
                .unwrap_or(FALLBACK_SOCKET_ADDR);
            SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(remote_endpoint),
                format!("Ecdh key generation failed: {:?}", e),
            )
        })?;

        // Store public key in context. Private key is intentionally set to zeros
        // as a placeholder - the actual private key remains securely within the
        // ECDH manager and is never exposed. All cryptographic operations that
        // require the private key are performed through the ECDH manager.
        let private_key = EcdhPrivateKey::new([0u8; 32]); // Security: placeholder only
        let keypair = (private_key, public_key);

        let mut context = self.context.write().await;
        context.local_keypair = Some(keypair);

        debug!(
            connection_id = %context.connection_id,
            "Local ECDH key pair generated using P-256"
        );

        Ok(())
    }

    /// Send SYN packet
    async fn send_syn_packet(&self) -> SessionResult<()> {
        let context = self.context.read().await;
        let public_key = context
            .local_keypair
            .as_ref()
            .ok_or_else(|| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    "Local key pair not generated",
                )
            })?
            .1;

        // Build SYN packet with public key using generic PacketBuilder
        let version_byte = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let packet_builder_engine =
            PacketBuilderEngine::with_defaults(version_byte, self.config.hmac_policy);

        // Create a temporary session ID for establishment
        let temp_session_id = SessionId::from_raw(0); // Will be replaced with actual session ID after establishment

        let _syn_header = packet_builder_engine
            .builder(PacketType::Syn)
            .session_id(temp_session_id)
            .sequence_number(SequenceNumber::new(1))
            .build_header()
            .map_err(|e| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    format!("Failed to build SYN packet: {:?}", e),
                )
            })?;

        // In a real implementation, this would send the packet over the network
        debug!(
            connection_id = %context.connection_id,
            remote = %context.remote_endpoint,
            public_key_len = public_key.as_bytes().len(),
            "SYN packet built and ready to send"
        );

        Ok(())
    }

    /// Wait for SYN-ACK packet
    async fn wait_for_syn_ack(&self) -> SessionResult<()> {
        // In a real implementation, this would wait for the actual SYN-ACK packet
        // For now, we simulate receiving it

        let timeout_duration = Duration::from_millis(self.config.handshake_timeout.as_millis());
        let result = timeout(timeout_duration, async {
            // Simulate network delay
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                debug!(
                    connection_id = %self.context.read().await.connection_id,
                    "SYN-ACK packet received"
                );
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.transition_to_state(EstablishmentState::Timeout)
                    .await?;
                Err(SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(self.context.read().await.remote_endpoint),
                    "SYN-ACK timeout",
                ))
            }
        }
    }

    /// Process SYN packet
    async fn process_syn_packet(&self, packet: Packet) -> SessionResult<()> {
        // Extract remote public key from packet payload
        let payload = packet.payload();
        let remote_public_key = if payload.len() != 64 {
            return Err(SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(self.context.read().await.remote_endpoint),
                "Invalid public key length in SYN",
            ));
        } else {
            let mut key_bytes = [0u8; 64];
            key_bytes.copy_from_slice(payload);
            EcdhPublicKey::new(key_bytes)
        };

        let mut context = self.context.write().await;
        context.remote_public_key = Some(remote_public_key);

        debug!(
            connection_id = %context.connection_id,
            "SYN packet processed"
        );

        Ok(())
    }

    /// Send SYN-ACK packet
    async fn send_syn_ack_packet(&self) -> SessionResult<()> {
        let context = self.context.read().await;
        let public_key = context
            .local_keypair
            .as_ref()
            .ok_or_else(|| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    "Local key pair not generated",
                )
            })?
            .1;

        // Build SYN-ACK packet with public key using generic PacketBuilder
        let version_byte = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let packet_builder_engine =
            PacketBuilderEngine::with_defaults(version_byte, self.config.hmac_policy);

        // Create a temporary session ID for establishment
        let temp_session_id = SessionId::from_raw(0); // Will be replaced with actual session ID after establishment

        // Create flags with both SYN and ACK set
        let mut flags = PacketFlags::new();
        flags.set_flag(PacketFlags::SYN);
        flags.set_flag(PacketFlags::ACK);

        let _syn_ack_header = packet_builder_engine
            .builder(PacketType::SynAck)
            .session_id(temp_session_id)
            .sequence_number(SequenceNumber::new(1))
            .ack_number(AckNumber::new(2))
            .flags(flags)
            .build_header()
            .map_err(|e| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    format!("Failed to build SYN-ACK packet: {:?}", e),
                )
            })?;

        // In a real implementation, this would send the packet over the network
        debug!(
            connection_id = %context.connection_id,
            remote = %context.remote_endpoint,
            public_key_len = public_key.as_bytes().len(),
            "SYN-ACK packet built and ready to send"
        );

        Ok(())
    }

    /// Perform key exchange using ECDH
    async fn perform_key_exchange(&self) -> SessionResult<()> {
        self.transition_to_state(EstablishmentState::KeyExchange)
            .await?;

        let timeout_duration = Duration::from_millis(self.config.key_exchange_timeout.as_millis());
        let result = timeout(timeout_duration, async {
            let context = self.context.read().await;

            let local_keypair = context.local_keypair.as_ref().ok_or_else(|| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    "Local key pair not available",
                )
            })?;

            let remote_public_key = *context.remote_public_key.as_ref().ok_or_else(|| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    "Remote public key not available",
                )
            })?;

            let key_id = format!("conn_{}", context.connection_id.0);
            let local_public_key = local_keypair.1;
            let connection_id_bytes = context.connection_id.0.to_be_bytes();
            drop(context);

            // Compute shared secret using ECDH manager
            let shared_secret = self
                .ecdh_manager
                .compute_shared_secret(&key_id, &remote_public_key)
                .map_err(|e| {
                    let remote_endpoint = self
                        .context
                        .try_read()
                        .ok()
                        .map(|ctx| ctx.remote_endpoint)
                        .unwrap_or(FALLBACK_SOCKET_ADDR);
                    SessionError::connection_establishment_failed(
                        NetworkEndpoint::from_socket_addr(remote_endpoint),
                        format!("Ecdh agreement failed: {:?}", e),
                    )
                })?;

            // Derive session parameters from shared secret using PBKDF2
            // This implements design/protocol/04-ecdh-cryptography.md §265-301
            use crate::security::crypto::session_derivation::SessionDerivation;

            let session_params = SessionDerivation::derive_session_keys_from_dh(
                &shared_secret,
                &local_public_key,
                &remote_public_key,
                &connection_id_bytes,
            )
            .map_err(|e| {
                let remote_endpoint = self
                    .context
                    .try_read()
                    .ok()
                    .map(|ctx| ctx.remote_endpoint)
                    .unwrap_or(FALLBACK_SOCKET_ADDR);
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(remote_endpoint),
                    format!("Session key derivation failed: {:?}", e),
                )
            })?;

            let mut context = self.context.write().await;
            context.shared_secret = Some(shared_secret);
            context.session_key = Some(Arc::new(session_params.session_key));

            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                tracing::debug!("Key exchange completed");

                debug!(
                    connection_id = %self.context.read().await.connection_id,
                    "Key exchange completed"
                );
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.transition_to_state(EstablishmentState::Timeout)
                    .await?;
                Err(SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(self.context.read().await.remote_endpoint),
                    "Key exchange timeout",
                ))
            }
        }
    }

    /// Perform authentication
    async fn perform_authentication(&self) -> SessionResult<()> {
        self.transition_to_state(EstablishmentState::Authenticating)
            .await?;

        let timeout_duration =
            Duration::from_millis(self.config.authentication_timeout.as_millis());
        let result = timeout(timeout_duration, async {
            // Generate challenge nonce
            let challenge_nonce = self.generate_nonce(32)?;

            // Generate response nonce
            let response_nonce = self.generate_nonce(32)?;

            // Create authentication token
            let auth_token = self
                .create_auth_token(&challenge_nonce, &response_nonce)
                .await?;

            let mut context = self.context.write().await;
            context.challenge_nonce = Some(challenge_nonce);
            context.response_nonce = Some(response_nonce);
            context.auth_token = Some(auth_token);

            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                tracing::debug!("Authentication completed");

                debug!(
                    connection_id = %self.context.read().await.connection_id,
                    "Authentication completed"
                );
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.transition_to_state(EstablishmentState::Timeout)
                    .await?;
                Err(SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(self.context.read().await.remote_endpoint),
                    "Authentication timeout",
                ))
            }
        }
    }

    /// Finalize connection
    async fn finalize_connection(&self) -> SessionResult<()> {
        self.transition_to_state(EstablishmentState::Finalizing)
            .await?;

        // Perform final validation and setup
        let context = self.context.read().await;

        // Validate that all required components are present
        if context.shared_secret.is_none() {
            return Err(SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                "Shared secret not established",
            ));
        }

        if context.session_key.is_none() {
            return Err(SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                "Session key not derived",
            ));
        }

        if self.config.enable_mutual_auth && context.auth_token.is_none() {
            return Err(SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                "Authentication not completed",
            ));
        }

        debug!(
            connection_id = %context.connection_id,
            "Connection finalized"
        );

        Ok(())
    }

    /// Generate cryptographic nonce
    fn generate_nonce(&self, size: usize) -> SessionResult<Vec<u8>> {
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut nonce = vec![0u8; size];

        rng.fill(&mut nonce).map_err(|_| {
            let remote_endpoint = self
                .context
                .try_read()
                .ok()
                .map(|ctx| ctx.remote_endpoint)
                .unwrap_or(FALLBACK_SOCKET_ADDR);
            SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(remote_endpoint),
                "Failed to generate nonce",
            )
        })?;

        Ok(nonce)
    }

    /// Create authentication token using HMAC over nonces and connection ID
    async fn create_auth_token(
        &self,
        challenge_nonce: &[u8],
        response_nonce: &[u8],
    ) -> SessionResult<Vec<u8>> {
        let context = self.context.read().await;
        let session_key = context.session_key.as_ref().ok_or_else(|| {
            SessionError::connection_establishment_failed(
                NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                "Session key not available for authentication",
            )
        })?;

        // Create authentication data
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(challenge_nonce);
        auth_data.extend_from_slice(response_nonce);
        auth_data.extend_from_slice(&context.connection_id.0.to_be_bytes());

        // Calculate HMAC using session key
        let hmac_calculator = HmacCalculator::new();
        let auth_token = hmac_calculator
            .calculate_packet_hmac(&auth_data, session_key.as_bytes(), self.config.hmac_policy)
            .map_err(|e| {
                SessionError::connection_establishment_failed(
                    NetworkEndpoint::from_socket_addr(context.remote_endpoint),
                    format!("HMAC calculation failed: {:?}", e),
                )
            })?;

        Ok(auth_token.as_bytes().to_vec())
    }

    /// Transition to new state
    async fn transition_to_state(&self, new_state: EstablishmentState) -> SessionResult<()> {
        let old_state = self.current_state().await;

        if old_state == new_state {
            return Ok(());
        }

        new_state.store(&self.state, std::sync::atomic::Ordering::Relaxed);

        debug!(
            connection_id = %self.context.read().await.connection_id,
            old_state = ?old_state,
            new_state = ?new_state,
            "Establishment state transition"
        );

        Ok(())
    }

    /// Start timeout task (wrapper for non-Arc contexts)
    async fn start_timeout_task(&self) {
        let timeout_duration = Duration::from_millis(self.config.connection_timeout.as_millis());
        let state_clone = self.state.clone();

        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout_duration).await;

            // Set timeout state directly
            EstablishmentState::Timeout.store(&state_clone, std::sync::atomic::Ordering::Relaxed);

            // Log timeout
            error!("Connection establishment timeout");
        });

        *self.timeout_handle.lock().await = Some(handle);
    }

    /// Stop timeout
    async fn stop_timeout(&self) {
        if let Some(handle) = self.timeout_handle.lock().await.take() {
            handle.abort();
        }
    }

    /// Get establishment statistics
    pub async fn get_stats(&self) -> EstablishmentStats {
        self.stats.read().await.clone()
    }

    /// Get establishment duration
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Drop for ConnectionEstablishment {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd use a proper shutdown mechanism
        if let Ok(mut handle) = self.timeout_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}
