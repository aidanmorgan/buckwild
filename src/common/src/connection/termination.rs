// Connection Termination - handles graceful connection shutdown
//
// This implements connection termination including graceful shutdown,
// resource cleanup, session termination, and final state management.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::net::SocketAddr;
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

use crate::error::{SessionError, SessionResult, SystemError};
use crate::protocol::packet::Packet;
use crate::protocol::packet::builder::PacketBuilderEngine;

// Use consolidated types
use crate::protocol::types::{
    AckNumber, AttemptCount, ConnectionId, Counter, HmacPolicy, PacketFlags, PacketType,
    SequenceNumber, SessionId, SessionIdLength, SyncState, Timeout, TimestampConfig, VersionByte,
};

/// Trait for sending packets over the network
pub trait PacketSender: Send + Sync {
    /// Send a packet to the specified destination
    fn send_packet(&self, packet: Bytes, destination: SocketAddr) -> Result<(), SessionError>;
}

/// Trait for receiving packets from the network
pub trait PacketReceiver: Send + Sync {
    /// Wait for a packet with optional timeout
    fn receive_packet(
        &self,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Packet>, SessionError>;
}

/// Connection termination state
/// M2 spec compliant with TIME_WAIT support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TerminationState {
    /// Connection is active
    Active = 0,

    /// Termination initiated
    Initiated = 1,

    /// Sending FIN packet
    FinSent = 2,

    /// Received FIN, sending FIN-ACK
    FinReceived = 3,

    /// Waiting for final ACK
    FinWait = 4,

    /// TIME_WAIT state - waiting for 2*MSL before full close
    /// This prevents delayed packets from interfering with new connections
    /// M2 spec requirement for proper termination sequence
    TimeWait = 5,

    /// Cleaning up sessions
    SessionCleanup = 6,

    /// Cleaning up resources
    ResourceCleanup = 7,

    /// Finalizing termination
    Finalizing = 8,

    /// Connection terminated
    Terminated = 9,

    /// Termination failed
    Failed = 10,

    /// Termination timeout
    Timeout = 11,

    /// Force terminated
    ForceTerminated = 12,
}

impl TerminationState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Active),
            1 => Some(Self::Initiated),
            2 => Some(Self::FinSent),
            3 => Some(Self::FinReceived),
            4 => Some(Self::FinWait),
            5 => Some(Self::TimeWait),
            6 => Some(Self::SessionCleanup),
            7 => Some(Self::ResourceCleanup),
            8 => Some(Self::Finalizing),
            9 => Some(Self::Terminated),
            10 => Some(Self::Failed),
            11 => Some(Self::Timeout),
            12 => Some(Self::ForceTerminated),
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
        matches!(
            self,
            Self::Terminated | Self::Failed | Self::Timeout | Self::ForceTerminated
        )
    }

    /// Check if this state indicates successful termination
    pub fn is_successful(&self) -> bool {
        matches!(self, Self::Terminated)
    }

    /// Check if this state indicates forced termination
    pub fn is_forced(&self) -> bool {
        matches!(self, Self::ForceTerminated)
    }
}

/// Termination reason
#[derive(Debug, Clone)]
pub enum TerminationReason {
    /// Normal shutdown requested
    NormalShutdown,

    /// Connection timeout
    Timeout,

    /// Connection error
    Error(String),

    /// Remote initiated termination
    RemoteInitiated,

    /// Resource exhaustion
    ResourceExhaustion,

    /// Security violation
    SecurityViolation,

    /// Application request
    ApplicationRequest,

    /// System shutdown
    SystemShutdown,

    /// Force termination
    ForceTermination,
}

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NormalShutdown => write!(f, "Normal shutdown"),
            Self::Timeout => write!(f, "Connection timeout"),
            Self::Error(e) => write!(f, "Connection error: {}", e),
            Self::RemoteInitiated => write!(f, "Remote initiated termination"),
            Self::ResourceExhaustion => write!(f, "Resource exhaustion"),
            Self::SecurityViolation => write!(f, "Security violation"),
            Self::ApplicationRequest => write!(f, "Application request"),
            Self::SystemShutdown => write!(f, "System shutdown"),
            Self::ForceTermination => write!(f, "Force termination"),
        }
    }
}

/// Connection termination configuration
#[derive(Debug, Clone)]
pub struct TerminationConfig {
    /// Graceful termination timeout
    pub graceful_timeout: Timeout,

    /// FIN packet timeout
    pub fin_timeout: Timeout,

    /// TIME_WAIT timeout (M2 spec: 2*MSL for proper connection cleanup)
    /// Default: 60 seconds (2 * 30 second MSL)
    pub time_wait_timeout: Timeout,

    /// Session cleanup timeout
    pub session_cleanup_timeout: Timeout,

    /// Resource cleanup timeout
    pub resource_cleanup_timeout: Timeout,

    /// Maximum retry attempts for graceful termination
    pub max_retry_attempts: AttemptCount,

    /// Retry delay
    pub retry_delay: Timeout,

    /// Enable graceful session termination
    pub enable_graceful_session_termination: bool,

    /// Enable resource cleanup
    pub enable_resource_cleanup: bool,

    /// Force termination after timeout
    pub force_after_timeout: bool,

    /// Enable TIME_WAIT state (M2 spec requirement)
    pub enable_time_wait: bool,
}

impl Default for TerminationConfig {
    fn default() -> Self {
        Self {
            graceful_timeout: Timeout::from_millis(30_000), // 30 seconds
            fin_timeout: Timeout::from_millis(5_000),       // 5 seconds
            time_wait_timeout: Timeout::from_millis(60_000), // 60 seconds (2*MSL)
            session_cleanup_timeout: Timeout::from_millis(10_000), // 10 seconds
            resource_cleanup_timeout: Timeout::from_millis(5_000), // 5 seconds
            max_retry_attempts: AttemptCount::new(3),
            retry_delay: Timeout::from_millis(1_000), // 1 second
            enable_graceful_session_termination: true,
            enable_resource_cleanup: true,
            force_after_timeout: true,
            enable_time_wait: true,
        }
    }
}

/// Connection termination context
#[derive(Debug)]
pub struct TerminationContext {
    /// Connection ID
    pub connection_id: ConnectionId,

    /// Local endpoint
    pub local_endpoint: SocketAddr,

    /// Remote endpoint
    pub remote_endpoint: SocketAddr,

    /// Termination reason
    pub reason: TerminationReason,

    /// Active session IDs at termination start
    pub active_sessions: Vec<SessionId>,

    /// Sessions successfully terminated
    pub terminated_sessions: Vec<SessionId>,

    /// Sessions that failed to terminate
    pub failed_sessions: Vec<SessionId>,

    /// Resources to cleanup
    pub resources_to_cleanup: Vec<String>,

    /// Resources successfully cleaned up
    pub cleaned_resources: Vec<String>,

    /// Resources that failed to cleanup
    pub failed_resources: Vec<String>,
}

impl TerminationContext {
    /// Create a new termination context
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        reason: TerminationReason,
    ) -> Self {
        Self {
            connection_id,
            local_endpoint,
            remote_endpoint,
            reason,
            active_sessions: Vec::new(),
            terminated_sessions: Vec::new(),
            failed_sessions: Vec::new(),
            resources_to_cleanup: Vec::new(),
            cleaned_resources: Vec::new(),
            failed_resources: Vec::new(),
        }
    }
}

/// Connection termination statistics
#[derive(Debug, Default, Clone)]
pub struct TerminationStats {
    pub terminations_initiated: Counter,
    pub graceful_terminations: Counter,
    pub forced_terminations: Counter,
    pub failed_terminations: Counter,
    pub timeout_terminations: Counter,
    pub sessions_terminated: Counter,
    pub sessions_failed_termination: Counter,
    pub resources_cleaned: Counter,
    pub resources_failed_cleanup: Counter,
    pub average_termination_time: Timeout,
    pub last_termination_time: Timeout,
}

/// Session termination callback type
type SessionTerminationCallback = Box<dyn Fn(SessionId) -> Result<(), SessionError> + Send + Sync>;
/// System termination callback type
type SystemTerminationCallback = Box<dyn Fn(&str) -> Result<(), SystemError> + Send + Sync>;

/// Connection Termination - handles graceful connection shutdown
pub struct ConnectionTermination {
    /// Configuration
    config: TerminationConfig,

    /// Current state
    state: SyncState,

    /// Termination context
    context: RwLock<TerminationContext>,

    /// Start time
    start_time: Instant,

    /// Statistics
    stats: RwLock<TerminationStats>,

    /// Timeout handle
    timeout_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Session termination callbacks
    session_callbacks: RwLock<Vec<SessionTerminationCallback>>,

    /// Resource cleanup callbacks
    system_callbacks: RwLock<Vec<SystemTerminationCallback>>,

    /// Packet sender for network integration
    packet_sender: Option<Arc<dyn PacketSender>>,

    /// Packet receiver for network integration
    packet_receiver: Option<Arc<dyn PacketReceiver>>,
}

impl ConnectionTermination {
    /// Create a new connection termination
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        reason: TerminationReason,
        config: TerminationConfig,
    ) -> Self {
        let context =
            TerminationContext::new(connection_id, local_endpoint, remote_endpoint, reason);

        Self {
            config,
            state: SyncState::new(TerminationState::Active.as_u8()),
            context: RwLock::new(context),
            start_time: Instant::now(),
            stats: RwLock::new(TerminationStats::default()),
            timeout_handle: Mutex::new(None),
            session_callbacks: RwLock::new(Vec::new()),
            system_callbacks: RwLock::new(Vec::new()),
            packet_sender: None,
            packet_receiver: None,
        }
    }

    /// Set packet sender for network integration
    pub fn set_packet_sender(&mut self, sender: Arc<dyn PacketSender>) {
        self.packet_sender = Some(sender);
    }

    /// Set packet receiver for network integration
    pub fn set_packet_receiver(&mut self, receiver: Arc<dyn PacketReceiver>) {
        self.packet_receiver = Some(receiver);
    }

    /// Start graceful termination
    #[instrument(skip(self))]
    pub async fn terminate_gracefully(&self) -> SessionResult<TerminationContext> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.terminations_initiated += 1;
        }

        // Start timeout
        self.start_timeout_task().await;

        // Transition to initiated state
        self.transition_to_state(TerminationState::Initiated)
            .await?;

        // Send FIN packet
        self.send_fin_packet().await?;

        // Wait for FIN-ACK or timeout (sends final ACK after receiving FIN-ACK)
        self.wait_for_fin_ack().await?;

        // Enter TIME_WAIT state if enabled (M2 spec requirement)
        if self.config.enable_time_wait {
            self.enter_time_wait().await?;
        }

        // Clean up sessions
        if self.config.enable_graceful_session_termination {
            self.cleanup_sessions().await?;
        }

        // Clean up resources
        if self.config.enable_resource_cleanup {
            self.cleanup_resources().await?;
        }

        // Finalize termination
        self.finalize_termination().await?;

        // Transition to terminated state
        self.transition_to_state(TerminationState::Terminated)
            .await?;

        // Stop timeout
        self.stop_timeout().await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.graceful_terminations += 1;

            let termination_time = self.start_time.elapsed().as_millis() as u64;
            stats.last_termination_time = Timeout::from_millis(termination_time);

            // Update average
            if stats.graceful_terminations == 1 {
                stats.average_termination_time = Timeout::from_millis(termination_time);
            } else {
                let avg_time = (stats.average_termination_time.as_millis() + termination_time) / 2;
                stats.average_termination_time = Timeout::from_millis(avg_time);
            }
        }

        info!(
            connection_id = %self.context.read().await.connection_id,
            termination_time_ms = self.start_time.elapsed().as_millis(),
            reason = %self.context.read().await.reason,
            "Connection terminated gracefully"
        );

        // Return context
        let context = self.context.read().await;
        Ok(TerminationContext {
            connection_id: context.connection_id,
            local_endpoint: context.local_endpoint,
            remote_endpoint: context.remote_endpoint,
            reason: context.reason.clone(),
            active_sessions: context.active_sessions.clone(),
            terminated_sessions: context.terminated_sessions.clone(),
            failed_sessions: context.failed_sessions.clone(),
            resources_to_cleanup: context.resources_to_cleanup.clone(),
            cleaned_resources: context.cleaned_resources.clone(),
            failed_resources: context.failed_resources.clone(),
        })
    }

    /// Force termination
    pub async fn terminate_forcefully(&self) -> SessionResult<TerminationContext> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.terminations_initiated += 1;
            stats.forced_terminations += 1;
        }

        // Transition to force terminated state
        self.transition_to_state(TerminationState::ForceTerminated)
            .await?;

        // Force cleanup sessions
        self.force_cleanup_sessions().await;

        // Force cleanup resources
        self.force_cleanup_resources().await;

        let context_read = self.context.read().await;
        let connection_id = context_read.connection_id;
        let reason = context_read.reason.clone();
        drop(context_read);

        warn!(
            connection_id = %connection_id,
            termination_time_ms = self.start_time.elapsed().as_millis(),
            reason = %reason,
            "Connection terminated forcefully"
        );

        // Return context
        let context = self.context.read().await;
        Ok(TerminationContext {
            connection_id: context.connection_id,
            local_endpoint: context.local_endpoint,
            remote_endpoint: context.remote_endpoint,
            reason: context.reason.clone(),
            active_sessions: context.active_sessions.clone(),
            terminated_sessions: context.terminated_sessions.clone(),
            failed_sessions: context.failed_sessions.clone(),
            resources_to_cleanup: context.resources_to_cleanup.clone(),
            cleaned_resources: context.cleaned_resources.clone(),
            failed_resources: context.failed_resources.clone(),
        })
    }

    /// Process FIN packet from remote
    pub async fn process_fin_packet(&self, _packet: Packet) -> SessionResult<()> {
        self.transition_to_state(TerminationState::FinReceived)
            .await?;

        // Send FIN-ACK
        self.send_fin_ack_packet().await?;

        // Start graceful termination
        self.terminate_gracefully().await?;

        Ok(())
    }

    /// Get current state
    pub async fn current_state(&self) -> TerminationState {
        TerminationState::load(&self.state, Ordering::Relaxed)
    }

    /// Check if termination is complete
    pub async fn is_complete(&self) -> bool {
        self.current_state().await.is_terminal()
    }

    /// Check if termination was successful
    pub async fn is_successful(&self) -> bool {
        self.current_state().await.is_successful()
    }

    /// Add session termination callback
    pub async fn add_session_callback<F>(&self, callback: F)
    where
        F: Fn(SessionId) -> Result<(), SessionError> + Send + Sync + 'static,
    {
        self.session_callbacks
            .write()
            .await
            .push(Box::new(callback));
    }

    /// Add resource cleanup callback
    pub async fn add_resource_callback<F>(&self, callback: F)
    where
        F: Fn(&str) -> Result<(), SystemError> + Send + Sync + 'static,
    {
        self.system_callbacks.write().await.push(Box::new(callback));
    }

    /// Set active sessions
    pub async fn set_active_sessions(&self, sessions: Vec<SessionId>) {
        let mut context = self.context.write().await;
        context.active_sessions = sessions;
    }

    /// Set resources to cleanup
    pub async fn set_resources_to_cleanup(&self, resources: Vec<String>) {
        let mut context = self.context.write().await;
        context.resources_to_cleanup = resources;
    }

    /// Send FIN packet
    async fn send_fin_packet(&self) -> SessionResult<()> {
        self.transition_to_state(TerminationState::FinSent).await?;

        let context = self.context.read().await;

        // Build FIN packet using generic PacketBuilder
        let version_byte = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let packet_builder_engine =
            PacketBuilderEngine::with_defaults(version_byte, HmacPolicy::Medium);

        // Use first active session ID, or 0 if none
        let session_id = context
            .active_sessions
            .first()
            .cloned()
            .unwrap_or_else(|| SessionId::from_raw(0));

        let fin_header = packet_builder_engine
            .builder(PacketType::Fin)
            .session_id(session_id.clone())
            .sequence_number(SequenceNumber::new(1))
            .build_header()
            .map_err(|e| SessionError::SessionManagementError {
                reason: format!("Failed to build FIN packet: {:?}", e),
            })?;

        // Serialize packet to bytes
        let mut buffer = vec![0u8; 1500]; // MTU-sized buffer
        let bytes_written = fin_header.serialize(&mut buffer).map_err(|e| {
            SessionError::SessionManagementError {
                reason: format!("Failed to serialize FIN packet: {:?}", e),
            }
        })?;
        let packet_bytes = Bytes::from(buffer[..bytes_written].to_vec());

        // Send packet if sender is configured
        if let Some(ref sender) = self.packet_sender {
            sender
                .send_packet(packet_bytes, context.remote_endpoint)
                .map_err(|e| SessionError::SessionManagementError {
                    reason: format!("Failed to send FIN packet: {:?}", e),
                })?;

            debug!(
                connection_id = %context.connection_id,
                remote = %context.remote_endpoint,
                session_id = %session_id,
                "FIN packet sent over network"
            );
        } else {
            debug!(
                connection_id = %context.connection_id,
                remote = %context.remote_endpoint,
                session_id = %session_id,
                "FIN packet built (no network sender configured)"
            );
        }

        Ok(())
    }

    /// Wait for FIN-ACK packet
    async fn wait_for_fin_ack(&self) -> SessionResult<()> {
        self.transition_to_state(TerminationState::FinWait).await?;

        let timeout_duration = Duration::from_millis(self.config.fin_timeout.as_millis());

        // If packet receiver is configured, actually wait for FIN-ACK
        if let Some(ref receiver) = self.packet_receiver {
            let result = timeout(timeout_duration, async {
                loop {
                    match receiver.receive_packet(Some(Duration::from_millis(100))) {
                        Ok(Some(packet)) => {
                            // Check if this is a FIN-ACK packet (FIN type with ACK flag set)
                            if packet.packet_type() == PacketType::Fin {
                                // FIN packets with ACK flag are FIN-ACK
                                // In this implementation, we accept any FIN packet as acknowledgment
                                return Ok(());
                            }
                            // Otherwise, continue waiting
                        }
                        Ok(None) => {
                            // Timeout on receive, continue waiting
                            continue;
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    debug!(
                        connection_id = %self.context.read().await.connection_id,
                        "FIN-ACK packet received from network"
                    );
                    // M2 spec: Send final ACK to complete the FIN handshake
                    self.send_final_ack().await?;
                    Ok(())
                }
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    warn!(
                        connection_id = %self.context.read().await.connection_id,
                        "FIN-ACK timeout, proceeding with termination"
                    );
                    Ok(()) // Continue with termination even if FIN-ACK times out
                }
            }
        } else {
            // No packet receiver configured, proceed without waiting
            debug!(
                connection_id = %self.context.read().await.connection_id,
                "FIN-ACK wait skipped (no network receiver configured)"
            );
            Ok(())
        }
    }

    /// Send final ACK to complete FIN handshake (M2 spec requirement)
    /// This is sent by the initiator after receiving FIN-ACK from the responder
    async fn send_final_ack(&self) -> SessionResult<()> {
        let context = self.context.read().await;

        // Build ACK packet
        let version_byte = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let packet_builder_engine =
            PacketBuilderEngine::with_defaults(version_byte, HmacPolicy::Medium);

        // Use first active session ID, or 0 if none
        let session_id = context
            .active_sessions
            .first()
            .cloned()
            .unwrap_or_else(|| SessionId::from_raw(0));

        let ack_header = packet_builder_engine
            .builder(PacketType::Ack)
            .session_id(session_id.clone())
            .sequence_number(SequenceNumber::new(2))
            .ack_number(AckNumber::new(2))
            .build_header()
            .map_err(|e| SessionError::SessionManagementError {
                reason: format!("Failed to build final ACK packet: {:?}", e),
            })?;

        // Serialize packet to bytes
        let mut buffer = vec![0u8; 1500]; // MTU-sized buffer
        let bytes_written = ack_header.serialize(&mut buffer).map_err(|e| {
            SessionError::SessionManagementError {
                reason: format!("Failed to serialize final ACK packet: {:?}", e),
            }
        })?;
        let packet_bytes = Bytes::from(buffer[..bytes_written].to_vec());

        // Send packet if sender is configured
        if let Some(ref sender) = self.packet_sender {
            sender
                .send_packet(packet_bytes, context.remote_endpoint)
                .map_err(|e| SessionError::SessionManagementError {
                    reason: format!("Failed to send final ACK packet: {:?}", e),
                })?;

            info!(
                connection_id = %context.connection_id,
                remote = %context.remote_endpoint,
                session_id = %session_id,
                "Final ACK packet sent - FIN handshake complete"
            );
        } else {
            debug!(
                connection_id = %context.connection_id,
                remote = %context.remote_endpoint,
                session_id = %session_id,
                "Final ACK packet built (no network sender configured)"
            );
        }

        Ok(())
    }

    /// Enter TIME_WAIT state (M2 spec requirement)
    /// Waits for 2*MSL to ensure delayed packets don't interfere with new connections
    async fn enter_time_wait(&self) -> SessionResult<()> {
        self.transition_to_state(TerminationState::TimeWait).await?;

        let time_wait_duration = Duration::from_millis(self.config.time_wait_timeout.as_millis());
        let connection_id = self.context.read().await.connection_id;

        info!(
            connection_id = %connection_id,
            duration_ms = time_wait_duration.as_millis(),
            "Entering TIME_WAIT state (2*MSL)"
        );

        // Wait for TIME_WAIT period
        tokio::time::sleep(time_wait_duration).await;

        debug!(
            connection_id = %connection_id,
            "TIME_WAIT period complete"
        );

        Ok(())
    }

    /// Send FIN-ACK packet
    async fn send_fin_ack_packet(&self) -> SessionResult<()> {
        let context = self.context.read().await;

        // Build FIN-ACK packet using generic PacketBuilder with both FIN and ACK flags
        let version_byte = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let packet_builder_engine =
            PacketBuilderEngine::with_defaults(version_byte, HmacPolicy::Medium);

        // Use first active session ID, or 0 if none
        let session_id = context
            .active_sessions
            .first()
            .cloned()
            .unwrap_or_else(|| SessionId::from_raw(0));

        // Create flags with both FIN and ACK set
        let mut flags = PacketFlags::new();
        flags.set_flag(PacketFlags::FIN);
        flags.set_flag(PacketFlags::ACK);

        let fin_ack_header = packet_builder_engine
            .builder(PacketType::Fin)
            .session_id(session_id.clone())
            .sequence_number(SequenceNumber::new(1))
            .ack_number(AckNumber::new(2))
            .flags(flags)
            .build_header()
            .map_err(|e| SessionError::SessionManagementError {
                reason: format!("Failed to build FIN-ACK packet: {:?}", e),
            })?;

        // Serialize packet to bytes
        let mut buffer = vec![0u8; 1500]; // MTU-sized buffer
        let bytes_written = fin_ack_header.serialize(&mut buffer).map_err(|e| {
            SessionError::SessionManagementError {
                reason: format!("Failed to serialize FIN-ACK packet: {:?}", e),
            }
        })?;
        let packet_bytes = Bytes::from(buffer[..bytes_written].to_vec());

        // Send packet if sender is configured
        if let Some(ref sender) = self.packet_sender {
            sender
                .send_packet(packet_bytes, context.remote_endpoint)
                .map_err(|e| SessionError::SessionManagementError {
                    reason: format!("Failed to send FIN-ACK packet: {:?}", e),
                })?;

            debug!(
                connection_id = %context.connection_id,
                remote = %context.remote_endpoint,
                session_id = %session_id,
                "FIN-ACK packet sent over network"
            );
        } else {
            debug!(
                connection_id = %context.connection_id,
                remote = %context.remote_endpoint,
                session_id = %session_id,
                "FIN-ACK packet built (no network sender configured)"
            );
        }

        Ok(())
    }

    /// Clean up sessions gracefully
    async fn cleanup_sessions(&self) -> SessionResult<()> {
        self.transition_to_state(TerminationState::SessionCleanup)
            .await?;

        let timeout_duration =
            Duration::from_millis(self.config.session_cleanup_timeout.as_millis());
        let result = timeout(timeout_duration, async {
            let active_sessions = {
                let context = self.context.read().await;
                context.active_sessions.clone()
            };

            let callbacks = self.session_callbacks.read().await;

            for session_id in active_sessions {
                let mut success = false;

                // Try all callbacks until one succeeds
                for callback in callbacks.iter() {
                    match callback(session_id.clone()) {
                        Ok(()) => {
                            success = true;
                            break;
                        }
                        Err(e) => {
                            debug!(
                                connection_id = %self.context.read().await.connection_id,
                                session_id = %session_id,
                                error = %e,
                                "Session termination callback failed"
                            );
                        }
                    }
                }

                // Update context
                let mut context = self.context.write().await;
                if success {
                    context.terminated_sessions.push(session_id);
                } else {
                    context.failed_sessions.push(session_id);
                }
            }

            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let context = self.context.read().await;
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.sessions_terminated += context.terminated_sessions.len() as u64;
                    stats.sessions_failed_termination += context.failed_sessions.len() as u64;
                }

                debug!(
                    connection_id = %context.connection_id,
                    terminated_sessions = context.terminated_sessions.len(),
                    failed_sessions = context.failed_sessions.len(),
                    "Session cleanup completed"
                );
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                warn!(
                    connection_id = %self.context.read().await.connection_id,
                    "Session cleanup timeout"
                );
                Ok(()) // Continue with termination even if session cleanup times out
            }
        }
    }

    /// Clean up resources gracefully
    async fn cleanup_resources(&self) -> SessionResult<()> {
        self.transition_to_state(TerminationState::ResourceCleanup)
            .await?;

        let timeout_duration =
            Duration::from_millis(self.config.resource_cleanup_timeout.as_millis());
        let result = timeout(timeout_duration, async {
            let resources_to_cleanup = {
                let context = self.context.read().await;
                context.resources_to_cleanup.clone()
            };

            let callbacks = self.system_callbacks.read().await;

            for resource_id in resources_to_cleanup {
                let mut success = false;

                // Try all callbacks until one succeeds
                for callback in callbacks.iter() {
                    match callback(&resource_id) {
                        Ok(()) => {
                            success = true;
                            break;
                        }
                        Err(e) => {
                            debug!(
                                connection_id = %self.context.read().await.connection_id,
                                resource_id,
                                error = %e,
                                "Resource cleanup callback failed"
                            );
                        }
                    }
                }

                // Update context
                let mut context = self.context.write().await;
                if success {
                    context.cleaned_resources.push(resource_id);
                } else {
                    context.failed_resources.push(resource_id);
                }
            }

            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let context = self.context.read().await;

                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.resources_cleaned += context.cleaned_resources.len() as u64;
                    stats.resources_failed_cleanup += context.failed_resources.len() as u64;
                }

                debug!(
                    connection_id = %context.connection_id,
                    cleaned_resources = context.cleaned_resources.len(),
                    failed_resources = context.failed_resources.len(),
                    "Resource cleanup completed"
                );
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                warn!(
                    connection_id = %self.context.read().await.connection_id,
                    "Resource cleanup timeout"
                );
                Ok(()) // Continue with termination even if resource cleanup times out
            }
        }
    }

    /// Force cleanup sessions
    async fn force_cleanup_sessions(&self) {
        let active_sessions = {
            let context = self.context.read().await;
            context.active_sessions.clone()
        };

        // Mark all sessions as failed (force termination doesn't wait for callbacks)
        let mut context = self.context.write().await;
        context.failed_sessions.extend(active_sessions);

        debug!(
            connection_id = %context.connection_id,
            failed_sessions = context.failed_sessions.len(),
            "Force session cleanup completed"
        );
    }

    /// Force cleanup resources
    async fn force_cleanup_resources(&self) {
        let resources_to_cleanup = {
            let context = self.context.read().await;
            context.resources_to_cleanup.clone()
        };

        // Mark all resources as failed (force termination doesn't wait for callbacks)
        let mut context = self.context.write().await;
        context.failed_resources.extend(resources_to_cleanup);

        debug!(
            connection_id = %context.connection_id,
            failed_resources = context.failed_resources.len(),
            "Force resource cleanup completed"
        );
    }

    /// Finalize termination
    async fn finalize_termination(&self) -> SessionResult<()> {
        self.transition_to_state(TerminationState::Finalizing)
            .await?;

        // Perform final validation and cleanup
        let context = self.context.read().await;

        debug!(
            connection_id = %context.connection_id,
            terminated_sessions = context.terminated_sessions.len(),
            failed_sessions = context.failed_sessions.len(),
            cleaned_resources = context.cleaned_resources.len(),
            failed_resources = context.failed_resources.len(),
            "Connection termination finalized"
        );

        Ok(())
    }

    /// Transition to new state
    ///
    /// M2 spec: Termination state transitions are logged with structured tracing
    /// for observability and debugging of the FIN handshake process.
    async fn transition_to_state(&self, new_state: TerminationState) -> SessionResult<()> {
        let old_state = self.current_state().await;

        if old_state == new_state {
            return Ok(());
        }

        new_state.store(&self.state, std::sync::atomic::Ordering::Relaxed);

        let connection_id = self.context.read().await.connection_id;

        // M2 spec: Log termination state transitions with structured fields
        info!(
            connection_id = %connection_id,
            from_state = ?old_state,
            to_state = ?new_state,
            from_u8 = old_state.as_u8(),
            to_u8 = new_state.as_u8(),
            is_terminal = new_state.is_terminal(),
            "Termination state transition"
        );

        debug!(
            "Termination state transition: connection_id={}, old_state={:?}, new_state={:?}",
            connection_id, old_state, new_state
        );

        Ok(())
    }

    /// Start timeout task (for non-Arc contexts)
    async fn start_timeout_task(&self) {
        let timeout_duration = Duration::from_millis(self.config.graceful_timeout.as_millis());
        let state_clone = self.state.clone();
        let force_after_timeout = self.config.force_after_timeout;
        let connection_id = self.context.read().await.connection_id;

        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout_duration).await;

            let current_state = TerminationState::load(&state_clone, Ordering::Relaxed);

            if !current_state.is_terminal() {
                if force_after_timeout {
                    // Mark as force terminated
                    TerminationState::ForceTerminated.store(&state_clone, Ordering::Relaxed);
                } else {
                    // Mark as timeout
                    TerminationState::Timeout.store(&state_clone, Ordering::Relaxed);
                }

                warn!(
                    connection_id = %connection_id,
                    "Connection termination timeout"
                );
            }
        });

        *self.timeout_handle.lock().await = Some(handle);
    }

    /// Stop timeout
    async fn stop_timeout(&self) {
        if let Some(handle) = self.timeout_handle.lock().await.take() {
            handle.abort();
        }
    }

    /// Get termination statistics
    pub async fn get_stats(&self) -> TerminationStats {
        self.stats.read().await.clone()
    }

    /// Get termination duration
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Drop for ConnectionTermination {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd use a proper shutdown mechanism
        if let Ok(mut handle) = self.timeout_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}
