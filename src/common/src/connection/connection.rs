// Connection abstraction that owns sessions and coordinates engines
//
// This implements the corrected architecture where Connection is the primary
// abstraction that owns multiple sessions and coordinates all engines.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::net::SocketAddr;
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::engines::flow_control::FlowControlEngine;
use crate::error::BuckwildError;
use crate::protocol::fragmentation::FragmentationEngine;
use crate::protocol::packet::{Packet, builder::PacketBuilderEngine};
use crate::protocol::types::SessionKey;
use crate::protocol::types::*;
use crate::security::crypto::hmac::HmacCalculator;
use crate::session::{SessionEngine, SessionEngineConfig, SessionState};
use arrayref::array_ref;
use bytes::Bytes;

// Use consolidated types
use crate::error::CryptographicError;
use crate::protocol::types::{
    AckNumber, ConnectionId, FragmentSize, MtuSize, SequenceNumber, SessionCount, SessionId,
    SessionIdLength, Timeout, Timestamp, TimestampConfig, VersionByte, WindowSize,
};

// Use consolidated ConnectionState from protocol types
use crate::protocol::types::ConnectionState;

/// Connection configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Connection timeout
    pub connection_timeout: Timeout,

    /// Heartbeat interval
    pub heartbeat_interval: Timeout,

    /// Maximum sessions per connection
    pub max_sessions_per_connection: crate::protocol::types::SessionCount,

    /// Enable connection recovery
    pub enable_recovery: bool,

    /// Recovery timeout
    pub recovery_timeout: Timeout,

    /// Maximum transmission unit (MTU)
    pub mtu: MtuSize,

    /// Maximum fragment size for packet fragmentation
    pub max_fragment_size: FragmentSize,

    /// Default HMAC policy
    pub hmac_policy: HmacPolicy,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Timeout::from_millis(30_000), // 30 seconds
            heartbeat_interval: Timeout::from_millis(5_000),  // 5 seconds
            max_sessions_per_connection: SessionCount::new(100),
            enable_recovery: true,
            recovery_timeout: Timeout::from_millis(10_000), // 10 seconds
            mtu: MtuSize::from_raw(1500),
            max_fragment_size: FragmentSize::from_raw(1400),
            hmac_policy: HmacPolicy::Medium,
        }
    }
}

// Connection statistics removed - use tokio-tracing events for metrics per design/rules.md
// Emit tracing::trace! events when packets are sent/received instead of collecting counters

/// Connection that owns sessions and coordinates engines
pub struct Connection {
    /// Connection ID
    connection_id: ConnectionId,

    /// Local endpoint
    local_endpoint: SocketAddr,

    /// Remote endpoint
    remote_endpoint: SocketAddr,

    /// Connection state
    state: SyncState,

    /// Creation time
    created_at: Instant,

    /// Last activity timestamp
    last_activity: AtomicMeasurementTimestamp,

    /// Configuration
    pub config: ConnectionConfig,

    /// Session engine (operates as an engine within this connection)
    session_engine: Arc<SessionEngine>,

    /// Flow control engine (per-connection)
    flow_control: Arc<FlowControlEngine>,

    /// Fragmentation engine (shared, but connection-aware)
    fragmentation_engine: Arc<FragmentationEngine>,

    /// Active sessions in this connection
    active_sessions: DashMap<SessionId, Arc<SessionState>>,

    /// Session creation order (for cleanup)
    session_creation_order: RwLock<Vec<SessionId>>,
}

impl Connection {
    /// Create a new connection
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        config: ConnectionConfig,
    ) -> Self {
        let current_time = Timestamp::now();

        // Create connection-specific engines
        let session_engine = Arc::new(SessionEngine::new(SessionEngineConfig::default()));
        let flow_control = Arc::new(FlowControlEngine::new(
            connection_id,
            SessionId::new_with_length(0, SessionIdLength::Bits32), // Default session ID for connection-level flow control
            0,                                                      // Initial send sequence
            0,                                                      // Initial receive sequence
        ));
        let fragmentation_engine = Arc::new(FragmentationEngine::new());

        Self {
            connection_id,
            local_endpoint,
            remote_endpoint,
            state: SyncState::new(ConnectionState::Closed.as_u8()),
            created_at: Instant::now(),
            last_activity: AtomicMeasurementTimestamp::new(current_time.as_nanos()),
            config,
            session_engine,
            flow_control,
            fragmentation_engine,
            active_sessions: DashMap::new(),
            session_creation_order: RwLock::new(Vec::new()),
        }
    }

    /// Get connection ID
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Get local endpoint
    pub fn local_endpoint(&self) -> SocketAddr {
        self.local_endpoint
    }

    /// Get remote endpoint
    pub fn remote_endpoint(&self) -> SocketAddr {
        self.remote_endpoint
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
            .unwrap_or(ConnectionState::Error)
    }

    /// Set connection state
    pub fn set_state(&self, new_state: ConnectionState) {
        let old_state = self.state();
        self.state.store(new_state.as_u8(), Ordering::Relaxed);

        debug!(
            connection_id = %self.connection_id,
            old_state = ?old_state,
            new_state = ?new_state,
            "Connection state changed"
        );
    }

    /// Update last activity
    pub fn update_activity(&self) {
        let current_time = Timestamp::now();
        self.last_activity
            .store(current_time.as_u64(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Check if connection is idle
    pub fn is_idle(&self, timeout: Timeout) -> bool {
        let current_time = Timestamp::now();
        let last_activity = Timestamp::from_raw(self.last_activity.load(Ordering::Relaxed));

        let idle_duration = (current_time.as_u64()).saturating_sub(last_activity.as_u64());
        idle_duration >= (timeout.as_u64()) * 1_000_000 // Convert millis to nanos
    }

    /// Create a new session within this connection
    pub async fn create_session(&self) -> Result<(SessionId, Arc<SessionState>), BuckwildError> {
        // Check session limit
        if self.active_sessions.len() >= self.config.max_sessions_per_connection.as_usize() {
            warn!(
                connection_id = %self.connection_id,
                current_sessions = self.active_sessions.len(),
                max_sessions = %self.config.max_sessions_per_connection,
                "Session limit exceeded for connection"
            );
            return Err(BuckwildError::resource_exhausted("Session limit exceeded"));
        }

        // Create session using the connection's session engine
        let (session_id, session_state) = self.session_engine.create_session().map_err(|e| {
            BuckwildError::security_error(format!("Failed to create session: {}", e))
        })?;

        // Add to active sessions
        self.active_sessions
            .insert(session_id.clone(), session_state.clone());

        // Track creation order
        {
            let mut creation_order = self.session_creation_order.write().await;
            creation_order.push(session_id.clone());
        }

        // Session engines already have the session registered via session_state
        // Flow control state is managed within SessionState.window_state

        tracing::trace!(session_id = %session_id, "Session created");

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id,
            total_sessions = self.active_sessions.len(),
            "Session created in connection"
        );

        Ok((session_id, session_state))
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &SessionId) -> Option<Arc<SessionState>> {
        self.active_sessions
            .get(session_id)
            .map(|entry| entry.clone())
    }

    /// Remove a session from this connection
    pub async fn remove_session(&self, session_id: &SessionId) -> bool {
        if let Some((_, _session_state)) = self.active_sessions.remove(session_id) {
            // Remove from session engine
            self.session_engine.remove_session(session_id);

            // Update creation order
            {
                let mut creation_order = self.session_creation_order.write().await;
                creation_order.retain(|id| id != session_id);
            }

            tracing::trace!(session_id = %session_id, "Session removed");

            info!(
                connection_id = %self.connection_id,
                session_id = %session_id,
                remaining_sessions = self.active_sessions.len(),
                "Session removed from connection"
            );

            true
        } else {
            false
        }
    }

    /// Get all active session IDs
    pub fn get_active_session_ids(&self) -> Vec<SessionId> {
        self.active_sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Process incoming packet
    pub async fn process_packet(
        &self,
        packet: Packet,
        source_addr: SocketAddr,
    ) -> Result<(), BuckwildError> {
        self.update_activity();

        tracing::trace!(source = %source_addr, bytes = packet.total_size(), "Packet received");

        // Extract session ID from packet
        let session_id = packet.session_id();

        // Get or create session for this packet
        let session_state = if let Some(session) = self.get_session(&session_id) {
            session
        } else {
            // For new sessions, create them automatically
            let (new_session_id, session_state) = self.create_session().await?;
            if new_session_id != session_id {
                warn!(
                    connection_id = %self.connection_id,
                    expected_session = %session_id,
                    created_session = %new_session_id,
                    "Session ID mismatch during auto-creation"
                );
            }
            session_state
        };

        // Process packet through engines in coordination
        self.coordinate_packet_processing(packet, session_state, source_addr)
            .await
    }

    /// Coordinate packet processing across all engines
    async fn coordinate_packet_processing(
        &self,
        packet: Packet,
        session_state: Arc<SessionState>,
        source_addr: SocketAddr,
    ) -> Result<(), BuckwildError> {
        // 1. Time synchronization (if needed)
        if packet.packet_type() == crate::protocol::types::PacketType::Heartbeat {
            // Heartbeat processing handled by session state updates
            session_state.update_activity();
        }

        // 2. Port hopping validation handled by port hopping engine per session

        // 3. Fragment processing (if fragmented)
        let processed_data = if packet.flags().is_frag() {
            let frag_request = crate::protocol::fragmentation::ReassemblyRequest {
                fragment: match packet.clone() {
                    Packet::Data(data_packet) => data_packet,
                    _ => {
                        return Err(BuckwildError::invalid_state(
                            "Expected data packet for fragmentation",
                        ));
                    }
                },
                source_ip: match source_addr {
                    SocketAddr::V4(addr) => u32::from(*addr.ip()),
                    SocketAddr::V6(_) => {
                        return Err(BuckwildError::network_error("IPv6 not supported"));
                    }
                },
            };

            match self.fragmentation_engine.process_fragment(frag_request)? {
                crate::protocol::fragmentation::ReassemblyResult::Complete { packet, .. } => {
                    Some(packet.payload)
                }
                crate::protocol::fragmentation::ReassemblyResult::InProgress { .. } => None,
                crate::protocol::fragmentation::ReassemblyResult::Rejected { .. } => None,
            }
        } else {
            Some(Bytes::copy_from_slice(packet.payload()))
        };

        // 4. Flow control processing (if we have complete data)
        if let Some(_data) = processed_data {
            // Flow control state tracked in session_state.window_state
            session_state.update_activity();
        }

        // 5. Update session state
        session_state.update_activity();

        Ok(())
    }

    /// Send data through this connection
    pub async fn send_data(
        &self,
        session_id: SessionId,
        data: bytes::Bytes,
    ) -> Result<(), BuckwildError> {
        let _session_state = self
            .get_session(&session_id)
            .ok_or_else(|| BuckwildError::invalid_state("Session not found"))?;

        // Update activity
        self.update_activity();

        // Check if fragmentation is needed
        if data.len() > self.config.max_sessions_per_connection.as_usize() {
            // Fragment the data
            let hmac_policy = self.config.hmac_policy;

            // Extract session key from session parameters
            let mut session_key_bytes = Vec::with_capacity(32);
            for i in 0..16 {
                if let Some(chunk) = _session_state.session_param(i) {
                    session_key_bytes.extend_from_slice(&chunk.to_be_bytes());
                } else {
                    // If session params not available, derive temporary key from session_id
                    session_key_bytes.extend_from_slice(&session_id.as_u64().to_be_bytes());
                    session_key_bytes.extend_from_slice(&self.connection_id.0.to_be_bytes());
                    break;
                }
            }
            // Pad to 32 bytes if needed
            session_key_bytes.resize(32, 0);
            let session_key = SessionKey::new(*array_ref![session_key_bytes, 0, 32]);

            // Build data packet using PacketBuilderEngine
            let version_byte =
                VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
            let packet_builder = PacketBuilderEngine::with_defaults(version_byte, hmac_policy);

            // Get proper sequence number from session state and increment
            let current_seq = _session_state.get_send_sequence();
            let next_seq = SequenceNumber::new(current_seq.as_u32() + 1);
            _session_state.set_send_sequence(next_seq);

            let mut data_packet = packet_builder
                .data()
                .session_id(session_id.clone())
                .sequence_number(next_seq)
                .ack_number(AckNumber::new(0))
                .window_size(WindowSize::new(65535))
                .payload(data.clone())
                .build()
                .map_err(|e| {
                    BuckwildError::invalid_state(format!("Packet builder failed: {:?}", e))
                })?;

            // Calculate HMAC over header fields + payload
            let mut packet_data_for_hmac = Vec::new();
            packet_data_for_hmac.extend_from_slice(&session_id.as_u64().to_be_bytes());
            packet_data_for_hmac.extend_from_slice(&data);

            let hmac_calculator = HmacCalculator::new();
            let hmac = hmac_calculator
                .calculate_packet_hmac(&packet_data_for_hmac, session_key.as_bytes(), hmac_policy)
                .map_err(|e| {
                    BuckwildError::Cryptographic(CryptographicError::HmacGenerationFailed {
                        reason: format!("{:?}", e),
                    })
                })?;

            // Update packet with calculated HMAC
            data_packet.hmac = hmac;

            let frag_request = crate::protocol::fragmentation::engine::FragmentationRequest {
                session_id: session_id.clone(),
                packet: data_packet,
                max_fragment_size: Some(self.config.max_fragment_size.as_usize()),
                source_ip: match self.local_endpoint {
                    std::net::SocketAddr::V4(addr) => (*addr.ip()).into(),
                    std::net::SocketAddr::V6(addr) => {
                        // Use first 4 bytes of IPv6 address as source IP identifier
                        let segments = addr.ip().segments();
                        ((segments[0] as u32) << 16) | (segments[1] as u32)
                    }
                },
            };

            let frag_result = self.fragmentation_engine.fragment_packet(frag_request)?;

            // Send all fragments through flow control
            for fragment in frag_result.fragments {
                self.flow_control
                    .send_data(fragment.payload.clone())
                    .await?;
            }
        } else {
            // Send directly through flow control
            self.flow_control.send_data(data.clone()).await?;
        }

        tracing::trace!(session_id = %session_id, bytes = data.len(), "Data sent");

        Ok(())
    }

    /// Start connection recovery
    /// Per M2 acceptance criteria: Recovery sub-states accessible only from ESTABLISHED state
    pub async fn start_recovery(&self) -> Result<(), BuckwildError> {
        if !self.config.enable_recovery {
            return Err(BuckwildError::configuration_error("Recovery disabled"));
        }

        // Enforce that recovery can only be started from ESTABLISHED state
        let current_state = self.state();
        if current_state != ConnectionState::Established {
            return Err(BuckwildError::invalid_state(format!(
                "Recovery can only be started from ESTABLISHED state, current state: {:?}",
                current_state
            )));
        }

        self.set_state(ConnectionState::Recovering);

        // Recovery coordinated through recovery engine per-session state

        info!(
            connection_id = %self.connection_id,
            "Connection recovery started"
        );

        Ok(())
    }

    /// Close connection gracefully
    pub async fn close(&self) -> Result<(), BuckwildError> {
        self.set_state(ConnectionState::Closing);

        // Close all sessions
        let session_ids = self.get_active_session_ids();
        for session_id in session_ids {
            self.remove_session(&session_id).await;
        }

        // Clean up engines
        self.flow_control.shutdown().await?;

        self.set_state(ConnectionState::Closed);

        info!(
            connection_id = %self.connection_id,
            "Connection closed gracefully"
        );

        Ok(())
    }

    // get_stats() removed - use tokio-tracing subscribers to collect metrics

    /// Get connection age (operational - used for cleanup decisions)
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if connection should be cleaned up (operational - used for cleanup logic)
    pub fn should_cleanup(&self) -> bool {
        // Cleanup if:
        // 1. No active sessions AND
        // 2. Inactive for more than idle timeout
        if self.active_sessions.is_empty() {
            let idle_duration = self
                .last_activity
                .get()
                .saturating_sub(Timestamp::now().as_u64());
            idle_duration > 300_000_000_000 // 5 minutes in nanoseconds
        } else {
            false
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("connection_id", &self.connection_id)
            .field("local_endpoint", &self.local_endpoint)
            .field("remote_endpoint", &self.remote_endpoint)
            .field("state", &self.state())
            .field("session_count", &self.session_count())
            .field("age", &self.age())
            .finish()
    }
}
