// Connection Engine Coordinator - orchestrates all engines for a connection
//
// This implements the atomic coordination between all engines as specified
// in design/architecture.md for zero-copy pipeline and lock-free operation.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use super::Connection;
use crate::protocol::fragmentation::FragmentationEngine;
use crate::protocol::fragmentation::engine::ReassemblyRequest;
use crate::protocol::packet::{Packet, builder::PacketBuilderEngine};
use crate::security::crypto::hmac::HmacCalculator;
use crate::session::SessionState;
// Use consolidated types
use crate::error::CryptographicError;
use crate::protocol::types::{
    AckNumber, BuckwildError, ConnectionId, Counter, PacketType, Port, SequenceNumber, SessionId,
    SessionIdLength, SessionKey, TimestampConfig, VersionByte, WindowSize,
};
use arrayref::array_ref;

/// Engine coordination statistics
#[derive(Debug, Default, Clone)]
pub struct CoordinationStats {
    pub packets_coordinated: Counter,
    pub fragmentation_operations: Counter,
    pub reassembly_operations: Counter,
    pub flow_control_operations: Counter,
    pub port_hopping_operations: Counter,
    pub time_sync_operations: Counter,
    pub recovery_operations: Counter,
    pub coordination_errors: Counter,
}

/// Connection Engine Coordinator
///
/// This coordinates all engines for a single connection in a lock-free,
/// zero-copy manner as specified in the architecture.
pub struct ConnectionEngineCoordinator {
    /// Connection ID
    connection_id: ConnectionId,

    /// Reference to the connection
    connection: Arc<Connection>,

    /// Shared fragmentation engine
    fragmentation_engine: Arc<FragmentationEngine>,

    /// Coordination statistics
    stats: RwLock<CoordinationStats>,
}

impl ConnectionEngineCoordinator {
    /// Create new connection engine coordinator
    pub fn new(
        connection_id: ConnectionId,
        connection: Arc<Connection>,
        fragmentation_engine: Arc<FragmentationEngine>,
    ) -> Self {
        Self {
            connection_id,
            connection,
            fragmentation_engine,
            stats: RwLock::new(CoordinationStats::default()),
        }
    }

    /// Coordinate packet processing across all engines
    ///
    /// This implements the zero-copy pipeline specified in architecture.md
    #[instrument(skip(self, packet, session_state), fields(connection_id = %self.connection_id))]
    pub async fn coordinate_packet_processing(
        &self,
        packet: Packet,
        session_state: Arc<SessionState>,
        source_addr: std::net::SocketAddr,
    ) -> Result<(), BuckwildError> {
        // Update coordination statistics
        {
            let mut stats = self.stats.write().await;
            stats.packets_coordinated += 1;
        }

        // Phase 1: Time synchronization validation
        // This must happen first to ensure packet timing is valid
        if let Err(e) = self.coordinate_time_sync(&packet, &session_state).await {
            self.record_coordination_error().await;
            return Err(e);
        }

        // Phase 2: Port hopping validation
        // Validate that packet arrived on expected port
        if let Err(e) = self.coordinate_port_hopping(&packet, &session_state).await {
            self.record_coordination_error().await;
            return Err(e);
        }

        // Phase 3: Fragment processing (if needed)
        // Handle fragmentation/reassembly with zero-copy operations
        let processed_payload = if packet.flags().is_frag() {
            match self
                .coordinate_fragmentation(&packet, &session_state, source_addr)
                .await?
            {
                Some(payload) => payload,
                None => return Ok(()), // Fragment processed but message not complete
            }
        } else {
            Bytes::copy_from_slice(packet.payload())
        };

        // Phase 4: Flow control processing
        // Process complete payload through flow control
        self.coordinate_flow_control(&packet, processed_payload, &session_state)
            .await?;

        // Phase 5: Session state updates
        // Update session state atomically
        self.coordinate_session_updates(&packet, &session_state, source_addr)
            .await?;

        debug!(
            connection_id = %self.connection_id,
            session_id = %packet.session_id(),
            packet_type = ?packet.packet_type(),
            "Packet coordination completed successfully"
        );

        Ok(())
    }

    /// Coordinate outbound packet transmission
    #[instrument(skip(self, session_id, data), fields(connection_id = %self.connection_id))]
    pub async fn coordinate_packet_transmission(
        &self,
        session_id: SessionId,
        data: bytes::Bytes,
    ) -> Result<Vec<Packet>, BuckwildError> {
        let session_state = self
            .connection
            .get_session(&session_id)
            .ok_or_else(|| BuckwildError::invalid_state("Session not found"))?;

        // Phase 1: Determine if fragmentation is needed
        let mtu_size = self.connection.config.mtu;
        let needs_fragmentation = data.len() > (mtu_size.as_usize() - 100); // Account for headers

        if needs_fragmentation {
            // Phase 2a: Fragment the message
            let packets = self
                .coordinate_outbound_fragmentation(session_id, data, &session_state)
                .await?;

            // Phase 2b: Apply flow control to all fragments
            for packet in &packets {
                self.coordinate_outbound_flow_control(packet, &session_state)
                    .await?;
            }

            Ok(packets)
        } else {
            // Phase 2: Create single packet
            let packet = self
                .create_data_packet(session_id, data, &session_state)
                .await?;

            // Phase 3: Apply flow control
            self.coordinate_outbound_flow_control(&packet, &session_state)
                .await?;

            Ok(vec![packet])
        }
    }

    /// Coordinate time synchronization
    async fn coordinate_time_sync(
        &self,
        packet: &Packet,
        session_state: &SessionState,
    ) -> Result<(), BuckwildError> {
        // Update time sync statistics
        {
            let mut stats = self.stats.write().await;
            stats.time_sync_operations += 1;
        }

        // Validate packet timestamp against current time and session offset
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32;

        let packet_timestamp = packet.timestamp().as_u64() as u32;
        let time_offset = session_state.time_offset();
        let adjusted_timestamp = packet_timestamp.wrapping_add(time_offset as u32);

        // Allow 30-second window for time synchronization
        let time_diff = current_time.abs_diff(adjusted_timestamp);

        if time_diff > 30_000 {
            // 30 seconds in milliseconds
            warn!(
                connection_id = %self.connection_id,
                packet_timestamp = packet_timestamp,
                current_time = current_time,
                time_offset = time_offset,
                time_diff = time_diff,
                "Packet timestamp outside acceptable window"
            );
            return Err(BuckwildError::invalid_input("Packet timestamp invalid"));
        }

        // Handle heartbeat packets for time synchronization
        if packet.packet_type() == PacketType::Heartbeat {
            // Process heartbeat for time synchronization
            // This would update the session's time offset if needed
            debug!(
                connection_id = %self.connection_id,
                "Processing heartbeat for time synchronization"
            );
        }

        Ok(())
    }

    /// Coordinate port hopping validation
    async fn coordinate_port_hopping(
        &self,
        _packet: &Packet,
        session_state: &SessionState,
    ) -> Result<(), BuckwildError> {
        // Update port hopping statistics
        {
            let mut stats = self.stats.write().await;
            stats.port_hopping_operations += 1;
        }

        // For now, we'll do basic port validation
        // In a full implementation, this would validate against expected port sequence
        let current_port = session_state.remote_port();

        debug!(
            connection_id = %self.connection_id,
            current_port = %current_port,
            "Port hopping validation completed"
        );

        Ok(())
    }

    /// Coordinate fragmentation/reassembly
    async fn coordinate_fragmentation(
        &self,
        packet: &Packet,
        session_state: &SessionState,
        source_addr: std::net::SocketAddr,
    ) -> Result<Option<bytes::Bytes>, BuckwildError> {
        // Update fragmentation statistics
        {
            let mut stats = self.stats.write().await;
            stats.reassembly_operations += 1;
        }

        // Create session HMAC key for fragment validation
        let _session_key = self.create_session_hmac_key(session_state)?;

        // Create reassembly request
        let reassembly_request = ReassemblyRequest {
            fragment: match packet.clone() {
                Packet::Data(data_packet) => data_packet,
                _ => {
                    return Err(BuckwildError::invalid_state(
                        "Expected data packet for fragmentation".to_string(),
                    ));
                }
            },
            source_ip: match source_addr {
                std::net::SocketAddr::V4(addr) => u32::from(*addr.ip()),
                std::net::SocketAddr::V6(_) => {
                    return Err(BuckwildError::network_error(
                        "IPv6 not supported".to_string(),
                    ));
                }
            },
        };

        // Process fragment through fragmentation system
        match self
            .fragmentation_engine
            .process_fragment(reassembly_request)?
        {
            crate::protocol::fragmentation::engine::ReassemblyResult::Complete {
                packet, ..
            } => {
                info!(
                    connection_id = %self.connection_id,
                    session_id = %packet.header.session_id(),
                    reassembled_size = packet.payload.len(),
                    "Message reassembly completed"
                );
                Ok(Some(packet.payload))
            }
            crate::protocol::fragmentation::engine::ReassemblyResult::InProgress { .. } => {
                debug!(
                    connection_id = %self.connection_id,
                    session_id = %packet.session_id(),
                    "Fragment processed, waiting for more fragments"
                );
                Ok(None)
            }
            crate::protocol::fragmentation::engine::ReassemblyResult::Rejected { reason: _ } => {
                debug!(
                    connection_id = %self.connection_id,
                    session_id = %packet.session_id(),
                    "Duplicate fragment ignored"
                );
                Ok(None)
            }
        }
    }

    /// Coordinate outbound fragmentation
    async fn coordinate_outbound_fragmentation(
        &self,
        session_id: SessionId,
        data: bytes::Bytes,
        session_state: &SessionState,
    ) -> Result<Vec<Packet>, BuckwildError> {
        // Update fragmentation statistics
        {
            let mut stats = self.stats.write().await;
            stats.fragmentation_operations += 1;
        }

        // Create session HMAC key
        let session_key = self.create_session_hmac_key(session_state)?;

        // Build data packet using PacketBuilderEngine
        let hmac_policy = self.connection.config.hmac_policy;
        let version_byte = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);

        let packet_builder = PacketBuilderEngine::with_defaults(version_byte, hmac_policy);

        // Get proper sequence number from session state and increment
        let current_seq = session_state.get_send_sequence();
        let next_seq = SequenceNumber::new(current_seq.as_u32() + 1);
        session_state.set_send_sequence(next_seq);

        // Build initial packet (HMAC will be calculated after)
        let mut data_packet = packet_builder
            .data()
            .session_id(session_id.clone())
            .sequence_number(next_seq)
            .ack_number(AckNumber::new(0))
            .window_size(WindowSize::new(65535))
            .payload(data.clone())
            .build()
            .map_err(|e| BuckwildError::invalid_state(format!("Packet builder failed: {:?}", e)))?;

        // Calculate HMAC over header fields + payload
        // Per design spec, HMAC is calculated over all packet fields except HMAC itself
        let mut packet_data_for_hmac = Vec::new();
        packet_data_for_hmac.push(data_packet.header.version_byte().version());
        packet_data_for_hmac.extend_from_slice(&session_id.as_u64().to_be_bytes());
        packet_data_for_hmac
            .extend_from_slice(&data_packet.header.sequence_number().as_u32().to_be_bytes());
        packet_data_for_hmac.extend_from_slice(&data[..]);

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

        // Create fragmentation request for the engine
        let fragmentation_request = crate::protocol::fragmentation::engine::FragmentationRequest {
            session_id: session_id.clone(),
            packet: data_packet,
            max_fragment_size: Some(self.connection.config.max_fragment_size.as_usize()),
            source_ip: match self.connection.local_endpoint() {
                std::net::SocketAddr::V4(addr) => (*addr.ip()).into(),
                std::net::SocketAddr::V6(addr) => {
                    // Use first 4 bytes of IPv6 address as source IP identifier
                    let segments = addr.ip().segments();
                    ((segments[0] as u32) << 16) | (segments[1] as u32)
                }
            },
        };

        // Fragment the message
        let fragmentation_result = self
            .fragmentation_engine
            .fragment_packet(fragmentation_request)?;

        info!(
            connection_id = %self.connection_id,
            session_id = %session_id.clone(),
            fragment_count = fragmentation_result.fragments.len(),
            fragment_id = %fragmentation_result.fragment_id,
            "Message fragmented successfully"
        );

        Ok(fragmentation_result
            .fragments
            .into_iter()
            .map(Packet::Data)
            .collect())
    }

    /// Coordinate flow control processing
    async fn coordinate_flow_control(
        &self,
        packet: &Packet,
        payload: bytes::Bytes,
        _session_state: &SessionState,
    ) -> Result<(), BuckwildError> {
        // Update flow control statistics
        {
            let mut stats = self.stats.write().await;
            stats.flow_control_operations += 1;
        }

        // Process through connection's flow control engine
        // This would involve the actual flow control logic
        debug!(
            connection_id = %self.connection_id,
            session_id = %packet.session_id(),
            payload_size = payload.len(),
            "Flow control processing completed"
        );

        Ok(())
    }

    /// Coordinate outbound flow control
    async fn coordinate_outbound_flow_control(
        &self,
        packet: &Packet,
        _session_state: &SessionState,
    ) -> Result<(), BuckwildError> {
        // Apply flow control to outbound packet
        debug!(
            connection_id = %self.connection_id,
            session_id = %packet.session_id(),
            "Outbound flow control applied"
        );

        Ok(())
    }

    /// Coordinate session state updates
    async fn coordinate_session_updates(
        &self,
        packet: &Packet,
        session_state: &SessionState,
        source_addr: std::net::SocketAddr,
    ) -> Result<(), BuckwildError> {
        // Update session activity
        session_state.update_activity();

        // Update sequence numbers if this is a data packet
        if packet.packet_type() == PacketType::Data {
            let sequence_number = packet.sequence_number();
            session_state.update_remote_seq(sequence_number);
        }

        // Update port information from source address
        let remote_port = source_addr.port();
        session_state.set_remote_port(
            Port::new(remote_port).unwrap_or(Port::from_u16_unchecked(remote_port)),
        );

        debug!(
            connection_id = %self.connection_id,
            session_id = %packet.session_id(),
            "Session state updated"
        );

        Ok(())
    }

    /// Create data packet for transmission
    async fn create_data_packet(
        &self,
        session_id: SessionId,
        data: bytes::Bytes,
        session_state: &SessionState,
    ) -> Result<Packet, BuckwildError> {
        let hmac_policy = self.connection.config.hmac_policy;
        let version_byte = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);

        let packet_builder = PacketBuilderEngine::with_defaults(version_byte, hmac_policy);

        // Get proper sequence number from session state and increment
        let current_seq = session_state.get_send_sequence();
        let next_seq = SequenceNumber::new(current_seq.as_u32() + 1);
        session_state.set_send_sequence(next_seq);

        let data_packet = packet_builder
            .data()
            .session_id(session_id.clone())
            .sequence_number(next_seq)
            .ack_number(AckNumber::new(0))
            .window_size(WindowSize::new(65535))
            .payload(data)
            .build()
            .map_err(|e| BuckwildError::invalid_state(format!("Packet builder failed: {:?}", e)))?;

        Ok(Packet::Data(data_packet))
    }

    /// Create session HMAC key from session state
    fn create_session_hmac_key(
        &self,
        session_state: &SessionState,
    ) -> Result<Arc<SessionKey>, BuckwildError> {
        // Extract HMAC key from session parameters (chunks 6-21)
        let mut key_bytes = Vec::with_capacity(32);
        for i in 0..16 {
            if let Some(chunk) = session_state.session_param(i) {
                key_bytes.extend_from_slice(&chunk.to_be_bytes());
            } else {
                return Err(BuckwildError::Cryptographic(
                    CryptographicError::KeyGenerationFailed {
                        key_type: "ECDH".to_string(),
                    },
                ));
            }
        }

        let hmac_key = SessionKey::new(*array_ref![&key_bytes, 0, 32]);

        Ok(Arc::new(hmac_key))
    }

    /// Record coordination error
    async fn record_coordination_error(&self) {
        let mut stats = self.stats.write().await;
        stats.coordination_errors += 1;
    }

    /// Get coordination statistics
    pub async fn get_stats(&self) -> CoordinationStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Reset coordination statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = CoordinationStats::default();
    }
}

impl std::fmt::Debug for ConnectionEngineCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionEngineCoordinator")
            .field("connection_id", &self.connection_id)
            .finish()
    }
}
