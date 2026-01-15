#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Recovery Strategies - Implementation of different recovery strategies
//
// This module implements the various recovery strategies including time sync,
// sequence repair, session rekeying, and emergency recovery procedures.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, instrument, warn};

use crate::engines::recovery::{RecoveryCoordination, RecoveryResult};
use crate::error::EngineError;
use crate::protocol::packet::PacketBuilderEngine;
use crate::protocol::packet::structures::*;
use crate::protocol::types::*;
use crate::security::crypto::ecdh::ThreadSafeEcdhManager;
use crate::session::SessionState;
use bytes::Bytes;

/// Recovery strategies implementation
pub struct RecoveryStrategies {
    /// Random number generator
    rng: SystemRandom,
    /// Packet builder engine for creating protocol packets
    packet_builder: PacketBuilderEngine,
}

impl RecoveryStrategies {
    /// Create new recovery strategies
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
            packet_builder: PacketBuilderEngine::new(),
        }
    }

    /// Execute time synchronization recovery
    #[instrument(skip(self, _session_state, coordination), fields(session_id = %session_id))]
    pub async fn execute_time_sync_recovery(
        &self,
        session_id: SessionId,
        _session_state: Arc<SessionState>,
        coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        info!(
            session_id = %session_id,
            "Executing time synchronization recovery"
        );

        // Generate challenge nonce for security
        let mut challenge_nonce = [0u8; 4];
        if self.rng.fill(&mut challenge_nonce).is_err() {
            error!("Failed to generate challenge nonce");
            return Ok(RecoveryResult::CryptoError);
        }
        let challenge_nonce = RecoveryNonce::new(u32::from_be_bytes(challenge_nonce));

        // Get current local timestamp with high precision
        let local_timestamp = Timestamp::now();

        // Create time sync request packet
        let sync_request = self
            .create_time_sync_request_packet(session_id.clone(), challenge_nonce, local_timestamp)
            .await?;

        let send_time = Instant::now();

        // Note: In a real implementation, we would store pending request for response matching

        // Send the packet (this would be implemented with actual packet transmission)
        if !coordination.send_recovery_packet(sync_request).await {
            return Ok(RecoveryResult::NetworkError);
        }

        // Wait for response with timeout
        let sync_response = match timeout(
            Duration::from_millis(TIME_RESYNC_TIMEOUT_MS.as_millis()),
            self.receive_time_sync_response(session_id.clone(), challenge_nonce),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                error!(error = ?e, "Time sync response error");
                return Ok(RecoveryResult::NetworkError);
            }
            Err(_) => {
                warn!("Time sync request timed out");
                return Ok(RecoveryResult::Timeout);
            }
        };

        let receive_time = Instant::now();

        // Validate response nonce
        if sync_response.challenge_nonce.as_u32() != challenge_nonce.as_u32() {
            warn!(
                expected_nonce = challenge_nonce.as_u32(),
                received_nonce = sync_response.challenge_nonce.as_u32(),
                "Time sync response nonce mismatch"
            );
            return Ok(RecoveryResult::InvalidNonce);
        }

        // Calculate time offset using NTP-style algorithm
        let rtt = receive_time.duration_since(send_time).as_millis() as i64;
        let peer_timestamp = sync_response.peer_timestamp.as_u64() as i64;
        let local_send_timestamp = local_timestamp.as_u64() as i64;
        let local_receive_timestamp = local_send_timestamp + rtt;

        // Time offset = ((peer_timestamp - local_send_timestamp) + (peer_timestamp - local_receive_timestamp)) / 2
        let time_offset = ((peer_timestamp - local_send_timestamp)
            + (peer_timestamp - local_receive_timestamp))
            / 2;

        // Validate time offset is reasonable
        if time_offset.unsigned_abs() > MAX_TIME_OFFSET_MS.as_millis() {
            warn!(
                time_offset,
                max_allowed = MAX_TIME_OFFSET_MS.as_millis(),
                "Time offset exceeds maximum allowed"
            );
            return Ok(RecoveryResult::VerificationFailed);
        }

        // Apply time synchronization
        if self
            .apply_time_synchronization(session_id.clone(), time_offset)
            .await?
        {
            info!(
                session_id = %session_id,
                time_offset,
                rtt = %rtt,
                "Time synchronization recovery successful"
            );
            Ok(RecoveryResult::Success)
        } else {
            Ok(RecoveryResult::Failed)
        }
    }

    /// Execute sequence repair recovery
    ///
    /// # Security Requirements
    ///
    /// This function requires a valid session key for HMAC-based repair confirmation.
    /// The session key MUST:
    /// - Be derived from a completed ECDH handshake
    /// - Not be all zeros (enforced by HmacContext::new)
    /// - Not be empty (enforced by HmacContext::new)
    ///
    /// # Parameters
    ///
    /// * `session_key` - The active session key for this connection. Must be obtained
    ///   from the session manager after successful ECDH key exchange.
    #[instrument(skip(self, session_state, session_key, coordination), fields(session_id = %session_id))]
    pub async fn execute_sequence_repair_recovery(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
        session_key: &SessionKey,
        coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        info!(
            session_id = %session_id,
            "Executing sequence repair recovery"
        );

        // Get current sequence state
        let _current_send_seq = session_state.get_send_sequence();
        let current_recv_seq = session_state.get_receive_sequence();
        let expected_recv_seq = session_state.get_expected_receive_sequence();

        // Determine repair strategy based on sequence gap
        let sequence_gap = expected_recv_seq
            .as_u32()
            .saturating_sub(current_recv_seq.as_u32());

        if sequence_gap == 0 {
            // No gap, just sync sequence numbers
            return self
                .sync_sequence_numbers(session_id, session_state, coordination)
                .await;
        }

        if sequence_gap > MAX_REPAIR_WINDOW_SIZE.as_u32() {
            warn!(
                session_id = %session_id,
                sequence_gap,
                max_window = MAX_REPAIR_WINDOW_SIZE.as_u32(),
                "Sequence gap too large for repair"
            );
            return Ok(RecoveryResult::Failed);
        }

        // Request missing packets
        let result = self
            .request_missing_packets(
                session_id.clone(),
                current_recv_seq,
                expected_recv_seq,
                coordination,
            )
            .await;

        match result {
            Ok(RecoveryResult::Success) => {
                // Send repair confirmation with HMAC
                let confirmation_result = self
                    .send_repair_confirmation(
                        session_id.clone(),
                        expected_recv_seq,
                        session_key,
                        coordination,
                    )
                    .await;

                if confirmation_result.is_ok() {
                    info!(
                        session_id = %session_id,
                        repaired_gap = sequence_gap,
                        new_sequence = %expected_recv_seq,
                        "Sequence repair recovery successful with confirmation"
                    );
                    Ok(RecoveryResult::Success)
                } else {
                    warn!(
                        session_id = %session_id,
                        "Sequence repair succeeded but confirmation failed"
                    );
                    Ok(RecoveryResult::Failed)
                }
            }
            _ => {
                warn!(
                    session_id = %session_id,
                    result = ?result,
                    "Sequence repair recovery failed"
                );
                result
            }
        }
    }

    /// Execute session rekeying recovery
    #[instrument(skip(self, _session_state, _ecdh_manager, _coordination), fields(session_id = %session_id))]
    pub async fn execute_session_rekey_recovery(
        &self,
        session_id: SessionId,
        _session_state: Arc<SessionState>,
        _ecdh_manager: &Arc<ThreadSafeEcdhManager>,
        _coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        info!(
            session_id = %session_id,
            "Executing session rekeying recovery"
        );

        // Generate new ECDH key pair using p256
        use p256::PublicKey;
        use p256::ecdh::EphemeralSecret;
        use rand_chacha::rand_core::OsRng;

        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = PublicKey::from(&secret);

        info!(
            session_id = %session_id,
            public_key_bytes = public_key.to_sec1_bytes().len(),
            "Generated new ECDH keypair for session rekeying"
        );

        // Store the public key for exchange
        // Note: The actual key exchange and session update requires:
        // 1. Sending the public key to the peer
        // 2. Receiving the peer's public key
        // 3. Computing the shared secret
        // 4. Deriving new session keys
        // 5. Updating session parameters
        //
        // This requires protocol-level support which is deferred to future implementation
        warn!(
            session_id = %session_id,
            "ECDH keypair generated but full key exchange protocol not yet implemented"
        );

        Ok(RecoveryResult::Success)
    }

    /// Execute emergency recovery
    #[instrument(skip(self, session_state, coordination), fields(session_id = %session_id))]
    pub async fn execute_emergency_recovery(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
        coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        warn!(
            session_id = %session_id,
            "Executing emergency recovery"
        );

        // Emergency recovery involves:
        // 1. Reset all session state
        // 2. Force time synchronization
        // 3. Reset sequence numbers
        // 4. Clear all buffers

        // Reset session state
        session_state.reset_to_initial_state();

        // Force time synchronization
        let time_sync_result: Result<RecoveryResult, EngineError> = self
            .execute_time_sync_recovery(session_id.clone(), session_state.clone(), coordination)
            .await;
        if time_sync_result
            .as_ref()
            .map_or(true, |r| *r != RecoveryResult::Success)
        {
            error!(
                session_id = %session_id,
                "Emergency time sync failed"
            );
            return Ok(RecoveryResult::Failed);
        }

        // Reset sequence numbers
        session_state.reset_sequence_numbers();

        // Clear all buffers
        session_state.clear_all_buffers();

        // Send emergency recovery notification to peer
        let emergency_packet = self
            .create_emergency_recovery_packet(session_id.clone())
            .await?;
        if !coordination.send_recovery_packet(emergency_packet).await {
            return Ok(RecoveryResult::NetworkError);
        }

        // Wait for acknowledgment
        match timeout(
            Duration::from_millis(EMERGENCY_RECOVERY_TIMEOUT_MS.as_millis()),
            self.receive_emergency_ack(session_id.clone()),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(
                    session_id = %session_id,
                    "Emergency recovery successful"
                );
                Ok(RecoveryResult::Success)
            }
            Ok(Err(e)) => {
                error!(error = ?e, "Emergency recovery ack error");
                Ok(RecoveryResult::NetworkError)
            }
            Err(_) => {
                warn!("Emergency recovery ack timed out");
                Ok(RecoveryResult::Timeout)
            }
        }
    }

    /// Execute connection termination
    #[instrument(skip(self, session_state, coordination), fields(session_id = %session_id))]
    pub async fn execute_connection_termination(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
        coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        error!(
            session_id = %session_id,
            "Executing connection termination"
        );

        // Send termination packet to peer
        let termination_packet = self.create_termination_packet(session_id.clone()).await?;
        coordination.send_recovery_packet(termination_packet).await;

        // Mark session as terminated
        session_state.set_terminated();

        // Clean up session resources
        session_state.cleanup_resources();

        info!(
            session_id = %session_id,
            "Connection termination completed"
        );

        Ok(RecoveryResult::Success)
    }

    // Private helper methods

    /// Apply time synchronization offset
    async fn apply_time_synchronization(
        &self,
        session_id: SessionId,
        time_offset: i64,
    ) -> Result<bool, EngineError> {
        // This would integrate with the time sync engine
        // For now, we'll simulate the operation

        debug!(
            session_id = %session_id,
            time_offset,
            "Applying time synchronization offset"
        );

        // Simulate time sync application
        sleep(Duration::from_millis(100)).await;

        Ok(true)
    }

    /// Sync sequence numbers with peer
    async fn sync_sequence_numbers(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
        coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        // Create sequence sync request
        let sync_request = self
            .create_sequence_sync_request(session_id.clone(), session_state.clone())
            .await?;

        // Send request
        if !coordination.send_recovery_packet(sync_request).await {
            return Ok(RecoveryResult::NetworkError);
        }

        // Wait for response
        match timeout(
            Duration::from_millis(SEQUENCE_REPAIR_TIMEOUT_MS.as_millis()),
            self.receive_sequence_sync_response(session_id.clone()),
        )
        .await
        {
            Ok(Ok(response)) => {
                // Update sequence numbers
                session_state.set_send_sequence(response.peer_send_sequence);
                session_state.set_receive_sequence(response.peer_receive_sequence);
                Ok(RecoveryResult::Success)
            }
            Ok(Err(_)) => Ok(RecoveryResult::NetworkError),
            Err(_) => Ok(RecoveryResult::Timeout),
        }
    }

    /// Request missing packets for sequence repair
    async fn request_missing_packets(
        &self,
        session_id: SessionId,
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
        coordination: &RecoveryCoordination,
    ) -> Result<RecoveryResult, EngineError> {
        let missing_count = end_seq.as_u32() - start_seq.as_u32();

        debug!(
            session_id = %session_id,
            start_seq = %start_seq,
            end_seq = %end_seq,
            missing_count,
            "Requesting missing packets"
        );

        // Create packet request
        let request_packet = self
            .create_packet_request(session_id.clone(), start_seq, end_seq)
            .await?;

        // Send request
        if !coordination.send_recovery_packet(request_packet).await {
            return Ok(RecoveryResult::NetworkError);
        }

        // Wait for retransmitted packets
        let mut received_count = 0;
        let timeout_duration = Duration::from_millis(SEQUENCE_REPAIR_TIMEOUT_MS.as_millis());
        let start_time = Instant::now();

        while received_count < missing_count && start_time.elapsed() < timeout_duration {
            match timeout(
                Duration::from_millis(1000), // 1 second per packet
                self.receive_retransmitted_packet(session_id.clone()),
            )
            .await
            {
                Ok(Ok(_)) => {
                    received_count += 1;
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        if received_count == missing_count {
            Ok(RecoveryResult::Success)
        } else {
            warn!(
                session_id = %session_id,
                received_count,
                expected_count = missing_count,
                "Incomplete packet recovery"
            );
            Ok(RecoveryResult::Failed)
        }
    }

    // Placeholder methods for packet creation and reception
    // These would be implemented with actual protocol logic

    async fn create_time_sync_request_packet(
        &self,
        session_id: SessionId,
        nonce: RecoveryNonce,
        timestamp: Timestamp,
    ) -> Result<Vec<u8>, EngineError> {
        // Build time sync request payload
        let payload = TimeSyncRequestPayload {
            client_timestamp: timestamp,
            sync_quality: SyncQuality::new(80), // High quality sync
            max_drift: TimeDrift::new(100),     // 100 PPM max drift
        };

        // Build control packet
        let packet = self
            .packet_builder
            .control()
            .session_id(session_id.clone())
            .payload(ControlPayload::TimeSyncRequest(payload))
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build time sync request: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500]; // MTU-sized buffer
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize time sync request: {:?}", e),
            })?;

        buffer.truncate(size);
        debug!(
            session_id = %session_id,
            nonce = nonce.as_u32(),
            size,
            "Created time sync request packet"
        );

        Ok(buffer)
    }

    async fn receive_time_sync_response(
        &self,
        _session_id: SessionId,
        nonce: RecoveryNonce,
    ) -> Result<TimeSyncResponse, EngineError> {
        // Placeholder implementation
        sleep(Duration::from_millis(100)).await;
        Ok(TimeSyncResponse {
            challenge_nonce: nonce,
            peer_timestamp: Timestamp::from_millis(1234567890),
        })
    }

    async fn create_emergency_recovery_packet(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<u8>, EngineError> {
        // Generate emergency recovery nonce
        let mut nonce_bytes = [0u8; 4];
        if self.rng.fill(&mut nonce_bytes).is_err() {
            return Err(EngineError::RecoveryError {
                reason: "Failed to generate recovery nonce".to_string(),
            });
        }
        let nonce = RecoveryNonce::new(u32::from_be_bytes(nonce_bytes));

        // Build recovery payload
        let payload = RecoveryPayload {
            reason: RecoveryReason::Rekey,
            nonce,
            last_good_sequence: SequenceNumber::new(0), // Should come from session state
            recovery_params: RecoveryParams::new(RecoveryLevel::Emergency),
        };

        // Build control packet
        let packet = self
            .packet_builder
            .control()
            .session_id(session_id.clone())
            .payload(ControlPayload::Recovery(payload))
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build emergency recovery packet: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize emergency recovery packet: {:?}", e),
            })?;

        buffer.truncate(size);
        debug!(
            session_id = %session_id,
            nonce = nonce.as_u32(),
            size,
            "Created emergency recovery packet"
        );

        Ok(buffer)
    }

    async fn receive_emergency_ack(&self, _session_id: SessionId) -> Result<(), EngineError> {
        // Placeholder implementation
        sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    pub(crate) async fn create_termination_packet(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<u8>, EngineError> {
        // Build FIN packet for graceful termination
        let packet = self
            .packet_builder
            .fin()
            .session_id(session_id.clone())
            .final_sequence(SequenceNumber::new(0)) // Should come from session state
            .reason(TerminationReason::Normal)
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build termination packet: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize termination packet: {:?}", e),
            })?;

        buffer.truncate(size);
        debug!(
            session_id = %session_id,
            size,
            "Created termination packet"
        );

        Ok(buffer)
    }

    async fn create_sequence_sync_request(
        &self,
        session_id: SessionId,
        session_state: Arc<SessionState>,
    ) -> Result<Vec<u8>, EngineError> {
        // Get current sequence numbers from session state
        let send_seq = session_state.get_send_sequence();

        // Build sequence negotiation payload
        let payload = SequenceNegPayload {
            proposed_sequence: send_seq,
            window_size: WindowSize::new(65535), // Default window
            flags: SequenceNegFlags::new(0),
        };

        // Build control packet
        let packet = self
            .packet_builder
            .control()
            .session_id(session_id.clone())
            .payload(ControlPayload::SequenceNeg(payload))
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build sequence sync request: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize sequence sync request: {:?}", e),
            })?;

        buffer.truncate(size);
        debug!(
            session_id = %session_id,
            proposed_seq = %send_seq,
            size,
            "Created sequence sync request packet"
        );

        Ok(buffer)
    }

    async fn receive_sequence_sync_response(
        &self,
        _session_id: SessionId,
    ) -> Result<SequenceSyncResponse, EngineError> {
        // Placeholder implementation
        sleep(Duration::from_millis(100)).await;
        Ok(SequenceSyncResponse {
            peer_send_sequence: SequenceNumber::new(1000),
            peer_receive_sequence: SequenceNumber::new(2000),
        })
    }

    async fn create_packet_request(
        &self,
        session_id: SessionId,
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
    ) -> Result<Vec<u8>, EngineError> {
        // Build ACK packet with SACK data to request specific packets
        // Note: Using DATA packet as a workaround since AckPacketBuilder is incomplete
        let sack_request_data = format!("SACK:{}-{}", start_seq, end_seq);

        let packet = self
            .packet_builder
            .data()
            .session_id(session_id.clone())
            .payload(Bytes::from(sack_request_data))
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build packet request: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize packet request: {:?}", e),
            })?;

        buffer.truncate(size);
        debug!(
            session_id = %session_id,
            start_seq = %start_seq,
            end_seq = %end_seq,
            size,
            "Created packet retransmission request"
        );

        Ok(buffer)
    }

    async fn receive_retransmitted_packet(
        &self,
        _session_id: SessionId,
    ) -> Result<Vec<u8>, EngineError> {
        // Placeholder implementation
        sleep(Duration::from_millis(50)).await;
        Ok(vec![0u8; 1024])
    }

    /// Send repair confirmation packet with HMAC verification
    ///
    /// After successful sequence repair, sends a confirmation packet containing
    /// an HMAC of the new sequence range to ensure cryptographic verification
    /// before the peer accepts the new sequence state.
    ///
    /// Per design/protocol/12-recovery-mechanisms.md §2 lines 302-310
    async fn send_repair_confirmation(
        &self,
        session_id: SessionId,
        new_sequence: SequenceNumber,
        session_key: &SessionKey,
        coordination: &RecoveryCoordination,
    ) -> Result<(), EngineError> {
        // Generate repair nonce for this confirmation
        let mut nonce_bytes = [0u8; 4];
        if self.rng.fill(&mut nonce_bytes).is_err() {
            return Err(EngineError::RecoveryError {
                reason: "Failed to generate repair confirmation nonce".to_string(),
            });
        }
        let repair_nonce = RecoveryNonce::new(u32::from_be_bytes(nonce_bytes));

        // Calculate repair confirmation HMAC
        // Per spec: HMAC_SHA256_128(session_key, nonce || sequence || session_id || "sequence_repair_v1")[0:8]
        let confirmation = Self::calculate_repair_confirmation(
            repair_nonce,
            new_sequence,
            session_id.clone(),
            session_key,
        );

        // Build management packet with RepairConfirm payload
        let payload = ManagementPayload::RepairConfirm(RepairConfirmPayload {
            repair_nonce,
            confirmed_sequence: new_sequence,
            confirmation_hmac: confirmation,
        });

        let packet = self
            .packet_builder
            .management()
            .session_id(session_id.clone())
            .payload(payload)
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build repair confirmation packet: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize repair confirmation packet: {:?}", e),
            })?;

        buffer.truncate(size);

        // Send confirmation
        if !coordination.send_recovery_packet(buffer).await {
            return Err(EngineError::RecoveryError {
                reason: "Failed to send repair confirmation packet".to_string(),
            });
        }

        debug!(
            session_id = %session_id,
            nonce = repair_nonce.as_u32(),
            confirmed_sequence = %new_sequence,
            size,
            "Sent repair confirmation packet with HMAC"
        );

        Ok(())
    }

    /// Calculate repair confirmation HMAC
    ///
    /// Computes the cryptographic confirmation value for sequence repair.
    /// Per design/protocol/12-recovery-mechanisms.md lines 302-310:
    /// HMAC_SHA256_128(session_key, nonce || sequence || session_id || "sequence_repair_v1")[0:8]
    ///
    /// This ensures that:
    /// - The nonce matches the repair request (prevents replay)
    /// - The sequence number is cryptographically bound (prevents tampering)
    /// - The session ID is included (prevents cross-session attacks)
    /// - Version string prevents protocol confusion
    ///
    /// Returns an 8-byte confirmation tag
    fn calculate_repair_confirmation(
        nonce: RecoveryNonce,
        sequence: SequenceNumber,
        session_id: SessionId,
        session_key: &SessionKey,
    ) -> [u8; 8] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Build confirmation input per spec
        let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
        confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
        confirmation_input.extend_from_slice(b"sequence_repair_v1");

        // Calculate HMAC-SHA256 using the session key
        let mut mac = Hmac::<Sha256>::new_from_slice(session_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(&confirmation_input);
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();

        // Return first 8 bytes (64 bits) per spec
        let mut confirmation = [0u8; 8];
        confirmation.copy_from_slice(&hmac_bytes[..8]);
        confirmation
    }

    /// Verify repair confirmation HMAC
    ///
    /// Verifies that a received repair confirmation HMAC is valid.
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// Returns true if the confirmation is valid, false otherwise.
    pub fn verify_repair_confirmation(
        nonce: RecoveryNonce,
        sequence: SequenceNumber,
        session_id: SessionId,
        session_key: &SessionKey,
        received_confirmation: [u8; 8],
    ) -> bool {
        let expected_confirmation =
            Self::calculate_repair_confirmation(nonce, sequence, session_id, session_key);

        // Constant-time comparison per security requirements
        use subtle::ConstantTimeEq;
        expected_confirmation.ct_eq(&received_confirmation).into()
    }
}

impl Default for RecoveryStrategies {
    fn default() -> Self {
        Self::new()
    }
}

// Helper structs for recovery operations

#[derive(Debug)]
struct TimeSyncResponse {
    challenge_nonce: RecoveryNonce,
    peer_timestamp: Timestamp,
}

#[derive(Debug)]
struct SequenceSyncResponse {
    peer_send_sequence: SequenceNumber,
    peer_receive_sequence: SequenceNumber,
}

// Recovery constants - using timeout_constants from protocol module
use crate::protocol::timeout::timeout_constants;

const TIME_RESYNC_TIMEOUT_MS: RecoveryTimeout =
    RecoveryTimeout(timeout_constants::TIME_RESYNC_TIMEOUT_MS);
const SEQUENCE_REPAIR_TIMEOUT_MS: RecoveryTimeout =
    RecoveryTimeout(timeout_constants::SEQUENCE_REPAIR_TIMEOUT_MS);
const EMERGENCY_RECOVERY_TIMEOUT_MS: RecoveryTimeout =
    RecoveryTimeout(timeout_constants::EMERGENCY_RECOVERY_TIMEOUT_MS);
const MAX_TIME_OFFSET_MS: TimeSyncTolerance = TimeSyncTolerance(5000); // 5 seconds per 09-time-synchronization.md
static MAX_REPAIR_WINDOW_SIZE: WindowSize = WindowSize(1000);
