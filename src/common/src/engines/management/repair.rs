// Sequence Repair Engine

use dashmap::DashMap;
use std::time::Instant;
use tracing::info;

use super::RepairResult;
use crate::error::EngineError;
use crate::protocol::packet::{ManagementPayload, PacketBuilderEngine, RepairRequestPayload};
use crate::protocol::types::*;

/// Repair engine for sequence number repair
pub struct RepairEngine {
    /// Packet builder for creating management packets
    packet_builder: PacketBuilderEngine,
    /// Active repair operations
    active_repairs: DashMap<u32, Instant>, // Using nonce as key
}

impl RepairEngine {
    /// Create a new repair engine
    pub fn new() -> Self {
        Self {
            packet_builder: PacketBuilderEngine::new(),
            active_repairs: DashMap::new(),
        }
    }

    /// Initiate sequence repair
    pub async fn initiate_repair(
        &self,
        session_id: SessionId,
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
        repair_type: RepairType,
        priority: RepairPriority,
    ) -> Result<Vec<u8>, EngineError> {
        let sequence_range = SequenceRange::new(start_seq, end_seq);
        // Generate repair nonce
        let nonce = (Timestamp::now().as_nanos() & 0xFFFFFFFF) as u32;

        // Build repair request payload
        let payload = RepairRequestPayload {
            repair_type,
            sequence_range: sequence_range.clone(),
            priority,
        };

        // Build management packet
        let packet = self
            .packet_builder
            .management()
            .session_id(session_id.clone())
            .payload(ManagementPayload::RepairRequest(payload))
            .build()
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to build repair request: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size = packet
            .serialize(&mut buffer)
            .map_err(|e| EngineError::RecoveryError {
                reason: format!("Failed to serialize repair request: {:?}", e),
            })?;

        buffer.truncate(size);

        // Track repair operation
        self.active_repairs.insert(nonce, Instant::now());

        info!(
            session_id = %session_id,
            repair_type = ?repair_type,
            start_seq = %sequence_range.start,
            end_seq = %sequence_range.end,
            size,
            "Created sequence repair request packet"
        );

        Ok(buffer)
    }

    /// Handle repair response
    pub async fn handle_repair_response(
        &self,
        nonce: u32,
        repaired_count: u32,
    ) -> Result<RepairResult, EngineError> {
        // Mark repair as complete
        self.active_repairs.remove(&nonce);

        Ok(RepairResult::Success { repaired_count })
    }
}

impl Default for RepairEngine {
    fn default() -> Self {
        Self::new()
    }
}
