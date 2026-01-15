#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Recovery Coordination - Coordination of recovery operations across sessions
//
// This module handles coordination of recovery operations, packet transmission,
// and synchronization between different recovery strategies.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{debug, info, warn};

use crate::engines::recovery::RecoveryResult;
use crate::error::EngineError;
use crate::protocol::types::*;

/// Recovery packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPacketType {
    TimeSync,
    SequenceRepair,
    SessionRekey,
    Emergency,
    Termination,
}

/// Recovery packet for transmission
#[derive(Debug, Clone)]
pub struct RecoveryPacket {
    pub packet_type: RecoveryPacketType,
    pub session_id: SessionId,
    pub data: Vec<u8>,
    pub timestamp: Instant,
    pub retry_count: RetryCount,
}

/// Recovery operation tracking
#[derive(Debug)]
struct RecoveryOperation {
    pub session_id: SessionId,
    pub operation_type: RecoveryPacketType,
    pub start_time: Instant,
    pub timeout: Duration,
    pub retry_count: RetryCount,
    pub max_retries: MaxRetries,
    pub response_channel: Option<mpsc::UnboundedSender<RecoveryResult>>,
}

/// Recovery coordination statistics
#[derive(Debug, Default, Clone)]
pub struct RecoveryCoordinationStats {
    pub total_packets_sent: Counter,
    pub total_packets_received: Counter,
    pub total_operations: Counter,
    pub successful_operations: Counter,
    pub failed_operations: Counter,
    pub timeout_operations: Counter,
    pub active_operations: Counter,
    pub average_operation_time_ms: RecoveryTimeout,
}

/// Recovery coordination engine
pub struct RecoveryCoordination {
    /// Active recovery operations
    active_operations: DashMap<String, Arc<Mutex<RecoveryOperation>>>,

    /// Packet transmission queue
    tx_queue: Arc<Mutex<Vec<RecoveryPacket>>>,

    /// Packet reception handlers
    rx_handlers: DashMap<SessionId, mpsc::UnboundedSender<Vec<u8>>>,

    /// Coordination statistics
    stats: RwLock<RecoveryCoordinationStats>,

    /// Packet sender callback
    packet_sender: Option<Arc<dyn Fn(RecoveryPacket) -> bool + Send + Sync>>,

    /// Operation timeout handler
    timeout_handler: Option<Arc<dyn Fn(SessionId, RecoveryPacketType) + Send + Sync>>,
}

impl RecoveryCoordination {
    /// Create new recovery coordination engine
    pub fn new() -> Self {
        Self {
            active_operations: DashMap::new(),
            tx_queue: Arc::new(Mutex::new(Vec::new())),
            rx_handlers: DashMap::new(),
            stats: RwLock::new(RecoveryCoordinationStats::default()),
            packet_sender: None,
            timeout_handler: None,
        }
    }

    /// Set packet sender callback
    pub fn set_packet_sender<F>(&mut self, sender: F)
    where
        F: Fn(RecoveryPacket) -> bool + Send + Sync + 'static,
    {
        self.packet_sender = Some(Arc::new(sender));
    }

    /// Set timeout handler callback
    pub fn set_timeout_handler<F>(&mut self, handler: F)
    where
        F: Fn(SessionId, RecoveryPacketType) + Send + Sync + 'static,
    {
        self.timeout_handler = Some(Arc::new(handler));
    }

    /// Send recovery packet
    pub async fn send_recovery_packet(&self, packet_data: Vec<u8>) -> bool {
        // For now, we'll create a generic packet
        // In a real implementation, this would parse the packet type and session ID
        let packet = RecoveryPacket {
            packet_type: RecoveryPacketType::TimeSync, // Placeholder
            session_id: SessionId::new_with_length(0, SessionIdLength::Bits64), // Placeholder
            data: packet_data,
            timestamp: Instant::now(),
            retry_count: RetryCount::new(0),
        };

        // Add to transmission queue
        {
            let mut queue = self.tx_queue.lock().await;
            queue.push(packet.clone());
        }

        // Send packet if callback is available
        if let Some(ref sender) = self.packet_sender {
            let success = sender(packet);

            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.total_packets_sent += 1;
            }

            success
        } else {
            warn!("No packet sender configured");
            false
        }
    }

    /// Start recovery operation
    pub async fn start_recovery_operation(
        &self,
        session_id: SessionId,
        operation_type: RecoveryPacketType,
        timeout_duration: Duration,
        max_retries: MaxRetries,
    ) -> Result<mpsc::UnboundedReceiver<RecoveryResult>, EngineError> {
        let session_id_for_logging = session_id.clone();
        let operation_key = format!("{}_{:?}", session_id.as_u64(), operation_type);

        // Check if operation is already active
        if self.active_operations.contains_key(&operation_key) {
            return Err(EngineError::recovery_coordination_error(
                "Operation already active",
            ));
        }

        // Create response channel
        let (tx, rx) = mpsc::unbounded_channel();

        // Create operation
        let operation = Arc::new(Mutex::new(RecoveryOperation {
            session_id: session_id.clone(),
            operation_type,
            start_time: Instant::now(),
            timeout: timeout_duration,
            retry_count: RetryCount::new(0),
            max_retries,
            response_channel: Some(tx),
        }));

        // Store operation
        self.active_operations
            .insert(operation_key.clone(), operation.clone());

        // Start timeout monitoring
        let coordination = self.clone_for_timeout();
        let timeout_key = operation_key.clone();

        let session_id_for_timeout = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout_duration).await;
            coordination
                .handle_operation_timeout(
                    timeout_key,
                    session_id_for_timeout.clone(),
                    operation_type,
                )
                .await;
        });

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_operations += 1;
            stats.active_operations += 1;
        }

        debug!(
            session_id = %session_id_for_logging,
            operation_type = ?operation_type,
            timeout_ms = timeout_duration.as_millis(),
            "Started recovery operation"
        );

        Ok(rx)
    }

    /// Complete recovery operation
    pub async fn complete_recovery_operation(
        &self,
        session_id: SessionId,
        operation_type: RecoveryPacketType,
        result: RecoveryResult,
    ) -> Result<(), EngineError> {
        let operation_key = format!("{}_{:?}", session_id, operation_type);

        if let Some((_, operation)) = self.active_operations.remove(&operation_key) {
            let op = operation.lock().await;
            let operation_duration = op.start_time.elapsed();

            // Send result through channel
            if let Some(ref tx) = op.response_channel {
                let _ = tx.send(result);
            }

            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.active_operations =
                    Counter::new(stats.active_operations.as_u64().saturating_sub(1));

                match result {
                    RecoveryResult::Success => {
                        stats.successful_operations += 1;
                    }
                    RecoveryResult::Timeout => {
                        stats.timeout_operations += 1;
                    }
                    _ => {
                        stats.failed_operations += 1;
                    }
                }

                // Update average operation time
                let total_completed = stats.successful_operations.as_u64()
                    + stats.failed_operations.as_u64()
                    + stats.timeout_operations.as_u64();
                if total_completed > 0 {
                    let current_avg = stats.average_operation_time_ms.as_millis();
                    let new_avg = (current_avg * (total_completed - 1)
                        + operation_duration.as_millis() as u64)
                        / total_completed;
                    stats.average_operation_time_ms = RecoveryTimeout::new(new_avg);
                }
            }

            debug!(
                session_id = %session_id,
                operation_type = ?operation_type,
                result = ?result,
                duration_ms = operation_duration.as_millis(),
                "Completed recovery operation"
            );

            Ok(())
        } else {
            Err(EngineError::recovery_coordination_error(
                "Operation not found",
            ))
        }
    }

    /// Handle incoming recovery packet
    pub async fn handle_incoming_packet(
        &self,
        session_id: SessionId,
        packet_data: Vec<u8>,
    ) -> Result<(), EngineError> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_packets_received += 1;
        }

        // Forward to session handler if available
        if let Some(handler) = self.rx_handlers.get(&session_id) {
            if let Err(e) = handler.send(packet_data) {
                warn!(
                    session_id = %session_id,
                    error = ?e,
                    "Failed to forward packet to session handler"
                );
                return Err(EngineError::recovery_coordination_error(
                    "Failed to forward packet",
                ));
            }
        } else {
            debug!(
                session_id = %session_id,
                "No handler registered for session"
            );
        }

        Ok(())
    }

    /// Register packet handler for session
    pub async fn register_packet_handler(
        &self,
        session_id: SessionId,
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, EngineError> {
        let (tx, rx) = mpsc::unbounded_channel();

        let session_id_for_logging = session_id.clone();
        self.rx_handlers.insert(session_id, tx);

        debug!(
            session_id = %session_id_for_logging,
            "Registered packet handler for session"
        );

        Ok(rx)
    }

    /// Unregister packet handler for session
    pub async fn unregister_packet_handler(&self, session_id: &SessionId) {
        self.rx_handlers.remove(session_id);

        debug!(
            session_id = %session_id,
            "Unregistered packet handler for session"
        );
    }

    /// Retry recovery operation
    pub async fn retry_recovery_operation(
        &self,
        session_id: SessionId,
        operation_type: RecoveryPacketType,
    ) -> Result<bool, EngineError> {
        let operation_key = format!("{}_{:?}", session_id, operation_type);

        if let Some(operation) = self.active_operations.get(&operation_key) {
            let mut op = operation.lock().await;

            if op.retry_count.as_u32() >= op.max_retries.as_u32() {
                warn!(
                    session_id = %session_id,
                    operation_type = ?operation_type,
                    retry_count = op.retry_count.as_u32(),
                    max_retries = op.max_retries.as_u32(),
                    "Maximum retries exceeded"
                );
                return Ok(false);
            }

            op.retry_count = RetryCount::new(op.retry_count.as_u32() + 1);

            debug!(
                session_id = %session_id,
                operation_type = ?operation_type,
                retry_count = op.retry_count.as_u32(),
                "Retrying recovery operation"
            );

            Ok(true)
        } else {
            Err(EngineError::recovery_coordination_error(
                "Operation not found",
            ))
        }
    }

    /// Get coordination statistics
    pub async fn get_coordination_stats(&self) -> RecoveryCoordinationStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_operations = Counter::new(self.active_operations.len() as u64);
        stats
    }

    /// Get active operations for a session
    pub async fn get_active_operations_for_session(
        &self,
        session_id: SessionId,
    ) -> Vec<RecoveryPacketType> {
        let mut operations = Vec::new();

        for entry in self.active_operations.iter() {
            let operation = entry.value().lock().await;
            if operation.session_id == session_id {
                operations.push(operation.operation_type);
            }
        }

        operations
    }

    /// Cancel recovery operation
    pub async fn cancel_recovery_operation(
        &self,
        session_id: SessionId,
        operation_type: RecoveryPacketType,
    ) -> Result<(), EngineError> {
        let operation_key = format!("{}_{:?}", session_id, operation_type);

        if let Some((_, operation)) = self.active_operations.remove(&operation_key) {
            let op = operation.lock().await;

            // Send cancellation result
            if let Some(ref tx) = op.response_channel {
                let _ = tx.send(RecoveryResult::Failed);
            }

            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.active_operations =
                    Counter::new(stats.active_operations.as_u64().saturating_sub(1));
                stats.failed_operations += 1;
            }

            debug!(
                session_id = %session_id,
                operation_type = ?operation_type,
                "Cancelled recovery operation"
            );

            Ok(())
        } else {
            Err(EngineError::recovery_coordination_error(
                "Operation not found",
            ))
        }
    }

    /// Cancel all operations for a session
    pub async fn cancel_all_operations_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<u32, EngineError> {
        let mut cancelled_count = 0;
        let mut operations_to_cancel = Vec::new();

        // Collect operations to cancel
        for entry in self.active_operations.iter() {
            let operation = entry.value().lock().await;
            if operation.session_id == session_id {
                operations_to_cancel.push((entry.key().clone(), operation.operation_type));
            }
        }

        // Cancel each operation
        for (operation_key, _operation_type) in operations_to_cancel {
            if let Some((_, operation)) = self.active_operations.remove(&operation_key) {
                let op = operation.lock().await;

                // Send cancellation result
                if let Some(ref tx) = op.response_channel {
                    let _ = tx.send(RecoveryResult::Failed);
                }

                cancelled_count += 1;
            }
        }

        // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
        if cancelled_count > 0 {
            info!(
                session_id = %session_id,
                cancelled_count,
                active_operations = self.active_operations.len(),
                "Cancelled all recovery operations for session"
            );
        }

        Ok(cancelled_count)
    }

    /// Cleanup expired operations
    pub async fn cleanup_expired_operations(&self) -> Result<u32, EngineError> {
        let current_time = Instant::now();
        let mut expired_operations = Vec::new();

        // Find expired operations
        for entry in self.active_operations.iter() {
            let operation = entry.value().lock().await;
            if current_time.duration_since(operation.start_time) > operation.timeout {
                expired_operations.push((
                    entry.key().clone(),
                    operation.session_id.clone(),
                    operation.operation_type,
                ));
            }
        }

        let expired_count = expired_operations.len() as u32;

        // Remove expired operations
        for (operation_key, session_id, operation_type) in expired_operations {
            if let Some((_, operation)) = self.active_operations.remove(&operation_key) {
                let op = operation.lock().await;

                // Send timeout result
                if let Some(ref tx) = op.response_channel {
                    let _ = tx.send(RecoveryResult::Timeout);
                }

                debug!(
                    session_id = %session_id,
                    operation_type = ?operation_type,
                    "Cleaned up expired recovery operation"
                );
            }
        }

        // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
        if expired_count > 0 {
            info!(
                expired_count,
                active_operations = self.active_operations.len(),
                "Cleaned up expired recovery operations"
            );
        }

        Ok(expired_count)
    }

    /// Shutdown coordination engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        // Cancel all active operations
        let operation_keys: Vec<String> = self
            .active_operations
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for operation_key in operation_keys {
            if let Some((_, operation)) = self.active_operations.remove(&operation_key) {
                let op = operation.lock().await;

                // Send shutdown result
                if let Some(ref tx) = op.response_channel {
                    let _ = tx.send(RecoveryResult::Failed);
                }
            }
        }

        // Clear handlers
        self.rx_handlers.clear();

        // Clear transmission queue
        {
            let mut queue = self.tx_queue.lock().await;
            queue.clear();
        }

        info!("Recovery coordination engine shut down");
        Ok(())
    }

    // Private helper methods

    /// Clone for timeout handling
    fn clone_for_timeout(&self) -> RecoveryCoordinationTimeout {
        RecoveryCoordinationTimeout {
            active_operations: self.active_operations.clone(),
            timeout_handler: self.timeout_handler.clone(),
        }
    }
}

impl Default for RecoveryCoordination {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct for timeout handling
struct RecoveryCoordinationTimeout {
    active_operations: DashMap<String, Arc<Mutex<RecoveryOperation>>>,
    timeout_handler: Option<Arc<dyn Fn(SessionId, RecoveryPacketType) + Send + Sync>>,
}

impl RecoveryCoordinationTimeout {
    async fn handle_operation_timeout(
        &self,
        operation_key: String,
        session_id: SessionId,
        operation_type: RecoveryPacketType,
    ) {
        if let Some((_, operation)) = self.active_operations.remove(&operation_key) {
            let op = operation.lock().await;

            // Send timeout result
            if let Some(ref tx) = op.response_channel {
                let _ = tx.send(RecoveryResult::Timeout);
            }

            // Call timeout handler if available
            if let Some(ref handler) = self.timeout_handler {
                handler(session_id.clone(), operation_type);
            }

            warn!(
                session_id = %session_id,
                operation_type = ?operation_type,
                "Recovery operation timed out"
            );
        }
    }
}
