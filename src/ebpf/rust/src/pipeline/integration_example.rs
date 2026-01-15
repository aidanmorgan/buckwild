//! Pipeline Integration Example
//!
//! This module demonstrates how to integrate all pipeline components
//! for a complete eBPF-to-userspace data flow. See the example handlers
//! below for integration patterns.

#![cfg(target_os = "linux")]
//! # Architecture Flow
//!
//! ```text
//! Network Packet → XDP Program → Port Validation
//!                       ↓
//!                 Session Lookup
//!                       ↓
//!                 Security Check
//!                       ↓
//!              submit_packet_event()
//!                       ↓
//!              Ring Buffer (256KB)
//!                       ↓
//!           RingBufferManager.poll()
//!                       ↓
//!              parse_packet_event()
//!                       ↓
//!           Channel (mpsc, backpressure)
//!                       ↓
//!            PipelineCoordinator
//!                       ↓
//!              Event Classification
//!                       ↓
//!         ┌──────────────┴──────────────┐
//!         ↓                             ↓
//!    Data Handler              Security Handler
//! ```

#![allow(dead_code)]

use crate::events::ring_buffer::RingBufferConfig;
use crate::pipeline::coordinator::{
    EventClassification, EventHandlerTrait, PipelineCoordinator, ProcessedEvent,
};
use buckwild_common::error::BuckwildError;
use std::sync::Arc;
use tracing::{info, warn};

/// Example data packet handler
pub struct DataPacketHandler {
    packet_count: Arc<std::sync::atomic::AtomicU64>,
}

impl DataPacketHandler {
    pub fn new() -> Self {
        Self {
            packet_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn get_packet_count(&self) -> u64 {
        self.packet_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl EventHandlerTrait for DataPacketHandler {
    fn handle(&self, event: &ProcessedEvent) -> Result<(), BuckwildError> {
        self.packet_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!(
            session_id = event.packet.session_id,
            sequence = event.packet.sequence,
            payload_length = event.packet.payload_length,
            "Processing data packet"
        );

        // Process data packet here
        Ok(())
    }

    fn name(&self) -> &str {
        "DataPacketHandler"
    }

    fn can_handle(&self, classification: &EventClassification) -> bool {
        matches!(classification, EventClassification::DataPacket)
    }
}

/// Example security event handler
pub struct SecurityViolationHandler {
    violation_count: Arc<std::sync::atomic::AtomicU64>,
}

impl SecurityViolationHandler {
    pub fn new() -> Self {
        Self {
            violation_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn get_violation_count(&self) -> u64 {
        self.violation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl EventHandlerTrait for SecurityViolationHandler {
    fn handle(&self, event: &ProcessedEvent) -> Result<(), BuckwildError> {
        self.violation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        warn!(
            session_id = event.packet.session_id,
            src_ip = %event.packet.src_ip,
            flags = event.packet.flags,
            "Security violation detected"
        );

        // Log to security system, update blocklists, etc.
        Ok(())
    }

    fn name(&self) -> &str {
        "SecurityViolationHandler"
    }

    fn can_handle(&self, classification: &EventClassification) -> bool {
        matches!(classification, EventClassification::SecurityViolation)
    }
}

/// Example session event handler
pub struct SessionEventHandler;

impl EventHandlerTrait for SessionEventHandler {
    fn handle(&self, event: &ProcessedEvent) -> Result<(), BuckwildError> {
        info!(
            session_id = event.packet.session_id,
            "Processing session event"
        );

        // Update session state, tracking, etc.
        Ok(())
    }

    fn name(&self) -> &str {
        "SessionEventHandler"
    }

    fn can_handle(&self, classification: &EventClassification) -> bool {
        matches!(classification, EventClassification::SessionEvent)
    }
}

/// Example of creating a fully configured pipeline
pub async fn create_production_pipeline() -> Result<PipelineCoordinator, BuckwildError> {
    // Create coordinator with custom config
    let config = RingBufferConfig {
        buffer_size: 512 * 1024, // 512KB for production
        poll_timeout: std::time::Duration::from_millis(50),
        max_batch_size: 200,
        enable_batching: true,
        max_events_in_flight: 20000,
    };

    let mut coordinator = PipelineCoordinator::new(config)?;

    // Add all handlers
    coordinator.add_handler(Box::new(DataPacketHandler::new()));
    coordinator.add_handler(Box::new(SecurityViolationHandler::new()));
    coordinator.add_handler(Box::new(SessionEventHandler));

    Ok(coordinator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_data_handler_creation() {
        let handler = DataPacketHandler::new();
        assert_eq!(handler.name(), "DataPacketHandler");
        assert_eq!(handler.get_packet_count(), 0);
    }

    #[test]
    fn test_security_handler_creation() {
        let handler = SecurityViolationHandler::new();
        assert_eq!(handler.name(), "SecurityViolationHandler");
        assert_eq!(handler.get_violation_count(), 0);
    }

    #[test]
    fn test_handler_can_handle() {
        let data_handler = DataPacketHandler::new();
        assert!(data_handler.can_handle(&EventClassification::DataPacket));
        assert!(!data_handler.can_handle(&EventClassification::SecurityViolation));

        let sec_handler = SecurityViolationHandler::new();
        assert!(sec_handler.can_handle(&EventClassification::SecurityViolation));
        assert!(!sec_handler.can_handle(&EventClassification::DataPacket));
    }

    #[tokio::test]
    async fn test_create_production_pipeline() {
        let result = create_production_pipeline().await;
        assert!(result.is_ok());
    }
}
