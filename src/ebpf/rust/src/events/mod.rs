//! eBPF event processing module
//! This module provides functionality for processing events from eBPF programs.
//! It handles ring buffer management, event processing, and dispatch to handlers.

#![cfg(target_os = "linux")]

pub mod processor;
pub mod ring_buffer;

// Re-export for convenience
pub use processor::EventProcessor;
pub use ring_buffer::{
    PacketEventParsed, RingBufferConfig, RingBufferManager, RingBufferStatsSnapshot,
};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;

/// Event processor manager
pub struct EventManager {
    processor: Arc<RwLock<processor::EventProcessor>>,
    running: bool,
}

impl EventManager {
    /// Create a new event manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            processor: Arc::new(RwLock::new(processor::EventProcessor::new()?)),
            running: false,
        })
    }

    /// Start event processing
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        self.processor.write().await.start().await?;
        self.running = true;
        tracing::info!("Event manager started");
        Ok(())
    }

    /// Stop event processing
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        self.processor.write().await.stop().await?;
        self.running = false;
        tracing::info!("Event manager stopped");
        Ok(())
    }

    /// Check if event processing is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get event processor reference
    pub fn processor(&self) -> Arc<RwLock<processor::EventProcessor>> {
        Arc::clone(&self.processor)
    }

    /// Get event statistics
    pub async fn get_statistics(&self) -> Result<EventStatistics> {
        let processor = self.processor.read().await;
        processor.get_statistics().await
    }
}

/// Event types that can be received from eBPF programs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EbpfEvent {
    PacketMetadata(PacketMetadataEvent),
    SecurityEvent(SecurityEventData),
    PerformanceMetric(PerformanceMetricEvent),
    SystemAlert(SystemAlertEvent),
}

/// Packet metadata event from eBPF ring buffer
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetadataEvent {
    pub session_id: SessionId,
    pub sequence_number: SequenceNumber,
    pub source_port: Port,
    pub dest_port: Port,
    pub packet_size: PacketSize,
    pub timestamp: Timestamp,
    pub packet_type: PacketType,
    pub hmac_policy: HmacPolicy,
    pub security_flags: PacketFlags,
    pub validation_status: ValidationResult<()>,
    pub src_ip: IpAddress,
    pub dst_ip: IpAddress,
}

/// Security event data from eBPF
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventData {
    pub timestamp: Timestamp,
    pub src_ip: IpAddress,
    pub dst_ip: IpAddress,
    pub src_port: Port,
    pub dst_port: Port,
    pub session_id: SessionId,
    pub event_type: EbpfEventType,
    pub severity: u8, // Security severity level (0=low, 1=medium, 2=high, 3=critical)
    pub action_taken: EbpfReturnCode,
    pub reserved: u8,
    pub additional_data: u32,
}

/// Performance metric event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetricEvent {
    pub timestamp: Timestamp,
    pub metric_type: String,
    pub value: MetricValue,
    pub labels: std::collections::HashMap<String, String>,
}

/// System alert event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAlertEvent {
    pub timestamp: Timestamp,
    pub alert_type: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub source: String,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Event handler trait
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle an eBPF event
    async fn handle_event(&self, event: EbpfEvent) -> Result<()>;

    /// Get handler name
    fn name(&self) -> &str;

    /// Check if handler can process this event type
    fn can_handle(&self, event: &EbpfEvent) -> bool;
}

/// Event statistics
#[derive(Debug, Clone, Default)]
pub struct EventStatistics {
    pub total_events_processed: EventCount,
    pub packet_metadata_events: EventCount,
    pub security_events: EventCount,
    pub performance_metric_events: EventCount,
    pub system_alert_events: EventCount,
    pub processing_errors: ErrorCount,
    pub events_per_second: Rate,
    pub average_processing_time_us: u64, // Average processing time in microseconds
    pub ring_buffer_utilization: f64,    // Utilization as percentage (0.0-100.0)
}

/// Event processing configuration
#[derive(Debug, Clone)]
pub struct EventProcessingConfig {
    pub ring_buffer_size: RingBufferSize,
    pub batch_size: usize,          // Number of events to process in a batch
    pub processing_timeout_ms: u64, // Timeout in milliseconds
    pub max_concurrent_handlers: WorkerThreadCount,
    pub enable_metrics: bool,
    pub enable_tracing: bool,
}

impl Default for EventProcessingConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size: RingBufferSize::new(1024 * 1024), // 1MB
            batch_size: 32,                                     // 32 events per batch
            processing_timeout_ms: 1000,                        // 1 second timeout
            max_concurrent_handlers: WorkerThreadCount::new(10),
            enable_metrics: true,
            enable_tracing: true,
        }
    }
}

/// Helper functions for event conversion
impl From<PacketMetadataEvent> for EbpfEvent {
    fn from(event: PacketMetadataEvent) -> Self {
        EbpfEvent::PacketMetadata(event)
    }
}

impl From<SecurityEventData> for EbpfEvent {
    fn from(event: SecurityEventData) -> Self {
        EbpfEvent::SecurityEvent(event)
    }
}

impl From<PerformanceMetricEvent> for EbpfEvent {
    fn from(event: PerformanceMetricEvent) -> Self {
        EbpfEvent::PerformanceMetric(event)
    }
}

impl From<SystemAlertEvent> for EbpfEvent {
    fn from(event: SystemAlertEvent) -> Self {
        EbpfEvent::SystemAlert(event)
    }
}

/// Security event types (matching eBPF definitions)
pub mod security_events {
    pub const RATE_LIMIT_VIOLATION: u8 = 1;
    pub const FRAGMENT_BOMB: u8 = 2;
    pub const FRAGMENT_OVERLAP: u8 = 3;
    pub const REPLAY_ATTACK: u8 = 4;
    pub const ENUMERATION_ATTACK: u8 = 5;
    pub const TIMING_ATTACK: u8 = 6;
    pub const SESSION_HIJACK: u8 = 7;
    pub const INVALID_PACKET: u8 = 8;
    pub const PORT_SCAN: u8 = 9;
    pub const UNKNOWN_SESSION: u8 = 10;
}

/// Security severity levels (matching eBPF definitions)
pub mod security_severity {
    pub const LOW: u8 = 0;
    pub const MEDIUM: u8 = 1;
    pub const HIGH: u8 = 2;
    pub const CRITICAL: u8 = 3;
}

/// Security actions (matching eBPF definitions)
pub mod security_actions {
    pub const ALLOW: u8 = 0;
    pub const DROP: u8 = 1;
    pub const BLOCK_TEMP: u8 = 2;
    pub const BLOCK_PERM: u8 = 3;
    pub const RATE_LIMIT: u8 = 4;
}

/// Helper function to convert security event type to string
pub fn security_event_type_to_string(event_type: u8) -> &'static str {
    match event_type {
        security_events::RATE_LIMIT_VIOLATION => "RateLimitViolation",
        security_events::FRAGMENT_BOMB => "FragmentBomb",
        security_events::FRAGMENT_OVERLAP => "FragmentOverlap",
        security_events::REPLAY_ATTACK => "ReplayAttack",
        security_events::ENUMERATION_ATTACK => "EnumerationAttack",
        security_events::TIMING_ATTACK => "TimingAttack",
        security_events::SESSION_HIJACK => "SessionHijack",
        security_events::INVALID_PACKET => "InvalidPacket",
        security_events::PORT_SCAN => "PortScan",
        security_events::UNKNOWN_SESSION => "UnknownSession",
        _ => "Unknown",
    }
}

/// Helper function to convert security severity to string
pub fn security_severity_to_string(severity: u8) -> &'static str {
    match severity {
        security_severity::LOW => "Low",
        security_severity::MEDIUM => "Medium",
        security_severity::HIGH => "High",
        security_severity::CRITICAL => "Critical",
        _ => "Unknown",
    }
}

/// Helper function to convert security action to string
pub fn security_action_to_string(action: u8) -> &'static str {
    match action {
        security_actions::ALLOW => "Allow",
        security_actions::DROP => "Drop",
        security_actions::BLOCK_TEMP => "BlockTemp",
        security_actions::BLOCK_PERM => "BlockPerm",
        security_actions::RATE_LIMIT => "RateLimit",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_manager_creation() {
        let manager = EventManager::new();
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(!manager.is_running());
    }

    #[test]
    fn test_event_processing_config_default() {
        let config = EventProcessingConfig::default();
        assert_eq!(config.ring_buffer_size.as_raw(), 1024 * 1024);
        assert_eq!(config.batch_size, 32);
        assert_eq!(config.processing_timeout_ms, 1000);
        assert_eq!(config.max_concurrent_handlers.as_raw(), 10);
        assert!(config.enable_metrics);
        assert!(config.enable_tracing);
    }

    #[test]
    fn test_event_conversions() {
        let packet_event = PacketMetadataEvent {
            session_id: SessionId::from_raw(12345),
            sequence_number: SequenceNumber::from_raw(1),
            source_port: Port::from_raw(8080),
            dest_port: Port::from_raw(443),
            packet_size: PacketSize::from_usize(1500),
            timestamp: Timestamp::from_nanos(1234567890),
            packet_type: PacketType::Data,
            hmac_policy: HmacPolicy::Light,
            security_flags: PacketFlags::new(),
            validation_status: ValidationResult::Valid(()),
            src_ip: IpAddress::from_ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddress::from_ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        };

        let ebpf_event: EbpfEvent = packet_event.into();
        match ebpf_event {
            EbpfEvent::PacketMetadata(event) => {
                assert_eq!(event.session_id.as_raw(), 12345);
                assert_eq!(event.source_port.as_raw(), 8080);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_security_event_type_conversion() {
        assert_eq!(
            security_event_type_to_string(security_events::RATE_LIMIT_VIOLATION),
            "RateLimitViolation"
        );
        assert_eq!(
            security_event_type_to_string(security_events::FRAGMENT_BOMB),
            "FragmentBomb"
        );
        assert_eq!(security_event_type_to_string(255), "Unknown");
    }

    #[test]
    fn test_security_severity_conversion() {
        assert_eq!(security_severity_to_string(security_severity::LOW), "Low");
        assert_eq!(security_severity_to_string(security_severity::HIGH), "High");
        assert_eq!(security_severity_to_string(255), "Unknown");
    }

    #[test]
    fn test_security_action_conversion() {
        assert_eq!(security_action_to_string(security_actions::ALLOW), "Allow");
        assert_eq!(security_action_to_string(security_actions::DROP), "Drop");
        assert_eq!(security_action_to_string(255), "Unknown");
    }

    #[test]
    fn test_alert_severity() {
        assert_eq!(AlertSeverity::Info as u8, 0);
        assert_eq!(AlertSeverity::Critical as u8, 3);
    }
}
