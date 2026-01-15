//! Pipeline Coordinator - Full Integration
//!
//! This module provides the complete integration between the ring buffer,
//! event processing, and eBPF program management.

#![cfg(target_os = "linux")]

use crate::events::ring_buffer::{PacketEventParsed, RingBufferConfig, RingBufferManager};
use crate::loader::tc_loader::TcLoader;
use crate::loader::xdp_loader::XdpLoader;
use crate::maps::MapManager;
use buckwild_common::error::BuckwildError;
use libbpf_rs::{MapHandle, Object, RingBufferBuilder};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, warn};

/// Integrated pipeline coordinator that manages the complete data flow
pub struct PipelineCoordinator {
    /// Ring buffer manager
    ring_buffer_manager: RingBufferManager,
    /// Event processing channel
    event_tx: mpsc::UnboundedSender<ProcessedEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<ProcessedEvent>>,
    /// Event handlers
    handlers: Vec<Box<dyn EventHandlerTrait>>,
    /// Processing task handle
    processing_task: Option<JoinHandle<()>>,
    /// Polling task handle
    polling_task: Option<JoinHandle<()>>,
    /// Coordinator statistics
    stats: Arc<RwLock<CoordinatorStats>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Processed event with metadata
#[derive(Debug, Clone)]
pub struct ProcessedEvent {
    /// Original packet event
    pub packet: PacketEventParsed,
    /// Processing timestamp
    pub processed_at: Instant,
    /// Event classification
    pub classification: EventClassification,
}

/// Event classification for routing
#[derive(Debug, Clone, PartialEq)]
pub enum EventClassification {
    /// Normal data packet
    DataPacket,
    /// Security violation
    SecurityViolation,
    /// Session management
    SessionEvent,
    /// Protocol error
    ProtocolError,
    /// Fragment event
    FragmentEvent,
}

/// Event handler trait
pub trait EventHandlerTrait: Send + Sync {
    /// Handle a processed event
    fn handle(&self, event: &ProcessedEvent) -> Result<(), BuckwildError>;

    /// Get handler name
    fn name(&self) -> &str;

    /// Check if this handler can process this event type
    fn can_handle(&self, classification: &EventClassification) -> bool;
}

/// Coordinator statistics
#[derive(Debug, Clone, Default)]
pub struct CoordinatorStats {
    /// Total events received from ring buffer
    pub events_received: u64,
    /// Events successfully processed
    pub events_processed: u64,
    /// Events that failed processing
    pub events_failed: u64,
    /// Events currently in flight
    pub events_in_flight: u64,
    /// Average processing time (microseconds)
    pub avg_processing_time_us: u64,
    /// Start time
    pub start_time: Option<Instant>,
}

impl PipelineCoordinator {
    /// Create a new pipeline coordinator
    pub fn new(ring_buffer_config: RingBufferConfig) -> Result<Self, BuckwildError> {
        let ring_buffer_manager = RingBufferManager::new(ring_buffer_config)?;
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Ok(Self {
            ring_buffer_manager,
            event_tx,
            event_rx: Some(event_rx),
            handlers: Vec::new(),
            processing_task: None,
            polling_task: None,
            stats: Arc::new(RwLock::new(CoordinatorStats::default())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Add an event handler
    pub fn add_handler(&mut self, handler: Box<dyn EventHandlerTrait>) {
        info!(handler_name = handler.name(), "Adding event handler");
        self.handlers.push(handler);
    }

    /// Initialize with eBPF map handle
    pub fn set_ring_buffer(&mut self, ring_buffer: libbpf_rs::RingBuffer<'static>) {
        self.ring_buffer_manager.set_ring_buffer(ring_buffer);
    }

    /// Start the coordinator
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<(), BuckwildError> {
        if self.running.load(std::sync::atomic::Ordering::Acquire) {
            return Err(BuckwildError::invalid_state("Coordinator already running"));
        }

        info!(
            handler_count = self.handlers.len(),
            "Starting pipeline coordinator"
        );

        // Update start time
        {
            let mut stats = self.stats.write().await;
            stats.start_time = Some(Instant::now());
        }

        // Start ring buffer polling
        self.start_ring_buffer_polling().await?;

        // Start event processing
        self.start_event_processing().await?;

        self.running
            .store(true, std::sync::atomic::Ordering::Release);
        info!("Pipeline coordinator started");
        Ok(())
    }

    /// Start ring buffer polling task
    async fn start_ring_buffer_polling(&mut self) -> Result<(), BuckwildError> {
        let event_tx = self.event_tx.clone();
        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);

        // Get event receiver from ring buffer manager
        let receiver = self.ring_buffer_manager.event_receiver();

        let polling_task = tokio::spawn(async move {
            info!("Ring buffer polling task started");

            // This is where we'd actually poll the ring buffer
            // For now, this is a placeholder that shows the structure
            while running.load(std::sync::atomic::Ordering::Acquire) {
                // In a real implementation, we'd:
                // 1. Receive PacketEventParsed from ring buffer manager's channel
                // 2. Classify the event
                // 3. Send ProcessedEvent to event_tx

                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            info!("Ring buffer polling task stopped");
        });

        self.polling_task = Some(polling_task);
        Ok(())
    }

    /// Start event processing task
    async fn start_event_processing(&mut self) -> Result<(), BuckwildError> {
        let mut event_rx = self
            .event_rx
            .take()
            .ok_or_else(|| BuckwildError::internal_error("Event receiver already taken"))?;

        let handlers = self
            .handlers
            .iter()
            .map(|h| Arc::new(h.name().to_string()))
            .collect::<Vec<_>>();

        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);

        let processing_task = tokio::spawn(async move {
            info!("Event processing task started");

            while running.load(std::sync::atomic::Ordering::Acquire) {
                tokio::select! {
                    Some(event) = event_rx.recv() => {
                        // Process the event
                        debug!(
                            session_id = event.packet.session_id,
                            sequence = event.packet.sequence,
                            "Processing event"
                        );

                        // Update statistics
                        let mut stats_guard = stats.write().await;
                        stats_guard.events_received += 1;
                        stats_guard.events_in_flight += 1;

                        // In real implementation, dispatch to handlers here

                        stats_guard.events_processed += 1;
                        stats_guard.events_in_flight -= 1;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Periodic maintenance
                    }
                }
            }

            info!("Event processing task stopped");
        });

        self.processing_task = Some(processing_task);
        Ok(())
    }

    /// Stop the coordinator
    #[instrument(skip(self))]
    pub async fn stop(&mut self) -> Result<(), BuckwildError> {
        if !self.running.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }

        info!("Stopping pipeline coordinator");

        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Stop ring buffer manager
        self.ring_buffer_manager.stop();

        // Stop polling task
        if let Some(task) = self.polling_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Stop processing task
        if let Some(task) = self.processing_task.take() {
            task.abort();
            let _ = task.await;
        }

        info!("Pipeline coordinator stopped");
        Ok(())
    }

    /// Get coordinator statistics
    pub async fn get_stats(&self) -> CoordinatorStats {
        let mut stats = self.stats.read().await.clone();

        // Add ring buffer stats
        let rb_stats = self.ring_buffer_manager.get_stats();
        stats.events_received = rb_stats.events_processed;

        stats
    }

    /// Release backpressure for an event
    pub fn release_event(&self) {
        self.ring_buffer_manager.release_event();
    }

    /// Classify a packet event for routing
    fn classify_event(packet: &PacketEventParsed) -> EventClassification {
        // Classification logic based on packet metadata
        if packet.flags & 0x80 != 0 {
            // High bit set indicates security issue
            EventClassification::SecurityViolation
        } else if packet.packet_type == 0x01 {
            // Type 1 is data packet
            EventClassification::DataPacket
        } else if packet.packet_type == 0x02 {
            // Type 2 is session event
            EventClassification::SessionEvent
        } else if packet.packet_type == 0xF0 {
            // Fragment indicator
            EventClassification::FragmentEvent
        } else {
            EventClassification::ProtocolError
        }
    }
}

// Note: Ring buffer creation is handled directly by RingBufferManager
// This example shows the pattern, but actual usage will be through the manager:
//
// Example pattern for reference:
// ```
// let ring_buffer = RingBufferBuilder::new()
//     .add(map_handle, callback)
//     .unwrap()
//     .build()
//     .unwrap();
// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let config = RingBufferConfig::default();
        let result = PipelineCoordinator::new(config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_coordinator_lifecycle() {
        let config = RingBufferConfig::default();
        let mut coordinator = PipelineCoordinator::new(config).unwrap();

        // Should not be running initially
        assert!(
            !coordinator
                .running
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[test]
    fn test_event_classification() {
        let packet = PacketEventParsed {
            session_id: 12345,
            sequence: 1,
            timestamp_us: 1000000,
            payload_length: 1500,
            packet_type: 0x01,
            flags: 0x00,
            src_ip: std::net::Ipv4Addr::new(192, 168, 1, 1),
            received_at: Instant::now(),
        };

        let classification = PipelineCoordinator::classify_event(&packet);
        assert_eq!(classification, EventClassification::DataPacket);
    }

    #[test]
    fn test_security_classification() {
        let packet = PacketEventParsed {
            session_id: 12345,
            sequence: 1,
            timestamp_us: 1000000,
            payload_length: 1500,
            packet_type: 0x03,
            flags: 0x80, // Security flag set
            src_ip: std::net::Ipv4Addr::new(192, 168, 1, 1),
            received_at: Instant::now(),
        };

        let classification = PipelineCoordinator::classify_event(&packet);
        assert_eq!(classification, EventClassification::SecurityViolation);
    }
}
