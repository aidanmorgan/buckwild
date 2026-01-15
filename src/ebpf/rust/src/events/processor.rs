//! eBPF event processor
//! This module provides the core event processing functionality for eBPF events.
//! It handles ring buffer polling, event parsing, and dispatching to handlers.

#![cfg(target_os = "linux")]

use super::{
    AlertSeverity, EbpfEvent, EventHandler, EventProcessingConfig, EventStatistics,
    PacketMetadataEvent, PerformanceMetricEvent, RingBufferManager, SecurityEventData,
    SystemAlertEvent,
};
use anyhow::Result;
use async_trait::async_trait;
use libbpf_rs::RingBuffer;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;

/// Event processor for handling eBPF events
pub struct EventProcessor {
    config: EventProcessingConfig,
    handlers: Vec<Arc<dyn EventHandler>>,
    ring_buffer: Option<RingBuffer<'static>>,
    event_sender: Option<mpsc::UnboundedSender<EbpfEvent>>,
    event_receiver: Option<mpsc::UnboundedReceiver<EbpfEvent>>,
    processing_task: Option<JoinHandle<()>>,
    ring_buffer_task: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
    statistics: Arc<RwLock<EventStatistics>>,
    last_stats_update: Arc<RwLock<Instant>>,
    /// Shared ring buffer manager for daemon integration
    ring_buffer_manager: Arc<RwLock<RingBufferManager>>,
}

impl EventProcessor {
    /// Create a new event processor
    pub fn new() -> Result<Self> {
        let config = EventProcessingConfig::default();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let ring_buffer_manager = Arc::new(RwLock::new(
            RingBufferManager::new(super::RingBufferConfig::default())
                .expect("Failed to create ring buffer manager"),
        ));

        Ok(Self {
            config,
            handlers: Vec::new(),
            ring_buffer: None,
            event_sender: Some(event_sender),
            event_receiver: Some(event_receiver),
            processing_task: None,
            ring_buffer_task: None,
            running: Arc::new(AtomicBool::new(false)),
            statistics: Arc::new(RwLock::new(EventStatistics::default())),
            last_stats_update: Arc::new(RwLock::new(Instant::now())),
            ring_buffer_manager,
        })
    }

    /// Create event processor with custom configuration
    pub fn with_config(config: EventProcessingConfig) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let ring_buffer_manager = Arc::new(RwLock::new(
            RingBufferManager::new(super::RingBufferConfig::default())
                .expect("Failed to create ring buffer manager"),
        ));

        Ok(Self {
            config,
            handlers: Vec::new(),
            ring_buffer: None,
            event_sender: Some(event_sender),
            event_receiver: Some(event_receiver),
            processing_task: None,
            ring_buffer_task: None,
            running: Arc::new(AtomicBool::new(false)),
            statistics: Arc::new(RwLock::new(EventStatistics::default())),
            last_stats_update: Arc::new(RwLock::new(Instant::now())),
            ring_buffer_manager,
        })
    }

    /// Add an event handler
    pub fn add_handler(&mut self, handler: Arc<dyn EventHandler>) {
        self.handlers.push(handler);
        tracing::info!(
            "Added event handler: {}",
            self.handlers.last().unwrap().name()
        );
    }

    /// Set the ring buffer for event processing
    pub fn set_ring_buffer(&mut self, ring_buffer: RingBuffer<'static>) {
        self.ring_buffer = Some(ring_buffer);
        tracing::info!("Ring buffer set for event processing");
    }

    /// Start event processing
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Take ownership of the event receiver
        let event_receiver = self
            .event_receiver
            .take()
            .ok_or_else(|| anyhow::anyhow!("Event receiver already taken"))?;

        // Start the event processing task
        let processing_task = self.start_processing_task(event_receiver).await?;
        self.processing_task = Some(processing_task);

        // Start the ring buffer polling task if ring buffer is available
        if self.ring_buffer.is_some() {
            let ring_buffer_task = self.start_ring_buffer_task().await?;
            self.ring_buffer_task = Some(ring_buffer_task);
        }

        self.running.store(true, Ordering::Relaxed);
        tracing::info!(
            "Event processor started with {} handlers",
            self.handlers.len()
        );
        Ok(())
    }

    /// Stop event processing
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.running.store(false, Ordering::Relaxed);

        // Stop processing task
        if let Some(task) = self.processing_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Stop ring buffer task
        if let Some(task) = self.ring_buffer_task.take() {
            task.abort();
            let _ = task.await;
        }

        tracing::info!("Event processor stopped");
        Ok(())
    }

    /// Start the event processing task
    async fn start_processing_task(
        &self,
        mut event_receiver: mpsc::UnboundedReceiver<EbpfEvent>,
    ) -> Result<JoinHandle<()>> {
        let handlers = self.handlers.clone();
        let running = Arc::clone(&self.running);
        let statistics = Arc::clone(&self.statistics);
        let last_stats_update = Arc::clone(&self.last_stats_update);
        let config = self.config.clone();

        let task = tokio::spawn(async move {
            let mut event_batch = Vec::with_capacity(config.batch_size);
            let mut last_batch_time = Instant::now();

            while running.load(Ordering::Relaxed) {
                // Collect events in batches
                let timeout = Duration::from_millis(config.processing_timeout_ms);
                let batch_ready = match tokio::time::timeout(timeout, event_receiver.recv()).await {
                    Ok(Some(event)) => {
                        event_batch.push(event);

                        // Collect more events up to batch size
                        while event_batch.len() < config.batch_size {
                            match event_receiver.try_recv() {
                                Ok(event) => event_batch.push(event),
                                Err(_) => break,
                            }
                        }

                        true
                    }
                    Ok(None) => break, // Channel closed
                    Err(_) => {
                        // Timeout - process any pending events
                        !event_batch.is_empty()
                    }
                };

                // Process batch if ready or timeout
                if batch_ready || last_batch_time.elapsed() > timeout {
                    if !event_batch.is_empty() {
                        Self::process_event_batch(&event_batch, &handlers, &statistics).await;
                        event_batch.clear();
                        last_batch_time = Instant::now();
                    }
                }

                // Update statistics periodically
                {
                    let mut last_update = last_stats_update.write().await;
                    if last_update.elapsed() > Duration::from_secs(1) {
                        Self::update_statistics_rates(&statistics, &last_update).await;
                        *last_update = Instant::now();
                    }
                }
            }

            // Process any remaining events
            if !event_batch.is_empty() {
                Self::process_event_batch(&event_batch, &handlers, &statistics).await;
            }

            tracing::info!("Event processing task stopped");
        });

        Ok(task)
    }

    /// Start the ring buffer polling task
    async fn start_ring_buffer_task(&mut self) -> Result<JoinHandle<()>> {
        let ring_buffer = self
            .ring_buffer
            .take()
            .ok_or_else(|| anyhow::anyhow!("Ring buffer not available"))?;

        let event_sender = self
            .event_sender
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Event sender not available"))?
            .clone();

        let running = Arc::clone(&self.running);
        let statistics = Arc::clone(&self.statistics);

        let task = tokio::spawn(async move {
            tracing::info!("Ring buffer polling task started");

            while running.load(Ordering::Relaxed) {
                // Poll ring buffer for events
                match ring_buffer.poll(Duration::from_millis(100)) {
                    Ok(_) => {
                        // Events are processed in the callback
                    }
                    Err(e) => {
                        tracing::error!("Ring buffer poll error: {}", e);

                        // Update error statistics
                        {
                            let mut stats = statistics.write().await;
                            stats.processing_errors =
                                ErrorCount::from_raw(stats.processing_errors.as_raw() + 1);
                        }

                        // Brief delay before retrying
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }

            tracing::info!("Ring buffer polling task stopped");
        });

        Ok(task)
    }

    /// Process a batch of events
    async fn process_event_batch(
        events: &[EbpfEvent],
        handlers: &[Arc<dyn EventHandler>],
        statistics: &Arc<RwLock<EventStatistics>>,
    ) {
        let start_time = Instant::now();
        let mut processed_count = 0;
        let mut error_count = 0;

        for event in events {
            // Find handlers that can process this event
            let applicable_handlers: Vec<_> = handlers
                .iter()
                .filter(|handler| handler.can_handle(event))
                .collect();

            if applicable_handlers.is_empty() {
                tracing::warn!("No handlers available for event: {:?}", event);
                continue;
            }

            // Process event with applicable handlers
            for handler in applicable_handlers {
                match handler.handle_event(event.clone()).await {
                    Ok(()) => {
                        processed_count += 1;
                        tracing::trace!("Event processed by handler: {}", handler.name());
                    }
                    Err(e) => {
                        error_count += 1;
                        // Log with session context for packet events
                        match event {
                            EbpfEvent::PacketMetadata(ref packet) => {
                                tracing::error!(
                                    session_id = %packet.session_id.as_raw(),
                                    packet_type = ?packet.packet_type,
                                    handler = %handler.name(),
                                    error = %e,
                                    "Handler failed to process packet event"
                                );
                            }
                            EbpfEvent::SecurityEvent(ref security) => {
                                tracing::error!(
                                    session_id = %security.session_id.as_raw(),
                                    event_type = ?security.event_type,
                                    handler = %handler.name(),
                                    error = %e,
                                    "Handler failed to process security event"
                                );
                            }
                            _ => {
                                tracing::error!(
                                    handler = %handler.name(),
                                    error = %e,
                                    "Handler failed to process event"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Update statistics
        let processing_time = start_time.elapsed();
        {
            let mut stats = statistics.write().await;
            stats
                .total_events_processed
                .fetch_add(processed_count as u64, std::sync::atomic::Ordering::Relaxed);
            stats.processing_errors =
                ErrorCount::from_raw(stats.processing_errors.as_raw() + error_count);

            // Update event type counters
            for event in events {
                match event {
                    EbpfEvent::PacketMetadata(_) => {
                        stats
                            .packet_metadata_events
                            .increment(std::sync::atomic::Ordering::Relaxed);
                    }
                    EbpfEvent::SecurityEvent(_) => {
                        stats
                            .security_events
                            .increment(std::sync::atomic::Ordering::Relaxed);
                    }
                    EbpfEvent::PerformanceMetric(_) => {
                        stats
                            .performance_metric_events
                            .increment(std::sync::atomic::Ordering::Relaxed);
                    }
                    EbpfEvent::SystemAlert(_) => {
                        stats
                            .system_alert_events
                            .increment(std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            // Update average processing time
            let total_events = stats
                .total_events_processed
                .load(std::sync::atomic::Ordering::Relaxed) as f64;
            if total_events > 0.0 {
                let current_avg = (stats.average_processing_time_us * 1000) as f64; // Convert microseconds to nanoseconds
                let new_time_ns = processing_time.as_nanos() as f64 / events.len() as f64;
                let avg_ns = (current_avg * (total_events - processed_count as f64)
                    + new_time_ns * processed_count as f64)
                    / total_events;
                stats.average_processing_time_us = (avg_ns / 1000.0) as u64; // Convert back to microseconds
            }
        }

        if processed_count > 0 {
            tracing::debug!(
                "Processed {} events in {:?}",
                processed_count,
                processing_time
            );
        }
    }

    /// Update statistics rates
    async fn update_statistics_rates(
        statistics: &Arc<RwLock<EventStatistics>>,
        last_update: &Instant,
    ) {
        let elapsed = last_update.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let mut stats = statistics.write().await;
            stats.events_per_second = Rate::from_raw(
                (stats
                    .total_events_processed
                    .load(std::sync::atomic::Ordering::Relaxed) as f64
                    / elapsed) as f32,
            );
        }
    }

    /// Get current statistics
    pub async fn get_statistics(&self) -> Result<EventStatistics> {
        let stats = self.statistics.read().await;
        Ok(stats.clone())
    }

    /// Reset statistics
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = EventStatistics::default();

        let mut last_update = self.last_stats_update.write().await;
        *last_update = Instant::now();

        tracing::info!("Event processor statistics reset");
    }

    /// Check if processor is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get handler count
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Send a test event (for testing purposes)
    pub async fn send_test_event(&self, event: EbpfEvent) -> Result<()> {
        if let Some(sender) = &self.event_sender {
            sender.send(event)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Event sender not available"))
        }
    }

    /// Get ring buffer manager for daemon integration
    /// Returns the shared instance used for event processing
    pub fn ring_buffer_manager(&self) -> Arc<RwLock<RingBufferManager>> {
        Arc::clone(&self.ring_buffer_manager)
    }
}

/// Example event handlers for common use cases

/// Logging event handler
pub struct LoggingEventHandler {
    name: String,
}

impl LoggingEventHandler {
    pub fn new() -> Self {
        Self {
            name: "LoggingEventHandler".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl EventHandler for LoggingEventHandler {
    async fn handle_event(&self, event: EbpfEvent) -> Result<()> {
        match event {
            EbpfEvent::PacketMetadata(packet) => {
                tracing::info!(
                    "Packet: session={}, seq={}, src={}:{}, dst={}:{}, size={}",
                    packet.session_id.as_raw(),
                    packet.sequence_number.as_raw(),
                    packet.src_ip,
                    packet.source_port.as_raw(),
                    packet.dst_ip,
                    packet.dest_port.as_raw(),
                    packet.packet_size.as_usize()
                );
            }
            EbpfEvent::SecurityEvent(security) => {
                tracing::warn!(
                    "Security event: type={:?}, severity={:?}, src={}:{}, action={:?}",
                    security.event_type,
                    security.severity,
                    security.src_ip,
                    security.src_port.as_raw(),
                    security.action_taken
                );
            }
            EbpfEvent::PerformanceMetric(metric) => {
                tracing::debug!(
                    "Performance metric: {} = {} {:?}",
                    metric.metric_type,
                    metric.value.as_raw(),
                    metric.labels
                );
            }
            EbpfEvent::SystemAlert(alert) => match alert.severity {
                AlertSeverity::Critical | AlertSeverity::Error => {
                    tracing::error!("System alert [{}]: {}", alert.alert_type, alert.message);
                }
                AlertSeverity::Warning => {
                    tracing::warn!("System alert [{}]: {}", alert.alert_type, alert.message);
                }
                AlertSeverity::Info => {
                    tracing::info!("System alert [{}]: {}", alert.alert_type, alert.message);
                }
            },
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn can_handle(&self, _event: &EbpfEvent) -> bool {
        true // Can handle all event types
    }
}

/// Metrics collection event handler
pub struct MetricsEventHandler {
    name: String,
    metrics: Arc<RwLock<HashMap<String, f64>>>,
}

impl MetricsEventHandler {
    pub fn new() -> Self {
        Self {
            name: "MetricsEventHandler".to_string(),
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_metrics(&self) -> HashMap<String, f64> {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }
}

#[async_trait::async_trait]
impl EventHandler for MetricsEventHandler {
    async fn handle_event(&self, event: EbpfEvent) -> Result<()> {
        let mut metrics = self.metrics.write().await;

        match event {
            EbpfEvent::PacketMetadata(packet) => {
                *metrics.entry("packets_total".to_string()).or_insert(0.0) += 1.0;
                *metrics.entry("bytes_total".to_string()).or_insert(0.0) +=
                    packet.packet_size.as_usize() as f64;
            }
            EbpfEvent::SecurityEvent(security) => {
                let event_type = format!("{:?}", security.event_type);
                let key = format!("security_events_{}", event_type.to_lowercase());
                *metrics.entry(key).or_insert(0.0) += 1.0;
            }
            EbpfEvent::PerformanceMetric(metric) => {
                metrics.insert(metric.metric_type, metric.value.as_raw());
            }
            EbpfEvent::SystemAlert(alert) => {
                let severity = format!("{:?}", alert.severity).to_lowercase();
                let key = format!("system_alerts_{}", severity);
                *metrics.entry(key).or_insert(0.0) += 1.0;
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn can_handle(&self, _event: &EbpfEvent) -> bool {
        true // Can handle all event types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_processor_creation() {
        let processor = EventProcessor::new();
        assert!(processor.is_ok());

        let processor = processor.unwrap();
        assert!(!processor.is_running());
        assert_eq!(processor.handler_count(), 0);
    }

    #[tokio::test]
    async fn test_add_handler() {
        let mut processor = EventProcessor::new().unwrap();
        let handler = Arc::new(LoggingEventHandler::new());

        processor.add_handler(handler);
        assert_eq!(processor.handler_count(), 1);
    }

    #[tokio::test]
    async fn test_statistics() {
        let processor = EventProcessor::new().unwrap();
        let stats = processor.get_statistics().await.unwrap();

        assert_eq!(stats.total_events_processed, EventCount::new(0));
        assert_eq!(stats.processing_errors, ErrorCount::new(0));
        assert_eq!(stats.events_per_second, Rate::new(0.0));
    }

    #[tokio::test]
    async fn test_logging_event_handler() {
        let handler = LoggingEventHandler::new();
        assert_eq!(handler.name(), "LoggingEventHandler");

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

        let event = EbpfEvent::PacketMetadata(packet_event);
        assert!(handler.can_handle(&event));

        let result = handler.handle_event(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_metrics_event_handler() {
        let handler = MetricsEventHandler::new();
        assert_eq!(handler.name(), "MetricsEventHandler");

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

        let event = EbpfEvent::PacketMetadata(packet_event);
        let result = handler.handle_event(event).await;
        assert!(result.is_ok());

        let metrics = handler.get_metrics().await;
        assert_eq!(metrics.get("packets_total"), Some(&1.0));
        assert_eq!(metrics.get("bytes_total"), Some(&1500.0));
    }

    #[test]
    fn test_event_processing_config() {
        let config = EventProcessingConfig::default();
        assert_eq!(config.ring_buffer_size, RingBufferSize::new(1024 * 1024));
        assert_eq!(config.batch_size, 32);
        assert!(config.enable_metrics);
        assert!(config.enable_tracing);
    }
}
