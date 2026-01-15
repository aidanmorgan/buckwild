//! eBPF ring buffer management
//!
//! This module provides ring buffer management for efficient communication
//! between eBPF programs and userspace applications.

#![cfg(target_os = "linux")]

use buckwild_common::error::BuckwildError;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;

/// Maximum number of events in flight for backpressure
const MAX_EVENTS_IN_FLIGHT: usize = 10000;

/// Ring buffer manager for eBPF event processing
pub struct RingBufferManager {
    /// Ring buffer instance (wrapped in Option for lifecycle management)
    ring_buffer: Option<RingBuffer<'static>>,
    /// Event sender channel
    event_sender: mpsc::UnboundedSender<PacketEventParsed>,
    /// Event receiver channel (Option to allow taking ownership)
    event_receiver: Option<mpsc::UnboundedReceiver<PacketEventParsed>>,
    /// Manager configuration
    config: RingBufferConfig,
    /// Statistics
    stats: Arc<RingBufferStats>,
    /// Backpressure semaphore
    backpressure: Arc<Semaphore>,
    /// Running flag
    running: Arc<AtomicU64>,
}

// SAFETY: RingBufferManager is safe to Send across thread boundaries because:
// 1. RingBuffer<'static> is only accessed from the polling task (single-threaded access)
// 2. All shared state (stats, backpressure, running) uses Arc and atomic types
// 3. libbpf's internal state is thread-safe for the operations we perform
// 4. The event channel (mpsc) is already Send + Sync
unsafe impl Send for RingBufferManager {}

/// Ring buffer configuration
#[derive(Debug, Clone)]
pub struct RingBufferConfig {
    /// Buffer size in bytes (default: 256KB)
    pub buffer_size: usize,
    /// Polling timeout in milliseconds (default: 100ms)
    pub poll_timeout: Duration,
    /// Maximum events per batch (default: 100)
    pub max_batch_size: usize,
    /// Whether to enable event batching
    pub enable_batching: bool,
    /// Maximum events in flight before backpressure kicks in
    pub max_events_in_flight: usize,
}

/// Parsed packet event from ring buffer
/// Matches the C struct packet_event from maps.h (32 bytes)
#[derive(Debug, Clone)]
pub struct PacketEventParsed {
    /// Session identifier
    pub session_id: u64,
    /// Packet sequence number (64-bit as in C struct)
    pub sequence: u64,
    /// Event timestamp in microseconds
    pub timestamp_us: u64,
    /// Payload size in bytes
    pub payload_length: u16,
    /// Packet type
    pub packet_type: u8,
    /// Packet flags
    pub flags: u8,
    /// Source IP address
    pub src_ip: std::net::Ipv4Addr,
    /// Time when event was received in userspace
    pub received_at: Instant,
}

/// Ring buffer statistics
#[derive(Debug)]
pub struct RingBufferStats {
    /// Total events processed
    pub events_processed: AtomicU64,
    /// Total events dropped (channel full or parse error)
    pub events_dropped: AtomicU64,
    /// Total parse errors
    pub parse_errors: AtomicU64,
    /// Total poll operations
    pub poll_count: AtomicU64,
    /// Total poll errors
    pub poll_errors: AtomicU64,
    /// Events currently in flight
    pub events_in_flight: AtomicUsize,
    /// Total bytes processed
    pub bytes_processed: AtomicU64,
    /// Start time
    pub start_time: Instant,
}

/// Event handler callback type
pub type EventHandler = Arc<dyn Fn(PacketEventParsed) -> Result<(), BuckwildError> + Send + Sync>;

impl RingBufferManager {
    /// Create a new ring buffer manager
    #[instrument]
    pub fn new(config: RingBufferConfig) -> Result<Self, BuckwildError> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let backpressure = Arc::new(Semaphore::new(config.max_events_in_flight));

        info!(
            buffer_size = config.buffer_size,
            poll_timeout_ms = config.poll_timeout.as_millis(),
            max_batch_size = config.max_batch_size,
            "Creating ring buffer manager"
        );

        Ok(Self {
            ring_buffer: None,
            event_sender,
            event_receiver: Some(event_receiver),
            config,
            stats: Arc::new(RingBufferStats::new()),
            backpressure,
            running: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Set a pre-constructed ring buffer
    /// The ring buffer should be built with callbacks that send events to this manager
    #[instrument(skip(self, ring_buffer))]
    pub fn set_ring_buffer(&mut self, ring_buffer: RingBuffer<'static>) {
        self.ring_buffer = Some(ring_buffer);
        info!("Ring buffer set successfully");
    }

    /// Get a callback for ring buffer events
    /// This can be used when building a RingBuffer to process events
    pub fn get_event_callback(&self) -> impl Fn(&[u8]) -> i32 + 'static {
        let event_sender = self.event_sender.clone();
        let stats = Arc::clone(&self.stats);
        let backpressure = Arc::clone(&self.backpressure);

        move |data: &[u8]| -> i32 {
            // Try to parse the event
            match Self::parse_packet_event(data) {
                Ok(event) => {
                    stats.events_processed.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_processed
                        .fetch_add(data.len() as u64, Ordering::Relaxed);

                    // Check backpressure before sending
                    if let Ok(permit) = backpressure.try_acquire() {
                        stats.events_in_flight.fetch_add(1, Ordering::Relaxed);

                        // Send event to channel
                        if let Err(e) = event_sender.send(event) {
                            error!(error = %e, "Failed to send eBPF event to channel");
                            stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                            stats.events_in_flight.fetch_sub(1, Ordering::Relaxed);
                            permit.forget(); // Release permit
                            return -1;
                        }

                        // Permit will be released when event is processed
                        permit.forget();
                    } else {
                        // Backpressure - drop event
                        warn!("Backpressure active - dropping event");
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        return -1;
                    }

                    0
                }
                Err(e) => {
                    error!(error = %e, data_len = data.len(), "Failed to parse packet event");
                    stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    -1
                }
            }
        }
    }

    /// Parse a packet event from raw bytes
    /// Matches C struct packet_event from maps.h (32 bytes packed)
    fn parse_packet_event(data: &[u8]) -> Result<PacketEventParsed, BuckwildError> {
        if data.len() < 32 {
            return Err(BuckwildError::invalid_input(format!(
                "Packet event too small: {} bytes (expected 32)",
                data.len()
            )));
        }

        // Parse packed structure (little-endian)
        let session_id = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let sequence = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let timestamp_us = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);

        let payload_length = u16::from_le_bytes([data[24], data[25]]);
        let packet_type = data[26];
        let flags = data[27];

        let src_ip = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Ok(PacketEventParsed {
            session_id,
            sequence,
            timestamp_us,
            payload_length,
            packet_type,
            flags,
            src_ip: std::net::Ipv4Addr::from(src_ip),
            received_at: Instant::now(),
        })
    }

    /// Start polling the ring buffer for events
    #[instrument(skip(self))]
    pub async fn start_polling(&mut self) -> Result<(), BuckwildError> {
        if self.ring_buffer.is_none() {
            return Err(BuckwildError::internal_error("Ring buffer not initialized"));
        }

        self.running.store(1, Ordering::Release);
        info!("Starting ring buffer polling");

        while self.running.load(Ordering::Acquire) == 1 {
            if let Some(ref mut ring_buffer) = self.ring_buffer {
                self.stats.poll_count.fetch_add(1, Ordering::Relaxed);

                match ring_buffer.poll(self.config.poll_timeout) {
                    Ok(_) => {
                        debug!("Ring buffer poll completed successfully");
                    }
                    Err(e) => {
                        self.stats.poll_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(error = %e, "Ring buffer poll error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }

            // Yield to prevent busy waiting
            tokio::task::yield_now().await;
        }

        info!("Ring buffer polling stopped");
        Ok(())
    }

    /// Stop the ring buffer manager
    #[instrument(skip(self))]
    pub fn stop(&mut self) {
        info!("Stopping ring buffer manager");
        self.running.store(0, Ordering::Release);
        self.ring_buffer = None;
    }

    /// Get the event receiver channel (mutable reference)
    /// Panics if receiver has been taken via take_event_receiver()
    pub fn event_receiver(&mut self) -> &mut mpsc::UnboundedReceiver<PacketEventParsed> {
        self.event_receiver
            .as_mut()
            .expect("Event receiver already taken")
    }

    /// Take ownership of the event receiver channel
    /// Returns None if already taken
    /// Use this when transferring the receiver to an event loop
    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<PacketEventParsed>> {
        self.event_receiver.take()
    }

    /// Release backpressure permit (call after processing event)
    pub fn release_event(&self) {
        self.stats.events_in_flight.fetch_sub(1, Ordering::Relaxed);
        self.backpressure.add_permits(1);
    }

    /// Get ring buffer statistics
    pub fn get_stats(&self) -> RingBufferStatsSnapshot {
        RingBufferStatsSnapshot {
            events_processed: self.stats.events_processed.load(Ordering::Relaxed),
            events_dropped: self.stats.events_dropped.load(Ordering::Relaxed),
            parse_errors: self.stats.parse_errors.load(Ordering::Relaxed),
            poll_count: self.stats.poll_count.load(Ordering::Relaxed),
            poll_errors: self.stats.poll_errors.load(Ordering::Relaxed),
            events_in_flight: self.stats.events_in_flight.load(Ordering::Relaxed),
            bytes_processed: self.stats.bytes_processed.load(Ordering::Relaxed),
            uptime: self.stats.start_time.elapsed(),
        }
    }

    /// Get events per second rate
    pub fn get_event_rate(&self) -> f64 {
        let uptime_secs = self.stats.start_time.elapsed().as_secs_f64();
        if uptime_secs > 0.0 {
            self.stats.events_processed.load(Ordering::Relaxed) as f64 / uptime_secs
        } else {
            0.0
        }
    }

    /// Get bytes per second rate
    pub fn get_throughput(&self) -> f64 {
        let uptime_secs = self.stats.start_time.elapsed().as_secs_f64();
        if uptime_secs > 0.0 {
            self.stats.bytes_processed.load(Ordering::Relaxed) as f64 / uptime_secs
        } else {
            0.0
        }
    }
}

/// Snapshot of ring buffer statistics
#[derive(Debug, Clone)]
pub struct RingBufferStatsSnapshot {
    /// Total events processed
    pub events_processed: u64,
    /// Total events dropped
    pub events_dropped: u64,
    /// Total parse errors
    pub parse_errors: u64,
    /// Total poll operations
    pub poll_count: u64,
    /// Total poll errors
    pub poll_errors: u64,
    /// Events currently in flight
    pub events_in_flight: usize,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Manager uptime
    pub uptime: Duration,
}

impl RingBufferStats {
    fn new() -> Self {
        Self {
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            poll_count: AtomicU64::new(0),
            poll_errors: AtomicU64::new(0),
            events_in_flight: AtomicUsize::new(0),
            bytes_processed: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self {
            buffer_size: 256 * 1024, // 256KB
            poll_timeout: Duration::from_millis(100),
            max_batch_size: 100,
            enable_batching: true,
            max_events_in_flight: MAX_EVENTS_IN_FLIGHT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_manager_creation() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_ring_buffer_config_defaults() {
        let config = RingBufferConfig::default();
        assert_eq!(config.buffer_size, 256 * 1024);
        assert_eq!(config.poll_timeout, Duration::from_millis(100));
        assert_eq!(config.max_batch_size, 100);
        assert!(config.enable_batching);
        assert_eq!(config.max_events_in_flight, MAX_EVENTS_IN_FLIGHT);
    }

    #[test]
    fn test_parse_packet_event_valid() {
        // Create a valid 32-byte packet event (little-endian)
        let mut data = vec![0u8; 32];

        // session_id = 0x1234567890ABCDEF
        data[0..8].copy_from_slice(&0x1234567890ABCDEFu64.to_le_bytes());

        // sequence = 42
        data[8..16].copy_from_slice(&42u64.to_le_bytes());

        // timestamp_us = 1234567890
        data[16..24].copy_from_slice(&1234567890u64.to_le_bytes());

        // payload_length = 1500
        data[24..26].copy_from_slice(&1500u16.to_le_bytes());

        // packet_type = 0x01
        data[26] = 0x01;

        // flags = 0x80
        data[27] = 0x80;

        // src_ip = 192.168.1.100
        data[28..32].copy_from_slice(&0xC0A80164u32.to_le_bytes());

        let result = RingBufferManager::parse_packet_event(&data);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.session_id, 0x1234567890ABCDEF);
        assert_eq!(event.sequence, 42);
        assert_eq!(event.timestamp_us, 1234567890);
        assert_eq!(event.payload_length, 1500);
        assert_eq!(event.packet_type, 0x01);
        assert_eq!(event.flags, 0x80);
        assert_eq!(event.src_ip, std::net::Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_parse_packet_event_too_small() {
        let data = vec![0u8; 16]; // Only 16 bytes
        let result = RingBufferManager::parse_packet_event(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ring_buffer_stats() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.parse_errors, 0);
        assert_eq!(stats.poll_count, 0);
        assert_eq!(stats.events_in_flight, 0);
        assert_eq!(stats.bytes_processed, 0);
    }

    #[test]
    fn test_event_rate_calculation() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();

        // Initially should be 0
        assert_eq!(manager.get_event_rate(), 0.0);

        // Simulate some events
        manager
            .stats
            .events_processed
            .store(1000, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(100));

        // Should have a non-zero rate now
        assert!(manager.get_event_rate() > 0.0);
    }

    #[test]
    fn test_throughput_calculation() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();

        // Initially should be 0
        assert_eq!(manager.get_throughput(), 0.0);

        // Simulate some bytes processed
        manager
            .stats
            .bytes_processed
            .store(100000, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(100));

        // Should have a non-zero throughput now
        assert!(manager.get_throughput() > 0.0);
    }
}
