// Flow Control Engine - Consolidated flow control logic with congestion control
//
// This implements comprehensive flow control and congestion control algorithms
// including slow start, congestion avoidance, fast recovery, and window management.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::cmp::min;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, instrument};

use crate::engines::flow_control::CongestionControl;
use crate::error::EngineError;
use crate::protocol::packet::{Packet, builder::PacketBuilderEngine};
use crate::protocol::types::*;

/// Flow Control Header (4 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowControlHeader {
    /// Window size (16-bit) - advertised receive window
    pub window_size: WindowSize,
    /// Reserved field (16-bit) - must be 0x0000
    pub reserved: ReservedField,
}

impl FlowControlHeader {
    /// Create a new flow control header
    pub fn new(window_size: WindowSize) -> Self {
        Self {
            window_size,
            reserved: ReservedField::new(),
        }
    }

    /// Serialize to bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&(self.window_size.as_u32() as u16).to_be_bytes());
        bytes[2..4].copy_from_slice(&self.reserved.as_be_bytes());
        bytes
    }

    /// Deserialize from bytes (big-endian)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EngineError> {
        if bytes.len() < 4 {
            return Err(EngineError::flow_control_error(
                "Flow control header requires 4 bytes",
            ));
        }

        let window_size_raw = u16::from_be_bytes([bytes[0], bytes[1]]);
        let _reserved = u16::from_be_bytes([bytes[2], bytes[3]]);

        Ok(Self {
            window_size: WindowSize::new(window_size_raw as u32),
            reserved: ReservedField::new(),
        })
    }
}

/// Flow control and congestion control constants
pub const INITIAL_CONGESTION_WINDOW: CongestionWindow = CongestionWindow(1460); // 1 MSS
pub static INITIAL_SEND_WINDOW: WindowSize = WindowSize::new(65535); // 64KB - 1 (spec requires 65535)
pub static INITIAL_RECEIVE_WINDOW: WindowSize = WindowSize::new(65535); // 64KB - 1 (spec requires 65535)
pub const MAX_CONGESTION_WINDOW: CongestionWindow = CongestionWindow(65535); // Max window per spec
pub const MIN_CONGESTION_WINDOW: CongestionWindow = CongestionWindow(292); // 2 MSS (2 × 146 bytes per spec)
pub const MSS: MaxSegmentSize = MaxSegmentSize::new(1460); // Maximum Segment Size
pub const SLOW_START_THRESHOLD: SlowStartThreshold = SlowStartThreshold::from_raw(65535); // Max window per spec
pub const WINDOW_UPDATE_THRESHOLD: WindowUpdateThreshold = WindowUpdateThreshold::new(0.25); // 25% change triggers update
pub const ZERO_WINDOW_PROBE_INTERVAL_MS: ZeroWindowProbeInterval =
    ZeroWindowProbeInterval::new(5000); // 5 seconds per spec
pub const MAX_ZERO_WINDOW_PROBE_INTERVAL_MS: ZeroWindowProbeInterval =
    ZeroWindowProbeInterval::new(60000); // 60 seconds
pub const WINDOW_UPDATE_TIMEOUT_MS: Timeout = Timeout::new(5000); // 5 seconds
pub const MAX_RECEIVE_BUFFER_SIZE: MaxReceiveBufferSize = MaxReceiveBufferSize::new(1048576); // 1MB
pub static MAX_RECEIVE_WINDOW: WindowSize = WindowSize::new(65535); // Max window per spec

/// Flow control state for send and receive windows
#[derive(Debug)]
pub struct FlowControlState {
    /// Send window size (advertised by peer)
    pub send_window: AtomicU32,

    /// Receive window size (advertised to peer)
    pub receive_window: AtomicU32,

    /// Send sequence numbers
    pub send_next: AtomicU32,
    pub send_unacked: AtomicU32,

    /// Receive sequence numbers
    pub receive_next: AtomicU32,
    pub receive_window_start: AtomicU32,

    /// Advertised window to peer
    pub advertised_window: AtomicU32,

    /// Send buffer for unacknowledged data
    pub send_buffer: Mutex<VecDeque<QueuedData>>,

    /// Receive buffer for out-of-order data
    pub receive_buffer: Mutex<HashMap<u32, ReceivedData>>,

    /// Reorder buffer for in-order delivery
    pub reorder_buffer: Mutex<BTreeMap<u32, Packet>>,
}

impl FlowControlState {
    pub fn new(initial_send_seq: u32, initial_recv_seq: u32) -> Self {
        Self {
            send_window: AtomicU32::new(INITIAL_SEND_WINDOW.as_u32()),
            receive_window: AtomicU32::new(INITIAL_RECEIVE_WINDOW.as_u32()),
            send_next: AtomicU32::new(initial_send_seq),
            send_unacked: AtomicU32::new(initial_send_seq),
            receive_next: AtomicU32::new(initial_recv_seq),
            receive_window_start: AtomicU32::new(initial_recv_seq),
            advertised_window: AtomicU32::new(INITIAL_RECEIVE_WINDOW.as_u32()),
            send_buffer: Mutex::new(VecDeque::new()),
            receive_buffer: Mutex::new(HashMap::new()),
            reorder_buffer: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn send_window(&self) -> WindowSize {
        WindowSize::new(self.send_window.load(Ordering::Relaxed))
    }

    pub fn receive_window(&self) -> WindowSize {
        WindowSize::new(self.receive_window.load(Ordering::Relaxed))
    }
}
// Queued data for transmission
#[derive(Debug, Clone)]
pub struct QueuedData {
    pub data: Bytes,
    pub sequence_number: SequenceNumber,
    pub timestamp: Instant,
    pub retransmit_count: Counter,
}

/// Received data tracking
#[derive(Debug, Clone)]
pub struct ReceivedData {
    pub data: Bytes,
    pub sequence_number: SequenceNumber,
    pub timestamp: Instant,
}

/// Flow control configuration
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    pub initial_congestion_window: CongestionWindow,
    pub initial_send_window: WindowSize,
    pub initial_receive_window: WindowSize,
    pub max_congestion_window: CongestionWindow,
    pub min_congestion_window: CongestionWindow,
    pub mss: MaxSegmentSize,
    pub slow_start_threshold: SlowStartThreshold,
    pub window_update_threshold: WindowUpdateThreshold,
    pub zero_window_probe_interval_ms: ZeroWindowProbeInterval,
    pub max_receive_buffer_size: MaxReceiveBufferSize,
    pub hmac_policy: HmacPolicy,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            initial_congestion_window: INITIAL_CONGESTION_WINDOW,
            initial_send_window: INITIAL_SEND_WINDOW,
            initial_receive_window: INITIAL_RECEIVE_WINDOW,
            max_congestion_window: MAX_CONGESTION_WINDOW,
            min_congestion_window: MIN_CONGESTION_WINDOW,
            mss: MSS,
            slow_start_threshold: SLOW_START_THRESHOLD,
            window_update_threshold: WINDOW_UPDATE_THRESHOLD,
            zero_window_probe_interval_ms: ZERO_WINDOW_PROBE_INTERVAL_MS,
            max_receive_buffer_size: MAX_RECEIVE_BUFFER_SIZE,
            hmac_policy: HmacPolicy::Medium, // Default to Medium security
        }
    }
}

/// Flow control operational state snapshot
/// NOTE: This is operational state for algorithm decisions, not metrics collection
/// Metrics are tracked via tokio-tracing events per design/rules.md
#[derive(Debug, Default, Clone)]
pub struct FlowControlStats {
    pub current_congestion_window: CongestionWindow,
    pub current_send_window: WindowSize,
    pub current_receive_window: WindowSize,
    pub bytes_in_flight: ByteCount,
    pub rtt: RoundTripTime,
}

/// Flow Control Engine for comprehensive flow and congestion control
pub struct FlowControlEngine {
    /// Connection ID this engine belongs to
    connection_id: ConnectionId,

    /// Session ID
    session_id: SessionId,

    /// Flow control state
    flow_control: FlowControlState,

    /// Congestion control engine
    congestion_control: CongestionControl,

    /// Flow control configuration
    config: FlowControlConfig,

    /// Flow control statistics
    stats: RwLock<FlowControlStats>,
}

impl FlowControlEngine {
    /// Create new flow control engine
    pub fn new(
        connection_id: ConnectionId,
        session_id: SessionId,
        initial_send_seq: u32,
        initial_recv_seq: u32,
    ) -> Self {
        let flow_control = FlowControlState::new(initial_send_seq, initial_recv_seq);
        let config = FlowControlConfig::default();

        Self {
            connection_id,
            session_id,
            flow_control,
            congestion_control: CongestionControl::new(
                config.initial_congestion_window.as_u32(),
                config.slow_start_threshold.as_u32(),
            ),
            config,
            stats: RwLock::new(FlowControlStats::default()),
        }
    }

    /// Check if data can be sent within current window
    pub fn can_send_data(&self, data_length: u32) -> bool {
        let send_next = self.flow_control.send_next.load(Ordering::Relaxed);
        let send_unacked = self.flow_control.send_unacked.load(Ordering::Relaxed);
        let bytes_in_flight = send_next.wrapping_sub(send_unacked);
        let effective_window = self.calculate_effective_window();
        let available_window = effective_window.saturating_sub(bytes_in_flight);

        data_length <= available_window
    }

    /// Calculate effective window (minimum of congestion and flow control windows)
    pub fn calculate_effective_window(&self) -> u32 {
        let congestion_window = self.congestion_control.get_congestion_window();
        let flow_control_window = self.flow_control.send_window().as_u32();

        min(congestion_window, flow_control_window)
    }

    /// Send data with flow control
    #[instrument(skip(self, data), fields(session_id = %self.session_id, data_len = data.len()))]
    pub async fn send_data(&self, data: Bytes) -> Result<(), EngineError> {
        // Check if we can send data
        if !self.can_send_data(data.len() as u32) {
            return Err(EngineError::window_exhausted());
        }

        // Fragment data if necessary
        if data.len() > self.config.mss.as_usize() {
            return self.send_fragmented_data(data).await;
        }

        // Create data packet
        let sequence_number =
            SequenceNumber::new(self.flow_control.send_next.load(Ordering::Relaxed));
        let data_packet = self
            .create_data_packet(sequence_number, data.clone())
            .await?;

        // Update send state
        let new_send_next = sequence_number.as_u32() + data.len() as u32;
        self.flow_control
            .send_next
            .store(new_send_next, Ordering::Relaxed);

        // Send packet (this would be handled by the network layer)
        self.send_packet(data_packet).await?;

        // Set retransmission timer
        self.set_retransmission_timer(sequence_number).await;

        tracing::trace!(
            bytes = data.len(),
            sequence = sequence_number.as_u32(),
            "Data sent"
        );

        // Queue data for potential retransmission
        let queued_data = QueuedData {
            data,
            sequence_number: SequenceNumber::new(
                self.flow_control.send_next.load(Ordering::Relaxed),
            ),
            timestamp: Instant::now(),
            retransmit_count: Counter::new(0),
        };

        let mut send_buffer = self.flow_control.send_buffer.lock().await;
        send_buffer.push_back(queued_data);

        Ok(())
    }

    /// Send fragmented data
    async fn send_fragmented_data(&self, data: Bytes) -> Result<(), EngineError> {
        let mss = self.config.mss.as_usize();
        let mut offset = 0;

        while offset < data.len() {
            let fragment_size = min(mss, data.len() - offset);
            let fragment = data.slice(offset..offset + fragment_size);

            // Send fragment
            let sequence_number =
                SequenceNumber::new(self.flow_control.send_next.load(Ordering::Relaxed));
            let fragment_packet = self
                .create_data_packet(sequence_number, fragment.clone())
                .await?;

            let new_send_next = sequence_number.as_u32() + fragment.len() as u32;
            self.flow_control
                .send_next
                .store(new_send_next, Ordering::Relaxed);
            self.send_packet(fragment_packet).await?;
            self.set_retransmission_timer(sequence_number).await;

            offset += fragment_size;
        }

        Ok(())
    }

    /// Create data packet
    async fn create_data_packet(
        &self,
        sequence_number: crate::protocol::types::SequenceNumber,
        data: Bytes,
    ) -> Result<Packet, EngineError> {
        let advertised_window =
            WindowSize::new(self.flow_control.advertised_window.load(Ordering::Relaxed));

        // Build data packet using PacketBuilderEngine
        let version_byte = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let hmac_policy = self.config.hmac_policy;
        let packet_builder = PacketBuilderEngine::with_defaults(version_byte, hmac_policy);

        // Get the next expected receive sequence number for ACK
        let receive_next_seq =
            SequenceNumber::new(self.flow_control.receive_next.load(Ordering::Relaxed));
        let ack_number = AckNumber::new(receive_next_seq.as_u32());

        let data_packet = packet_builder
            .data()
            .session_id(self.session_id.clone())
            .sequence_number(sequence_number)
            .ack_number(ack_number)
            .window_size(advertised_window)
            .payload(data)
            .build()
            .map_err(|e| EngineError::FlowControlError {
                reason: format!("Packet builder failed: {:?}", e),
            })?;

        Ok(Packet::Data(data_packet))
    }

    /// Send packet
    ///
    /// Integration point: network layer should override this to send actual packets.
    /// Currently logs packet metadata for testing/development.
    async fn send_packet(&self, packet: Packet) -> Result<(), EngineError> {
        // Network integration point - actual packet transmission handled by network layer
        debug!(
            session_id = %self.session_id,
            packet_size = packet.payload().len(),
            "Packet ready for transmission"
        );
        Ok(())
    }

    /// Set retransmission timer
    ///
    /// Integration point: retransmission system should override this to manage timers.
    /// Currently logs timer metadata for testing/development.
    async fn set_retransmission_timer(
        &self,
        sequence_number: crate::protocol::types::SequenceNumber,
    ) {
        // Retransmission integration point - actual timer management handled by recovery engine
        debug!(
            session_id = %self.session_id,
            sequence_number = %sequence_number,
            "Retransmission timer set"
        );
    }

    /// Get flow control statistics
    pub async fn get_flow_control_stats(&self) -> FlowControlStats {
        let mut stats = self.stats.read().await.clone();

        // Update current values
        stats.current_congestion_window =
            CongestionWindow::new(self.congestion_control.get_congestion_window());
        stats.current_send_window = self.flow_control.send_window();
        stats.current_receive_window = self.flow_control.receive_window();

        // Calculate bytes in flight
        let send_next = self.flow_control.send_next.load(Ordering::Relaxed);
        let send_unacked = self.flow_control.send_unacked.load(Ordering::Relaxed);
        let bytes_in_flight_raw = send_next.wrapping_sub(send_unacked);
        stats.bytes_in_flight = ByteCount::new(bytes_in_flight_raw as u64);

        stats
    }

    /// Get current send window size
    pub fn get_send_window(&self) -> WindowSize {
        self.flow_control.send_window()
    }

    /// Get current receive window size
    pub fn get_receive_window(&self) -> WindowSize {
        self.flow_control.receive_window()
    }

    /// Get current congestion window size
    pub fn get_congestion_window(&self) -> u32 {
        self.congestion_control.get_congestion_window()
    }

    /// Get current congestion state
    pub fn get_congestion_state(&self) -> CongestionState {
        self.congestion_control.get_congestion_state()
    }

    /// Get slow start threshold
    pub fn get_slow_start_threshold(&self) -> u32 {
        self.congestion_control.get_slow_start_threshold()
    }

    /// Process acknowledgment (for testing)
    #[cfg(test)]
    pub fn process_ack(&self, ack_number: u32, bytes_acked: u32) -> Result<(), EngineError> {
        self.congestion_control.process_ack(ack_number, bytes_acked)
    }

    /// Handle timeout (for testing)
    #[cfg(test)]
    pub fn handle_timeout(&self) -> Result<(), EngineError> {
        self.congestion_control.handle_timeout()
    }

    /// Update RTT (for testing)
    #[cfg(test)]
    pub fn update_rtt(&self, rtt: RoundTripTime) {
        self.congestion_control.update_rtt(rtt);
    }

    /// Get RTO (for testing)
    #[cfg(test)]
    pub fn get_rto(&self) -> RoundTripTime {
        self.congestion_control.get_rto()
    }

    /// Set send window (for testing)
    #[cfg(test)]
    pub fn set_send_window(&self, window: u32) {
        self.flow_control
            .send_window
            .store(window, Ordering::Relaxed);
    }

    /// Set congestion window (for testing)
    #[cfg(test)]
    pub fn set_congestion_window(&self, window: u32) {
        self.congestion_control.set_congestion_window(window);
    }

    /// Set congestion state (for testing)
    #[cfg(test)]
    pub fn set_congestion_state(&self, state: CongestionState) {
        self.congestion_control.set_congestion_state(state);
    }

    /// Get send_next sequence number (for testing)
    #[cfg(test)]
    pub fn get_send_next(&self) -> u32 {
        self.flow_control.send_next.load(Ordering::Relaxed)
    }

    /// Set send_next sequence number (for testing)
    #[cfg(test)]
    pub fn set_send_next(&self, seq: u32) {
        self.flow_control.send_next.store(seq, Ordering::Relaxed);
    }

    /// Get send_unacked sequence number (for testing)
    #[cfg(test)]
    pub fn get_send_unacked(&self) -> u32 {
        self.flow_control.send_unacked.load(Ordering::Relaxed)
    }

    /// Shutdown the flow control engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        // Clear send buffer
        {
            let mut send_buffer = self.flow_control.send_buffer.lock().await;
            send_buffer.clear();
        }

        // Clear receive buffer
        {
            let mut receive_buffer = self.flow_control.receive_buffer.lock().await;
            receive_buffer.clear();
        }

        // Clear reorder buffer
        {
            let mut reorder_buffer = self.flow_control.reorder_buffer.lock().await;
            reorder_buffer.clear();
        }

        info!(
            connection_id = %self.connection_id,
            session_id = %self.session_id,
            "Flow control engine shut down"
        );

        Ok(())
    }
}
