// Session state implementation
//
// This file implements the SessionState struct with atomic fields for concurrent access.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::{
    AtomicCongestionWindow, AtomicPortValue, AtomicSessionParam, CongestionWindow, Port,
    RoundTripTime, SequenceNumber, SyncState, WindowSize,
};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
// Use standard atomic types directly

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus {
    /// Session is initializing
    Initializing = 0,

    /// Session is established
    Established = 1,

    /// Session is closing
    Closing = 2,

    /// Session is closed
    Closed = 3,
}

impl SessionStatus {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Initializing),
            1 => Some(Self::Established),
            2 => Some(Self::Closing),
            3 => Some(Self::Closed),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Store to atomic storage
    pub fn store(&self, atomic: &SyncState, ordering: std::sync::atomic::Ordering) {
        atomic.store(self.as_u8(), ordering);
    }

    /// Load from atomic storage
    pub fn load(atomic: &SyncState, ordering: std::sync::atomic::Ordering) -> Self {
        Self::from_u8(atomic.load(ordering)).unwrap_or(Self::Closed)
    }
}

/// Window state for flow control
#[derive(Debug)]
#[repr(align(64))] // Align to cache line boundary
pub struct WindowState {
    /// Send window size
    send_window: WindowSize,

    /// Receive window size
    recv_window: WindowSize,

    /// Congestion window size
    congestion_window: AtomicCongestionWindow,

    /// Slow start threshold
    ssthresh: WindowSize,

    /// Round trip time (microseconds)
    rtt: RoundTripTime,

    /// RTT variation (microseconds)
    rtt_var: RoundTripTime,

    /// Retransmission timeout (microseconds)
    rto: RoundTripTime,

    /// Padding to fill the cache line
    _padding: [u8; 36],
}

impl WindowState {
    /// Create a new window state
    pub fn new() -> Self {
        Self {
            send_window: WindowSize::new(65535), // Default to 64KB
            recv_window: WindowSize::new(65535), // Default to 64KB
            congestion_window: AtomicCongestionWindow::new(1460), // Start with 1 MSS
            ssthresh: WindowSize::new(65535),    // Default to 64KB
            rtt: RoundTripTime::new(100_000_000), // 100ms default in nanoseconds
            rtt_var: RoundTripTime::new(50_000_000), // 50ms default in nanoseconds
            rto: RoundTripTime::new(300_000_000), // 300ms default in nanoseconds
            _padding: [0; 36],
        }
    }

    /// Get the send window size
    pub fn send_window(&self) -> WindowSize {
        self.send_window
    }

    /// Set the send window size
    pub fn set_send_window(&mut self, value: WindowSize) {
        self.send_window = value;
    }

    /// Get the receive window size
    pub fn recv_window(&self) -> WindowSize {
        self.recv_window
    }

    /// Set the receive window size
    pub fn set_recv_window(&mut self, value: WindowSize) {
        self.recv_window = value;
    }

    /// Get the congestion window size
    pub fn congestion_window(&self) -> CongestionWindow {
        CongestionWindow::new(self.congestion_window.load(Ordering::Relaxed))
    }

    /// Set the congestion window size
    pub fn set_congestion_window(&self, value: CongestionWindow) {
        self.congestion_window
            .store(value.as_u32(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the slow start threshold
    pub fn ssthresh(&self) -> WindowSize {
        self.ssthresh
    }

    /// Set the slow start threshold
    pub fn set_ssthresh(&mut self, value: WindowSize) {
        self.ssthresh = value;
    }

    /// Get the round trip time
    pub fn rtt(&self) -> RoundTripTime {
        self.rtt
    }

    /// Set the round trip time
    pub fn set_rtt(&mut self, value: RoundTripTime) {
        self.rtt = value;
    }

    /// Get the RTT variation
    pub fn rtt_var(&self) -> RoundTripTime {
        self.rtt_var
    }

    /// Set the RTT variation
    pub fn set_rtt_var(&mut self, value: RoundTripTime) {
        self.rtt_var = value;
    }

    /// Get the retransmission timeout
    pub fn rto(&self) -> RoundTripTime {
        self.rto
    }

    /// Set the retransmission timeout
    pub fn set_rto(&mut self, value: RoundTripTime) {
        self.rto = value;
    }

    /// Update RTT and RTO according to RFC 6298
    pub fn update_rtt(&mut self, measured_rtt: RoundTripTime) {
        let current_rtt = self.rtt();
        let current_rtt_var = self.rtt_var();

        // RFC 6298 algorithm
        if current_rtt.as_nanos() == 100_000_000 {
            // Initial value (100ms in nanoseconds)
            // First measurement
            self.set_rtt(measured_rtt);
            self.set_rtt_var(RoundTripTime::new(measured_rtt.as_nanos() / 2));
            self.set_rto(RoundTripTime::new(measured_rtt.as_nanos() * 3));
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
            // SRTT = (1 - alpha) * SRTT + alpha * R'
            // where alpha = 1/8 and beta = 1/4
            let alpha = 8; // 1/8
            let beta = 4; // 1/4

            let rtt_diff = if measured_rtt.as_nanos() > current_rtt.as_nanos() {
                measured_rtt.as_nanos() - current_rtt.as_nanos()
            } else {
                current_rtt.as_nanos() - measured_rtt.as_nanos()
            };

            let new_rtt_var_ns = current_rtt_var.as_nanos() - (current_rtt_var.as_nanos() / beta)
                + (rtt_diff / beta);
            let new_rtt = RoundTripTime::new(
                current_rtt.as_nanos() - (current_rtt.as_nanos() / alpha as u64)
                    + (measured_rtt.as_nanos() / alpha as u64),
            );

            // RTO = SRTT + max(G, K*RTTVAR)
            // where K = 4 and G is the clock granularity (1ms)
            let new_rto = RoundTripTime::new(
                new_rtt.as_nanos() + std::cmp::max(1_000_000, 4 * new_rtt_var_ns), // 1ms granularity
            );

            self.set_rtt_var(RoundTripTime::new(new_rtt_var_ns));
            self.set_rtt(new_rtt);
            self.set_rto(new_rto);
        }
    }

    /// Double the RTO on timeout (with upper limit)
    pub fn backoff_rto(&mut self) {
        let current_rto = self.rto();
        let new_rto_ns = std::cmp::min(current_rto.as_nanos() * 2, 60_000_000_000); // Max 60 seconds
        self.set_rto(RoundTripTime::new(new_rto_ns));
    }

    /// Reset window state to initial values
    pub fn reset(&mut self) {
        self.set_send_window(WindowSize::new(65535));
        self.set_recv_window(WindowSize::new(65535));
        self.set_congestion_window(CongestionWindow::new(1460));
        self.set_ssthresh(WindowSize::new(65535));
        self.set_rtt(RoundTripTime::new(100_000_000));
        self.set_rtt_var(RoundTripTime::new(50_000_000));
        self.set_rto(RoundTripTime::new(300_000_000));
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache-line aligned session state with atomic fields for concurrent access
#[derive(Debug)]
#[repr(align(64))] // Align to cache line boundary
pub struct SessionState {
    // First cache line: Core session state
    /// Session status
    status: SyncState,

    /// Last activity timestamp (seconds since UNIX epoch)
    last_activity: AtomicU64,

    /// Local sequence number
    local_seq: AtomicU32,

    /// Remote sequence number
    remote_seq: AtomicU32,

    /// Local port
    local_port: AtomicPortValue,

    /// Remote port
    remote_port: AtomicPortValue,

    /// Time offset (milliseconds)
    time_offset: AtomicU32,

    /// Padding to fill the first cache line
    _padding1: [u8; 32],

    // Second cache line: Window state
    /// Window state for flow control
    window_state: WindowState,

    // Third cache line: Port hopping parameters
    /// Port hopping seed (derived from ECDH)
    port_hop_seed: [AtomicPortValue; 16],

    /// Padding to fill the third cache line
    _padding3: [u8; 32],

    // Fourth cache line: Session parameters
    /// Session parameters (derived from ECDH)
    session_params: [AtomicSessionParam; 16],

    /// Padding to fill the fourth cache line
    _padding4: [u8; 32],
}

impl SessionState {
    /// Create a new session state
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        Self {
            status: SyncState::new(SessionStatus::Initializing.as_u8()),
            last_activity: AtomicU64::new(now),
            local_seq: AtomicU32::new(0),
            remote_seq: AtomicU32::new(0),
            local_port: AtomicPortValue::new(0),
            remote_port: AtomicPortValue::new(0),
            time_offset: AtomicU32::new(0),
            _padding1: [0; 32],
            window_state: WindowState::new(),
            port_hop_seed: [
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
                AtomicPortValue::new(0),
            ],
            _padding3: [0; 32],
            session_params: [
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
                AtomicSessionParam::new(0),
            ],
            _padding4: [0; 32],
        }
    }

    /// Get the session status
    pub fn status(&self) -> SessionStatus {
        SessionStatus::from_u8(self.status.load(Ordering::Relaxed)).unwrap_or(SessionStatus::Closed)
    }

    /// Set the session status
    pub fn set_status(&self, status: SessionStatus) {
        self.status
            .store(status.as_u8(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the last activity timestamp
    pub fn last_activity(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// Update the last activity timestamp to now
    pub fn update_activity(&self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Get the local sequence number
    pub fn local_seq(&self) -> SequenceNumber {
        SequenceNumber::new(self.local_seq.load(Ordering::Relaxed))
    }

    /// Set the local sequence number
    pub fn set_local_seq(&self, value: SequenceNumber) {
        self.local_seq.store(value.as_u32(), Ordering::Relaxed);
    }

    /// Increment the local sequence number and return the new value
    pub fn increment_local_seq(&self) -> SequenceNumber {
        let new_val = self.local_seq.fetch_add(1, Ordering::Relaxed) + 1;
        SequenceNumber::new(new_val)
    }

    /// Get the remote sequence number
    pub fn remote_seq(&self) -> SequenceNumber {
        SequenceNumber::new(self.remote_seq.load(Ordering::Relaxed))
    }

    /// Set the remote sequence number
    pub fn set_remote_seq(&self, value: SequenceNumber) {
        self.remote_seq.store(value.as_u32(), Ordering::Relaxed);
    }

    /// Update the remote sequence number if the new value is greater
    pub fn update_remote_seq(&self, value: SequenceNumber) -> bool {
        let current = self.remote_seq.load(Ordering::Relaxed);

        // Check if the new value is greater
        if value.as_u32() > current {
            self.remote_seq.store(value.as_u32(), Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get the local port
    pub fn local_port(&self) -> Port {
        // Port values from atomic storage are always valid as they're constrained during set operations
        Port::from_raw(self.local_port.load(Ordering::Relaxed))
    }

    /// Set the local port
    pub fn set_local_port(&self, value: Port) {
        self.local_port
            .store(value.as_u16(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the remote port
    pub fn remote_port(&self) -> Port {
        // Port values from atomic storage are always valid as they're constrained during set operations
        Port::from_raw(self.remote_port.load(Ordering::Relaxed))
    }

    /// Set the remote port
    pub fn set_remote_port(&self, value: Port) {
        self.remote_port
            .store(value.as_u16(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the time offset (milliseconds)
    pub fn time_offset(&self) -> i32 {
        self.time_offset.load(Ordering::Relaxed) as i32
    }

    /// Set the time offset (milliseconds)
    pub fn set_time_offset(&self, value: i32) {
        self.time_offset.store(value as u32, Ordering::Relaxed);
    }

    /// Get the window state
    pub fn window_state(&self) -> &WindowState {
        &self.window_state
    }

    /// Get a port hopping parameter
    pub fn port_hop_param(&self, index: usize) -> Option<u16> {
        if index < self.port_hop_seed.len() {
            Some(self.port_hop_seed[index].load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Set a port hopping parameter
    pub fn set_port_hop_param(&self, index: usize, value: crate::protocol::types::Port) -> bool {
        if index < self.port_hop_seed.len() {
            self.port_hop_seed[index].store(value.as_u16(), std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get a session parameter
    pub fn session_param(&self, index: usize) -> Option<u16> {
        if index < self.session_params.len() {
            Some(self.session_params[index].load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Set a session parameter
    pub fn set_session_param(&self, index: usize, value: u16) -> bool {
        if index < self.session_params.len() {
            self.session_params[index].store(value, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Initialize session parameters from PBKDF2-derived chunks (chunks 0-25)
    pub fn init_from_pbkdf2(&self, params: &[u8]) -> Result<(), &'static str> {
        use crate::security::crypto::kdf::{ChunkRange, Kdf};

        // Validate parameters
        if Kdf::validate_parameters(params).is_err() {
            return Err("Invalid PBKDF2 parameters");
        }

        // Set initial sequence numbers (chunks 0-3)
        let (local_seq, remote_seq) = Kdf::extract_sequence_numbers(params)
            .map_err(|_| "Failed to extract sequence numbers")?;

        self.set_local_seq(SequenceNumber::new(local_seq));
        self.set_remote_seq(SequenceNumber::new(remote_seq));

        // Set port offsets (chunks 4-5)
        let (local_port_offset, remote_port_offset) =
            Kdf::extract_port_offsets(params).map_err(|_| "Failed to extract port offsets")?;

        // Port offsets from KDF are always valid
        self.set_local_port(Port::from_raw(local_port_offset));
        self.set_remote_port(Port::from_raw(remote_port_offset));

        // Set HMAC key (chunks 6-21) - store in session parameters
        let hmac_key = Kdf::extract_hmac_key(params).map_err(|_| "Failed to extract HMAC key")?;

        // Store HMAC key chunks in session parameters (16 chunks = 32 bytes)
        for i in 0..16 {
            let chunk = u16::from_be_bytes([hmac_key[i * 2], hmac_key[i * 2 + 1]]);
            self.set_session_param(i, chunk);
        }

        // Set port hopping seed (chunks 22-23)
        let port_hop_seed = Kdf::extract_port_hopping_seed(params)
            .map_err(|_| "Failed to extract port hopping seed")?;

        // Store port hopping seed in port hop parameters
        // Port values from u16 conversion are always valid
        self.set_port_hop_param(0, Port::from_raw((port_hop_seed >> 16) as u16));
        self.set_port_hop_param(1, Port::from_raw((port_hop_seed & 0xFFFF) as u16));

        // Initialize additional port hopping parameters from reserved chunks (24-25)
        let reserved_chunks = Kdf::get_range_chunks(params, ChunkRange::Reserved)
            .map_err(|_| "Failed to extract reserved chunks")?;

        if reserved_chunks.len() >= 2 {
            // Reserved chunks from KDF are always valid port values
            self.set_port_hop_param(2, Port::from_raw(reserved_chunks[0]));
            self.set_port_hop_param(3, Port::from_raw(reserved_chunks[1]));
        }

        Ok(())
    }

    /// Check if the session is idle (no activity for the specified duration)
    pub fn is_idle(&self, timeout: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        let last = self.last_activity();
        now.saturating_sub(last) >= timeout.as_secs()
    }

    /// Get the current send sequence number
    pub fn get_send_sequence(&self) -> SequenceNumber {
        SequenceNumber::new(self.local_seq.load(Ordering::Relaxed))
    }

    /// Get the current receive sequence number
    pub fn get_receive_sequence(&self) -> SequenceNumber {
        SequenceNumber::new(self.remote_seq.load(Ordering::Relaxed))
    }

    /// Get the expected receive sequence number
    pub fn get_expected_receive_sequence(&self) -> SequenceNumber {
        let current = self.remote_seq.load(Ordering::Relaxed);
        SequenceNumber::new(current + 1)
    }

    /// Set the send sequence number
    pub fn set_send_sequence(&self, seq: SequenceNumber) {
        self.local_seq.store(seq.as_u32(), Ordering::Relaxed);
    }

    /// Set the receive sequence number
    pub fn set_receive_sequence(&self, seq: SequenceNumber) {
        self.remote_seq.store(seq.as_u32(), Ordering::Relaxed);
    }

    /// Reset session to initial state
    pub fn reset_to_initial_state(&self) {
        self.local_seq.store(0, Ordering::Relaxed);
        self.remote_seq.store(0, Ordering::Relaxed);
        self.set_status(SessionStatus::Initializing);
    }

    /// Reset sequence numbers
    pub fn reset_sequence_numbers(&self) {
        self.local_seq.store(0, Ordering::Relaxed);
        self.remote_seq.store(0, Ordering::Relaxed);
    }

    /// Clear all buffers
    pub fn clear_all_buffers(&self) {
        // Reset sequence numbers
        self.local_seq.store(0, Ordering::Relaxed);
        self.remote_seq.store(0, Ordering::Relaxed);
        // Note: window_state contains non-atomic fields,
        // so we only reset the atomic congestion window here
        self.window_state
            .set_congestion_window(CongestionWindow::new(1460));
    }

    /// Set session as terminated
    pub fn set_terminated(&self) {
        self.set_status(SessionStatus::Closed);
    }

    /// Cleanup resources
    pub fn cleanup_resources(&self) {
        // Clear all state
        self.clear_all_buffers();
        self.set_terminated();
        self.last_activity.store(0, Ordering::Relaxed);
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}
