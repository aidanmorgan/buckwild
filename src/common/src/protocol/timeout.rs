// Comprehensive timeout and reliability system
//
// This module implements RFC 6298 compliant RTO calculation, connection timeouts,
// fragment reassembly timeouts, and comprehensive timeout monitoring as defined
// in protocol/08-timeout-and-reliability.md

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::Interval;
use tracing::{debug, error, info, trace, warn};

// Import ALL types from the authoritative consolidated types module
use crate::error::BuckwildError;
use crate::protocol::types::*;

/// RFC 6298 constants for RTO calculation
pub mod rfc6298_constants {

    /// Initial RTT estimate (1 second)
    pub const RTT_INITIAL_MS: u32 = 1000;

    /// Minimum RTT value (1ms)
    pub const RTT_MIN_MS: u32 = 1;

    /// Maximum RTT value (60 seconds)
    pub const RTT_MAX_MS: u32 = 60000;

    /// Alpha for SRTT calculation (1/8)
    pub const RTT_ALPHA: f64 = 0.125;

    /// Beta for RTTVAR calculation (1/4)
    pub const RTT_BETA: f64 = 0.25;

    /// Clock granularity (10ms)
    pub const RTT_G: u32 = 10;

    /// RTTVAR multiplier (4)
    pub const RTT_K: f64 = 4.0;

    /// Minimum retransmission timeout (1 second)
    pub const MIN_RETRANSMISSION_TIMEOUT_MS: u32 = 1000;

    /// Maximum retransmission timeout (60 seconds)
    pub const MAX_RETRANSMISSION_TIMEOUT_MS: u32 = 60000;

    /// Maximum retransmission attempts
    /// Spec: 02-core-definitions.md §"Protocol Constants" - 8 retransmission attempts
    /// before declaring connection failure (corrected from 5 per audit findings)
    pub const MAX_RETRANSMISSION_ATTEMPTS: u32 = 8;
}

/// Timeout configuration constants
pub mod timeout_constants {

    use crate::protocol::types::{Interval, Timeout};

    /// Connection establishment timeout (30 seconds)
    pub const CONNECTION_TIMEOUT_MS: Timeout = Timeout(30000);

    /// Heartbeat timeout (90 seconds)
    /// Spec: 02-core-definitions.md, used in 08-timeout-and-reliability.md §3.2
    pub const HEARTBEAT_TIMEOUT_MS: Timeout = Timeout(90000);

    /// Session idle timeout (5 minutes)
    pub const SESSION_IDLE_TIMEOUT_MS: Timeout = Timeout(300000);

    /// Fragment reassembly timeout (5 seconds)
    pub const FRAGMENT_TIMEOUT_MS: u64 = 5000;

    /// Maximum heartbeat failures before connection failure
    pub const MAX_HEARTBEAT_FAILURES: u32 = 3;

    /// Zero window probe interval (1 second)
    pub const ZERO_WINDOW_PROBE_INTERVAL_MS: Interval = Interval(1_000_000_000); // 1 second in nanoseconds

    /// Maximum zero window probe interval (60 seconds)
    pub const MAX_ZERO_WINDOW_PROBE_INTERVAL_MS: Interval = Interval(60_000_000_000); // 60 seconds in nanoseconds

    /// Window update timeout (30 seconds)
    pub const WINDOW_UPDATE_TIMEOUT_MS: Timeout = Timeout(30000);

    /// Discovery timeout (5 seconds)
    pub const DISCOVERY_TIMEOUT_MS: u64 = 5000;

    /// Maximum discovery timeout (60 seconds)
    pub const MAX_DISCOVERY_TIMEOUT_MS: u64 = 60000;

    /// Discovery retry count
    pub const DISCOVERY_RETRY_COUNT: u32 = 3;

    /// Time resync timeout (5 seconds)
    /// Spec: 02-core-definitions.md §"Recovery Constants"
    pub const TIME_RESYNC_TIMEOUT_MS: u64 = 5000;

    /// Rekey timeout (10 seconds)
    /// Spec: 02-core-definitions.md §"Recovery Constants"
    pub const REKEY_TIMEOUT_MS: u64 = 10000;

    /// Sequence repair timeout (8 seconds)
    /// Spec: 02-core-definitions.md §"Recovery Constants"
    pub const SEQUENCE_REPAIR_TIMEOUT_MS: u64 = 8000;

    /// Recovery escalation delay (2 seconds)
    /// Spec: 02-core-definitions.md §"Recovery Constants"
    pub const RECOVERY_ESCALATION_DELAY_MS: u64 = 2000;

    /// Connection close timeout (5 seconds)
    /// Spec: 02-core-definitions.md - graceful shutdown timeout
    pub const CONNECTION_CLOSE_TIMEOUT_MS: u64 = 5000;

    /// Emergency recovery timeout (60 seconds)
    pub const EMERGENCY_RECOVERY_TIMEOUT_MS: u64 = 60000;

    /// General recovery timeout (20 seconds)
    pub const RECOVERY_TIMEOUT_MS: u64 = 20000;

    /// Maximum recovery attempts
    pub const MAX_RECOVERY_ATTEMPTS: u32 = 3;

    /// Base timeout for generic operations (5 seconds)
    pub const BASE_TIMEOUT_MS: u64 = 5000;

    /// Maximum generic timeout (120 seconds)
    pub const MAX_GENERIC_TIMEOUT_MS: u64 = 120000;

    /// Maximum retry attempts for generic operations
    pub const MAX_RETRY_ATTEMPTS: u32 = 5;

    /// Timestamp window for anti-replay (30 seconds)
    pub const TIMESTAMP_WINDOW_MS: u64 = 30000;

    /// Time sync tolerance for clock drift detection (50ms)
    /// Spec: 09-time-synchronization.md, 02-core-definitions.md
    pub const TIME_SYNC_TOLERANCE_MS: u64 = 50;
}

/// RTO calculation state following RFC 6298
#[derive(Debug)]
pub struct RtoState {
    /// Smoothed RTT estimate in milliseconds
    rtt_srtt: Arc<std::sync::atomic::AtomicU32>,

    /// RTT variation estimate in milliseconds
    rtt_rttvar: Arc<std::sync::atomic::AtomicU32>,

    /// Current retransmission timeout in milliseconds
    rtt_rto: Arc<std::sync::atomic::AtomicU32>,

    /// Flag for first RTT measurement
    first_measurement: Arc<std::sync::atomic::AtomicBool>,

    /// Timestamp of last measurement (microseconds)
    last_measurement_time: Arc<std::sync::atomic::AtomicU64>,

    /// Total number of measurements
    measurement_count: Arc<std::sync::atomic::AtomicU64>,
}

impl RtoState {
    /// Create new RTO state with initial values
    pub fn new() -> Self {
        use rfc6298_constants::*;

        Self {
            rtt_srtt: Arc::new(std::sync::atomic::AtomicU32::new(RTT_INITIAL_MS)),
            rtt_rttvar: Arc::new(std::sync::atomic::AtomicU32::new(RTT_INITIAL_MS / 2)),
            rtt_rto: Arc::new(std::sync::atomic::AtomicU32::new(RTT_INITIAL_MS)),
            first_measurement: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            last_measurement_time: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            measurement_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Measure RTT from send time to acknowledgment time
    pub fn measure_rtt(
        &self,
        send_time: MicrosecondTimestamp,
        ack_time: MicrosecondTimestamp,
    ) -> u32 {
        use rfc6298_constants::*;

        // Calculate RTT sample in microseconds
        let rtt_micros = ack_time.as_u64().saturating_sub(send_time.as_u64());
        let rtt_sample_ms = (rtt_micros / 1000)
            .max(RTT_MIN_MS as u64)
            .min(RTT_MAX_MS as u64) as u32;

        // Update measurement statistics
        self.last_measurement_time
            .store(ack_time.as_u64(), std::sync::atomic::Ordering::Relaxed);
        self.measurement_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        trace!("RTT measurement: {}ms", rtt_sample_ms);

        rtt_sample_ms
    }

    /// Update RTO using RFC 6298 algorithm with measured RTT
    pub fn update_rto_with_measurement(&self, rtt_sample_ms: u32) -> Duration {
        use rfc6298_constants::*;

        if self
            .first_measurement
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // First RTT measurement - initialize estimates
            self.rtt_srtt
                .store(rtt_sample_ms, std::sync::atomic::Ordering::Relaxed);
            self.rtt_rttvar
                .store(rtt_sample_ms / 2, std::sync::atomic::Ordering::Relaxed);

            debug!(
                "First RTT measurement: SRTT={}ms, RTTVAR={}ms",
                rtt_sample_ms,
                rtt_sample_ms / 2
            );
        } else {
            // Update smoothed RTT and variation using exponential averaging
            let current_srtt = self.rtt_srtt.load(std::sync::atomic::Ordering::Relaxed);
            let rtt_variation = (rtt_sample_ms as i32 - current_srtt as i32).unsigned_abs();

            // RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R'|
            let current_rttvar = self.rtt_rttvar.load(std::sync::atomic::Ordering::Relaxed);
            let new_rttvar =
                ((1.0 - RTT_BETA) * current_rttvar as f64 + RTT_BETA * rtt_variation as f64) as u32;
            self.rtt_rttvar
                .store(new_rttvar, std::sync::atomic::Ordering::Relaxed);

            // SRTT = (1 - α) * SRTT + α * R'
            let new_srtt =
                ((1.0 - RTT_ALPHA) * current_srtt as f64 + RTT_ALPHA * rtt_sample_ms as f64) as u32;
            self.rtt_srtt
                .store(new_srtt, std::sync::atomic::Ordering::Relaxed);

            debug!("RTT update: SRTT={}ms, RTTVAR={}ms", new_srtt, new_rttvar);
        }

        // Calculate RTO: RTO = SRTT + max(G, K * RTTVAR)
        let srtt = self.rtt_srtt.load(std::sync::atomic::Ordering::Relaxed);
        let rttvar = self.rtt_rttvar.load(std::sync::atomic::Ordering::Relaxed);
        let rto_value = srtt + (RTT_G.max((RTT_K * rttvar as f64) as u32));

        // Ensure RTO is within acceptable bounds
        let bounded_rto =
            rto_value.clamp(MIN_RETRANSMISSION_TIMEOUT_MS, MAX_RETRANSMISSION_TIMEOUT_MS);
        self.rtt_rto
            .store(bounded_rto, std::sync::atomic::Ordering::Relaxed);

        debug!("RTO calculated: {}ms", bounded_rto);

        Duration::from_millis(bounded_rto as u64)
    }

    /// Handle retransmission timeout with exponential backoff
    pub fn handle_retransmission_timeout(&self) -> Duration {
        use rfc6298_constants::*;

        // Double the RTO for next retransmission attempt
        let current_rto = self.rtt_rto.load(std::sync::atomic::Ordering::Relaxed);
        let new_rto = (current_rto * 2).min(MAX_RETRANSMISSION_TIMEOUT_MS);
        self.rtt_rto
            .store(new_rto, std::sync::atomic::Ordering::Relaxed);

        warn!("Retransmission timeout: RTO doubled to {}ms", new_rto);

        Duration::from_millis(new_rto as u64)
    }

    /// Get current RTO value for setting retransmission timers
    pub fn get_current_rto(&self) -> Duration {
        let rto = self.rtt_rto.load(std::sync::atomic::Ordering::Relaxed);
        Duration::from_millis(rto as u64)
    }

    /// Reset RTO to initial values (used after connection establishment)
    pub fn reset_rto_estimates(&self) {
        use rfc6298_constants::*;

        self.rtt_srtt
            .store(RTT_INITIAL_MS, std::sync::atomic::Ordering::Relaxed);
        self.rtt_rttvar
            .store(RTT_INITIAL_MS / 2, std::sync::atomic::Ordering::Relaxed);
        self.rtt_rto
            .store(RTT_INITIAL_MS, std::sync::atomic::Ordering::Relaxed);
        self.first_measurement
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.measurement_count
            .store(0, std::sync::atomic::Ordering::Relaxed);

        info!("RTO estimates reset to initial values");
    }

    /// Get RTT statistics for monitoring
    pub fn get_statistics(&self) -> RtoStatistics {
        RtoStatistics {
            srtt_ms: self.rtt_srtt.load(std::sync::atomic::Ordering::Relaxed),
            rttvar_ms: self.rtt_rttvar.load(std::sync::atomic::Ordering::Relaxed),
            rto_ms: self.rtt_rto.load(std::sync::atomic::Ordering::Relaxed),
            measurement_count: self
                .measurement_count
                .load(std::sync::atomic::Ordering::Relaxed),
            last_measurement_time: MicrosecondTimestamp::new(
                self.last_measurement_time
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

impl Default for RtoState {
    fn default() -> Self {
        Self::new()
    }
}

/// RTO statistics for monitoring
#[derive(Debug, Clone)]
pub struct RtoStatistics {
    pub srtt_ms: u32,
    pub rttvar_ms: u32,
    pub rto_ms: u32,
    pub measurement_count: u64,
    pub last_measurement_time: MicrosecondTimestamp,
}

/// Packet timing information for RTT measurement
#[derive(Debug, Clone)]
pub struct PacketTiming {
    pub packet_id: PacketId,
    pub send_time: MicrosecondTimestamp,
    pub sequence_number: SequenceNumber,
    pub retransmitted: bool,
    pub retry_count: u32,
}

impl PacketTiming {
    /// Create new packet timing
    pub fn new(packet_id: PacketId, sequence_number: SequenceNumber) -> Self {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            packet_id,
            send_time: MicrosecondTimestamp::new(now_nanos),
            sequence_number,
            retransmitted: false,
            retry_count: 0,
        }
    }

    /// Mark packet as retransmitted
    pub fn mark_retransmitted(&mut self) {
        self.retransmitted = true;
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        self.send_time = MicrosecondTimestamp::new(now_nanos);
        self.retry_count += 1;
    }

    /// Check if packet has exceeded maximum retries
    pub fn has_exceeded_max_retries(&self) -> bool {
        self.retry_count >= rfc6298_constants::MAX_RETRANSMISSION_ATTEMPTS
    }
}

/// Timeout event types for monitoring
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutEventType {
    Connection,
    Heartbeat,
    SessionIdle,
    Fragment,
    Retransmission,
    Discovery,
    Recovery,
    WindowUpdate,
    ZeroWindowProbe,
    TimestampReplay,
    Generic,
}

/// Timeout event outcome
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutOutcome {
    Success,
    Timeout,
    Retry,
    Failure,
    Cancelled,
}

/// Timeout event for monitoring and statistics
#[derive(Debug, Clone)]
pub struct TimeoutEvent {
    pub event_type: TimeoutEventType,
    pub outcome: TimeoutOutcome,
    pub duration_ms: u64,
    pub timestamp: MicrosecondTimestamp,
    pub rto_value_ms: u32,
    pub connection_id: Option<ConnectionId>,
    pub additional_info: String,
}

impl TimeoutEvent {
    /// Create new timeout event
    pub fn new(
        event_type: TimeoutEventType,
        outcome: TimeoutOutcome,
        duration_ms: u64,
        connection_id: Option<ConnectionId>,
        additional_info: String,
    ) -> Self {
        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            event_type,
            outcome,
            duration_ms,
            timestamp: MicrosecondTimestamp::new(now_micros),
            rto_value_ms: 0, // Will be filled by timeout manager
            connection_id,
            additional_info,
        }
    }
}

/// Recovery operation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryType {
    TimeResync,
    Rekey,
    SequenceRepair,
    Emergency,
}

impl RecoveryType {
    /// Get timeout limit for recovery type
    pub fn get_timeout_limit(&self) -> Duration {
        use timeout_constants::*;

        match self {
            Self::TimeResync => Duration::from_millis(TIME_RESYNC_TIMEOUT_MS),
            Self::Rekey => Duration::from_millis(REKEY_TIMEOUT_MS),
            Self::SequenceRepair => Duration::from_millis(SEQUENCE_REPAIR_TIMEOUT_MS),
            Self::Emergency => Duration::from_millis(EMERGENCY_RECOVERY_TIMEOUT_MS),
        }
    }
}

/// Error context for timeout backoff
#[derive(Debug, Clone)]
pub struct TimeoutErrorContext {
    pub error_type: TimeoutEventType,
    pub retry_count: u32,
    pub operation: String,
    pub connection_id: Option<ConnectionId>,
    pub last_error: String,
}

impl TimeoutErrorContext {
    /// Create new error context
    pub fn new(
        error_type: TimeoutEventType,
        operation: String,
        connection_id: Option<ConnectionId>,
        last_error: String,
    ) -> Self {
        Self {
            error_type,
            retry_count: 0,
            operation,
            connection_id,
            last_error,
        }
    }

    /// Increment retry count
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    /// Check if maximum retries exceeded
    pub fn has_exceeded_max_retries(&self) -> bool {
        self.retry_count >= timeout_constants::MAX_RETRY_ATTEMPTS
    }
}

/// Comprehensive timeout manager
#[derive(Debug)]
pub struct TimeoutManager {
    /// RTO state for RTT calculations
    rto_state: Arc<RtoState>,

    /// Pending packets for RTT measurement
    pending_packets: Arc<RwLock<HashMap<PacketId, PacketTiming>>>,

    /// Retransmission timers
    retransmission_timers: Arc<RwLock<HashMap<PacketId, Instant>>>,

    /// Retransmission counts per packet
    retransmission_counts: Arc<RwLock<HashMap<PacketId, u32>>>,

    /// Connection timeouts
    _connection_timeouts: Arc<RwLock<HashMap<ConnectionId, Instant>>>,

    /// Fragment reassembly timeouts
    fragment_timeouts: Arc<RwLock<HashMap<FragmentId, Instant>>>,

    /// Timeout statistics
    timeout_statistics: Arc<RwLock<Vec<TimeoutEvent>>>,

    /// Statistics cleanup interval
    cleanup_interval: Interval,
}

impl TimeoutManager {
    /// Create new timeout manager
    pub fn new() -> Self {
        Self {
            rto_state: Arc::new(RtoState::new()),
            pending_packets: Arc::new(RwLock::new(HashMap::new())),
            retransmission_timers: Arc::new(RwLock::new(HashMap::new())),
            retransmission_counts: Arc::new(RwLock::new(HashMap::new())),
            _connection_timeouts: Arc::new(RwLock::new(HashMap::new())),
            fragment_timeouts: Arc::new(RwLock::new(HashMap::new())),
            timeout_statistics: Arc::new(RwLock::new(Vec::new())),
            cleanup_interval: tokio::time::interval(Duration::from_secs(60)), // Cleanup every minute
        }
    }

    /// Send packet with timing tracking for RTT measurement
    pub async fn send_packet_with_timing(
        &self,
        packet_id: PacketId,
        sequence_number: SequenceNumber,
    ) -> Result<(), BuckwildError> {
        let timing = PacketTiming::new(packet_id, sequence_number);

        // Track packet for RTT measurement
        {
            let mut pending = self.pending_packets.write().await;
            pending.insert(packet_id, timing);
        }

        // Set retransmission timer
        let timeout_value = self.rto_state.get_current_rto();
        self.set_retransmission_timer(packet_id, timeout_value)
            .await;

        debug!(
            "Packet {} sent with RTO timer {}ms",
            packet_id,
            timeout_value.as_millis()
        );

        Ok(())
    }

    /// Handle acknowledgment packet for RTT measurement
    pub async fn handle_ack_packet(
        &self,
        ack_sequence: SequenceNumber,
    ) -> Result<(), BuckwildError> {
        let ack_time_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let ack_time = MicrosecondTimestamp::new(ack_time_micros);
        let mut acked_packets = Vec::new();

        // Find corresponding sent packets for RTT measurement
        {
            let pending = self.pending_packets.read().await;
            for (packet_id, timing) in pending.iter() {
                if timing.sequence_number.as_u32() <= ack_sequence.as_u32() {
                    acked_packets.push((*packet_id, timing.clone()));
                }
            }
        }

        for (packet_id, timing) in acked_packets {
            // Only measure RTT for non-retransmitted packets (Karn's algorithm)
            if !timing.retransmitted {
                let rtt_sample_ms = self.rto_state.measure_rtt(timing.send_time, ack_time);
                self.rto_state.update_rto_with_measurement(rtt_sample_ms);

                debug!("RTT measured for packet {}: {}ms", packet_id, rtt_sample_ms);
            }

            // Clean up tracking
            self.cancel_retransmission_timer(packet_id).await;

            {
                let mut pending = self.pending_packets.write().await;
                pending.remove(&packet_id);
            }

            {
                let mut counts = self.retransmission_counts.write().await;
                counts.remove(&packet_id);
            }
        }

        Ok(())
    }

    /// Handle retransmission timer expiry
    pub async fn handle_retransmission_timer_expiry(
        &self,
        packet_id: PacketId,
    ) -> Result<bool, BuckwildError> {
        let mut should_retransmit = false;

        // Check if packet is still pending
        {
            let mut pending = self.pending_packets.write().await;
            if let Some(mut timing) = pending.remove(&packet_id) {
                // Increment retransmission count
                let retry_count = {
                    let mut counts = self.retransmission_counts.write().await;
                    let count = counts.entry(packet_id).or_insert(0);
                    *count += 1;
                    *count
                };

                if timing.has_exceeded_max_retries() {
                    // Maximum retries exceeded - declare connection failed
                    error!(
                        "Packet {} exceeded maximum retries ({})",
                        packet_id, retry_count
                    );

                    self.track_timeout_event(TimeoutEvent::new(
                        TimeoutEventType::Retransmission,
                        TimeoutOutcome::Failure,
                        0,
                        None,
                        format!("Max retries exceeded for packet {}", packet_id),
                    ))
                    .await;

                    return Ok(false);
                }

                // Handle RTO timeout (exponential backoff)
                let new_rto = self.rto_state.handle_retransmission_timeout();

                // Mark packet as retransmitted
                timing.mark_retransmitted();

                // Re-insert timing for next attempt
                pending.insert(packet_id, timing);

                // Set new retransmission timer
                self.set_retransmission_timer(packet_id, new_rto).await;

                should_retransmit = true;

                warn!(
                    "Retransmitting packet {} (attempt {}), new RTO: {}ms",
                    packet_id,
                    retry_count,
                    new_rto.as_millis()
                );
            }
        }

        if should_retransmit {
            self.track_timeout_event(TimeoutEvent::new(
                TimeoutEventType::Retransmission,
                TimeoutOutcome::Retry,
                0,
                None,
                format!("Retransmitting packet {}", packet_id),
            ))
            .await;
        }

        Ok(should_retransmit)
    }

    /// Set retransmission timer for packet
    async fn set_retransmission_timer(&self, packet_id: PacketId, timeout: Duration) {
        let expiry_time = Instant::now() + timeout;

        {
            let mut timers = self.retransmission_timers.write().await;
            timers.insert(packet_id, expiry_time);
        }

        // In a real implementation, this would schedule a timer callback
        // For now, we'll rely on periodic checking
        trace!(
            "Retransmission timer set for packet {} ({}ms)",
            packet_id,
            timeout.as_millis()
        );
    }

    /// Cancel retransmission timer for acknowledged packet
    async fn cancel_retransmission_timer(&self, packet_id: PacketId) {
        {
            let mut timers = self.retransmission_timers.write().await;
            timers.remove(&packet_id);
        }

        trace!("Retransmission timer cancelled for packet {}", packet_id);
    }

    /// Check for expired retransmission timers
    pub async fn check_retransmission_timers(&self) -> Vec<PacketId> {
        let now = Instant::now();
        let mut expired_packets = Vec::new();

        {
            let timers = self.retransmission_timers.read().await;
            for (packet_id, expiry_time) in timers.iter() {
                if now >= *expiry_time {
                    expired_packets.push(*packet_id);
                }
            }
        }

        expired_packets
    }

    /// Manage connection timeouts
    pub async fn manage_connection_timeouts(
        &self,
        connection_id: ConnectionId,
        connection_state: ConnectionState,
        connection_start_time: Option<Instant>,
        last_heartbeat_time: Option<Instant>,
        last_packet_time: Option<Instant>,
        consecutive_heartbeat_failures: u32,
    ) -> Result<Vec<TimeoutAction>, BuckwildError> {
        use timeout_constants::*;

        let now = Instant::now();
        let mut actions = Vec::new();

        // Connection establishment timeout
        if connection_state == ConnectionState::Connecting {
            if let Some(start_time) = connection_start_time {
                let time_since_start = now.duration_since(start_time);
                if time_since_start > Duration::from_millis(CONNECTION_TIMEOUT_MS.as_u64()) {
                    actions.push(TimeoutAction::ConnectionEstablishmentTimeout(connection_id));

                    self.track_timeout_event(TimeoutEvent::new(
                        TimeoutEventType::Connection,
                        TimeoutOutcome::Timeout,
                        time_since_start.as_millis() as u64,
                        Some(connection_id),
                        "Connection establishment timeout".to_string(),
                    ))
                    .await;
                }
            }
        }

        // Heartbeat timeout detection
        if connection_state == ConnectionState::Established {
            if let Some(heartbeat_time) = last_heartbeat_time {
                let time_since_heartbeat = now.duration_since(heartbeat_time);
                if time_since_heartbeat > Duration::from_millis(HEARTBEAT_TIMEOUT_MS.as_u64()) {
                    if consecutive_heartbeat_failures < MAX_HEARTBEAT_FAILURES {
                        actions.push(TimeoutAction::HeartbeatTimeout(connection_id));
                    } else {
                        actions.push(TimeoutAction::ConnectionFailure(
                            connection_id,
                            "Heartbeat timeout".to_string(),
                        ));
                    }

                    self.track_timeout_event(TimeoutEvent::new(
                        TimeoutEventType::Heartbeat,
                        if consecutive_heartbeat_failures < MAX_HEARTBEAT_FAILURES {
                            TimeoutOutcome::Retry
                        } else {
                            TimeoutOutcome::Failure
                        },
                        time_since_heartbeat.as_millis() as u64,
                        Some(connection_id),
                        format!(
                            "Heartbeat timeout (failures: {})",
                            consecutive_heartbeat_failures
                        ),
                    ))
                    .await;
                }
            }
        }

        // Session idle timeout
        if let Some(packet_time) = last_packet_time {
            let time_since_activity = now.duration_since(packet_time);
            if time_since_activity > Duration::from_millis(SESSION_IDLE_TIMEOUT_MS.as_u64()) {
                actions.push(TimeoutAction::SessionIdleTimeout(connection_id));

                self.track_timeout_event(TimeoutEvent::new(
                    TimeoutEventType::SessionIdle,
                    TimeoutOutcome::Timeout,
                    time_since_activity.as_millis() as u64,
                    Some(connection_id),
                    "Session idle timeout".to_string(),
                ))
                .await;
            }
        }

        Ok(actions)
    }

    /// Manage fragment reassembly timeouts
    pub async fn manage_fragment_timeouts(&self) -> Result<Vec<FragmentId>, BuckwildError> {
        use timeout_constants::*;

        let now = Instant::now();
        let mut expired_fragments = Vec::new();

        {
            let timeouts = self.fragment_timeouts.read().await;
            for (fragment_id, timeout_time) in timeouts.iter() {
                if now >= *timeout_time {
                    expired_fragments.push(*fragment_id);
                }
            }
        }

        // Clean up expired fragments
        if !expired_fragments.is_empty() {
            let mut timeouts = self.fragment_timeouts.write().await;
            for fragment_id in &expired_fragments {
                timeouts.remove(fragment_id);

                self.track_timeout_event(TimeoutEvent::new(
                    TimeoutEventType::Fragment,
                    TimeoutOutcome::Timeout,
                    FRAGMENT_TIMEOUT_MS,
                    None,
                    format!("Fragment {} reassembly timeout", fragment_id),
                ))
                .await;
            }
        }

        Ok(expired_fragments)
    }

    /// Set fragment reassembly timeout
    pub async fn set_fragment_reassembly_timeout(&self, fragment_id: FragmentId) {
        use timeout_constants::*;

        let timeout_time = Instant::now() + Duration::from_millis(FRAGMENT_TIMEOUT_MS);

        {
            let mut timeouts = self.fragment_timeouts.write().await;
            timeouts.insert(fragment_id, timeout_time);
        }

        debug!(
            "Fragment reassembly timeout set for fragment {} ({}ms)",
            fragment_id, FRAGMENT_TIMEOUT_MS
        );
    }

    /// Cancel fragment reassembly timeout
    pub async fn cancel_fragment_timeout(&self, fragment_id: FragmentId) {
        {
            let mut timeouts = self.fragment_timeouts.write().await;
            timeouts.remove(&fragment_id);
        }

        trace!(
            "Fragment reassembly timeout cancelled for fragment {}",
            fragment_id
        );
    }

    /// Calculate exponential backoff with jitter
    pub fn calculate_exponential_backoff(
        &self,
        retry_count: u32,
        base_timeout_ms: u64,
        max_timeout_ms: u64,
    ) -> u64 {
        use rand::Rng;

        // Calculate exponential component
        let exponential_component = base_timeout_ms.saturating_mul(2_u64.pow(retry_count));

        // Add 10% jitter
        let jitter_range = (exponential_component as f64 * 0.1) as u64;
        let mut rng = rand::thread_rng();
        let jitter = if jitter_range > 0 {
            rng.gen_range(0..=jitter_range)
        } else {
            0
        };

        exponential_component
            .saturating_add(jitter)
            .min(max_timeout_ms)
    }

    /// Implement timeout backoff for different error types
    pub fn implement_timeout_backoff(&self, error_context: &TimeoutErrorContext) -> u64 {
        use timeout_constants::*;

        match error_context.error_type {
            TimeoutEventType::Connection => self.calculate_exponential_backoff(
                error_context.retry_count,
                CONNECTION_TIMEOUT_MS.as_u64(),
                CONNECTION_TIMEOUT_MS.as_u64() * 4,
            ),
            TimeoutEventType::Discovery => self.calculate_exponential_backoff(
                error_context.retry_count,
                DISCOVERY_TIMEOUT_MS,
                MAX_DISCOVERY_TIMEOUT_MS,
            ),
            TimeoutEventType::Fragment => self.calculate_exponential_backoff(
                error_context.retry_count,
                FRAGMENT_TIMEOUT_MS,
                FRAGMENT_TIMEOUT_MS * 8,
            ),
            TimeoutEventType::Recovery => self.calculate_exponential_backoff(
                error_context.retry_count,
                RECOVERY_TIMEOUT_MS,
                RECOVERY_TIMEOUT_MS * 4,
            ),
            _ => self.calculate_exponential_backoff(
                error_context.retry_count,
                BASE_TIMEOUT_MS,
                MAX_GENERIC_TIMEOUT_MS,
            ),
        }
    }

    /// Handle timeout error with backoff
    pub async fn handle_timeout_error_with_backoff(
        &self,
        mut error_context: TimeoutErrorContext,
    ) -> Result<Option<u64>, BuckwildError> {
        if error_context.has_exceeded_max_retries() {
            // Maximum retries exceeded
            self.track_timeout_event(TimeoutEvent::new(
                error_context.error_type.clone(),
                TimeoutOutcome::Failure,
                0,
                error_context.connection_id,
                format!("Maximum retries exceeded for {}", error_context.operation),
            ))
            .await;

            return Ok(None);
        }

        // Calculate backoff time
        let backoff_time = self.implement_timeout_backoff(&error_context);

        // Update retry count
        error_context.increment_retry();

        self.track_timeout_event(TimeoutEvent::new(
            error_context.error_type.clone(),
            TimeoutOutcome::Retry,
            backoff_time,
            error_context.connection_id,
            format!(
                "Retry {} for {}",
                error_context.retry_count, error_context.operation
            ),
        ))
        .await;

        info!(
            "Scheduling retry for {} after {}ms (attempt {})",
            error_context.operation, backoff_time, error_context.retry_count
        );

        Ok(Some(backoff_time))
    }

    /// Validate packet timestamp against anti-replay window
    pub fn validate_packet_timestamp_timeout(
        &self,
        packet_timestamp: u64,
    ) -> Result<(), BuckwildError> {
        use timeout_constants::*;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Calculate packet age using month-based epoch
        let month_start = self.get_current_month_start_utc();
        let packet_age = current_time.saturating_sub(month_start + packet_timestamp);

        // Apply TIMESTAMP_WINDOW_MS timeout
        if packet_age > TIMESTAMP_WINDOW_MS {
            error!(
                "Packet timestamp too old: {}ms (limit: {}ms)",
                packet_age, TIMESTAMP_WINDOW_MS
            );
            return Err(BuckwildError::invalid_state("Timestamp replay detected"));
        }

        // Check for future timestamps (clock skew tolerance)
        if packet_timestamp > current_time + TIME_SYNC_TOLERANCE_MS {
            error!(
                "Packet timestamp in future: {}ms ahead",
                packet_timestamp - current_time
            );
            return Err(BuckwildError::invalid_state("Future timestamp detected"));
        }

        Ok(())
    }

    /// Get current month start in UTC milliseconds
    fn get_current_month_start_utc(&self) -> u64 {
        // Simplified implementation - in practice would use proper date/time library
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Approximate month start (this is simplified)
        let days_in_ms = 24 * 60 * 60 * 1000;
        let approximate_day_of_month = (now / days_in_ms) % 30;
        now - (approximate_day_of_month * days_in_ms)
    }

    /// Track timeout performance for optimization
    async fn track_timeout_event(&self, mut event: TimeoutEvent) {
        // Fill in RTO value
        event.rto_value_ms = self.rto_state.get_current_rto().as_millis() as u32;

        {
            let mut stats = self.timeout_statistics.write().await;
            stats.push(event);

            // Keep only recent events (last 1000)
            if stats.len() > 1000 {
                let drain_count = stats.len() - 1000;
                stats.drain(0..drain_count);
            }
        }
    }

    /// Get timeout statistics for monitoring
    pub async fn get_timeout_statistics(&self) -> Vec<TimeoutEvent> {
        let stats = self.timeout_statistics.read().await;
        stats.clone()
    }

    /// Get RTO statistics
    pub fn get_rto_statistics(&self) -> RtoStatistics {
        self.rto_state.get_statistics()
    }

    /// Reset RTO estimates
    pub fn reset_rto_estimates(&self) {
        self.rto_state.reset_rto_estimates();
    }

    /// Cleanup expired statistics and timers
    pub async fn cleanup_expired_data(&self) {
        let now = Instant::now();

        // Clean up old statistics (keep events from last 5 minutes)
        {
            let cutoff_micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64
                - (300 * 1_000_000); // 5 minutes in microseconds
            let cutoff_timestamp = MicrosecondTimestamp::new(cutoff_micros);

            let mut stats = self.timeout_statistics.write().await;
            stats.retain(|event| event.timestamp.as_u64() >= cutoff_timestamp.as_u64());
        }

        // Clean up expired timers (this would be handled by timer callbacks in practice)
        {
            let mut timers = self.retransmission_timers.write().await;
            timers.retain(|_, expiry_time| now < *expiry_time);
        }

        debug!("Cleaned up expired timeout data");
    }

    /// Run periodic cleanup
    pub async fn run_periodic_cleanup(&mut self) {
        loop {
            self.cleanup_interval.tick().await;
            self.cleanup_expired_data().await;
        }
    }
}

impl Default for TimeoutManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Actions that can be triggered by timeout events
#[derive(Debug, Clone)]
pub enum TimeoutAction {
    ConnectionEstablishmentTimeout(ConnectionId),
    HeartbeatTimeout(ConnectionId),
    SessionIdleTimeout(ConnectionId),
    ConnectionFailure(ConnectionId, String),
    RetransmitPacket(PacketId),
    RequestFragmentRetransmission(FragmentId),
    InitiateRecovery(ConnectionId, RecoveryType),
    SendZeroWindowProbe(ConnectionId),
    SendWindowProbe(ConnectionId),
}
