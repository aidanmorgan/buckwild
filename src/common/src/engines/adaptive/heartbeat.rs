#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Heartbeat mechanism for connection liveness detection
//!
//! This module implements the heartbeat mechanism that:
//! - Sends HEARTBEAT packets at configurable intervals
//! - Detects connection failure after missing consecutive heartbeats
//! - Carries RTT measurement data in heartbeat packets
//! - Negotiates heartbeat intervals during connection setup
//! - Implements heartbeat suppression when data packets are exchanged
//!
//! According to specification:
//! - Default interval: 30 seconds (HEARTBEAT_INTERVAL_MS)
//! - Timeout: 90 seconds (3 x 30s = HEARTBEAT_TIMEOUT_MS)
//! - Jitter: +/- 100ms to prevent synchronization

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use thiserror::Error;
use tracing::{Level, debug, info, span, warn};

use crate::error::EngineError;
use crate::protocol::types::{HeartbeatInterval, HeartbeatSequence, RoundTripTime, SessionId};

/// Heartbeat-specific error types
#[derive(Error, Debug, Clone)]
pub enum HeartbeatError {
    #[error("Heartbeat timeout: no response for {elapsed_ms}ms (max: {timeout_ms}ms)")]
    Timeout { elapsed_ms: u64, timeout_ms: u64 },

    #[error("Invalid heartbeat interval: {interval_ms}ms (must be > 0)")]
    InvalidInterval { interval_ms: u64 },

    #[error("Heartbeat sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u32, actual: u32 },

    #[error("Heartbeat suppression error: {reason}")]
    SuppressionError { reason: String },

    #[error("Heartbeat generation failed: {reason}")]
    GenerationFailed { reason: String },

    #[error("Connection declared dead after {consecutive_failures} consecutive failures")]
    ConnectionDead { consecutive_failures: u8 },

    #[error("Heartbeat configuration error: {parameter} = {value}")]
    ConfigurationError { parameter: String, value: String },
}

impl From<HeartbeatError> for EngineError {
    fn from(err: HeartbeatError) -> Self {
        EngineError::AdaptiveNetworkingError {
            reason: err.to_string(),
        }
    }
}

/// Heartbeat configuration
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Heartbeat interval in milliseconds
    pub interval_ms: HeartbeatInterval,

    /// Heartbeat timeout in milliseconds (typically 3x interval)
    pub timeout_ms: u64,

    /// Maximum number of consecutive missed heartbeats before connection dead
    pub max_consecutive_failures: u8,

    /// Jitter range in milliseconds (+/-)
    pub jitter_ms: u64,

    /// Enable heartbeat suppression when data packets exchanged
    pub enable_suppression: bool,

    /// Negotiated flag - whether this configuration came from negotiation
    pub negotiated: bool,
}

impl HeartbeatConfig {
    /// Default heartbeat configuration per specification
    pub fn default_config() -> Self {
        Self {
            interval_ms: HeartbeatInterval::new(30000), // 30 seconds
            timeout_ms: 90000,                          // 90 seconds
            max_consecutive_failures: 3,                // 3 consecutive failures
            jitter_ms: 100,                             // +/- 100ms jitter
            enable_suppression: true,
            negotiated: false,
        }
    }

    /// Create configuration with custom interval
    pub fn with_interval(interval_ms: u64) -> Result<Self, HeartbeatError> {
        if interval_ms == 0 {
            return Err(HeartbeatError::InvalidInterval { interval_ms });
        }

        Ok(Self {
            interval_ms: HeartbeatInterval::new(interval_ms),
            timeout_ms: interval_ms * 3,
            max_consecutive_failures: 3,
            jitter_ms: 100,
            enable_suppression: true,
            negotiated: false,
        })
    }

    /// Create negotiated configuration from peer parameters
    pub fn negotiate(local_interval: u64, peer_interval: u64) -> Result<Self, HeartbeatError> {
        // Use maximum of local and peer intervals for safety
        let negotiated_interval = local_interval.max(peer_interval);

        if negotiated_interval == 0 {
            return Err(HeartbeatError::InvalidInterval {
                interval_ms: negotiated_interval,
            });
        }

        Ok(Self {
            interval_ms: HeartbeatInterval::new(negotiated_interval),
            timeout_ms: negotiated_interval * 3,
            max_consecutive_failures: 3,
            jitter_ms: 100,
            enable_suppression: true,
            negotiated: true,
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), HeartbeatError> {
        if self.interval_ms.as_millis() == 0 {
            return Err(HeartbeatError::InvalidInterval { interval_ms: 0 });
        }

        if self.max_consecutive_failures == 0 {
            return Err(HeartbeatError::ConfigurationError {
                parameter: "max_consecutive_failures".to_string(),
                value: "0".to_string(),
            });
        }

        if self.timeout_ms < self.interval_ms.as_millis() {
            return Err(HeartbeatError::ConfigurationError {
                parameter: "timeout_ms".to_string(),
                value: format!("{} (must be >= interval_ms)", self.timeout_ms),
            });
        }

        Ok(())
    }
}

/// Heartbeat state tracking
#[derive(Debug)]
pub struct HeartbeatState {
    /// Current heartbeat sequence number
    sequence: AtomicU64,

    /// Last heartbeat send time (monotonic clock)
    last_send_time: Mutex<Option<Instant>>,

    /// Last heartbeat receive time (monotonic clock)
    last_receive_time: Mutex<Option<Instant>>,

    /// Consecutive failures counter
    consecutive_failures: AtomicU8,

    /// Suppression state - data packet received resets timeout
    last_data_packet_time: Mutex<Option<Instant>>,

    /// Current RTT estimate in nanoseconds
    current_rtt: AtomicU64,

    /// Connection alive flag
    connection_alive: std::sync::atomic::AtomicBool,

    /// Configuration
    config: Arc<HeartbeatConfig>,
}

impl HeartbeatState {
    /// Create new heartbeat state with configuration
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            sequence: AtomicU64::new(0),
            last_send_time: Mutex::new(None),
            last_receive_time: Mutex::new(None),
            consecutive_failures: AtomicU8::new(0),
            last_data_packet_time: Mutex::new(None),
            current_rtt: AtomicU64::new(100_000_000), // 100ms default in nanoseconds
            connection_alive: std::sync::atomic::AtomicBool::new(true),
            config: Arc::new(config),
        }
    }

    /// Check if heartbeat should be sent based on interval and jitter
    pub fn should_send_heartbeat(&self) -> bool {
        let guard = self
            .last_send_time
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        match *guard {
            None => true, // First heartbeat
            Some(last_send) => {
                let elapsed = last_send.elapsed();
                let interval_ms = self.config.interval_ms.as_millis();
                let jitter_ms = self.config.jitter_ms;

                // Add random jitter to prevent synchronization
                let jitter = if jitter_ms > 0 {
                    (rand::random::<u64>() % (jitter_ms * 2)).saturating_sub(jitter_ms)
                } else {
                    0
                };
                let target_interval_ms = interval_ms.saturating_add(jitter);

                elapsed.as_millis() as u64 >= target_interval_ms
            }
        }
    }

    /// Record heartbeat send
    pub fn record_send(&self) -> HeartbeatSequence {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        *self
            .last_send_time
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

        debug!(
            sequence = seq,
            interval_ms = self.config.interval_ms.as_millis(),
            "Heartbeat sent"
        );

        HeartbeatSequence(seq as u32)
    }

    /// Record heartbeat response and update RTT
    pub fn record_response(&self, sequence: HeartbeatSequence, sent_time: Instant) {
        let rtt_nanos = sent_time.elapsed().as_nanos() as u64;
        self.current_rtt.store(rtt_nanos, Ordering::Relaxed);

        *self
            .last_receive_time
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

        // Reset consecutive failures on successful response
        self.consecutive_failures.store(0, Ordering::SeqCst);

        debug!(
            sequence = sequence.0,
            rtt_ms = rtt_nanos / 1_000_000,
            "Heartbeat response received"
        );
    }

    /// Record data packet reception (for suppression)
    pub fn record_data_packet(&self) {
        if self.config.enable_suppression {
            *self
                .last_data_packet_time
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

            debug!("Data packet received, heartbeat timeout reset");
        }
    }

    /// Check for heartbeat timeout
    pub fn check_timeout(&self) -> Result<(), HeartbeatError> {
        // Get the most recent activity time (send, receive, or data packet)
        let last_activity = {
            let send_guard = self
                .last_send_time
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let recv_guard = self
                .last_receive_time
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let data_guard = self
                .last_data_packet_time
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            [*send_guard, *recv_guard, *data_guard]
                .iter()
                .filter_map(|&t| t)
                .max()
        };

        match last_activity {
            None => Ok(()), // No activity yet, no timeout
            Some(last) => {
                let elapsed_ms = last.elapsed().as_millis() as u64;

                if elapsed_ms > self.config.timeout_ms {
                    // Increment consecutive failures
                    let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;

                    warn!(
                        elapsed_ms = elapsed_ms,
                        timeout_ms = self.config.timeout_ms,
                        consecutive_failures = failures,
                        "Heartbeat timeout detected"
                    );

                    if failures >= self.config.max_consecutive_failures {
                        self.connection_alive.store(false, Ordering::SeqCst);

                        return Err(HeartbeatError::ConnectionDead {
                            consecutive_failures: failures,
                        });
                    }

                    Err(HeartbeatError::Timeout {
                        elapsed_ms,
                        timeout_ms: self.config.timeout_ms,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Get current RTT estimate
    pub fn current_rtt(&self) -> RoundTripTime {
        let nanos = self.current_rtt.load(Ordering::Relaxed);
        RoundTripTime::new(nanos)
    }

    /// Get current sequence number
    pub fn current_sequence(&self) -> u32 {
        self.sequence.load(Ordering::SeqCst) as u32
    }

    /// Check if connection is alive
    pub fn is_alive(&self) -> bool {
        self.connection_alive.load(Ordering::SeqCst)
    }

    /// Get consecutive failures count
    pub fn consecutive_failures(&self) -> u8 {
        self.consecutive_failures.load(Ordering::SeqCst)
    }

    /// Reset state (for recovery)
    pub fn reset(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        self.connection_alive.store(true, Ordering::SeqCst);
        *self
            .last_send_time
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .last_receive_time
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .last_data_packet_time
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;

        info!("Heartbeat state reset");
    }
}

/// Heartbeat engine
pub struct HeartbeatEngine {
    /// Session identifier
    session_id: SessionId,

    /// Heartbeat state
    state: Arc<HeartbeatState>,
}

impl HeartbeatEngine {
    /// Create new heartbeat engine
    pub fn new(session_id: SessionId, config: HeartbeatConfig) -> Result<Self, HeartbeatError> {
        config.validate()?;

        let state = Arc::new(HeartbeatState::new(config));

        Ok(Self { session_id, state })
    }

    /// Create with default configuration
    pub fn with_defaults(session_id: SessionId) -> Result<Self, HeartbeatError> {
        Self::new(session_id, HeartbeatConfig::default_config())
    }

    /// Check if heartbeat should be sent
    pub fn should_send(&self) -> bool {
        let _span = span!(Level::DEBUG, "heartbeat_check", session_id = %self.session_id).entered();

        self.state.should_send_heartbeat()
    }

    /// Generate heartbeat packet data
    pub fn generate_heartbeat(&self) -> Result<(HeartbeatSequence, RoundTripTime), HeartbeatError> {
        let _span =
            span!(Level::INFO, "heartbeat_generate", session_id = %self.session_id).entered();

        if !self.state.is_alive() {
            return Err(HeartbeatError::GenerationFailed {
                reason: "Connection declared dead".to_string(),
            });
        }

        let sequence = self.state.record_send();
        let rtt = self.state.current_rtt();

        Ok((sequence, rtt))
    }

    /// Process heartbeat response
    pub fn process_response(
        &self,
        sequence: HeartbeatSequence,
        sent_time: Instant,
    ) -> Result<RoundTripTime, HeartbeatError> {
        let _span = span!(Level::INFO, "heartbeat_response",
            session_id = %self.session_id,
            sequence = sequence.0
        )
        .entered();

        self.state.record_response(sequence, sent_time);
        Ok(self.state.current_rtt())
    }

    /// Record data packet (for heartbeat suppression)
    pub fn on_data_packet(&self) {
        self.state.record_data_packet();
    }

    /// Check for keepalive timeout
    pub fn check_keepalive(&self) -> Result<(), HeartbeatError> {
        let _span =
            span!(Level::DEBUG, "heartbeat_keepalive", session_id = %self.session_id).entered();

        self.state.check_timeout()
    }

    /// Get current RTT estimate
    pub fn current_rtt(&self) -> RoundTripTime {
        self.state.current_rtt()
    }

    /// Check if connection is alive
    pub fn is_alive(&self) -> bool {
        self.state.is_alive()
    }

    /// Get consecutive failures
    pub fn consecutive_failures(&self) -> u8 {
        self.state.consecutive_failures()
    }

    /// Reset heartbeat state (for recovery)
    pub fn reset(&self) {
        let _span = span!(Level::INFO, "heartbeat_reset", session_id = %self.session_id).entered();

        self.state.reset();
    }

    /// Get heartbeat configuration
    pub fn config(&self) -> Arc<HeartbeatConfig> {
        self.state.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_heartbeat_config_default() {
        let config = HeartbeatConfig::default_config();
        assert_eq!(config.interval_ms.as_millis(), 30000);
        assert_eq!(config.timeout_ms, 90000);
        assert_eq!(config.max_consecutive_failures, 3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_heartbeat_config_custom_interval() {
        let config = HeartbeatConfig::with_interval(15000).unwrap();
        assert_eq!(config.interval_ms.as_millis(), 15000);
        assert_eq!(config.timeout_ms, 45000); // 3x interval
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_heartbeat_config_invalid_interval() {
        assert!(HeartbeatConfig::with_interval(0).is_err());
    }

    #[test]
    fn test_heartbeat_config_negotiation() {
        let config = HeartbeatConfig::negotiate(20000, 30000).unwrap();
        assert_eq!(config.interval_ms.as_millis(), 30000); // Max of both
        assert!(config.negotiated);
    }

    #[test]
    fn test_heartbeat_send_timing() {
        // Create config with zero jitter for deterministic testing
        let config = HeartbeatConfig {
            interval_ms: HeartbeatInterval::new(100), // 100ms interval
            timeout_ms: 300,
            max_consecutive_failures: 3,
            jitter_ms: 0, // No jitter for deterministic test
            enable_suppression: true,
            negotiated: false,
        };
        let state = HeartbeatState::new(config);

        // Should send first heartbeat immediately
        assert!(state.should_send_heartbeat());

        // Record send
        state.record_send();

        // Should not send immediately after
        assert!(!state.should_send_heartbeat());

        // Wait for interval (no jitter, so 150ms is plenty)
        thread::sleep(Duration::from_millis(150));

        // Should send now
        assert!(state.should_send_heartbeat());
    }

    #[test]
    fn test_heartbeat_response_resets_failures() {
        let config = HeartbeatConfig::default_config();
        let state = HeartbeatState::new(config);

        // Simulate failures
        state.consecutive_failures.store(2, Ordering::SeqCst);

        // Record response
        let sent_time = Instant::now();
        state.record_response(HeartbeatSequence(1), sent_time);

        // Failures should be reset
        assert_eq!(state.consecutive_failures(), 0);
    }

    #[test]
    fn test_heartbeat_timeout_detection() {
        let config = HeartbeatConfig {
            interval_ms: HeartbeatInterval::new(1000),
            timeout_ms: 100,
            max_consecutive_failures: 3,
            jitter_ms: 10,
            enable_suppression: true,
            negotiated: false,
        };
        let state = HeartbeatState::new(config);

        // Record send
        state.record_send();

        // Should not timeout immediately
        assert!(state.check_timeout().is_ok());

        // Wait for timeout
        thread::sleep(Duration::from_millis(150));

        // Should detect timeout
        assert!(state.check_timeout().is_err());
    }

    #[test]
    fn test_heartbeat_suppression() {
        let config = HeartbeatConfig {
            interval_ms: HeartbeatInterval::new(1000),
            timeout_ms: 100,
            max_consecutive_failures: 3,
            jitter_ms: 10,
            enable_suppression: true,
            negotiated: false,
        };
        let state = HeartbeatState::new(config);

        // Record send
        state.record_send();

        // Wait partial timeout
        thread::sleep(Duration::from_millis(60));

        // Record data packet (should reset timeout window)
        state.record_data_packet();

        // Wait more
        thread::sleep(Duration::from_millis(60));

        // Should not timeout because data packet reset the window
        assert!(state.check_timeout().is_ok());
    }

    #[test]
    fn test_heartbeat_consecutive_failures() {
        let config = HeartbeatConfig {
            interval_ms: HeartbeatInterval::new(1000),
            timeout_ms: 50,
            max_consecutive_failures: 3,
            jitter_ms: 10,
            enable_suppression: true,
            negotiated: false,
        };
        let state = HeartbeatState::new(config);

        state.record_send();

        // First failure
        thread::sleep(Duration::from_millis(60));
        let result = state.check_timeout();
        assert!(result.is_err());
        assert_eq!(state.consecutive_failures(), 1);
        assert!(state.is_alive());

        // Second failure
        thread::sleep(Duration::from_millis(60));
        let result = state.check_timeout();
        assert!(result.is_err());
        assert_eq!(state.consecutive_failures(), 2);
        assert!(state.is_alive());

        // Third failure - connection dead
        thread::sleep(Duration::from_millis(60));
        let result = state.check_timeout();
        assert!(result.is_err());
        assert_eq!(state.consecutive_failures(), 3);
        assert!(!state.is_alive());
    }

    #[test]
    fn test_heartbeat_engine_creation() {
        let session_id = SessionId::new(1);
        let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

        assert!(engine.is_alive());
        assert_eq!(engine.consecutive_failures(), 0);
    }

    #[test]
    fn test_heartbeat_engine_generate() {
        let session_id = SessionId::new(1);
        let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

        let (sequence, _rtt) = engine.generate_heartbeat().unwrap();
        assert_eq!(sequence.0, 0); // First sequence

        let (sequence2, _) = engine.generate_heartbeat().unwrap();
        assert_eq!(sequence2.0, 1); // Incremented
    }

    #[test]
    fn test_heartbeat_engine_reset() {
        let session_id = SessionId::new(1);
        let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

        // Generate some heartbeats
        engine.generate_heartbeat().unwrap();
        engine.generate_heartbeat().unwrap();

        // Simulate failures
        engine.state.consecutive_failures.store(2, Ordering::SeqCst);

        // Reset
        engine.reset();

        // State should be reset
        assert_eq!(engine.consecutive_failures(), 0);
        assert!(engine.is_alive());
    }

    #[test]
    fn test_heartbeat_manager_create() {
        let session_id = SessionId::new(42);
        let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

        let (seq1, _rtt1) = engine.generate_heartbeat().unwrap();
        let (seq2, _rtt2) = engine.generate_heartbeat().unwrap();
        let (seq3, _rtt3) = engine.generate_heartbeat().unwrap();

        assert_eq!(seq1.0, 0);
        assert_eq!(seq2.0, 1);
        assert_eq!(seq3.0, 2);
    }

    #[test]
    fn test_heartbeat_manager_rtt_calculation() {
        let session_id = SessionId::new(100);
        let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

        let sent_time = Instant::now();
        thread::sleep(Duration::from_millis(50));

        let rtt = engine
            .process_response(HeartbeatSequence(0), sent_time)
            .unwrap();

        assert!(rtt.as_millis() >= 50);
        assert!(rtt.as_millis() < 100);
    }

    #[test]
    fn test_heartbeat_exchange() {
        let session_id = SessionId::new(200);
        let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

        let (sequence, _initial_rtt) = engine.generate_heartbeat().unwrap();
        assert_eq!(sequence.0, 0);

        let sent_time = Instant::now();
        thread::sleep(Duration::from_millis(25));

        let measured_rtt = engine.process_response(sequence, sent_time).unwrap();

        assert!(measured_rtt.as_millis() >= 25);
        assert!(measured_rtt.as_millis() < 50);
        assert_eq!(engine.consecutive_failures(), 0);
        assert!(engine.is_alive());
    }
}
