// Anti-replay protection engine
//
// This module provides comprehensive anti-replay protection using sliding windows,
// timestamp validation, and sequence number tracking.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::security::SecurityError;
use crate::protocol::types::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Result type for anti-replay operations
pub type AntiReplayResult<T> = Result<T, SecurityError>;

/// Anti-replay window configuration
#[derive(Debug, Clone)]
pub struct AntiReplayConfig {
    /// Size of the sliding window for sequence numbers
    pub window_size: WindowSize,

    /// Maximum allowed timestamp drift in seconds
    pub max_timestamp_drift: Duration,

    /// Maximum age of packets in seconds
    pub max_packet_age: Duration,

    /// Enable strict sequence number checking
    pub strict_sequence_check: bool,

    /// Enable timestamp validation
    pub timestamp_validation: bool,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            window_size: WindowSize::new(64),
            max_timestamp_drift: Duration::new(30, 0), // 30 seconds in nanoseconds
            max_packet_age: Duration::new(300, 0),     // 5 minutes in nanoseconds
            strict_sequence_check: true,
            timestamp_validation: true,
        }
    }
}

/// Sliding window for sequence number tracking
#[derive(Debug, Clone)]
struct SlidingWindow {
    /// Base sequence number (left edge of window)
    base: WindowBase,

    /// Bitmap representing received packets
    bitmap: Bitmap,

    /// Window size
    size: WindowSize,
}

impl SlidingWindow {
    /// Create a new sliding window
    fn new(size: u32) -> Self {
        Self {
            base: WindowBase::zero(),
            bitmap: Bitmap::empty(),
            size: WindowSize::new(size.min(64)), // Limit to 64 bits
        }
    }

    /// Check if a sequence number is valid and mark it as received
    fn check_and_mark(&mut self, seq: crate::protocol::types::SequenceNumber) -> bool {
        // Handle sequence number wraparound
        let diff = seq.as_u32().wrapping_sub(self.base.as_u32());

        if diff < self.size.as_u32() {
            // Within current window (bit 0 = base, bit 63 = base+63)
            let bit_pos = diff as u8;
            if self.bitmap.has_bit(bit_pos) {
                // Already received
                false
            } else {
                // Mark as received
                self.bitmap.set_bit(bit_pos);
                true
            }
        } else if diff < (1u32 << 31) {
            // Advance window forward
            let advance = diff - self.size.as_u32() + 1;
            self.advance_window(advance);

            // Mark the new packet at the highest position
            let bit_pos = (self.size.as_u32() - 1) as u8;
            self.bitmap.set_bit(bit_pos);
            true
        } else {
            // Too old (behind window)
            false
        }
    }

    /// Advance the window forward
    fn advance_window(&mut self, positions: u32) {
        if positions >= self.size.as_u32() {
            // Complete window shift
            self.bitmap = Bitmap::empty();
        } else {
            // Partial window shift
            let shifted = self.bitmap.as_u64() >> positions;
            self.bitmap = Bitmap::new(shifted);
        }
        self.base = WindowBase::new(self.base.as_u32().wrapping_add(positions));
    }

    /// Reset the window
    fn reset(&mut self, new_base: u32) {
        self.base = WindowBase::new(new_base);
        self.bitmap = Bitmap::empty();
    }
}

/// Session-specific anti-replay state
#[derive(Debug)]
struct SessionAntiReplayState {
    /// Sliding window for sequence numbers
    window: SlidingWindow,

    /// Last valid timestamp
    last_timestamp: Option<SystemTime>,

    /// Session creation time
    created_at: SystemTime,

    /// Number of packets processed
    packet_count: PacketCount,

    /// Number of replay attempts detected
    replay_count: PacketCount,
}

impl SessionAntiReplayState {
    /// Create new session state
    fn new(window_size: u32) -> Self {
        Self {
            window: SlidingWindow::new(window_size),
            last_timestamp: None,
            created_at: SystemTime::now(),
            packet_count: PacketCount::new(0),
            replay_count: PacketCount::new(0),
        }
    }

    /// Reset the session state
    fn reset(&mut self, base_seq: crate::protocol::types::SequenceNumber) {
        self.window.reset(base_seq.as_u32());
        self.last_timestamp = None;
        self.packet_count = PacketCount::new(0);
        self.replay_count = PacketCount::new(0);
    }
}

/// Anti-replay statistics
#[derive(Debug, Clone, Copy)]
pub struct AntiReplayStatistics {
    /// Total packets processed
    pub total_packets: u64,

    /// Number of replay attempts detected
    pub replay_attempts: u64,
}

/// Anti-replay protection engine
pub struct AntiReplayEngine {
    /// Configuration
    config: AntiReplayConfig,

    /// Per-session anti-replay state
    sessions: Arc<RwLock<HashMap<SessionId, SessionAntiReplayState>>>,

    /// Timestamp validator
    timestamp_validator: super::timestamp::TimestampValidator,
}

impl AntiReplayEngine {
    /// Create a new anti-replay engine with default configuration
    pub fn new() -> Self {
        Self::from_config(AntiReplayConfig::default())
    }
}

impl Default for AntiReplayEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayEngine {
    /// Create a new anti-replay engine with custom configuration
    pub fn from_config(config: AntiReplayConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timestamp_validator: super::timestamp::TimestampValidator::new(),
        }
    }

    /// Create an anti-replay engine with default configuration
    pub fn new_default() -> Self {
        Self::new()
    }

    /// Validate a packet header against replay attacks (test compatibility)
    pub fn validate_packet(
        &self,
        header: &crate::protocol::packet::PacketHeader,
    ) -> AntiReplayResult<()> {
        // Extract information from header
        let session_id = header.session_id();
        let sequence = header.sequence_number();
        let timestamp = Some(header.timestamp());

        // Use timestamp validator (before incrementing stats) only if enabled
        if self.config.timestamp_validation {
            if let Err(e) = self.timestamp_validator.validate(header) {
                // Count the failed attempt
                if let Ok(mut sessions) = self.sessions.write() {
                    let state = sessions.entry(session_id).or_insert_with(|| {
                        SessionAntiReplayState::new(self.config.window_size.as_u32())
                    });
                    state.packet_count += 1;
                    state.replay_count += 1;
                }
                return Err(e);
            }
        }

        // Note: Duplicate detection is now handled by the sequence window in validate_packet_full
        // The separate duplicate_detector was causing test interference via global static

        // Use the full validation (includes sequence-based duplicate detection and stats tracking)
        self.validate_packet_full(session_id, sequence, timestamp)
    }

    /// Validate a packet against replay attacks
    pub fn validate_packet_full(
        &self,
        session_id: SessionId,
        sequence: SequenceNumber,
        timestamp: Option<Timestamp>,
    ) -> AntiReplayResult<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire sessions write lock"))?;

        // Get or create session state
        let session_state = sessions
            .entry(session_id.clone())
            .or_insert_with(|| SessionAntiReplayState::new(self.config.window_size.as_u32()));

        // Update statistics (count all packets, not just valid ones)
        session_state.packet_count += 1;

        // Validate timestamp if enabled and provided
        if self.config.timestamp_validation {
            if let Some(ts) = timestamp {
                self.validate_timestamp(session_state, ts)?;
            }
        }

        // Validate sequence number
        self.validate_sequence(session_id.clone(), session_state, sequence)?;

        Ok(())
    }

    /// Validate packet timestamp
    fn validate_timestamp(
        &self,
        session_state: &mut SessionAntiReplayState,
        timestamp: Timestamp,
    ) -> AntiReplayResult<()> {
        let now = SystemTime::now();
        let packet_time = UNIX_EPOCH + Duration::from_nanos(timestamp.as_nanos());

        // Check if packet is too old
        if let Ok(age) = now.duration_since(packet_time) {
            if age.as_nanos() as u64 > self.config.max_packet_age.as_nanos() as u64 {
                session_state.replay_count += 1;
                return Err(SecurityError::timestamp_validation_failed(
                    timestamp,
                    self.config.max_packet_age.as_nanos() as u64,
                ));
            }
        }

        // Check if packet is too far in the future
        if let Ok(drift) = packet_time.duration_since(now) {
            if drift.as_nanos() as u64 > self.config.max_timestamp_drift.as_nanos() as u64 {
                session_state.replay_count += 1;
                return Err(SecurityError::timestamp_validation_failed(
                    timestamp,
                    self.config.max_timestamp_drift.as_nanos() as u64,
                ));
            }
        }

        // Check for timestamp regression (optional strict check)
        if let Some(last_ts) = session_state.last_timestamp {
            if packet_time < last_ts {
                let regression = last_ts
                    .duration_since(packet_time)
                    .unwrap_or(Duration::ZERO);

                if regression.as_nanos() as u64 > self.config.max_timestamp_drift.as_nanos() as u64 {
                    session_state.replay_count += 1;
                    return Err(SecurityError::timestamp_validation_failed(
                        timestamp,
                        self.config.max_timestamp_drift.as_nanos() as u64,
                    ));
                }
            }
        }

        // Update last timestamp
        session_state.last_timestamp = Some(packet_time);

        Ok(())
    }

    /// Validate sequence number
    fn validate_sequence(
        &self,
        session_id: SessionId,
        session_state: &mut SessionAntiReplayState,
        sequence: SequenceNumber,
    ) -> AntiReplayResult<()> {
        let seq_num = sequence.as_u32();

        if !session_state
            .window
            .check_and_mark(SequenceNumber::new(seq_num))
        {
            session_state.replay_count += 1;

            // Determine if this is a duplicate or replay
            let diff = seq_num.wrapping_sub(session_state.window.base.as_u32());
            if diff < session_state.window.size.as_u32() || diff >= (1u32 << 31) {
                return Err(SecurityError::duplicate_packet(session_id, sequence));
            }
            return Err(SecurityError::replay_attack(session_id, sequence));
        }

        Ok(())
    }

    /// Reset session state (for key rotation or session restart)
    pub fn reset_session(
        &self,
        session_id: SessionId,
        base_sequence: SequenceNumber,
    ) -> AntiReplayResult<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire sessions write lock"))?;

        if let Some(session_state) = sessions.get_mut(&session_id) {
            session_state.reset(base_sequence);
        }

        Ok(())
    }

    /// Remove session state
    pub fn remove_session(&self, session_id: SessionId) -> AntiReplayResult<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire sessions write lock"))?;

        sessions.remove(&session_id);
        Ok(())
    }

    /// Get session statistics
    pub fn get_session_stats(&self, session_id: SessionId) -> AntiReplayResult<Option<(u64, u64)>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire sessions read lock"))?;

        if let Some(session_state) = sessions.get(&session_id) {
            Ok(Some((
                session_state
                    .packet_count
                    .load(std::sync::atomic::Ordering::Relaxed),
                session_state
                    .replay_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            )))
        } else {
            Ok(None)
        }
    }

    /// Clean up old sessions
    pub fn cleanup_old_sessions(&self, max_age: Duration) -> AntiReplayResult<usize> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire sessions write lock"))?;

        let now = SystemTime::now();
        let initial_count = sessions.len();

        sessions.retain(|_, state| {
            now.duration_since(state.created_at)
                .map(|age| age < max_age)
                .unwrap_or(false)
        });

        Ok(initial_count - sessions.len())
    }

    /// Get total statistics across all sessions
    pub fn get_total_stats(&self) -> AntiReplayResult<(usize, u64, u64)> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire sessions read lock"))?;

        let session_count = sessions.len();
        let (total_packets, total_replays) =
            sessions
                .values()
                .fold((0u64, 0u64), |(packets, replays), state| {
                    (
                        packets
                            + state
                                .packet_count
                                .load(std::sync::atomic::Ordering::Relaxed),
                        replays
                            + state
                                .replay_count
                                .load(std::sync::atomic::Ordering::Relaxed),
                    )
                });

        Ok((session_count, total_packets, total_replays))
    }

    /// Get statistics (test compatibility)
    pub fn get_statistics(&self) -> AntiReplayStatistics {
        let (_, total_packets, replay_attempts) = self.get_total_stats().unwrap_or((0, 0, 0));

        AntiReplayStatistics {
            total_packets,
            replay_attempts,
        }
    }

    /// Update configuration
    pub fn update_config(&mut self, config: AntiReplayConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &AntiReplayConfig {
        &self.config
    }
}

/// Thread-safe anti-replay engine
pub struct ThreadSafeAntiReplayEngine {
    /// Inner engine
    inner: Arc<RwLock<AntiReplayEngine>>,
}

impl ThreadSafeAntiReplayEngine {
    /// Create a new thread-safe anti-replay engine
    pub fn new(config: AntiReplayConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AntiReplayEngine::from_config(config))),
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(AntiReplayConfig::default())
    }

    /// Validate a packet against replay attacks
    pub fn validate_packet(
        &self,
        session_id: SessionId,
        sequence: SequenceNumber,
        timestamp: Option<Timestamp>,
    ) -> AntiReplayResult<()> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        engine.validate_packet_full(session_id, sequence, timestamp)
    }

    /// Reset session state
    pub fn reset_session(
        &self,
        session_id: SessionId,
        base_sequence: SequenceNumber,
    ) -> AntiReplayResult<()> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        engine.reset_session(session_id, base_sequence)
    }

    /// Remove session state
    pub fn remove_session(&self, session_id: SessionId) -> AntiReplayResult<()> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        engine.remove_session(session_id)
    }

    /// Get session statistics
    pub fn get_session_stats(&self, session_id: SessionId) -> AntiReplayResult<Option<(u64, u64)>> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        engine.get_session_stats(session_id)
    }

    /// Clean up old sessions
    pub fn cleanup_old_sessions(&self, max_age: Duration) -> AntiReplayResult<usize> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        engine.cleanup_old_sessions(max_age)
    }

    /// Get total statistics
    pub fn get_total_stats(&self) -> AntiReplayResult<(usize, u64, u64)> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        engine.get_total_stats()
    }

    /// Update configuration
    pub fn update_config(&self, config: AntiReplayConfig) -> AntiReplayResult<()> {
        let mut engine = self
            .inner
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine write lock"))?;

        engine.update_config(config);
        Ok(())
    }

    /// Get current configuration
    pub fn get_config(&self) -> AntiReplayResult<AntiReplayConfig> {
        let engine = self
            .inner
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire engine read lock"))?;

        Ok(engine.get_config().clone())
    }
}
