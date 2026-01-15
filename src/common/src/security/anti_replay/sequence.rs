// Sequence number validation for anti-replay protection
//
// This module provides sequence number validation using sliding windows
// to detect duplicate and out-of-order packets.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::SecurityError;
use crate::protocol::types::*;

/// Result type for sequence validation operations
pub type SequenceResult<T> = Result<T, SecurityError>;

/// Sequence validation configuration
#[derive(Debug, Clone)]
pub struct SequenceValidationConfig {
    /// Size of the sliding window
    pub window_size: WindowSizeValue,

    /// Enable strict ordering (reject out-of-order packets)
    pub strict_ordering: SecurityFlag,

    /// Maximum sequence number gap before considering it a new session
    pub max_gap: GapTolerance,
}

impl Default for SequenceValidationConfig {
    fn default() -> Self {
        Self {
            window_size: WindowSizeValue::new(1000),
            strict_ordering: SecurityFlag::new(false),
            max_gap: GapTolerance::new(1000),
        }
    }
}

/// Sliding window for sequence number tracking
#[derive(Debug, Clone)]
pub struct SequenceWindow {
    /// Base sequence number (left edge of window)
    base: SequenceNumber,

    /// Window tracking received sequence numbers (1000 entries)
    /// Each entry represents whether a sequence number has been received
    /// True = received, False = not received
    window: [bool; 1000],

    /// Window size (1000 entries)
    size: WindowSize,

    /// Highest sequence number seen
    highest: SequenceNumber,

    /// Total packets received
    received_count: ReceivedCount,

    /// Duplicate packets detected
    duplicate_count: DuplicateCount,
}

impl SequenceWindow {
    /// Create a new sequence window
    pub fn new(size: u32) -> Self {
        Self {
            base: SequenceNumber::new(0),
            window: [false; 1000],
            size: WindowSize::new(size.min(1000)), // Limit to 1000 entries
            highest: SequenceNumber::new(0),
            received_count: ReceivedCount::zero(),
            duplicate_count: DuplicateCount::zero(),
        }
    }

    /// Check if a sequence number is valid and mark it as received
    pub fn check_and_mark(
        &mut self,
        session_id: SessionId,
        seq: SequenceNumber,
    ) -> SequenceResult<bool> {
        let seq_num = seq.as_u32();

        // Calculate difference from base, handling wraparound
        let diff = seq_num.wrapping_sub(self.base.as_u32());

        if diff < self.size.as_u32() {
            // Within current window
            // Use circular buffer indexing: (base + diff) % 1000
            let window_idx = (self.base.as_u32().wrapping_add(diff) as usize) % 1000;
            if self.window[window_idx] {
                // Already received
                self.duplicate_count.increment();
                Err(SecurityError::duplicate_packet(session_id, seq))
            } else {
                // Mark as received
                self.window[window_idx] = true;
                self.received_count.increment();
                if seq_num.wrapping_sub(self.highest.as_u32()) < (1u32 << 31)
                    || self.received_count.get() == 1
                {
                    self.highest = seq;
                }
                Ok(true)
            }
        } else if diff < (1u32 << 31) {
            // Advance window forward
            let advance = diff - self.size.as_u32() + 1;
            self.advance_window(advance);

            // Mark the new packet at the end of the window
            // After advance, base has moved forward, so recalculate position
            let new_diff = seq_num.wrapping_sub(self.base.as_u32());
            let window_idx = (self.base.as_u32().wrapping_add(new_diff) as usize) % 1000;
            self.window[window_idx] = true;
            self.received_count.increment();
            self.highest = seq;
            Ok(true)
        } else {
            // Too old (behind window) - potential replay attack
            Err(SecurityError::replay_attack(session_id, seq))
        }
    }

    /// Advance the window forward
    fn advance_window(&mut self, positions: u32) {
        if positions >= self.size.as_u32() {
            // Complete window shift - clear all entries
            self.window = [false; 1000];
        } else {
            // Partial window shift - clear the entries that are moving out of the window
            // These are the entries from base to base+positions-1
            for i in 0..positions {
                let seq_to_clear = self.base.as_u32().wrapping_add(i);
                let idx = (seq_to_clear as usize) % 1000;
                self.window[idx] = false;
            }
        }
        self.base = SequenceNumber::new(self.base.as_u32().wrapping_add(positions));
    }

    /// Reset the window with a new base sequence
    pub fn reset(&mut self, new_base: SequenceNumber) {
        self.base = new_base;
        self.highest = new_base;
        self.window = [false; 1000]; // Clear all entries
        self.received_count
            .store(1, std::sync::atomic::Ordering::Relaxed);
        self.duplicate_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get window statistics
    pub fn stats(&self) -> (SequenceNumber, SequenceNumber, u64, u64) {
        (
            self.base,
            self.highest,
            self.received_count.get(),
            self.duplicate_count.get(),
        )
    }

    /// Check if sequence number would be accepted without marking
    pub fn would_accept(&self, seq: SequenceNumber) -> bool {
        let seq_num = seq.as_u32();

        if self.received_count.get() == 0 {
            return true;
        }

        let diff = seq_num.wrapping_sub(self.base.as_u32());

        if diff < self.size.as_u32() {
            // Within current window - check if already received
            let window_idx = (self.base.as_u32().wrapping_add(diff) as usize) % 1000;
            !self.window[window_idx]
        } else if diff < (1u32 << 31) {
            true // Would advance window
        } else {
            false // Too old
        }
    }

    /// Get the expected next sequence number
    pub fn expected_next(&self) -> SequenceNumber {
        SequenceNumber::new(self.highest.as_u32().wrapping_add(1))
    }

    /// Check if window is full
    pub fn is_full(&self) -> bool {
        // Window is full if all entries within the window size are true
        let window_size = self.size.as_u32() as usize;
        self.window[..window_size.min(1000)].iter().all(|&x| x)
    }
}

/// Sequence number validator
pub struct SequenceValidator {
    /// Configuration
    config: SequenceValidationConfig,

    /// Sliding window (using RefCell for interior mutability)
    window: std::cell::RefCell<SequenceWindow>,
}

impl SequenceValidator {
    /// Create a new sequence validator with initial sequence number
    pub fn new(initial_seq: u32) -> Self {
        let config = SequenceValidationConfig::default();
        let mut window = SequenceWindow::new(config.window_size.as_u32());
        // Set the base - packets will be validated against this base
        window.base = SequenceNumber::new(initial_seq);
        window.highest = SequenceNumber::new(initial_seq);
        // Start with received_count=0 so packets are validated normally
        Self {
            config,
            window: std::cell::RefCell::new(window),
        }
    }

    /// Create a new sequence validator from config
    pub fn from_config(config: SequenceValidationConfig) -> Self {
        let window = SequenceWindow::new(config.window_size.as_u32());
        Self {
            config,
            window: std::cell::RefCell::new(window),
        }
    }

    /// Create with default configuration
    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(0)
    }
}

impl Default for SequenceValidator {
    fn default() -> Self {
        Self::new_default()
    }
}

impl SequenceValidator {
    /// Validate a packet header
    pub fn validate(&self, header: &crate::protocol::packet::PacketHeader) -> SequenceResult<()> {
        let session_id = header.session_id();
        let sequence = header.sequence_number();

        // Get mutable access to window through RefCell
        let mut window = self.window.borrow_mut();

        // Check for large gaps that might indicate session restart
        if window.received_count.get() > 0 {
            let gap = sequence.as_u32().wrapping_sub(window.highest.as_u32());
            if gap > self.config.max_gap.as_u32() && gap < (1u32 << 31) {
                // Large gap detected - might be session restart
                return Err(SecurityError::sequence_validation_failed(
                    sequence,
                    window.expected_next(),
                ));
            }
        }

        // Strict ordering check
        if self.config.strict_ordering.as_bool()
            && window.received_count.get() > 0
            && sequence.as_u32().wrapping_sub(window.highest.as_u32()) >= (1u32 << 31)
        {
            // Out of order packet
            return Err(SecurityError::sequence_validation_failed(
                sequence,
                window.expected_next(),
            ));
        }

        // Check and mark in window
        window.check_and_mark(session_id, sequence)?;

        Ok(())
    }

    /// Validate a sequence number
    pub fn validate_sequence(
        &mut self,
        session_id: SessionId,
        sequence: SequenceNumber,
    ) -> SequenceResult<()> {
        let mut window = self.window.borrow_mut();

        // Check for large gaps that might indicate session restart
        if window.received_count.get() > 0 {
            let gap = sequence.as_u32().wrapping_sub(window.highest.as_u32());
            if gap > self.config.max_gap.as_u32() && gap < (1u32 << 31) {
                // Large gap detected - might be session restart
                return Err(SecurityError::sequence_validation_failed(
                    sequence,
                    window.expected_next(),
                ));
            }
        }

        // Strict ordering check
        if self.config.strict_ordering.as_bool()
            && window.received_count.get() > 0
            && sequence.as_u32().wrapping_sub(window.highest.as_u32()) >= (1u32 << 31)
        {
            // Out of order packet
            return Err(SecurityError::sequence_validation_failed(
                sequence,
                window.expected_next(),
            ));
        }

        // Check and mark in window
        window.check_and_mark(session_id, sequence)?;

        Ok(())
    }

    /// Reset the validator with a new base sequence
    pub fn reset(&mut self, base_sequence: SequenceNumber) {
        self.window.borrow_mut().reset(base_sequence);
    }

    /// Check if a sequence would be accepted
    pub fn would_accept(&self, sequence: SequenceNumber) -> bool {
        self.window.borrow().would_accept(sequence)
    }

    /// Get validator statistics
    pub fn stats(&self) -> (u32, u32, u64, u64) {
        let (base, highest, accepted, rejected) = self.window.borrow().stats();
        (base.as_u32(), highest.as_u32(), accepted, rejected)
    }

    /// Get expected next sequence number
    pub fn expected_next(&self) -> SequenceNumber {
        self.window.borrow().expected_next()
    }

    /// Update configuration
    pub fn update_config(&mut self, config: SequenceValidationConfig) {
        let window_size = config.window_size;
        self.config = config;
        // Recreate window if size changed
        let mut window = self.window.borrow_mut();
        if window.size.as_u32() != window_size.as_u32() {
            let (base, _highest, _, _) = window.stats();
            *window = SequenceWindow::new(window_size.as_u32());
            if window.received_count.get() > 0 {
                window.reset(base);
            }
        }
    }

    /// Get current configuration
    pub fn get_config(&self) -> &SequenceValidationConfig {
        &self.config
    }
}
