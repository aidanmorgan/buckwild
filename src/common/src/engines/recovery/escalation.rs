#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Recovery Escalation System
//
// Implements 6-level recovery escalation per design/protocol/12-recovery-mechanisms.md:
// Level 1: Time Resync (max 3 attempts)
// Level 2: Sequence Repair (max 3 attempts)
// Level 3: ECDH Rekeying (max 3 attempts)
// Level 4: Port Resync (max 3 attempts)
// Level 5: PSK Discovery (max 2 attempts)
// Level 6: Connection Reset (max 1 attempt)

use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};

use crate::error::EngineError;

/// Recovery level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecoveryLevel {
    /// Level 1: Time Resynchronization
    /// Fixes timing drift that causes port hopping misalignment
    /// Max attempts: 3
    TimeResync = 1,

    /// Level 2: Sequence Repair
    /// Repairs sequence number gaps and reorder buffer issues
    /// Max attempts: 3
    SequenceRepair = 2,

    /// Level 3: ECDH Rekeying
    /// Generates new ephemeral keys and re-derives session key
    /// Max attempts: 3
    EcdhRekeying = 3,

    /// Level 4: Port Resynchronization
    /// Re-establishes port hopping coordination
    /// Max attempts: 3
    PortResync = 4,

    /// Level 5: PSK Discovery
    /// Re-discovers shared PSK in multi-PSK environments
    /// Max attempts: 2
    PskDiscovery = 5,

    /// Level 6: Connection Reset
    /// Full connection teardown and re-establishment
    /// Max attempts: 1 (permanent failure after)
    ConnectionReset = 6,
}

impl RecoveryLevel {
    /// Get maximum attempts for this level
    pub fn max_attempts(&self) -> u32 {
        match self {
            Self::TimeResync => 3,
            Self::SequenceRepair => 3,
            Self::EcdhRekeying => 3,
            Self::PortResync => 3,
            Self::PskDiscovery => 2,
            Self::ConnectionReset => 1,
        }
    }

    /// Get next level in escalation
    pub fn next_level(&self) -> Option<Self> {
        match self {
            Self::TimeResync => Some(Self::SequenceRepair),
            Self::SequenceRepair => Some(Self::EcdhRekeying),
            Self::EcdhRekeying => Some(Self::PortResync),
            Self::PortResync => Some(Self::PskDiscovery),
            Self::PskDiscovery => Some(Self::ConnectionReset),
            Self::ConnectionReset => None, // Terminal
        }
    }

    /// Check if this is the terminal level
    pub fn is_terminal(&self) -> bool {
        *self == Self::ConnectionReset
    }

    /// Get descriptive name
    pub fn name(&self) -> &'static str {
        match self {
            Self::TimeResync => "Time Resynchronization",
            Self::SequenceRepair => "Sequence Repair",
            Self::EcdhRekeying => "ECDH Rekeying",
            Self::PortResync => "Port Resynchronization",
            Self::PskDiscovery => "PSK Discovery",
            Self::ConnectionReset => "Connection Reset",
        }
    }
}

/// Recovery attempt tracking
#[derive(Debug, Clone)]
pub struct RecoveryAttempt {
    /// Recovery level
    pub level: RecoveryLevel,

    /// Attempt number (1-indexed)
    pub attempt: u32,

    /// Start time
    pub started_at: SystemTime,

    /// Completed time (None if in progress)
    pub completed_at: Option<SystemTime>,

    /// Success flag
    pub success: bool,

    /// Error message (if failed)
    pub error: Option<String>,
}

impl RecoveryAttempt {
    /// Create new recovery attempt
    pub fn new(level: RecoveryLevel, attempt: u32) -> Self {
        Self {
            level,
            attempt,
            started_at: SystemTime::now(),
            completed_at: None,
            success: false,
            error: None,
        }
    }

    /// Mark as completed successfully
    pub fn complete_success(&mut self) {
        self.completed_at = Some(SystemTime::now());
        self.success = true;
    }

    /// Mark as failed
    pub fn complete_failure(&mut self, error: String) {
        self.completed_at = Some(SystemTime::now());
        self.success = false;
        self.error = Some(error);
    }

    /// Get duration
    pub fn duration(&self) -> Option<Duration> {
        match (self.started_at.elapsed(), &self.completed_at) {
            (Ok(elapsed), Some(_)) => Some(elapsed),
            _ => None,
        }
    }
}

/// Recovery state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// Normal operation (no recovery needed)
    Normal,

    /// Recovery in progress
    InProgress,

    /// Recovery succeeded
    Recovered,

    /// Recovery failed (permanent failure)
    Failed,
}

/// Recovery escalation manager
#[derive(Debug)]
pub struct RecoveryEscalation {
    /// Current recovery level
    current_level: RecoveryLevel,

    /// Attempts at current level
    attempts_at_level: u32,

    /// Current state
    state: RecoveryState,

    /// History of recovery attempts
    attempt_history: Vec<RecoveryAttempt>,

    /// Current attempt (in progress)
    current_attempt: Option<RecoveryAttempt>,

    /// Base backoff duration
    base_backoff_ms: u64,

    /// Last attempt time
    last_attempt_time: Option<SystemTime>,
}

impl Default for RecoveryEscalation {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl RecoveryEscalation {
    /// Create new recovery escalation manager
    /// base_backoff_ms: Base exponential backoff (1000ms default)
    pub fn new(base_backoff_ms: u64) -> Self {
        Self {
            current_level: RecoveryLevel::TimeResync,
            attempts_at_level: 0,
            state: RecoveryState::Normal,
            attempt_history: Vec::new(),
            current_attempt: None,
            base_backoff_ms,
            last_attempt_time: None,
        }
    }

    /// Get current state
    pub fn state(&self) -> RecoveryState {
        self.state
    }

    /// Get current level
    pub fn current_level(&self) -> RecoveryLevel {
        self.current_level
    }

    /// Get attempts at current level
    pub fn attempts_at_current_level(&self) -> u32 {
        self.attempts_at_level
    }

    /// Check if recovery needed
    pub fn needs_recovery(&self) -> bool {
        self.state == RecoveryState::InProgress
            || (self.state == RecoveryState::Normal && self.attempts_at_level > 0)
    }

    /// Check if permanently failed
    pub fn is_permanently_failed(&self) -> bool {
        self.state == RecoveryState::Failed
    }

    /// Calculate backoff duration for next attempt
    /// Exponential backoff: base * 2^attempt
    pub fn calculate_backoff(&self) -> Duration {
        let exponent = self.attempts_at_level.saturating_sub(1);
        let multiplier = 2u64.saturating_pow(exponent);
        let backoff_ms = self.base_backoff_ms.saturating_mul(multiplier);

        // Cap at 30 seconds
        let capped_ms = backoff_ms.min(30_000);

        Duration::from_millis(capped_ms)
    }

    /// Check if backoff period has elapsed
    pub fn backoff_elapsed(&self) -> bool {
        match self.last_attempt_time {
            None => true,
            Some(last_time) => {
                let backoff = self.calculate_backoff();
                last_time.elapsed().unwrap_or_default() >= backoff
            }
        }
    }

    /// Start recovery attempt
    /// Returns Err if:
    /// - Recovery already in progress
    /// - Backoff period not elapsed
    /// - Permanently failed
    pub fn start_recovery(&mut self) -> Result<RecoveryLevel, EngineError> {
        if self.state == RecoveryState::Failed {
            return Err(EngineError::PermanentFailure(
                "Recovery permanently failed".to_string(),
            ));
        }

        if self.state == RecoveryState::InProgress {
            return Err(EngineError::InvalidState(
                "Recovery already in progress".to_string(),
            ));
        }

        if !self.backoff_elapsed() {
            let remaining = if let Some(last_time) = self.last_attempt_time {
                self.calculate_backoff()
                    .saturating_sub(last_time.elapsed().unwrap_or_default())
            } else {
                // If no last_attempt_time, use full backoff duration
                self.calculate_backoff()
            };
            return Err(EngineError::BackoffRequired(remaining));
        }

        self.attempts_at_level += 1;
        self.state = RecoveryState::InProgress;
        self.last_attempt_time = Some(SystemTime::now());

        let attempt = RecoveryAttempt::new(self.current_level, self.attempts_at_level);
        self.current_attempt = Some(attempt.clone());

        info!(
            "Starting recovery: level={} ({}), attempt={}/{}",
            self.current_level as u8,
            self.current_level.name(),
            self.attempts_at_level,
            self.current_level.max_attempts()
        );

        Ok(self.current_level)
    }

    /// Complete recovery attempt successfully
    pub fn complete_success(&mut self) -> Result<(), EngineError> {
        if self.state != RecoveryState::InProgress {
            return Err(EngineError::InvalidState(
                "No recovery in progress".to_string(),
            ));
        }

        if let Some(mut attempt) = self.current_attempt.take() {
            attempt.complete_success();
            self.attempt_history.push(attempt.clone());

            info!(
                "Recovery succeeded: level={} ({}), attempt={}, duration={:?}",
                self.current_level as u8,
                self.current_level.name(),
                self.attempts_at_level,
                attempt.duration()
            );
        }

        // Reset to normal
        self.state = RecoveryState::Recovered;
        self.current_level = RecoveryLevel::TimeResync;
        self.attempts_at_level = 0;

        Ok(())
    }

    /// Complete recovery attempt with failure
    /// Automatically escalates to next level if attempts exhausted
    pub fn complete_failure(&mut self, error: String) -> Result<bool, EngineError> {
        if self.state != RecoveryState::InProgress {
            return Err(EngineError::InvalidState(
                "No recovery in progress".to_string(),
            ));
        }

        if let Some(mut attempt) = self.current_attempt.take() {
            attempt.complete_failure(error.clone());
            self.attempt_history.push(attempt.clone());

            warn!(
                "Recovery failed: level={} ({}), attempt={}/{}, error={}",
                self.current_level as u8,
                self.current_level.name(),
                self.attempts_at_level,
                self.current_level.max_attempts(),
                error
            );
        }

        self.state = RecoveryState::Normal;

        // Check if should escalate
        if self.attempts_at_level >= self.current_level.max_attempts() {
            return self.escalate();
        }

        Ok(false) // Not escalated
    }

    /// Escalate to next recovery level
    /// Returns true if escalated, false if terminal level reached (permanent failure)
    fn escalate(&mut self) -> Result<bool, EngineError> {
        match self.current_level.next_level() {
            Some(next_level) => {
                warn!(
                    "Escalating recovery: {} → {}",
                    self.current_level.name(),
                    next_level.name()
                );

                self.current_level = next_level;
                self.attempts_at_level = 0;

                Ok(true)
            }
            None => {
                error!("Recovery permanently failed: all escalation levels exhausted");
                self.state = RecoveryState::Failed;
                Ok(false)
            }
        }
    }

    /// Get attempt history
    pub fn attempt_history(&self) -> &[RecoveryAttempt] {
        &self.attempt_history
    }

    /// Get statistics
    pub fn statistics(&self) -> RecoveryStatistics {
        let total_attempts = self.attempt_history.len();
        let successful_attempts = self.attempt_history.iter().filter(|a| a.success).count();

        let mut level_attempts = [0u32; 6];
        for attempt in &self.attempt_history {
            let idx = (attempt.level as u8 - 1) as usize;
            if idx < 6 {
                level_attempts[idx] += 1;
            }
        }

        RecoveryStatistics {
            total_attempts,
            successful_attempts,
            current_level: self.current_level,
            attempts_at_current_level: self.attempts_at_level,
            state: self.state,
            level_attempts,
        }
    }

    /// Reset to normal state (use with caution)
    pub fn reset(&mut self) {
        info!("Resetting recovery escalation to normal state");
        self.current_level = RecoveryLevel::TimeResync;
        self.attempts_at_level = 0;
        self.state = RecoveryState::Normal;
        self.current_attempt = None;
    }
}

/// Recovery statistics
#[derive(Debug, Clone)]
pub struct RecoveryStatistics {
    pub total_attempts: usize,
    pub successful_attempts: usize,
    pub current_level: RecoveryLevel,
    pub attempts_at_current_level: u32,
    pub state: RecoveryState,
    pub level_attempts: [u32; 6],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_recovery_level_escalation() {
        assert_eq!(
            RecoveryLevel::TimeResync.next_level(),
            Some(RecoveryLevel::SequenceRepair)
        );
        assert_eq!(
            RecoveryLevel::SequenceRepair.next_level(),
            Some(RecoveryLevel::EcdhRekeying)
        );
        assert_eq!(
            RecoveryLevel::EcdhRekeying.next_level(),
            Some(RecoveryLevel::PortResync)
        );
        assert_eq!(
            RecoveryLevel::PortResync.next_level(),
            Some(RecoveryLevel::PskDiscovery)
        );
        assert_eq!(
            RecoveryLevel::PskDiscovery.next_level(),
            Some(RecoveryLevel::ConnectionReset)
        );
        assert_eq!(RecoveryLevel::ConnectionReset.next_level(), None);
    }

    #[test]
    fn test_recovery_level_max_attempts() {
        assert_eq!(RecoveryLevel::TimeResync.max_attempts(), 3);
        assert_eq!(RecoveryLevel::SequenceRepair.max_attempts(), 3);
        assert_eq!(RecoveryLevel::EcdhRekeying.max_attempts(), 3);
        assert_eq!(RecoveryLevel::PortResync.max_attempts(), 3);
        assert_eq!(RecoveryLevel::PskDiscovery.max_attempts(), 2);
        assert_eq!(RecoveryLevel::ConnectionReset.max_attempts(), 1);
    }

    #[test]
    fn test_recovery_escalation_success() {
        let mut escalation = RecoveryEscalation::new(100); // 100ms backoff for testing

        // Start recovery
        let level = escalation.start_recovery().unwrap();
        assert_eq!(level, RecoveryLevel::TimeResync);
        assert_eq!(escalation.state(), RecoveryState::InProgress);

        // Complete successfully
        escalation.complete_success().unwrap();
        assert_eq!(escalation.state(), RecoveryState::Recovered);
        assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
        assert_eq!(escalation.attempts_at_current_level(), 0);
    }

    #[test]
    fn test_recovery_escalation_failure_and_escalate() {
        let mut escalation = RecoveryEscalation::new(10); // 10ms backoff

        // Level 1: Time Resync - 3 attempts
        for i in 1..=3 {
            thread::sleep(Duration::from_millis(20)); // Wait for backoff
            escalation.start_recovery().unwrap();
            let escalated = escalation
                .complete_failure(format!("Attempt {} failed", i))
                .unwrap();

            if i < 3 {
                assert!(!escalated);
                assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
            } else {
                assert!(escalated);
                assert_eq!(escalation.current_level(), RecoveryLevel::SequenceRepair);
            }
        }

        // Now at Level 2: Sequence Repair
        assert_eq!(escalation.current_level(), RecoveryLevel::SequenceRepair);
        assert_eq!(escalation.attempts_at_current_level(), 0);
    }

    #[test]
    fn test_exponential_backoff() {
        let mut escalation = RecoveryEscalation::new(1000); // 1 second base

        // Attempt 1: 1 second
        escalation.attempts_at_level = 1;
        assert_eq!(escalation.calculate_backoff(), Duration::from_secs(1));

        // Attempt 2: 2 seconds
        escalation.attempts_at_level = 2;
        assert_eq!(escalation.calculate_backoff(), Duration::from_secs(2));

        // Attempt 3: 4 seconds
        escalation.attempts_at_level = 3;
        assert_eq!(escalation.calculate_backoff(), Duration::from_secs(4));

        // Very high attempt: capped at 30 seconds
        escalation.attempts_at_level = 10;
        assert_eq!(escalation.calculate_backoff(), Duration::from_secs(30));
    }

    #[test]
    fn test_permanent_failure() {
        let mut escalation = RecoveryEscalation::new(10);

        // Exhaust all levels
        let levels = [
            (RecoveryLevel::TimeResync, 3),
            (RecoveryLevel::SequenceRepair, 3),
            (RecoveryLevel::EcdhRekeying, 3),
            (RecoveryLevel::PortResync, 3),
            (RecoveryLevel::PskDiscovery, 2),
            (RecoveryLevel::ConnectionReset, 1),
        ];

        for (_level, max_attempts) in levels.iter() {
            for _ in 1..=*max_attempts {
                thread::sleep(Duration::from_millis(20));
                escalation.start_recovery().unwrap();
                escalation.complete_failure("Failed".to_string()).unwrap();
            }
        }

        // Should be permanently failed
        assert!(escalation.is_permanently_failed());
        assert_eq!(escalation.state(), RecoveryState::Failed);

        // Cannot start new recovery
        assert!(escalation.start_recovery().is_err());
    }
}
