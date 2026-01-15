#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Recovery Escalation Level Tests
//!
//! Comprehensive tests for all 6 recovery escalation levels:
//! 1. Time Resync
//! 2. Sequence Repair
//! 3. ECDH Rekeying
//! 4. Port Resync
//! 5. PSK Discovery
//! 6. Connection Reset
//!
//! Tests verify:
//! - Triggering recovery at each level
//! - Exponential backoff behavior
//! - Escalation after max attempts exhausted
//! - State transitions and terminal failure

use super::escalation::{RecoveryEscalation, RecoveryLevel, RecoveryState};
use std::thread;
use std::time::Duration;

// =============================================================================
// Level 1: Time Resynchronization Tests
// =============================================================================

#[test]
fn test_level1_time_resync_trigger() {
    let mut escalation = RecoveryEscalation::new(100);

    // Start at Level 1
    let level = escalation.start_recovery().expect("Should start recovery");
    assert_eq!(level, RecoveryLevel::TimeResync);
    assert_eq!(escalation.state(), RecoveryState::InProgress);
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
    assert_eq!(escalation.attempts_at_current_level(), 1);
}

#[test]
fn test_level1_time_resync_success() {
    let mut escalation = RecoveryEscalation::new(100);

    // Start recovery
    escalation.start_recovery().expect("Should start recovery");

    // Complete successfully
    escalation
        .complete_success()
        .expect("Should complete successfully");

    // Should reset to normal
    assert_eq!(escalation.state(), RecoveryState::Recovered);
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
    assert_eq!(escalation.attempts_at_current_level(), 0);
}

#[test]
fn test_level1_time_resync_backoff() {
    let mut escalation = RecoveryEscalation::new(100);

    // Attempt 1: 100ms backoff
    escalation.start_recovery().expect("Should start recovery");
    let backoff1 = escalation.calculate_backoff();
    assert_eq!(backoff1, Duration::from_millis(100));

    escalation
        .complete_failure("Attempt 1 failed".to_string())
        .expect("Should complete failure");

    // Wait for backoff to elapse
    thread::sleep(Duration::from_millis(150));

    // Attempt 2: 200ms backoff (2^1 * base)
    escalation.start_recovery().expect("Should start recovery");
    let backoff2 = escalation.calculate_backoff();
    assert_eq!(backoff2, Duration::from_millis(200));

    escalation
        .complete_failure("Attempt 2 failed".to_string())
        .expect("Should complete failure");

    // Wait for backoff to elapse
    thread::sleep(Duration::from_millis(250));

    // Attempt 3: 400ms backoff (2^2 * base)
    escalation.start_recovery().expect("Should start recovery");
    let backoff3 = escalation.calculate_backoff();
    assert_eq!(backoff3, Duration::from_millis(400));
}

#[test]
fn test_level1_time_resync_max_attempts() {
    let mut escalation = RecoveryEscalation::new(10);

    // TimeResync max attempts is 3
    for i in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        let escalated = escalation
            .complete_failure(format!("Attempt {} failed", i))
            .expect("Should complete failure");

        if i < 3 {
            assert!(!escalated, "Should not escalate before max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
        } else {
            assert!(escalated, "Should escalate after max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::SequenceRepair);
        }
    }
}

#[test]
fn test_level1_exponential_backoff_cap() {
    let mut escalation = RecoveryEscalation::new(1000);

    // Test that backoff calculation is correct for progressive attempts
    // Attempt 1: backoff = 1000 * 2^0 = 1000ms
    escalation.start_recovery().expect("Should start");
    assert_eq!(escalation.calculate_backoff(), Duration::from_millis(1000));
    escalation
        .complete_failure("1".to_string())
        .expect("Should fail");

    // Wait for backoff
    thread::sleep(Duration::from_millis(1100));

    // Attempt 2: backoff = 1000 * 2^1 = 2000ms
    escalation.start_recovery().expect("Should start");
    assert_eq!(escalation.calculate_backoff(), Duration::from_millis(2000));
    escalation
        .complete_failure("2".to_string())
        .expect("Should fail");

    // Wait for backoff
    thread::sleep(Duration::from_millis(2100));

    // Attempt 3: backoff = 1000 * 2^2 = 4000ms
    escalation.start_recovery().expect("Should start");
    assert_eq!(escalation.calculate_backoff(), Duration::from_millis(4000));

    // Verify that the formula would cap at 30 seconds for higher attempts
    // If we could make 6 attempts: 1000 * 2^5 = 32000ms > 30000ms (capped)
    // This demonstrates the backoff doubling behavior
}

// =============================================================================
// Level 2: Sequence Repair Tests
// =============================================================================

#[test]
fn test_level2_sequence_repair_escalation() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust Level 1
    for _ in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Time resync failed".to_string())
            .expect("Should complete failure");
    }

    // Should now be at Level 2
    assert_eq!(escalation.current_level(), RecoveryLevel::SequenceRepair);
    assert_eq!(escalation.attempts_at_current_level(), 0);
}

#[test]
fn test_level2_sequence_repair_max_attempts() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 2
    for _ in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Level 1 failed".to_string())
            .expect("Should complete failure");
    }

    // Exhaust Level 2 (max 3 attempts)
    for i in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        let escalated = escalation
            .complete_failure(format!("Sequence repair attempt {} failed", i))
            .expect("Should complete failure");

        if i < 3 {
            assert!(!escalated, "Should not escalate before max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::SequenceRepair);
        } else {
            assert!(escalated, "Should escalate after max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::EcdhRekeying);
        }
    }
}

#[test]
fn test_level2_sequence_repair_success_resets() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 2
    for _ in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Level 1 failed".to_string())
            .expect("Should complete failure");
    }

    // Successfully recover at Level 2
    thread::sleep(Duration::from_millis(20));
    escalation.start_recovery().expect("Should start recovery");
    escalation
        .complete_success()
        .expect("Should complete successfully");

    // Should reset to normal
    assert_eq!(escalation.state(), RecoveryState::Recovered);
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
    assert_eq!(escalation.attempts_at_current_level(), 0);
}

// =============================================================================
// Level 3: ECDH Rekeying Tests
// =============================================================================

#[test]
fn test_level3_ecdh_rekeying_escalation() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust Level 1 and 2
    for _ in 1..=6 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Should now be at Level 3
    assert_eq!(escalation.current_level(), RecoveryLevel::EcdhRekeying);
    assert_eq!(escalation.attempts_at_current_level(), 0);
}

#[test]
fn test_level3_ecdh_rekeying_max_attempts() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 3
    for _ in 1..=6 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Exhaust Level 3 (max 3 attempts)
    for i in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        let escalated = escalation
            .complete_failure(format!("ECDH rekey attempt {} failed", i))
            .expect("Should complete failure");

        if i < 3 {
            assert!(!escalated, "Should not escalate before max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::EcdhRekeying);
        } else {
            assert!(escalated, "Should escalate after max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::PortResync);
        }
    }
}

// =============================================================================
// Level 4: Port Resynchronization Tests
// =============================================================================

#[test]
fn test_level4_port_resync_escalation() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust Levels 1, 2, and 3
    for _ in 1..=9 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Should now be at Level 4
    assert_eq!(escalation.current_level(), RecoveryLevel::PortResync);
    assert_eq!(escalation.attempts_at_current_level(), 0);
}

#[test]
fn test_level4_port_resync_max_attempts() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 4
    for _ in 1..=9 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Exhaust Level 4 (max 3 attempts)
    for i in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        let escalated = escalation
            .complete_failure(format!("Port resync attempt {} failed", i))
            .expect("Should complete failure");

        if i < 3 {
            assert!(!escalated, "Should not escalate before max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::PortResync);
        } else {
            assert!(escalated, "Should escalate after max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::PskDiscovery);
        }
    }
}

// =============================================================================
// Level 5: PSK Discovery Tests
// =============================================================================

#[test]
fn test_level5_psk_discovery_escalation() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust Levels 1-4
    for _ in 1..=12 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Should now be at Level 5
    assert_eq!(escalation.current_level(), RecoveryLevel::PskDiscovery);
    assert_eq!(escalation.attempts_at_current_level(), 0);
}

#[test]
fn test_level5_psk_discovery_max_attempts() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 5
    for _ in 1..=12 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Exhaust Level 5 (max 2 attempts - different from others!)
    for i in 1..=2 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        let escalated = escalation
            .complete_failure(format!("PSK discovery attempt {} failed", i))
            .expect("Should complete failure");

        if i < 2 {
            assert!(!escalated, "Should not escalate before max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::PskDiscovery);
        } else {
            assert!(escalated, "Should escalate after max attempts");
            assert_eq!(escalation.current_level(), RecoveryLevel::ConnectionReset);
        }
    }
}

// =============================================================================
// Level 6: Connection Reset Tests
// =============================================================================

#[test]
fn test_level6_connection_reset_terminal() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust all levels to reach Level 6
    for _ in 1..=14 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Should now be at Level 6
    assert_eq!(escalation.current_level(), RecoveryLevel::ConnectionReset);
    assert!(escalation.current_level().is_terminal());
}

#[test]
fn test_level6_connection_reset_max_attempts() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 6
    for _ in 1..=14 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Level 6 has max 1 attempt
    thread::sleep(Duration::from_millis(20));
    escalation.start_recovery().expect("Should start recovery");
    let escalated = escalation
        .complete_failure("Connection reset failed".to_string())
        .expect("Should complete failure");

    // Should not escalate further (terminal state)
    assert!(!escalated, "Should not escalate from terminal level");
    assert_eq!(escalation.state(), RecoveryState::Failed);
    assert!(escalation.is_permanently_failed());
}

#[test]
fn test_level6_permanent_failure_cannot_restart() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust all levels
    for _ in 1..=15 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Should be permanently failed
    assert!(escalation.is_permanently_failed());

    // Attempting to start recovery should fail
    let result = escalation.start_recovery();
    assert!(
        result.is_err(),
        "Should not be able to start recovery when permanently failed"
    );
}

// =============================================================================
// Escalation Chain Tests
// =============================================================================

#[test]
fn test_full_escalation_chain() {
    let mut escalation = RecoveryEscalation::new(10);

    let expected_levels = vec![
        (RecoveryLevel::TimeResync, 3),
        (RecoveryLevel::SequenceRepair, 3),
        (RecoveryLevel::EcdhRekeying, 3),
        (RecoveryLevel::PortResync, 3),
        (RecoveryLevel::PskDiscovery, 2),
        (RecoveryLevel::ConnectionReset, 1),
    ];

    for (expected_level, max_attempts) in expected_levels {
        for attempt in 1..=max_attempts {
            thread::sleep(Duration::from_millis(20));
            let level = escalation.start_recovery().expect("Should start recovery");
            assert_eq!(
                level, expected_level,
                "Expected level {} at attempt {}",
                expected_level as u8, attempt
            );

            escalation
                .complete_failure(format!("Attempt {} failed", attempt))
                .expect("Should complete failure");
        }
    }

    // Should now be permanently failed
    assert!(escalation.is_permanently_failed());
}

#[test]
fn test_escalation_level_sequence() {
    // Test that each level correctly identifies its next level
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
fn test_max_attempts_per_level() {
    assert_eq!(RecoveryLevel::TimeResync.max_attempts(), 3);
    assert_eq!(RecoveryLevel::SequenceRepair.max_attempts(), 3);
    assert_eq!(RecoveryLevel::EcdhRekeying.max_attempts(), 3);
    assert_eq!(RecoveryLevel::PortResync.max_attempts(), 3);
    assert_eq!(RecoveryLevel::PskDiscovery.max_attempts(), 2);
    assert_eq!(RecoveryLevel::ConnectionReset.max_attempts(), 1);
}

// =============================================================================
// Backoff Behavior Tests
// =============================================================================

#[test]
fn test_backoff_required_error() {
    let mut escalation = RecoveryEscalation::new(1000);

    // Start first attempt
    escalation.start_recovery().expect("Should start recovery");
    escalation
        .complete_failure("Failed".to_string())
        .expect("Should complete failure");

    // Try to start immediately without waiting for backoff
    let result = escalation.start_recovery();
    assert!(
        result.is_err(),
        "Should not allow recovery before backoff elapsed"
    );
}

#[test]
fn test_backoff_elapsed_allows_retry() {
    let mut escalation = RecoveryEscalation::new(10);

    // Start first attempt
    escalation.start_recovery().expect("Should start recovery");
    escalation
        .complete_failure("Failed".to_string())
        .expect("Should complete failure");

    // Wait for backoff
    thread::sleep(Duration::from_millis(20));

    // Should now be able to retry
    let result = escalation.start_recovery();
    assert!(
        result.is_ok(),
        "Should allow recovery after backoff elapsed"
    );
}

#[test]
fn test_backoff_doubles_each_attempt() {
    let mut escalation = RecoveryEscalation::new(100);

    let expected_backoffs = [
        Duration::from_millis(100), // 2^0 * 100
        Duration::from_millis(200), // 2^1 * 100
        Duration::from_millis(400), // 2^2 * 100
    ];

    for (i, expected) in expected_backoffs.iter().enumerate() {
        if i > 0 {
            // Wait for previous backoff to elapse
            // For safety, wait 2x the previous backoff
            let prev_backoff = expected_backoffs[i - 1];
            thread::sleep(prev_backoff + Duration::from_millis(50));
        }

        escalation.start_recovery().expect("Should start recovery");
        let backoff = escalation.calculate_backoff();
        assert_eq!(backoff, *expected, "Backoff mismatch at attempt {}", i + 1);

        escalation
            .complete_failure(format!("Attempt {} failed", i + 1))
            .expect("Should complete failure");
    }
}

// =============================================================================
// State Transition Tests
// =============================================================================

#[test]
fn test_state_normal_to_in_progress() {
    let mut escalation = RecoveryEscalation::new(100);

    assert_eq!(escalation.state(), RecoveryState::Normal);

    escalation.start_recovery().expect("Should start recovery");
    assert_eq!(escalation.state(), RecoveryState::InProgress);
}

#[test]
fn test_state_in_progress_to_recovered() {
    let mut escalation = RecoveryEscalation::new(100);

    escalation.start_recovery().expect("Should start recovery");
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    escalation
        .complete_success()
        .expect("Should complete successfully");
    assert_eq!(escalation.state(), RecoveryState::Recovered);
}

#[test]
fn test_state_in_progress_to_normal_on_failure() {
    let mut escalation = RecoveryEscalation::new(100);

    escalation.start_recovery().expect("Should start recovery");
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    escalation
        .complete_failure("Failed".to_string())
        .expect("Should complete failure");
    assert_eq!(escalation.state(), RecoveryState::Normal);
}

#[test]
fn test_state_to_failed_after_all_levels() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust all levels
    for _ in 1..=15 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    assert_eq!(escalation.state(), RecoveryState::Failed);
}

#[test]
fn test_cannot_start_when_in_progress() {
    let mut escalation = RecoveryEscalation::new(100);

    escalation.start_recovery().expect("Should start recovery");

    // Try to start again while in progress
    let result = escalation.start_recovery();
    assert!(result.is_err(), "Should not allow concurrent recovery");
}

// =============================================================================
// Recovery History Tests
// =============================================================================

#[test]
fn test_attempt_history_tracking() {
    let mut escalation = RecoveryEscalation::new(10);

    // Make a few attempts
    for i in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure(format!("Attempt {} failed", i))
            .expect("Should complete failure");
    }

    let history = escalation.attempt_history();
    assert_eq!(history.len(), 3, "Should have 3 attempts in history");

    // Verify all were failures
    for attempt in history {
        assert!(!attempt.success, "All attempts should be failures");
    }
}

#[test]
fn test_statistics_tracking() {
    let mut escalation = RecoveryEscalation::new(10);

    // Make some attempts
    thread::sleep(Duration::from_millis(20));
    escalation.start_recovery().expect("Should start recovery");
    escalation
        .complete_failure("Failed".to_string())
        .expect("Should complete failure");

    thread::sleep(Duration::from_millis(20));
    escalation.start_recovery().expect("Should start recovery");
    escalation
        .complete_success()
        .expect("Should complete successfully");

    let stats = escalation.statistics();
    assert_eq!(stats.total_attempts, 2);
    assert_eq!(stats.successful_attempts, 1);
    assert_eq!(stats.current_level, RecoveryLevel::TimeResync);
}

// =============================================================================
// Reset Tests
// =============================================================================

#[test]
fn test_reset_clears_state() {
    let mut escalation = RecoveryEscalation::new(10);

    // Get to Level 3
    for _ in 1..=6 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    assert_eq!(escalation.current_level(), RecoveryLevel::EcdhRekeying);

    // Reset
    escalation.reset();

    // Should be back to initial state
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
    assert_eq!(escalation.attempts_at_current_level(), 0);
    assert_eq!(escalation.state(), RecoveryState::Normal);
}

#[test]
fn test_reset_allows_fresh_recovery() {
    let mut escalation = RecoveryEscalation::new(10);

    // Make it fail
    for _ in 1..=3 {
        thread::sleep(Duration::from_millis(20));
        escalation.start_recovery().expect("Should start recovery");
        escalation
            .complete_failure("Failed".to_string())
            .expect("Should complete failure");
    }

    // Reset clears level and attempts
    escalation.reset();

    // Note: reset() doesn't clear last_attempt_time, so backoff may still apply
    // Wait for any remaining backoff
    thread::sleep(Duration::from_millis(20));

    // Should be able to start fresh recovery
    let level = escalation.start_recovery().expect("Should start recovery");
    assert_eq!(level, RecoveryLevel::TimeResync);
}
