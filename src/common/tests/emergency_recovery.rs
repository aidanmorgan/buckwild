//! MED-030 Emergency Recovery Integration Tests
//!
//! Tests emergency recovery scenarios including catastrophic connection loss,
//! emergency reconnection paths, and recovery from complete network partition.
//!
//! Protocol Reference: design/protocol/12-recovery-mechanisms.md
//! - Recovery Escalation Levels (lines 34-65)
//! - Emergency Recovery (Level 4, lines 44)
//! - Connection Termination (Level 5, lines 45)
//! - Terminal Failure Handling (lines 802-858)

use std::time::Duration;
use tokio::time::sleep;

use buckwild_common::engines::recovery::escalation::{
    RecoveryEscalation, RecoveryLevel, RecoveryState,
};
use buckwild_common::error::EngineError;

// Test 1: Emergency recovery level escalation
// Tests that recovery escalates to emergency level after lower levels fail

#[tokio::test]
async fn test_emergency_level_escalation() {
    let mut escalation = RecoveryEscalation::new(10); // 10ms backoff for fast testing

    // Exhaust all lower levels to reach Emergency
    // Per protocol: TimeResync (3) → SequenceRepair (3) → EcdhRekeying (3) → PortResync (3)
    let lower_levels = vec![
        (RecoveryLevel::TimeResync, 3),
        (RecoveryLevel::SequenceRepair, 3),
        (RecoveryLevel::EcdhRekeying, 3),
        (RecoveryLevel::PortResync, 3),
    ];

    for (expected_level, max_attempts) in lower_levels {
        for _ in 0..max_attempts {
            sleep(Duration::from_millis(20)).await;
            let level = escalation.start_recovery().expect("start_recovery failed");
            assert_eq!(level, expected_level);
            escalation
                .complete_failure(format!("{:?} failed", expected_level))
                .expect("complete_failure failed");
        }
    }

    // Next recovery should be at PskDiscovery level (emergency path)
    sleep(Duration::from_millis(20)).await;
    let level = escalation.start_recovery().expect("start_recovery failed");
    assert_eq!(
        level,
        RecoveryLevel::PskDiscovery,
        "Should escalate to emergency level"
    );
}

// Test 2: Sudden disconnect recovery
// Simulates catastrophic connection loss requiring emergency recovery

#[tokio::test]
async fn test_sudden_disconnect_recovery() {
    let mut escalation = RecoveryEscalation::new(10);

    // Simulate immediate escalation to emergency by failing all lower levels quickly
    for _ in 0..12 {
        // 3 attempts each for 4 lower levels
        sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start_recovery failed");
        escalation
            .complete_failure("sudden disconnect".to_string())
            .expect("complete_failure failed");
    }

    // Should now be at emergency level (PskDiscovery)
    sleep(Duration::from_millis(20)).await;
    let level = escalation.start_recovery().expect("start_recovery failed");
    assert_eq!(
        level,
        RecoveryLevel::PskDiscovery,
        "Sudden disconnect should reach emergency recovery"
    );

    // Emergency recovery attempt
    let state_before = escalation.state();
    assert_eq!(state_before, RecoveryState::InProgress);

    // Simulate emergency recovery success
    escalation
        .complete_success()
        .expect("Emergency recovery should succeed");
    assert_eq!(
        escalation.state(),
        RecoveryState::Recovered,
        "Emergency recovery should restore connection"
    );
}

// Test 3: Network partition recovery
// Tests recovery from complete network partition where all communication fails

#[tokio::test]
async fn test_network_partition_recovery() {
    let mut escalation = RecoveryEscalation::new(10);

    // Simulate network partition by failing all recovery attempts
    // This will escalate through all levels to terminal failure
    let total_attempts = 3 + 3 + 3 + 3 + 2 + 1; // Per protocol escalation limits

    for _ in 0..total_attempts {
        sleep(Duration::from_millis(20)).await;
        let result = escalation.start_recovery();

        if result.is_ok() {
            escalation
                .complete_failure("network partition".to_string())
                .expect("complete_failure failed");
        } else {
            // Reached permanent failure state
            break;
        }
    }

    // After exhausting all recovery levels, should be in failed state
    assert!(
        escalation.is_permanently_failed(),
        "Complete network partition should result in permanent failure"
    );
    assert_eq!(escalation.state(), RecoveryState::Failed);

    // Verify cannot recover from permanent failure
    let result = escalation.start_recovery();
    assert!(
        result.is_err(),
        "Should not allow recovery from permanent failure"
    );
    assert!(matches!(result, Err(EngineError::PermanentFailure(_))));
}

// Test 4: Emergency recovery with partial success
// Tests emergency recovery succeeding after initial failures

#[tokio::test]
async fn test_emergency_recovery_partial_success() {
    let mut escalation = RecoveryEscalation::new(10);

    // Fast-forward to emergency level by exhausting lower levels
    for _ in 0..12 {
        sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start_recovery failed");
        escalation
            .complete_failure("forced escalation".to_string())
            .expect("complete_failure failed");
    }

    // At emergency level (PskDiscovery)
    sleep(Duration::from_millis(20)).await;
    let level = escalation.start_recovery().expect("start_recovery failed");
    assert_eq!(level, RecoveryLevel::PskDiscovery);

    // First emergency attempt fails
    escalation
        .complete_failure("emergency attempt 1 failed".to_string())
        .expect("complete_failure failed");

    // Second emergency attempt succeeds
    sleep(Duration::from_millis(20)).await;
    escalation.start_recovery().expect("start_recovery failed");
    escalation
        .complete_success()
        .expect("Emergency recovery should succeed");

    // Verify recovery succeeded and state reset
    assert_eq!(escalation.state(), RecoveryState::Recovered);
    assert_eq!(
        escalation.current_level(),
        RecoveryLevel::TimeResync,
        "Should reset to initial level after recovery"
    );
}

// Test 5: Multiple simultaneous failure conditions
// Tests handling when multiple failures occur, triggering emergency recovery

#[tokio::test]
async fn test_multiple_simultaneous_failures() {
    let mut escalation = RecoveryEscalation::new(10);

    // Simulate rapid failures indicating catastrophic issues
    // This represents: time drift + sequence errors + auth failures
    for failure_type in &["time drift", "sequence gap", "auth failure"] {
        sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start_recovery failed");
        escalation
            .complete_failure(failure_type.to_string())
            .expect("complete_failure failed");
    }

    // After 3 failures at TimeResync level, should escalate
    assert_eq!(
        escalation.current_level(),
        RecoveryLevel::SequenceRepair,
        "Multiple failures should trigger escalation"
    );

    // Continue failing to reach emergency
    for _ in 0..9 {
        // 9 more to reach emergency (3+3+3)
        sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start_recovery failed");
        escalation
            .complete_failure("ongoing failures".to_string())
            .expect("complete_failure failed");
    }

    sleep(Duration::from_millis(20)).await;
    let level = escalation.start_recovery().expect("start_recovery failed");
    assert_eq!(
        level,
        RecoveryLevel::PskDiscovery,
        "Cascading failures should reach emergency level"
    );
}

// Test 6: Recovery backoff enforcement during emergency
// Validates that backoff is enforced even during emergency recovery

#[tokio::test]
async fn test_emergency_recovery_backoff_enforcement() {
    let mut escalation = RecoveryEscalation::new(100); // 100ms backoff

    // Escalate to emergency level (wait for backoff before each attempt)
    for i in 0..12 {
        if i > 0 {
            sleep(Duration::from_millis(200)).await; // Wait for backoff
        }
        escalation.start_recovery().expect("start_recovery failed");
        escalation
            .complete_failure("escalate".to_string())
            .expect("complete_failure failed");
    }

    // At emergency level, fail an attempt
    sleep(Duration::from_millis(200)).await;
    escalation.start_recovery().expect("start_recovery failed");
    escalation
        .complete_failure("emergency failed".to_string())
        .expect("complete_failure failed");

    // Immediate retry should fail due to backoff
    let result = escalation.start_recovery();
    assert!(
        result.is_err(),
        "Should enforce backoff even at emergency level"
    );
    assert!(matches!(result, Err(EngineError::BackoffRequired(_))));

    // After backoff, should allow retry (exponential backoff may require longer wait)
    sleep(Duration::from_millis(1500)).await;
    let result = escalation.start_recovery();
    assert!(result.is_ok(), "Should allow retry after backoff period");
}

// Test 7: Emergency recovery state transitions
// Validates state machine transitions during emergency recovery

#[tokio::test]
async fn test_emergency_recovery_state_transitions() {
    let mut escalation = RecoveryEscalation::new(10);

    // Initial state
    assert_eq!(escalation.state(), RecoveryState::Normal);

    // Escalate to emergency
    for _ in 0..12 {
        sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start_recovery failed");
        assert_eq!(escalation.state(), RecoveryState::InProgress);

        escalation
            .complete_failure("escalate".to_string())
            .expect("complete_failure failed");
        assert_eq!(escalation.state(), RecoveryState::Normal);
    }

    // Start emergency recovery
    sleep(Duration::from_millis(20)).await;
    let level = escalation.start_recovery().expect("start_recovery failed");
    assert_eq!(level, RecoveryLevel::PskDiscovery);
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    // Successful emergency recovery
    escalation
        .complete_success()
        .expect("complete_success failed");
    assert_eq!(escalation.state(), RecoveryState::Recovered);

    // State should reset after successful recovery
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
}

// Test 8: Connection termination as final recovery step
// Tests terminal failure path when all recovery including emergency fails

#[tokio::test]
async fn test_connection_termination_after_emergency_failure() {
    let mut escalation = RecoveryEscalation::new(10);

    // Exhaust all recovery levels including emergency
    // Per protocol: TimeResync(3) + SequenceRepair(3) + EcdhRekeying(3) +
    //               PortResync(3) + PskDiscovery(2) + ConnectionReset(1) = 15 attempts
    for i in 0..15 {
        sleep(Duration::from_millis(20)).await;
        let result = escalation.start_recovery();

        if let Ok(level) = result {
            println!("Attempt {}: Level {:?}", i + 1, level);
            escalation
                .complete_failure(format!("attempt {} failed", i + 1))
                .expect("complete_failure failed");
        } else {
            // Reached permanent failure
            println!("Permanent failure at attempt {}", i + 1);
            break;
        }
    }

    // Should be in permanently failed state
    assert!(
        escalation.is_permanently_failed(),
        "Should reach permanent failure after exhausting all levels"
    );
    assert_eq!(escalation.state(), RecoveryState::Failed);

    // Cannot start new recovery
    let result = escalation.start_recovery();
    assert!(matches!(result, Err(EngineError::PermanentFailure(_))));
}
