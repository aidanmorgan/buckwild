#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Recovery Engine Tests
//
// Tests verify recovery level escalation, criticality checks, and timeouts
// following design/protocol/12-recovery-mechanisms.md

use super::engine::{RecoveryLevel, RecoveryResult};

// =============================================================================
// Recovery Level Tests
// =============================================================================

#[test]
fn test_recovery_level_escalation() {
    assert_eq!(RecoveryLevel::None.escalate(), RecoveryLevel::TimeSync);
    assert_eq!(
        RecoveryLevel::TimeSync.escalate(),
        RecoveryLevel::SessionRekey
    );
    assert_eq!(
        RecoveryLevel::SessionRekey.escalate(),
        RecoveryLevel::SequenceRepair
    );
    assert_eq!(
        RecoveryLevel::SequenceRepair.escalate(),
        RecoveryLevel::Emergency
    );
    assert_eq!(
        RecoveryLevel::Emergency.escalate(),
        RecoveryLevel::ConnectionTerminate
    );
    assert_eq!(
        RecoveryLevel::ConnectionTerminate.escalate(),
        RecoveryLevel::Failed
    );
    assert_eq!(RecoveryLevel::Failed.escalate(), RecoveryLevel::Failed); // Stay at Failed
}

#[test]
fn test_recovery_level_criticality() {
    assert!(!RecoveryLevel::None.is_critical());
    assert!(!RecoveryLevel::TimeSync.is_critical());
    assert!(!RecoveryLevel::SequenceRepair.is_critical());
    assert!(!RecoveryLevel::SessionRekey.is_critical());
    assert!(RecoveryLevel::Emergency.is_critical());
    assert!(RecoveryLevel::ConnectionTerminate.is_critical());
    assert!(RecoveryLevel::Failed.is_critical());
}

#[test]
fn test_recovery_level_timeouts() {
    assert_eq!(RecoveryLevel::None.timeout_ms().as_millis(), 0);
    assert_eq!(RecoveryLevel::TimeSync.timeout_ms().as_millis(), 10000);
    assert_eq!(
        RecoveryLevel::SequenceRepair.timeout_ms().as_millis(),
        15000
    );
    assert_eq!(RecoveryLevel::SessionRekey.timeout_ms().as_millis(), 20000);
    assert_eq!(RecoveryLevel::Emergency.timeout_ms().as_millis(), 30000);
    assert_eq!(
        RecoveryLevel::ConnectionTerminate.timeout_ms().as_millis(),
        5000
    );
    assert_eq!(RecoveryLevel::Failed.timeout_ms().as_millis(), 0);
}

#[test]
fn test_recovery_level_ordering() {
    assert!(RecoveryLevel::None < RecoveryLevel::TimeSync);
    assert!(RecoveryLevel::TimeSync < RecoveryLevel::SessionRekey);
    assert!(RecoveryLevel::SessionRekey < RecoveryLevel::SequenceRepair);
    assert!(RecoveryLevel::SequenceRepair < RecoveryLevel::Emergency);
    assert!(RecoveryLevel::Emergency < RecoveryLevel::ConnectionTerminate);
    assert!(RecoveryLevel::ConnectionTerminate < RecoveryLevel::Failed);
}

#[test]
fn test_recovery_level_full_escalation_chain() {
    let mut level = RecoveryLevel::None;
    let expected_chain = vec![
        RecoveryLevel::TimeSync,
        RecoveryLevel::SessionRekey,
        RecoveryLevel::SequenceRepair,
        RecoveryLevel::Emergency,
        RecoveryLevel::ConnectionTerminate,
        RecoveryLevel::Failed,
    ];

    for expected in expected_chain {
        level = level.escalate();
        assert_eq!(level, expected);
    }

    // Further escalation should stay at Failed
    level = level.escalate();
    assert_eq!(level, RecoveryLevel::Failed);
}

// =============================================================================
// Recovery Result Tests
// =============================================================================

#[test]
fn test_recovery_result_equality() {
    assert_eq!(RecoveryResult::Success, RecoveryResult::Success);
    assert_eq!(RecoveryResult::Timeout, RecoveryResult::Timeout);
    assert_eq!(RecoveryResult::InvalidNonce, RecoveryResult::InvalidNonce);
    assert_eq!(RecoveryResult::InvalidKey, RecoveryResult::InvalidKey);
    assert_eq!(
        RecoveryResult::SharedSecretMismatch,
        RecoveryResult::SharedSecretMismatch
    );
    assert_eq!(
        RecoveryResult::VerificationFailed,
        RecoveryResult::VerificationFailed
    );
    assert_eq!(RecoveryResult::NetworkError, RecoveryResult::NetworkError);
    assert_eq!(RecoveryResult::CryptoError, RecoveryResult::CryptoError);
    assert_eq!(RecoveryResult::Failed, RecoveryResult::Failed);
}

#[test]
fn test_recovery_result_inequality() {
    assert_ne!(RecoveryResult::Success, RecoveryResult::Failed);
    assert_ne!(RecoveryResult::Timeout, RecoveryResult::Success);
    assert_ne!(RecoveryResult::InvalidNonce, RecoveryResult::InvalidKey);
}

// =============================================================================
// Recovery Strategy Initialization Tests
// =============================================================================

#[test]
fn test_recovery_strategies_initialization() {
    use super::strategies::RecoveryStrategies;

    let _strategies = RecoveryStrategies::new();
    // Should not panic during initialization
}

#[test]
fn test_recovery_coordination_initialization() {
    use super::coordination::RecoveryCoordination;

    let coordination = RecoveryCoordination::new();
    // Should not panic during initialization
    drop(coordination);
}

// =============================================================================
// Recovery Level Timeout Progression Tests
// =============================================================================

#[test]
fn test_recovery_timeouts_increase_with_escalation() {
    // Timeouts should generally increase as escalation proceeds
    // (except ConnectionTerminate which is a quick final attempt)
    let none_timeout = RecoveryLevel::None.timeout_ms().as_millis();
    let time_sync_timeout = RecoveryLevel::TimeSync.timeout_ms().as_millis();
    let sequence_repair_timeout = RecoveryLevel::SequenceRepair.timeout_ms().as_millis();
    let session_rekey_timeout = RecoveryLevel::SessionRekey.timeout_ms().as_millis();
    let emergency_timeout = RecoveryLevel::Emergency.timeout_ms().as_millis();

    assert!(none_timeout < time_sync_timeout);
    assert!(time_sync_timeout < sequence_repair_timeout);
    assert!(sequence_repair_timeout < session_rekey_timeout);
    assert!(session_rekey_timeout < emergency_timeout);
}

#[test]
fn test_critical_levels_have_appropriate_timeouts() {
    // Emergency should have longest timeout (30s)
    assert_eq!(RecoveryLevel::Emergency.timeout_ms().as_millis(), 30000);

    // ConnectionTerminate should have short timeout (5s) for quick termination
    assert_eq!(
        RecoveryLevel::ConnectionTerminate.timeout_ms().as_millis(),
        5000
    );

    // Failed should have no timeout
    assert_eq!(RecoveryLevel::Failed.timeout_ms().as_millis(), 0);
}

// =============================================================================
// Recovery Level Edge Case Tests
// =============================================================================

#[test]
fn test_none_level_properties() {
    let level = RecoveryLevel::None;
    assert!(!level.is_critical());
    assert_eq!(level.timeout_ms().as_millis(), 0);
    assert_eq!(level.escalate(), RecoveryLevel::TimeSync);
}

#[test]
fn test_failed_level_properties() {
    let level = RecoveryLevel::Failed;
    assert!(level.is_critical());
    assert_eq!(level.timeout_ms().as_millis(), 0);
    assert_eq!(level.escalate(), RecoveryLevel::Failed); // Should not escalate further
}

#[test]
fn test_all_non_critical_levels() {
    let non_critical = vec![
        RecoveryLevel::None,
        RecoveryLevel::TimeSync,
        RecoveryLevel::SequenceRepair,
        RecoveryLevel::SessionRekey,
    ];

    for level in non_critical {
        assert!(!level.is_critical(), "{:?} should not be critical", level);
    }
}

#[test]
fn test_all_critical_levels() {
    let critical = vec![
        RecoveryLevel::Emergency,
        RecoveryLevel::ConnectionTerminate,
        RecoveryLevel::Failed,
    ];

    for level in critical {
        assert!(level.is_critical(), "{:?} should be critical", level);
    }
}
