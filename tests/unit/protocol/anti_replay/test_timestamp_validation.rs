use std::time::{Duration, SystemTime};
use buckwild_common::protocol::{TimestampValidator, EpochType, TimestampValidationResult};

#[test]
fn test_timestamp_validation_valid() {
    let validator = TimestampValidator::new();
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500; // Convert to 500ms buckets

    let result = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();

    assert_eq!(result, TimestampValidationResult::Valid);
}

#[test]
fn test_timestamp_validation_duplicate() {
    let validator = TimestampValidator::new();
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // First validation should succeed
    let result1 = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();
    assert_eq!(result1, TimestampValidationResult::Valid);

    // Second validation with same parameters should detect duplicate
    let result2 = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();
    assert_eq!(result2, TimestampValidationResult::Duplicate);
}

#[test]
fn test_timestamp_validation_too_old() {
    let validator = TimestampValidator::new();
    let old_time = SystemTime::now()
        .checked_sub(Duration::from_secs(60)) // 60 seconds ago
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let result = validator.validate_timestamp(
        old_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();

    assert_eq!(result, TimestampValidationResult::TooOld);
}

#[test]
fn test_timestamp_validation_too_future() {
    let validator = TimestampValidator::new();
    let future_time = SystemTime::now()
        .checked_add(Duration::from_secs(10)) // 10 seconds in future
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let result = validator.validate_timestamp(
        future_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();

    assert_eq!(result, TimestampValidationResult::TooFuture);
}

#[test]
fn test_clock_skew_validation() {
    let validator = TimestampValidator::new();
    
    // Small skew should be acceptable
    assert!(validator.validate_clock_skew(1000, 1005)); // 2.5 second difference
    
    // Large skew should be rejected
    assert!(!validator.validate_clock_skew(1000, 1020)); // 10 second difference
}

#[test]
fn test_dual_epoch_support() {
    let validator = TimestampValidator::new();
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Test daily epoch
    let result_daily = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();
    assert_eq!(result_daily, TimestampValidationResult::Valid);

    // Test monthly epoch with same timestamp but different session
    let result_monthly = validator.validate_timestamp(
        current_time,
        EpochType::Monthly,
        12346,
        1,
    ).unwrap();
    assert_eq!(result_monthly, TimestampValidationResult::Valid);
}

#[test]
fn test_cache_cleanup() {
    let validator = TimestampValidator::new();
    
    // Add some entries
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    for i in 0..10 {
        validator.validate_timestamp(
            current_time + i,
            EpochType::Daily,
            12345 + i,
            i as u32,
        ).unwrap();
    }

    let stats_before = validator.get_cache_stats();
    assert_eq!(stats_before.entry_count, 10);

    // Force cleanup - entries should still be there since they're not expired
    validator.cleanup_expired_entries().unwrap();
    
    let stats_after = validator.get_cache_stats();
    assert_eq!(stats_after.entry_count, 10);
}

#[test]
fn test_different_sessions_same_timestamp() {
    let validator = TimestampValidator::new();
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Same timestamp, different sessions should both be valid
    let result1 = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();
    assert_eq!(result1, TimestampValidationResult::Valid);

    let result2 = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        54321,
        1,
    ).unwrap();
    assert_eq!(result2, TimestampValidationResult::Valid);
}

#[test]
fn test_same_session_different_sequences() {
    let validator = TimestampValidator::new();
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Same session, different sequences should both be valid
    let result1 = validator.validate_timestamp(
        current_time,
        EpochType::Daily,
        12345,
        1,
    ).unwrap();
    assert_eq!(result1, TimestampValidationResult::Valid);

    let result2 = validator.validate_timestamp(
        current_time + 1,
        EpochType::Daily,
        12345,
        2,
    ).unwrap();
    assert_eq!(result2, TimestampValidationResult::Valid);
}

#[test]
fn test_cache_statistics() {
    let validator = TimestampValidator::new();
    
    let stats_empty = validator.get_cache_stats();
    assert_eq!(stats_empty.entry_count, 0);
    
    // Add some entries
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    for i in 0..5 {
        validator.validate_timestamp(
            current_time + i,
            EpochType::Daily,
            12345 + i,
            i as u32,
        ).unwrap();
    }

    let stats_filled = validator.get_cache_stats();
    assert_eq!(stats_filled.entry_count, 5);
    assert!(stats_filled.memory_usage_bytes > 0);
}