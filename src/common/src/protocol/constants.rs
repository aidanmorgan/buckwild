// Protocol constants defined in design/protocol specifications
//
// Reference: design/protocol/09-time-synchronization.md

/// Time synchronization precision requirement (milliseconds)
///
/// Defines the required synchronization precision between peers for coordinated
/// port hopping. Sync is considered successful if time offset is within this threshold.
///
/// Reference: design/protocol/09-time-synchronization.md §140
/// Spec value: TIME_SYNC_PRECISION_MS = 10
pub const TIME_SYNC_PRECISION_MS: u64 = 10;

/// Time synchronization precision in nanoseconds (derived)
pub const TIME_SYNC_PRECISION_NS: u64 = TIME_SYNC_PRECISION_MS * 1_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_sync_precision_constant_exists() {
        assert_eq!(TIME_SYNC_PRECISION_MS, 10);
    }

    #[test]
    fn test_time_sync_precision_correct_value() {
        assert_eq!(TIME_SYNC_PRECISION_MS, 10);
    }

    #[test]
    fn test_time_sync_precision_nanosecond_conversion() {
        assert_eq!(TIME_SYNC_PRECISION_NS, 10_000_000);
    }
}
