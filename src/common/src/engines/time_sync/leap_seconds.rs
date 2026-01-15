// Leap second handling for accurate UTC offset calculations
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

/// Leap seconds table - UTC offset from TAI
/// Format: (Unix timestamp at which leap second was added, cumulative leap seconds)
/// Source: IERS Bulletin C - authoritative leap second announcements
/// Current through 2025-12-31 (no leap seconds announced beyond 2017-01-01)
pub const LEAP_SECONDS: &[(i64, i32)] = &[
    (63072000, 10),   // 1972-01-01
    (78796800, 11),   // 1972-07-01
    (94694400, 12),   // 1973-01-01
    (126230400, 13),  // 1974-01-01
    (157766400, 14),  // 1975-01-01
    (189302400, 15),  // 1976-01-01
    (220924800, 16),  // 1977-01-01
    (252460800, 17),  // 1978-01-01
    (283996800, 18),  // 1979-01-01
    (315532800, 19),  // 1980-01-01
    (362793600, 20),  // 1981-07-01
    (394329600, 21),  // 1982-07-01
    (425865600, 22),  // 1983-07-01
    (489024000, 23),  // 1985-07-01
    (567993600, 24),  // 1988-01-01
    (631152000, 25),  // 1990-01-01
    (662688000, 26),  // 1991-01-01
    (709948800, 27),  // 1992-07-01
    (741484800, 28),  // 1993-07-01
    (773020800, 29),  // 1994-07-01
    (820454400, 30),  // 1996-01-01
    (867715200, 31),  // 1997-07-01
    (915148800, 32),  // 1999-01-01
    (1136073600, 33), // 2006-01-01
    (1230768000, 34), // 2009-01-01
    (1341100800, 35), // 2012-07-01
    (1435708800, 36), // 2015-07-01
    (1483228800, 37), // 2017-01-01
];

/// Get the leap second offset for a given Unix timestamp
///
/// Returns the cumulative number of leap seconds that have been added
/// up to and including the given timestamp. This is the difference
/// between TAI (International Atomic Time) and UTC at that moment.
///
/// For timestamps before 1972-01-01, returns 10 (the initial offset).
/// For timestamps after the last known leap second, returns the current offset (37).
pub fn get_leap_seconds(unix_timestamp: i64) -> i32 {
    // Binary search for the most recent leap second at or before this timestamp
    let mut left = 0;
    let mut right = LEAP_SECONDS.len();

    while left < right {
        let mid = left + (right - left) / 2;
        if LEAP_SECONDS[mid].0 <= unix_timestamp {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    if left == 0 {
        // Before first leap second entry - return initial offset
        10
    } else {
        // Return the leap second count from the most recent entry
        LEAP_SECONDS[left - 1].1
    }
}

/// Check if a given timestamp is during a leap second
///
/// A leap second occurs at 23:59:60 UTC, which is represented as
/// unix_timestamp being exactly equal to the leap second insertion point.
/// Returns true if the timestamp is the exact second when a leap second was inserted.
pub fn is_leap_second(unix_timestamp: i64) -> bool {
    LEAP_SECONDS.iter().any(|(ts, _)| *ts == unix_timestamp)
}

/// Get the next scheduled leap second after a timestamp (if known)
///
/// Returns the Unix timestamp of the next leap second insertion after
/// the given timestamp, or None if no future leap seconds are known.
/// As of 2025, no leap seconds are scheduled beyond 2017-01-01.
pub fn next_leap_second_after(unix_timestamp: i64) -> Option<i64> {
    LEAP_SECONDS
        .iter()
        .find(|(ts, _)| *ts > unix_timestamp)
        .map(|(ts, _)| *ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_leap_seconds_before_1972() {
        // Before first leap second entry
        let ts = 0; // 1970-01-01
        assert_eq!(get_leap_seconds(ts), 10);
    }

    #[test]
    fn test_get_leap_seconds_at_exact_insertion() {
        // Exactly at 1972-01-01 leap second insertion
        assert_eq!(get_leap_seconds(63072000), 10);

        // Exactly at 1972-07-01 leap second insertion
        assert_eq!(get_leap_seconds(78796800), 11);
    }

    #[test]
    fn test_get_leap_seconds_between_insertions() {
        // Between 1972-01-01 and 1972-07-01
        let ts = 70000000;
        assert_eq!(get_leap_seconds(ts), 10);

        // Between 1972-07-01 and 1973-01-01
        let ts = 90000000;
        assert_eq!(get_leap_seconds(ts), 11);
    }

    #[test]
    fn test_get_leap_seconds_current() {
        // After most recent leap second (2017-01-01)
        let ts = 1600000000; // 2020-09-13
        assert_eq!(get_leap_seconds(ts), 37);

        // Far future timestamp
        let ts = 2000000000; // 2033-05-18
        assert_eq!(get_leap_seconds(ts), 37);
    }

    #[test]
    fn test_get_leap_seconds_all_entries() {
        // Verify each entry returns correct count
        for (i, &(ts, expected_count)) in LEAP_SECONDS.iter().enumerate() {
            assert_eq!(
                get_leap_seconds(ts),
                expected_count,
                "Entry {}: timestamp {} should have {} leap seconds",
                i,
                ts,
                expected_count
            );

            // One second after insertion should also have the new count
            assert_eq!(
                get_leap_seconds(ts + 1),
                expected_count,
                "Entry {}: timestamp {}+1 should have {} leap seconds",
                i,
                ts,
                expected_count
            );
        }
    }

    #[test]
    fn test_is_leap_second_true() {
        // Check exact leap second insertion points
        assert!(is_leap_second(63072000)); // 1972-01-01
        assert!(is_leap_second(78796800)); // 1972-07-01
        assert!(is_leap_second(1483228800)); // 2017-01-01 (most recent)
    }

    #[test]
    fn test_is_leap_second_false() {
        // One second before/after are not leap seconds
        assert!(!is_leap_second(63072000 - 1));
        assert!(!is_leap_second(63072000 + 1));

        // Random timestamps
        assert!(!is_leap_second(0));
        assert!(!is_leap_second(1600000000));
    }

    #[test]
    fn test_next_leap_second_after_found() {
        // Before first leap second
        assert_eq!(next_leap_second_after(0), Some(63072000));

        // Between two leap seconds
        assert_eq!(next_leap_second_after(70000000), Some(78796800));

        // Just before last leap second
        assert_eq!(next_leap_second_after(1483228799), Some(1483228800));
    }

    #[test]
    fn test_next_leap_second_after_none() {
        // After the last known leap second
        assert_eq!(next_leap_second_after(1483228800), None);
        assert_eq!(next_leap_second_after(1600000000), None);
        assert_eq!(next_leap_second_after(2000000000), None);
    }

    #[test]
    fn test_leap_second_table_ordering() {
        // Verify table is sorted by timestamp
        for i in 1..LEAP_SECONDS.len() {
            assert!(
                LEAP_SECONDS[i].0 > LEAP_SECONDS[i - 1].0,
                "Leap second table not sorted at index {}",
                i
            );
        }
    }

    #[test]
    fn test_leap_second_table_incremental() {
        // Verify leap second counts increment by 1
        for i in 1..LEAP_SECONDS.len() {
            assert_eq!(
                LEAP_SECONDS[i].1,
                LEAP_SECONDS[i - 1].1 + 1,
                "Leap second count not incremental at index {}",
                i
            );
        }
    }

    #[test]
    fn test_leap_second_initial_offset() {
        // First entry should be 10 (TAI-UTC offset at 1972-01-01)
        assert_eq!(LEAP_SECONDS[0].1, 10);
    }

    #[test]
    fn test_leap_second_current_offset() {
        // Most recent entry should be 37 (as of 2017-01-01)
        let last_idx = LEAP_SECONDS.len() - 1;
        assert_eq!(LEAP_SECONDS[last_idx].1, 37);
    }
}
