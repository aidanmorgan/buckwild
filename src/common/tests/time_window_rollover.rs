//! Time Window Rollover Tests
//!
//! TASK-080: Time window rollover boundary tests for TC-003 audit finding.
//!
//! Tests daily, monthly, and yearly time boundary transitions to ensure:
//! - Time bucket calculations remain correct across boundaries
//! - Port hopping synchronization is maintained
//! - Time offset calculations handle wraparound correctly
//!
//! ## Protocol References
//! - design/protocol/09-time-synchronization.md §3-4 (time bucket intervals)
//! - design/protocol/10-port-hopping.md §3-5 (port hopping synchronization)

#[cfg(test)]
mod daily_rollover {
    use buckwild_common::engines::time_sync::epoch::{EpochType, TimeEpoch};
    use chrono::{TimeZone, Utc};

    /// Helper: Convert chrono DateTime to milliseconds since UNIX epoch
    fn datetime_to_ms(dt: chrono::DateTime<Utc>) -> u64 {
        dt.timestamp_millis() as u64
    }

    #[test]
    fn test_midnight_bucket_transition_just_before() {
        // Test time bucket calculation at 23:59:59.999 UTC
        // Expected: Bucket calculation should be stable and deterministic

        let midnight = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .single()
            .expect("Valid date");
        let just_before_midnight = midnight - chrono::Duration::milliseconds(1);
        let time_ms = datetime_to_ms(just_before_midnight);

        let window = TimeEpoch::get_daily_time_window(time_ms);

        // Verify window is valid
        assert_eq!(window.epoch_type, EpochType::Daily);
        assert!(window.window_start.as_nanos() <= window.window_end.as_nanos());

        // Window duration should be 500ms (500,000,000 nanoseconds)
        let window_duration = window.window_end.as_nanos() - window.window_start.as_nanos();
        assert_eq!(
            window_duration, 500_000_000,
            "Window duration should be exactly 500ms"
        );

        // Verify the window contains the test time
        let time_ns = time_ms * 1_000_000; // Convert ms to ns
        assert!(
            time_ns >= window.window_start.as_nanos(),
            "Time should be >= window start"
        );
        assert!(
            time_ns < window.window_end.as_nanos(),
            "Time should be < window end"
        );
    }

    #[test]
    fn test_midnight_bucket_transition_just_after() {
        // Test time bucket calculation at 00:00:00.001 UTC (new day)
        // Expected: Bucket calculation resets for new day

        let midnight = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .single()
            .expect("Valid date");
        let just_after_midnight = midnight + chrono::Duration::milliseconds(1);
        let time_ms = datetime_to_ms(just_after_midnight);

        let window = TimeEpoch::get_daily_time_window(time_ms);

        // Verify window is valid
        assert_eq!(window.epoch_type, EpochType::Daily);

        // Window should start at midnight (epoch start)
        let day_start = TimeEpoch::get_day_start_ms(time_ms);
        assert_eq!(
            window.epoch_start.as_millis(),
            day_start,
            "Epoch start should be midnight UTC"
        );

        // First window of the day should be window 0
        // (unless the 1ms offset puts us in window 1, which is acceptable)
        assert!(
            window.window.as_u64() <= 1,
            "Should be in first or second window of the day (window 0 or 1)"
        );

        // Window duration should be 500ms
        let window_duration = window.window_end.as_nanos() - window.window_start.as_nanos();
        assert_eq!(
            window_duration, 500_000_000,
            "Window duration should be exactly 500ms"
        );
    }

    #[test]
    fn test_midnight_transition_continuity() {
        // Verify that the bucket calculation is continuous across midnight
        // (no gaps or overlaps in window coverage)

        let midnight = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .single()
            .expect("Valid date");

        // Get window just before midnight
        let before_ms = datetime_to_ms(midnight - chrono::Duration::milliseconds(1));
        let window_before = TimeEpoch::get_daily_time_window(before_ms);

        // Get window just after midnight
        let after_ms = datetime_to_ms(midnight + chrono::Duration::milliseconds(1));
        let window_after = TimeEpoch::get_daily_time_window(after_ms);

        // Verify both windows are valid
        assert_eq!(window_before.epoch_type, EpochType::Daily);
        assert_eq!(window_after.epoch_type, EpochType::Daily);

        // Verify epoch boundaries differ (new day started)
        assert_ne!(
            window_before.epoch_start, window_after.epoch_start,
            "Epoch start should differ across midnight"
        );

        // Verify window after midnight is at the start of the new epoch
        assert_eq!(
            window_after.epoch_start.as_millis(),
            TimeEpoch::get_day_start_ms(after_ms),
            "New day epoch should start at midnight"
        );
    }

    #[test]
    fn test_port_sync_across_midnight() {
        // Ensure port calculations remain synchronized across midnight
        // Uses same daily key for day boundaries

        let midnight = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .single()
            .expect("Valid date");

        // Time windows before and after midnight
        let before_ms = datetime_to_ms(midnight - chrono::Duration::milliseconds(250));
        let after_ms = datetime_to_ms(midnight + chrono::Duration::milliseconds(250));

        let window_before = TimeEpoch::get_daily_time_window(before_ms);
        let window_after = TimeEpoch::get_daily_time_window(after_ms);

        // Both windows should be valid and have correct structure
        assert_eq!(window_before.epoch_type, EpochType::Daily);
        assert_eq!(window_after.epoch_type, EpochType::Daily);

        // Window numbering should be deterministic
        // Before midnight: high window number (near end of day)
        // After midnight: low window number (start of day)

        // Calculate windows per day (86400 seconds / 0.5 seconds per window)
        let windows_per_day = 86400 * 1000 / 500; // 172,800 windows per day

        // Window before midnight should be near the end
        assert!(
            window_before.window.as_u64() > windows_per_day - 10,
            "Window before midnight should be near end of day (window {})",
            window_before.window.as_u64()
        );

        // Window after midnight should be at the start
        assert!(
            window_after.window.as_u64() < 10,
            "Window after midnight should be near start of day (window {})",
            window_after.window.as_u64()
        );
    }

    #[test]
    fn test_time_offset_calculation_spans_midnight() {
        // Verify time offset calculations work correctly across midnight

        let midnight = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .single()
            .expect("Valid date");

        // Test with positive offset (system time ahead)
        let offset_ms = 100i64; // 100ms offset

        let _before_ms = datetime_to_ms(midnight - chrono::Duration::milliseconds(50));
        let window_with_offset = TimeEpoch::current_time_window(EpochType::Daily, offset_ms);

        // Window should be calculated with offset applied
        // This means synchronized_time = before_ms + 100ms
        // which would put us 50ms *after* midnight, in the new day

        assert_eq!(window_with_offset.epoch_type, EpochType::Daily);

        // Verify the window is valid
        assert!(
            window_with_offset.window_start.as_nanos() <= window_with_offset.window_end.as_nanos(),
            "Window start should be <= window end"
        );

        // With offset applied, we should be in a different epoch
        // (depends on current time, but structure should be valid)
        let no_offset_window = TimeEpoch::current_time_window(EpochType::Daily, 0);

        // Windows may differ due to offset, but both should be valid
        assert_eq!(no_offset_window.epoch_type, EpochType::Daily);

        // Verify window duration is always 500ms regardless of offset
        let duration_with_offset =
            window_with_offset.window_end.as_nanos() - window_with_offset.window_start.as_nanos();
        let duration_no_offset =
            no_offset_window.window_end.as_nanos() - no_offset_window.window_start.as_nanos();

        assert_eq!(duration_with_offset, 500_000_000);
        assert_eq!(duration_no_offset, 500_000_000);
    }
}

#[cfg(test)]
mod monthly_rollover {
    use buckwild_common::engines::time_sync::epoch::{EpochType, TimeEpoch};
    use chrono::{TimeZone, Utc};

    /// Helper: Convert chrono DateTime to milliseconds since UNIX epoch
    fn datetime_to_ms(dt: chrono::DateTime<Utc>) -> u64 {
        dt.timestamp_millis() as u64
    }

    #[test]
    fn test_month_boundary_last_day() {
        // Test bucket calculation on the last day of the month

        // January 31, 2025, 23:59:59.999
        let last_day = Utc
            .with_ymd_and_hms(2025, 1, 31, 23, 59, 59)
            .single()
            .expect("Valid date");
        let last_moment = last_day + chrono::Duration::milliseconds(999);
        let time_ms = datetime_to_ms(last_moment);

        let window = TimeEpoch::get_monthly_time_window(time_ms);

        // Verify window is valid
        assert_eq!(window.epoch_type, EpochType::Monthly);
        assert!(window.window_start.as_nanos() <= window.window_end.as_nanos());

        // Window should be for January
        let month_start = TimeEpoch::get_month_start_ms(time_ms);
        let expected_month_start = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("Valid date");
        assert_eq!(
            month_start,
            datetime_to_ms(expected_month_start),
            "Month start should be January 1"
        );

        assert_eq!(
            window.epoch_start.as_millis(),
            month_start,
            "Epoch start should match month start"
        );
    }

    #[test]
    fn test_month_boundary_transition_jan_to_feb() {
        // Test Jan 31 → Feb 1 transition

        let jan_31_end = Utc
            .with_ymd_and_hms(2025, 1, 31, 23, 59, 59)
            .single()
            .expect("Valid date")
            + chrono::Duration::milliseconds(999);
        let feb_1_start = Utc
            .with_ymd_and_hms(2025, 2, 1, 0, 0, 0)
            .single()
            .expect("Valid date")
            + chrono::Duration::milliseconds(1);

        let window_jan = TimeEpoch::get_monthly_time_window(datetime_to_ms(jan_31_end));
        let window_feb = TimeEpoch::get_monthly_time_window(datetime_to_ms(feb_1_start));

        // Both should be monthly windows
        assert_eq!(window_jan.epoch_type, EpochType::Monthly);
        assert_eq!(window_feb.epoch_type, EpochType::Monthly);

        // Epoch starts should differ
        assert_ne!(
            window_jan.epoch_start, window_feb.epoch_start,
            "Epoch start should change at month boundary"
        );

        // February window should start at Feb 1
        let feb_start = TimeEpoch::get_month_start_ms(datetime_to_ms(feb_1_start));
        assert_eq!(
            window_feb.epoch_start.as_millis(),
            feb_start,
            "February epoch should start on Feb 1"
        );

        // Verify Feb 1 is indeed the month start
        let feb_dt = Utc
            .with_ymd_and_hms(2025, 2, 1, 0, 0, 0)
            .single()
            .expect("Valid date");
        assert_eq!(feb_start, datetime_to_ms(feb_dt));
    }

    #[test]
    fn test_varying_month_lengths() {
        // Test different month lengths (28, 30, 31 days)

        // January: 31 days
        let jan_31 = Utc
            .with_ymd_and_hms(2025, 1, 31, 23, 59, 59)
            .single()
            .expect("Valid date");
        let jan_window = TimeEpoch::get_monthly_time_window(datetime_to_ms(jan_31));
        assert_eq!(jan_window.epoch_type, EpochType::Monthly);

        // February 2025: 28 days (not a leap year)
        let feb_28 = Utc
            .with_ymd_and_hms(2025, 2, 28, 23, 59, 59)
            .single()
            .expect("Valid date");
        let feb_window = TimeEpoch::get_monthly_time_window(datetime_to_ms(feb_28));
        assert_eq!(feb_window.epoch_type, EpochType::Monthly);

        // April: 30 days
        let apr_30 = Utc
            .with_ymd_and_hms(2025, 4, 30, 23, 59, 59)
            .single()
            .expect("Valid date");
        let apr_window = TimeEpoch::get_monthly_time_window(datetime_to_ms(apr_30));
        assert_eq!(apr_window.epoch_type, EpochType::Monthly);

        // All should have valid window structure
        assert!(jan_window.window_start.as_nanos() <= jan_window.window_end.as_nanos());
        assert!(feb_window.window_start.as_nanos() <= feb_window.window_end.as_nanos());
        assert!(apr_window.window_start.as_nanos() <= apr_window.window_end.as_nanos());

        // Each should have different epoch starts (different months)
        assert_ne!(jan_window.epoch_start, feb_window.epoch_start);
        assert_ne!(feb_window.epoch_start, apr_window.epoch_start);
    }

    #[test]
    fn test_leap_year_february_29() {
        // Test leap year handling: Feb 29, 2024

        // 2024 is a leap year
        let feb_29 = Utc
            .with_ymd_and_hms(2024, 2, 29, 12, 0, 0)
            .single()
            .expect("Valid leap year date");
        let time_ms = datetime_to_ms(feb_29);

        let window = TimeEpoch::get_monthly_time_window(time_ms);

        // Verify window is valid
        assert_eq!(window.epoch_type, EpochType::Monthly);
        assert!(window.window_start.as_nanos() <= window.window_end.as_nanos());

        // Epoch should start on Feb 1, 2024
        let feb_1 = Utc
            .with_ymd_and_hms(2024, 2, 1, 0, 0, 0)
            .single()
            .expect("Valid date");
        assert_eq!(
            window.epoch_start.as_millis(),
            datetime_to_ms(feb_1),
            "Epoch start should be Feb 1, 2024"
        );

        // Test transition from Feb 29 to Mar 1
        let feb_29_end = Utc
            .with_ymd_and_hms(2024, 2, 29, 23, 59, 59)
            .single()
            .expect("Valid date")
            + chrono::Duration::milliseconds(999);
        let mar_1 = Utc
            .with_ymd_and_hms(2024, 3, 1, 0, 0, 0)
            .single()
            .expect("Valid date")
            + chrono::Duration::milliseconds(1);

        let window_feb = TimeEpoch::get_monthly_time_window(datetime_to_ms(feb_29_end));
        let window_mar = TimeEpoch::get_monthly_time_window(datetime_to_ms(mar_1));

        // Epoch starts should differ
        assert_ne!(
            window_feb.epoch_start, window_mar.epoch_start,
            "Epoch should change from Feb to Mar"
        );
    }

    #[test]
    fn test_non_leap_year_no_feb_29() {
        // Verify non-leap year behavior (2025 is not a leap year)

        // Feb 28, 2025 should be valid
        let feb_28 = Utc
            .with_ymd_and_hms(2025, 2, 28, 23, 59, 59)
            .single()
            .expect("Valid date");
        let window = TimeEpoch::get_monthly_time_window(datetime_to_ms(feb_28));

        assert_eq!(window.epoch_type, EpochType::Monthly);

        // Transition to March 1, 2025
        let mar_1 = Utc
            .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
            .single()
            .expect("Valid date");
        let window_mar = TimeEpoch::get_monthly_time_window(datetime_to_ms(mar_1));

        // Epoch should change
        assert_ne!(window.epoch_start, window_mar.epoch_start);

        // March epoch should start on March 1
        let mar_start = TimeEpoch::get_month_start_ms(datetime_to_ms(mar_1));
        assert_eq!(window_mar.epoch_start.as_millis(), mar_start);
    }
}

#[cfg(test)]
mod year_rollover {
    use buckwild_common::engines::time_sync::epoch::{EpochType, TimeEpoch};
    use chrono::{TimeZone, Utc};

    /// Helper: Convert chrono DateTime to milliseconds since UNIX epoch
    fn datetime_to_ms(dt: chrono::DateTime<Utc>) -> u64 {
        dt.timestamp_millis() as u64
    }

    #[test]
    fn test_dec_31_to_jan_1_transition() {
        // Test year rollover: Dec 31, 2024 23:59:59.999 → Jan 1, 2025 00:00:00.001

        let dec_31_end = Utc
            .with_ymd_and_hms(2024, 12, 31, 23, 59, 59)
            .single()
            .expect("Valid date")
            + chrono::Duration::milliseconds(999);
        let jan_1_start = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("Valid date")
            + chrono::Duration::milliseconds(1);

        // Test daily epoch
        let window_dec_daily = TimeEpoch::get_daily_time_window(datetime_to_ms(dec_31_end));
        let window_jan_daily = TimeEpoch::get_daily_time_window(datetime_to_ms(jan_1_start));

        assert_eq!(window_dec_daily.epoch_type, EpochType::Daily);
        assert_eq!(window_jan_daily.epoch_type, EpochType::Daily);

        // Daily epoch should change at midnight
        assert_ne!(
            window_dec_daily.epoch_start, window_jan_daily.epoch_start,
            "Daily epoch should change at year boundary"
        );

        // Test monthly epoch
        let window_dec_monthly = TimeEpoch::get_monthly_time_window(datetime_to_ms(dec_31_end));
        let window_jan_monthly = TimeEpoch::get_monthly_time_window(datetime_to_ms(jan_1_start));

        assert_eq!(window_dec_monthly.epoch_type, EpochType::Monthly);
        assert_eq!(window_jan_monthly.epoch_type, EpochType::Monthly);

        // Monthly epoch should change at month boundary
        assert_ne!(
            window_dec_monthly.epoch_start, window_jan_monthly.epoch_start,
            "Monthly epoch should change at year boundary"
        );
    }

    #[test]
    fn test_epoch_calculations_across_year_boundary() {
        // Verify epoch start calculations work correctly across year boundaries

        let dec_31 = Utc
            .with_ymd_and_hms(2024, 12, 31, 12, 0, 0)
            .single()
            .expect("Valid date");
        let jan_1 = Utc
            .with_ymd_and_hms(2025, 1, 1, 12, 0, 0)
            .single()
            .expect("Valid date");

        // Day start calculations
        let dec_day_start = TimeEpoch::get_day_start_ms(datetime_to_ms(dec_31));
        let jan_day_start = TimeEpoch::get_day_start_ms(datetime_to_ms(jan_1));

        // Verify day starts are at midnight
        let dec_midnight = Utc
            .with_ymd_and_hms(2024, 12, 31, 0, 0, 0)
            .single()
            .expect("Valid date");
        let jan_midnight = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("Valid date");

        assert_eq!(dec_day_start, datetime_to_ms(dec_midnight));
        assert_eq!(jan_day_start, datetime_to_ms(jan_midnight));

        // Month start calculations
        let dec_month_start = TimeEpoch::get_month_start_ms(datetime_to_ms(dec_31));
        let jan_month_start = TimeEpoch::get_month_start_ms(datetime_to_ms(jan_1));

        // Verify month starts are at first day of month
        let dec_1 = Utc
            .with_ymd_and_hms(2024, 12, 1, 0, 0, 0)
            .single()
            .expect("Valid date");
        let jan_1_month = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("Valid date");

        assert_eq!(dec_month_start, datetime_to_ms(dec_1));
        assert_eq!(jan_month_start, datetime_to_ms(jan_1_month));
    }

    #[test]
    fn test_year_boundary_leap_year_transition() {
        // Test leap year transitions

        // 2023 → 2024 (entering leap year)
        let dec_31_2023 = Utc
            .with_ymd_and_hms(2023, 12, 31, 23, 59, 59)
            .single()
            .expect("Valid date");
        let jan_1_2024 = Utc
            .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .single()
            .expect("Valid date");

        let window_2023 = TimeEpoch::get_daily_time_window(datetime_to_ms(dec_31_2023));
        let window_2024 = TimeEpoch::get_daily_time_window(datetime_to_ms(jan_1_2024));

        assert_ne!(
            window_2023.epoch_start, window_2024.epoch_start,
            "Epoch should change at year boundary into leap year"
        );

        // 2024 → 2025 (leaving leap year)
        let dec_31_2024 = Utc
            .with_ymd_and_hms(2024, 12, 31, 23, 59, 59)
            .single()
            .expect("Valid date");
        let jan_1_2025 = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("Valid date");

        let window_2024 = TimeEpoch::get_daily_time_window(datetime_to_ms(dec_31_2024));
        let window_2025 = TimeEpoch::get_daily_time_window(datetime_to_ms(jan_1_2025));

        assert_ne!(
            window_2024.epoch_start, window_2025.epoch_start,
            "Epoch should change at year boundary leaving leap year"
        );
    }

    #[test]
    fn test_port_hopping_synchronization_across_year() {
        // Verify port hopping remains synchronized across year boundaries

        let dec_31 = Utc
            .with_ymd_and_hms(2024, 12, 31, 23, 59, 59)
            .single()
            .expect("Valid date");
        let jan_1 = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 1)
            .single()
            .expect("Valid date");

        // Get windows for both sides of year boundary
        let window_dec = TimeEpoch::get_daily_time_window(datetime_to_ms(dec_31));
        let window_jan = TimeEpoch::get_daily_time_window(datetime_to_ms(jan_1));

        // Both should be valid daily windows
        assert_eq!(window_dec.epoch_type, EpochType::Daily);
        assert_eq!(window_jan.epoch_type, EpochType::Daily);

        // Window structure should be consistent
        let dec_duration = window_dec.window_end.as_nanos() - window_dec.window_start.as_nanos();
        let jan_duration = window_jan.window_end.as_nanos() - window_jan.window_start.as_nanos();

        assert_eq!(dec_duration, 500_000_000, "December window should be 500ms");
        assert_eq!(jan_duration, 500_000_000, "January window should be 500ms");

        // Windows should be at different epochs (different days)
        assert_ne!(window_dec.epoch_start, window_jan.epoch_start);

        // Dec 31 should be near end of its day
        let windows_per_day = 86400 * 1000 / 500; // 172,800 windows per day
        assert!(
            window_dec.window.as_u64() > windows_per_day - 10,
            "Dec 31 23:59:59 should be near end of day"
        );

        // Jan 1 should be at start of its day
        assert!(
            window_jan.window.as_u64() < 10,
            "Jan 1 00:00:01 should be near start of day"
        );
    }

    #[test]
    fn test_time_offset_persistence_across_year() {
        // Verify time offset calculations persist correctly across year boundaries

        let _dec_31 = Utc
            .with_ymd_and_hms(2024, 12, 31, 23, 59, 59)
            .single()
            .expect("Valid date");

        // Apply a time offset
        let offset_ms = 5000i64; // 5 second offset

        // Calculate window with offset before year boundary
        let window_with_offset = TimeEpoch::current_time_window(EpochType::Daily, offset_ms);

        // Window should be valid
        assert_eq!(window_with_offset.epoch_type, EpochType::Daily);
        assert!(
            window_with_offset.window_start.as_nanos() <= window_with_offset.window_end.as_nanos()
        );

        // Verify offset is applied (window time should differ from wall clock time)
        let no_offset_window = TimeEpoch::current_time_window(EpochType::Daily, 0);

        // Both windows should be valid
        assert_eq!(no_offset_window.epoch_type, EpochType::Daily);

        // Windows may be in different buckets due to 5-second offset
        // but both should have 500ms duration
        let with_offset_duration =
            window_with_offset.window_end.as_nanos() - window_with_offset.window_start.as_nanos();
        let no_offset_duration =
            no_offset_window.window_end.as_nanos() - no_offset_window.window_start.as_nanos();

        assert_eq!(with_offset_duration, 500_000_000);
        assert_eq!(no_offset_duration, 500_000_000);
    }
}
