// Tests for time epoch calculations and 500ms time window synchronization
//
// These tests verify that port hopping uses correct 500ms time windows
// as specified in design/protocol/10-port-hopping.md
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_hop_interval_constant_is_500ms() {
    // Verify HOP_INTERVAL_MS constant is exactly 500ms
    assert_eq!(
        HOP_INTERVAL_MS.as_millis(),
        500,
        "HOP_INTERVAL_MS must be 500 milliseconds"
    );
}

#[test]
fn test_current_epoch_calculates_500ms_buckets() {
    // Test that get_current_epoch() calculates 500ms time buckets correctly
    let epoch_mgr = TimeEpoch::new();

    // Test at a known time: January 1, 2024, 00:00:01.000 UTC (1 second into the month)
    // Month start: January 1, 2024, 00:00:00.000 UTC = 1704067200000 ms
    // Current time: 1704067200000 + 1000 = 1704067201000 ms
    // ms_since_month_start = 1000 ms
    // Expected epoch = 1000 / 500 = 2 (two 500ms windows have passed)

    // We can't easily set the time, but we can test the calculation logic
    // by checking that epochs increase by 1 every 500ms

    let month_start_ms = TimeEpoch::current_month_start_ms();
    let current_ms = TimeEpoch::current_time_ms();
    let ms_since_month_start = current_ms - month_start_ms;

    let expected_epoch = ms_since_month_start / 500;
    let actual_epoch = epoch_mgr.get_current_epoch();

    assert_eq!(
        actual_epoch as u64, expected_epoch,
        "Epoch should be ms_since_month_start / 500. ms_since_month_start={}, expected={}, actual={}",
        ms_since_month_start, expected_epoch, actual_epoch
    );
}

#[test]
fn test_daily_time_window_uses_500ms_buckets() {
    // Test that daily time windows use 500ms intervals
    // Day start: midnight UTC
    // Time: 00:00:01.000 (1 second = 1000ms into the day)
    // Expected window number: 1000 / 500 = 2

    let day_start_ms = 1704067200000u64; // January 1, 2024, 00:00:00 UTC
    let test_time_ms = day_start_ms + 1000; // 1 second later

    let time_window = TimeEpoch::get_daily_time_window(test_time_ms);

    assert_eq!(
        time_window.window, 2,
        "Window number should be 2 (1000ms / 500ms)"
    );
    assert_eq!(
        time_window.epoch_type,
        EpochType::Daily,
        "Epoch type should be Daily"
    );
}

#[test]
fn test_daily_time_window_boundaries() {
    // Test time window boundaries align correctly
    let day_start_ms = 1704067200000u64; // January 1, 2024, 00:00:00 UTC

    // Test at window boundary
    let test_time_ms = day_start_ms + 1000; // Exactly at 2nd window boundary
    let time_window = TimeEpoch::get_daily_time_window(test_time_ms);

    assert_eq!(time_window.window, 2);

    // Test 1ms before next boundary
    let test_time_ms = day_start_ms + 1499; // 1499ms (still in 2nd window)
    let time_window = TimeEpoch::get_daily_time_window(test_time_ms);

    assert_eq!(time_window.window, 2, "Should still be in window 2");

    // Test at next boundary
    let test_time_ms = day_start_ms + 1500; // Exactly at 3rd window boundary
    let time_window = TimeEpoch::get_daily_time_window(test_time_ms);

    assert_eq!(time_window.window, 3, "Should be in window 3");
}

#[test]
fn test_monthly_time_window_uses_500ms_buckets() {
    // Test that monthly time windows use 500ms intervals
    let month_start_ms = 1704067200000u64; // January 1, 2024, 00:00:00 UTC
    let test_time_ms = month_start_ms + 2500; // 2.5 seconds later

    let time_window = TimeEpoch::get_monthly_time_window(test_time_ms);

    assert_eq!(
        time_window.window, 5,
        "Window number should be 5 (2500ms / 500ms)"
    );
    assert_eq!(
        time_window.epoch_type,
        EpochType::Monthly,
        "Epoch type should be Monthly"
    );
}

#[test]
fn test_epoch_for_host_uses_500ms_buckets() {
    // Test that per-host epoch calculation uses 500ms buckets
    let epoch_mgr = TimeEpoch::new();
    let test_host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // Set a time offset of 0 (no offset)
    TimeEpoch::set_host_time_offset(test_host, 0);

    let month_start_ms = TimeEpoch::current_month_start_ms();
    let current_ms = TimeEpoch::current_time_ms();
    let ms_since_month_start = current_ms - month_start_ms;

    let expected_epoch = ms_since_month_start / 500;
    let actual_epoch = epoch_mgr.get_current_epoch_for_host(test_host);

    assert_eq!(
        actual_epoch as u64, expected_epoch,
        "Host epoch should be ms_since_month_start / 500"
    );

    // Clean up
    TimeEpoch::remove_host_time_offset(test_host);
}

#[test]
fn test_epoch_synchronization_across_hosts() {
    // Test that multiple hosts with same time offset get same epoch
    let epoch_mgr = TimeEpoch::new();
    let host1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let host2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // Both hosts have same time offset
    TimeEpoch::set_host_time_offset(host1, 0);
    TimeEpoch::set_host_time_offset(host2, 0);

    let epoch1 = epoch_mgr.get_current_epoch_for_host(host1);
    let epoch2 = epoch_mgr.get_current_epoch_for_host(host2);

    assert_eq!(
        epoch1, epoch2,
        "Hosts with same offset should have same epoch"
    );

    // Clean up
    TimeEpoch::remove_host_time_offset(host1);
    TimeEpoch::remove_host_time_offset(host2);
}

#[test]
fn test_time_window_calculation_determinism() {
    // Test that same time always produces same window
    let test_time_ms = 1704067205000u64; // January 1, 2024, 00:00:05.000 UTC

    let window1 = TimeEpoch::get_daily_time_window(test_time_ms);
    let window2 = TimeEpoch::get_daily_time_window(test_time_ms);

    assert_eq!(
        window1.window, window2.window,
        "Same time should produce same window"
    );
    assert_eq!(
        window1.window_start, window2.window_start,
        "Window start should be identical"
    );
    assert_eq!(
        window1.window_end, window2.window_end,
        "Window end should be identical"
    );
}

#[test]
fn test_window_duration_is_500ms() {
    // Test that each window is exactly 500ms long
    let day_start_ms = 1704067200000u64;
    let test_time_ms = day_start_ms + 1000;

    let time_window = TimeEpoch::get_daily_time_window(test_time_ms);

    let window_duration_ms =
        time_window.window_end.as_millis() - time_window.window_start.as_millis();

    assert_eq!(
        window_duration_ms, 500,
        "Each time window should be exactly 500ms long"
    );
}

#[test]
fn test_consecutive_windows_are_adjacent() {
    // Test that consecutive windows are adjacent (no gaps or overlaps)
    let day_start_ms = 1704067200000u64;

    let window1 = TimeEpoch::get_daily_time_window(day_start_ms + 1000);
    let window2 = TimeEpoch::get_daily_time_window(day_start_ms + 1500);

    assert_eq!(
        window1.window_end, window2.window_start,
        "Consecutive windows should be adjacent (window1.end == window2.start)"
    );
    assert_eq!(
        window2.window,
        window1.window + 1,
        "Window numbers should be consecutive"
    );
}

#[test]
fn test_time_offset_affects_epoch_calculation() {
    // Test that time offsets properly affect epoch calculation
    let epoch_mgr = TimeEpoch::new();
    let test_host = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Set offset of +500ms (half a window)
    TimeEpoch::set_host_time_offset(test_host, 500_000); // 500ms in microseconds

    let base_epoch = epoch_mgr.get_current_epoch();
    let offset_epoch = epoch_mgr.get_current_epoch_for_host(test_host);

    // With 500ms offset, epoch might be same or +1 depending on where we are in the window
    let epoch_diff = (offset_epoch as i64 - base_epoch as i64).abs();
    assert!(
        epoch_diff <= 1,
        "500ms offset should change epoch by at most 1 window"
    );

    // Clean up
    TimeEpoch::remove_host_time_offset(test_host);
}

#[test]
fn test_large_time_values() {
    // Test that calculation works with large time values (months into the future)
    // January 1, 2030, 00:00:00 UTC = 1893456000000 ms
    let future_time_ms = 1893456000000u64 + 5000; // 5 seconds into 2030

    let time_window = TimeEpoch::get_daily_time_window(future_time_ms);

    assert_eq!(
        time_window.window, 10,
        "Window should be 10 (5000ms / 500ms)"
    );
}

#[test]
fn test_time_window_serialization_consistency() {
    // Test that time window fields are internally consistent
    let test_time_ms = 1704067205250u64; // January 1, 2024, 00:00:05.250 UTC

    let time_window = TimeEpoch::get_daily_time_window(test_time_ms);

    // Verify test time falls within the window
    assert!(
        test_time_ms >= time_window.window_start.as_millis(),
        "Test time should be >= window start"
    );
    assert!(
        test_time_ms < time_window.window_end.as_millis(),
        "Test time should be < window end"
    );

    // Verify window is within the current day
    assert!(
        time_window.window_start.as_millis() >= time_window.epoch_start.as_millis(),
        "Window start should be >= epoch (day) start"
    );
}
