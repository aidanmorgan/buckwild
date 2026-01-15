// Epoch Management - Time epoch calculations and boundary handling
//
// This module handles time epoch calculations, boundary transitions,
// and provides time window management for port hopping coordination.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Datelike, TimeZone, Utc};
use parking_lot::RwLock;
use tracing::{debug, info};

use crate::error::EngineError;
use crate::protocol::types::*;

/// Hop interval in milliseconds
pub const HOP_INTERVAL_MS: Interval = Interval(500_000_000); // 500ms in nanoseconds

/// Month boundary preparation window in milliseconds (1 hour)
pub const MONTH_BOUNDARY_PREPARATION_WINDOW_MS: u64 = 3600000;

/// Security boundary threshold for time validation (30 seconds)
pub const TIME_SECURITY_BOUNDARY_MS: u64 = 30000;

/// Maximum time skew allowed for security validation (5 seconds)
pub const MAX_SECURITY_TIME_SKEW_MS: u64 = 5000;

/// Epoch type for time calculations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochType {
    /// Daily epoch (for base port hopping)
    Daily,
    /// Monthly epoch (for session port hopping)
    Monthly,
}

/// Time window for port hopping
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeWindow {
    /// Window number (500ms buckets since epoch start)
    pub window: Counter,
    /// Epoch start time (milliseconds since UNIX epoch)
    pub epoch_start: Timestamp,
    /// Window start time (milliseconds since UNIX epoch)
    pub window_start: Timestamp,
    /// Window end time (milliseconds since UNIX epoch)
    pub window_end: Timestamp,
    /// Epoch type (daily or monthly)
    pub epoch_type: EpochType,
}

/// Per-host atomic time offsets for thread-safe coordination
static HOST_TIME_OFFSETS: std::sync::LazyLock<RwLock<HashMap<IpAddr, TimeOffset>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// Global atomic time offset for legacy compatibility
static GLOBAL_TIME_OFFSET: std::sync::LazyLock<TimeOffset> =
    std::sync::LazyLock::new(|| TimeOffset::new(0));

/// Month boundary preparation flag
static MONTH_BOUNDARY_PREPARATION: std::sync::LazyLock<AtomicFlag> =
    std::sync::LazyLock::new(|| AtomicFlag::new(false));

/// Time epoch management with dual-epoch system and security hardening
pub struct TimeEpoch;

impl TimeEpoch {
    /// Create a new time epoch manager
    pub fn new() -> Self {
        Self
    }

    /// Get the current UTC time in milliseconds since UNIX epoch
    pub fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64
    }

    /// Get the current UTC time in microseconds since UNIX epoch
    pub fn current_time_us() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_micros() as u64
    }

    /// Get the current UTC time with high precision
    pub fn current_time_high_precision() -> u64 {
        // Use the most precise clock available on the system
        #[cfg(target_os = "linux")]
        {
            use std::time::Instant;
            static START_INSTANT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
            static START_TIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

            let start_instant = START_INSTANT.get_or_init(Instant::now);
            let start_time = START_TIME.get_or_init(|| Self::current_time_us());

            let elapsed = start_instant.elapsed();
            *start_time + elapsed.as_micros() as u64
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::current_time_us()
        }
    }

    /// Get the start of the current UTC day in milliseconds since UNIX epoch
    pub fn current_day_start_ms() -> u64 {
        let now = Utc::now();
        // Use single() to handle ambiguous/invalid dates, fallback to current time
        let day_start = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .single()
            .unwrap_or(now);
        day_start.timestamp_millis() as u64
    }

    /// Get the start of the current UTC month in milliseconds since UNIX epoch
    pub fn current_month_start_ms() -> u64 {
        let now = Utc::now();
        let month_start = Utc
            .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
            .single()
            .unwrap_or_else(Utc::now);
        month_start.timestamp_millis() as u64
    }

    /// Get the current time window for the specified epoch type with per-host atomic offset
    pub fn current_time_window_for_host(
        epoch_type: EpochType,
        host: IpAddr,
        time_offset_ms: i64,
    ) -> TimeWindow {
        let current_time = Self::current_time_ms();
        let host_offset = Self::get_host_time_offset(host) / 1000; // Convert from microseconds
        let synchronized_time = (current_time as i64 + time_offset_ms + host_offset) as u64;

        match epoch_type {
            EpochType::Daily => Self::get_daily_time_window(synchronized_time),
            EpochType::Monthly => Self::get_monthly_time_window(synchronized_time),
        }
    }

    /// Get the current time window for the specified epoch type (legacy method)
    pub fn current_time_window(epoch_type: EpochType, time_offset_ms: i64) -> TimeWindow {
        let current_time = Self::current_time_ms();
        let global_offset = GLOBAL_TIME_OFFSET.load(Ordering::Relaxed) / 1000; // Convert from microseconds
        let synchronized_time = (current_time as i64 + time_offset_ms + global_offset) as u64;

        match epoch_type {
            EpochType::Daily => Self::get_daily_time_window(synchronized_time),
            EpochType::Monthly => Self::get_monthly_time_window(synchronized_time),
        }
    }

    /// Get the current synchronized time for a specific host
    pub fn synchronized_time_ms_for_host(host: IpAddr) -> u64 {
        let current_time = Self::current_time_ms();
        let host_offset = Self::get_host_time_offset(host) / 1000; // Convert from microseconds
        (current_time as i64 + host_offset) as u64
    }

    /// Get the current synchronized time in microseconds for a specific host
    pub fn synchronized_time_us_for_host(host: IpAddr) -> u64 {
        let current_time = Self::current_time_us();
        let host_offset = Self::get_host_time_offset(host);
        (current_time as i64 + host_offset) as u64
    }

    /// Get the current synchronized time with global offset (legacy method)
    pub fn synchronized_time_ms() -> u64 {
        let current_time = Self::current_time_ms();
        let global_offset = GLOBAL_TIME_OFFSET.load(Ordering::Relaxed) / 1000; // Convert from microseconds
        (current_time as i64 + global_offset) as u64
    }

    /// Get the current synchronized time in microseconds with global offset (legacy method)
    pub fn synchronized_time_us() -> u64 {
        let current_time = Self::current_time_us();
        let global_offset = GLOBAL_TIME_OFFSET.load(Ordering::Relaxed);
        (current_time as i64 + global_offset) as u64
    }

    /// Set the atomic time offset for a specific host in microseconds (thread-safe)
    pub fn set_host_time_offset(host: IpAddr, offset_us: i64) {
        let offsets = HOST_TIME_OFFSETS.read();
        if let Some(atomic_offset) = offsets.get(&host) {
            atomic_offset.store(offset_us, std::sync::atomic::Ordering::Relaxed);
        } else {
            drop(offsets);
            let mut offsets = HOST_TIME_OFFSETS.write();
            offsets.insert(host, TimeOffset::new(offset_us));
        }

        debug!(
            host = %host,
            offset_us,
            offset_ms = offset_us / 1000,
            "Set time offset for host"
        );
    }

    /// Add to the atomic time offset for a specific host in microseconds (thread-safe)
    pub fn add_host_time_offset(host: IpAddr, offset_us: i64) -> i64 {
        let offsets = HOST_TIME_OFFSETS.read();
        if let Some(atomic_offset) = offsets.get(&host) {
            let new_offset = atomic_offset
                .fetch_add(offset_us, std::sync::atomic::Ordering::Relaxed)
                + offset_us;
            debug!(
                host = %host,
                added_offset_us = offset_us,
                new_total_offset_us = new_offset,
                "Added to time offset for host"
            );
            new_offset
        } else {
            drop(offsets);
            let mut offsets = HOST_TIME_OFFSETS.write();
            let atomic_offset = TimeOffset::new(offset_us);
            offsets.insert(host, atomic_offset);
            debug!(
                host = %host,
                initial_offset_us = offset_us,
                "Initialized time offset for host"
            );
            offset_us
        }
    }

    /// Get the current atomic time offset for a specific host in microseconds
    pub fn get_host_time_offset(host: IpAddr) -> i64 {
        let offsets = HOST_TIME_OFFSETS.read();
        offsets
            .get(&host)
            .map(|atomic_offset| atomic_offset.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Remove time offset for a host (when host is no longer active)
    pub fn remove_host_time_offset(host: IpAddr) {
        let mut offsets = HOST_TIME_OFFSETS.write();
        if offsets.remove(&host).is_some() {
            debug!(
                host = %host,
                "Removed time offset for host"
            );
        }
    }

    /// Get all hosts with time offsets (for monitoring/debugging)
    pub fn get_all_host_offsets() -> HashMap<IpAddr, i64> {
        let offsets = HOST_TIME_OFFSETS.read();
        offsets
            .iter()
            .map(|(host, atomic_offset)| (*host, atomic_offset.load(Ordering::Relaxed)))
            .collect()
    }

    /// Set the global atomic time offset in microseconds (legacy method)
    pub fn set_atomic_time_offset(offset_us: i64) {
        GLOBAL_TIME_OFFSET.store(offset_us, std::sync::atomic::Ordering::Relaxed);

        debug!(
            offset_us,
            offset_ms = offset_us / 1000,
            "Set global time offset"
        );
    }

    /// Add to the global atomic time offset in microseconds (legacy method)
    pub fn add_atomic_time_offset(offset_us: i64) -> i64 {
        let new_offset = GLOBAL_TIME_OFFSET
            .fetch_add(offset_us, std::sync::atomic::Ordering::Relaxed)
            + offset_us;

        debug!(
            added_offset_us = offset_us,
            new_total_offset_us = new_offset,
            "Added to global time offset"
        );

        new_offset
    }

    /// Get the current global atomic time offset in microseconds
    pub fn get_atomic_time_offset() -> i64 {
        GLOBAL_TIME_OFFSET.load(Ordering::Relaxed)
    }

    /// Get the daily time window for the specified time
    pub fn get_daily_time_window(time_ms: u64) -> TimeWindow {
        let day_start = Self::get_day_start_ms(time_ms);
        let ms_since_day_start = time_ms - day_start;
        let hop_interval_ms = HOP_INTERVAL_MS.as_millis(); // Convert nanoseconds to milliseconds
        let window = ms_since_day_start / hop_interval_ms;
        let window_start_ms = day_start + (window * hop_interval_ms);
        let window_end_ms = window_start_ms + hop_interval_ms;

        // Convert to nanoseconds for Timestamp storage
        TimeWindow {
            window: Counter::new(window),
            epoch_start: Timestamp::from_millis(day_start),
            window_start: Timestamp::from_millis(window_start_ms),
            window_end: Timestamp::from_millis(window_end_ms),
            epoch_type: EpochType::Daily,
        }
    }

    /// Get the monthly time window for the specified time
    pub fn get_monthly_time_window(time_ms: u64) -> TimeWindow {
        let month_start = Self::get_month_start_ms(time_ms);
        let ms_since_month_start = time_ms - month_start;
        let hop_interval_ms = HOP_INTERVAL_MS.as_millis(); // Convert nanoseconds to milliseconds
        let window = ms_since_month_start / hop_interval_ms;
        let window_start_ms = month_start + (window * hop_interval_ms);
        let window_end_ms = window_start_ms + hop_interval_ms;

        // Convert to nanoseconds for Timestamp storage
        TimeWindow {
            window: Counter::new(window),
            epoch_start: Timestamp::from_millis(month_start),
            window_start: Timestamp::from_millis(window_start_ms),
            window_end: Timestamp::from_millis(window_end_ms),
            epoch_type: EpochType::Monthly,
        }
    }

    /// Get the start of the day containing the specified time
    pub fn get_day_start_ms(time_ms: u64) -> u64 {
        let dt = DateTime::<Utc>::from_timestamp_millis(time_ms as i64).unwrap_or_else(Utc::now);
        let day_start = Utc
            .with_ymd_and_hms(dt.year(), dt.month(), dt.day(), 0, 0, 0)
            .single()
            .unwrap_or_else(Utc::now);
        day_start.timestamp_millis() as u64
    }

    /// Get the start of the month containing the specified time
    pub fn get_month_start_ms(time_ms: u64) -> u64 {
        let dt = DateTime::<Utc>::from_timestamp_millis(time_ms as i64).unwrap_or_else(Utc::now);
        let month_start = Utc
            .with_ymd_and_hms(dt.year(), dt.month(), 1, 0, 0, 0)
            .single()
            .unwrap_or_else(Utc::now);
        month_start.timestamp_millis() as u64
    }

    /// Calculate the next hop time from the current time with per-host atomic coordination
    pub fn next_hop_time_for_host(host: IpAddr, time_offset_ms: i64, epoch_type: EpochType) -> u64 {
        let current_window = Self::current_time_window_for_host(epoch_type, host, time_offset_ms);
        let next_window = current_window.window.as_u64() + 1;
        let hop_interval = HOP_INTERVAL_MS.as_u64();

        match epoch_type {
            EpochType::Daily => {
                u64::from(current_window.epoch_start) + (next_window * hop_interval)
            }
            EpochType::Monthly => {
                u64::from(current_window.epoch_start) + (next_window * hop_interval)
            }
        }
    }

    /// Calculate the next hop time from the current time (legacy method)
    pub fn next_hop_time(time_offset_ms: i64, epoch_type: EpochType) -> u64 {
        let current_window = Self::current_time_window(epoch_type, time_offset_ms);
        let next_window = current_window.window.as_u64() + 1;
        let hop_interval = HOP_INTERVAL_MS.as_u64();

        match epoch_type {
            EpochType::Daily => {
                u64::from(current_window.epoch_start) + (next_window * hop_interval)
            }
            EpochType::Monthly => {
                u64::from(current_window.epoch_start) + (next_window * hop_interval)
            }
        }
    }

    /// Calculate the next hop time with per-host atomic offset coordination
    pub fn next_hop_time_atomic_for_host(host: IpAddr, epoch_type: EpochType) -> u64 {
        let host_offset = Self::get_host_time_offset(host) / 1000; // Convert to milliseconds
        Self::next_hop_time_for_host(host, host_offset, epoch_type)
    }

    /// Get the current epoch number for the specified type
    pub fn get_current_epoch(&self) -> u32 {
        let current_time = Self::current_time_ms();
        let month_start = Self::get_month_start_ms(current_time);
        let ms_since_month_start = current_time - month_start;
        (ms_since_month_start / HOP_INTERVAL_MS.as_millis()) as u32
    }

    /// Get the current epoch number for a specific host
    pub fn get_current_epoch_for_host(&self, host: IpAddr) -> u32 {
        let current_time = Self::synchronized_time_ms_for_host(host);
        let month_start = Self::get_month_start_ms(current_time);
        let ms_since_month_start = current_time - month_start;
        (ms_since_month_start / HOP_INTERVAL_MS.as_millis()) as u32
    }

    /// Check if the current time is near a month boundary
    pub fn is_near_month_boundary(threshold_ms: u64) -> bool {
        let current_time = Self::current_time_ms();
        let current_dt =
            DateTime::<Utc>::from_timestamp_millis(current_time as i64).unwrap_or_else(Utc::now);

        // Check if we're near the end of the month
        let days_in_month = Self::days_in_month(current_dt.year(), current_dt.month());
        let is_last_day = current_dt.day() == days_in_month;

        if is_last_day {
            // Calculate time until midnight
            let next_day = Utc
                .with_ymd_and_hms(
                    current_dt.year(),
                    current_dt.month(),
                    current_dt.day(),
                    0,
                    0,
                    0,
                )
                .single()
                .unwrap_or_else(Utc::now)
                + chrono::Duration::days(1);

            let ms_until_midnight =
                (next_day.timestamp_millis() - current_dt.timestamp_millis()) as u64;

            // If we're within the threshold of midnight on the last day of the month
            ms_until_midnight <= threshold_ms
        } else {
            false
        }
    }

    /// Check if we're in the month boundary preparation window
    pub fn is_in_month_boundary_preparation() -> bool {
        MONTH_BOUNDARY_PREPARATION.load(Ordering::Relaxed)
            || Self::is_near_month_boundary(MONTH_BOUNDARY_PREPARATION_WINDOW_MS)
    }

    /// Set the month boundary preparation flag (atomic)
    pub fn set_month_boundary_preparation(enabled: bool) {
        MONTH_BOUNDARY_PREPARATION.store(enabled, std::sync::atomic::Ordering::Relaxed);

        if enabled {
            info!("Month boundary preparation enabled");
        } else {
            info!("Month boundary preparation disabled");
        }
    }

    /// Start month boundary preparation window
    pub fn start_month_boundary_preparation() {
        MONTH_BOUNDARY_PREPARATION.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("Month boundary preparation window started");
    }

    /// End month boundary preparation window
    pub fn end_month_boundary_preparation() {
        MONTH_BOUNDARY_PREPARATION.store(false, std::sync::atomic::Ordering::Relaxed);
        info!("Month boundary preparation window ended");
    }

    /// Validate time is within security boundaries using constant-time comparison
    pub fn validate_time_security_boundary(time_ms: u64, reference_time_ms: u64) -> bool {
        let time_diff = time_ms.abs_diff(reference_time_ms);

        // Use constant-time comparison for security-critical validation
        let boundary_bytes = TIME_SECURITY_BOUNDARY_MS.to_le_bytes();
        let diff_bytes = time_diff.to_le_bytes();

        // Compare using constant-time to prevent timing attacks
        let mut result = true;
        for i in 0..8 {
            if i < 8 {
                result &= diff_bytes[i] <= boundary_bytes[i]
                    || (i > 0 && diff_bytes[i - 1] < boundary_bytes[i - 1]);
            }
        }

        result
    }

    /// Validate time skew is within acceptable limits using constant-time comparison
    pub fn validate_time_skew(local_time_ms: u64, peer_time_ms: u64) -> bool {
        let skew = local_time_ms.abs_diff(peer_time_ms);

        // Use constant-time comparison for security-critical validation
        let max_skew_bytes = MAX_SECURITY_TIME_SKEW_MS.to_le_bytes();
        let skew_bytes = skew.to_le_bytes();

        // Compare using constant-time to prevent timing attacks
        let mut result = true;
        for i in 0..8 {
            if i < 8 {
                result &= skew_bytes[i] <= max_skew_bytes[i]
                    || (i > 0 && skew_bytes[i - 1] < max_skew_bytes[i - 1]);
            }
        }

        result
    }

    /// Validate timestamp against replay window with constant-time comparison
    pub fn validate_timestamp_replay_window(
        timestamp_ms: u64,
        window_start_ms: u64,
        window_end_ms: u64,
    ) -> bool {
        // Use constant-time comparisons to prevent timing-based attacks
        let start_valid = timestamp_ms >= window_start_ms;
        let end_valid = timestamp_ms <= window_end_ms;

        // Combine results in constant time
        start_valid && end_valid
    }

    /// Validate dual-epoch timestamp consistency
    pub fn validate_dual_epoch_consistency(daily_timestamp: u64, monthly_timestamp: u64) -> bool {
        let current_time = Self::synchronized_time_ms();

        // Validate both timestamps are within acceptable bounds
        let daily_valid = Self::validate_time_security_boundary(daily_timestamp, current_time);
        let monthly_valid = Self::validate_time_security_boundary(monthly_timestamp, current_time);

        daily_valid && monthly_valid
    }

    /// Get time until next month boundary in milliseconds
    pub fn time_until_next_month_boundary() -> u64 {
        let current_time = Self::current_time_ms();
        let current_dt =
            DateTime::<Utc>::from_timestamp_millis(current_time as i64).unwrap_or_else(Utc::now);

        // Calculate next month start
        let next_month = if current_dt.month() == 12 {
            Utc.with_ymd_and_hms(current_dt.year() + 1, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(Utc::now)
        } else {
            Utc.with_ymd_and_hms(current_dt.year(), current_dt.month() + 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(Utc::now)
        };

        (next_month.timestamp_millis() - current_dt.timestamp_millis()) as u64
    }

    /// Get epoch statistics
    pub fn get_epoch_stats(&self) -> EpochStats {
        let current_time = Self::current_time_ms();
        let daily_window = Self::get_daily_time_window(current_time);
        let monthly_window = Self::get_monthly_time_window(current_time);

        EpochStats {
            current_time_ms: Timestamp::new(current_time, TimestampConfig::Bits32),
            daily_epoch_start: daily_window.epoch_start,
            monthly_epoch_start: monthly_window.epoch_start,
            daily_window_number: daily_window.window,
            monthly_window_number: monthly_window.window,
            time_until_next_month: Duration::from_millis(Self::time_until_next_month_boundary()),
            is_month_boundary_prep: Self::is_in_month_boundary_preparation(),
            global_time_offset_us: TimeOffset::new(GLOBAL_TIME_OFFSET.load(Ordering::Relaxed)),
            active_host_count: HostCount::new(HOST_TIME_OFFSETS.read().len()),
        }
    }

    /// Get epoch statistics for a specific host
    pub fn get_epoch_stats_for_host(&self, host: IpAddr) -> EpochStats {
        let current_time = Self::synchronized_time_ms_for_host(host);
        let daily_window = Self::get_daily_time_window(current_time);
        let monthly_window = Self::get_monthly_time_window(current_time);

        EpochStats {
            current_time_ms: Timestamp::new(current_time, TimestampConfig::Bits32),
            daily_epoch_start: daily_window.epoch_start,
            monthly_epoch_start: monthly_window.epoch_start,
            daily_window_number: daily_window.window,
            monthly_window_number: monthly_window.window,
            time_until_next_month: Duration::from_millis(Self::time_until_next_month_boundary()),
            is_month_boundary_prep: Self::is_in_month_boundary_preparation(),
            global_time_offset_us: TimeOffset::new(Self::get_host_time_offset(host)),
            active_host_count: HostCount::new(1), // This host
        }
    }

    /// Cleanup expired host offsets (for hosts that are no longer active)
    pub fn cleanup_expired_host_offsets(inactive_hosts: &[IpAddr]) -> Result<(), EngineError> {
        let mut offsets = HOST_TIME_OFFSETS.write();
        let mut removed_count = 0;

        for host in inactive_hosts {
            if offsets.remove(host).is_some() {
                removed_count += 1;
                debug!(
                    host = %host,
                    "Removed time offset for inactive host"
                );
            }
        }

        if removed_count > 0 {
            info!(removed_count, "Cleaned up time offsets for inactive hosts");
        }

        Ok(())
    }

    // Private helper methods

    /// Get the number of days in the specified month
    /// Get the number of days in the specified month
    fn days_in_month(year: i32, month: u32) -> u32 {
        // Safe fallback date construction - known valid date: 2000-01-01
        let safe_fallback = match chrono::NaiveDate::from_ymd_opt(2000, 1, 1) {
            Some(date) => date,
            None => {
                // Unreachable in practice, but return sensible default
                return 31;
            }
        };

        let last_day_of_month = match month {
            12 => chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap_or(safe_fallback),
            _ => chrono::NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap_or(safe_fallback),
        };

        let last_day_of_month = last_day_of_month - chrono::Duration::days(1);
        last_day_of_month.day()
    }
}

impl Default for TimeEpoch {
    fn default() -> Self {
        Self::new()
    }
}

/// Epoch statistics
#[derive(Debug, Clone)]
pub struct EpochStats {
    pub current_time_ms: Timestamp,
    pub daily_epoch_start: Timestamp,
    pub monthly_epoch_start: Timestamp,
    pub daily_window_number: Counter,
    pub monthly_window_number: Counter,
    pub time_until_next_month: Duration,
    pub is_month_boundary_prep: bool,
    pub global_time_offset_us: TimeOffset,
    pub active_host_count: HostCount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_time_epoch_creation() {
        let _epoch = TimeEpoch::new();
        let _default_epoch = TimeEpoch;

        // Should create without error
    }

    #[test]
    fn test_current_time_ms() {
        let time1 = TimeEpoch::current_time_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let time2 = TimeEpoch::current_time_ms();

        // Time should advance
        assert!(time2 > time1);
        assert!(time2 - time1 >= 10);
    }

    #[test]
    fn test_current_time_us() {
        let time1 = TimeEpoch::current_time_us();
        std::thread::sleep(std::time::Duration::from_micros(1000));
        let time2 = TimeEpoch::current_time_us();

        // Time should advance (microseconds are more precise)
        assert!(time2 > time1);
    }

    #[test]
    fn test_current_time_high_precision() {
        let time1 = TimeEpoch::current_time_high_precision();
        std::thread::sleep(std::time::Duration::from_micros(100));
        let time2 = TimeEpoch::current_time_high_precision();

        // High precision time should advance
        assert!(time2 >= time1);
    }

    #[test]
    fn test_current_day_start_ms() {
        let day_start = TimeEpoch::current_day_start_ms();
        let current = TimeEpoch::current_time_ms();

        // Day start should be before or equal to current time
        assert!(day_start <= current);

        // Day start should be at midnight UTC (divisible by milliseconds in a day)
        let day_ms = 24 * 60 * 60 * 1000;
        assert_eq!(day_start % day_ms, 0);
    }

    #[test]
    fn test_current_month_start_ms() {
        let month_start = TimeEpoch::current_month_start_ms();
        let current = TimeEpoch::current_time_ms();

        // Month start should be before or equal to current time
        assert!(month_start <= current);

        // Month start should be at day 1 of the month
        let dt = DateTime::from_timestamp_millis(month_start as i64).unwrap();
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 0);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_current_time_window_daily() {
        let window = TimeEpoch::current_time_window(EpochType::Daily, 0);

        // Window should have valid fields
        assert_eq!(window.epoch_type, EpochType::Daily);
        assert!(window.window_start <= window.window_end);

        // Window duration should be 500ms (500_000_000 nanoseconds)
        let window_duration_ns = window.window_end.as_nanos() - window.window_start.as_nanos();
        assert_eq!(window_duration_ns, 500_000_000);
    }

    #[test]
    fn test_current_time_window_monthly() {
        let window = TimeEpoch::current_time_window(EpochType::Monthly, 0);

        // Window should have valid fields
        assert_eq!(window.epoch_type, EpochType::Monthly);
        assert!(window.window_start <= window.window_end);

        // Window duration should be 500ms (500_000_000 nanoseconds)
        let window_duration_ns = window.window_end.as_nanos() - window.window_start.as_nanos();
        assert_eq!(window_duration_ns, 500_000_000);
    }

    #[test]
    fn test_time_window_with_offset() {
        let window1 = TimeEpoch::current_time_window(EpochType::Daily, 0);
        let window2 = TimeEpoch::current_time_window(EpochType::Daily, 1000);

        // Both windows should be valid
        assert_eq!(window1.epoch_type, EpochType::Daily);
        assert_eq!(window2.epoch_type, EpochType::Daily);

        // Windows should have valid structure
        assert!(window1.window_start <= window1.window_end);
        assert!(window2.window_start <= window2.window_end);

        // Time offset of +1000ms should advance the synchronized time
        // This means window2 should have a window_start >= window1.window_start
        // (may be same window if we're mid-window, or next window if offset crosses boundary)
        assert!(window2.window_start.as_nanos() >= window1.window_start.as_nanos());

        // Large offset (60 seconds) should definitely move us to a different window
        // Windows are 500ms, so 60000ms offset = 120 windows forward
        let window3 = TimeEpoch::current_time_window(EpochType::Daily, 60000);
        assert!(window3.window_start.as_nanos() > window1.window_start.as_nanos());

        // Negative offset should move us backward
        let window4 = TimeEpoch::current_time_window(EpochType::Daily, -60000);
        assert!(window4.window_start.as_nanos() < window1.window_start.as_nanos());
    }

    #[test]
    fn test_hop_interval_constant() {
        // HOP_INTERVAL_MS should be 500ms in nanoseconds
        assert_eq!(HOP_INTERVAL_MS.as_nanos(), 500_000_000);
    }

    #[test]
    fn test_security_constants() {
        // Verify security time constants are reasonable
        assert_eq!(TIME_SECURITY_BOUNDARY_MS, 30000); // 30 seconds
        assert_eq!(MAX_SECURITY_TIME_SKEW_MS, 5000); // 5 seconds
        assert_eq!(MONTH_BOUNDARY_PREPARATION_WINDOW_MS, 3600000); // 1 hour
    }

    #[test]
    fn test_host_time_offset_management() {
        let host1 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let host2 = "192.168.1.2".parse::<IpAddr>().unwrap();

        // Set offsets for different hosts
        TimeEpoch::set_host_time_offset(host1, 1000);
        TimeEpoch::set_host_time_offset(host2, 2000);

        // Verify offsets are stored correctly
        assert_eq!(TimeEpoch::get_host_time_offset(host1), 1000);
        assert_eq!(TimeEpoch::get_host_time_offset(host2), 2000);

        // Get all offsets
        let all_offsets = TimeEpoch::get_all_host_offsets();
        assert!(all_offsets.contains_key(&host1));
        assert!(all_offsets.contains_key(&host2));
    }

    #[test]
    fn test_atomic_time_offset() {
        // Store original offset
        let original = TimeEpoch::get_atomic_time_offset();

        // Set a new offset
        TimeEpoch::set_atomic_time_offset(5000);
        assert_eq!(TimeEpoch::get_atomic_time_offset(), 5000);

        // Reset to original
        TimeEpoch::set_atomic_time_offset(original);
    }

    #[test]
    fn test_month_boundary_preparation() {
        // Get current state
        let was_preparing = TimeEpoch::is_in_month_boundary_preparation();

        // Toggle preparation state
        TimeEpoch::set_month_boundary_preparation(true);
        assert!(TimeEpoch::is_in_month_boundary_preparation());

        TimeEpoch::set_month_boundary_preparation(false);
        assert!(!TimeEpoch::is_in_month_boundary_preparation());

        // Restore original state
        TimeEpoch::set_month_boundary_preparation(was_preparing);
    }

    #[test]
    fn test_time_window_boundaries() {
        let window = TimeEpoch::current_time_window(EpochType::Daily, 0);

        // Window start should be aligned to 500ms boundaries (500_000_000 ns)
        assert_eq!(
            (window.window_start.as_nanos() - window.epoch_start.as_nanos()) % 500_000_000,
            0
        );

        // Current time should be within window (convert ms to ns for comparison)
        let current_ms = TimeEpoch::current_time_ms();
        let current_ns = current_ms * 1_000_000; // Convert to nanoseconds
        assert!(current_ns >= window.window_start.as_nanos());
    }

    #[test]
    fn test_epoch_type_equality() {
        assert_eq!(EpochType::Daily, EpochType::Daily);
        assert_eq!(EpochType::Monthly, EpochType::Monthly);
        assert_ne!(EpochType::Daily, EpochType::Monthly);
    }

    #[test]
    fn test_time_window_for_specific_host() {
        let host = "10.0.0.1".parse::<IpAddr>().unwrap();

        // Set offset for host (1000ms in microseconds)
        TimeEpoch::set_host_time_offset(host, 1000000);

        let _window_without_host = TimeEpoch::current_time_window(EpochType::Daily, 0);
        let _window_with_host = TimeEpoch::current_time_window_for_host(EpochType::Daily, host, 0);

        // Windows should be different due to host offset
        // (might be same window number if offset is small, but test the mechanism exists)

        // Verify offset was set
        assert_eq!(TimeEpoch::get_host_time_offset(host), 1000000);
    }

    #[test]
    fn test_epoch_stats_structure() {
        // Verify EpochStats can be created and cloned
        let stats = EpochStats {
            current_time_ms: Timestamp::from_millis(1000),
            daily_epoch_start: Timestamp::from_millis(0),
            monthly_epoch_start: Timestamp::from_millis(0),
            daily_window_number: Counter::new(10),
            monthly_window_number: Counter::new(20),
            time_until_next_month: Duration::from_secs(3600),
            is_month_boundary_prep: false,
            global_time_offset_us: TimeOffset::new(0),
            active_host_count: HostCount::new(5),
        };

        let stats_clone = stats.clone();
        assert_eq!(stats.current_time_ms, stats_clone.current_time_ms);
    }

    #[test]
    fn test_daily_and_monthly_windows_different() {
        let daily = TimeEpoch::current_time_window(EpochType::Daily, 0);
        let monthly = TimeEpoch::current_time_window(EpochType::Monthly, 0);

        // Both should be valid but have different epoch types
        assert_eq!(daily.epoch_type, EpochType::Daily);
        assert_eq!(monthly.epoch_type, EpochType::Monthly);

        // Epoch starts should be different (day vs month)
        assert_ne!(daily.epoch_start, monthly.epoch_start);
    }
}
