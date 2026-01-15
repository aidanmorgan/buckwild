// Drift Detection - Clock drift detection and compensation
//
// This module handles detection of clock drift using statistical analysis
// of time synchronization samples and applies compensation.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, info, warn};

use super::engine::{SyncSample, TimeSyncState};
use super::epoch::TimeEpoch;
use crate::error::EngineError;
use crate::protocol::types::*;

/// Clock drift detection and compensation
pub struct DriftCompensator {
    /// Time synchronization state
    state: Arc<TimeSyncState>,

    /// Drift calculation window in milliseconds
    drift_calculation_window: u64,

    /// Maximum acceptable drift in parts per million
    max_acceptable_drift_ppm: f64,

    /// Minimum samples required for drift calculation
    min_samples_for_drift: usize,

    /// Drift compensation threshold in milliseconds
    compensation_threshold_ms: f64,
}

impl DriftCompensator {
    /// Create a new drift compensator
    pub fn new(state: Arc<TimeSyncState>) -> Self {
        Self {
            state,
            drift_calculation_window: 300000, // 5 minutes
            max_acceptable_drift_ppm: 100.0,  // 100 ppm
            min_samples_for_drift: 3,
            compensation_threshold_ms: 1.0, // 1ms threshold
        }
    }

    /// Detect clock drift using historical samples for a specific host
    pub fn detect_drift_for_host(&self, host: IpAddr) -> DriftRate {
        // Get sync samples for this host
        let samples = self.state.sync_samples_for_host(host);

        // Need at least minimum samples for drift calculation
        if samples.len() < self.min_samples_for_drift {
            return DriftRate::new(0.0);
        }

        // Use recent samples within drift calculation window
        let current_time = TimeEpoch::current_time_ms();
        let recent_samples: Vec<&SyncSample> = samples
            .iter()
            .filter(|s| {
                current_time.saturating_sub(s.timestamp.as_u64()) < self.drift_calculation_window
            })
            .collect();

        if recent_samples.len() < self.min_samples_for_drift {
            return DriftRate::new(0.0);
        }

        // Calculate drift rate using linear regression
        let time_points: Vec<f64> = recent_samples
            .iter()
            .map(|s| s.timestamp.as_u64() as f64)
            .collect();
        let offset_points: Vec<f64> = recent_samples
            .iter()
            .map(|s| s.time_offset.as_nanos() as f64)
            .collect();

        // Calculate drift rate (milliseconds per millisecond)
        let drift_rate = self.calculate_linear_regression_slope(&time_points, &offset_points);

        // Convert to parts per million
        let drift_ppm = drift_rate * 1_000_000.0;

        let drift_rate = DriftRate::new(drift_ppm);

        // Validate drift is within acceptable bounds
        if drift_rate.is_excessive(self.max_acceptable_drift_ppm) {
            warn!(
                host = %host,
                drift_ppm,
                max_acceptable = self.max_acceptable_drift_ppm,
                samples_count = recent_samples.len(),
                "Excessive clock drift detected for host - ignoring as potentially erroneous"
            );
            return DriftRate::new(0.0); // Ignore excessive drift as potentially erroneous
        }

        // Update drift state for this host
        self.state
            .set_drift_rate_for_host(host, DriftRate(drift_ppm));

        debug!(
            host = %host,
            drift_ppm,
            samples_count = recent_samples.len(),
            window_ms = self.drift_calculation_window,
            "Calculated clock drift for host"
        );

        drift_rate
    }

    /// Legacy method - detect drift (returns 0.0 since we're now per-host)
    pub fn detect_drift(&self) -> DriftRate {
        warn!("detect_drift called - use detect_drift_for_host instead");
        DriftRate::new(0.0)
    }

    /// Detect drift for all hosts
    pub fn detect_drift_for_all_hosts(&self) -> Vec<(IpAddr, DriftRate)> {
        let hosts = self.state.get_all_hosts_with_samples();
        let mut drift_results = Vec::new();

        for host in hosts {
            let drift = self.detect_drift_for_host(host);
            if drift.is_significant(0.1) {
                // Only include significant drift
                drift_results.push((host, drift));
            }
        }

        drift_results
    }

    /// Compensate for clock drift for a specific host
    pub fn compensate_drift_for_host(&self, host: IpAddr) -> bool {
        let drift_rate = self.state.drift_rate_for_host(host);

        // Ignore very small drift
        if !drift_rate.is_significant(1.0) {
            return false;
        }

        let current_time = TimeEpoch::current_time_ms();
        let time_since_last_sync =
            current_time.saturating_sub(self.state.last_sync_time_for_host(host).as_u64());

        // Calculate accumulated drift
        let drift_ms = (time_since_last_sync as f64 * drift_rate.as_f64()) / 1_000_000.0;

        // Apply drift compensation if significant
        if drift_ms.abs() > self.compensation_threshold_ms {
            // Convert to microseconds for the atomic offset
            let drift_us = (Rate::from_raw((drift_ms as f32) * 1000.0).0) as i64;
            self.state
                .add_local_offset_for_host(host, TimeOffset::new(-drift_us));
            self.state
                .set_last_sync_time_for_host(host, Timestamp::from_millis(current_time));

            debug!(
                host = %host,
                drift_ms,
                drift_rate_ppm = drift_rate.as_f64(),
                time_since_sync_ms = time_since_last_sync,
                "Applied clock drift compensation for host"
            );

            true
        } else {
            false
        }
    }

    /// Legacy method - compensate drift (returns false since we're now per-host)
    pub fn compensate_drift(&self) -> bool {
        warn!("compensate_drift called - use compensate_drift_for_host instead");
        false
    }

    /// Compensate drift for all hosts
    pub fn compensate_drift_for_all_hosts(&self) -> bool {
        let hosts = self.state.get_all_hosts_with_drift();
        let mut any_compensated = false;

        for host in hosts {
            if self.compensate_drift_for_host(host) {
                any_compensated = true;
            }
        }

        any_compensated
    }

    /// Get drift statistics for a specific host
    pub fn get_drift_stats_for_host(&self, host: IpAddr) -> DriftStats {
        let samples = self.state.sync_samples_for_host(host);
        let current_time = TimeEpoch::current_time_ms();

        let recent_samples: Vec<&SyncSample> = samples
            .iter()
            .filter(|s| {
                current_time.saturating_sub(s.timestamp.as_u64()) < self.drift_calculation_window
            })
            .collect();

        let drift_rate = self.state.drift_rate_for_host(host);
        let last_compensation_time = self.state.last_sync_time_for_host(host);

        // Calculate drift trend
        let drift_trend = if recent_samples.len() >= 2 {
            // Safety: len >= 2 guarantees first() and last() return Some
            let first_offset = recent_samples
                .first()
                .map(|s| s.time_offset.as_nanos())
                .unwrap_or(0);
            let last_offset = recent_samples
                .last()
                .map(|s| s.time_offset.as_nanos())
                .unwrap_or(0);
            if last_offset > first_offset {
                DriftTrend::Increasing
            } else if last_offset < first_offset {
                DriftTrend::Decreasing
            } else {
                DriftTrend::Stable
            }
        } else {
            DriftTrend::Unknown
        };

        // Calculate accumulated drift since last compensation
        let time_since_compensation =
            current_time.saturating_sub(u64::from(last_compensation_time));
        let accumulated_drift_ms =
            (time_since_compensation as f64 * drift_rate.as_f64()) / 1_000_000.0;

        DriftStats {
            drift_rate_ppm: drift_rate,
            samples_count: recent_samples.len(),
            calculation_window_ms: self.drift_calculation_window,
            last_compensation_time: u64::from(last_compensation_time),
            accumulated_drift_ms,
            drift_trend,
            is_excessive: drift_rate.is_excessive(self.max_acceptable_drift_ppm),
            needs_compensation: accumulated_drift_ms.abs() > self.compensation_threshold_ms,
        }
    }

    /// Get drift statistics for all hosts
    pub fn get_drift_stats_for_all_hosts(&self) -> Vec<(IpAddr, DriftStats)> {
        let hosts = self.state.get_all_hosts_with_drift();

        hosts
            .into_iter()
            .map(|host| (host, self.get_drift_stats_for_host(host)))
            .collect()
    }

    /// Reset drift data for a specific host
    pub fn reset_drift_for_host(&self, host: IpAddr) -> Result<(), EngineError> {
        self.state.set_drift_rate_for_host(host, DriftRate(0.0));
        self.state.clear_sync_samples_for_host(host);

        info!(
            host = %host,
            "Reset drift data for host"
        );

        Ok(())
    }

    /// Set the drift calculation window in milliseconds
    pub fn set_drift_calculation_window(&mut self, window_ms: u64) {
        self.drift_calculation_window = window_ms;

        debug!(window_ms, "Updated drift calculation window");
    }

    /// Set the maximum acceptable drift in parts per million
    pub fn set_max_acceptable_drift_ppm(&mut self, max_drift_ppm: f64) {
        self.max_acceptable_drift_ppm = max_drift_ppm;

        debug!(max_drift_ppm, "Updated maximum acceptable drift");
    }

    /// Set the minimum samples required for drift calculation
    pub fn set_min_samples_for_drift(&mut self, min_samples: usize) {
        self.min_samples_for_drift = min_samples.max(2); // At least 2 samples needed

        debug!(
            min_samples = self.min_samples_for_drift,
            "Updated minimum samples for drift calculation"
        );
    }

    /// Set the drift compensation threshold in milliseconds
    pub fn set_compensation_threshold(&mut self, threshold_ms: f64) {
        self.compensation_threshold_ms = threshold_ms.abs();

        debug!(
            threshold_ms = self.compensation_threshold_ms,
            "Updated drift compensation threshold"
        );
    }

    /// Get drift compensator configuration
    pub fn get_drift_config(&self) -> DriftConfig {
        DriftConfig {
            drift_calculation_window: self.drift_calculation_window,
            max_acceptable_drift_ppm: self.max_acceptable_drift_ppm,
            min_samples_for_drift: self.min_samples_for_drift,
            compensation_threshold_ms: self.compensation_threshold_ms,
        }
    }

    // Private helper methods

    /// Calculate the slope of a linear regression line
    fn calculate_linear_regression_slope(&self, x_values: &[f64], y_values: &[f64]) -> f64 {
        let n = x_values.len();
        if n < 2 {
            return 0.0;
        }

        let sum_x: f64 = x_values.iter().sum::<f64>();
        let sum_y: f64 = y_values.iter().sum::<f64>();
        let sum_xy: f64 = x_values
            .iter()
            .zip(y_values.iter())
            .map(|(x, y)| x * y)
            .sum::<f64>();
        let sum_x2: f64 = x_values.iter().map(|x| x * x).sum::<f64>();

        let denominator = n as f64 * sum_x2 - sum_x * sum_x;
        if denominator.abs() < f64::EPSILON {
            return 0.0;
        }

        (n as f64 * sum_xy - sum_x * sum_y) / denominator
    }
}

/// Drift trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftTrend {
    Increasing,
    Decreasing,
    Stable,
    Unknown,
}

/// Drift statistics for a host
#[derive(Debug, Clone)]
pub struct DriftStats {
    pub drift_rate_ppm: DriftRate,
    pub samples_count: usize,
    pub calculation_window_ms: u64,
    pub last_compensation_time: u64,
    pub accumulated_drift_ms: f64,
    pub drift_trend: DriftTrend,
    pub is_excessive: bool,
    pub needs_compensation: bool,
}

/// Drift compensator configuration
#[derive(Debug, Clone)]
pub struct DriftConfig {
    pub drift_calculation_window: u64,
    pub max_acceptable_drift_ppm: f64,
    pub min_samples_for_drift: usize,
    pub compensation_threshold_ms: f64,
}
