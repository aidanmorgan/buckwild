// Time Adjustment - Time adjustment logic and gradual synchronization
//
// This module handles gradual time adjustments to prevent disruption
// to port hopping and other time-sensitive operations.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::atomic::Ordering;
use tracing::{debug, info, trace, warn};

use super::engine::{TimeSyncState, TimeSyncStatus};
use crate::protocol::types::*;
// Use TimeAdjustment from types module
use super::epoch::{EpochType, TimeEpoch};
use crate::error::EngineError;

/// Time adjustment manager
pub struct TimeAdjuster {
    /// Time synchronization state
    state: Arc<TimeSyncState>,

    /// Maximum time adjustment per hop in milliseconds
    max_adjustment_per_hop: f64,

    /// Gradual adjustment rate (0.0-1.0)
    adjustment_rate: f64,
}

impl TimeAdjuster {
    /// Create a new time adjuster
    pub fn new(state: Arc<TimeSyncState>) -> Self {
        Self {
            state,
            max_adjustment_per_hop: 25.0, // 25ms maximum per hop
            adjustment_rate: 0.1,         // 10% per hop
        }
    }

    /// Apply a gradual time adjustment for a specific host
    pub fn apply_gradual_adjustment_for_host(
        &self,
        host: IpAddr,
        total_offset_ms: f64,
        sync_quality: Score,
    ) -> bool {
        // Convert to microseconds for atomic operations
        let total_offset_us = (total_offset_ms * 1000.0) as i64;

        // If offset is small enough, apply it immediately
        if total_offset_ms.abs() < 1.0 {
            self.state
                .add_local_offset_for_host(host, TimeOffset::new(total_offset_us));
            self.state.set_sync_quality_for_host(host, sync_quality);

            debug!(
                host = %host,
                offset_ms = total_offset_ms,
                quality = %sync_quality,
                "Applied small time adjustment immediately for host"
            );

            return true;
        }

        // Calculate adjustment schedule
        let adjustment_steps = self.calculate_adjustment_steps(total_offset_ms);
        let step_size = total_offset_ms / adjustment_steps as f64;

        // Queue gradual adjustments aligned with hop intervals
        let _next_hop_time = TimeEpoch::next_hop_time_atomic_for_host(host, EpochType::Monthly);

        // Clear any existing adjustments for this host
        self.state.clear_time_adjustments_for_host(host);

        // Create new adjustment queue
        for step in 0..adjustment_steps {
            let adjustment = TimeAdjustment {
                offset: TimeOffset::new((step_size * 1_000_000.0) as i64), // Convert ms to nanoseconds
                apply_time: Timestamp::from_nanos(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                ),
                step_number: StepCount::new(step + 1),
                total_steps: StepCount::new(adjustment_steps),
                paused: false,
            };

            self.state
                .add_time_adjustment_for_host(host, adjustment.clone());

            trace!(
                host = %host,
                step = step + 1,
                total_steps = adjustment_steps as usize,
                offset_ms = step_size,
                step_number = adjustment.step_number.as_u32() as usize,
                "Scheduled gradual time adjustment for host"
            );
        }

        // Update state
        self.state
            .set_status_for_host(host, TimeSyncStatus::Adjusting);
        self.state.set_sync_quality_for_host(host, sync_quality);

        info!(
            host = %host,
            total_offset_ms,
            steps = adjustment_steps,
            step_size_ms = step_size,
            quality = sync_quality.as_f32(),
            "Started gradual time adjustment for host"
        );

        true
    }

    /// Legacy method - apply gradual adjustment (no-op since we're now per-host)
    pub fn apply_gradual_adjustment(&self, _total_offset_ms: f64, _sync_quality: Score) -> bool {
        warn!("apply_gradual_adjustment called - use apply_gradual_adjustment_for_host instead");
        false
    }

    /// Process pending time adjustments for a specific host
    pub fn process_adjustments_for_host(&self, host: IpAddr) -> bool {
        let current_time = TimeEpoch::current_time_ms();
        let mut applied = false;
        let mut completed_indices = Vec::new();

        // Get all adjustments for this host
        let adjustments = self.state.time_adjustments_for_host(host);

        // Process each adjustment
        for (index, adjustment) in adjustments.iter().enumerate() {
            if adjustment.paused {
                continue;
            }

            if current_time >= adjustment.apply_time.as_u64() {
                // Apply time adjustment (convert to microseconds)
                let offset_us = adjustment.offset.as_nanos() * 1000;
                self.state
                    .add_local_offset_for_host(host, TimeOffset::new(offset_us));

                // Mark for removal
                completed_indices.push(index);
                applied = true;

                debug!(
                    host = %host,
                    step = adjustment.step_number.as_usize(),
                    total_steps = adjustment.total_steps.as_usize(),
                    offset_ms = adjustment.offset.as_nanos() / 1_000_000,
                    "Applied gradual time adjustment step for host"
                );
            }
        }

        // Remove completed adjustments (in reverse order to maintain indices)
        for index in completed_indices.iter().rev() {
            self.state.remove_time_adjustment_for_host(host, *index);
        }

        // Check if adjustment is complete
        if applied
            && self.state.time_adjustments_for_host(host).is_empty()
            && self.state.status_for_host(host) == TimeSyncStatus::Adjusting
        {
            self.state
                .set_status_for_host(host, TimeSyncStatus::Synchronized);

            info!(
                host = %host,
                "Gradual time adjustment complete for host"
            );
        }

        applied
    }

    /// Legacy method - process adjustments (returns false since we're now per-host)
    pub fn process_adjustments(&self) -> bool {
        warn!("process_adjustments called - use process_adjustments_for_host instead");
        false
    }

    /// Process adjustments for all hosts
    pub fn process_all_adjustments(&self) -> bool {
        let mut any_applied = false;

        // Get all hosts with adjustments
        let hosts = self.state.get_all_hosts_with_adjustments();

        for host in hosts {
            if self.process_adjustments_for_host(host) {
                any_applied = true;
            }
        }

        any_applied
    }

    /// Initiate emergency time synchronization for a specific host
    pub fn apply_emergency_adjustment_for_host(&self, host: IpAddr, large_offset_ms: f64) -> bool {
        // Convert to microseconds for atomic operations
        let offset_us = (large_offset_ms * 1000.0) as i64;

        // Update state
        let attempts = self.state.increment_emergency_sync_attempts_for_host(host);
        self.state
            .set_status_for_host(host, TimeSyncStatus::Emergency);

        warn!(
            host = %host,
            offset_ms = large_offset_ms,
            attempt = attempts.load(Ordering::Relaxed),
            "Initiated emergency time synchronization for host"
        );

        // Apply the offset immediately
        self.state
            .add_local_offset_for_host(host, TimeOffset::new(offset_us));

        // Clear any pending adjustments for this host
        self.state.clear_time_adjustments_for_host(host);

        // Update state
        self.state
            .set_status_for_host(host, TimeSyncStatus::Synchronized);

        info!(
            host = %host,
            offset_ms = large_offset_ms,
            "Applied emergency time adjustment for host"
        );

        true
    }

    /// Legacy method - apply emergency adjustment (no-op since we're now per-host)
    pub fn apply_emergency_adjustment(&self, _large_offset_ms: f64) -> bool {
        warn!(
            "apply_emergency_adjustment called - use apply_emergency_adjustment_for_host instead"
        );
        false
    }

    /// Pause time adjustments for a specific host
    pub fn pause_adjustments_for_host(&self, host: IpAddr) -> Result<(), EngineError> {
        let mut adjustments = self.state.time_adjustments_for_host(host);

        for adjustment in &mut adjustments {
            adjustment.paused = true;
        }

        self.state.set_time_adjustments_for_host(host, adjustments);

        debug!(
            host = %host,
            "Paused time adjustments for host"
        );

        Ok(())
    }

    /// Resume time adjustments for a specific host
    pub fn resume_adjustments_for_host(&self, host: IpAddr) -> Result<(), EngineError> {
        let mut adjustments = self.state.time_adjustments_for_host(host);

        for adjustment in &mut adjustments {
            adjustment.paused = false;
        }

        self.state.set_time_adjustments_for_host(host, adjustments);

        debug!(
            host = %host,
            "Resumed time adjustments for host"
        );

        Ok(())
    }

    /// Cancel all pending adjustments for a specific host
    pub fn cancel_adjustments_for_host(&self, host: IpAddr) -> Result<(), EngineError> {
        self.state.clear_time_adjustments_for_host(host);

        // Reset status if it was adjusting
        if self.state.status_for_host(host) == TimeSyncStatus::Adjusting {
            self.state
                .set_status_for_host(host, TimeSyncStatus::Synchronized);
        }

        info!(
            host = %host,
            "Cancelled all time adjustments for host"
        );

        Ok(())
    }

    /// Get adjustment status for a specific host
    pub fn get_adjustment_status_for_host(&self, host: IpAddr) -> AdjustmentStatus {
        let adjustments = self.state.time_adjustments_for_host(host);
        let status = self.state.status_for_host(host);

        if adjustments.is_empty() {
            AdjustmentStatus {
                is_adjusting: false,
                total_steps: StepCount::new(0),
                completed_steps: StepCount::new(0),
                remaining_offset: TimeOffset::new(0),
                next_adjustment_time: None,
                is_paused: false,
            }
        } else {
            let completed_steps = adjustments
                .iter()
                .filter(|adj| TimeEpoch::current_time_ms() >= adj.apply_time.as_u64())
                .count() as u32;

            let remaining_offset: f64 = adjustments
                .iter()
                .filter(|adj| TimeEpoch::current_time_ms() < adj.apply_time.as_u64())
                .map(|adj| adj.offset.as_nanos() as f64)
                .sum::<f64>();

            let next_adjustment_time = adjustments
                .iter()
                .filter(|adj| TimeEpoch::current_time_ms() < adj.apply_time.as_u64())
                .map(|adj| adj.apply_time.as_u64())
                .min();

            let is_paused = adjustments.iter().any(|adj| adj.paused);

            AdjustmentStatus {
                is_adjusting: status == TimeSyncStatus::Adjusting,
                total_steps: adjustments
                    .first()
                    .map(|adj| adj.total_steps)
                    .unwrap_or(StepCount::new(0)),
                completed_steps: StepCount::new(completed_steps),
                remaining_offset: TimeOffset::new((remaining_offset * 1000.0) as i64),
                next_adjustment_time,
                is_paused,
            }
        }
    }

    /// Set the maximum time adjustment per hop in milliseconds
    pub fn set_max_adjustment_per_hop(&mut self, max_ms: f64) {
        self.max_adjustment_per_hop = max_ms;

        debug!(
            max_adjustment_per_hop_ms = max_ms,
            "Updated maximum adjustment per hop"
        );
    }

    /// Set the gradual adjustment rate (0.0-1.0)
    pub fn set_adjustment_rate(&mut self, rate: f64) {
        self.adjustment_rate = rate.clamp(0.01, 1.0);

        debug!(
            adjustment_rate = self.adjustment_rate,
            "Updated adjustment rate"
        );
    }

    /// Get adjustment configuration
    pub fn get_adjustment_config(&self) -> AdjustmentConfig {
        AdjustmentConfig {
            max_adjustment_per_hop: AdjustmentRate::new(self.max_adjustment_per_hop),
            adjustment_rate: AdjustmentRate::new(self.adjustment_rate),
        }
    }

    // Private helper methods

    /// Calculate the number of steps needed for gradual adjustment
    fn calculate_adjustment_steps(&self, total_offset: f64) -> u32 {
        let max_step_size = self
            .max_adjustment_per_hop
            .min(total_offset.abs() * self.adjustment_rate);
        let steps = (total_offset.abs() / max_step_size).ceil() as u32;

        // Ensure adjustment completes within reasonable time
        let max_steps = 60; // Complete within 30 seconds (60 hops)
        steps.max(1).min(max_steps)
    }
}

/// Time adjustment status for a specific host
#[derive(Debug, Clone)]
pub struct AdjustmentStatus {
    pub is_adjusting: bool,
    pub total_steps: StepCount,
    pub completed_steps: StepCount,
    pub remaining_offset: TimeOffset,
    pub next_adjustment_time: Option<u64>,
    pub is_paused: bool,
}

/// Time adjustment configuration
#[derive(Debug, Clone)]
pub struct AdjustmentConfig {
    pub max_adjustment_per_hop: AdjustmentRate,
    pub adjustment_rate: AdjustmentRate,
}
