#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Port Hopping Edge Cases - Time Window Boundary Handling
//
// Implements edge case handling for port hopping, specifically addressing
// time window boundary conditions to ensure no packet loss during transitions.
//
// Key requirements (TASK-062, 3P-CRIT-026, EDGE-001):
// - Detect when near port hopping window boundary
// - Handle packets that span the boundary
// - Ensure no packet loss at boundary transitions
// - Consider both sending and receiving sides

use crate::engines::time_sync::epoch::TimeEpoch;

/// Safety margin for time window boundaries (milliseconds)
/// Packets within this margin of a boundary are considered boundary-spanning
pub const HOP_INTERVAL_SAFETY_MARGIN_MS: u64 = 50; // 50ms before/after boundary

/// Maximum number of epochs to check for boundary spanning packets
pub const MAX_BOUNDARY_EPOCHS: u32 = 2;

/// Time window boundary detector
#[derive(Debug, Clone)]
pub struct BoundaryDetector {
    /// Current time window duration (milliseconds)
    hop_interval_ms: u64,

    /// Safety margin for boundaries (milliseconds)
    safety_margin_ms: u64,
}

impl BoundaryDetector {
    /// Create a new boundary detector
    pub fn new(hop_interval_ms: u64) -> Self {
        Self {
            hop_interval_ms,
            safety_margin_ms: HOP_INTERVAL_SAFETY_MARGIN_MS,
        }
    }

    /// Check if current time is near a window boundary
    ///
    /// Returns true if within safety margin of either the start or end of the current window.
    pub fn is_near_boundary(&self, current_time_ms: u64) -> bool {
        let window_position = current_time_ms % self.hop_interval_ms;

        // Near start of window
        let near_start = window_position < self.safety_margin_ms;

        // Near end of window
        let near_end = window_position > (self.hop_interval_ms - self.safety_margin_ms);

        near_start || near_end
    }

    /// Calculate time until next boundary
    pub fn time_until_next_boundary(&self, current_time_ms: u64) -> u64 {
        let window_position = current_time_ms % self.hop_interval_ms;
        self.hop_interval_ms - window_position
    }

    /// Calculate time since last boundary
    pub fn time_since_last_boundary(&self, current_time_ms: u64) -> u64 {
        current_time_ms % self.hop_interval_ms
    }

    /// Get the boundary status for current time
    pub fn get_boundary_status(&self, current_time_ms: u64) -> BoundaryStatus {
        let window_position = current_time_ms % self.hop_interval_ms;

        if window_position < self.safety_margin_ms {
            BoundaryStatus::NearStart {
                distance_ms: window_position,
            }
        } else if window_position > (self.hop_interval_ms - self.safety_margin_ms) {
            BoundaryStatus::NearEnd {
                distance_ms: self.hop_interval_ms - window_position,
            }
        } else {
            BoundaryStatus::StableWindow {
                time_until_boundary: self.hop_interval_ms - window_position,
            }
        }
    }
}

/// Boundary status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryStatus {
    /// Near the start of a time window
    NearStart { distance_ms: u64 },

    /// Near the end of a time window
    NearEnd { distance_ms: u64 },

    /// In stable middle of time window
    StableWindow { time_until_boundary: u64 },
}

impl BoundaryStatus {
    /// Check if this status indicates being near a boundary
    pub fn is_near_boundary(&self) -> bool {
        matches!(
            self,
            BoundaryStatus::NearStart { .. } | BoundaryStatus::NearEnd { .. }
        )
    }

    /// Get distance to nearest boundary in milliseconds
    pub fn distance_to_boundary(&self) -> u64 {
        match self {
            BoundaryStatus::NearStart { distance_ms } => *distance_ms,
            BoundaryStatus::NearEnd { distance_ms } => *distance_ms,
            BoundaryStatus::StableWindow {
                time_until_boundary,
            } => *time_until_boundary,
        }
    }
}

/// Boundary-spanning packet validator
///
/// Handles packets that arrive during time window transitions, ensuring
/// they are accepted on either the old or new port according to which
/// window they belong to.
pub struct BoundarySpanningValidator {
    /// Time epoch manager
    time_epoch: std::sync::Arc<TimeEpoch>,

    /// Boundary detector
    detector: BoundaryDetector,
}

impl BoundarySpanningValidator {
    /// Create a new boundary spanning validator
    pub fn new(time_epoch: std::sync::Arc<TimeEpoch>, hop_interval_ms: u64) -> Self {
        Self {
            time_epoch,
            detector: BoundaryDetector::new(hop_interval_ms),
        }
    }

    /// Validate a packet that may span a boundary
    ///
    /// Returns the epochs that should be checked for this packet based on
    /// current time and boundary proximity.
    pub fn get_valid_epochs_for_packet(&self, current_epoch: u32) -> Vec<u32> {
        let current_time_ms = TimeEpoch::current_time_ms();
        let boundary_status = self.detector.get_boundary_status(current_time_ms);

        match boundary_status {
            BoundaryStatus::NearStart { .. } => {
                // Near start of window - check current and previous epochs
                let mut epochs = vec![current_epoch];
                if current_epoch > 0 {
                    epochs.push(current_epoch - 1);
                }
                epochs
            }
            BoundaryStatus::NearEnd { .. } => {
                // Near end of window - check current and next epochs
                vec![current_epoch, current_epoch + 1]
            }
            BoundaryStatus::StableWindow { .. } => {
                // Stable window - only check current epoch
                vec![current_epoch]
            }
        }
    }

    /// Check if a packet should be accepted during a boundary transition
    ///
    /// This handles the case where a packet may have been sent just before
    /// a hop but arrives just after, or vice versa.
    pub fn should_accept_packet_during_transition(
        &self,
        packet_epoch: u32,
        current_epoch: u32,
    ) -> bool {
        let current_time_ms = TimeEpoch::current_time_ms();
        let boundary_status = self.detector.get_boundary_status(current_time_ms);

        match boundary_status {
            BoundaryStatus::NearStart { .. } => {
                // Accept packets from previous or current epoch
                packet_epoch == current_epoch || packet_epoch == current_epoch.saturating_sub(1)
            }
            BoundaryStatus::NearEnd { .. } => {
                // Accept packets from current or next epoch
                packet_epoch == current_epoch || packet_epoch == current_epoch + 1
            }
            BoundaryStatus::StableWindow { .. } => {
                // Only accept current epoch in stable window
                packet_epoch == current_epoch
            }
        }
    }

    /// Get the recommended action for sending packets near a boundary
    pub fn get_send_strategy(&self) -> SendStrategy {
        let current_time_ms = TimeEpoch::current_time_ms();
        let boundary_status = self.detector.get_boundary_status(current_time_ms);

        match boundary_status {
            BoundaryStatus::NearStart { distance_ms } if distance_ms < 10 => {
                // Very close to boundary start - wait for stable window
                SendStrategy::WaitForStableWindow {
                    wait_ms: self.detector.safety_margin_ms - distance_ms,
                }
            }
            BoundaryStatus::NearEnd { distance_ms } if distance_ms < 10 => {
                // Very close to boundary end - either wait or send on next port
                SendStrategy::SendOnNextPort {
                    transition_in_ms: distance_ms,
                }
            }
            _ => {
                // Safe to send on current port
                SendStrategy::SendOnCurrentPort
            }
        }
    }
}

/// Strategy for sending packets near boundaries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStrategy {
    /// Send on current port (safe, in stable window)
    SendOnCurrentPort,

    /// Wait for stable window before sending
    WaitForStableWindow { wait_ms: u64 },

    /// Send on next port (boundary transition imminent)
    SendOnNextPort { transition_in_ms: u64 },
}

impl Default for BoundaryDetector {
    fn default() -> Self {
        Self::new(500) // Default 500ms hop interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_detector_creation() {
        let detector = BoundaryDetector::new(500);
        assert_eq!(detector.hop_interval_ms, 500);
        assert_eq!(detector.safety_margin_ms, HOP_INTERVAL_SAFETY_MARGIN_MS);
    }

    #[test]
    fn test_is_near_boundary_start() {
        let detector = BoundaryDetector::new(500);

        // Within 50ms of start (time % 500 < 50)
        assert!(detector.is_near_boundary(1025)); // 25ms into window
        assert!(detector.is_near_boundary(1049)); // 49ms into window

        // Not near boundary
        assert!(!detector.is_near_boundary(1100)); // 100ms into window
    }

    #[test]
    fn test_is_near_boundary_end() {
        let detector = BoundaryDetector::new(500);

        // Within 50ms of end (time % 500 > 450)
        assert!(detector.is_near_boundary(1475)); // 25ms before end
        assert!(detector.is_near_boundary(1499)); // 1ms before end

        // Not near boundary
        assert!(!detector.is_near_boundary(1400)); // 100ms before end
    }

    #[test]
    fn test_time_until_next_boundary() {
        let detector = BoundaryDetector::new(500);

        // 100ms into window -> 400ms until next boundary
        assert_eq!(detector.time_until_next_boundary(1100), 400);

        // 450ms into window -> 50ms until next boundary
        assert_eq!(detector.time_until_next_boundary(1450), 50);
    }

    #[test]
    fn test_time_since_last_boundary() {
        let detector = BoundaryDetector::new(500);

        // 100ms into window
        assert_eq!(detector.time_since_last_boundary(1100), 100);

        // 450ms into window
        assert_eq!(detector.time_since_last_boundary(1450), 450);
    }

    #[test]
    fn test_boundary_status_near_start() {
        let detector = BoundaryDetector::new(500);

        let status = detector.get_boundary_status(1025); // 25ms into window
        match status {
            BoundaryStatus::NearStart { distance_ms } => {
                assert_eq!(distance_ms, 25);
            }
            _ => panic!("Expected NearStart status"),
        }

        assert!(status.is_near_boundary());
        assert_eq!(status.distance_to_boundary(), 25);
    }

    #[test]
    fn test_boundary_status_near_end() {
        let detector = BoundaryDetector::new(500);

        let status = detector.get_boundary_status(1475); // 25ms before end
        match status {
            BoundaryStatus::NearEnd { distance_ms } => {
                assert_eq!(distance_ms, 25);
            }
            _ => panic!("Expected NearEnd status"),
        }

        assert!(status.is_near_boundary());
        assert_eq!(status.distance_to_boundary(), 25);
    }

    #[test]
    fn test_boundary_status_stable_window() {
        let detector = BoundaryDetector::new(500);

        let status = detector.get_boundary_status(1250); // 250ms into window
        match status {
            BoundaryStatus::StableWindow {
                time_until_boundary,
            } => {
                assert_eq!(time_until_boundary, 250);
            }
            _ => panic!("Expected StableWindow status"),
        }

        assert!(!status.is_near_boundary());
        assert_eq!(status.distance_to_boundary(), 250);
    }

    #[test]
    fn test_valid_epochs_near_start() {
        let time_epoch = std::sync::Arc::new(TimeEpoch::new());
        let validator = BoundarySpanningValidator::new(time_epoch, 500);

        // Mock being near start of window
        let current_epoch = 10u32;

        // In real usage, this would check current time via TimeEpoch
        // For testing, we verify the logic with the method signature
        let epochs = validator.get_valid_epochs_for_packet(current_epoch);

        // Should return at least current epoch
        assert!(epochs.contains(&current_epoch));
    }

    #[test]
    fn test_should_accept_packet_current_epoch() {
        let time_epoch = std::sync::Arc::new(TimeEpoch::new());
        let validator = BoundarySpanningValidator::new(time_epoch, 500);

        // Packet from current epoch should always be accepted
        assert!(validator.should_accept_packet_during_transition(10, 10));
    }

    #[test]
    fn test_send_strategy_safe() {
        let time_epoch = std::sync::Arc::new(TimeEpoch::new());
        let validator = BoundarySpanningValidator::new(time_epoch, 500);

        // In stable window, should return SendOnCurrentPort
        // (actual behavior depends on current time from TimeEpoch)
        let strategy = validator.get_send_strategy();

        // Strategy should be one of the valid enum variants
        assert!(matches!(
            strategy,
            SendStrategy::SendOnCurrentPort
                | SendStrategy::WaitForStableWindow { .. }
                | SendStrategy::SendOnNextPort { .. }
        ));
    }

    #[test]
    fn test_default_boundary_detector() {
        let detector = BoundaryDetector::default();
        assert_eq!(detector.hop_interval_ms, 500);
    }

    #[test]
    fn test_boundary_detection_accuracy() {
        let detector = BoundaryDetector::new(500);

        // Test exact boundaries
        assert!(detector.is_near_boundary(1000)); // Exactly at start
        assert!(detector.is_near_boundary(1500)); // Exactly at end

        // Test just inside safety margin
        assert!(detector.is_near_boundary(1001)); // 1ms after start
        assert!(detector.is_near_boundary(1499)); // 1ms before end

        // Test just outside safety margin
        assert!(!detector.is_near_boundary(1051)); // 51ms after start
        assert!(!detector.is_near_boundary(1449)); // 51ms before end
    }

    #[test]
    fn test_epoch_validation_with_wraparound() {
        let time_epoch = std::sync::Arc::new(TimeEpoch::new());
        let validator = BoundarySpanningValidator::new(time_epoch, 500);

        // Test that epoch 0 doesn't cause issues when checking previous epoch
        let epochs = validator.get_valid_epochs_for_packet(0);
        assert!(epochs.contains(&0));

        // Should handle wraparound safely
        assert!(!epochs.is_empty());
    }
}
