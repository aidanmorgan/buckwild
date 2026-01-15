//! HMAC Policy Enforcement for Month Boundaries
//!
//! This module implements TASK-054: Month Boundary HMAC_STRONG Enforcement
//!
//! # Security Rationale
//!
//! During month boundary transitions (within 1 hour of month end), the protocol
//! enforces HMAC_STRONG (32-byte full HMAC-SHA256) regardless of negotiated policy.
//! This prevents key rollover attacks where an attacker might exploit the transition
//! period between monthly epochs to inject malicious packets.
//!
//! # Implementation
//!
//! - Detects when within 1 hour of month boundary using `TimeEpoch::is_in_month_boundary_preparation()`
//! - Forces HMAC_STRONG policy during this period
//! - Returns to negotiated policy after boundary passes
//! - Thread-safe using atomic flags from epoch module

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::engines::time_sync::epoch::TimeEpoch;
use crate::protocol::types::HmacPolicy;
use tracing::debug;

/// HMAC policy selector with month boundary enforcement
///
/// This structure determines the appropriate HMAC policy to use based on:
/// 1. Whether we're near a month boundary (within 1 hour)
/// 2. The negotiated policy for normal operation
///
/// # Security Guarantee
///
/// During month boundary preparation window (1 hour before month end):
/// - **ALL packets MUST use HMAC_STRONG (32-byte full HMAC-SHA256)**
/// - This overrides any negotiated policy (even if negotiated as LIGHT or MEDIUM)
/// - Prevents key rollover attacks during epoch transitions
#[derive(Debug, Clone)]
pub struct PolicySelector {
    /// Negotiated policy for normal (non-boundary) operation
    negotiated_policy: HmacPolicy,
}

impl PolicySelector {
    /// Create a new policy selector with the negotiated policy
    ///
    /// # Arguments
    ///
    /// * `negotiated_policy` - The policy negotiated during connection establishment
    ///
    /// # Returns
    ///
    /// A new `PolicySelector` that will enforce HMAC_STRONG during month boundaries
    pub fn new(negotiated_policy: HmacPolicy) -> Self {
        Self { negotiated_policy }
    }

    /// Get the effective HMAC policy to use right now
    ///
    /// # Returns
    ///
    /// - `HmacPolicy::Strong` if within 1 hour of month boundary
    /// - Otherwise returns the negotiated policy
    ///
    /// # Security Note
    ///
    /// This function is the core of TASK-054. It ensures that during the critical
    /// month boundary window, all packets use maximum authentication strength.
    pub fn effective_policy(&self) -> HmacPolicy {
        if TimeEpoch::is_in_month_boundary_preparation() {
            debug!(
                negotiated = ?self.negotiated_policy,
                effective = ?HmacPolicy::Strong,
                "Month boundary preparation active - enforcing HMAC_STRONG"
            );
            HmacPolicy::Strong
        } else {
            self.negotiated_policy
        }
    }

    /// Check if we're currently forcing HMAC_STRONG due to month boundary
    ///
    /// # Returns
    ///
    /// `true` if HMAC_STRONG is being forced due to month boundary proximity
    pub fn is_forcing_strong(&self) -> bool {
        TimeEpoch::is_in_month_boundary_preparation()
            && self.negotiated_policy != HmacPolicy::Strong
    }

    /// Get the negotiated policy (what would be used without boundary enforcement)
    pub fn negotiated_policy(&self) -> HmacPolicy {
        self.negotiated_policy
    }

    /// Update the negotiated policy (e.g., after renegotiation)
    pub fn set_negotiated_policy(&mut self, policy: HmacPolicy) {
        self.negotiated_policy = policy;
    }
}

impl Default for PolicySelector {
    fn default() -> Self {
        Self::new(HmacPolicy::Medium) // Default to MEDIUM per protocol spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::time_sync::epoch::TimeEpoch;

    #[test]
    fn test_policy_selector_default() {
        let selector = PolicySelector::default();
        assert_eq!(selector.negotiated_policy(), HmacPolicy::Medium);
    }

    #[test]
    fn test_policy_selector_new() {
        let selector = PolicySelector::new(HmacPolicy::Light);
        assert_eq!(selector.negotiated_policy(), HmacPolicy::Light);
    }

    #[test]
    fn test_policy_selector_set_negotiated() {
        let mut selector = PolicySelector::new(HmacPolicy::Light);
        selector.set_negotiated_policy(HmacPolicy::Strong);
        assert_eq!(selector.negotiated_policy(), HmacPolicy::Strong);
    }

    #[test]
    fn test_effective_policy_normal_period() {
        // During normal period (not near month boundary), should return negotiated policy
        TimeEpoch::set_month_boundary_preparation(false);

        let selector = PolicySelector::new(HmacPolicy::Light);
        assert_eq!(selector.effective_policy(), HmacPolicy::Light);

        let selector = PolicySelector::new(HmacPolicy::Medium);
        assert_eq!(selector.effective_policy(), HmacPolicy::Medium);
    }

    #[test]
    fn test_effective_policy_month_boundary() {
        // During month boundary, should ALWAYS return HMAC_STRONG
        TimeEpoch::set_month_boundary_preparation(true);

        // Even if negotiated as LIGHT, must use STRONG
        let selector = PolicySelector::new(HmacPolicy::Light);
        assert_eq!(
            selector.effective_policy(),
            HmacPolicy::Strong,
            "LIGHT policy must be overridden to STRONG during month boundary"
        );

        // Even if negotiated as MEDIUM, must use STRONG
        let selector = PolicySelector::new(HmacPolicy::Medium);
        assert_eq!(
            selector.effective_policy(),
            HmacPolicy::Strong,
            "MEDIUM policy must be overridden to STRONG during month boundary"
        );

        // If already STRONG, remains STRONG
        let selector = PolicySelector::new(HmacPolicy::Strong);
        assert_eq!(selector.effective_policy(), HmacPolicy::Strong);

        // Cleanup
        TimeEpoch::set_month_boundary_preparation(false);
    }

    #[test]
    fn test_is_forcing_strong_normal() {
        TimeEpoch::set_month_boundary_preparation(false);

        let selector = PolicySelector::new(HmacPolicy::Light);
        assert!(!selector.is_forcing_strong());

        let selector = PolicySelector::new(HmacPolicy::Medium);
        assert!(!selector.is_forcing_strong());
    }

    #[test]
    fn test_is_forcing_strong_boundary() {
        TimeEpoch::set_month_boundary_preparation(true);

        // Should report forcing when negotiated policy is not STRONG
        let selector = PolicySelector::new(HmacPolicy::Light);
        assert!(selector.is_forcing_strong());

        let selector = PolicySelector::new(HmacPolicy::Medium);
        assert!(selector.is_forcing_strong());

        // Should NOT report forcing when already STRONG
        let selector = PolicySelector::new(HmacPolicy::Strong);
        assert!(!selector.is_forcing_strong());

        // Cleanup
        TimeEpoch::set_month_boundary_preparation(false);
    }

    #[test]
    fn test_month_boundary_window_transition() {
        // Simulate entering month boundary window
        TimeEpoch::set_month_boundary_preparation(false);
        let selector = PolicySelector::new(HmacPolicy::Light);
        assert_eq!(selector.effective_policy(), HmacPolicy::Light);

        // Enter boundary window
        TimeEpoch::set_month_boundary_preparation(true);
        assert_eq!(selector.effective_policy(), HmacPolicy::Strong);

        // Exit boundary window
        TimeEpoch::set_month_boundary_preparation(false);
        assert_eq!(selector.effective_policy(), HmacPolicy::Light);
    }

    #[test]
    fn test_policy_selector_with_all_policies() {
        // Test that all policy variants work correctly
        for policy in &[HmacPolicy::Light, HmacPolicy::Medium, HmacPolicy::Strong] {
            let selector = PolicySelector::new(*policy);

            // Normal period should return the policy as-is
            TimeEpoch::set_month_boundary_preparation(false);
            assert_eq!(selector.effective_policy(), *policy);

            // Boundary period should always return Strong
            TimeEpoch::set_month_boundary_preparation(true);
            assert_eq!(selector.effective_policy(), HmacPolicy::Strong);
        }

        // Cleanup
        TimeEpoch::set_month_boundary_preparation(false);
    }
}
