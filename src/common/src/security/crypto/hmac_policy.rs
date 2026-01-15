#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! HMAC Policy Framework
//!
//! This module implements the three-tier HMAC policy framework for the Buckwild
//! frequency hopping network protocol, providing negotiation and validation.
//!
//! # Policy Selection Logic (Per Specification)
//!
//! The HMAC policy negotiation follows these rules from `design/protocol/02-core-definitions.md`:
//!
//! ## Three-Tier Policies
//!
//! - **LIGHT (1)**: 64-bit HMAC-SHA256, 128-bit key (8 bytes output)
//!   - Minimal authentication overhead for high-performance scenarios
//!   - Suitable for data packets in trusted environments
//!
//! - **MEDIUM (2)**: 128-bit HMAC-SHA256, 256-bit key (16 bytes output)
//!   - Standard authentication for control packets
//!   - Default minimum policy for new connections
//!   - Balance of security and performance
//!
//! - **STRONG (3)**: 256-bit HMAC-SHA256, 256-bit key (32 bytes output)
//!   - Maximum authentication strength for critical packets
//!   - Full SHA-256 output, no truncation
//!   - Required for key exchange and session establishment
//!
//! ## Policy Preference Ordering
//!
//! During negotiation, policies are evaluated in order of strength (strongest first):
//! 1. STRONG (3) - preferred if both sides support it
//! 2. MEDIUM (2) - fallback if STRONG unavailable
//! 3. LIGHT (1) - only if explicitly configured and above minimum
//!
//! ## Negotiation Algorithm
//!
//! 1. **Propose**: Initiator proposes strongest locally-supported policy
//! 2. **Match**: Find strongest policy supported by both peers
//! 3. **Validate**: Ensure matched policy meets minimum requirement
//! 4. **Accept/Reject**: Return matched policy or PolicyMismatch error
//!
//! ## Minimum Policy Enforcement
//!
//! - Default minimum: MEDIUM (2)
//! - Configurable per deployment security requirements
//! - Negotiated policy must be >= minimum or connection fails
//! - Both peers must agree on minimum to establish connection

use crate::error::security::{SecurityError, SecurityResult};
use crate::protocol::types::HmacPolicy;
use tracing::{info, warn};

/// Minimum acceptable HMAC policy (configurable)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimumPolicy(HmacPolicy);

impl MinimumPolicy {
    /// Create a new minimum policy requirement
    pub fn new(policy: HmacPolicy) -> Self {
        Self(policy)
    }

    /// Get the policy value
    pub fn policy(&self) -> HmacPolicy {
        self.0
    }

    /// Check if a proposed policy meets the minimum requirement
    pub fn accepts(&self, proposed: HmacPolicy) -> bool {
        proposed >= self.0
    }
}

impl Default for MinimumPolicy {
    /// Default minimum policy is MEDIUM per design requirements
    fn default() -> Self {
        Self(HmacPolicy::Medium)
    }
}

/// HMAC policy negotiation engine
///
/// Handles policy negotiation during connection establishment according to the
/// protocol specification: propose highest policy, accept if compatible with
/// minimum requirements.
#[derive(Debug, Clone)]
pub struct PolicyNegotiator {
    /// Locally supported policies (in order of preference, strongest first)
    supported_policies: Vec<HmacPolicy>,

    /// Minimum acceptable policy
    minimum_policy: MinimumPolicy,
}

impl PolicyNegotiator {
    /// Create a new policy negotiator with all policies supported
    pub fn new() -> Self {
        Self {
            supported_policies: vec![HmacPolicy::Strong, HmacPolicy::Medium, HmacPolicy::Light],
            minimum_policy: MinimumPolicy::default(),
        }
    }

    /// Create a new policy negotiator with specific supported policies
    pub fn with_policies(policies: Vec<HmacPolicy>) -> Self {
        let mut sorted_policies = policies;
        sorted_policies.sort_by(|a, b| b.cmp(a)); // Strongest first

        Self {
            supported_policies: sorted_policies,
            minimum_policy: MinimumPolicy::default(),
        }
    }

    /// Set the minimum acceptable policy
    pub fn with_minimum_policy(mut self, minimum: HmacPolicy) -> Self {
        self.minimum_policy = MinimumPolicy::new(minimum);
        self
    }

    /// Get the proposed policy (highest supported)
    pub fn propose_policy(&self) -> Option<HmacPolicy> {
        self.supported_policies.first().copied()
    }

    /// Negotiate policy with remote peer
    ///
    /// Returns the negotiated policy if compatible, or PolicyMismatch error if
    /// no common policy meets the minimum requirement.
    ///
    /// # Policy Selection Logic
    ///
    /// The negotiation follows this algorithm:
    ///
    /// 1. **Iterate in preference order**: Walk through local policies from strongest to weakest
    ///    (STRONG → MEDIUM → LIGHT)
    /// 2. **Find common support**: For each local policy, check if remote peer supports it
    /// 3. **Validate minimum**: Ensure the matched policy meets the minimum requirement
    /// 4. **Return first match**: The first (strongest) policy meeting all criteria is selected
    ///
    /// # Examples
    ///
    /// ```text
    /// Local: [STRONG, MEDIUM, LIGHT], Minimum: MEDIUM, Remote: [MEDIUM, LIGHT]
    /// → Negotiated: MEDIUM (strongest common policy above minimum)
    ///
    /// Local: [STRONG, MEDIUM, LIGHT], Minimum: MEDIUM, Remote: [LIGHT]
    /// → Error: PolicyMismatch (no common policy meets minimum)
    ///
    /// Local: [STRONG, MEDIUM], Minimum: MEDIUM, Remote: [STRONG, MEDIUM, LIGHT]
    /// → Negotiated: STRONG (strongest common policy)
    /// ```
    pub fn negotiate(&self, remote_policies: &[HmacPolicy]) -> SecurityResult<HmacPolicy> {
        // STEP 1: Find strongest policy supported by both sides
        // Local policies are pre-sorted strongest-first (STRONG → MEDIUM → LIGHT)
        for local_policy in &self.supported_policies {
            if remote_policies.contains(local_policy) {
                // STEP 2: Check if negotiated policy meets minimum requirement
                if self.minimum_policy.accepts(*local_policy) {
                    info!(
                        policy = ?local_policy,
                        "HMAC policy negotiated successfully"
                    );
                    return Ok(*local_policy);
                }
                warn!(
                    proposed = ?local_policy,
                    minimum = ?self.minimum_policy.policy(),
                    "Negotiated policy below minimum requirement"
                );
            }
        }

        // STEP 3: No compatible policy found - connection must fail
        Err(SecurityError::policy_mismatch(format!(
            "No compatible HMAC policy (local: {:?}, remote: {:?}, minimum: {:?})",
            self.supported_policies,
            remote_policies,
            self.minimum_policy.policy()
        )))
    }

    /// Validate that a proposed policy is acceptable
    pub fn validate_policy(&self, policy: HmacPolicy) -> SecurityResult<()> {
        if !self.supported_policies.contains(&policy) {
            return Err(SecurityError::policy_mismatch(format!(
                "Policy {:?} not in supported list: {:?}",
                policy, self.supported_policies
            )));
        }

        if !self.minimum_policy.accepts(policy) {
            return Err(SecurityError::policy_mismatch(format!(
                "Policy {:?} below minimum requirement: {:?}",
                policy,
                self.minimum_policy.policy()
            )));
        }

        Ok(())
    }

    /// Serialize supported policies for transmission
    pub fn serialize_policies(&self) -> Vec<u8> {
        self.supported_policies
            .iter()
            .map(|p| p.as_byte())
            .collect()
    }

    /// Deserialize policies from wire format
    pub fn deserialize_policies(data: &[u8]) -> SecurityResult<Vec<HmacPolicy>> {
        let mut policies = Vec::with_capacity(data.len());

        for &byte in data {
            if let Some(policy) = HmacPolicy::from_byte(byte) {
                policies.push(policy);
            } else {
                return Err(SecurityError::invalid_parameter(format!(
                    "Invalid HMAC policy byte: {}",
                    byte
                )));
            }
        }

        if policies.is_empty() {
            return Err(SecurityError::invalid_parameter(
                "No policies in serialized data".to_string(),
            ));
        }

        Ok(policies)
    }

    /// Get supported policies
    pub fn supported_policies(&self) -> &[HmacPolicy] {
        &self.supported_policies
    }

    /// Get minimum policy
    pub fn minimum_policy(&self) -> HmacPolicy {
        self.minimum_policy.policy()
    }
}

impl Default for PolicyNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy mismatch handler for connection establishment
///
/// Coordinates the response to policy mismatches during handshake according
/// to the protocol specification.
#[derive(Debug)]
pub struct PolicyMismatchHandler {
    /// Timeout for connection closure after mismatch
    connection_timeout_ms: u64,
}

impl PolicyMismatchHandler {
    /// Create a new policy mismatch handler
    pub fn new(connection_timeout_ms: u64) -> Self {
        Self {
            connection_timeout_ms,
        }
    }

    /// Handle policy mismatch during handshake
    ///
    /// Returns error code for RST packet and timeout duration for connection closure
    pub fn handle_mismatch(
        &self,
        local_policies: &[HmacPolicy],
        remote_policies: &[HmacPolicy],
        minimum_policy: HmacPolicy,
    ) -> (u8, std::time::Duration) {
        warn!(
            local_policies = ?local_policies,
            remote_policies = ?remote_policies,
            minimum_policy = ?minimum_policy,
            "HMAC policy mismatch detected"
        );

        // Return PolicyMismatch error code and connection timeout
        const POLICY_MISMATCH_ERROR_CODE: u8 = 0x04; // From protocol specification
        let timeout = std::time::Duration::from_millis(self.connection_timeout_ms);

        (POLICY_MISMATCH_ERROR_CODE, timeout)
    }

    /// Get connection timeout duration
    pub fn connection_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.connection_timeout_ms)
    }
}

impl Default for PolicyMismatchHandler {
    fn default() -> Self {
        const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 30_000; // 30 seconds
        Self::new(DEFAULT_CONNECTION_TIMEOUT_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimum_policy_default() {
        let min_policy = MinimumPolicy::default();
        assert_eq!(min_policy.policy(), HmacPolicy::Medium);
    }

    #[test]
    fn test_minimum_policy_accepts() {
        let min_policy = MinimumPolicy::new(HmacPolicy::Medium);

        assert!(min_policy.accepts(HmacPolicy::Strong));
        assert!(min_policy.accepts(HmacPolicy::Medium));
        assert!(!min_policy.accepts(HmacPolicy::Light));
    }

    #[test]
    fn test_policy_negotiator_default() {
        let negotiator = PolicyNegotiator::new();

        assert_eq!(negotiator.supported_policies.len(), 3);
        assert_eq!(negotiator.minimum_policy.policy(), HmacPolicy::Medium);
    }

    #[test]
    fn test_policy_negotiator_propose_strongest() {
        let negotiator = PolicyNegotiator::new();

        assert_eq!(negotiator.propose_policy(), Some(HmacPolicy::Strong));
    }

    #[test]
    fn test_policy_negotiation_success_strong() {
        let negotiator = PolicyNegotiator::new();
        let remote_policies = vec![HmacPolicy::Strong, HmacPolicy::Medium, HmacPolicy::Light];

        let result = negotiator.negotiate(&remote_policies);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HmacPolicy::Strong);
    }

    #[test]
    fn test_policy_negotiation_success_medium() {
        let negotiator = PolicyNegotiator::new();
        let remote_policies = vec![HmacPolicy::Medium, HmacPolicy::Light];

        let result = negotiator.negotiate(&remote_policies);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HmacPolicy::Medium);
    }

    #[test]
    fn test_policy_negotiation_failure_below_minimum() {
        let negotiator = PolicyNegotiator::new();
        let remote_policies = vec![HmacPolicy::Light];

        let result = negotiator.negotiate(&remote_policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_negotiation_failure_no_overlap() {
        let negotiator = PolicyNegotiator::with_policies(vec![HmacPolicy::Strong]);
        let remote_policies = vec![HmacPolicy::Light];

        let result = negotiator.negotiate(&remote_policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_negotiation_with_custom_minimum() {
        let negotiator = PolicyNegotiator::new().with_minimum_policy(HmacPolicy::Strong);
        let remote_policies = vec![HmacPolicy::Medium, HmacPolicy::Light];

        let result = negotiator.negotiate(&remote_policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policy_success() {
        let negotiator = PolicyNegotiator::new();

        assert!(negotiator.validate_policy(HmacPolicy::Strong).is_ok());
        assert!(negotiator.validate_policy(HmacPolicy::Medium).is_ok());
    }

    #[test]
    fn test_validate_policy_below_minimum() {
        let negotiator = PolicyNegotiator::new();

        assert!(negotiator.validate_policy(HmacPolicy::Light).is_err());
    }

    #[test]
    fn test_validate_policy_not_supported() {
        let negotiator = PolicyNegotiator::with_policies(vec![HmacPolicy::Strong]);

        assert!(negotiator.validate_policy(HmacPolicy::Medium).is_err());
    }

    #[test]
    fn test_serialize_deserialize_policies() {
        let negotiator = PolicyNegotiator::new();
        let serialized = negotiator.serialize_policies();

        let deserialized = PolicyNegotiator::deserialize_policies(&serialized);
        assert!(deserialized.is_ok());

        let policies = deserialized.unwrap();
        assert_eq!(policies.len(), 3);
        assert!(policies.contains(&HmacPolicy::Strong));
        assert!(policies.contains(&HmacPolicy::Medium));
        assert!(policies.contains(&HmacPolicy::Light));
    }

    #[test]
    fn test_deserialize_invalid_policy_byte() {
        let invalid_data = vec![1, 2, 99]; // 99 is invalid
        let result = PolicyNegotiator::deserialize_policies(&invalid_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty_data() {
        let empty_data = vec![];
        let result = PolicyNegotiator::deserialize_policies(&empty_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_policy_mismatch_handler() {
        let handler = PolicyMismatchHandler::new(30_000);
        let local = vec![HmacPolicy::Strong, HmacPolicy::Medium];
        let remote = vec![HmacPolicy::Light];

        let (error_code, timeout) = handler.handle_mismatch(&local, &remote, HmacPolicy::Medium);

        assert_eq!(error_code, 0x04);
        assert_eq!(timeout.as_millis(), 30_000);
    }

    #[test]
    fn test_policy_mismatch_handler_default() {
        let handler = PolicyMismatchHandler::default();
        let timeout = handler.connection_timeout();

        assert_eq!(timeout.as_millis(), 30_000);
    }

    #[test]
    fn test_negotiation_prefers_strongest_common() {
        let negotiator = PolicyNegotiator::with_policies(vec![
            HmacPolicy::Strong,
            HmacPolicy::Medium,
            HmacPolicy::Light,
        ]);

        // Remote supports Medium and Light, should choose Medium
        let remote = vec![HmacPolicy::Medium, HmacPolicy::Light];
        let result = negotiator.negotiate(&remote);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HmacPolicy::Medium);
    }

    #[test]
    fn test_with_minimum_policy_filters_negotiation() {
        let negotiator = PolicyNegotiator::new().with_minimum_policy(HmacPolicy::Medium);

        // Even though Light is supported by both, minimum is Medium
        let remote = vec![HmacPolicy::Light];
        let result = negotiator.negotiate(&remote);

        assert!(result.is_err());
    }
}
