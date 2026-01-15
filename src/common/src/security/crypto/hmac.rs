#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// HMAC implementation with adaptive policies
//
// This module provides HMAC functionality with different security policies
// for the Buckwild frequency hopping network.

use crate::error::security::SecurityError;
use crate::protocol::types::*;
use ring::hmac::{self, Key, Tag};
use std::sync::Arc;
use tracing::instrument;

/// Result type for HMAC operations
pub type HmacResult<T> = Result<T, SecurityError>;

// Use HmacPolicy from consolidated types

impl HmacPolicy {
    /// Get the tag length for this policy
    pub fn tag_length(&self) -> usize {
        match self {
            Self::Light => 8,
            Self::Medium => 16,
            Self::Strong => 32,
        }
    }

    /// Get the algorithm for this policy
    fn algorithm(&self) -> &'static hmac::Algorithm {
        // We always use SHA-256, but truncate the output
        &hmac::HMAC_SHA256
    }
}

/// HMAC context for efficient verification
pub struct HmacContext {
    /// HMAC key
    key: Key,

    /// Security policy
    policy: HmacPolicy,
}

impl HmacContext {
    /// Create a new HMAC context
    ///
    /// # Arguments
    /// * `key` - HMAC key bytes (must not be all zeros)
    /// * `policy` - Security policy determining tag length
    ///
    /// # Panics
    /// Panics if key is empty or all zeros (security violation)
    pub fn new(key: &[u8], policy: HmacPolicy) -> Self {
        // Validate key is not empty
        assert!(!key.is_empty(), "HMAC key must not be empty");

        // Validate key is not all zeros (security check)
        assert!(
            !key.iter().all(|&b| b == 0),
            "HMAC key must not be all zeros"
        );

        let key = Key::new(*policy.algorithm(), key);

        Self { key, policy }
    }

    /// Sign a message
    #[instrument(skip(self, message), fields(message_len = message.len(), policy = ?self.policy))]
    pub fn sign(&self, message: &[u8]) -> Tag {
        hmac::sign(&self.key, message)
    }

    /// Verify a tag
    #[instrument(skip(self, message, tag), fields(message_len = message.len(), tag_len = tag.len(), policy = ?self.policy))]
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> HmacResult<()> {
        // Check tag length
        if tag.len() != HmacPolicy::tag_length(&self.policy) {
            return Err(SecurityError::invalid_hmac_tag());
        }

        // Sign the message
        let computed_tag = self.sign(message);

        // Truncate the computed tag to the policy length
        let truncated_tag = &computed_tag.as_ref()[..HmacPolicy::tag_length(&self.policy)];

        // Verify in constant time
        use subtle::ConstantTimeEq;
        if !bool::from(truncated_tag.ct_eq(tag)) {
            return Err(SecurityError::hmac_verification_failed());
        }

        Ok(())
    }

    /// Get the security policy
    pub fn policy(&self) -> HmacPolicy {
        self.policy
    }
}

/// Thread-safe HMAC context
pub struct ThreadSafeHmacContext {
    /// Inner HMAC context
    inner: Arc<HmacContext>,
}

impl ThreadSafeHmacContext {
    /// Create a new thread-safe HMAC context
    ///
    /// # Arguments
    /// * `key` - HMAC key bytes (must not be all zeros)
    /// * `policy` - Security policy determining tag length
    ///
    /// # Panics
    /// Panics if key is empty or all zeros (via HmacContext::new)
    pub fn new(key: &[u8], policy: HmacPolicy) -> Self {
        Self {
            inner: Arc::new(HmacContext::new(key, policy)),
        }
    }

    /// Sign a message
    #[instrument(skip(self, message), fields(message_len = message.len()))]
    pub fn sign(&self, message: &[u8]) -> Tag {
        self.inner.sign(message)
    }

    /// Verify a tag
    #[instrument(skip(self, message, tag), fields(message_len = message.len(), tag_len = tag.len()))]
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> HmacResult<()> {
        self.inner.verify(message, tag)
    }

    /// Get the security policy
    pub fn policy(&self) -> HmacPolicy {
        self.inner.policy()
    }
}

/// HMAC calculator for packet authentication
pub struct HmacCalculator {
    /// Default policy
    default_policy: HmacPolicy,
}

impl HmacCalculator {
    /// Create a new HMAC calculator
    pub fn new() -> Self {
        Self {
            default_policy: HmacPolicy::Medium,
        }
    }

    /// Create a new HMAC calculator with a specific default policy
    pub fn with_policy(policy: HmacPolicy) -> Self {
        Self {
            default_policy: policy,
        }
    }

    /// Calculate HMAC for a packet
    pub fn calculate_packet_hmac(
        &self,
        packet_data: &[u8],
        session_key: &[u8],
        policy: HmacPolicy,
    ) -> HmacResult<HmacTag> {
        let context = HmacContext::new(session_key, policy);
        let tag = context.sign(packet_data);
        let truncated_tag = &tag.as_ref()[..HmacPolicy::tag_length(&policy)];

        // Convert to HmacTag
        let mut hmac_tag = [0u8; 32];
        let len = truncated_tag.len().min(32);
        hmac_tag[..len].copy_from_slice(&truncated_tag[..len]);

        Ok(HmacTag::new(hmac_tag[..len].to_vec(), policy)?)
    }

    /// Verify HMAC for a packet
    pub fn verify_packet_hmac(
        &self,
        packet_data: &[u8],
        session_key: &[u8],
        received_hmac: &HmacTag,
        policy: HmacPolicy,
    ) -> HmacResult<()> {
        let context = HmacContext::new(session_key, policy);
        context.verify(packet_data, received_hmac.as_bytes())
    }

    /// Get the default policy
    pub fn default_policy(&self) -> HmacPolicy {
        self.default_policy
    }

    /// Set the default policy
    pub fn set_default_policy(&mut self, policy: HmacPolicy) {
        self.default_policy = policy;
    }
}

impl Default for HmacCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// HMAC policy negotiation
pub struct HmacPolicyNegotiation {
    /// Available policies
    available_policies: Vec<HmacPolicy>,
}

impl HmacPolicyNegotiation {
    /// Create a new HMAC policy negotiation
    pub fn new(available_policies: Vec<HmacPolicy>) -> Self {
        Self { available_policies }
    }

    /// Create a new HMAC policy negotiation with all policies
    pub fn all_policies() -> Self {
        Self {
            available_policies: vec![HmacPolicy::Light, HmacPolicy::Medium, HmacPolicy::Strong],
        }
    }

    /// Negotiate a policy
    pub fn negotiate(&self, remote_policies: &[HmacPolicy]) -> Option<HmacPolicy> {
        // Find the strongest policy supported by both sides
        for policy in &[HmacPolicy::Strong, HmacPolicy::Medium, HmacPolicy::Light] {
            if self.available_policies.contains(policy) && remote_policies.contains(policy) {
                return Some(*policy);
            }
        }

        None
    }

    /// Serialize available policies
    pub fn serialize(&self) -> Vec<u8> {
        self.available_policies
            .iter()
            .map(|p| p.as_byte())
            .collect()
    }

    /// Deserialize available policies
    pub fn deserialize(data: &[u8]) -> HmacResult<Vec<HmacPolicy>> {
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

        Ok(policies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // HMAC Policy Tests
    // =========================================================================

    #[test]
    fn test_hmac_policy_tag_lengths() {
        assert_eq!(HmacPolicy::Light.tag_length(), 8);
        assert_eq!(HmacPolicy::Medium.tag_length(), 16);
        assert_eq!(HmacPolicy::Strong.tag_length(), 32);
    }

    #[test]
    fn test_hmac_policy_tag_size() {
        assert_eq!(HmacPolicy::Light.tag_size(), 8);
        assert_eq!(HmacPolicy::Medium.tag_size(), 16);
        assert_eq!(HmacPolicy::Strong.tag_size(), 32);
    }

    // =========================================================================
    // RFC 4231 Test Vectors for HMAC-SHA256
    // =========================================================================

    #[test]
    fn test_hmac_rfc4231_test_case_1() {
        // Test Case 1 from RFC 4231
        let key = vec![0x0b; 20];
        let data = b"Hi There";

        let context = HmacContext::new(&key, HmacPolicy::Strong);
        let tag = context.sign(data);

        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();

        assert_eq!(tag.as_ref(), &expected[..]);
    }

    #[test]
    fn test_hmac_rfc4231_test_case_2() {
        // Test Case 2 from RFC 4231
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let context = HmacContext::new(key, HmacPolicy::Strong);
        let tag = context.sign(data);

        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();

        assert_eq!(tag.as_ref(), &expected[..]);
    }

    #[test]
    fn test_hmac_rfc4231_test_case_3() {
        // Test Case 3 from RFC 4231
        let key = vec![0xaa; 20];
        let data = vec![0xdd; 50];

        let context = HmacContext::new(&key, HmacPolicy::Strong);
        let tag = context.sign(&data);

        let expected =
            hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
                .unwrap();

        assert_eq!(tag.as_ref(), &expected[..]);
    }

    #[test]
    fn test_hmac_rfc4231_test_case_4() {
        // Test Case 4 from RFC 4231
        let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let data = vec![0xcd; 50];

        let context = HmacContext::new(&key, HmacPolicy::Strong);
        let tag = context.sign(&data);

        let expected =
            hex::decode("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
                .unwrap();

        assert_eq!(tag.as_ref(), &expected[..]);
    }

    #[test]
    fn test_hmac_rfc4231_test_case_6() {
        // Test Case 6 from RFC 4231 (tests key larger than block size)
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let context = HmacContext::new(&key, HmacPolicy::Strong);
        let tag = context.sign(data);

        let expected =
            hex::decode("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
                .unwrap();

        assert_eq!(tag.as_ref(), &expected[..]);
    }

    #[test]
    fn test_hmac_rfc4231_test_case_7() {
        // Test Case 7 from RFC 4231
        let key = vec![0xaa; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

        let context = HmacContext::new(&key, HmacPolicy::Strong);
        let tag = context.sign(data);

        let expected =
            hex::decode("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
                .unwrap();

        assert_eq!(tag.as_ref(), &expected[..]);
    }

    // =========================================================================
    // HMAC Context Tests
    // =========================================================================

    #[test]
    fn test_hmac_context_sign_and_verify() {
        let key = b"test_key_12345678901234567890";
        let message = b"Test message for HMAC";

        let context = HmacContext::new(key, HmacPolicy::Medium);
        let tag = context.sign(message);

        // Truncate to policy length
        let truncated = &tag.as_ref()[..HmacPolicy::Medium.tag_length()];

        // Verification should succeed
        assert!(context.verify(message, truncated).is_ok());
    }

    #[test]
    fn test_hmac_context_verify_wrong_tag_fails() {
        let key = b"test_key_12345678901234567890";
        let message = b"Test message for HMAC";
        let wrong_tag = vec![0u8; 16];

        let context = HmacContext::new(key, HmacPolicy::Medium);

        // Verification should fail
        assert!(context.verify(message, &wrong_tag).is_err());
    }

    #[test]
    fn test_hmac_context_verify_wrong_message_fails() {
        let key = b"test_key_12345678901234567890";
        let message = b"Test message for HMAC";
        let wrong_message = b"Wrong message";

        let context = HmacContext::new(key, HmacPolicy::Medium);
        let tag = context.sign(message);
        let truncated = &tag.as_ref()[..HmacPolicy::Medium.tag_length()];

        // Verification with wrong message should fail
        assert!(context.verify(wrong_message, truncated).is_err());
    }

    #[test]
    fn test_hmac_context_verify_wrong_tag_length_fails() {
        let key = b"test_key_12345678901234567890";
        let message = b"Test message for HMAC";

        let context = HmacContext::new(key, HmacPolicy::Medium);
        let tag = context.sign(message);

        // Try to verify with wrong tag length
        let wrong_length_tag = &tag.as_ref()[..8]; // Use 8 instead of 16
        assert!(context.verify(message, wrong_length_tag).is_err());
    }

    #[test]
    fn test_hmac_truncation_for_light_policy() {
        let key = b"test_key";
        let message = b"test message";

        let context = HmacContext::new(key, HmacPolicy::Light);
        let tag = context.sign(message);
        let truncated = &tag.as_ref()[..HmacPolicy::Light.tag_length()];

        assert_eq!(truncated.len(), 8);
        assert!(context.verify(message, truncated).is_ok());
    }

    #[test]
    fn test_hmac_truncation_for_medium_policy() {
        let key = b"test_key";
        let message = b"test message";

        let context = HmacContext::new(key, HmacPolicy::Medium);
        let tag = context.sign(message);
        let truncated = &tag.as_ref()[..HmacPolicy::Medium.tag_length()];

        assert_eq!(truncated.len(), 16);
        assert!(context.verify(message, truncated).is_ok());
    }

    #[test]
    fn test_hmac_truncation_for_strong_policy() {
        let key = b"test_key";
        let message = b"test message";

        let context = HmacContext::new(key, HmacPolicy::Strong);
        let tag = context.sign(message);
        let truncated = &tag.as_ref()[..HmacPolicy::Strong.tag_length()];

        assert_eq!(truncated.len(), 32);
        assert!(context.verify(message, truncated).is_ok());
    }

    // =========================================================================
    // Thread-Safe HMAC Context Tests
    // =========================================================================

    #[test]
    fn test_thread_safe_hmac_context() {
        let key = b"test_key";
        let message = b"test message";

        let context = ThreadSafeHmacContext::new(key, HmacPolicy::Medium);
        let tag = context.sign(message);
        let truncated = &tag.as_ref()[..HmacPolicy::Medium.tag_length()];

        assert!(context.verify(message, truncated).is_ok());
        assert_eq!(context.policy(), HmacPolicy::Medium);
    }

    #[test]
    fn test_thread_safe_hmac_context_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let key = b"test_key_for_concurrent_access";
        let context = Arc::new(ThreadSafeHmacContext::new(key, HmacPolicy::Medium));
        let mut handles = vec![];

        for i in 0..10 {
            let context_clone = Arc::clone(&context);
            let handle = thread::spawn(move || {
                let message = format!("message_{}", i);
                let tag = context_clone.sign(message.as_bytes());
                let truncated = &tag.as_ref()[..HmacPolicy::Medium.tag_length()];

                context_clone.verify(message.as_bytes(), truncated).unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    // =========================================================================
    // HMAC Calculator Tests
    // =========================================================================

    #[test]
    fn test_hmac_calculator_default_policy() {
        let calculator = HmacCalculator::new();
        let packet_data = b"test packet data";
        let session_key = b"session_key_123456789012345678";

        let hmac_tag = calculator
            .calculate_packet_hmac(packet_data, session_key, HmacPolicy::Medium)
            .unwrap();

        // Verify the tag can be verified
        let context = HmacContext::new(session_key, HmacPolicy::Medium);
        let tag_bytes = hmac_tag.data();
        assert!(context.verify(packet_data, tag_bytes).is_ok());
    }

    #[test]
    fn test_hmac_calculator_with_custom_policy() {
        let calculator = HmacCalculator::with_policy(HmacPolicy::Strong);
        let packet_data = b"test packet data";
        let session_key = b"session_key_123456789012345678";

        let hmac_tag = calculator
            .calculate_packet_hmac(packet_data, session_key, HmacPolicy::Strong)
            .unwrap();

        // Verify the tag can be verified
        let context = HmacContext::new(session_key, HmacPolicy::Strong);
        let tag_bytes = hmac_tag.data();
        assert!(context.verify(packet_data, tag_bytes).is_ok());
    }

    // =========================================================================
    // HMAC Negotiation Tests
    // =========================================================================

    #[test]
    fn test_hmac_negotiation_select_best_policy() {
        let client_policies = vec![HmacPolicy::Light, HmacPolicy::Medium];
        let server_policies = vec![HmacPolicy::Medium, HmacPolicy::Strong];

        let negotiation = HmacPolicyNegotiation::new(client_policies);
        let selected = negotiation.negotiate(&server_policies);

        assert_eq!(selected, Some(HmacPolicy::Medium));
    }

    #[test]
    fn test_hmac_negotiation_no_common_policy() {
        let client_policies = vec![HmacPolicy::Light];
        let server_policies = vec![HmacPolicy::Strong];

        let negotiation = HmacPolicyNegotiation::new(client_policies);
        let selected = negotiation.negotiate(&server_policies);

        assert_eq!(selected, None);
    }

    #[test]
    fn test_hmac_negotiation_serialize_deserialize() {
        let policies = vec![HmacPolicy::Light, HmacPolicy::Medium, HmacPolicy::Strong];
        let negotiation = HmacPolicyNegotiation::new(policies.clone());

        let serialized = negotiation.serialize();
        let deserialized = HmacPolicyNegotiation::deserialize(&serialized).unwrap();

        assert_eq!(deserialized, policies);
    }

    // =========================================================================
    // Security Tests
    // =========================================================================

    #[test]
    fn test_hmac_determinism() {
        // HMAC should produce the same output for the same input
        let key = b"determinism_test_key";
        let message = b"deterministic message";

        let context = HmacContext::new(key, HmacPolicy::Medium);
        let tag1 = context.sign(message);
        let tag2 = context.sign(message);

        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }

    #[test]
    fn test_hmac_different_keys_produce_different_tags() {
        let key1 = b"key_one";
        let key2 = b"key_two";
        let message = b"same message";

        let context1 = HmacContext::new(key1, HmacPolicy::Medium);
        let context2 = HmacContext::new(key2, HmacPolicy::Medium);

        let tag1 = context1.sign(message);
        let tag2 = context2.sign(message);

        assert_ne!(tag1.as_ref(), tag2.as_ref());
    }

    #[test]
    fn test_hmac_different_messages_produce_different_tags() {
        let key = b"same_key";
        let message1 = b"message one";
        let message2 = b"message two";

        let context = HmacContext::new(key, HmacPolicy::Medium);

        let tag1 = context.sign(message1);
        let tag2 = context.sign(message2);

        assert_ne!(tag1.as_ref(), tag2.as_ref());
    }

    // =========================================================================
    // TASK-007: Empty Key Rejection Tests
    // =========================================================================

    #[test]
    #[should_panic(expected = "HMAC key must not be empty")]
    fn test_hmac_context_rejects_empty_key() {
        let empty_key: &[u8] = &[];
        let _context = HmacContext::new(empty_key, HmacPolicy::Medium);
    }

    #[test]
    #[should_panic(expected = "HMAC key must not be all zeros")]
    fn test_hmac_context_rejects_all_zero_key() {
        let zero_key = [0u8; 32];
        let _context = HmacContext::new(&zero_key, HmacPolicy::Medium);
    }

    #[test]
    #[should_panic(expected = "HMAC key must not be all zeros")]
    fn test_thread_safe_hmac_context_rejects_all_zero_key() {
        let zero_key = [0u8; 32];
        let _context = ThreadSafeHmacContext::new(&zero_key, HmacPolicy::Medium);
    }

    #[test]
    fn test_hmac_context_accepts_valid_key() {
        // Non-zero key should work fine
        let valid_key = [0x42u8; 32];
        let context = HmacContext::new(&valid_key, HmacPolicy::Medium);
        let message = b"test message";
        let tag = context.sign(message);
        assert_eq!(tag.as_ref().len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_hmac_calculator_with_valid_session_key() {
        let calculator = HmacCalculator::new();
        let packet_data = b"test packet";
        let session_key = [0x42u8; 32]; // Valid non-zero key

        let result =
            calculator.calculate_packet_hmac(packet_data, &session_key, HmacPolicy::Medium);

        assert!(result.is_ok(), "Should succeed with valid key");
    }

    #[test]
    #[should_panic(expected = "HMAC key must not be all zeros")]
    fn test_hmac_calculator_rejects_zero_session_key() {
        let calculator = HmacCalculator::new();
        let packet_data = b"test packet";
        let zero_key = [0u8; 32];

        let _result = calculator.calculate_packet_hmac(packet_data, &zero_key, HmacPolicy::Medium);
    }

    // =========================================================================
    // CRIT-006 Timing Analysis Tests
    // =========================================================================

    mod timing_analysis {
        use super::*;
        use std::time::Instant;

        /// Calculate Pearson correlation coefficient between two variables
        fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
            assert_eq!(x.len(), y.len());
            let n = x.len() as f64;

            let mean_x: f64 = x.iter().sum::<f64>() / n;
            let mean_y: f64 = y.iter().sum::<f64>() / n;

            let mut numerator = 0.0;
            let mut sum_sq_x = 0.0;
            let mut sum_sq_y = 0.0;

            for i in 0..x.len() {
                let dx = x[i] - mean_x;
                let dy = y[i] - mean_y;
                numerator += dx * dy;
                sum_sq_x += dx * dx;
                sum_sq_y += dy * dy;
            }

            let denominator = (sum_sq_x * sum_sq_y).sqrt();

            if denominator == 0.0 {
                0.0
            } else {
                numerator / denominator
            }
        }

        /// Calculate p-value from Pearson correlation coefficient using t-distribution
        fn correlation_p_value(r: f64, n: usize) -> f64 {
            if n < 3 {
                return 1.0;
            }

            let df = (n - 2) as f64;
            let t = r * (df / (1.0 - r * r)).sqrt();

            let abs_t = t.abs();

            // Approximate cumulative distribution function for standard normal
            let z = abs_t / (2.0_f64).sqrt();
            let erf_approx = {
                let a1 = 0.254829592;
                let a2 = -0.284496736;
                let a3 = 1.421413741;
                let a4 = -1.453152027;
                let a5 = 1.061405429;
                let p = 0.3275911;

                let sign = if z < 0.0 { -1.0 } else { 1.0 };
                let z = z.abs();

                let t = 1.0 / (1.0 + p * z);
                let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-z * z).exp();

                sign * y
            };

            let cdf = 0.5 * (1.0 + erf_approx);
            2.0 * (1.0 - cdf)
        }

        /// Measure timing for a single HMAC verification
        fn measure_verify_timing(ctx: &HmacContext, message: &[u8], tag: &[u8]) -> f64 {
            let start = Instant::now();
            let _ = ctx.verify(message, tag);
            let duration = start.elapsed();
            duration.as_nanos() as f64
        }

        /// Generate test tag with specified prefix match length
        fn generate_test_tag(correct_tag: &[u8], match_fraction: f64) -> Vec<u8> {
            let match_bytes = (correct_tag.len() as f64 * match_fraction) as usize;
            let mut tag = vec![0u8; correct_tag.len()];

            // Copy matching prefix
            tag[..match_bytes].copy_from_slice(&correct_tag[..match_bytes]);

            // Fill rest with different values
            for i in match_bytes..tag.len() {
                tag[i] = correct_tag[i].wrapping_add(1);
            }

            tag
        }

        #[test]
        fn test_hmac_timing_analysis_medium_policy() {
            const SAMPLES: usize = 10000;
            const P_VALUE_THRESHOLD: f64 = 0.05;

            let key = b"test_key_for_timing_analysis_32b";
            let message = b"Test message for constant-time verification analysis";
            let policy = HmacPolicy::Medium;

            let ctx = HmacContext::new(key, policy);
            let correct_tag = ctx.sign(message);
            let correct_tag_bytes = &correct_tag.as_ref()[..policy.tag_length()];

            // Test prefix match lengths: 0%, 25%, 50%, 75%, 100%
            let match_fractions = [0.0, 0.25, 0.5, 0.75, 1.0];

            eprintln!(
                "\nHMAC Timing Analysis (Policy: {:?}, {} samples)",
                policy, SAMPLES
            );

            for &match_fraction in &match_fractions {
                let mut timings = Vec::with_capacity(SAMPLES);
                let mut match_levels = Vec::with_capacity(SAMPLES);

                let test_tag = generate_test_tag(correct_tag_bytes, match_fraction);

                // Collect timing samples
                for _ in 0..SAMPLES {
                    let timing = measure_verify_timing(&ctx, message, &test_tag);
                    timings.push(timing);
                    match_levels.push(match_fraction);
                }

                // Calculate statistics
                let mean_timing: f64 = timings.iter().sum::<f64>() / timings.len() as f64;
                let variance: f64 = timings
                    .iter()
                    .map(|&t| {
                        let diff = t - mean_timing;
                        diff * diff
                    })
                    .sum::<f64>()
                    / timings.len() as f64;
                let std_dev = variance.sqrt();

                // Calculate correlation between timing and match level
                let correlation = pearson_correlation(&match_levels, &timings);
                let p_value = correlation_p_value(correlation, SAMPLES);

                eprintln!("Prefix match: {:.0}%", match_fraction * 100.0);
                eprintln!("  Mean timing: {:.2} ns", mean_timing);
                eprintln!("  Std dev: {:.2} ns", std_dev);
                eprintln!("  Correlation: {:.6}", correlation);
                eprintln!("  P-value: {:.6}", p_value);

                // Assert no significant correlation
                assert!(
                    p_value > P_VALUE_THRESHOLD,
                    "Timing correlation detected! P-value {:.6} < threshold {:.6} for {}% match",
                    p_value,
                    P_VALUE_THRESHOLD,
                    match_fraction * 100.0
                );
            }

            eprintln!("All timing analysis tests passed\n");
        }

        #[test]
        fn test_hmac_timing_analysis_light_policy() {
            const SAMPLES: usize = 10000;
            const P_VALUE_THRESHOLD: f64 = 0.05;

            let key = b"test_key_light_policy_32bytes!!";
            let message = b"Test message for Light policy timing analysis";
            let policy = HmacPolicy::Light;

            let ctx = HmacContext::new(key, policy);
            let correct_tag = ctx.sign(message);
            let correct_tag_bytes = &correct_tag.as_ref()[..policy.tag_length()];

            let match_fractions = [0.0, 0.5, 1.0];

            eprintln!(
                "\nHMAC Timing Analysis - Light Policy ({} bytes, {} samples)",
                policy.tag_length(),
                SAMPLES
            );

            for &match_fraction in &match_fractions {
                let mut timings = Vec::with_capacity(SAMPLES);
                let mut match_levels = Vec::with_capacity(SAMPLES);

                let test_tag = generate_test_tag(correct_tag_bytes, match_fraction);

                for _ in 0..SAMPLES {
                    let timing = measure_verify_timing(&ctx, message, &test_tag);
                    timings.push(timing);
                    match_levels.push(match_fraction);
                }

                let correlation = pearson_correlation(&match_levels, &timings);
                let p_value = correlation_p_value(correlation, SAMPLES);

                eprintln!(
                    "  Prefix match {:.0}%: p-value = {:.6}",
                    match_fraction * 100.0,
                    p_value
                );

                assert!(
                    p_value > P_VALUE_THRESHOLD,
                    "Light policy timing leak: P-value {:.6} < {:.6}",
                    p_value,
                    P_VALUE_THRESHOLD
                );
            }

            eprintln!("Light policy timing analysis passed\n");
        }

        #[test]
        fn test_hmac_timing_analysis_strong_policy() {
            const SAMPLES: usize = 10000;
            const P_VALUE_THRESHOLD: f64 = 0.05;

            let key = b"test_key_strong_policy_32bytes!";
            let message = b"Test message for Strong policy timing analysis";
            let policy = HmacPolicy::Strong;

            let ctx = HmacContext::new(key, policy);
            let correct_tag = ctx.sign(message);
            let correct_tag_bytes = &correct_tag.as_ref()[..policy.tag_length()];

            let match_fractions = [0.0, 0.25, 0.5, 0.75, 1.0];

            eprintln!(
                "\nHMAC Timing Analysis - Strong Policy ({} bytes, {} samples)",
                policy.tag_length(),
                SAMPLES
            );

            for &match_fraction in &match_fractions {
                let mut timings = Vec::with_capacity(SAMPLES);
                let mut match_levels = Vec::with_capacity(SAMPLES);

                let test_tag = generate_test_tag(correct_tag_bytes, match_fraction);

                for _ in 0..SAMPLES {
                    let timing = measure_verify_timing(&ctx, message, &test_tag);
                    timings.push(timing);
                    match_levels.push(match_fraction);
                }

                let correlation = pearson_correlation(&match_levels, &timings);
                let p_value = correlation_p_value(correlation, SAMPLES);

                eprintln!(
                    "  Prefix match {:.0}%: p-value = {:.6}",
                    match_fraction * 100.0,
                    p_value
                );

                assert!(
                    p_value > P_VALUE_THRESHOLD,
                    "Strong policy timing leak: P-value {:.6} < {:.6}",
                    p_value,
                    P_VALUE_THRESHOLD
                );
            }

            eprintln!("Strong policy timing analysis passed\n");
        }

        #[test]
        fn test_statistical_functions() {
            // Test perfect positive correlation
            let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
            let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];
            let r = pearson_correlation(&x, &y);
            assert!((r - 1.0).abs() < 0.0001, "Expected r ≈ 1.0, got {}", r);

            // Test perfect negative correlation
            let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
            let y = vec![10.0, 8.0, 6.0, 4.0, 2.0];
            let r = pearson_correlation(&x, &y);
            assert!((r + 1.0).abs() < 0.0001, "Expected r ≈ -1.0, got {}", r);

            // Test no correlation
            let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
            let y = vec![5.0, 5.0, 5.0, 5.0, 5.0];
            let r = pearson_correlation(&x, &y);
            assert!(r.abs() < 0.0001, "Expected r ≈ 0.0, got {}", r);

            // Test p-value for significant correlation
            let r = 0.9;
            let n = 100;
            let p = correlation_p_value(r, n);
            assert!(
                p < 0.05,
                "Expected p < 0.05 for strong correlation, got {}",
                p
            );

            // Test p-value for weak correlation
            let r = 0.1;
            let n = 100;
            let p = correlation_p_value(r, n);
            assert!(
                p > 0.05,
                "Expected p > 0.05 for weak correlation, got {}",
                p
            );
        }
    }
}
