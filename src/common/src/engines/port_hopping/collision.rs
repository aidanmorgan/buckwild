#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Port Collision Resolution
//!
//! Handles deterministic port collision resolution when a calculated port
//! is already in use. Both peers must select the same alternative port
//! using a deterministic algorithm based on the session key and attempt number.
//!
//! **Protocol Reference**: design/protocol/13-edge-case-handling.md §Port Hopping Edge Cases

use ring::hmac;
use tracing::{debug, warn};

use crate::error::EngineError;
use crate::protocol::types::{Port, SessionKey};

/// Maximum collision resolution attempts before giving up
const MAX_COLLISION_ATTEMPTS: u32 = 10;

/// Port range for collision resolution
const MIN_PORT: u16 = 1024;
const MAX_PORT: u16 = 65535;
const PORT_RANGE: u32 = (MAX_PORT - MIN_PORT + 1) as u32;

/// Port collision detector
pub struct PortCollisionDetector {
    /// Session key for deterministic port derivation
    session_key: hmac::Key,
}

impl PortCollisionDetector {
    /// Create a new port collision detector with the session key
    pub fn new(session_key: &SessionKey) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, session_key.as_bytes());
        Self { session_key: key }
    }

    /// Derive an alternative port deterministically
    ///
    /// Both peers MUST call this with identical inputs to arrive at the same alternative port.
    ///
    /// # Arguments
    /// * `original_port` - The port that encountered a collision
    /// * `attempt_number` - Zero-based attempt counter (0 = first alternative, 1 = second, etc.)
    ///
    /// # Returns
    /// Alternative port that both peers will independently calculate
    ///
    /// # Algorithm
    /// ```text
    /// alternative_port = MIN_PORT + (HMAC-SHA256(session_key, original_port || attempt_number) mod PORT_RANGE)
    /// ```
    pub fn derive_alternative_port(
        &self,
        original_port: Port,
        attempt_number: u32,
    ) -> Result<Port, EngineError> {
        if attempt_number >= MAX_COLLISION_ATTEMPTS {
            return Err(EngineError::port_hopping_error(
                "Maximum collision resolution attempts exceeded",
            ));
        }

        // Create input: original_port (2 bytes) || attempt_number (4 bytes)
        let mut input = [0u8; 6];
        input[0..2].copy_from_slice(&original_port.as_u16().to_be_bytes());
        input[2..6].copy_from_slice(&attempt_number.to_be_bytes());

        // Calculate HMAC
        let tag = hmac::sign(&self.session_key, &input);

        // Extract first 4 bytes as u32
        let hash_value = u32::from_be_bytes([
            tag.as_ref()[0],
            tag.as_ref()[1],
            tag.as_ref()[2],
            tag.as_ref()[3],
        ]);

        // Map to port range deterministically
        let port_offset = hash_value % PORT_RANGE;
        let alternative_port_value = MIN_PORT + port_offset as u16;

        let alternative_port = Port::new(alternative_port_value)
            .map_err(|_| EngineError::port_hopping_error("Invalid alternative port derived"))?;

        debug!(
            original_port = %original_port,
            attempt_number = attempt_number,
            alternative_port = %alternative_port,
            "Derived alternative port for collision"
        );

        Ok(alternative_port)
    }

    /// Check if a collision is indicated by an error
    ///
    /// Detects EADDRINUSE errors from bind() operations
    pub fn is_collision_error(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::AddrInUse
    }

    /// Resolve a port collision by finding an available alternative
    ///
    /// # Arguments
    /// * `original_port` - Port that failed to bind
    /// * `bind_fn` - Function to attempt binding to a port (returns true if successful)
    ///
    /// # Returns
    /// The successfully bound alternative port, or error if all attempts fail
    pub fn resolve_collision<F>(
        &self,
        original_port: Port,
        mut bind_fn: F,
    ) -> Result<Port, EngineError>
    where
        F: FnMut(Port) -> bool,
    {
        warn!(
            original_port = %original_port,
            "Port collision detected, attempting resolution"
        );

        // Try alternatives deterministically
        for attempt in 0..MAX_COLLISION_ATTEMPTS {
            let alternative_port = self.derive_alternative_port(original_port, attempt)?;

            // Attempt to bind to alternative port
            if bind_fn(alternative_port) {
                debug!(
                    original_port = %original_port,
                    alternative_port = %alternative_port,
                    attempt = attempt,
                    "Port collision resolved"
                );
                return Ok(alternative_port);
            }

            warn!(
                original_port = %original_port,
                alternative_port = %alternative_port,
                attempt = attempt,
                "Alternative port also in use, trying next"
            );
        }

        Err(EngineError::port_hopping_error(format!(
            "Failed to resolve port collision after {} attempts",
            MAX_COLLISION_ATTEMPTS
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_key() -> SessionKey {
        SessionKey::new([42u8; 32])
    }

    #[test]
    fn test_derive_alternative_port_deterministic() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Derive alternative port twice with same inputs
        let alt1 = detector
            .derive_alternative_port(original_port, 0)
            .expect("derive alt1");
        let alt2 = detector
            .derive_alternative_port(original_port, 0)
            .expect("derive alt2");

        // Must be identical
        assert_eq!(alt1, alt2, "Derivation must be deterministic");
    }

    #[test]
    fn test_derive_alternative_port_different_per_attempt() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Different attempts should yield different ports
        let alt0 = detector
            .derive_alternative_port(original_port, 0)
            .expect("derive alt0");
        let alt1 = detector
            .derive_alternative_port(original_port, 1)
            .expect("derive alt1");
        let alt2 = detector
            .derive_alternative_port(original_port, 2)
            .expect("derive alt2");

        assert_ne!(alt0, alt1, "Attempt 0 != Attempt 1");
        assert_ne!(alt1, alt2, "Attempt 1 != Attempt 2");
        assert_ne!(alt0, alt2, "Attempt 0 != Attempt 2");
    }

    #[test]
    fn test_derive_alternative_port_same_key_different_peers() {
        // Both peers use the same session key
        let session_key = create_test_session_key();
        let detector1 = PortCollisionDetector::new(&session_key);
        let detector2 = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Both peers derive alternatives independently
        let alt1 = detector1
            .derive_alternative_port(original_port, 0)
            .expect("peer1 derive");
        let alt2 = detector2
            .derive_alternative_port(original_port, 0)
            .expect("peer2 derive");

        // Must select the same alternative
        assert_eq!(
            alt1, alt2,
            "Both peers must select identical alternative port"
        );
    }

    #[test]
    fn test_derive_alternative_port_in_valid_range() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        for attempt in 0..5 {
            let alt = detector
                .derive_alternative_port(original_port, attempt)
                .expect("derive alternative");

            assert!(
                alt.as_u16() >= MIN_PORT,
                "Alternative port must be >= MIN_PORT"
            );
            assert!(
                alt.as_u16() <= MAX_PORT,
                "Alternative port must be <= MAX_PORT"
            );
        }
    }

    #[test]
    fn test_derive_alternative_port_max_attempts() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Attempting beyond max should fail
        let result = detector.derive_alternative_port(original_port, MAX_COLLISION_ATTEMPTS);
        assert!(
            result.is_err(),
            "Should fail when exceeding max collision attempts"
        );
    }

    #[test]
    fn test_is_collision_error() {
        // EADDRINUSE error should be detected
        let error = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert!(
            PortCollisionDetector::is_collision_error(&error),
            "AddrInUse should be detected as collision"
        );

        // Other errors should not be detected as collisions
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(
            !PortCollisionDetector::is_collision_error(&error),
            "PermissionDenied should not be collision"
        );
    }

    #[test]
    fn test_resolve_collision_success() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Simulate: first alternative succeeds
        let bind_fn = |port: Port| port.as_u16() != 5000; // Reject original, accept alternatives

        let resolved = detector
            .resolve_collision(original_port, bind_fn)
            .expect("should resolve");

        assert_ne!(
            resolved, original_port,
            "Resolved port should differ from original"
        );
    }

    #[test]
    fn test_resolve_collision_multiple_attempts() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Pre-calculate first 3 alternatives
        let alt0 = detector
            .derive_alternative_port(original_port, 0)
            .expect("alt0");
        let alt1 = detector
            .derive_alternative_port(original_port, 1)
            .expect("alt1");
        let alt2 = detector
            .derive_alternative_port(original_port, 2)
            .expect("alt2");

        // Simulate: first two alternatives fail, third succeeds
        let bind_fn = |port: Port| port != alt0 && port != alt1;

        let resolved = detector
            .resolve_collision(original_port, bind_fn)
            .expect("should resolve");

        assert_eq!(resolved, alt2, "Should resolve to third alternative");
    }

    #[test]
    fn test_resolve_collision_exhaustion() {
        let session_key = create_test_session_key();
        let detector = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Simulate: all ports fail
        let bind_fn = |_port: Port| false;

        let result = detector.resolve_collision(original_port, bind_fn);

        assert!(result.is_err(), "Should fail when all alternatives fail");
    }

    #[test]
    fn test_collision_resolution_cross_peer_consistency() {
        // Simulate two peers independently resolving the same collision
        let session_key = create_test_session_key();
        let detector_peer1 = PortCollisionDetector::new(&session_key);
        let detector_peer2 = PortCollisionDetector::new(&session_key);

        let original_port = Port::new(5000).expect("valid port");

        // Pre-calculate blocked alternatives (same for both peers)
        let alt0 = detector_peer1
            .derive_alternative_port(original_port, 0)
            .expect("alt0");
        let alt1 = detector_peer1
            .derive_alternative_port(original_port, 1)
            .expect("alt1");

        // Both peers see the same ports as blocked (first two fail, third succeeds)
        let bind_fn = |port: Port| port != alt0 && port != alt1;

        let resolved1 = detector_peer1
            .resolve_collision(original_port, bind_fn)
            .expect("peer1 resolve");
        let resolved2 = detector_peer2
            .resolve_collision(original_port, bind_fn)
            .expect("peer2 resolve");

        assert_eq!(
            resolved1, resolved2,
            "Both peers must resolve to identical port"
        );
    }
}
