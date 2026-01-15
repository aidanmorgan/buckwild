//! Cryptographic utilities for the Buckwild daemon
//!
//! This module provides secure memory management and cryptographic utilities.

use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

// Import consolidated types from common crate

// Re-export SecureBytes from common for compatibility
pub mod secure_storage {
    pub use buckwild_common::memory::SecureBytes;
}

/// Secure bytes container that zeros memory on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes container

    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Get the data as a slice

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the data

    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes[{} bytes]", self.data.len())
    }
}

/// Constant-time comparison of two byte slices
#[tracing::instrument(name = "crypto.hmac_verify", skip(a, b), fields(tag_size = a.len()))]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}
