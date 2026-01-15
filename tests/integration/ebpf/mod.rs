// eBPF Integration Tests Module
//!
//! This module contains comprehensive integration tests for validating
//! the C-to-Rust pipeline for eBPF event processing.

pub mod ebpf_integration_tests;
pub mod test_c_rust_struct_compatibility;
pub mod test_c_ffi_integration;
pub mod test_ebpf_security_integration;
pub mod test_ring_buffer_mock;

// Rust-only integration tests (no C FFI)
#[path = "../rust/ebpf_integration_test.rs"]
pub mod ebpf_integration_test;

#[cfg(test)]
mod tests {
    /// Integration test suite covering:
    /// - C struct layout compatibility
    /// - Binary data parsing
    /// - FFI interoperability
    /// - Ring buffer event flow
    /// - Endianness handling
    ///
    /// Run with: cargo test --test integration -- ebpf
    #[test]
    fn integration_test_suite_exists() {
        // This test ensures the integration test module compiles
        assert!(true);
    }
}
