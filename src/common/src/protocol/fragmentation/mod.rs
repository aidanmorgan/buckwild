// Fragmentation subsystem
//
// This module provides a unified fragmentation system including:
// - Fragmentation engine for packet fragmentation and reassembly
// - Security validation for fragments
// - Memory management for fragment storage
// - Overlap detection for fragment validation
// - Rate limiting for fragment processing

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

pub mod engine;
pub mod memory;
pub mod overlap;
pub mod rate_limit;
pub mod security;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptest_roundtrip;

// Re-export main fragmentation functionality
pub use engine::{
    FragmentationConfig, FragmentationEngine, FragmentationRequest, FragmentationResult,
    FragmentationStats, ReassemblyRequest, ReassemblyResult,
};
pub use memory::{FragmentMemoryManager, FragmentMemoryStats, MemoryConfig, PoolStats};
pub use overlap::{
    CoverageGap, FragmentCoverage, FragmentInfo, OverlapConfig, OverlapDetector, OverlapResult,
    OverlapStats, ReassemblyKey,
};
pub use rate_limit::{
    FragmentRateLimitStats, FragmentRateLimiter, RateLimitConfig, RateLimitRequest,
    RateLimitViolation, ViolationType,
};
pub use security::{
    FragmentSecurityEngine, FragmentSecurityPolicies, FragmentSecurityStats,
    SecurityValidationResult,
};
