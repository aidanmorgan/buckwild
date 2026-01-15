// Anti-replay protection

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

pub mod duplicate;
pub mod engine;
pub mod handshake_cache;
pub mod pattern_detector;
pub mod sequence;
pub mod timestamp;
pub mod timestamp_cache;

#[cfg(test)]
mod tests;

// Re-export anti-replay types
pub use duplicate::{
    DuplicateDetectionConfig, DuplicateDetector, DuplicateResult, ThreadSafeDuplicateDetector,
};
pub use engine::{
    AntiReplayConfig, AntiReplayEngine, AntiReplayResult, AntiReplayStatistics,
    ThreadSafeAntiReplayEngine,
};
pub use handshake_cache::{HandshakeCacheResult, HandshakeReplayCache, ThreadSafeHandshakeCache};
pub use pattern_detector::{
    AlertLevel, PatternDetectorConfig, PatternDetectorResult, ReplayPatternDetector, SecurityAlert,
};
pub use sequence::{SequenceResult, SequenceValidationConfig, SequenceValidator, SequenceWindow};
pub use timestamp::{
    TimestampResult, TimestampValidationConfig, TimestampValidator, TimestampWindow,
};
pub use timestamp_cache::{ThreadSafeTimestampCache, TimestampCache, TimestampCacheResult};
