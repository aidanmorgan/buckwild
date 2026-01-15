#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Recovery engine modules
pub mod coordination;
pub mod engine;
pub mod escalation;
pub mod strategies;
pub mod triggers;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod escalation_tests;

// Re-export recovery types - explicit to avoid ambiguous glob warnings
pub use coordination::RecoveryCoordination;
pub use engine::{
    RecoveryAttempt as EngineRecoveryAttempt, RecoveryEngine, RecoveryLevel as EngineRecoveryLevel,
    RecoveryResult,
};
pub use escalation::{RecoveryAttempt, RecoveryEscalation, RecoveryLevel};
pub use strategies::RecoveryStrategies;
pub use triggers::{detect_sequence_mismatch, detect_time_drift, detect_time_drift_default};
