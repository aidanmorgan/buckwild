#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Recovery engine errors
//!
//! This module defines errors for the recovery engine, including state restoration,
//! recovery escalation, and repair strategies. Errors include context about the
//! specific recovery operation and level that failed.

use crate::protocol::types::*;
use thiserror::Error;

/// Recovery engine error types
#[derive(Error, Debug, Clone)]
pub enum RecoveryError {
    #[error("Recovery failed: {reason} at level {level}")]
    RecoveryFailed {
        reason: String,
        level: RecoveryLevel,
    },

    #[error("Recovery timeout: {recovery_id} after {timeout_ms:?}ms")]
    RecoveryTimeout {
        recovery_id: String,
        timeout_ms: RecoveryTimeout,
    },

    #[error("Recovery escalation failed: from level {from} to {to}")]
    RecoveryEscalationFailed {
        from: RecoveryLevel,
        to: RecoveryLevel,
    },

    #[error("State restoration failed: {component}")]
    StateRestorationFailed { component: String },

    #[error("State snapshot missing: {snapshot_id}")]
    StateSnapshotMissing { snapshot_id: String },

    #[error("State snapshot corrupted: {snapshot_id}")]
    StateSnapshotCorrupted { snapshot_id: String },

    #[error("State rollback failed: {reason}")]
    StateRollbackFailed { reason: String },

    #[error("Recovery strategy not found: {strategy_name}")]
    RecoveryStrategyNotFound { strategy_name: String },

    #[error("Recovery strategy invalid: {strategy_name}")]
    RecoveryStrategyInvalid { strategy_name: String },

    #[error("Recovery strategy execution failed: {strategy_name} - {reason}")]
    RecoveryStrategyExecutionFailed {
        strategy_name: String,
        reason: String,
    },

    #[error("Recovery level exceeded: {current} > {max}")]
    RecoveryLevelExceeded {
        current: RecoveryLevel,
        max: RecoveryLevel,
    },

    #[error("Recovery not possible: {reason}")]
    RecoveryNotPossible { reason: String },

    #[error("Recovery state invalid: {state}")]
    RecoveryStateInvalid { state: String },

    #[error("Recovery coordination failed: {reason}")]
    RecoveryCoordinationFailed { reason: String },

    #[error("Repair operation failed: {repair_type:?} - {reason}")]
    RepairOperationFailed {
        repair_type: RepairType,
        reason: String,
    },

    #[error("Repair target unreachable: {target}")]
    RepairTargetUnreachable { target: String },

    #[error("Repair resource exhausted: {resource}")]
    RepairResourceExhausted { resource: String },

    #[error("Max recovery attempts reached: {attempts}")]
    MaxRecoveryAttemptsReached { attempts: u32 },

    #[error("Recovery backoff required: {duration:?}")]
    RecoveryBackoffRequired { duration: std::time::Duration },

    #[error("Recovery checkpoint failed: {checkpoint_id}")]
    RecoveryCheckpointFailed { checkpoint_id: String },

    #[error("Recovery verification failed: {reason}")]
    RecoveryVerificationFailed { reason: String },

    #[error("Recovery data inconsistent: {details}")]
    RecoveryDataInconsistent { details: String },

    #[error("Recovery metrics unavailable: {metric_name}")]
    RecoveryMetricsUnavailable { metric_name: String },

    #[error("Recovery engine not initialized")]
    RecoveryEngineNotInitialized,

    #[error("Recovery engine shutdown")]
    RecoveryEngineShutdown,
}

impl RecoveryError {
    /// Create a recovery failed error
    pub fn recovery_failed(reason: impl Into<String>, level: RecoveryLevel) -> Self {
        Self::RecoveryFailed {
            reason: reason.into(),
            level,
        }
    }

    /// Create a state restoration failed error
    pub fn state_restoration_failed(component: impl Into<String>) -> Self {
        Self::StateRestorationFailed {
            component: component.into(),
        }
    }

    /// Create a recovery strategy execution failed error
    pub fn recovery_strategy_execution_failed(
        strategy_name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::RecoveryStrategyExecutionFailed {
            strategy_name: strategy_name.into(),
            reason: reason.into(),
        }
    }

    /// Create a recovery not possible error
    pub fn recovery_not_possible(reason: impl Into<String>) -> Self {
        Self::RecoveryNotPossible {
            reason: reason.into(),
        }
    }

    /// Create a repair operation failed error
    pub fn repair_operation_failed(repair_type: RepairType, reason: impl Into<String>) -> Self {
        Self::RepairOperationFailed {
            repair_type,
            reason: reason.into(),
        }
    }

    /// Create a recovery verification failed error
    pub fn recovery_verification_failed(reason: impl Into<String>) -> Self {
        Self::RecoveryVerificationFailed {
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::RecoveryFailed { .. } => true,
            Self::RecoveryTimeout { .. } => true,
            Self::RecoveryEscalationFailed { .. } => true,
            Self::StateRestorationFailed { .. } => true,
            Self::StateSnapshotMissing { .. } => true,
            Self::StateSnapshotCorrupted { .. } => false,
            Self::StateRollbackFailed { .. } => true,
            Self::RecoveryStrategyNotFound { .. } => true,
            Self::RecoveryStrategyInvalid { .. } => false,
            Self::RecoveryStrategyExecutionFailed { .. } => true,
            Self::RecoveryLevelExceeded { .. } => false,
            Self::RecoveryNotPossible { .. } => false,
            Self::RecoveryStateInvalid { .. } => false,
            Self::RecoveryCoordinationFailed { .. } => true,
            Self::RepairOperationFailed { .. } => true,
            Self::RepairTargetUnreachable { .. } => true,
            Self::RepairResourceExhausted { .. } => true,
            Self::MaxRecoveryAttemptsReached { .. } => false,
            Self::RecoveryBackoffRequired { .. } => true,
            Self::RecoveryCheckpointFailed { .. } => true,
            Self::RecoveryVerificationFailed { .. } => true,
            Self::RecoveryDataInconsistent { .. } => false,
            Self::RecoveryMetricsUnavailable { .. } => true,
            Self::RecoveryEngineNotInitialized => false,
            Self::RecoveryEngineShutdown => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::RecoveryFailed { level, .. } => match level {
                RecoveryLevel::TimeSync => Some("Escalate to rekey recovery"),
                RecoveryLevel::Rekey => Some("Escalate to repair recovery"),
                RecoveryLevel::Repair => Some("Escalate to emergency recovery"),
                RecoveryLevel::Emergency => Some("Escalate to terminate"),
                RecoveryLevel::Terminate | RecoveryLevel::Failed => Some("Reset connection"),
            },
            Self::RecoveryTimeout { .. } => Some("Retry recovery with longer timeout"),
            Self::RecoveryEscalationFailed { .. } => Some("Reset to initial recovery level"),
            Self::StateRestorationFailed { .. } => Some("Use backup state snapshot"),
            Self::StateSnapshotMissing { .. } => Some("Create new state snapshot"),
            Self::StateRollbackFailed { .. } => Some("Perform full state reset"),
            Self::RecoveryStrategyNotFound { .. } => Some("Use default recovery strategy"),
            Self::RecoveryStrategyExecutionFailed { .. } => {
                Some("Try alternative recovery strategy")
            }
            Self::RecoveryCoordinationFailed { .. } => Some("Restart recovery coordination"),
            Self::RepairOperationFailed { .. } => Some("Try alternative repair method"),
            Self::RepairTargetUnreachable { .. } => Some("Find alternative repair target"),
            Self::RepairResourceExhausted { .. } => Some("Free resources and retry repair"),
            Self::RecoveryBackoffRequired { .. } => Some("Wait before retrying recovery"),
            Self::RecoveryCheckpointFailed { .. } => Some("Retry checkpoint creation"),
            Self::RecoveryVerificationFailed { .. } => Some("Retry recovery operation"),
            Self::RecoveryMetricsUnavailable { .. } => Some("Use estimated metrics"),
            _ => None,
        }
    }

    /// Get the recovery component that caused this error
    pub fn recovery_component(&self) -> &'static str {
        match self {
            Self::RecoveryFailed { .. }
            | Self::RecoveryTimeout { .. }
            | Self::RecoveryEscalationFailed { .. }
            | Self::RecoveryLevelExceeded { .. }
            | Self::RecoveryNotPossible { .. }
            | Self::MaxRecoveryAttemptsReached { .. }
            | Self::RecoveryBackoffRequired { .. } => "recovery_orchestration",

            Self::StateRestorationFailed { .. }
            | Self::StateSnapshotMissing { .. }
            | Self::StateSnapshotCorrupted { .. }
            | Self::StateRollbackFailed { .. }
            | Self::RecoveryCheckpointFailed { .. } => "state_management",

            Self::RecoveryStrategyNotFound { .. }
            | Self::RecoveryStrategyInvalid { .. }
            | Self::RecoveryStrategyExecutionFailed { .. } => "strategy_execution",

            Self::RepairOperationFailed { .. }
            | Self::RepairTargetUnreachable { .. }
            | Self::RepairResourceExhausted { .. } => "repair_operations",

            Self::RecoveryCoordinationFailed { .. }
            | Self::RecoveryVerificationFailed { .. }
            | Self::RecoveryDataInconsistent { .. }
            | Self::RecoveryMetricsUnavailable { .. } => "coordination",

            Self::RecoveryStateInvalid { .. }
            | Self::RecoveryEngineNotInitialized
            | Self::RecoveryEngineShutdown => "engine_lifecycle",
        }
    }

    /// Get the severity level of this recovery error
    pub fn severity_level(&self) -> RecoverySeverity {
        match self {
            Self::RecoveryNotPossible { .. }
            | Self::RecoveryLevelExceeded { .. }
            | Self::MaxRecoveryAttemptsReached { .. }
            | Self::StateSnapshotCorrupted { .. }
            | Self::RecoveryEngineShutdown => RecoverySeverity::Critical,

            Self::RecoveryFailed { .. }
            | Self::StateRestorationFailed { .. }
            | Self::RecoveryStrategyExecutionFailed { .. }
            | Self::RecoveryDataInconsistent { .. } => RecoverySeverity::High,

            Self::RecoveryTimeout { .. }
            | Self::RecoveryEscalationFailed { .. }
            | Self::RepairOperationFailed { .. }
            | Self::RecoveryVerificationFailed { .. } => RecoverySeverity::Medium,

            Self::StateSnapshotMissing { .. }
            | Self::RecoveryStrategyNotFound { .. }
            | Self::RecoveryBackoffRequired { .. }
            | Self::RecoveryMetricsUnavailable { .. } => RecoverySeverity::Low,

            _ => RecoverySeverity::Medium,
        }
    }
}

/// Recovery error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoverySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Recovery layer result type
pub type RecoveryResult<T> = Result<T, RecoveryError>;
