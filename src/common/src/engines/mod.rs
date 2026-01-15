#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Engine layer
pub mod adaptive;
pub mod discovery;
pub mod flow_control;
pub mod management;
pub mod port_hopping;
pub mod recovery;
pub mod reliability;
pub mod time_sync;

// Import consolidated types

// Re-export engine types (specific to avoid conflicts)
pub use adaptive::{DelayMeasurement, NetworkMeasurement, ParameterOptimization};
pub use discovery::{DiscoveryEngine, DiscoveryResult};
pub use flow_control::{CongestionControl, FlowControlEngine, WindowManagement};
pub use management::{RekeyEngine, RekeyResult, RepairEngine, RepairResult};
pub use port_hopping::{PortHoppingCalculation, PortHoppingCoordination, PortHoppingEngine};
pub use recovery::{RecoveryCoordination, RecoveryEngine, RecoveryStrategies};
pub use reliability::{
    ReliabilityEngine, RetransmissionEngine, RtoCalculator, SackBlock, SackProcessor,
};
pub use time_sync::{TimeEpoch, TimeSyncEngine};
