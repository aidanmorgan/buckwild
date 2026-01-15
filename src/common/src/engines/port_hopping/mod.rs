#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Port hopping engine
pub mod calculation;
pub mod collision;
pub mod coordination;
pub mod derivation;
pub mod edge_cases;
pub mod engine;
pub mod phases;
pub mod window;

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod sequence_tests;

// Import consolidated types

// Re-export port hopping types
pub use calculation::{PortHoppingCalculation, PortHoppingParams};
pub use collision::PortCollisionDetector;
pub use coordination::PortHoppingCoordination;
pub use derivation::{PortParameters, derive_session_port_parameters};
pub use edge_cases::{BoundaryDetector, BoundarySpanningValidator, BoundaryStatus, SendStrategy};
pub use engine::{
    PortBinding, PortBindingStatus, PortHoppingEngine, PortTransitionEvent, SessionPortState,
};
pub use phases::{BasePortHopping, PortHoppingPhase, SessionPortHopping, TwoPhasePortHopping};
pub use window::AsymmetricWindow;
