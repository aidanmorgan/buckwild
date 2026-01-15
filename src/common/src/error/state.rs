// State management errors
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum StateError {
    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("State corruption detected: {component}")]
    StateCorruption { component: String },
}

pub type StateResult<T> = Result<T, StateError>;
