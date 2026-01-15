//! eBPF loader error types
//!
//! This module defines typed errors for eBPF program loading and management
//! following the layered error handling approach specified in design/rules.md.

use thiserror::Error;

/// Errors that can occur during eBPF loader operations
#[derive(Error, Debug)]
pub enum LoaderError {
    /// eBPF verifier rejected the program
    #[error("eBPF verifier rejected program: {log}")]
    VerifierRejection {
        /// Verifier error log
        log: String,
    },

    /// Network interface not found
    #[error("interface {name} not found")]
    InterfaceNotFound {
        /// Interface name that was not found
        name: String,
    },

    /// Program not found in ELF file
    #[error("program {name} not found in ELF file")]
    ProgramNotFound {
        /// Program name that was not found
        name: String,
    },

    /// Map not found in loaded program
    #[error("map {name} not found")]
    MapNotFound {
        /// Map name that was not found
        name: String,
    },

    /// Program already attached to interface
    #[error("already attached to interface {interface}")]
    AlreadyAttached {
        /// Interface name where program is already attached
        interface: String,
    },

    /// Program not attached to interface
    #[error("not attached to interface {interface}")]
    NotAttached {
        /// Interface name where program is not attached
        interface: String,
    },

    /// Session not found in routing map
    #[error("session not found in routing map")]
    SessionNotFound,

    /// Invalid port hopping configuration
    #[error("invalid port hopping configuration: {reason}")]
    InvalidConfiguration {
        /// Reason for invalid configuration
        reason: String,
    },

    /// I/O error during loader operations
    #[error("I/O error: {operation}")]
    Io {
        /// The I/O operation that failed
        operation: String,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// System error (syscall failure)
    /// System error (syscall failure)
    #[cfg(target_os = "linux")]
    #[error("system error: {operation}")]
    System {
        /// The system operation that failed
        operation: String,
        /// The underlying system error
        #[source]
        source: nix::Error,
    },

    /// Internal state corruption (mutex poisoned)
    #[error("internal state corrupted: {details}")]
    StateCorrupted {
        /// Details about the corruption
        details: String,
    },
}

/// Result type for eBPF loader operations
pub type LoaderResult<T> = Result<T, LoaderError>;
