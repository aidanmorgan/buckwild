//! eBPF program bindings module
//! This module provides Rust bindings for the eBPF programs written in C.
//! It handles FFI safety, type conversions, and provides safe Rust interfaces
//! to interact with the eBPF programs.

#![cfg(target_os = "linux")]

pub mod socket_filter_bindings;
pub mod tc_bindings;
pub mod xdp_bindings;

use anyhow::Result;
use libbpf_rs::{Program, ProgramType};
use std::collections::HashMap;
use std::path::Path;

// Import consolidated types
use buckwild_common::protocol::types::*;

/// Common eBPF program binding interface
pub trait EbpfBinding {
    /// Load the eBPF program from object file
    fn load_program(&mut self, path: &Path) -> Result<()>;

    /// Attach the program to the appropriate hook
    fn attach(&mut self) -> Result<()>;

    /// Detach the program
    fn detach(&mut self) -> Result<()>;

    /// Check if the program is currently attached
    fn is_attached(&self) -> bool;

    /// Get program statistics
    fn get_stats(&self) -> Result<ProgramStats>;
}

/// Program statistics structure
#[derive(Debug, Clone)]
pub struct ProgramStats {
    pub run_time_ns: u64, // Runtime in nanoseconds
    pub run_cnt: EventCount,
    pub recursion_misses: EventCount,
}

/// eBPF program manager for handling multiple program types
pub struct EbpfProgramManager {
    programs: HashMap<String, Box<dyn EbpfBinding>>,
    loaded_objects: HashMap<String, libbpf_rs::Object>,
}

impl EbpfProgramManager {
    /// Create a new program manager
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            loaded_objects: HashMap::new(),
        }
    }

    /// Register a new eBPF program binding
    pub fn register_program(&mut self, name: String, binding: Box<dyn EbpfBinding>) {
        self.programs.insert(name, binding);
    }

    /// Load all registered programs
    pub fn load_all_programs(&mut self, object_dir: &Path) -> Result<()> {
        for (name, program) in &mut self.programs {
            let object_path = object_dir.join(format!("{}.o", name));
            program.load_program(&object_path)?;
            tracing::info!("Loaded eBPF program: {}", name);
        }
        Ok(())
    }

    /// Attach all loaded programs
    pub fn attach_all_programs(&mut self) -> Result<()> {
        for (name, program) in &mut self.programs {
            program.attach()?;
            tracing::info!("Attached eBPF program: {}", name);
        }
        Ok(())
    }

    /// Detach all programs
    pub fn detach_all_programs(&mut self) -> Result<()> {
        for (name, program) in &mut self.programs {
            if program.is_attached() {
                program.detach()?;
                tracing::info!("Detached eBPF program: {}", name);
            }
        }
        Ok(())
    }

    /// Get statistics for all programs
    pub fn get_all_stats(&self) -> Result<HashMap<String, ProgramStats>> {
        let mut stats = HashMap::new();
        for (name, program) in &self.programs {
            stats.insert(name.clone(), program.get_stats()?);
        }
        Ok(stats)
    }
}

impl Default for EbpfProgramManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to convert libbpf program type to our enum
pub fn convert_program_type(prog_type: ProgramType) -> Result<String> {
    match prog_type {
        ProgramType::Xdp => Ok("XDP".to_string()),
        ProgramType::SchedCls => Ok("TC".to_string()),
        ProgramType::SocketFilter => Ok("SocketFilter".to_string()),
        _ => Err(anyhow::anyhow!("Unsupported program type: {:?}", prog_type)),
    }
}

/// Helper function to validate eBPF program compatibility
pub fn validate_program_compatibility(program: &Program) -> Result<()> {
    // Check if the program has the required sections
    let prog_type = program.prog_type();
    match prog_type {
        ProgramType::Xdp => {
            // Validate XDP program requirements
            if program.name().starts_with("xdp_") {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Xdp program must have 'xdp_' prefix"))
            }
        }
        ProgramType::SchedCls => {
            // Validate TC program requirements
            if program.name().starts_with("tc_") {
                Ok(())
            } else {
                Err(anyhow::anyhow!("TC program must have 'tc_' prefix"))
            }
        }
        ProgramType::SocketFilter => {
            // Validate socket filter program requirements
            if program.name().starts_with("socket_") {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Socket filter program must have 'socket_' prefix"
                ))
            }
        }
        _ => Err(anyhow::anyhow!("Unsupported program type: {:?}", prog_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_manager_creation() {
        let manager = EbpfProgramManager::new();
        assert!(manager.programs.is_empty());
        assert!(manager.loaded_objects.is_empty());
    }

    #[test]
    fn test_convert_program_type() {
        assert_eq!(convert_program_type(ProgramType::Xdp).unwrap(), "XDP");
        assert_eq!(convert_program_type(ProgramType::SchedCls).unwrap(), "TC");
        assert_eq!(
            convert_program_type(ProgramType::SocketFilter).unwrap(),
            "SocketFilter"
        );
    }
}
