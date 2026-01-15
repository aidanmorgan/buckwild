//! TC (Traffic Control) program bindings
//! This module provides Rust bindings for TC eBPF programs.
//! It handles loading, attaching, and managing TC programs for traffic shaping and QoS.

#![cfg(target_os = "linux")]

use super::{EbpfBinding, ProgramStats};
use anyhow::Result;
use libbpf_rs::{Link, Object, Program, TcAttachPoint, TcHook};
use std::ffi::CString;
use std::os::unix::io::AsFd;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

// Import consolidated types
use buckwild_common::protocol::types::*;

// TC attach point constants for libbpf-rs 0.21
const TC_EGRESS: TcAttachPoint = libbpf_rs::TC_EGRESS;
const TC_INGRESS: TcAttachPoint = libbpf_rs::TC_INGRESS;

/// Helper function to get interface index from interface name
fn get_ifindex(interface: &str) -> Result<i32> {
    let c_interface = CString::new(interface)?;
    let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("Interface '{}' not found", interface);
    }
    Ok(ifindex as i32)
}

/// TC program binding for Buckwild traffic control
pub struct TcBinding {
    object: Option<Object>,
    tc_hook: Option<TcHook>,
    interface: String,
    attach_point: TcAttachPoint,
    attached: bool,
    program_name: String,
}

impl TcBinding {
    /// Create a new TC binding for the specified network interface
    pub fn new(interface: String, attach_point: TcAttachPoint) -> Self {
        Self {
            object: None,
            tc_hook: None,
            interface,
            attach_point,
            attached: false,
            program_name: "tc_buckwild_egress".to_string(),
        }
    }

    /// Get the network interface name
    pub fn interface(&self) -> &str {
        self.interface.as_str()
    }

    /// Get the TC attach point
    pub fn attach_point(&self) -> TcAttachPoint {
        self.attach_point
    }
}

impl EbpfBinding for TcBinding {
    fn load_program(&mut self, path: &Path) -> Result<()> {
        // Load the eBPF object file
        let open_obj = libbpf_rs::ObjectBuilder::default().open_file(path)?;
        let object = open_obj.load()?;

        // Verify the main TC program exists
        let _program = object
            .progs_iter()
            .find(|p| p.name() == self.program_name.as_str())
            .ok_or_else(|| anyhow::anyhow!("TC program '{}' not found", self.program_name))?;

        self.object = Some(object);

        tracing::info!("Loaded TC program for interface: {}", self.interface);
        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        let object = self
            .object
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Object not loaded"))?;

        // Find the TC program
        let program = object
            .progs_iter()
            .find(|p| p.name() == self.program_name.as_str())
            .ok_or_else(|| anyhow::anyhow!("TC program '{}' not found", self.program_name))?;

        // Create TC hook
        let mut tc_hook = TcHook::new(program.as_fd());
        tc_hook
            .ifindex(get_ifindex(self.interface.as_str())?)
            .attach_point(self.attach_point);

        // Create the qdisc if it doesn't exist
        tc_hook.create()?;

        // Attach the program
        tc_hook.attach()?;

        self.tc_hook = Some(tc_hook);
        self.attached = true;

        tracing::info!(
            "Attached TC program to interface: {} at {:?}",
            self.interface.as_str(),
            self.attach_point
        );
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        if let Some(mut tc_hook) = self.tc_hook.take() {
            tc_hook.detach()?; // Detach the program
            self.attached = false;
            tracing::info!(
                "Detached TC program from interface: {} at {:?}",
                self.interface.as_str(),
                self.attach_point
            );
        }
        Ok(())
    }

    fn is_attached(&self) -> bool {
        self.attached
    }

    fn get_stats(&self) -> Result<ProgramStats> {
        let object = self
            .object
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Object not loaded"))?;

        // Verify program exists
        let _program = object
            .progs_iter()
            .find(|p| p.name() == self.program_name.as_str())
            .ok_or_else(|| anyhow::anyhow!("TC program '{}' not found", self.program_name))?;

        // Program statistics require BPF_PROG_GET_INFO_BY_FD syscall
        // libbpf-rs 0.21+ doesn't expose this directly; stats are available via /sys/fs/bpf
        Ok(ProgramStats {
            run_time_ns: 0,
            run_cnt: EventCount::new(0),
            recursion_misses: EventCount::new(0),
        })
    }
}

/// TC program manager for handling multiple TC programs
pub struct TcProgramManager {
    pub egress_bindings: Vec<Arc<RwLock<TcBinding>>>,
    pub ingress_bindings: Vec<Arc<RwLock<TcBinding>>>,
    program_dir: Option<std::path::PathBuf>,
}

impl TcProgramManager {
    /// Create a new TC program manager
    pub fn new() -> Self {
        Self {
            egress_bindings: Vec::new(),
            ingress_bindings: Vec::new(),
            program_dir: None,
        }
    }

    /// Set the directory containing eBPF object files
    pub fn set_program_directory<P: AsRef<Path>>(&mut self, dir: P) {
        self.program_dir = Some(dir.as_ref().to_path_buf());
    }

    /// Add a TC egress binding for a network interface
    pub fn add_egress_interface(&mut self, interface: String) -> Arc<RwLock<TcBinding>> {
        let binding = Arc::new(RwLock::new(TcBinding::new(interface, TC_EGRESS)));
        self.egress_bindings.push(Arc::clone(&binding));
        binding
    }

    /// Add a TC ingress binding for a network interface
    pub fn add_ingress_interface(&mut self, interface: String) -> Arc<RwLock<TcBinding>> {
        let binding = Arc::new(RwLock::new(TcBinding::new(interface, TC_INGRESS)));
        self.ingress_bindings.push(Arc::clone(&binding));
        binding
    }

    /// Load TC programs for all interfaces
    pub async fn load_all_programs(&self) -> Result<()> {
        let program_dir = self
            .program_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Program directory not set"))?;

        let tc_program_path = program_dir.join("buckwild_tc.o");

        // Load egress programs
        for binding in &self.egress_bindings {
            let mut binding = binding.write().await;
            binding.load_program(&tc_program_path)?;
        }

        // Load ingress programs
        for binding in &self.ingress_bindings {
            let mut binding = binding.write().await;
            binding.load_program(&tc_program_path)?;
        }

        tracing::info!(
            "Loaded TC programs for {} egress and {} ingress interfaces",
            self.egress_bindings.len(),
            self.ingress_bindings.len()
        );
        Ok(())
    }

    /// Attach TC programs to all interfaces
    pub async fn attach_all_programs(&self) -> Result<()> {
        // Attach egress programs
        for binding in &self.egress_bindings {
            let mut binding = binding.write().await;
            binding.attach()?;
        }

        // Attach ingress programs
        for binding in &self.ingress_bindings {
            let mut binding = binding.write().await;
            binding.attach()?;
        }

        tracing::info!(
            "Attached TC programs to {} egress and {} ingress interfaces",
            self.egress_bindings.len(),
            self.ingress_bindings.len()
        );
        Ok(())
    }

    /// Detach TC programs from all interfaces
    pub async fn detach_all_programs(&self) -> Result<()> {
        // Detach egress programs
        for binding in &self.egress_bindings {
            let mut binding = binding.write().await;
            binding.detach()?;
        }

        // Detach ingress programs
        for binding in &self.ingress_bindings {
            let mut binding = binding.write().await;
            binding.detach()?;
        }

        tracing::info!(
            "Detached TC programs from {} egress and {} ingress interfaces",
            self.egress_bindings.len(),
            self.ingress_bindings.len()
        );
        Ok(())
    }

    /// Get statistics for all TC programs
    pub async fn get_all_stats(&self) -> Result<Vec<(String, String, ProgramStats)>> {
        let mut stats = Vec::new();

        // Get egress stats
        for binding in &self.egress_bindings {
            let binding = binding.read().await;
            let interface = binding.interface().to_string();
            let program_stats = binding.get_stats()?;
            stats.push((interface, "egress".to_string(), program_stats));
        }

        // Get ingress stats
        for binding in &self.ingress_bindings {
            let binding = binding.read().await;
            let interface = binding.interface().to_string();
            let program_stats = binding.get_stats()?;
            stats.push((interface, "ingress".to_string(), program_stats));
        }

        Ok(stats)
    }

    /// Get the number of attached interfaces
    pub async fn attached_count(&self) -> (usize, usize) {
        let mut egress_count = 0;
        let mut ingress_count = 0;

        for binding in &self.egress_bindings {
            let binding = binding.read().await;
            if binding.is_attached() {
                egress_count += 1;
            }
        }

        for binding in &self.ingress_bindings {
            let binding = binding.read().await;
            if binding.is_attached() {
                ingress_count += 1;
            }
        }

        (egress_count, ingress_count)
    }
}

impl Default for TcProgramManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to check if TC is supported on an interface
pub fn is_tc_supported(interface: &str) -> Result<bool> {
    // Try to query the interface index
    match get_ifindex(interface) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Helper function to create a clsact qdisc on an interface
pub fn create_clsact_qdisc(interface: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("tc")
        .args(&["qdisc", "add", "dev", interface, "clsact"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "File exists" error as the qdisc might already exist
        if !stderr.contains("File exists") {
            return Err(anyhow::anyhow!("Failed to create clsact qdisc: {}", stderr));
        }
    }

    tracing::info!("Created clsact qdisc on interface: {}", interface);
    Ok(())
}

/// Helper function to remove a clsact qdisc from an interface
pub fn remove_clsact_qdisc(interface: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("tc")
        .args(&["qdisc", "del", "dev", interface, "clsact"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "No such file or directory" error as the qdisc might not exist
        if !stderr.contains("No such file or directory") {
            return Err(anyhow::anyhow!("Failed to remove clsact qdisc: {}", stderr));
        }
    }

    tracing::info!("Removed clsact qdisc from interface: {}", interface);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tc_binding_creation() {
        let binding = TcBinding::new("eth0".to_string(), TC_EGRESS);
        assert_eq!(binding.interface(), "eth0");
        assert_eq!(binding.attach_point(), TC_EGRESS);
        assert!(!binding.is_attached());
    }

    #[test]
    fn test_tc_program_manager_creation() {
        let manager = TcProgramManager::new();
        assert!(manager.egress_bindings.is_empty());
        assert!(manager.ingress_bindings.is_empty());
        assert!(manager.program_dir.is_none());
    }

    #[tokio::test]
    async fn test_add_interfaces() {
        let mut manager = TcProgramManager::new();

        let egress_binding = manager.add_egress_interface("eth0".to_string());
        let ingress_binding = manager.add_ingress_interface("eth0".to_string());

        assert_eq!(manager.egress_bindings.len(), 1);
        assert_eq!(manager.ingress_bindings.len(), 1);

        assert_eq!(egress_binding.read().await.interface(), "eth0");
        assert_eq!(ingress_binding.read().await.interface(), "eth0");

        assert_eq!(egress_binding.read().await.attach_point(), TC_EGRESS);
        assert_eq!(ingress_binding.read().await.attach_point(), TC_INGRESS);
    }
}
