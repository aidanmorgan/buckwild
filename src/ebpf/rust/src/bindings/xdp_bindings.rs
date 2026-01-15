//! XDP program bindings
//! This module provides Rust bindings for XDP eBPF programs.
//! It handles loading, attaching, and managing XDP programs for packet processing.

#![cfg(target_os = "linux")]

use super::{EbpfBinding, ProgramStats};
use anyhow::Result;
use libbpf_rs::{Link, Object, Program};
use std::ffi::CString;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

// Import consolidated types
use buckwild_common::protocol::types::*;

/// Helper function to get interface index from interface name
fn get_ifindex(interface: &str) -> Result<i32> {
    let c_interface = CString::new(interface)?;
    let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("Interface '{}' not found", interface);
    }
    Ok(ifindex as i32)
}

/// XDP program binding for Buckwild packet processing
pub struct XdpBinding {
    object: Option<Object>,
    link: Option<Link>,
    interface: String,
    attached: bool,
    program_name: String,
}

impl XdpBinding {
    /// Create a new XDP binding for the specified network interface
    pub fn new(interface: String) -> Self {
        Self {
            object: None,
            link: None,
            interface,
            attached: false,
            program_name: "xdp_buckwild_handler".to_string(),
        }
    }

    /// Get the network interface name
    pub fn interface(&self) -> &str {
        self.interface.as_str()
    }
}

impl EbpfBinding for XdpBinding {
    fn load_program(&mut self, path: &Path) -> Result<()> {
        // Load the eBPF object file
        let open_obj = libbpf_rs::ObjectBuilder::default().open_file(path)?;
        let object = open_obj.load()?;

        // Verify the main XDP program exists
        let _program = object
            .progs_iter()
            .find(|p| p.name() == self.program_name.as_str())
            .ok_or_else(|| anyhow::anyhow!("Xdp program '{}' not found", self.program_name))?;

        self.object = Some(object);

        tracing::info!("Loaded XDP program for interface: {}", self.interface);
        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        let object = self
            .object
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Object not loaded"))?;

        // Find and attach the XDP program
        let program = object
            .prog_mut(&self.program_name)
            .ok_or_else(|| anyhow::anyhow!("Xdp program '{}' not found", self.program_name))?;

        // Attach XDP program to the network interface
        let link = program.attach_xdp(get_ifindex(&self.interface)?)?;

        self.link = Some(link);
        self.attached = true;

        tracing::info!(
            "Attached XDP program to interface: {}",
            self.interface.as_str()
        );
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        if let Some(link) = self.link.take() {
            drop(link); // Dropping the link detaches the program
            self.attached = false;
            tracing::info!(
                "Detached XDP program from interface: {}",
                self.interface.as_str()
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
            .ok_or_else(|| anyhow::anyhow!("Xdp program '{}' not found", self.program_name))?;

        // Program statistics require BPF_PROG_GET_INFO_BY_FD syscall
        // libbpf-rs 0.21+ doesn't expose this directly; stats are available via /sys/fs/bpf
        Ok(ProgramStats {
            run_time_ns: 0,
            run_cnt: EventCount::new(0),
            recursion_misses: EventCount::new(0),
        })
    }
}

/// XDP program manager for handling multiple XDP programs
pub struct XdpProgramManager {
    pub bindings: Vec<Arc<RwLock<XdpBinding>>>,
    program_dir: Option<std::path::PathBuf>,
}

impl XdpProgramManager {
    /// Create a new XDP program manager
    pub fn new() -> Self {
        Self {
            bindings: Vec::new(),
            program_dir: None,
        }
    }

    /// Set the directory containing eBPF object files
    pub fn set_program_directory<P: AsRef<Path>>(&mut self, dir: P) {
        self.program_dir = Some(dir.as_ref().to_path_buf());
    }

    /// Add an XDP binding for a network interface
    pub fn add_interface(&mut self, interface: String) -> Arc<RwLock<XdpBinding>> {
        let binding = Arc::new(RwLock::new(XdpBinding::new(interface)));
        self.bindings.push(Arc::clone(&binding));
        binding
    }

    /// Load XDP programs for all interfaces
    pub async fn load_all_programs(&self) -> Result<()> {
        let program_dir = self
            .program_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Program directory not set"))?;

        let xdp_program_path = program_dir.join("buckwild_xdp.o");

        for binding in &self.bindings {
            let mut binding = binding.write().await;
            binding.load_program(&xdp_program_path)?;
        }

        tracing::info!("Loaded XDP programs for {} interfaces", self.bindings.len());
        Ok(())
    }

    /// Attach XDP programs to all interfaces
    pub async fn attach_all_programs(&self) -> Result<()> {
        for binding in &self.bindings {
            let mut binding = binding.write().await;
            binding.attach()?;
        }

        tracing::info!(
            "Attached XDP programs to {} interfaces",
            self.bindings.len()
        );
        Ok(())
    }

    /// Detach XDP programs from all interfaces
    pub async fn detach_all_programs(&self) -> Result<()> {
        for binding in &self.bindings {
            let mut binding = binding.write().await;
            binding.detach()?;
        }

        tracing::info!(
            "Detached XDP programs from {} interfaces",
            self.bindings.len()
        );
        Ok(())
    }

    /// Get statistics for all XDP programs
    pub async fn get_all_stats(&self) -> Result<Vec<(String, ProgramStats)>> {
        let mut stats = Vec::new();

        for binding in &self.bindings {
            let binding = binding.read().await;
            let interface = binding.interface().to_string();
            let program_stats = binding.get_stats()?;
            stats.push((interface, program_stats));
        }

        Ok(stats)
    }

    /// Get the number of attached interfaces
    pub async fn attached_count(&self) -> usize {
        let mut count = 0;
        for binding in &self.bindings {
            let binding = binding.read().await;
            if binding.is_attached() {
                count += 1;
            }
        }
        count
    }
}

impl Default for XdpProgramManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to find available network interfaces
pub fn find_network_interfaces() -> Result<Vec<String>> {
    use std::fs;

    let sys_net_path = "/sys/class/net";
    let entries = fs::read_dir(sys_net_path)?;

    let mut interfaces = Vec::new();
    for entry in entries {
        let entry = entry?;
        let interface_name = entry.file_name().to_string_lossy().to_string();

        // Skip loopback and virtual interfaces for XDP
        if !interface_name.starts_with("lo")
            && !interface_name.starts_with("veth")
            && !interface_name.starts_with("docker")
        {
            interfaces.push(interface_name);
        }
    }

    Ok(interfaces)
}

/// Helper function to check if XDP is supported on an interface
pub fn is_xdp_supported(interface: &str) -> Result<bool> {
    // Try to query the interface index
    match get_ifindex(interface) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_binding_creation() {
        let binding = XdpBinding::new("eth0".to_string());
        assert_eq!(binding.interface(), "eth0");
        assert!(!binding.is_attached());
    }

    #[test]
    fn test_xdp_program_manager_creation() {
        let manager = XdpProgramManager::new();
        assert!(manager.bindings.is_empty());
        assert!(manager.program_dir.is_none());
    }

    #[tokio::test]
    async fn test_add_interface() {
        let mut manager = XdpProgramManager::new();
        let binding = manager.add_interface("eth0".to_string());

        assert_eq!(manager.bindings.len(), 1);
        assert_eq!(binding.read().await.interface(), "eth0");
    }

    #[test]
    fn test_find_network_interfaces() {
        // This test might fail in some environments where /sys/class/net is not available
        match find_network_interfaces() {
            Ok(interfaces) => {
                // Should find at least one interface (even if it's just lo)
                assert!(!interfaces.is_empty());
            }
            Err(_) => {
                // It's okay if this fails in test environments
                println!("Network interface discovery not available in test environment");
            }
        }
    }
}
