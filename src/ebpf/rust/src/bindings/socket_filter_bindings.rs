//! Socket filter program bindings
//! This module provides Rust bindings for socket filter eBPF programs.
//! It handles loading, attaching, and managing socket filter programs for packet filtering.

#![cfg(target_os = "linux")]

use super::{EbpfBinding, ProgramStats};
use anyhow::Result;
use libbpf_rs::{Link, Object, Program};
use std::os::unix::io::{AsFd, AsRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

// Import consolidated types
use buckwild_common::protocol::types::*;

/// Socket filter program binding for Buckwild packet filtering
pub struct SocketFilterBinding {
    object: Option<Object>,
    socket_fd: Option<EbpfFileDescriptor>,
    attached: bool,
    filter_type: SocketFilterType,
}

/// Types of socket filters
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketFilterType {
    Session,
    Security,
}

impl SocketFilterBinding {
    /// Create a new socket filter binding
    pub fn new(filter_type: SocketFilterType) -> Self {
        Self {
            object: None,
            socket_fd: None,
            attached: false,
            filter_type,
        }
    }

    /// Get the filter type
    pub fn filter_type(&self) -> SocketFilterType {
        self.filter_type
    }

    /// Set the socket file descriptor to attach to
    pub fn set_socket_fd(&mut self, socket_fd: RawFd) {
        self.socket_fd = Some(EbpfFileDescriptor::new(socket_fd));
    }

    /// Get the program name based on filter type
    fn get_program_name(&self) -> &'static str {
        match self.filter_type {
            SocketFilterType::Session => "socket_session_filter",
            SocketFilterType::Security => "socket_security_filter",
        }
    }
}

impl EbpfBinding for SocketFilterBinding {
    fn load_program(&mut self, path: &Path) -> Result<()> {
        // Load the eBPF object file
        let open_obj = libbpf_rs::ObjectBuilder::default().open_file(path)?;
        let object = open_obj.load()?;

        // Verify the socket filter program exists
        let program_name = self.get_program_name();
        let _program = object
            .progs_iter()
            .find(|p| p.name() == program_name)
            .ok_or_else(|| anyhow::anyhow!("Socket filter program '{}' not found", program_name))?;

        self.object = Some(object);

        tracing::info!("Loaded socket filter program: {}", program_name);
        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        let object = self
            .object
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Object not loaded"))?;

        // Find the socket filter program
        let program_name = self.get_program_name();
        let program = object
            .progs_iter()
            .find(|p| p.name() == program_name)
            .ok_or_else(|| anyhow::anyhow!("Socket filter program '{}' not found", program_name))?;

        let socket_fd = self
            .socket_fd
            .ok_or_else(|| anyhow::anyhow!("Socket FD not set"))?;

        // Attach socket filter program to the socket
        unsafe {
            let prog_fd = program.as_fd().as_raw_fd();
            let ret = libc::setsockopt(
                socket_fd.as_i32(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_BPF,
                &prog_fd as *const _ as *const libc::c_void,
                std::mem::size_of::<RawFd>() as libc::socklen_t,
            );

            if ret != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to attach socket filter: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        self.attached = true;

        tracing::info!(
            "Attached socket filter program: {} to socket FD: {}",
            self.get_program_name(),
            socket_fd.as_i32()
        );
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        if let Some(socket_fd) = self.socket_fd {
            // Detach socket filter program from the socket
            unsafe {
                let ret = libc::setsockopt(
                    socket_fd.as_i32(),
                    libc::SOL_SOCKET,
                    libc::SO_DETACH_FILTER,
                    std::ptr::null(),
                    0,
                );

                if ret != 0 {
                    return Err(anyhow::anyhow!(
                        "Failed to detach socket filter: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }

            self.attached = false;
            tracing::info!(
                "Detached socket filter program: {} from socket FD: {}",
                self.get_program_name(),
                socket_fd.as_i32()
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
        let program_name = self.get_program_name();
        let _program = object
            .progs_iter()
            .find(|p| p.name() == program_name)
            .ok_or_else(|| anyhow::anyhow!("Socket filter program '{}' not found", program_name))?;

        // Program statistics require BPF_PROG_GET_INFO_BY_FD syscall
        // libbpf-rs 0.21+ doesn't expose this directly; stats are available via /sys/fs/bpf
        Ok(ProgramStats {
            run_time_ns: 0,
            run_cnt: EventCount::new(0),
            recursion_misses: EventCount::new(0),
        })
    }
}

/// Socket filter program manager for handling multiple socket filters
pub struct SocketFilterManager {
    session_filters: Vec<Arc<RwLock<SocketFilterBinding>>>,
    security_filters: Vec<Arc<RwLock<SocketFilterBinding>>>,
    program_dir: Option<std::path::PathBuf>,
}

impl SocketFilterManager {
    /// Create a new socket filter manager
    pub fn new() -> Self {
        Self {
            session_filters: Vec::new(),
            security_filters: Vec::new(),
            program_dir: None,
        }
    }

    /// Set the directory containing eBPF object files
    pub fn set_program_directory<P: AsRef<Path>>(&mut self, dir: P) {
        self.program_dir = Some(dir.as_ref().to_path_buf());
    }

    /// Add a session filter binding
    pub fn add_session_filter(&mut self, socket_fd: RawFd) -> Arc<RwLock<SocketFilterBinding>> {
        let mut binding = SocketFilterBinding::new(SocketFilterType::Session);
        binding.set_socket_fd(socket_fd);
        let binding = Arc::new(RwLock::new(binding));
        self.session_filters.push(Arc::clone(&binding));
        binding
    }

    /// Add a security filter binding
    pub fn add_security_filter(&mut self, socket_fd: RawFd) -> Arc<RwLock<SocketFilterBinding>> {
        let mut binding = SocketFilterBinding::new(SocketFilterType::Security);
        binding.set_socket_fd(socket_fd);
        let binding = Arc::new(RwLock::new(binding));
        self.security_filters.push(Arc::clone(&binding));
        binding
    }

    /// Load socket filter programs
    pub async fn load_all_programs(&self) -> Result<()> {
        let program_dir = self
            .program_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Program directory not set"))?;

        let session_filter_path = program_dir.join("session_filter.o");
        let security_filter_path = program_dir.join("security_filter.o");

        // Load session filters
        for binding in &self.session_filters {
            let mut binding = binding.write().await;
            binding.load_program(&session_filter_path)?;
        }

        // Load security filters
        for binding in &self.security_filters {
            let mut binding = binding.write().await;
            binding.load_program(&security_filter_path)?;
        }

        tracing::info!(
            "Loaded socket filter programs: {} session, {} security",
            self.session_filters.len(),
            self.security_filters.len()
        );
        Ok(())
    }

    /// Attach socket filter programs
    pub async fn attach_all_programs(&self) -> Result<()> {
        // Attach session filters
        for binding in &self.session_filters {
            let mut binding = binding.write().await;
            binding.attach()?;
        }

        // Attach security filters
        for binding in &self.security_filters {
            let mut binding = binding.write().await;
            binding.attach()?;
        }

        tracing::info!(
            "Attached socket filter programs: {} session, {} security",
            self.session_filters.len(),
            self.security_filters.len()
        );
        Ok(())
    }

    /// Detach socket filter programs
    pub async fn detach_all_programs(&self) -> Result<()> {
        // Detach session filters
        for binding in &self.session_filters {
            let mut binding = binding.write().await;
            binding.detach()?;
        }

        // Detach security filters
        for binding in &self.security_filters {
            let mut binding = binding.write().await;
            binding.detach()?;
        }

        tracing::info!(
            "Detached socket filter programs: {} session, {} security",
            self.session_filters.len(),
            self.security_filters.len()
        );
        Ok(())
    }

    /// Get statistics for all socket filter programs
    pub async fn get_all_stats(&self) -> Result<Vec<(SocketFilterType, ProgramStats)>> {
        let mut stats = Vec::new();

        // Get session filter stats
        for binding in &self.session_filters {
            let binding = binding.read().await;
            let program_stats = binding.get_stats()?;
            stats.push((SocketFilterType::Session, program_stats));
        }

        // Get security filter stats
        for binding in &self.security_filters {
            let binding = binding.read().await;
            let program_stats = binding.get_stats()?;
            stats.push((SocketFilterType::Security, program_stats));
        }

        Ok(stats)
    }

    /// Get the number of attached filters
    pub async fn attached_count(&self) -> (usize, usize) {
        let mut session_count = 0;
        let mut security_count = 0;

        for binding in &self.session_filters {
            let binding = binding.read().await;
            if binding.is_attached() {
                session_count += 1;
            }
        }

        for binding in &self.security_filters {
            let binding = binding.read().await;
            if binding.is_attached() {
                security_count += 1;
            }
        }

        (session_count, security_count)
    }
}

impl Default for SocketFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create a raw socket for packet capture
pub fn create_raw_socket() -> Result<EbpfFileDescriptor> {
    unsafe {
        let socket_fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::ETH_P_ALL.to_be() as i32,
        );
        if socket_fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create raw socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(EbpfFileDescriptor::new(socket_fd))
    }
}

/// Helper function to bind a socket to a specific interface
pub fn bind_socket_to_interface(socket_fd: EbpfFileDescriptor, interface: &str) -> Result<()> {
    use std::ffi::CString;

    let interface_cstr = CString::new(interface)?;
    let ifindex = unsafe { libc::if_nametoindex(interface_cstr.as_ptr()) };

    if ifindex == 0 {
        return Err(anyhow::anyhow!("Interface '{}' not found", interface));
    }

    let sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    unsafe {
        let ret = libc::bind(
            socket_fd.as_i32(),
            &sockaddr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );

        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to bind socket to interface '{}': {}",
                interface,
                std::io::Error::last_os_error()
            ));
        }
    }

    tracing::info!(
        "Bound socket FD {} to interface: {}",
        socket_fd.as_i32(),
        interface
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_filter_binding_creation() {
        let binding = SocketFilterBinding::new(SocketFilterType::Session);
        assert_eq!(binding.filter_type(), SocketFilterType::Session);
        assert!(!binding.is_attached());
        assert_eq!(binding.get_program_name(), "socket_session_filter");

        let binding = SocketFilterBinding::new(SocketFilterType::Security);
        assert_eq!(binding.filter_type(), SocketFilterType::Security);
        assert_eq!(binding.get_program_name(), "socket_security_filter");
    }

    #[test]
    fn test_socket_filter_manager_creation() {
        let manager = SocketFilterManager::new();
        assert!(manager.session_filters.is_empty());
        assert!(manager.security_filters.is_empty());
        assert!(manager.program_dir.is_none());
    }

    #[test]
    fn test_socket_filter_types() {
        assert_eq!(SocketFilterType::Session, SocketFilterType::Session);
        assert_ne!(SocketFilterType::Session, SocketFilterType::Security);
    }
}
