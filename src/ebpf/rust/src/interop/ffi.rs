//! FFI bindings for eBPF interoperability (DEPRECATED)
//!
//! NOTE: This module is deprecated. Use loaders/xdp_loader.rs, loaders/tc_loader.rs,
//! and loaders/security_loader.rs which use libbpf-rs directly.
//!
//! This module provides legacy Foreign Function Interface (FFI) bindings
//! and is retained for API compatibility only.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use buckwild_common::error::BuckwildError;
use buckwild_common::protocol::types::*;
use libbpf_sys::*;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

/// FFI wrapper for eBPF program operations
pub struct eBpfFfi {
    /// Program file descriptor
    prog_fd: EbpfFileDescriptor,
    /// Map file descriptors
    map_fds: Vec<EbpfFileDescriptor>,
}

impl eBpfFfi {
    /// Create a new eBPF FFI wrapper
    pub fn new() -> Self {
        Self {
            prog_fd: EbpfFileDescriptor::new(-1),
            map_fds: Vec::new(),
        }
    }

    /// Load an eBPF program from object file
    pub fn load_program(&mut self, obj_path: &str) -> Result<(), BuckwildError> {
        let obj_path_c = CString::new(obj_path)
            .map_err(|e| BuckwildError::internal_error(format!("Invalid path: {}", e)))?;

        // This is a simplified implementation
        // In a real implementation, you would use libbpf to load the program
        let raw_fd = unsafe {
            // Placeholder for actual libbpf program loading
            // bpf_prog_load(...)
            1 // Dummy fd
        };

        self.prog_fd = EbpfFileDescriptor::new(raw_fd);

        if self.prog_fd.as_i32() < 0 {
            return Err(BuckwildError::internal_error("Failed to load eBPF program"));
        }

        Ok(())
    }

    /// Attach eBPF program to a hook
    pub fn attach_program(
        &self,
        attach_type: AttachType,
        target: &str,
    ) -> Result<(), BuckwildError> {
        if self.prog_fd.as_i32() < 0 {
            return Err(BuckwildError::internal_error("Program not loaded"));
        }

        let target_c = CString::new(target)
            .map_err(|e| BuckwildError::internal_error(format!("Invalid target: {}", e)))?;

        // Placeholder for actual program attachment
        match attach_type {
            AttachType::Xdp => {
                // Attach XDP program
                // bpf_set_link_xdp_fd(...)
            }
            AttachType::TcIngress | AttachType::TcEgress => {
                // Attach TC program
                // tc_attach_bpf(...)
            }
            AttachType::SocketFilter => {
                // Attach socket filter
                // setsockopt(..., SO_ATTACH_BPF, ...)
            }
        }

        Ok(())
    }

    /// Detach eBPF program
    pub fn detach_program(
        &self,
        attach_type: AttachType,
        target: &str,
    ) -> Result<(), BuckwildError> {
        let target_c = CString::new(target)
            .map_err(|e| BuckwildError::internal_error(format!("Invalid target: {}", e)))?;

        // Placeholder for actual program detachment
        match attach_type {
            AttachType::Xdp => {
                // Detach XDP program
                // bpf_set_link_xdp_fd(..., -1, ...)
            }
            AttachType::TcIngress | AttachType::TcEgress => {
                // Detach TC program
                // tc_detach_bpf(...)
            }
            AttachType::SocketFilter => {
                // Detach socket filter
                // setsockopt(..., SO_DETACH_BPF, ...)
            }
        }

        Ok(())
    }

    /// Get map file descriptor by name
    pub fn get_map_fd(&self, map_name: &str) -> Result<EbpfFileDescriptor, BuckwildError> {
        let map_name_c = CString::new(map_name)
            .map_err(|e| BuckwildError::internal_error(format!("Invalid map name: {}", e)))?;

        // Placeholder for actual map fd retrieval
        // In a real implementation, you would use bpf_object__find_map_fd_by_name
        Ok(EbpfFileDescriptor::new(1)) // Dummy fd
    }

    /// Update map element
    pub fn update_map_element(
        &self,
        map_fd: EbpfFileDescriptor,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), BuckwildError> {
        let ret = unsafe {
            bpf_map_update_elem(
                map_fd.as_i32(),
                key.as_ptr() as *const c_void,
                value.as_ptr() as *const c_void,
                flags,
            )
        };

        if ret != 0 {
            return Err(BuckwildError::internal_error(
                "Failed to update map element",
            ));
        }

        Ok(())
    }

    /// Lookup map element
    pub fn lookup_map_element(
        &self,
        map_fd: EbpfFileDescriptor,
        key: &[u8],
    ) -> Result<Vec<u8>, BuckwildError> {
        let mut value = vec![0u8; 1024]; // Assume max value size

        let ret = unsafe {
            bpf_map_lookup_elem(
                map_fd.as_i32(),
                key.as_ptr() as *const c_void,
                value.as_mut_ptr() as *mut c_void,
            )
        };

        if ret != 0 {
            return Err(BuckwildError::internal_error(
                "Failed to lookup map element",
            ));
        }

        Ok(value)
    }

    /// Delete map element
    pub fn delete_map_element(
        &self,
        map_fd: EbpfFileDescriptor,
        key: &[u8],
    ) -> Result<(), BuckwildError> {
        let ret = unsafe { bpf_map_delete_elem(map_fd.as_i32(), key.as_ptr() as *const c_void) };

        if ret != 0 {
            return Err(BuckwildError::internal_error(
                "Failed to delete map element",
            ));
        }

        Ok(())
    }

    /// Get program file descriptor
    pub fn get_prog_fd(&self) -> EbpfFileDescriptor {
        self.prog_fd
    }
}

/// eBPF program attach types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachType {
    /// XDP (eXpress Data Path)
    Xdp,
    /// Traffic Control Ingress
    TcIngress,
    /// Traffic Control Egress
    TcEgress,
    /// Socket Filter
    SocketFilter,
}

/// eBPF map types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    /// Hash map
    Hash,
    /// Array map
    Array,
    /// Ring buffer
    RingBuf,
    /// Per-CPU hash map
    PerCpuHash,
    /// Per-CPU array map
    PerCpuArray,
}

/// eBPF program information
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// Program name
    pub name: String,
    /// Program type
    pub prog_type: String,
    /// Program file descriptor
    pub fd: EbpfFileDescriptor,
    /// Program size in instructions
    pub size: EbpfInstructionCount,
    /// Program load time
    pub load_time: std::time::SystemTime,
}

/// eBPF map information
#[derive(Debug, Clone)]
pub struct MapInfo {
    /// Map name
    pub name: String,
    /// Map type
    pub map_type: EbpfMapType,
    /// Map file descriptor
    pub fd: EbpfFileDescriptor,
    /// Key size in bytes
    pub key_size: KeySize,
    /// Value size in bytes
    pub value_size: ValueSize,
    /// Maximum entries
    pub max_entries: EbpfMapSize,
}

impl Drop for eBpfFfi {
    fn drop(&mut self) {
        // Clean up file descriptors
        if self.prog_fd.as_i32() >= 0 {
            unsafe {
                libc::close(self.prog_fd.as_i32());
            }
        }

        for &map_fd in &self.map_fds {
            if map_fd.as_i32() >= 0 {
                unsafe {
                    libc::close(map_fd.as_i32());
                }
            }
        }
    }
}

impl Default for eBpfFfi {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Stage 3: C Logic Function FFI Bindings
// ============================================================================

/// Parsed header structure (matches C struct)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ParsedHeader {
    pub version: u8,
    pub packet_type: u8,
    pub session_id_type: u8,
    pub session_id: u64,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub timestamp: u32,
    pub payload_length: u16,
    pub hmac_policy: u8,
    pub flags: u8,
}

/// Session state structure (matches C struct)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionState {
    pub session_id: u64,
    pub state: u32,
    pub last_packet_time: u64,
    pub current_port: u16,
    pub next_port: u16,
    pub port_window_start: u32,
    pub port_window_size: u32,
}

/// Session security state structure (matches C struct)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionSecurityState {
    pub fragment_count_current_window: u32,
    pub rate_limit_window_start: u64,
    pub outstanding_fragments: u32,
    pub total_reassembly_memory: u64,
}

// Constants (match C defines)
pub const SESSION_STATE_ACTIVE: u32 = 2;
pub const PORT_VALID: i32 = 0;
pub const PORT_VALID_NEXT_WINDOW: i32 = 1;
pub const PORT_INVALID: i32 = -1;
pub const RATE_LIMIT_OK: i32 = 0;
pub const RATE_LIMIT_EXCEEDED: i32 = 1;
pub const FRAGMENT_BOMB_NONE: i32 = 0;
pub const FRAGMENT_BOMB_DETECTED: i32 = 1;
pub const FRAGMENT_SIZE_VALID: i32 = 0;
pub const FRAGMENT_SIZE_INVALID: i32 = 1;

// External C functions (inline functions from header files)
// Note: These are defined as inline in headers, so we need to link against object files
// or compile a wrapper library that includes them.

extern "C" {
    /// Detect if packet is Buckwild protocol
    ///
    /// # Safety
    /// Caller must ensure packet pointer is valid for packet_len bytes
    pub fn is_buckwild_protocol(packet: *const u8, packet_len: usize) -> i32;

    /// Parse Buckwild header with adaptive fields
    ///
    /// # Safety
    /// Caller must ensure packet pointer is valid and parsed pointer is valid
    pub fn parse_buckwild_header(
        packet: *const u8,
        packet_len: usize,
        parsed: *mut ParsedHeader,
    ) -> i32;

    /// Check if session is active
    ///
    /// # Safety
    /// Caller must ensure session pointer is valid
    pub fn is_session_active(session: *const SessionState, current_time_ns: u64) -> i32;

    /// Validate port against session expectations
    ///
    /// # Safety
    /// Caller must ensure session pointer is valid
    pub fn validate_port(
        session: *const SessionState,
        received_port: u16,
        current_time_bucket: u32,
    ) -> i32;

    /// Check fragment rate limit
    ///
    /// # Safety
    /// Caller must ensure sec pointer is valid
    pub fn check_fragment_rate_limit(sec: *const SessionSecurityState, current_time_ns: u64)
    -> i32;

    /// Check for fragment bomb attack
    ///
    /// # Safety
    /// Caller must ensure sec pointer is valid
    pub fn check_fragment_bomb(sec: *const SessionSecurityState) -> i32;

    /// Validate fragment size
    pub fn validate_fragment_size(fragment_size: u16) -> i32;
}

// Safe Rust wrappers for C functions

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Safe wrapper for is_buckwild_protocol
///
/// Panics are caught at FFI boundary and converted to false return
pub fn check_buckwild_protocol(packet: &[u8]) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if packet.is_empty() {
            return false;
        }
        unsafe { is_buckwild_protocol(packet.as_ptr(), packet.len()) == 1 }
    }))
    .unwrap_or(false)
}

/// Safe wrapper for parse_buckwild_header
///
/// Panics are caught at FFI boundary and converted to error result
pub fn parse_header(packet: &[u8]) -> Result<ParsedHeader, &'static str> {
    catch_unwind(AssertUnwindSafe(|| {
        if packet.len() < 26 {
            return Err("Packet too small");
        }

        let mut parsed = ParsedHeader::default();
        let result =
            unsafe { parse_buckwild_header(packet.as_ptr(), packet.len(), &mut parsed as *mut _) };

        if result == 0 {
            Ok(parsed)
        } else {
            Err("Failed to parse header")
        }
    }))
    .unwrap_or(Err("Panic during header parsing"))
}

/// Safe wrapper for is_session_active
///
/// Panics are caught at FFI boundary and converted to false return
pub fn check_session_active(session: &SessionState, current_time_ns: u64) -> bool {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        is_session_active(session as *const _, current_time_ns) == 1
    }))
    .unwrap_or(false)
}

/// Safe wrapper for validate_port
///
/// Panics are caught at FFI boundary and converted to PORT_INVALID
pub fn check_port_valid(
    session: &SessionState,
    received_port: u16,
    current_time_bucket: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        validate_port(session as *const _, received_port, current_time_bucket)
    }))
    .unwrap_or(PORT_INVALID)
}

/// Safe wrapper for check_fragment_rate_limit
///
/// Panics are caught at FFI boundary and converted to false return (limit not exceeded)
pub fn check_rate_limit(sec: &SessionSecurityState, current_time_ns: u64) -> bool {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        check_fragment_rate_limit(sec as *const _, current_time_ns) == RATE_LIMIT_OK
    }))
    .unwrap_or(false)
}

/// Safe wrapper for check_fragment_bomb
///
/// Panics are caught at FFI boundary and converted to false return (no bomb detected)
pub fn check_for_fragment_bomb(sec: &SessionSecurityState) -> bool {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        check_fragment_bomb(sec as *const _) == FRAGMENT_BOMB_DETECTED
    }))
    .unwrap_or(false)
}

/// Safe wrapper for validate_fragment_size
///
/// Panics are caught at FFI boundary and converted to false return (invalid size)
pub fn check_fragment_size(fragment_size: u16) -> bool {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        validate_fragment_size(fragment_size) == FRAGMENT_SIZE_VALID
    }))
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_ffi_creation() {
        let ffi = eBpfFfi::new();
        assert_eq!(ffi.get_prog_fd().as_i32(), -1);
        assert!(ffi.map_fds.is_empty());
    }

    #[test]
    fn test_attach_type_enum() {
        assert_eq!(AttachType::Xdp, AttachType::Xdp);
        assert_ne!(AttachType::Xdp, AttachType::TcIngress);
    }

    #[test]
    fn test_map_type_enum() {
        assert_eq!(MapType::Hash, MapType::Hash);
        assert_ne!(MapType::Hash, MapType::Array);
    }

    #[test]
    fn test_program_info() {
        let info = ProgramInfo {
            name: "test_prog".to_string(),
            prog_type: "XDP".to_string(),
            fd: EbpfFileDescriptor::new(5),
            size: EbpfInstructionCount::new(100),
            load_time: std::time::SystemTime::now(),
        };

        assert_eq!(info.name, "test_prog");
        assert_eq!(info.fd.as_i32(), 5);
        assert_eq!(info.size.as_u32(), 100);
    }

    #[test]
    fn test_map_info() {
        let info = MapInfo {
            name: "test_map".to_string(),
            map_type: EbpfMapType::Hash,
            fd: EbpfFileDescriptor::new(6),
            key_size: KeySize::new(4),
            value_size: ValueSize::new(8),
            max_entries: EbpfMapSize::new(1024),
        };

        assert_eq!(info.name, "test_map");
        assert_eq!(info.map_type, EbpfMapType::Hash);
        assert_eq!(info.key_size.as_usize(), 4);
        assert_eq!(info.value_size.as_usize(), 8);
    }
}
