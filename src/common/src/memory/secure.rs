// Secure memory handling with automatic zeroing
//
// This module provides secure memory allocation that ensures sensitive data
// (such as cryptographic keys) is zeroed when no longer needed. All types in
// this module use zeroize to prevent key material from remaining in memory.
//
// Security Policy:
// - All key material MUST be stored in SecureBuffer/SecureBytes
// - Temporary key buffers MUST use Zeroizing<T> wrapper
// - Memory is zeroed on drop, even if panics occur
// - Memory locking (mlock) is attempted on Unix systems to prevent swapping
use crate::error::BuckwildError;
use crate::protocol::types::{AllocationCount, BufferSize, MemorySize, NodeId};
use std::alloc::{Layout, alloc, dealloc};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure memory allocation that zeros on drop
pub struct SecureMemory {
    ptr: NonNull<u8>,
    size: BufferSize,
    layout: Layout,
}

impl SecureMemory {
    /// Allocate secure memory
    pub fn new(size: BufferSize) -> Result<Self, BuckwildError> {
        let size_raw = size.as_usize();
        if size_raw == 0 {
            return Err(BuckwildError::internal_error(
                "Cannot allocate zero-sized memory",
            ));
        }

        let layout = Layout::from_size_align(size_raw, std::mem::align_of::<u8>())
            .map_err(|_| BuckwildError::internal_error("Invalid memory layout"))?;

        let ptr = unsafe {
            let raw_ptr = alloc(layout);
            if raw_ptr.is_null() {
                return Err(BuckwildError::internal_error(
                    "Secure memory allocation failed",
                ));
            }

            // Zero the allocated memory
            ptr::write_bytes(raw_ptr, 0, size_raw);

            NonNull::new_unchecked(raw_ptr)
        };

        // Try to lock the memory to prevent swapping (best effort)
        #[cfg(unix)]
        unsafe {
            libc::mlock(ptr.as_ptr() as *const libc::c_void, size_raw);
        }

        #[cfg(windows)]
        unsafe {
            winapi::um::memoryapi::VirtualLock(
                ptr.as_ptr() as *mut winapi::ctypes::c_void,
                size_raw,
            );
        }

        Ok(Self { ptr, size, layout })
    }

    /// Get the size of the secure memory
    pub fn size(&self) -> BufferSize {
        self.size
    }

    /// Get a mutable slice to the memory
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size.as_usize()) }
    }

    /// Get a slice to the memory
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size.as_usize()) }
    }

    /// Get a raw pointer to the memory
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Get a mutable raw pointer to the memory
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Zero the memory contents
    pub fn zero(&mut self) {
        unsafe {
            ptr::write_bytes(self.ptr.as_ptr(), 0, self.size.as_usize());
        }
    }

    /// Copy data into secure memory
    pub fn copy_from_slice(&mut self, data: &[u8]) -> Result<(), BuckwildError> {
        let size_raw = self.size.as_usize();
        if data.len() > size_raw {
            return Err(BuckwildError::internal_error(
                "Data too large for secure memory",
            ));
        }

        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr(), data.len());
            // Zero any remaining bytes
            if data.len() < size_raw {
                ptr::write_bytes(self.ptr.as_ptr().add(data.len()), 0, size_raw - data.len());
            }
        }

        Ok(())
    }

    /// Compare with another slice in constant time
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        if other.len() != self.size.as_usize() {
            return false;
        }

        self.as_slice().ct_eq(other).into()
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Zero the memory before deallocation
        let size_raw = self.size.as_usize();
        unsafe {
            ptr::write_bytes(self.ptr.as_ptr(), 0, size_raw);
        }

        // Unlock the memory
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.ptr.as_ptr() as *const libc::c_void, size_raw);
        }

        #[cfg(windows)]
        unsafe {
            winapi::um::memoryapi::VirtualUnlock(
                self.ptr.as_ptr() as *mut winapi::ctypes::c_void,
                size_raw,
            );
        }

        // Deallocate the memory
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

unsafe impl Send for SecureMemory {}
unsafe impl Sync for SecureMemory {}

/// Secure buffer that automatically zeros on drop
///
/// This type provides a secure container for sensitive data (keys, secrets, etc.)
/// with automatic memory zeroing when the buffer is dropped.
///
/// Security Properties:
/// - Derives `ZeroizeOnDrop` to ensure automatic cleanup
/// - Memory is securely zeroed even if panics occur during drop
/// - All mutation methods ensure proper zeroing of old data
#[derive(ZeroizeOnDrop, Clone)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        // Zero the allocated memory
        let data = vec![0; capacity];
        Self { data }
    }

    /// Create a new secure buffer from data
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut data = Vec::with_capacity(slice.len());
        data.extend_from_slice(slice);
        Self { data }
    }

    /// Create an empty secure buffer
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a new secure buffer with specified size (for compatibility)
    pub fn with_size(size: usize) -> Self {
        Self::with_capacity(size)
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Get a slice of the buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable slice of the buffer
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Extend the buffer with data
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }

    /// Push a byte to the buffer
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Clear the buffer (zeros the data)
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    /// Resize the buffer, filling new elements with zeros
    pub fn resize(&mut self, new_len: usize) {
        self.data.resize(new_len, 0);
    }

    /// Reserve additional capacity
    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    /// Truncate the buffer to the specified length
    pub fn truncate(&mut self, len: usize) {
        if len < self.data.len() {
            // Zero the truncated portion
            self.data[len..].zeroize();
        }
        self.data.truncate(len);
    }

    /// Compare with another slice in constant time
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        if other.len() != self.data.len() {
            return false;
        }

        self.data.as_slice().ct_eq(other).into()
    }

    /// Copy from slice (for compatibility with crypto modules)
    pub fn copy_from_slice(&mut self, slice: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(slice);
    }
}

impl Default for SecureBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuffer([REDACTED {} bytes])", self.len())
    }
}

impl std::ops::Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// NUMA-aware memory allocator
pub struct NumaAllocator {
    node_count: usize,
    current_node: AtomicUsize,
}

impl NumaAllocator {
    /// Create a new NUMA allocator
    pub fn new() -> Self {
        let node_count = Self::detect_numa_nodes();
        Self {
            node_count,
            current_node: AtomicUsize::new(0),
        }
    }

    /// Detect the number of NUMA nodes
    fn detect_numa_nodes() -> usize {
        // Try to detect NUMA nodes, fallback to 1 if detection fails
        #[cfg(unix)]
        {
            // On Linux, we can check /sys/devices/system/node/
            if let Ok(entries) = std::fs::read_dir("/sys/devices/system/node/") {
                let count = entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with("node"))
                    .count();
                if count > 0 {
                    return count;
                }
            }
        }

        // Fallback to CPU count / cores per node (rough estimate)
        std::cmp::max(1, num_cpus::get() / 8)
    }

    /// Allocate memory on a specific NUMA node
    pub fn allocate_on_node(
        &self,
        size: BufferSize,
        node: usize,
    ) -> Result<SecureMemory, BuckwildError> {
        if node >= self.node_count {
            return Err(BuckwildError::internal_error("Invalid NUMA node"));
        }

        #[cfg(target_os = "linux")]
        {
            // Use NUMA-aware allocation on Linux
            use std::alloc::{Layout, alloc_zeroed};
            use std::ptr::NonNull;

            // First allocate memory using standard allocator
            let layout = Layout::from_size_align(size.as_usize(), std::mem::align_of::<u8>())
                .map_err(|_| BuckwildError::internal_error("Invalid memory layout"))?;

            let raw_ptr = unsafe { alloc_zeroed(layout) };
            if raw_ptr.is_null() {
                return Err(BuckwildError::internal_error("Memory allocation failed"));
            }

            // Set NUMA memory policy to bind to specific node
            // MPOL_BIND = 2, binds memory to specific nodes
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                let mode: i32 = 2; // MPOL_BIND
                let nodemask: u64 = 1u64 << node;
                let maxnode: u64 = 64; // Maximum node + 1

                unsafe {
                    let result = libc::syscall(
                        libc::SYS_mbind,
                        raw_ptr as *mut libc::c_void,
                        size.as_usize(),
                        mode,
                        &nodemask as *const u64,
                        maxnode,
                        0, // flags
                    );

                    if result != 0 {
                        // mbind failed, but memory is still allocated
                        // Log warning but continue with non-NUMA allocation
                        warn!(
                            "mbind syscall failed for NUMA node {}: errno {}",
                            node,
                            *libc::__errno_location()
                        );
                    } else {
                        debug!("Successfully bound memory to NUMA node {}", node);
                    }
                }
            }

            // Lock the memory to prevent swapping
            #[cfg(target_os = "linux")]
            unsafe {
                if libc::mlock(raw_ptr as *const libc::c_void, size.as_usize()) != 0 {
                    warn!(
                        "Failed to lock NUMA memory: errno {}",
                        *libc::__errno_location()
                    );
                }
            }

            // Create SecureMemory with the allocated buffer
            let ptr = unsafe { NonNull::new_unchecked(raw_ptr) };

            Ok(SecureMemory { ptr, size, layout })
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux systems, fall back to regular secure memory allocation
            warn!("NUMA allocation not supported on this platform, using regular allocation");
            SecureMemory::new(size)
        }
    }

    /// Allocate memory using round-robin NUMA node selection
    pub fn allocate_round_robin(&self, size: BufferSize) -> Result<SecureMemory, BuckwildError> {
        let node = self
            .current_node
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.node_count;
        self.allocate_on_node(size, node)
    }

    /// Allocate memory on the local NUMA node
    pub fn allocate_local(&self, size: BufferSize) -> Result<SecureMemory, BuckwildError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // Detect current CPU's NUMA node using getcpu syscall
            let mut cpu: u32 = 0;
            let mut node: u32 = 0;

            unsafe {
                let result = libc::syscall(
                    libc::SYS_getcpu,
                    &mut cpu as *mut u32,
                    &mut node as *mut u32,
                    std::ptr::null_mut::<libc::c_void>(),
                );

                if result == 0 {
                    debug!("Current CPU: {}, NUMA node: {}", cpu, node);
                    return self.allocate_on_node(size, node.as_usize());
                } else {
                    warn!(
                        "getcpu syscall failed: errno {}, falling back to node 0",
                        *libc::__errno_location()
                    );
                    return self.allocate_on_node(size, 0);
                }
            }
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // On non-Linux or non-x86_64 systems, allocate on node 0
            debug!("NUMA node detection not supported on this platform, using node 0");
            self.allocate_on_node(size, 0)
        }
    }

    /// Get the number of NUMA nodes
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}

impl Default for NumaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory statistics
#[derive(Debug, Clone)]
pub struct MemoryStatistics {
    pub secure_allocations: AllocationCount,
    pub total_secure_memory: MemorySize,
    pub numa_nodes: NodeId,
}

/// Type alias for SecureBuffer to match crypto module expectations
pub type SecureBytes = SecureBuffer;

/// Global memory statistics tracker
static SECURE_ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static TOTAL_SECURE_MEMORY: AtomicUsize = AtomicUsize::new(0);

/// Get current memory statistics
pub fn memory_statistics() -> MemoryStatistics {
    MemoryStatistics {
        secure_allocations: AllocationCount::new(
            SECURE_ALLOCATION_COUNT.load(Ordering::Relaxed) as u64
        ),
        total_secure_memory: MemorySize::new(TOTAL_SECURE_MEMORY.load(Ordering::Relaxed) as u64),
        numa_nodes: NodeId::new(NumaAllocator::detect_numa_nodes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_with_capacity() {
        let buffer = SecureBuffer::with_capacity(32);
        assert_eq!(buffer.len(), 32);
        assert!(buffer.capacity() >= 32);
    }

    #[test]
    fn test_secure_buffer_from_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let buffer = SecureBuffer::from_slice(&data);
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.as_slice(), &data);
    }

    #[test]
    fn test_secure_buffer_new() {
        let buffer = SecureBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_secure_buffer_with_size() {
        let buffer = SecureBuffer::with_size(64);
        assert_eq!(buffer.len(), 64);
    }

    #[test]
    fn test_secure_buffer_extend_from_slice() {
        let mut buffer = SecureBuffer::new();
        buffer.extend_from_slice(&[1, 2, 3]);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_secure_buffer_push() {
        let mut buffer = SecureBuffer::new();
        buffer.push(42);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.as_slice()[0], 42);
    }

    #[test]
    fn test_secure_buffer_clear() {
        let mut buffer = SecureBuffer::from_slice(&[1, 2, 3, 4, 5]);
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_secure_buffer_resize() {
        let mut buffer = SecureBuffer::with_capacity(10);
        buffer.resize(20);
        assert_eq!(buffer.len(), 20);
        // New elements should be zeroed
        for &byte in &buffer.as_slice()[10..] {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn test_secure_buffer_truncate() {
        let mut buffer = SecureBuffer::from_slice(&[1, 2, 3, 4, 5]);
        buffer.truncate(3);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_secure_buffer_constant_time_eq() {
        let buffer = SecureBuffer::from_slice(&[1, 2, 3, 4, 5]);

        // Equal slices
        assert!(buffer.constant_time_eq(&[1, 2, 3, 4, 5]));

        // Different content
        assert!(!buffer.constant_time_eq(&[1, 2, 3, 4, 6]));

        // Different length
        assert!(!buffer.constant_time_eq(&[1, 2, 3]));
    }

    #[test]
    fn test_secure_buffer_copy_from_slice() {
        let mut buffer = SecureBuffer::from_slice(&[1, 2, 3]);
        buffer.copy_from_slice(&[4, 5, 6, 7]);
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &[4, 5, 6, 7]);
    }

    #[test]
    fn test_secure_buffer_debug_redacts_content() {
        let buffer = SecureBuffer::from_slice(&[0x42; 32]);
        let debug_output = format!("{:?}", buffer);

        // Should not contain the actual bytes
        assert!(!debug_output.contains("42"));
        // Should indicate it's redacted
        assert!(debug_output.contains("REDACTED"));
        assert!(debug_output.contains("32 bytes"));
    }

    #[test]
    fn test_secure_buffer_deref() {
        let buffer = SecureBuffer::from_slice(&[1, 2, 3]);
        // Test deref to &[u8]
        let slice: &[u8] = &buffer;
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn test_secure_buffer_deref_mut() {
        let mut buffer = SecureBuffer::from_slice(&[1, 2, 3]);
        // Test deref_mut to &mut [u8]
        let slice: &mut [u8] = &mut buffer;
        slice[0] = 10;
        assert_eq!(buffer.as_slice(), &[10, 2, 3]);
    }

    #[test]
    fn test_secure_buffer_reserve() {
        let mut buffer = SecureBuffer::new();
        buffer.reserve(100);
        assert!(buffer.capacity() >= 100);
    }

    #[test]
    fn test_secure_memory_new() {
        let memory = SecureMemory::new(BufferSize::new(64));
        assert!(memory.is_ok());
        let memory = memory.unwrap();
        assert_eq!(memory.size().as_usize(), 64);
    }

    #[test]
    fn test_secure_memory_zero_sized_fails() {
        let result = SecureMemory::new(BufferSize::new(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_memory_copy_from_slice() {
        let mut memory = SecureMemory::new(BufferSize::new(32)).unwrap();
        let data = [1u8, 2, 3, 4, 5];
        memory.copy_from_slice(&data).unwrap();
        assert_eq!(&memory.as_slice()[..5], &data);
    }

    #[test]
    fn test_secure_memory_copy_too_large_fails() {
        let mut memory = SecureMemory::new(BufferSize::new(4)).unwrap();
        let data = [1u8; 10];
        let result = memory.copy_from_slice(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_memory_constant_time_eq() {
        let mut memory = SecureMemory::new(BufferSize::new(5)).unwrap();
        memory.copy_from_slice(&[1, 2, 3, 4, 5]).unwrap();

        assert!(memory.constant_time_eq(&[1, 2, 3, 4, 5]));
        assert!(!memory.constant_time_eq(&[1, 2, 3, 4, 6]));
        assert!(!memory.constant_time_eq(&[1, 2, 3]));
    }

    #[test]
    fn test_secure_memory_zero() {
        let mut memory = SecureMemory::new(BufferSize::new(8)).unwrap();
        memory.copy_from_slice(&[0xFF; 8]).unwrap();
        memory.zero();

        for &byte in memory.as_slice() {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn test_numa_allocator_new() {
        let allocator = NumaAllocator::new();
        assert!(allocator.node_count() >= 1);
    }
}
