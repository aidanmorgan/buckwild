/// eBPF Compatibility Validation Tests
/// 
/// This module tests that all eBPF boundary types are compatible with C FFI
/// and work correctly across the eBPF boundary.

use std::mem;
use std::ffi::c_int;
use crate::common::rust::src::protocol::types::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that eBPF types have correct C representation
    #[test]
    fn test_ebpf_type_c_representation() {
        // Test that EbpfFileDescriptor is transparent and C-compatible
        assert_eq!(mem::size_of::<EbpfFileDescriptor>(), mem::size_of::<c_int>());
        assert_eq!(mem::align_of::<EbpfFileDescriptor>(), mem::align_of::<c_int>());
        
        // Test that enum types have correct size
        assert_eq!(mem::size_of::<EbpfMapType>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<EbpfEventType>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<EbpfReturnCode>(), mem::size_of::<i32>());
        assert_eq!(mem::size_of::<EbpfProgramType>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<EbpfAttachType>(), mem::size_of::<u32>());
        
        // Test that size types are transparent
        assert_eq!(mem::size_of::<EbpfInstructionCount>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<EbpfMapSize>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<EbpfProgramId>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<EbpfStackSize>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<RingBufferSize>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<KeySize>(), mem::size_of::<u32>());
        assert_eq!(mem::size_of::<ValueSize>(), mem::size_of::<u32>());
    }

    /// Test eBPF file descriptor operations
    #[test]
    fn test_ebpf_file_descriptor_operations() {
        let fd = EbpfFileDescriptor::from_raw(5);
        assert_eq!(fd.as_raw(), 5);
        assert!(fd.is_valid());
        
        let invalid_fd = EbpfFileDescriptor::invalid();
        assert_eq!(invalid_fd.as_raw(), -1);
        assert!(!invalid_fd.is_valid());
        
        let default_fd = EbpfFileDescriptor::default();
        assert_eq!(default_fd.as_raw(), -1);
        assert!(!default_fd.is_valid());
    }

    /// Test eBPF map type serialization/deserialization
    #[test]
    fn test_ebpf_map_type_serialization() {
        let map_type = EbpfMapType::Hash;
        assert_eq!(map_type.as_raw(), 1);
        assert_eq!(EbpfMapType::from_raw(1), Some(EbpfMapType::Hash));
        
        let ring_buf = EbpfMapType::RingBuf;
        assert_eq!(ring_buf.as_raw(), 27);
        assert_eq!(EbpfMapType::from_raw(27), Some(EbpfMapType::RingBuf));
        
        // Test invalid value
        assert_eq!(EbpfMapType::from_raw(999), None);
    }

    /// Test eBPF event type serialization/deserialization
    #[test]
    fn test_ebpf_event_type_serialization() {
        let event_type = EbpfEventType::PacketReceived;
        assert_eq!(event_type.as_raw(), 1);
        assert_eq!(EbpfEventType::from_raw(1), EbpfEventType::PacketReceived);
        
        let auth_failure = EbpfEventType::AuthFailure;
        assert_eq!(auth_failure.as_raw(), 2);
        assert_eq!(EbpfEventType::from_raw(2), EbpfEventType::AuthFailure);
        
        // Test invalid value defaults to Error
        assert_eq!(EbpfEventType::from_raw(999), EbpfEventType::Error);
    }

    /// Test eBPF return code operations
    #[test]
    fn test_ebpf_return_code_operations() {
        let pass = EbpfReturnCode::Pass;
        assert_eq!(pass.as_raw(), 1);
        assert_eq!(EbpfReturnCode::from_raw(1), Some(EbpfReturnCode::Pass));
        
        let drop = EbpfReturnCode::Drop;
        assert_eq!(drop.as_raw(), 0);
        assert_eq!(EbpfReturnCode::from_raw(0), Some(EbpfReturnCode::Drop));
        
        // Test invalid value
        assert_eq!(EbpfReturnCode::from_raw(999), None);
    }

    /// Test eBPF instruction count validation
    #[test]
    fn test_ebpf_instruction_count_validation() {
        let valid_count = EbpfInstructionCount::from_raw(1000);
        assert_eq!(valid_count.as_raw(), 1000);
        assert!(valid_count.is_valid());
        
        let max_count = EbpfInstructionCount::from_raw(EbpfInstructionCount::MAX_INSTRUCTIONS);
        assert!(max_count.is_valid());
        
        let invalid_count = EbpfInstructionCount::from_raw(EbpfInstructionCount::MAX_INSTRUCTIONS + 1);
        assert!(!invalid_count.is_valid());
    }

    /// Test eBPF map size validation
    #[test]
    fn test_ebpf_map_size_validation() {
        let valid_size = EbpfMapSize::from_entries(1024);
        assert_eq!(valid_size.as_entries(), 1024);
        assert!(valid_size.is_valid());
        
        let zero_size = EbpfMapSize::from_entries(0);
        assert!(!zero_size.is_valid());
        
        let max_size = EbpfMapSize::from_entries(EbpfMapSize::MAX_ENTRIES);
        assert!(max_size.is_valid());
        
        let invalid_size = EbpfMapSize::from_entries(EbpfMapSize::MAX_ENTRIES + 1);
        assert!(!invalid_size.is_valid());
    }

    /// Test ring buffer size validation (must be power of 2)
    #[test]
    fn test_ring_buffer_size_validation() {
        let valid_size = RingBufferSize::from_bytes(1024);
        assert_eq!(valid_size.as_bytes(), 1024);
        assert!(valid_size.is_valid());
        
        let default_size = RingBufferSize::default();
        assert_eq!(default_size.as_bytes(), RingBufferSize::DEFAULT_SIZE);
        assert!(default_size.is_valid());
        
        // Test power of 2 requirement
        let invalid_size = RingBufferSize::from_bytes(1000);
        assert!(!invalid_size.is_valid());
        
        let zero_size = RingBufferSize::from_bytes(0);
        assert!(!zero_size.is_valid());
        
        let too_large = RingBufferSize::from_bytes(RingBufferSize::MAX_SIZE + 1);
        assert!(!too_large.is_valid());
    }

    /// Test key and value size validation
    #[test]
    fn test_key_value_size_validation() {
        let key_size = KeySize::from_bytes(4);
        assert_eq!(key_size.as_bytes(), 4);
        assert!(key_size.is_valid());
        
        let value_size = ValueSize::from_bytes(8);
        assert_eq!(value_size.as_bytes(), 8);
        assert!(value_size.is_valid());
        
        let zero_key = KeySize::from_bytes(0);
        assert!(!zero_key.is_valid());
        
        let zero_value = ValueSize::from_bytes(0);
        assert!(!zero_value.is_valid());
        
        let max_key = KeySize::from_bytes(KeySize::MAX_KEY_SIZE);
        assert!(max_key.is_valid());
        
        let max_value = ValueSize::from_bytes(ValueSize::MAX_VALUE_SIZE);
        assert!(max_value.is_valid());
        
        let invalid_key = KeySize::from_bytes(KeySize::MAX_KEY_SIZE + 1);
        assert!(!invalid_key.is_valid());
        
        let invalid_value = ValueSize::from_bytes(ValueSize::MAX_VALUE_SIZE + 1);
        assert!(!invalid_value.is_valid());
    }

    /// Test eBPF stack size validation
    #[test]
    fn test_ebpf_stack_size_validation() {
        let valid_stack = EbpfStackSize::from_bytes(256);
        assert_eq!(valid_stack.as_bytes(), 256);
        assert!(valid_stack.is_valid());
        
        let max_stack = EbpfStackSize::from_bytes(EbpfStackSize::MAX_STACK_SIZE);
        assert!(max_stack.is_valid());
        
        let invalid_stack = EbpfStackSize::from_bytes(EbpfStackSize::MAX_STACK_SIZE + 1);
        assert!(!invalid_stack.is_valid());
        
        let default_stack = EbpfStackSize::default();
        assert_eq!(default_stack.as_bytes(), EbpfStackSize::MAX_STACK_SIZE);
        assert!(default_stack.is_valid());
    }

    /// Test eBPF program ID operations
    #[test]
    fn test_ebpf_program_id_operations() {
        let valid_id = EbpfProgramId::from_raw(12345);
        assert_eq!(valid_id.as_raw(), 12345);
        assert!(valid_id.is_valid());
        
        let invalid_id = EbpfProgramId::from_raw(EbpfProgramId::INVALID);
        assert_eq!(invalid_id.as_raw(), 0);
        assert!(!invalid_id.is_valid());
        
        let default_id = EbpfProgramId::default();
        assert_eq!(default_id.as_raw(), 0);
        assert!(!default_id.is_valid());
    }

    /// Test eBPF program type operations
    #[test]
    fn test_ebpf_program_type_operations() {
        let xdp_type = EbpfProgramType::Xdp;
        assert_eq!(xdp_type.as_raw(), 6);
        assert_eq!(EbpfProgramType::from_raw(6), Some(EbpfProgramType::Xdp));
        
        let socket_filter = EbpfProgramType::SocketFilter;
        assert_eq!(socket_filter.as_raw(), 1);
        assert_eq!(EbpfProgramType::from_raw(1), Some(EbpfProgramType::SocketFilter));
        
        // Test invalid value
        assert_eq!(EbpfProgramType::from_raw(999), None);
    }

    /// Test eBPF attach type operations
    #[test]
    fn test_ebpf_attach_type_operations() {
        let ingress = EbpfAttachType::CgroupInetIngress;
        assert_eq!(ingress.as_raw(), 0);
        assert_eq!(EbpfAttachType::from_raw(0), Some(EbpfAttachType::CgroupInetIngress));
        
        let egress = EbpfAttachType::CgroupInetEgress;
        assert_eq!(egress.as_raw(), 1);
        assert_eq!(EbpfAttachType::from_raw(1), Some(EbpfAttachType::CgroupInetEgress));
        
        // Test invalid value
        assert_eq!(EbpfAttachType::from_raw(999), None);
    }
}

/// Memory layout compatibility tests
#[cfg(test)]
mod memory_layout_tests {
    use super::*;

    /// Test that shared data structures have expected memory layout
    #[test]
    fn test_shared_structure_memory_layout() {
        // These structures are defined in ebpf/src/interop/shared.rs
        // We need to ensure they maintain C-compatible layout
        
        // Test that basic types have expected sizes
        assert_eq!(mem::size_of::<SessionId>(), 8); // u64
        assert_eq!(mem::size_of::<Port>(), 2); // u16
        assert_eq!(mem::size_of::<Timestamp>(), 8); // u64
        assert_eq!(mem::size_of::<PacketSize>(), 2); // u16
        assert_eq!(mem::size_of::<SequenceNumber>(), 4); // u32
        
        // Test alignment requirements
        assert_eq!(mem::align_of::<SessionId>(), 8);
        assert_eq!(mem::align_of::<Port>(), 2);
        assert_eq!(mem::align_of::<Timestamp>(), 8);
        assert_eq!(mem::align_of::<PacketSize>(), 2);
        assert_eq!(mem::align_of::<SequenceNumber>(), 4);
    }

    /// Test that eBPF types can be safely transmitted across FFI boundary
    #[test]
    fn test_ffi_boundary_safety() {
        // Test that we can safely convert between raw values and types
        let fd = EbpfFileDescriptor::from_raw(5);
        let raw_fd: c_int = fd.as_raw();
        let fd2 = EbpfFileDescriptor::from_raw(raw_fd);
        assert_eq!(fd, fd2);
        
        // Test enum conversion
        let map_type = EbpfMapType::Hash;
        let raw_type: u32 = map_type.as_raw();
        let map_type2 = EbpfMapType::from_raw(raw_type).unwrap();
        assert_eq!(map_type, map_type2);
        
        // Test size type conversion
        let size = EbpfMapSize::from_entries(1024);
        let raw_size: u32 = size.as_raw();
        let size2 = EbpfMapSize::from_entries(raw_size);
        assert_eq!(size, size2);
    }

    /// Test that types maintain their invariants across serialization
    #[test]
    fn test_serialization_invariants() {
        // Test that ring buffer size maintains power-of-2 invariant
        let valid_sizes = [1024, 2048, 4096, 8192, 16384, 32768, 65536];
        for size in valid_sizes {
            let ring_buf = RingBufferSize::from_bytes(size);
            assert!(ring_buf.is_valid());
            assert_eq!(ring_buf.as_bytes(), size);
        }
        
        // Test that invalid sizes are rejected
        let invalid_sizes = [1000, 1500, 3000, 5000];
        for size in invalid_sizes {
            let ring_buf = RingBufferSize::from_bytes(size);
            assert!(!ring_buf.is_valid());
        }
    }
}

/// Atomic operations compatibility tests
#[cfg(test)]
mod atomic_compatibility_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, AtomicI32, Ordering};

    /// Test that eBPF types work correctly with atomic operations
    #[test]
    fn test_atomic_operations() {
        // Test that we can use eBPF types with atomic operations
        let atomic_fd = AtomicI32::new(-1);
        let fd = EbpfFileDescriptor::from_raw(atomic_fd.load(Ordering::Relaxed));
        assert!(!fd.is_valid());
        
        atomic_fd.store(5, Ordering::Relaxed);
        let fd2 = EbpfFileDescriptor::from_raw(atomic_fd.load(Ordering::Relaxed));
        assert!(fd2.is_valid());
        assert_eq!(fd2.as_raw(), 5);
        
        // Test atomic enum operations
        let atomic_type = AtomicU32::new(EbpfMapType::Hash.as_raw());
        let map_type = EbpfMapType::from_raw(atomic_type.load(Ordering::Relaxed)).unwrap();
        assert_eq!(map_type, EbpfMapType::Hash);
        
        atomic_type.store(EbpfMapType::Array.as_raw(), Ordering::Relaxed);
        let map_type2 = EbpfMapType::from_raw(atomic_type.load(Ordering::Relaxed)).unwrap();
        assert_eq!(map_type2, EbpfMapType::Array);
    }

    /// Test compare-and-swap operations with eBPF types
    #[test]
    fn test_compare_and_swap() {
        let atomic_size = AtomicU32::new(1024);
        let old_size = EbpfMapSize::from_entries(1024);
        let new_size = EbpfMapSize::from_entries(2048);
        
        let result = atomic_size.compare_exchange(
            old_size.as_raw(),
            new_size.as_raw(),
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), old_size.as_raw());
        
        let current_size = EbpfMapSize::from_entries(atomic_size.load(Ordering::Relaxed));
        assert_eq!(current_size, new_size);
    }
}

/// eBPF map key/value compatibility tests
#[cfg(test)]
mod map_compatibility_tests {
    use super::*;

    /// Test that map keys are properly sized and aligned
    #[test]
    fn test_map_key_compatibility() {
        // Test session map key (should be 8 bytes for u64 session ID)
        let session_id = SessionId::from_raw(12345);
        let key_bytes = session_id.to_ebpf_u64().to_ne_bytes();
        assert_eq!(key_bytes.len(), 8);
        
        // Test port map key (should be properly aligned)
        let port = Port::from_raw(8080);
        let port_bytes = port.to_ebpf_u16().to_ne_bytes();
        assert_eq!(port_bytes.len(), 2);
        
        // Test sequence number (should be 4 bytes)
        let seq = SequenceNumber::from_raw(1000);
        let seq_bytes = seq.to_ebpf_u32().to_ne_bytes();
        assert_eq!(seq_bytes.len(), 4);
        
        // Test fragment ID (should be 2 bytes)
        let frag_id = FragmentId::from_raw(42);
        let frag_bytes = frag_id.to_ebpf_u16().to_ne_bytes();
        assert_eq!(frag_bytes.len(), 2);
    }

    /// Test that we can convert between eBPF and Rust representations
    #[test]
    fn test_ebpf_conversion_roundtrip() {
        // Test SessionId conversion
        let original_session = SessionId::from_raw(0x123456789ABCDEF0);
        let ebpf_value = original_session.to_ebpf_u64();
        let converted_session = SessionId::from_ebpf_u64(ebpf_value);
        assert_eq!(original_session, converted_session);
        
        // Test Port conversion
        let original_port = Port::from_raw(8080);
        let ebpf_value = original_port.to_ebpf_u16();
        let converted_port = Port::from_ebpf_u16(ebpf_value);
        assert_eq!(original_port, converted_port);
        
        // Test SequenceNumber conversion
        let original_seq = SequenceNumber::from_raw(0x12345678);
        let ebpf_value = original_seq.to_ebpf_u32();
        let converted_seq = SequenceNumber::from_ebpf_u32(ebpf_value);
        assert_eq!(original_seq, converted_seq);
        
        // Test FragmentId conversion
        let original_frag = FragmentId::from_raw(0x1234);
        let ebpf_value = original_frag.to_ebpf_u16();
        let converted_frag = FragmentId::from_ebpf_u16(ebpf_value);
        assert_eq!(original_frag, converted_frag);
    }
}