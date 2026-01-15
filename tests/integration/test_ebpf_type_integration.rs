/// eBPF Type Integration Tests
/// 
/// This module tests that the consolidated types work correctly with the existing
/// eBPF integration code and maintain compatibility across the FFI boundary.

use std::collections::HashMap;
use crate::common::rust::src::protocol::types::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that eBPF shared structures work with consolidated types
    #[test]
    fn test_shared_structures_with_consolidated_types() {
        // Test PacketMetadata structure
        let mut packet_meta = PacketMetadata::new();
        packet_meta.len = PacketSize::from_bytes(1500);
        packet_meta.src_ip = IpAddress::from_ipv4([192, 168, 1, 1]);
        packet_meta.dst_ip = IpAddress::from_ipv4([192, 168, 1, 2]);
        packet_meta.src_port = Port::from_raw(8080);
        packet_meta.dst_port = Port::from_raw(8443);
        packet_meta.session_id = SessionId::from_raw(12345);
        packet_meta.timestamp = Timestamp::from_nanos(1000000000);
        
        assert!(packet_meta.is_valid());
        assert_eq!(packet_meta.len.as_bytes(), 1500);
        assert_eq!(packet_meta.src_port.as_raw(), 8080);
        assert_eq!(packet_meta.dst_port.as_raw(), 8443);
        assert_eq!(packet_meta.session_id.as_raw(), 12345);
        
        // Test SessionInfo structure
        let mut session_info = SessionInfo::new(
            SessionId::from_raw(12345),
            IpAddress::from_ipv4([192, 168, 1, 1])
        );
        session_info.current_port = Port::from_raw(8080);
        session_info.next_port = Port::from_raw(8081);
        session_info.state = SessionState::Active;
        
        assert_eq!(session_info.session_id.as_raw(), 12345);
        assert!(session_info.is_active());
        
        // Test increment operations
        session_info.increment_packets(PacketSize::from_bytes(100));
        assert_eq!(session_info.packet_count.as_raw(), 1);
        assert_eq!(session_info.byte_count.as_raw(), 100);
    }

    /// Test that eBPF map keys work correctly
    #[test]
    fn test_ebpf_map_keys() {
        // Test SessionMapKey
        let session_key = SessionMapKey {
            session_id: SessionId::from_raw(12345).to_ebpf_u64(),
        };
        assert_eq!(session_key.session_id, 12345);
        
        // Test PortMapKey
        let port_key = PortMapKey {
            ip_addr: 0x0101A8C0, // 192.168.1.1 in network byte order
            port: Port::from_raw(8080).to_ebpf_u16(),
            reserved: 0,
        };
        assert_eq!(port_key.port, 8080);
        
        // Test SecurityMapKey
        let security_key = SecurityMapKey {
            session_id: SessionId::from_raw(12345).to_ebpf_u64(),
            context_type: 1,
            reserved: 0,
        };
        assert_eq!(security_key.session_id, 12345);
    }

    /// Test eBPF event creation and processing
    #[test]
    fn test_ebpf_events() {
        // Test SharedEvent creation
        let mut event = SharedEvent::new(
            EventType::PacketReceived,
            SessionId::from_raw(12345)
        );
        
        assert_eq!(event.session_id.as_raw(), 12345);
        assert_eq!(event.get_event_type(), Some(EventType::PacketReceived));
        
        // Test setting event data
        let test_data = b"test event data";
        event.set_data(test_data);
        assert_eq!(&event.data[..test_data.len()], test_data);
        
        // Test different event types
        let auth_failure_event = SharedEvent::new(
            EventType::AuthFailure,
            SessionId::from_raw(67890)
        );
        assert_eq!(auth_failure_event.get_event_type(), Some(EventType::AuthFailure));
        assert_eq!(auth_failure_event.session_id.as_raw(), 67890);
    }

    /// Test security context operations
    #[test]
    fn test_security_context() {
        let mut ctx = SecurityContext::new();
        
        // Test HMAC key setting
        let key = AuthenticationKey::from_bytes([0x42; 32]);
        ctx.set_hmac_key(key);
        assert_eq!(ctx.hmac_key.as_bytes(), &[0x42; 32]);
        
        // Test sequence validation
        ctx.last_sequence = SequenceNumber::from_raw(100);
        assert!(ctx.is_sequence_valid(SequenceNumber::from_raw(101)));
        assert!(!ctx.is_sequence_valid(SequenceNumber::from_raw(99)));
        assert!(!ctx.is_sequence_valid(SequenceNumber::from_raw(100)));
    }

    /// Test port hopping state
    #[test]
    fn test_port_hopping_state() {
        let mut state = PortHoppingState::new();
        
        // Set initial state
        state.current_port = Port::from_raw(8080);
        state.next_port = Port::from_raw(8081);
        state.hop_interval = HopInterval::from_millis(1000);
        state.last_hop = Timestamp::from_nanos(1000000000);
        
        // Test hop timing
        let current_time = Timestamp::from_nanos(2000000000); // 1 second later
        assert!(state.should_hop(current_time));
        
        let too_early = Timestamp::from_nanos(1500000000); // 0.5 seconds later
        assert!(!state.should_hop(too_early));
        
        // Test hop operation
        let new_port = Port::from_raw(8082);
        state.hop(new_port, current_time);
        assert_eq!(state.current_port.as_raw(), 8081);
        assert_eq!(state.next_port.as_raw(), 8082);
        assert_eq!(state.hop_count, 1);
    }

    /// Test eBPF type conversion roundtrips
    #[test]
    fn test_type_conversion_roundtrips() {
        // Test SessionId
        let original_session = SessionId::from_raw(0x123456789ABCDEF0);
        let ebpf_value = original_session.to_ebpf_u64();
        let converted_session = SessionId::from_ebpf_u64(ebpf_value);
        assert_eq!(original_session, converted_session);
        
        // Test Port
        let original_port = Port::from_raw(8080);
        let ebpf_value = original_port.to_ebpf_u16();
        let converted_port = Port::from_ebpf_u16(ebpf_value);
        assert_eq!(original_port, converted_port);
        
        // Test SequenceNumber
        let original_seq = SequenceNumber::from_raw(0x12345678);
        let ebpf_value = original_seq.to_ebpf_u32();
        let converted_seq = SequenceNumber::from_ebpf_u32(ebpf_value);
        assert_eq!(original_seq, converted_seq);
        
        // Test FragmentId
        let original_frag = FragmentId::from_raw(0x1234);
        let ebpf_value = original_frag.to_ebpf_u16();
        let converted_frag = FragmentId::from_ebpf_u16(ebpf_value);
        assert_eq!(original_frag, converted_frag);
    }

    /// Test eBPF compatibility validation
    #[test]
    fn test_ebpf_compatibility_validation() {
        // Test that core types are eBPF compatible
        let session_id = SessionId::from_raw(12345);
        assert!(session_id.is_ebpf_compatible());
        assert!(session_id.validate_map_usage().is_ok());
        
        let port = Port::from_raw(8080);
        assert!(port.is_ebpf_compatible());
        assert!(port.validate_map_usage().is_ok());
        
        let seq_num = SequenceNumber::from_raw(1000);
        assert!(seq_num.is_ebpf_compatible());
        assert!(seq_num.validate_map_usage().is_ok());
        
        let frag_id = FragmentId::from_raw(42);
        assert!(frag_id.is_ebpf_compatible());
        assert!(frag_id.validate_map_usage().is_ok());
        
        let timestamp = Timestamp::from_nanos(1000000000);
        assert!(timestamp.is_ebpf_compatible());
        assert!(timestamp.validate_map_usage().is_ok());
    }

    /// Test eBPF file descriptor operations
    #[test]
    fn test_ebpf_file_descriptor_operations() {
        let fd = EbpfFileDescriptor::from_raw(5);
        assert!(fd.is_valid());
        assert!(fd.is_ebpf_compatible());
        assert!(fd.validate_map_usage().is_ok());
        
        let invalid_fd = EbpfFileDescriptor::invalid();
        assert!(!invalid_fd.is_valid());
        assert!(!invalid_fd.is_ebpf_compatible());
        assert!(invalid_fd.validate_map_usage().is_err());
    }

    /// Test eBPF map configuration validation
    #[test]
    fn test_ebpf_map_configuration() {
        // Test valid hash map configuration
        let result = validate_map_config(
            EbpfMapType::Hash,
            KeySize::from_bytes(8), // SessionId size
            ValueSize::from_bytes(32), // SessionInfo size
            EbpfMapSize::from_entries(10000),
        );
        assert!(result.is_ok());
        
        // Test array map configuration
        let result = validate_map_config(
            EbpfMapType::Array,
            KeySize::from_bytes(4), // Array index
            ValueSize::from_bytes(16),
            EbpfMapSize::from_entries(1024),
        );
        assert!(result.is_ok());
        
        // Test ring buffer configuration
        let result = validate_map_config(
            EbpfMapType::RingBuf,
            KeySize::from_bytes(0), // Ring buffer doesn't use keys
            ValueSize::from_bytes(0), // Ring buffer doesn't use values
            EbpfMapSize::from_entries(4096),
        );
        assert!(result.is_ok());
    }

    /// Test eBPF program configuration validation
    #[test]
    fn test_ebpf_program_configuration() {
        // Test XDP program configuration
        let result = validate_program_config(
            EbpfProgramType::Xdp,
            None, // XDP doesn't use attach type
            EbpfInstructionCount::from_raw(1000),
            EbpfStackSize::from_bytes(256),
        );
        assert!(result.is_ok());
        
        // Test socket filter configuration
        let result = validate_program_config(
            EbpfProgramType::SocketFilter,
            Some(EbpfAttachType::CgroupInetIngress),
            EbpfInstructionCount::from_raw(500),
            EbpfStackSize::from_bytes(128),
        );
        assert!(result.is_ok());
        
        // Test TC program configuration
        let result = validate_program_config(
            EbpfProgramType::SchedCls,
            Some(EbpfAttachType::CgroupInetEgress),
            EbpfInstructionCount::from_raw(2000),
            EbpfStackSize::from_bytes(512),
        );
        assert!(result.is_ok());
    }

    /// Test comprehensive eBPF compatibility
    #[test]
    fn test_comprehensive_ebpf_compatibility() {
        let result = validate_ebpf_compatibility();
        assert!(result.is_ok(), "eBPF compatibility validation failed: {:?}", result);
    }
}

/// Mock implementations for testing
#[cfg(test)]
mod mock_ebpf_types {
    use super::*;

    /// Mock PacketMetadata for testing
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PacketMetadata {
        pub len: PacketSize,
        pub src_ip: IpAddress,
        pub dst_ip: IpAddress,
        pub src_port: Port,
        pub dst_port: Port,
        pub protocol: u8,
        pub flags: PacketFlags,
        pub timestamp: Timestamp,
        pub session_id: SessionId,
    }

    impl PacketMetadata {
        pub fn new() -> Self {
            Self {
                len: PacketSize::from_bytes(0),
                src_ip: IpAddress::from_ipv4([0, 0, 0, 0]),
                dst_ip: IpAddress::from_ipv4([0, 0, 0, 0]),
                src_port: Port::from_raw(0),
                dst_port: Port::from_raw(0),
                protocol: 0,
                flags: PacketFlags::empty(),
                timestamp: Timestamp::from_nanos(0),
                session_id: SessionId::from_raw(0),
            }
        }

        pub fn is_valid(&self) -> bool {
            self.len.as_bytes() > 0 && self.len.as_bytes() <= 65535
        }
    }

    /// Mock SessionInfo for testing
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionInfo {
        pub session_id: SessionId,
        pub peer_ip: IpAddress,
        pub current_port: Port,
        pub next_port: Port,
        pub state: SessionState,
        pub last_activity: Timestamp,
        pub packet_count: PacketCount,
        pub byte_count: ByteCount,
    }

    impl SessionInfo {
        pub fn new(session_id: SessionId, peer_ip: IpAddress) -> Self {
            Self {
                session_id,
                peer_ip,
                current_port: Port::from_raw(0),
                next_port: Port::from_raw(0),
                state: SessionState::Initializing,
                last_activity: Timestamp::from_nanos(0),
                packet_count: PacketCount::from_raw(0),
                byte_count: ByteCount::from_raw(0),
            }
        }

        pub fn is_active(&self) -> bool {
            matches!(self.state, SessionState::Active)
        }

        pub fn increment_packets(&mut self, bytes: PacketSize) {
            self.packet_count = PacketCount::from_raw(self.packet_count.as_raw() + 1);
            self.byte_count = ByteCount::from_raw(self.byte_count.as_raw() + bytes.as_bytes() as u64);
        }
    }

    /// Mock SecurityContext for testing
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityContext {
        pub hmac_key: AuthenticationKey,
        pub replay_window: TimestampWindow,
        pub last_sequence: SequenceNumber,
        pub key_rotation: u32,
        pub flags: u32,
        pub reserved: [u8; 12],
    }

    impl SecurityContext {
        pub fn new() -> Self {
            Self {
                hmac_key: AuthenticationKey::from_bytes([0; 32]),
                replay_window: TimestampWindow::from_millis(0),
                last_sequence: SequenceNumber::from_raw(0),
                key_rotation: 0,
                flags: 0,
                reserved: [0; 12],
            }
        }

        pub fn set_hmac_key(&mut self, key: AuthenticationKey) {
            self.hmac_key = key;
        }

        pub fn is_sequence_valid(&self, sequence: SequenceNumber) -> bool {
            sequence.as_raw() > self.last_sequence.as_raw()
        }
    }

    /// Mock PortHoppingState for testing
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PortHoppingState {
        pub epoch: Epoch,
        pub current_port: Port,
        pub next_port: Port,
        pub hop_interval: HopInterval,
        pub last_hop: Timestamp,
        pub hop_count: u32,
        pub reserved: u16,
    }

    impl PortHoppingState {
        pub fn new() -> Self {
            Self {
                epoch: Epoch::from_raw(0),
                current_port: Port::from_raw(0),
                next_port: Port::from_raw(0),
                hop_interval: HopInterval::from_millis(1000),
                last_hop: Timestamp::from_nanos(0),
                hop_count: 0,
                reserved: 0,
            }
        }

        pub fn should_hop(&self, current_time: Timestamp) -> bool {
            current_time.as_nanos() >= self.last_hop.as_nanos() + (self.hop_interval.as_millis() * 1_000_000)
        }

        pub fn hop(&mut self, new_port: Port, timestamp: Timestamp) {
            self.current_port = self.next_port;
            self.next_port = new_port;
            self.last_hop = timestamp;
            self.hop_count += 1;
        }
    }

    /// Mock SharedEvent for testing
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SharedEvent {
        pub event_type: EbpfEventType,
        pub timestamp: Timestamp,
        pub session_id: SessionId,
        pub data: [u8; 64],
    }

    impl SharedEvent {
        pub fn new(event_type: EventType, session_id: SessionId) -> Self {
            Self {
                event_type: EbpfEventType::from_raw(event_type as u32),
                timestamp: Timestamp::from_nanos(0),
                session_id,
                data: [0; 64],
            }
        }

        pub fn set_data(&mut self, data: &[u8]) {
            let len = std::cmp::min(data.len(), 64);
            self.data[..len].copy_from_slice(&data[..len]);
        }

        pub fn get_event_type(&self) -> Option<EventType> {
            match self.event_type.as_raw() {
                1 => Some(EventType::PacketReceived),
                2 => Some(EventType::AuthFailure),
                3 => Some(EventType::ReplayAttack),
                4 => Some(EventType::PortHop),
                5 => Some(EventType::SessionEstablished),
                6 => Some(EventType::SessionTerminated),
                7 => Some(EventType::SecurityViolation),
                8 => Some(EventType::PerformanceAlert),
                _ => None,
            }
        }
    }

    /// Mock map key types
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SessionMapKey {
        pub session_id: u64,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PortMapKey {
        pub ip_addr: u32,
        pub port: u16,
        pub reserved: u16,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SecurityMapKey {
        pub session_id: u64,
        pub context_type: u32,
        pub reserved: u32,
    }

    /// Mock event types
    #[repr(u32)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventType {
        PacketReceived = 1,
        AuthFailure = 2,
        ReplayAttack = 3,
        PortHop = 4,
        SessionEstablished = 5,
        SessionTerminated = 6,
        SecurityViolation = 7,
        PerformanceAlert = 8,
    }
}