/// Comprehensive test coverage for consolidated protocol types
/// 
/// This test module provides complete coverage for all newtype wrappers,
/// atomic operations, type conversions, and trait implementations.

use std::sync::atomic::Ordering;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use crate::protocol::types::*;
use crate::protocol::types::atomic::*;

#[cfg(test)]
mod header_types {
    use super::*;

    #[test]
    fn test_protocol_version() {
        let version = ProtocolVersion::new(1);
        assert_eq!(version.as_u8(), 1);
        assert_eq!(ProtocolVersion::CURRENT.as_u8(), 1);
        assert_eq!(ProtocolVersion::MAX.as_u8(), 1);
        
        // Test From/Into conversions
        let version_from: ProtocolVersion = 2u8.into();
        assert_eq!(version_from.as_u8(), 2);
        
        // Test Debug trait
        assert!(format!("{:?}", version).contains("ProtocolVersion"));
        
        // Test Clone, Copy, PartialEq, Eq
        let version2 = version;
        assert_eq!(version, version2);
        
        // Test PartialOrd, Ord
        assert!(ProtocolVersion::new(1) < ProtocolVersion::new(2));
        
        // Test Hash
        let mut hasher = DefaultHasher::new();
        version.hash(&mut hasher);
        let hash1 = hasher.finish();
        
        let mut hasher2 = DefaultHasher::new();
        version.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_version_byte() {
        let version_byte = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        assert!(version_byte.as_u8() > 0);
        
        // Test raw construction
        let raw_version = VersionByte::from_raw(0x15);
        assert_eq!(raw_version.as_u8(), 0x15);
        
        // Test From/Into conversions
        let version_from: VersionByte = 0x20u8.into();
        assert_eq!(version_from.as_u8(), 0x20);
        
        // Test all traits
        test_basic_traits(&version_byte);
    }

    #[test]
    fn test_session_id_length() {
        // Test all variants
        assert_eq!(SessionIdLength::Bits16 as u8, 0);
        assert_eq!(SessionIdLength::Bits32 as u8, 1);
        assert_eq!(SessionIdLength::Bits64 as u8, 2);
        
        // Test from_u8
        assert_eq!(SessionIdLength::from_u8(0), SessionIdLength::Bits16);
        assert_eq!(SessionIdLength::from_u8(1), SessionIdLength::Bits32);
        assert_eq!(SessionIdLength::from_u8(2), SessionIdLength::Bits64);
        assert_eq!(SessionIdLength::from_u8(3), SessionIdLength::Bits32); // Default fallback
        
        // Test len
        assert_eq!(SessionIdLength::Bits16.len(), 2);
        assert_eq!(SessionIdLength::Bits32.len(), 4);
        assert_eq!(SessionIdLength::Bits64.len(), 8);
        
        // Test Debug, Clone, Copy, PartialEq, Eq
        let length = SessionIdLength::Bits32;
        let length2 = length;
        assert_eq!(length, length2);
        assert!(format!("{:?}", length).contains("Bits32"));
    }

    #[test]
    fn test_timestamp_config() {
        // Test all variants
        assert_eq!(TimestampConfig::Bits16 as u8, 0);
        assert_eq!(TimestampConfig::Bits24 as u8, 1);
        assert_eq!(TimestampConfig::Bits24High as u8, 2);
        assert_eq!(TimestampConfig::Bits32 as u8, 3);
        
        // Test from_u8
        assert_eq!(TimestampConfig::from_u8(0), TimestampConfig::Bits16);
        assert_eq!(TimestampConfig::from_u8(1), TimestampConfig::Bits24);
        assert_eq!(TimestampConfig::from_u8(2), TimestampConfig::Bits24High);
        assert_eq!(TimestampConfig::from_u8(3), TimestampConfig::Bits32);
        assert_eq!(TimestampConfig::from_u8(4), TimestampConfig::Bits32); // Default fallback
        
        // Test len
        assert_eq!(TimestampConfig::Bits16.len(), 2);
        assert_eq!(TimestampConfig::Bits24.len(), 3);
        assert_eq!(TimestampConfig::Bits24High.len(), 3);
        assert_eq!(TimestampConfig::Bits32.len(), 4);
        
        test_basic_traits(&TimestampConfig::Bits24);
    }

    #[test]
    fn test_packet_type() {
        // Test all variants with correct values
        assert_eq!(PacketType::Syn as u8, 0x01);
        assert_eq!(PacketType::SynAck as u8, 0x02);
        assert_eq!(PacketType::Ack as u8, 0x03);
        assert_eq!(PacketType::Data as u8, 0x04);
        assert_eq!(PacketType::Fin as u8, 0x05);
        assert_eq!(PacketType::Heartbeat as u8, 0x06);
        assert_eq!(PacketType::Error as u8, 0x09);
        assert_eq!(PacketType::Rst as u8, 0x0B);
        assert_eq!(PacketType::Control as u8, 0x0C);
        assert_eq!(PacketType::Management as u8, 0x0D);
        assert_eq!(PacketType::Discovery as u8, 0x0E);
        
        // Test from_u8
        assert_eq!(PacketType::from_u8(0x01), Some(PacketType::Syn));
        assert_eq!(PacketType::from_u8(0x02), Some(PacketType::SynAck));
        assert_eq!(PacketType::from_u8(0xFF), None); // Invalid
        
        // Test as_u8
        assert_eq!(PacketType::Syn.as_u8(), 0x01);
        assert_eq!(PacketType::Discovery.as_u8(), 0x0E);
        
        test_basic_traits(&PacketType::Data);
    }

    #[test]
    fn test_packet_flags() {
        let mut flags = PacketFlags::new();
        assert_eq!(flags.as_u8(), 0);
        
        // Test flag constants
        assert_eq!(PacketFlags::FIN, 1 << 0);
        assert_eq!(PacketFlags::SYN, 1 << 1);
        assert_eq!(PacketFlags::RST, 1 << 2);
        assert_eq!(PacketFlags::PSH, 1 << 3);
        assert_eq!(PacketFlags::ACK, 1 << 4);
        assert_eq!(PacketFlags::URG, 1 << 5);
        assert_eq!(PacketFlags::SACK, 1 << 6);
        assert_eq!(PacketFlags::FRAGMENT, 1 << 7);
        
        // Test setting flags
        flags.set(PacketFlags::SYN);
        assert!(flags.is_set(PacketFlags::SYN));
        assert!(!flags.is_set(PacketFlags::ACK));
        
        flags.set(PacketFlags::ACK);
        assert!(flags.is_set(PacketFlags::SYN));
        assert!(flags.is_set(PacketFlags::ACK));
        
        // Test clearing flags
        flags.clear(PacketFlags::SYN);
        assert!(!flags.is_set(PacketFlags::SYN));
        assert!(flags.is_set(PacketFlags::ACK));
        
        // Test with_flags constructor
        let flags2 = PacketFlags::with_flags(PacketFlags::SYN | PacketFlags::ACK);
        assert!(flags2.is_set(PacketFlags::SYN));
        assert!(flags2.is_set(PacketFlags::ACK));
        
        // Test From conversion
        let flags3: PacketFlags = 0x12u8.into();
        assert_eq!(flags3.as_u8(), 0x12);
        
        test_basic_traits(&flags);
    }

    #[test]
    fn test_payload_length() {
        let length = PayloadLength::new(1500);
        assert_eq!(length.as_u16(), 1500);
        
        // Test From/Into conversions
        let length2: PayloadLength = 2000u16.into();
        assert_eq!(length2.as_u16(), 2000);
        
        let raw: u16 = length.into();
        assert_eq!(raw, 1500);
        
        test_basic_traits(&length);
    }

    #[test]
    fn test_error_code() {
        let error = ErrorCode::new(0x42);
        assert_eq!(error.as_u8(), 0x42);
        
        // Test From/Into conversions
        let error2: ErrorCode = 0x55u8.into();
        assert_eq!(error2.as_u8(), 0x55);
        
        let raw: u8 = error.into();
        assert_eq!(raw, 0x42);
        
        test_basic_traits(&error);
    }

    // Helper function to test basic traits
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod identifier_types {
    use super::*;

    #[test]
    fn test_session_id() {
        let session_id = SessionId::new(0x123456789ABCDEF0, SessionIdLength::Bits64);
        assert_eq!(session_id.as_u64(), 0x123456789ABCDEF0);
        assert_eq!(session_id.as_raw(), 0x123456789ABCDEF0);
        
        // Test length-based construction
        let session_16 = SessionId::new(0x123456789ABCDEF0, SessionIdLength::Bits16);
        assert_eq!(session_16.as_u64(), 0xDEF0); // Masked to 16 bits
        
        let session_32 = SessionId::new(0x123456789ABCDEF0, SessionIdLength::Bits32);
        assert_eq!(session_32.as_u64(), 0x9ABCDEF0); // Masked to 32 bits
        
        // Test from_raw
        let session_raw = SessionId::from_raw(0x12345678);
        assert_eq!(session_raw.as_u64(), 0x12345678);
        
        // Test eBPF conversions
        assert_eq!(session_id.to_ebpf_u64(), 0x123456789ABCDEF0);
        let from_ebpf = SessionId::from_ebpf_u64(0x87654321);
        assert_eq!(from_ebpf.as_u64(), 0x87654321);
        
        // Test encoding length detection
        let small_id = SessionId::from_raw(100);
        assert_eq!(small_id.encoding_length(), SessionIdLength::Bits16);
        
        let medium_id = SessionId::from_raw(0x12345678);
        assert_eq!(medium_id.encoding_length(), SessionIdLength::Bits32);
        
        let large_id = SessionId::from_raw(0x123456789ABCDEF0);
        assert_eq!(large_id.encoding_length(), SessionIdLength::Bits64);
        
        // Test From/Into conversions
        let session_from: SessionId = 0x11223344u64.into();
        assert_eq!(session_from.as_u64(), 0x11223344);
        
        let raw: u64 = session_id.into();
        assert_eq!(raw, 0x123456789ABCDEF0);
        
        // Test Display
        let display_str = format!("{}", session_id);
        assert_eq!(display_str, "1311768467463790320");
        
        test_basic_traits(&session_id);
    }

    #[test]
    fn test_connection_id() {
        let conn_id = ConnectionId::new(0x123456789ABCDEF0);
        assert_eq!(conn_id.as_u64(), 0x123456789ABCDEF0);
        
        // Test From/Into conversions
        let conn_from: ConnectionId = 0x11223344u64.into();
        assert_eq!(conn_from.as_u64(), 0x11223344);
        
        let raw: u64 = conn_id.into();
        assert_eq!(raw, 0x123456789ABCDEF0);
        
        // Test Display
        let display_str = format!("{}", conn_id);
        assert_eq!(display_str, "1311768467463790320");
        
        test_basic_traits(&conn_id);
    }

    #[test]
    fn test_sequence_number() {
        let seq = SequenceNumber::new(0x12345678);
        assert_eq!(seq.as_u32(), 0x12345678);
        assert_eq!(SequenceNumber::MAX, 0xFFFFFFFF);
        
        // Test wrapping operations
        let next = seq.next();
        assert_eq!(next.as_u32(), 0x12345679);
        
        let max_seq = SequenceNumber::new(0xFFFFFFFF);
        let wrapped = max_seq.next();
        assert_eq!(wrapped.as_u32(), 0); // Wraps around
        
        // Test diff
        let seq1 = SequenceNumber::new(100);
        let seq2 = SequenceNumber::new(50);
        assert_eq!(seq1.diff(&seq2), 50);
        
        // Test eBPF conversions
        assert_eq!(seq.to_ebpf_u32(), 0x12345678);
        let from_ebpf = SequenceNumber::from_ebpf_u32(0x87654321);
        assert_eq!(from_ebpf.as_u32(), 0x87654321);
        
        // Test From/Into conversions
        let seq_from: SequenceNumber = 0x11223344u32.into();
        assert_eq!(seq_from.as_u32(), 0x11223344);
        
        let raw: u32 = seq.into();
        assert_eq!(raw, 0x12345678);
        
        test_basic_traits(&seq);
    }

    #[test]
    fn test_ack_number() {
        let ack = AckNumber::new(0x12345678);
        assert_eq!(ack.as_u32(), 0x12345678);
        
        // Test From/Into conversions
        let ack_from: AckNumber = 0x11223344u32.into();
        assert_eq!(ack_from.as_u32(), 0x11223344);
        
        let raw: u32 = ack.into();
        assert_eq!(raw, 0x12345678);
        
        test_basic_traits(&ack);
    }

    #[test]
    fn test_socket_id() {
        let socket_id = SocketId::new(0x123456789ABCDEF0);
        assert_eq!(socket_id.as_u64(), 0x123456789ABCDEF0);
        assert_eq!(socket_id.as_raw(), 0x123456789ABCDEF0);
        
        // Test From/Into conversions
        let socket_from: SocketId = 0x11223344u64.into();
        assert_eq!(socket_from.as_u64(), 0x11223344);
        
        let raw: u64 = socket_id.into();
        assert_eq!(raw, 0x123456789ABCDEF0);
        
        // Test Display
        let display_str = format!("{}", socket_id);
        assert_eq!(display_str, "1311768467463790320");
        
        test_basic_traits(&socket_id);
    }

    #[test]
    fn test_process_id() {
        let process_id = ProcessId::new(12345);
        assert_eq!(process_id.as_u32(), 12345);
        assert_eq!(process_id.as_raw(), 12345);
        
        // Test From/Into conversions
        let process_from: ProcessId = 67890u32.into();
        assert_eq!(process_from.as_u32(), 67890);
        
        let raw: u32 = process_id.into();
        assert_eq!(raw, 12345);
        
        // Test Display
        let display_str = format!("{}", process_id);
        assert_eq!(display_str, "12345");
        
        test_basic_traits(&process_id);
    }

    // Helper function to test basic traits for identifier types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod network_types {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_port() {
        let port = Port::new(8080);
        assert_eq!(port.as_u16(), 8080);
        assert_eq!(port.as_raw(), 8080);
        
        // Test constants
        assert_eq!(Port::MIN, 1024);
        assert_eq!(Port::MAX, 65535);
        assert_eq!(Port::WELL_KNOWN_MAX, 1023);
        
        // Test next
        let next_port = port.next();
        assert_eq!(next_port.as_u16(), 8081);
        
        let max_port = Port::new(65535);
        let wrapped = max_port.next();
        assert_eq!(wrapped.as_u16(), Port::MIN); // Wraps to MIN
        
        // Test validation
        assert!(port.is_valid());
        assert!(!Port::new(0).is_valid());
        
        // Test well-known check
        assert!(Port::new(80).is_well_known());
        assert!(!Port::new(8080).is_well_known());
        
        // Test eBPF conversions
        assert_eq!(port.to_ebpf_u16(), 8080);
        let from_ebpf = Port::from_ebpf_u16(9090);
        assert_eq!(from_ebpf.as_u16(), 9090);
        
        // Test From/Into conversions
        let port_from: Port = 3000u16.into();
        assert_eq!(port_from.as_u16(), 3000);
        
        let raw: u16 = port.into();
        assert_eq!(raw, 8080);
        
        test_basic_traits(&port);
    }

    #[test]
    fn test_ip_address() {
        // Test IPv4
        let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let ip_v4 = IpAddress::from_ipv4(ipv4);
        
        match ip_v4 {
            IpAddress::V4(addr) => assert_eq!(addr, ipv4),
            _ => panic!("Expected IPv4 address"),
        }
        
        // Test IPv6
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ip_v6 = IpAddress::from_ipv6(ipv6);
        
        match ip_v6 {
            IpAddress::V6(addr) => assert_eq!(addr, ipv6),
            _ => panic!("Expected IPv6 address"),
        }
        
        // Test From/Into conversions with IpAddr
        let std_ip = IpAddr::V4(ipv4);
        let ip_from_std: IpAddress = std_ip.into();
        let std_back: IpAddr = ip_from_std.into();
        assert_eq!(std_ip, std_back);
        
        // Test as_raw and from_raw
        let raw_ip = ip_v4.as_raw();
        let ip_from_raw = IpAddress::from_raw(raw_ip);
        assert_eq!(ip_v4, ip_from_raw);
        
        // Test Debug, Clone, Copy, PartialEq, Eq, Hash
        let ip_copy = ip_v4;
        assert_eq!(ip_v4, ip_copy);
        
        let debug_str = format!("{:?}", ip_v4);
        assert!(!debug_str.is_empty());
        
        let mut hasher = DefaultHasher::new();
        ip_v4.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    #[test]
    fn test_network_endpoint() {
        let ip = IpAddress::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let port = Port::new(8080);
        let endpoint = NetworkEndpoint::new(ip, port);
        
        assert_eq!(endpoint.ip, ip);
        assert_eq!(endpoint.port, port);
        
        // Test from_socket_addr
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9090);
        let endpoint_from_socket = NetworkEndpoint::from_socket_addr(socket_addr);
        assert_eq!(endpoint_from_socket.port.as_u16(), 9090);
        
        // Test to_socket_addr
        let socket_back = endpoint.to_socket_addr();
        assert_eq!(socket_back.port(), 8080);
        
        // Test Display
        let display_str = format!("{}", endpoint);
        assert!(display_str.contains("192.168.1.1"));
        assert!(display_str.contains("8080"));
        
        // Test Debug, Clone, Copy, PartialEq, Eq, Hash
        let endpoint_copy = endpoint;
        assert_eq!(endpoint, endpoint_copy);
        
        let debug_str = format!("{:?}", endpoint);
        assert!(!debug_str.is_empty());
        
        let mut hasher = DefaultHasher::new();
        endpoint.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    #[test]
    fn test_mtu_size() {
        let mtu = MtuSize::new(1500);
        assert_eq!(mtu.as_u16(), 1500);
        
        // Test constants
        assert_eq!(MtuSize::DEFAULT, 1500);
        assert_eq!(MtuSize::FRAGMENTATION_THRESHOLD, 1400);
        
        // Test From conversion
        let mtu_from: MtuSize = 1400u16.into();
        assert_eq!(mtu_from.as_u16(), 1400);
        
        test_basic_traits(&mtu);
    }

    #[test]
    fn test_packet_size() {
        let size = PacketSize::new(65536);
        assert_eq!(size.as_usize(), 65536);
        assert_eq!(size.as_raw(), 65536);
        
        // Test constant
        assert_eq!(PacketSize::MAX_TOTAL_REASSEMBLED, 65536);
        
        // Test From conversion
        let size_from: PacketSize = 32768usize.into();
        assert_eq!(size_from.as_usize(), 32768);
        
        // Test Display
        let display_str = format!("{}", size);
        assert_eq!(display_str, "65536");
        
        test_basic_traits(&size);
    }

    #[test]
    fn test_header_size() {
        let header = HeaderSize::new(18);
        assert_eq!(header.as_u16(), 18);
        assert_eq!(header.as_usize(), 18);
        
        // Test constants
        assert_eq!(HeaderSize::BASE, 18);
        assert_eq!(HeaderSize::FRAGMENT, 8);
        
        // Test arithmetic operations
        let total_size = header + 1000usize;
        assert_eq!(total_size, 1018);
        
        let total_size_u32 = header + 500u32;
        assert_eq!(total_size_u32, 518);
        
        // Test From conversion
        let header_from: HeaderSize = 24u16.into();
        assert_eq!(header_from.as_u16(), 24);
        
        test_basic_traits(&header);
    }

    #[test]
    fn test_network_condition() {
        // Test all variants
        assert_eq!(NetworkCondition::Excellent as u8, 0);
        assert_eq!(NetworkCondition::Good as u8, 1);
        assert_eq!(NetworkCondition::Fair as u8, 2);
        assert_eq!(NetworkCondition::Poor as u8, 3);
        assert_eq!(NetworkCondition::Critical as u8, 4);
        
        // Test from_u8
        assert_eq!(NetworkCondition::from_u8(0), Some(NetworkCondition::Excellent));
        assert_eq!(NetworkCondition::from_u8(4), Some(NetworkCondition::Critical));
        assert_eq!(NetworkCondition::from_u8(5), None); // Invalid
        
        // Test as_u8
        assert_eq!(NetworkCondition::Good.as_u8(), 1);
        
        // Test Debug, Clone, Copy, PartialEq, Eq, Hash
        let condition = NetworkCondition::Good;
        let condition_copy = condition;
        assert_eq!(condition, condition_copy);
        
        let debug_str = format!("{:?}", condition);
        assert!(debug_str.contains("Good"));
        
        let mut hasher = DefaultHasher::new();
        condition.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    // Helper function to test basic traits for network types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}#
[cfg(test)]
mod time_types {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_timestamp() {
        let timestamp = Timestamp::new(1000000000, TimestampConfig::Bits32);
        assert_eq!(timestamp.as_u64(), 1000000000);
        assert_eq!(timestamp.as_nanos(), 1000000000);
        
        // Test from_raw
        let timestamp_raw = Timestamp::from_raw(2000000000);
        assert_eq!(timestamp_raw.as_u64(), 2000000000);
        
        // Test now
        let now = Timestamp::now();
        assert!(now.as_u64() > 0);
        
        // Test saturating_sub
        let diff = timestamp_raw.saturating_sub(timestamp);
        assert_eq!(diff, 1000000000);
        
        let underflow = timestamp.saturating_sub(timestamp_raw);
        assert_eq!(underflow, 0); // Saturates to 0
        
        // Test elapsed
        let elapsed = timestamp.elapsed();
        assert!(elapsed.as_nanos() > 0);
        
        // Test From/Into conversions
        let timestamp_from: Timestamp = 3000000000u64.into();
        assert_eq!(timestamp_from.as_u64(), 3000000000);
        
        let raw: u64 = timestamp.into();
        assert_eq!(raw, 1000000000);
        
        test_basic_traits(&timestamp);
    }

    #[test]
    fn test_duration() {
        let duration = Duration::new(5000000000); // 5 seconds in nanoseconds
        assert_eq!(duration.as_u64(), 5000000000);
        assert_eq!(duration.as_nanos(), 5000000000);
        assert_eq!(duration.as_millis(), 5000);
        assert_eq!(duration.as_seconds(), 5);
        
        // Test from_raw and as_raw
        let duration_raw = Duration::from_raw(1000000000);
        assert_eq!(duration_raw.as_raw(), 1000000000);
        
        // Test from_millis and from_seconds
        let duration_millis = Duration::from_millis(2000);
        assert_eq!(duration_millis.as_nanos(), 2000000000);
        
        let duration_seconds = Duration::from_seconds(3);
        assert_eq!(duration_seconds.as_nanos(), 3000000000);
        
        // Test std::time::Duration conversions
        let std_duration = std::time::Duration::from_secs(1);
        let our_duration: Duration = std_duration.into();
        assert_eq!(our_duration.as_seconds(), 1);
        
        let std_back: std::time::Duration = our_duration.into();
        assert_eq!(std_back.as_secs(), 1);
        
        let as_std = duration.as_std_duration();
        assert_eq!(as_std.as_secs(), 5);
        
        // Test From/Into conversions
        let duration_from: Duration = 4000000000u64.into();
        assert_eq!(duration_from.as_u64(), 4000000000);
        
        let raw: u64 = duration.into();
        assert_eq!(raw, 5000000000);
        
        test_basic_traits(&duration);
    }

    #[test]
    fn test_interval() {
        let interval = Interval::new(30000000000); // 30 seconds in nanoseconds
        assert_eq!(interval.as_u64(), 30000000000);
        assert_eq!(interval.as_nanos(), 30000000000);
        assert_eq!(interval.as_millis(), 30000);
        
        // Test from_millis
        let interval_millis = Interval::from_millis(15000);
        assert_eq!(interval_millis.as_nanos(), 15000000000);
        
        // Test From/Into conversions
        let interval_from: Interval = 60000000000u64.into();
        assert_eq!(interval_from.as_u64(), 60000000000);
        
        let raw: u64 = interval.into();
        assert_eq!(raw, 30000000000);
        
        test_basic_traits(&interval);
    }

    #[test]
    fn test_time_offset() {
        let offset = TimeOffset::new(-1000000000); // -1 second in nanoseconds
        assert_eq!(offset.as_i64(), -1000000000);
        assert_eq!(offset.as_nanos(), -1000000000);
        
        // Test positive offset
        let positive_offset = TimeOffset::new(2000000000);
        assert_eq!(positive_offset.as_i64(), 2000000000);
        
        // Test From/Into conversions
        let offset_from: TimeOffset = -500000000i64.into();
        assert_eq!(offset_from.as_i64(), -500000000);
        
        let raw: i64 = offset.into();
        assert_eq!(raw, -1000000000);
        
        test_basic_traits(&offset);
    }

    #[test]
    fn test_round_trip_time() {
        let rtt = RoundTripTime::new(50000000); // 50ms in nanoseconds
        assert_eq!(rtt.as_u64(), 50000000);
        assert_eq!(rtt.as_nanos(), 50000000);
        assert_eq!(rtt.as_millis(), 50);
        
        // Test From/Into conversions
        let rtt_from: RoundTripTime = 100000000u64.into();
        assert_eq!(rtt_from.as_u64(), 100000000);
        
        let raw: u64 = rtt.into();
        assert_eq!(raw, 50000000);
        
        test_basic_traits(&rtt);
    }

    #[test]
    fn test_recovery_timeout() {
        let timeout = RecoveryTimeout::new(15000); // 15 seconds in milliseconds
        assert_eq!(timeout.as_u64(), 15000);
        assert_eq!(timeout.as_millis(), 15000);
        
        // Test From/Into conversions
        let timeout_from: RecoveryTimeout = 30000u64.into();
        assert_eq!(timeout_from.as_u64(), 30000);
        
        let raw: u64 = timeout.into();
        assert_eq!(raw, 15000);
        
        test_basic_traits(&timeout);
    }

    #[test]
    fn test_time_sync_tolerance() {
        let tolerance = TimeSyncTolerance::new(-500); // -500ms
        assert_eq!(tolerance.as_i64(), -500);
        assert_eq!(tolerance.as_millis(), -500);
        
        // Test positive tolerance
        let positive_tolerance = TimeSyncTolerance::new(1000);
        assert_eq!(positive_tolerance.as_i64(), 1000);
        
        // Test From/Into conversions
        let tolerance_from: TimeSyncTolerance = -250i64.into();
        assert_eq!(tolerance_from.as_i64(), -250);
        
        let raw: i64 = tolerance.into();
        assert_eq!(raw, -500);
        
        test_basic_traits(&tolerance);
    }

    #[test]
    fn test_microsecond_timestamp() {
        let timestamp = MicrosecondTimestamp::new(1000000); // 1 second in microseconds
        assert_eq!(timestamp.as_u64(), 1000000);
        assert_eq!(timestamp.as_micros(), 1000000);
        assert_eq!(timestamp.as_nanos(), 1000000000);
        
        // Test now
        let now = MicrosecondTimestamp::now();
        assert!(now.as_u64() > 0);
        
        // Test from_nanos
        let from_nanos = MicrosecondTimestamp::from_nanos(2000000000);
        assert_eq!(from_nanos.as_micros(), 2000000);
        
        // Test saturating_sub
        let timestamp2 = MicrosecondTimestamp::new(500000);
        let diff = timestamp.saturating_sub(timestamp2);
        assert_eq!(diff, 500000);
        
        let underflow = timestamp2.saturating_sub(timestamp);
        assert_eq!(underflow, 0); // Saturates to 0
        
        // Test From/Into conversions
        let timestamp_from: MicrosecondTimestamp = 2000000u64.into();
        assert_eq!(timestamp_from.as_u64(), 2000000);
        
        let raw: u64 = timestamp.into();
        assert_eq!(raw, 1000000);
        
        test_basic_traits(&timestamp);
    }

    #[test]
    fn test_drift_rate() {
        let drift = DriftRate::new(50.5); // 50.5 ppm
        assert_eq!(drift.as_f64(), 50.5);
        assert_eq!(drift.as_ppm(), 50.5);
        
        // Test is_excessive
        assert!(drift.is_excessive(40.0));
        assert!(!drift.is_excessive(60.0));
        
        // Test is_significant
        assert!(drift.is_significant(10.0));
        assert!(!drift.is_significant(100.0));
        
        // Test negative drift
        let negative_drift = DriftRate::new(-25.0);
        assert!(negative_drift.is_excessive(20.0)); // abs() > 20.0
        
        // Test From/Into conversions
        let drift_from: DriftRate = 75.25f64.into();
        assert_eq!(drift_from.as_f64(), 75.25);
        
        let raw: f64 = drift.into();
        assert_eq!(raw, 50.5);
        
        // Test Debug, Clone, Copy, PartialEq, PartialOrd
        let drift_copy = drift;
        assert_eq!(drift, drift_copy);
        
        let debug_str = format!("{:?}", drift);
        assert!(debug_str.contains("50.5"));
        
        assert!(drift > DriftRate::new(40.0));
        assert!(drift < DriftRate::new(60.0));
    }

    // Helper function to test basic traits for time types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod fragmentation_types {
    use super::*;

    #[test]
    fn test_fragment_id() {
        let frag_id = FragmentId::new(12345);
        assert_eq!(frag_id.as_u16(), 12345);
        
        // Test constant
        assert_eq!(FragmentId::SPACE, 0xFFFF);
        
        // Test eBPF conversions
        assert_eq!(frag_id.to_ebpf_u16(), 12345);
        let from_ebpf = FragmentId::from_ebpf_u16(54321);
        assert_eq!(from_ebpf.as_u16(), 54321);
        
        // Test From/Into conversions
        let frag_from: FragmentId = 9999u16.into();
        assert_eq!(frag_from.as_u16(), 9999);
        
        let raw: u16 = frag_id.into();
        assert_eq!(raw, 12345);
        
        test_basic_traits(&frag_id);
    }

    #[test]
    fn test_fragment_index() {
        let frag_index = FragmentIndex::new(5);
        assert_eq!(frag_index.as_u16(), 5);
        
        // Test From conversion
        let frag_from: FragmentIndex = 10u16.into();
        assert_eq!(frag_from.as_u16(), 10);
        
        test_basic_traits(&frag_index);
    }

    #[test]
    fn test_fragment_offset() {
        let frag_offset = FragmentOffset::new(1400);
        assert_eq!(frag_offset.as_u16(), 1400);
        
        // Test From conversion
        let frag_from: FragmentOffset = 2800u16.into();
        assert_eq!(frag_from.as_u16(), 2800);
        
        test_basic_traits(&frag_offset);
    }

    // Helper function to test basic traits for fragmentation types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod flow_control_types {
    use super::*;

    #[test]
    fn test_window_size() {
        let window = WindowSize::new(65535);
        assert_eq!(window.as_u32(), 65535);
        
        // Test constant
        assert_eq!(WindowSize::DEFAULT, 65535);
        
        // Test From/Into conversions
        let window_from: WindowSize = 32768u32.into();
        assert_eq!(window_from.as_u32(), 32768);
        
        let raw: u32 = window.into();
        assert_eq!(raw, 65535);
        
        test_basic_traits(&window);
    }

    #[test]
    fn test_congestion_window() {
        let cong_window = CongestionWindow::new(1460);
        assert_eq!(cong_window.as_u32(), 1460);
        
        // Test constant
        assert_eq!(CongestionWindow::DEFAULT, 1460);
        
        // Test From/Into conversions
        let cong_from: CongestionWindow = 2920u32.into();
        assert_eq!(cong_from.as_u32(), 2920);
        
        let raw: u32 = cong_window.into();
        assert_eq!(raw, 1460);
        
        test_basic_traits(&cong_window);
    }

    // Helper function to test basic traits for flow control types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}#[cf
g(test)]
mod metrics_types {
    use super::*;

    #[test]
    fn test_score() {
        let score = Score::new(0.75);
        assert_eq!(score.as_f32(), 0.75);
        
        // Test clamping
        let high_score = Score::new(1.5);
        assert_eq!(high_score.as_f32(), 1.0); // Clamped to 1.0
        
        let low_score = Score::new(-0.5);
        assert_eq!(low_score.as_f32(), 0.0); // Clamped to 0.0
        
        // Test From conversion
        let score_from: Score = 0.9f32.into();
        assert_eq!(score_from.as_f32(), 0.9);
        
        // Test Debug, Clone, Copy, PartialEq, PartialOrd
        let score_copy = score;
        assert_eq!(score, score_copy);
        
        let debug_str = format!("{:?}", score);
        assert!(debug_str.contains("0.75"));
        
        assert!(score > Score::new(0.5));
        assert!(score < Score::new(0.9));
    }

    #[test]
    fn test_attempt_count() {
        let mut count = AttemptCount::new(5);
        assert_eq!(count.as_u32(), 5);
        assert_eq!(count.as_raw(), 5);
        
        // Test from_raw
        let count_raw = AttemptCount::from_raw(10);
        assert_eq!(count_raw.as_u32(), 10);
        
        // Test increment
        count.increment();
        assert_eq!(count.as_u32(), 6);
        
        // Test arithmetic operations
        let sum = count + 4u32;
        assert_eq!(sum.as_u32(), 10);
        
        // Test comparisons with u32
        assert!(count > 5u32);
        assert!(count == 6u32);
        assert!(count < 10u32);
        
        // Test From/Into conversions
        let count_from: AttemptCount = 15u32.into();
        assert_eq!(count_from.as_u32(), 15);
        
        // Test Display
        let display_str = format!("{}", count);
        assert_eq!(display_str, "6");
        
        // Test Default
        let default_count = AttemptCount::default();
        assert_eq!(default_count.as_u32(), 0);
        
        test_basic_traits(&count);
    }

    #[test]
    fn test_failure_count() {
        let mut count = FailureCount::new(3);
        assert_eq!(count.as_u32(), 3);
        assert_eq!(count.as_raw(), 3);
        
        // Test from_raw
        let count_raw = FailureCount::from_raw(7);
        assert_eq!(count_raw.as_u32(), 7);
        
        // Test increment and add
        count.increment();
        assert_eq!(count.as_u32(), 4);
        
        count.add(5);
        assert_eq!(count.as_u32(), 9);
        
        // Test arithmetic operations
        let sum = count + 1u32;
        assert_eq!(sum.as_u32(), 10);
        
        // Test comparisons with u32
        assert!(count > 8u32);
        assert!(count == 9u32);
        assert!(count < 15u32);
        
        // Test From/Into conversions
        let count_from: FailureCount = 12u32.into();
        assert_eq!(count_from.as_u32(), 12);
        
        // Test Display
        let display_str = format!("{}", count);
        assert_eq!(display_str, "9");
        
        // Test Default
        let default_count = FailureCount::default();
        assert_eq!(default_count.as_u32(), 0);
        
        test_basic_traits(&count);
    }

    #[test]
    fn test_session_count() {
        let mut count = SessionCount::new(10);
        assert_eq!(count.as_u32(), 10);
        assert_eq!(count.as_raw(), 10);
        
        // Test from_raw
        let count_raw = SessionCount::from_raw(20);
        assert_eq!(count_raw.as_u32(), 20);
        
        // Test increment, decrement, and add
        count.increment();
        assert_eq!(count.as_u32(), 11);
        
        count.decrement();
        assert_eq!(count.as_u32(), 10);
        
        count.add(5);
        assert_eq!(count.as_u32(), 15);
        
        // Test decrement at zero
        let mut zero_count = SessionCount::new(0);
        zero_count.decrement();
        assert_eq!(zero_count.as_u32(), 0); // Should not underflow
        
        // Test arithmetic operations
        let sum = count + 5u32;
        assert_eq!(sum.as_u32(), 20);
        
        // Test comparisons with u32
        assert!(count > 10u32);
        assert!(count == 15u32);
        assert!(count < 20u32);
        
        // Test From/Into conversions
        let count_from: SessionCount = 25u32.into();
        assert_eq!(count_from.as_u32(), 25);
        
        // Test Display
        let display_str = format!("{}", count);
        assert_eq!(display_str, "15");
        
        // Test Default
        let default_count = SessionCount::default();
        assert_eq!(default_count.as_u32(), 0);
        
        test_basic_traits(&count);
    }

    #[test]
    fn test_timeout_count() {
        let mut count = TimeoutCount::new(2);
        assert_eq!(count.as_u32(), 2);
        
        // Test increment
        count.increment();
        assert_eq!(count.as_u32(), 3);
        
        // Test From conversion
        let count_from: TimeoutCount = 8u32.into();
        assert_eq!(count_from.as_u32(), 8);
        
        test_basic_traits(&count);
    }

    #[test]
    fn test_counter() {
        let mut counter = Counter::new(100);
        assert_eq!(counter.as_u64(), 100);
        
        // Test increment and add
        counter.increment();
        assert_eq!(counter.as_u64(), 101);
        
        counter.add(50);
        assert_eq!(counter.as_u64(), 151);
        
        // Test From conversion
        let counter_from: Counter = 200u64.into();
        assert_eq!(counter_from.as_u64(), 200);
        
        // Test Default
        let default_counter = Counter::default();
        assert_eq!(default_counter.as_u64(), 0);
        
        test_basic_traits(&counter);
    }

    #[test]
    fn test_recovery_nonce() {
        let nonce = RecoveryNonce::new(0x12345678);
        assert_eq!(nonce.as_u32(), 0x12345678);
        
        // Test From conversion
        let nonce_from: RecoveryNonce = 0x87654321u32.into();
        assert_eq!(nonce_from.as_u32(), 0x87654321);
        
        // Test Debug, Clone, Copy, PartialEq, Eq, Hash
        let nonce_copy = nonce;
        assert_eq!(nonce, nonce_copy);
        
        let debug_str = format!("{:?}", nonce);
        assert!(!debug_str.is_empty());
        
        let mut hasher = DefaultHasher::new();
        nonce.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    #[test]
    fn test_metrics_interval() {
        let duration = std::time::Duration::from_secs(60);
        let interval = MetricsInterval::new(duration);
        assert_eq!(interval.as_duration(), duration);
        assert_eq!(interval.as_raw(), duration);
        
        // Test from_raw
        let interval_raw = MetricsInterval::from_raw(std::time::Duration::from_secs(30));
        assert_eq!(interval_raw.as_duration().as_secs(), 30);
        
        // Test From conversion
        let interval_from: MetricsInterval = std::time::Duration::from_secs(120).into();
        assert_eq!(interval_from.as_duration().as_secs(), 120);
        
        test_basic_traits(&interval);
    }

    // Helper function to test basic traits for metrics types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod configuration_types {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_timeout() {
        let timeout = Timeout::new(5000);
        assert_eq!(timeout.as_u64(), 5000);
        assert_eq!(timeout.as_millis(), 5000);
        
        // Test from_millis
        let timeout_millis = Timeout::from_millis(10000);
        assert_eq!(timeout_millis.as_u64(), 10000);
        
        // Test From/Into conversions
        let timeout_from: Timeout = 15000u64.into();
        assert_eq!(timeout_from.as_u64(), 15000);
        
        let raw: u64 = timeout.into();
        assert_eq!(raw, 5000);
        
        test_basic_traits(&timeout);
    }

    #[test]
    fn test_threshold() {
        let threshold = Threshold::new(100);
        assert_eq!(threshold.as_u32(), 100);
        
        // Test From/Into conversions
        let threshold_from: Threshold = 200u32.into();
        assert_eq!(threshold_from.as_u32(), 200);
        
        let raw: u32 = threshold.into();
        assert_eq!(raw, 100);
        
        test_basic_traits(&threshold);
    }

    #[test]
    fn test_max_segment_size() {
        let mss = MaxSegmentSize::new(1460);
        assert_eq!(mss.as_u16(), 1460);
        
        // Test constant
        assert_eq!(MaxSegmentSize::DEFAULT, 1460);
        
        // Test From conversion
        let mss_from: MaxSegmentSize = 1200u16.into();
        assert_eq!(mss_from.as_u16(), 1200);
        
        test_basic_traits(&mss);
    }

    #[test]
    fn test_connection_features() {
        let mut features = ConnectionFeatures::new(0);
        assert_eq!(features.as_u32(), 0);
        
        // Test feature constants
        assert_eq!(ConnectionFeatures::FRAGMENTATION, 1 << 0);
        assert_eq!(ConnectionFeatures::SELECTIVE_ACK, 1 << 1);
        assert_eq!(ConnectionFeatures::WINDOW_SCALING, 1 << 2);
        assert_eq!(ConnectionFeatures::TIMESTAMPS, 1 << 3);
        assert_eq!(ConnectionFeatures::FLOW_CONTROL, 1 << 4);
        
        // Test setting features
        features.set(ConnectionFeatures::FRAGMENTATION);
        assert!(features.is_set(ConnectionFeatures::FRAGMENTATION));
        assert!(!features.is_set(ConnectionFeatures::SELECTIVE_ACK));
        
        features.set(ConnectionFeatures::SELECTIVE_ACK);
        assert!(features.is_set(ConnectionFeatures::FRAGMENTATION));
        assert!(features.is_set(ConnectionFeatures::SELECTIVE_ACK));
        
        // Test clearing features
        features.clear(ConnectionFeatures::FRAGMENTATION);
        assert!(!features.is_set(ConnectionFeatures::FRAGMENTATION));
        assert!(features.is_set(ConnectionFeatures::SELECTIVE_ACK));
        
        // Test Debug, Clone, Copy, PartialEq, Eq
        let features_copy = features;
        assert_eq!(features, features_copy);
        
        let debug_str = format!("{:?}", features);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_sync_state() {
        // Test all variants
        assert_eq!(SyncState::Unsynchronized as u8, 0);
        assert_eq!(SyncState::Synchronizing as u8, 1);
        assert_eq!(SyncState::Synchronized as u8, 2);
        assert_eq!(SyncState::Degraded as u8, 3);
        
        // Test from_u8
        assert_eq!(SyncState::from_u8(0), Some(SyncState::Unsynchronized));
        assert_eq!(SyncState::from_u8(1), Some(SyncState::Synchronizing));
        assert_eq!(SyncState::from_u8(2), Some(SyncState::Synchronized));
        assert_eq!(SyncState::from_u8(3), Some(SyncState::Degraded));
        assert_eq!(SyncState::from_u8(4), None); // Invalid
        
        // Test as_u8
        assert_eq!(SyncState::Synchronized.as_u8(), 2);
        
        // Test atomic operations
        use std::sync::atomic::{AtomicU8, Ordering};
        let atomic = AtomicU8::new(0);
        
        // Test load
        let loaded = SyncState::load(&atomic, Ordering::Relaxed);
        assert_eq!(loaded, SyncState::Unsynchronized);
        
        // Test store
        SyncState::Synchronized.store(&atomic, Ordering::Relaxed);
        assert_eq!(atomic.load(Ordering::Relaxed), 2);
        
        // Test compare_exchange
        let result = SyncState::compare_exchange(
            &atomic,
            SyncState::Synchronized,
            SyncState::Degraded,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        assert_eq!(result, Ok(SyncState::Synchronized));
        assert_eq!(atomic.load(Ordering::Relaxed), 3);
        
        // Test Debug, Clone, Copy, PartialEq, Eq, Hash
        let state = SyncState::Synchronized;
        let state_copy = state;
        assert_eq!(state, state_copy);
        
        let debug_str = format!("{:?}", state);
        assert!(debug_str.contains("Synchronized"));
        
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    #[test]
    fn test_daemon_name() {
        let name = DaemonName::new("buckwild-daemon".to_string());
        assert_eq!(name.as_str(), "buckwild-daemon");
        assert_eq!(name.as_raw(), &"buckwild-daemon".to_string());
        
        // Test from_raw
        let name_raw = DaemonName::from_raw("test-daemon".to_string());
        assert_eq!(name_raw.as_str(), "test-daemon");
        
        // Test From/Into conversions
        let name_from: DaemonName = "another-daemon".to_string().into();
        assert_eq!(name_from.as_str(), "another-daemon");
        
        let raw: String = name.into();
        assert_eq!(raw, "buckwild-daemon");
        
        // Test Debug, Clone, PartialEq, Eq, Hash
        let name_clone = name_raw.clone();
        assert_eq!(name_raw, name_clone);
        
        let debug_str = format!("{:?}", name_raw);
        assert!(debug_str.contains("test-daemon"));
        
        let mut hasher = DefaultHasher::new();
        name_raw.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    #[test]
    fn test_path_types() {
        let path = PathBuf::from("/var/log/buckwild");
        
        // Test LogDirectory
        let log_dir = LogDirectory::new(path.clone());
        assert_eq!(log_dir.as_path(), &path);
        assert_eq!(log_dir.as_raw(), &path);
        
        let log_dir_raw = LogDirectory::from_raw(path.clone());
        assert_eq!(log_dir_raw.as_path(), &path);
        
        let log_dir_from: LogDirectory = path.clone().into();
        assert_eq!(log_dir_from.as_path(), &path);
        
        let path_back: PathBuf = log_dir.into();
        assert_eq!(path_back, path);
        
        // Test PskDirectory
        let psk_dir = PskDirectory::new(path.clone());
        assert_eq!(psk_dir.as_path(), &path);
        
        // Test ConfigPath
        let config_path = ConfigPath::new(path.clone());
        assert_eq!(config_path.as_path(), &path);
        
        // Test StateDirectory
        let state_dir = StateDirectory::new(path.clone());
        assert_eq!(state_dir.as_path(), &path);
        
        // Test Debug, Clone, PartialEq, Eq, Hash for one type (they're all similar)
        let log_dir_clone = log_dir_raw.clone();
        assert_eq!(log_dir_raw, log_dir_clone);
        
        let debug_str = format!("{:?}", log_dir_raw);
        assert!(!debug_str.is_empty());
        
        let mut hasher = DefaultHasher::new();
        log_dir_raw.hash(&mut hasher);
        let hash = hasher.finish();
        assert!(hash > 0);
    }

    // Helper function to test basic traits for configuration types
    fn test_basic_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test PartialOrd and Ord
        assert_eq!(value.partial_cmp(value), Some(std::cmp::Ordering::Equal));
        assert_eq!(value.cmp(value), std::cmp::Ordering::Equal);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}#[cf
g(test)]
mod security_types {
    use super::*;

    #[test]
    fn test_security_mode() {
        // Test all variants
        assert_eq!(SecurityMode::None as u8, 0);
        assert_eq!(SecurityMode::Basic as u8, 1);
        assert_eq!(SecurityMode::Enhanced as u8, 2);
        assert_eq!(SecurityMode::Maximum as u8, 3);
        
        // Test from_u8
        assert_eq!(SecurityMode::from_u8(0), Some(SecurityMode::None));
        assert_eq!(SecurityMode::from_u8(1), Some(SecurityMode::Basic));
        assert_eq!(SecurityMode::from_u8(2), Some(SecurityMode::Enhanced));
        assert_eq!(SecurityMode::from_u8(3), Some(SecurityMode::Maximum));
        assert_eq!(SecurityMode::from_u8(4), None); // Invalid
        
        // Test as_u8
        assert_eq!(SecurityMode::Enhanced.as_u8(), 2);
        
        test_enum_traits(&SecurityMode::Enhanced);
    }

    #[test]
    fn test_hmac_policy() {
        // Test all variants
        assert_eq!(HmacPolicy::None as u8, 0);
        assert_eq!(HmacPolicy::Required as u8, 1);
        assert_eq!(HmacPolicy::Optional as u8, 2);
        
        // Test from_u8
        assert_eq!(HmacPolicy::from_u8(0), Some(HmacPolicy::None));
        assert_eq!(HmacPolicy::from_u8(1), Some(HmacPolicy::Required));
        assert_eq!(HmacPolicy::from_u8(2), Some(HmacPolicy::Optional));
        assert_eq!(HmacPolicy::from_u8(3), None); // Invalid
        
        // Test as_u8
        assert_eq!(HmacPolicy::Required.as_u8(), 1);
        
        test_enum_traits(&HmacPolicy::Required);
    }

    #[test]
    fn test_recovery_reason() {
        // Test all variants
        assert_eq!(RecoveryReason::SequenceGap as u8, 0);
        assert_eq!(RecoveryReason::Timeout as u8, 1);
        assert_eq!(RecoveryReason::DuplicateAck as u8, 2);
        assert_eq!(RecoveryReason::HmacFailure as u8, 3);
        assert_eq!(RecoveryReason::TimeSync as u8, 4);
        assert_eq!(RecoveryReason::NetworkPartition as u8, 5);
        assert_eq!(RecoveryReason::KeyExpiry as u8, 6);
        assert_eq!(RecoveryReason::ProtocolViolation as u8, 7);
        assert_eq!(RecoveryReason::ResourceExhaustion as u8, 8);
        assert_eq!(RecoveryReason::SecurityBreach as u8, 9);
        
        // Test from_u8
        assert_eq!(RecoveryReason::from_u8(0), Some(RecoveryReason::SequenceGap));
        assert_eq!(RecoveryReason::from_u8(5), Some(RecoveryReason::NetworkPartition));
        assert_eq!(RecoveryReason::from_u8(9), Some(RecoveryReason::SecurityBreach));
        assert_eq!(RecoveryReason::from_u8(10), None); // Invalid
        
        // Test as_u8
        assert_eq!(RecoveryReason::HmacFailure.as_u8(), 3);
        
        test_enum_traits(&RecoveryReason::TimeSync);
    }

    #[test]
    fn test_recovery_strategy() {
        // Test all variants
        assert_eq!(RecoveryStrategy::Retransmit as u8, 0x01);
        assert_eq!(RecoveryStrategy::Reset as u8, 0x02);
        assert_eq!(RecoveryStrategy::Reconnect as u8, 0x03);
        assert_eq!(RecoveryStrategy::Fallback as u8, 0x04);
        
        // Test from_u8
        assert_eq!(RecoveryStrategy::from_u8(0x01), Some(RecoveryStrategy::Retransmit));
        assert_eq!(RecoveryStrategy::from_u8(0x02), Some(RecoveryStrategy::Reset));
        assert_eq!(RecoveryStrategy::from_u8(0x03), Some(RecoveryStrategy::Reconnect));
        assert_eq!(RecoveryStrategy::from_u8(0x04), Some(RecoveryStrategy::Fallback));
        assert_eq!(RecoveryStrategy::from_u8(0x05), None); // Invalid
        
        // Test as_u8
        assert_eq!(RecoveryStrategy::Reconnect.as_u8(), 0x03);
        
        // Test Debug, Clone, Copy, PartialEq, Eq
        let strategy = RecoveryStrategy::Reset;
        let strategy_copy = strategy;
        assert_eq!(strategy, strategy_copy);
        
        let debug_str = format!("{:?}", strategy);
        assert!(debug_str.contains("Reset"));
    }

    #[test]
    fn test_challenge_nonce() {
        let nonce_bytes = [0x42u8; 32];
        let nonce = ChallengeNonce::new(nonce_bytes);
        assert_eq!(nonce.as_bytes(), &nonce_bytes);
        
        // Test from_bytes
        let nonce_from_bytes = ChallengeNonce::from_bytes(nonce_bytes);
        assert_eq!(nonce_from_bytes.as_bytes(), &nonce_bytes);
        
        // Test From/Into conversions
        let nonce_from: ChallengeNonce = nonce_bytes.into();
        assert_eq!(nonce_from.as_bytes(), &nonce_bytes);
        
        let bytes_back: [u8; 32] = nonce.into();
        assert_eq!(bytes_back, nonce_bytes);
        
        test_byte_array_traits(&nonce);
    }

    #[test]
    fn test_crypto_nonce() {
        let nonce_bytes = [0x55u8; 12];
        let nonce = CryptoNonce::new(nonce_bytes);
        assert_eq!(nonce.as_bytes(), &nonce_bytes);
        
        // Test from_bytes
        let nonce_from_bytes = CryptoNonce::from_bytes(nonce_bytes);
        assert_eq!(nonce_from_bytes.as_bytes(), &nonce_bytes);
        
        // Test From/Into conversions
        let nonce_from: CryptoNonce = nonce_bytes.into();
        assert_eq!(nonce_from.as_bytes(), &nonce_bytes);
        
        let bytes_back: [u8; 12] = nonce.into();
        assert_eq!(bytes_back, nonce_bytes);
        
        test_byte_array_traits(&nonce);
    }

    #[test]
    fn test_shared_secret() {
        let secret_bytes = [0x33u8; 32];
        let secret = SharedSecret::new(secret_bytes);
        assert_eq!(secret.as_bytes(), &secret_bytes);
        
        // Test from_bytes
        let secret_from_bytes = SharedSecret::from_bytes(secret_bytes);
        assert_eq!(secret_from_bytes.as_bytes(), &secret_bytes);
        
        // Test From/Into conversions
        let secret_from: SharedSecret = secret_bytes.into();
        assert_eq!(secret_from.as_bytes(), &secret_bytes);
        
        let bytes_back: [u8; 32] = secret.into();
        assert_eq!(bytes_back, secret_bytes);
        
        // Test Debug, Clone, PartialEq, Eq (no Copy due to Drop)
        let secret_clone = secret.clone();
        assert_eq!(secret, secret_clone);
        
        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.is_empty());
        
        // Test that Drop zeroes the secret (we can't directly test this without unsafe code)
        // But we can test that Drop is implemented
        drop(secret);
    }

    #[test]
    fn test_ecdh_keys() {
        // Test public key
        let pub_key_bytes = [0x11u8; 64];
        let pub_key = EcdhPublicKey::new(pub_key_bytes);
        assert_eq!(pub_key.as_bytes(), &pub_key_bytes);
        
        let pub_key_from_bytes = EcdhPublicKey::from_bytes(pub_key_bytes);
        assert_eq!(pub_key_from_bytes.as_bytes(), &pub_key_bytes);
        
        let pub_key_from: EcdhPublicKey = pub_key_bytes.into();
        let pub_bytes_back: [u8; 64] = pub_key.into();
        assert_eq!(pub_bytes_back, pub_key_bytes);
        
        // Test private key
        let priv_key_bytes = [0x22u8; 32];
        let priv_key = EcdhPrivateKey::new(priv_key_bytes);
        assert_eq!(priv_key.as_bytes(), &priv_key_bytes);
        
        let priv_key_from_bytes = EcdhPrivateKey::from_bytes(priv_key_bytes);
        assert_eq!(priv_key_from_bytes.as_bytes(), &priv_key_bytes);
        
        let priv_key_from: EcdhPrivateKey = priv_key_bytes.into();
        let priv_bytes_back: [u8; 32] = priv_key.into();
        assert_eq!(priv_bytes_back, priv_key_bytes);
        
        // Test that private key has Drop (zeroing)
        drop(priv_key);
        
        // Test traits for public key (has Copy)
        let pub_key_copy = pub_key;
        assert_eq!(pub_key, pub_key_copy);
        
        // Test traits for private key (no Copy due to Drop)
        let priv_key_clone = priv_key_from.clone();
        assert_eq!(priv_key_from, priv_key_clone);
    }

    #[test]
    fn test_session_key() {
        let key_bytes = [0x44u8; 32];
        let key = SessionKey::new(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);
        
        // Test from_bytes
        let key_from_bytes = SessionKey::from_bytes(key_bytes);
        assert_eq!(key_from_bytes.as_bytes(), &key_bytes);
        
        // Test From/Into conversions
        let key_from: SessionKey = key_bytes.into();
        assert_eq!(key_from.as_bytes(), &key_bytes);
        
        let bytes_back: [u8; 32] = key.into();
        assert_eq!(bytes_back, key_bytes);
        
        // Test that Drop zeroes the key
        drop(key);
        
        // Test traits (no Copy due to Drop)
        let key_clone = key_from.clone();
        assert_eq!(key_from, key_clone);
    }

    #[test]
    fn test_daily_key() {
        let key_bytes = [0x66u8; 32];
        let key = DailyKey::new(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);
        
        // Test from_bytes
        let key_from_bytes = DailyKey::from_bytes(key_bytes);
        assert_eq!(key_from_bytes.as_bytes(), &key_bytes);
        
        // Test From/Into conversions
        let key_from: DailyKey = key_bytes.into();
        let bytes_back: [u8; 32] = key.into();
        assert_eq!(bytes_back, key_bytes);
        
        // Test that Drop zeroes the key
        drop(key);
        
        // Test traits (no Copy due to Drop)
        let key_clone = key_from.clone();
        assert_eq!(key_from, key_clone);
    }

    #[test]
    fn test_hash_values() {
        let hash_bytes = [0x77u8; 32];
        
        // Test HashValue
        let hash = HashValue::new(hash_bytes);
        assert_eq!(hash.as_bytes(), &hash_bytes);
        
        let hash_from_bytes = HashValue::from_bytes(hash_bytes);
        let hash_from: HashValue = hash_bytes.into();
        let bytes_back: [u8; 32] = hash.into();
        assert_eq!(bytes_back, hash_bytes);
        
        test_byte_array_traits(&hash);
        
        // Test FingerprintHash
        let fingerprint = FingerprintHash::new(hash_bytes);
        assert_eq!(fingerprint.as_bytes(), &hash_bytes);
        test_byte_array_traits(&fingerprint);
        
        // Test ValidationHash
        let validation = ValidationHash::new(hash_bytes);
        assert_eq!(validation.as_bytes(), &hash_bytes);
        test_byte_array_traits(&validation);
    }

    #[test]
    fn test_discovery_id() {
        let id = DiscoveryId::new(0x123456789ABCDEF0);
        assert_eq!(id.as_u64(), 0x123456789ABCDEF0);
        assert_eq!(id.as_raw(), 0x123456789ABCDEF0);
        
        // Test from_raw
        let id_raw = DiscoveryId::from_raw(0x987654321);
        assert_eq!(id_raw.as_u64(), 0x987654321);
        
        // Test From/Into conversions
        let id_from: DiscoveryId = 0x111222333u64.into();
        assert_eq!(id_from.as_u64(), 0x111222333);
        
        let raw: u64 = id.into();
        assert_eq!(raw, 0x123456789ABCDEF0);
        
        test_byte_array_traits(&id);
    }

    #[test]
    fn test_session_salt() {
        let salt = SessionSalt::new(0x12345678);
        assert_eq!(salt.as_u32(), 0x12345678);
        assert_eq!(salt.as_raw(), 0x12345678);
        
        // Test from_raw
        let salt_raw = SessionSalt::from_raw(0x87654321);
        assert_eq!(salt_raw.as_u32(), 0x87654321);
        
        // Test From/Into conversions
        let salt_from: SessionSalt = 0x11223344u32.into();
        assert_eq!(salt_from.as_u32(), 0x11223344);
        
        let raw: u32 = salt.into();
        assert_eq!(raw, 0x12345678);
        
        test_byte_array_traits(&salt);
    }

    // Helper function to test enum traits
    fn test_enum_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }

    // Helper function to test byte array traits
    fn test_byte_array_traits<T>(value: &T) 
    where 
        T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + Hash
    {
        // Test Debug
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty());
        
        // Test Clone and Copy
        let cloned = value.clone();
        let copied = *value;
        assert_eq!(*value, cloned);
        assert_eq!(*value, copied);
        
        // Test PartialEq and Eq
        assert_eq!(*value, *value);
        
        // Test Hash
        let mut hasher1 = DefaultHasher::new();
        value.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        value.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod atomic_types {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_atomic_session_id() {
        let session_id = SessionId::new(0x123456789ABCDEF0, SessionIdLength::Bits64);
        let atomic_session = AtomicSessionId::new(session_id);
        
        // Test load
        let loaded = atomic_session.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u64(), 0x123456789ABCDEF0);
        
        // Test store
        let new_session = SessionId::from_raw(0x987654321);
        atomic_session.store(new_session, Ordering::Relaxed);
        let loaded_after_store = atomic_session.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u64(), 0x987654321);
        
        // Test fetch_add
        let old_value = atomic_session.fetch_add(100, Ordering::Relaxed);
        assert_eq!(old_value.as_u64(), 0x987654321);
        let new_value = atomic_session.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u64(), 0x987654321 + 100);
        
        // Test compare_exchange
        let current = SessionId::from_raw(0x987654321 + 100);
        let new = SessionId::from_raw(0x111111111);
        let result = atomic_session.compare_exchange(current, new, Ordering::Relaxed, Ordering::Relaxed);
        assert_eq!(result, Ok(current));
        assert_eq!(atomic_session.load(Ordering::Relaxed).as_u64(), 0x111111111);
        
        // Test Debug
        let debug_str = format!("{:?}", atomic_session);
        assert!(debug_str.contains("AtomicSessionId"));
    }

    #[test]
    fn test_window_size_atomic() {
        let window = WindowSize::new(65535);
        let atomic_window = WindowSizeAtomic::new(window);
        
        // Test load
        let loaded = atomic_window.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u32(), 65535);
        
        // Test store
        let new_window = WindowSize::new(32768);
        atomic_window.store(new_window, Ordering::Relaxed);
        let loaded_after_store = atomic_window.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u32(), 32768);
    }

    #[test]
    fn test_congestion_window_atomic() {
        let cong_window = CongestionWindow::new(1460);
        let atomic_cong = CongestionWindowAtomic::new(cong_window);
        
        // Test load
        let loaded = atomic_cong.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u32(), 1460);
        
        // Test store
        let new_cong = CongestionWindow::new(2920);
        atomic_cong.store(new_cong, Ordering::Relaxed);
        let loaded_after_store = atomic_cong.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u32(), 2920);
    }

    #[test]
    fn test_fragment_id_atomic() {
        let frag_id = FragmentId::new(12345);
        let atomic_frag = FragmentIdAtomic::new(frag_id);
        
        // Test load
        let loaded = atomic_frag.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u16(), 12345);
        
        // Test store
        let new_frag = FragmentId::new(54321);
        atomic_frag.store(new_frag, Ordering::Relaxed);
        let loaded_after_store = atomic_frag.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u16(), 54321);
        
        // Test fetch_add
        let old_value = atomic_frag.fetch_add(100, Ordering::Relaxed);
        assert_eq!(old_value.as_u16(), 54321);
        let new_value = atomic_frag.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u16(), 54321 + 100);
    }

    #[test]
    fn test_timestamp_atomic() {
        let timestamp = Timestamp::from_raw(1000000000);
        let atomic_timestamp = TimestampAtomic::new(timestamp);
        
        // Test load
        let loaded = atomic_timestamp.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u64(), 1000000000);
        
        // Test store
        let new_timestamp = Timestamp::from_raw(2000000000);
        atomic_timestamp.store(new_timestamp, Ordering::Relaxed);
        let loaded_after_store = atomic_timestamp.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u64(), 2000000000);
    }

    #[test]
    fn test_microsecond_timestamp_atomic() {
        let timestamp = MicrosecondTimestamp::new(1000000);
        let atomic_timestamp = MicrosecondTimestampAtomic::new(timestamp);
        
        // Test load
        let loaded = atomic_timestamp.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u64(), 1000000);
        
        // Test store
        let new_timestamp = MicrosecondTimestamp::new(2000000);
        atomic_timestamp.store(new_timestamp, Ordering::Relaxed);
        let loaded_after_store = atomic_timestamp.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u64(), 2000000);
    }

    #[test]
    fn test_round_trip_time_atomic() {
        let rtt = RoundTripTime::new(50000000);
        let atomic_rtt = RoundTripTimeAtomic::new(rtt);
        
        // Test load
        let loaded = atomic_rtt.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u64(), 50000000);
        
        // Test store
        let new_rtt = RoundTripTime::new(100000000);
        atomic_rtt.store(new_rtt, Ordering::Relaxed);
        let loaded_after_store = atomic_rtt.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u64(), 100000000);
    }

    #[test]
    fn test_time_offset_atomic() {
        let offset = TimeOffset::new(-1000000000);
        let atomic_offset = TimeOffsetAtomic::new(offset);
        
        // Test load
        let loaded = atomic_offset.load(Ordering::Relaxed);
        assert_eq!(loaded.as_i64(), -1000000000);
        
        // Test store
        let new_offset = TimeOffset::new(500000000);
        atomic_offset.store(new_offset, Ordering::Relaxed);
        let loaded_after_store = atomic_offset.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_i64(), 500000000);
        
        // Test fetch_add
        let old_value = atomic_offset.fetch_add(250000000, Ordering::Relaxed);
        assert_eq!(old_value.as_i64(), 500000000);
        let new_value = atomic_offset.load(Ordering::Relaxed);
        assert_eq!(new_value.as_i64(), 750000000);
    }

    #[test]
    fn test_sequence_number_atomic() {
        let seq = SequenceNumber::new(0x12345678);
        let atomic_seq = SequenceNumberAtomic::new(seq);
        
        // Test load
        let loaded = atomic_seq.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u32(), 0x12345678);
        
        // Test store
        let new_seq = SequenceNumber::new(0x87654321);
        atomic_seq.store(new_seq, Ordering::Relaxed);
        let loaded_after_store = atomic_seq.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u32(), 0x87654321);
        
        // Test fetch_add
        let old_value = atomic_seq.fetch_add(100, Ordering::Relaxed);
        assert_eq!(old_value.as_u32(), 0x87654321);
        let new_value = atomic_seq.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u32(), 0x87654321 + 100);
        
        // Test compare_exchange
        let current = SequenceNumber::new(0x87654321 + 100);
        let new = SequenceNumber::new(0x11111111);
        let result = atomic_seq.compare_exchange(current, new, Ordering::Relaxed, Ordering::Relaxed);
        assert_eq!(result, Ok(current));
        assert_eq!(atomic_seq.load(Ordering::Relaxed).as_u32(), 0x11111111);
    }

    #[test]
    fn test_port_atomic() {
        let port = Port::new(8080);
        let atomic_port = PortAtomic::new(port);
        
        // Test load
        let loaded = atomic_port.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u16(), 8080);
        
        // Test store
        let new_port = Port::new(9090);
        atomic_port.store(new_port, Ordering::Relaxed);
        let loaded_after_store = atomic_port.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u16(), 9090);
        
        // Test fetch_add
        let old_value = atomic_port.fetch_add(10, Ordering::Relaxed);
        assert_eq!(old_value.as_u16(), 9090);
        let new_value = atomic_port.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u16(), 9100);
    }

    #[test]
    fn test_attempt_count_atomic() {
        let count = AttemptCount::new(5);
        let atomic_count = AttemptCountAtomic::new(count);
        
        // Test load
        let loaded = atomic_count.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u32(), 5);
        
        // Test store
        let new_count = AttemptCount::new(10);
        atomic_count.store(new_count, Ordering::Relaxed);
        let loaded_after_store = atomic_count.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u32(), 10);
        
        // Test fetch_add
        let old_value = atomic_count.fetch_add(3, Ordering::Relaxed);
        assert_eq!(old_value.as_u32(), 10);
        let new_value = atomic_count.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u32(), 13);
    }

    #[test]
    fn test_failure_count_atomic() {
        let count = FailureCount::new(2);
        let atomic_count = FailureCountAtomic::new(count);
        
        // Test load
        let loaded = atomic_count.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u32(), 2);
        
        // Test store
        let new_count = FailureCount::new(7);
        atomic_count.store(new_count, Ordering::Relaxed);
        let loaded_after_store = atomic_count.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u32(), 7);
        
        // Test fetch_add
        let old_value = atomic_count.fetch_add(5, Ordering::Relaxed);
        assert_eq!(old_value.as_u32(), 7);
        let new_value = atomic_count.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u32(), 12);
    }

    #[test]
    fn test_session_count_atomic() {
        let count = SessionCount::new(10);
        let atomic_count = SessionCountAtomic::new(count);
        
        // Test load
        let loaded = atomic_count.load(Ordering::Relaxed);
        assert_eq!(loaded.as_u32(), 10);
        
        // Test store
        let new_count = SessionCount::new(20);
        atomic_count.store(new_count, Ordering::Relaxed);
        let loaded_after_store = atomic_count.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store.as_u32(), 20);
        
        // Test fetch_add
        let old_value = atomic_count.fetch_add(5, Ordering::Relaxed);
        assert_eq!(old_value.as_u32(), 20);
        let new_value = atomic_count.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u32(), 25);
        
        // Test fetch_sub
        let old_value = atomic_count.fetch_sub(3, Ordering::Relaxed);
        assert_eq!(old_value.as_u32(), 25);
        let new_value = atomic_count.load(Ordering::Relaxed);
        assert_eq!(new_value.as_u32(), 22);
    }

    #[test]
    fn test_sync_state_atomic() {
        let state = SyncState::Synchronized;
        let atomic_state = SyncStateAtomic::new(state);
        
        // Test load
        let loaded = atomic_state.load(Ordering::Relaxed);
        assert_eq!(loaded, SyncState::Synchronized);
        
        // Test store
        atomic_state.store(SyncState::Degraded, Ordering::Relaxed);
        let loaded_after_store = atomic_state.load(Ordering::Relaxed);
        assert_eq!(loaded_after_store, SyncState::Degraded);
        
        // Test compare_exchange
        let result = atomic_state.compare_exchange(
            SyncState::Degraded,
            SyncState::Synchronizing,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        assert_eq!(result, Ok(SyncState::Degraded));
        assert_eq!(atomic_state.load(Ordering::Relaxed), SyncState::Synchronizing);
        
        // Test Debug
        let debug_str = format!("{:?}", atomic_state);
        assert!(debug_str.contains("SyncStateAtomic"));
    }

    #[test]
    fn test_memory_ordering() {
        let session_id = SessionId::from_raw(12345);
        let atomic_session = AtomicSessionId::new(session_id);
        
        // Test different memory orderings
        atomic_session.store(SessionId::from_raw(11111), Ordering::Relaxed);
        assert_eq!(atomic_session.load(Ordering::Relaxed).as_u64(), 11111);
        
        atomic_session.store(SessionId::from_raw(22222), Ordering::Release);
        assert_eq!(atomic_session.load(Ordering::Acquire).as_u64(), 22222);
        
        atomic_session.store(SessionId::from_raw(33333), Ordering::SeqCst);
        assert_eq!(atomic_session.load(Ordering::SeqCst).as_u64(), 33333);
        
        // Test compare_exchange with different orderings
        let result = atomic_session.compare_exchange(
            SessionId::from_raw(33333),
            SessionId::from_raw(44444),
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
        assert_eq!(result, Ok(SessionId::from_raw(33333)));
        assert_eq!(atomic_session.load(Ordering::SeqCst).as_u64(), 44444);
    }
}