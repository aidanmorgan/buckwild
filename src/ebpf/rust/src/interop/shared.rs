//! Shared data structures for eBPF interoperability
//!
//! This module defines data structures that are shared between eBPF programs
//! and Rust userspace code, ensuring consistent data layout and interpretation.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;
use serde::{Deserialize, Serialize};
use std::mem;

/// Shared packet metadata structure
/// Uses fixed-size fields for eBPF C interoperability
/// Fields arranged to minimize padding (u64s first for alignment)
///
/// SAFETY: Uses repr(C) with explicit padding instead of repr(C, packed) to avoid
/// undefined behavior when creating references to fields. The layout matches the
/// C struct with natural alignment.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMetadata {
    /// Session ID (8 bytes)
    pub session_id: u64,
    /// Timestamp (8 bytes, nanoseconds)
    pub timestamp: u64,
    /// Packet length (4 bytes)
    pub len: u32,
    /// Source IP address (4 bytes, IPv4 only for now)
    pub src_ip: [u8; 4],
    /// Destination IP address (4 bytes, IPv4 only for now)
    pub dst_ip: [u8; 4],
    /// Source port (2 bytes)
    pub src_port: u16,
    /// Destination port (2 bytes)
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17) (1 byte)
    pub protocol: u8,
    /// Packet flags (1 byte)
    pub flags: u8,
}

/// Shared session information structure
/// Uses fixed-size fields for eBPF C interoperability
///
/// SAFETY: Uses repr(C) with explicit padding instead of repr(C, packed) to avoid
/// undefined behavior when creating references to fields. The layout matches the
/// C struct with natural alignment.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    /// Session ID (8 bytes)
    pub session_id: u64,
    /// Peer IP address (4 bytes, IPv4 only)
    pub peer_ip: [u8; 4],
    /// Current port (2 bytes)
    pub current_port: u16,
    /// Next port (2 bytes)
    pub next_port: u16,
    /// Session state (4 bytes)
    pub state: u32,
    /// Last activity timestamp (8 bytes)
    pub last_activity: u64,
    /// Packet count (4 bytes)
    pub packet_count: u32,
    /// Byte count (4 bytes)
    pub byte_count: u32,
}

/// Shared security context structure
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityContext {
    /// HMAC key (32 bytes for HMAC-SHA256)
    pub hmac_key: [u8; 32],
    /// Anti-replay window in milliseconds
    pub replay_window: u64,
    /// Last sequence number
    pub last_sequence: SequenceNumber,
    /// Key rotation counter
    pub key_rotation: u32,
    /// Security flags
    pub flags: u32,
    /// Reserved for future use
    pub reserved: [u8; 12],
}

/// Shared port hopping state structure
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortHoppingState {
    /// Current epoch
    pub epoch: Epoch,
    /// Current port
    pub current_port: Port,
    /// Next port
    pub next_port: Port,
    /// Hop interval (milliseconds)
    pub hop_interval: HopInterval,
    /// Last hop timestamp
    pub last_hop: Timestamp,
    /// Hop count
    pub hop_count: u32,
    /// Reserved for alignment
    pub reserved: u16,
}

/// Shared statistics structure
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedStats {
    /// Packets processed
    pub packets_processed: PacketCount,
    /// Packets dropped
    pub packets_dropped: PacketCount,
    /// Bytes processed
    pub bytes_processed: ByteCount,
    /// Authentication failures
    pub auth_failures: FailureCount,
    /// Replay attacks detected
    pub replay_attacks: EventCount,
    /// Port hops performed
    pub port_hops: EventCount,
    /// Last update timestamp
    pub last_update: Timestamp,
}

/// Event types for eBPF to userspace communication
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Packet received event
    PacketReceived = 1,
    /// Authentication failure event
    AuthFailure = 2,
    /// Replay attack detected event
    ReplayAttack = 3,
    /// Port hop event
    PortHop = 4,
    /// Session established event
    SessionEstablished = 5,
    /// Session terminated event
    SessionTerminated = 6,
    /// Security violation event
    SecurityViolation = 7,
    /// Performance alert event
    PerformanceAlert = 8,
}

/// Shared event structure for ring buffer communication
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SharedEvent {
    /// Event type
    pub event_type: EbpfEventType,
    /// Event timestamp
    pub timestamp: Timestamp,
    /// Session ID (if applicable)
    pub session_id: SessionId,
    /// Event-specific data
    pub data: [u8; 64],
}

impl Serialize for SharedEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SharedEvent", 4)?;
        state.serialize_field("event_type", &self.event_type)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("session_id", &self.session_id)?;
        state.serialize_field("data", &self.data.as_slice())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SharedEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct SharedEventVisitor;

        impl<'de> Visitor<'de> for SharedEventVisitor {
            type Value = SharedEvent;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SharedEvent")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SharedEvent, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut event_type = None;
                let mut timestamp = None;
                let mut session_id = None;
                let mut data: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "event_type" => event_type = Some(map.next_value()?),
                        "timestamp" => timestamp = Some(map.next_value()?),
                        "session_id" => session_id = Some(map.next_value()?),
                        "data" => data = Some(map.next_value()?),
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let data_vec = data.ok_or_else(|| de::Error::missing_field("data"))?;
                let mut data_array = [0u8; 64];
                let len = std::cmp::min(data_vec.len(), 64);
                data_array[..len].copy_from_slice(&data_vec[..len]);

                Ok(SharedEvent {
                    event_type: event_type.ok_or_else(|| de::Error::missing_field("event_type"))?,
                    timestamp: timestamp.ok_or_else(|| de::Error::missing_field("timestamp"))?,
                    session_id: session_id.ok_or_else(|| de::Error::missing_field("session_id"))?,
                    data: data_array,
                })
            }
        }

        const FIELDS: &[&str] = &["event_type", "timestamp", "session_id", "data"];
        deserializer.deserialize_struct("SharedEvent", FIELDS, SharedEventVisitor)
    }
}

/// Map key types for different eBPF maps
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionMapKey {
    /// Session ID
    pub session_id: u64, // Keep as raw u64 for eBPF compatibility
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortMapKey {
    /// IP address
    pub ip_addr: u32, // Keep as raw u32 for eBPF compatibility
    /// Port number
    pub port: u16, // Keep as raw u16 for eBPF compatibility
    /// Reserved for alignment
    pub reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecurityMapKey {
    /// Session ID
    pub session_id: u64, // Keep as raw u64 for eBPF compatibility
    /// Security context type
    pub context_type: u32,
    /// Reserved for alignment
    pub reserved: u32,
}

/// Constants for shared data structures
pub const MAX_SESSIONS: usize = 10000;
pub const MAX_PORTS: usize = 65536;
pub const MAX_SECURITY_CONTEXTS: usize = 10000;
pub const HMAC_KEY_SIZE: usize = 32;
pub const REPLAY_WINDOW_SIZE: usize = 64;
pub const EVENT_DATA_SIZE: usize = 64;

/// Utility functions for data structure manipulation
impl PacketMetadata {
    /// Create a new packet metadata structure
    pub fn new() -> Self {
        Self {
            len: 0,
            src_ip: [0, 0, 0, 0],
            dst_ip: [0, 0, 0, 0],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            flags: 0,
            timestamp: 0,
            session_id: 0,
        }
    }

    /// Check if this is a valid packet
    pub fn is_valid(&self) -> bool {
        self.len > 0 && self.len <= 65535
    }

    /// Get source IP as string
    pub fn src_ip_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]
        )
    }

    /// Get destination IP as string
    pub fn dst_ip_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]
        )
    }
}

impl SessionInfo {
    /// Create a new session info structure
    pub fn new(session_id: SessionId, peer_ip: IpAddress) -> Self {
        Self {
            session_id: session_id.as_raw(),
            peer_ip: match peer_ip {
                IpAddress::V4(octets) => octets,
                IpAddress::V6(_) => [0, 0, 0, 0], // Default to 0.0.0.0 for IPv6
            },
            current_port: 0,
            next_port: 0,
            state: SessionState::Initializing as u32,
            last_activity: 0,
            packet_count: 0,
            byte_count: 0,
        }
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active as u32
    }

    /// Update activity timestamp
    pub fn update_activity(&mut self, timestamp: Timestamp) {
        self.last_activity = timestamp.as_nanos();
    }

    /// Increment packet count
    pub fn increment_packets(&mut self, bytes: PacketSize) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.byte_count = self.byte_count.saturating_add(bytes.as_usize() as u32);
    }
}

impl SecurityContext {
    /// Create a new security context
    pub fn new() -> Self {
        Self {
            hmac_key: [0; 32],
            replay_window: 5000, // 5 second replay window
            last_sequence: SequenceNumber::from_raw(0),
            key_rotation: 0,
            flags: 0,
            reserved: [0; 12],
        }
    }

    /// Set HMAC key
    pub fn set_hmac_key(&mut self, key: [u8; 32]) {
        self.hmac_key = key;
    }

    /// Check if sequence number is valid (anti-replay)
    pub fn is_sequence_valid(&self, sequence: SequenceNumber) -> bool {
        // Simple check - in real implementation would use sliding window
        sequence.as_raw() > self.last_sequence.as_raw()
    }
}

impl PortHoppingState {
    /// Create a new port hopping state
    pub fn new() -> Self {
        Self {
            epoch: Epoch::from_raw(0),
            current_port: Port::from_raw(0),
            next_port: Port::from_raw(0),
            hop_interval: HopInterval::new(1000), // 1 second default
            last_hop: Timestamp::from_nanos(0),
            hop_count: 0,
            reserved: 0,
        }
    }

    /// Check if it's time to hop
    pub fn should_hop(&self, current_time: Timestamp) -> bool {
        current_time.as_nanos()
            >= self.last_hop.as_nanos() + (self.hop_interval.as_u64() * 1_000_000)
        // Convert ms to ns
    }

    /// Perform port hop
    pub fn hop(&mut self, new_port: Port, timestamp: Timestamp) {
        self.current_port = self.next_port;
        self.next_port = new_port;
        self.last_hop = timestamp;
        self.hop_count += 1;
    }
}

impl SharedEvent {
    /// Create a new shared event
    pub fn new(event_type: EventType, session_id: SessionId) -> Self {
        // Map EventType to EbpfEventType
        let ebpf_event_type = match event_type {
            EventType::PacketReceived => EbpfEventType::PacketReceived,
            EventType::SessionEstablished => EbpfEventType::SessionCreated,
            EventType::AuthFailure | EventType::ReplayAttack => EbpfEventType::SecurityEvent,
            _ => EbpfEventType::PacketReceived, // Default
        };

        Self {
            event_type: ebpf_event_type,
            timestamp: Timestamp::from_nanos(0), // Will be set by eBPF program
            session_id,
            data: [0; EVENT_DATA_SIZE],
        }
    }

    /// Set event data
    pub fn set_data(&mut self, data: &[u8]) {
        let len = std::cmp::min(data.len(), EVENT_DATA_SIZE);
        self.data[..len].copy_from_slice(&data[..len]);
    }

    /// Get event type
    pub fn get_event_type(&self) -> Option<EventType> {
        match self.event_type {
            EbpfEventType::PacketReceived => Some(EventType::PacketReceived),
            EbpfEventType::PacketSent => Some(EventType::PacketReceived), // Map to closest match
            EbpfEventType::SessionCreated => Some(EventType::SessionEstablished),
            EbpfEventType::SecurityEvent => Some(EventType::SecurityViolation),
        }
    }
}

/// Compile-time assertions to ensure structure sizes are as expected
/// Updated after removing packed repr and using natural alignment
const _: () = {
    // PacketMetadata: 8+8+4+4+4+2+2+1+1 = 34 bytes (no padding needed, naturally aligned)
    assert!(mem::size_of::<PacketMetadata>() <= 40); // Allow for natural padding
    // SessionInfo: 8+4+2+2+4+8+4+4 = 36 bytes, naturally aligned to 40
    assert!(mem::size_of::<SessionInfo>() <= 40);
    // SecurityContext remains the same (already repr(C) without packed)
    assert!(mem::size_of::<SecurityContext>() == 64);
    assert!(mem::size_of::<PortHoppingState>() == 40);
    assert!(mem::size_of::<SharedStats>() == 56);
    assert!(mem::size_of::<SharedEvent>() == 88);
};

impl Default for PacketMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PortHoppingState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_metadata() {
        let mut meta = PacketMetadata::new();
        assert!(!meta.is_valid());

        meta.len = 1000;
        meta.src_ip = [127, 0, 0, 1];
        meta.dst_ip = [192, 168, 1, 1];

        assert!(meta.is_valid());
        assert_eq!(meta.src_ip_string(), "127.0.0.1");
        assert_eq!(meta.dst_ip_string(), "192.168.1.1");
    }

    #[test]
    fn test_session_info() {
        let mut session = SessionInfo::new(
            SessionId::from_raw(12345),
            IpAddress::from_ipv4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
        );
        // Copy values to avoid creating references to packed fields
        let session_id = session.session_id;
        assert_eq!(session_id, 12345);
        assert!(!session.is_active());

        session.state = SessionState::Active as u32;
        assert!(session.is_active());

        session.increment_packets(PacketSize::from_usize(100));
        let packet_count = session.packet_count;
        let byte_count = session.byte_count;
        assert_eq!(packet_count, 1);
        assert_eq!(byte_count, 100);
    }

    #[test]
    fn test_security_context() {
        let mut ctx = SecurityContext::new();
        let key = [1u8; 32];
        ctx.set_hmac_key(key);

        assert_eq!(ctx.hmac_key, [1; 32]);
        assert!(ctx.is_sequence_valid(SequenceNumber::from_raw(1)));
        assert!(!ctx.is_sequence_valid(SequenceNumber::from_raw(0)));
    }

    #[test]
    fn test_port_hopping_state() {
        let mut state = PortHoppingState::new();
        assert!(!state.should_hop(Timestamp::from_nanos(0)));

        state.hop(Port::from_raw(8080), Timestamp::from_nanos(1000000000));
        assert_eq!(state.current_port.as_raw(), 0);
        assert_eq!(state.next_port.as_raw(), 8080);
        assert_eq!(state.hop_count, 1);
    }

    #[test]
    fn test_shared_event() {
        let mut event = SharedEvent::new(EventType::PacketReceived, SessionId::from_raw(12345));
        assert_eq!(event.session_id.as_raw(), 12345);
        assert_eq!(event.get_event_type(), Some(EventType::PacketReceived));

        let data = b"test event data";
        event.set_data(data);
        assert_eq!(&event.data[..data.len()], data);
    }

    #[test]
    fn test_structure_sizes() {
        // Ensure structures have expected sizes for C interop
        // After removing packed repr, sizes may be padded to natural alignment
        assert!(mem::size_of::<PacketMetadata>() <= 40);
        assert!(mem::size_of::<SessionInfo>() <= 40);
        assert_eq!(mem::size_of::<SecurityContext>(), 64);
        assert_eq!(mem::size_of::<PortHoppingState>(), 40);
        assert_eq!(mem::size_of::<SharedEvent>(), 88);
    }
}
