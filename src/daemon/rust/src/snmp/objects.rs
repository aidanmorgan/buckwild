/// BUCKWILD-MIB object implementations
///
/// Implements all MIB objects defined in docs/BUCKWILD-MIB.txt including:
/// - buckwildStatsGroup: Protocol statistics
/// - buckwildSecurityGroup: Security metrics
/// - buckwildPortHopGroup: Port hopping metrics
/// - buckwildSessionTable: Session tracking
/// - buckwildPerformanceGroup: Performance metrics
use rasn::types::ObjectIdentifier;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

/// Base OID for BUCKWILD-MIB: enterprises.99999
/// Full path: .1.3.6.1.4.1.99999
const BUCKWILD_MIB_BASE: &[u32] = &[1, 3, 6, 1, 4, 1, 99999];

/// buckwildObjects: .1.3.6.1.4.1.99999.1
const BUCKWILD_OBJECTS: &[u32] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// buckwildStats: .1.3.6.1.4.1.99999.1.1
const BUCKWILD_STATS: &[u32] = &[1, 3, 6, 1, 4, 1, 99999, 1, 1];

/// buckwildSecurity: .1.3.6.1.4.1.99999.1.2
const BUCKWILD_SECURITY: &[u32] = &[1, 3, 6, 1, 4, 1, 99999, 1, 2];

/// buckwildPortHop: .1.3.6.1.4.1.99999.1.3
const BUCKWILD_PORT_HOP: &[u32] = &[1, 3, 6, 1, 4, 1, 99999, 1, 3];

/// buckwildSessions: .1.3.6.1.4.1.99999.1.4
const BUCKWILD_SESSIONS: &[u32] = &[1, 3, 6, 1, 4, 1, 99999, 1, 4];

/// buckwildPerformance: .1.3.6.1.4.1.99999.1.5
const BUCKWILD_PERFORMANCE: &[u32] = &[1, 3, 6, 1, 4, 1, 99999, 1, 5];

/// Helper to create ObjectIdentifier from slice
fn oid_from_slice(parts: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(parts.iter().map(|&n| n.into()).collect())
}

/// Session state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Establishing = 1,
    EcdhExchange = 2,
    Established = 3,
    Rekeying = 4,
    Closing = 5,
    Closed = 6,
}

/// Session entry for buckwildSessionTable
#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub index: u32,
    pub session_id: u32,
    pub peer_address: String,
    pub state: SessionState,
    pub uptime_secs: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_hop_time: SystemTime,
}

impl SessionEntry {
    /// Create new session entry
    pub fn new(index: u32, session_id: u32, peer_address: String, state: SessionState) -> Self {
        Self {
            index,
            session_id,
            peer_address,
            state,
            uptime_secs: 0,
            packets_sent: 0,
            packets_received: 0,
            last_hop_time: SystemTime::now(),
        }
    }

    /// Get OID for session entry column
    pub fn get_oid(&self, column: u32) -> ObjectIdentifier {
        let mut parts = BUCKWILD_SESSIONS.to_vec();
        parts.extend_from_slice(&[1, 1, column, self.index]);
        oid_from_slice(&parts)
    }
}

/// MIB objects storage
#[derive(Debug)]
pub struct MibObjects {
    start_time: Instant,

    // Statistics Group
    packets_transmitted: AtomicU64,
    packets_received: AtomicU64,
    packets_dropped: AtomicU64,
    bytes_transmitted: AtomicU64,
    bytes_received: AtomicU64,
    active_connections: AtomicU32,
    total_connections_established: AtomicU64,

    // Security Group
    hmac_validation_failures: AtomicU64,
    replay_attacks_detected: AtomicU64,
    authentication_failures: AtomicU64,
    fragment_bombs_detected: AtomicU64,
    rate_limit_violations: AtomicU64,
    blocked_sources: AtomicU32,

    // Port Hopping Group
    port_transitions: AtomicU64,
    port_transition_failures: AtomicU64,
    current_listening_ports: AtomicU32,
    time_sync_drift_ms: AtomicU32,

    // Performance Group
    avg_latency_us: AtomicU32,
    max_latency_us: AtomicU32,
    p99_latency_us: AtomicU32,
    throughput_bps: AtomicU32,
}

impl Default for MibObjects {
    fn default() -> Self {
        Self::new()
    }
}

impl MibObjects {
    /// Create new MIB objects storage
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            packets_transmitted: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            bytes_transmitted: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_connections: AtomicU32::new(0),
            total_connections_established: AtomicU64::new(0),
            hmac_validation_failures: AtomicU64::new(0),
            replay_attacks_detected: AtomicU64::new(0),
            authentication_failures: AtomicU64::new(0),
            fragment_bombs_detected: AtomicU64::new(0),
            rate_limit_violations: AtomicU64::new(0),
            blocked_sources: AtomicU32::new(0),
            port_transitions: AtomicU64::new(0),
            port_transition_failures: AtomicU64::new(0),
            current_listening_ports: AtomicU32::new(0),
            time_sync_drift_ms: AtomicU32::new(0),
            avg_latency_us: AtomicU32::new(0),
            max_latency_us: AtomicU32::new(0),
            p99_latency_us: AtomicU32::new(0),
            throughput_bps: AtomicU32::new(0),
        }
    }

    /// Get OID for a specific MIB object
    pub fn get_oid(&self, group: &str, object: u32) -> Option<ObjectIdentifier> {
        let base = match group {
            "stats" => BUCKWILD_STATS,
            "security" => BUCKWILD_SECURITY,
            "porthop" => BUCKWILD_PORT_HOP,
            "performance" => BUCKWILD_PERFORMANCE,
            _ => return None,
        };

        let mut parts = base.to_vec();
        parts.push(object);
        Some(oid_from_slice(&parts))
    }

    /// Get value for a specific OID
    pub fn get_value(&self, oid: &ObjectIdentifier) -> Option<MibValue> {
        let parts: Vec<u32> = oid
            .as_ref()
            .iter()
            .filter_map(|n| u32::try_from(*n).ok())
            .collect();

        if parts.len() < 10 {
            return None;
        }

        // Check if this is a buckwild OID
        if !parts.starts_with(BUCKWILD_OBJECTS) {
            return None;
        }

        let group = parts[8];
        let object = parts.get(9).copied()?;

        match group {
            1 => self.get_stats_value(object),
            2 => self.get_security_value(object),
            3 => self.get_porthop_value(object),
            5 => self.get_performance_value(object),
            _ => None,
        }
    }

    /// Get next OID in lexicographic order
    pub fn get_next_oid(&self, oid: &ObjectIdentifier) -> Option<ObjectIdentifier> {
        let parts: Vec<u32> = oid
            .as_ref()
            .iter()
            .filter_map(|n| u32::try_from(*n).ok())
            .collect();

        // If OID is before our MIB, return first object
        if parts.len() < 7 || parts < BUCKWILD_STATS.to_vec() {
            return self.get_oid("stats", 1);
        }

        // If OID is after our MIB, return None (end of MIB view)
        let perf_last = &[1, 3, 6, 1, 4, 1, 99999, 1, 5, 4];
        if parts > perf_last.to_vec() {
            return None;
        }

        if parts.len() < 10 {
            return self.get_oid("stats", 1);
        }

        let group = parts[8];
        let object = parts[9];

        // Navigate through MIB tree
        match (group, object) {
            (1, n) if n < 7 => self.get_oid("stats", n + 1),
            (1, 7) => self.get_oid("security", 1),
            (2, n) if n < 6 => self.get_oid("security", n + 1),
            (2, 6) => self.get_oid("porthop", 1),
            (3, n) if n < 4 => self.get_oid("porthop", n + 1),
            (3, 4) => self.get_oid("performance", 1),
            (5, n) if n < 4 => self.get_oid("performance", n + 1),
            _ => None,
        }
    }

    fn get_stats_value(&self, object: u32) -> Option<MibValue> {
        match object {
            1 => Some(MibValue::Counter64(
                self.packets_transmitted.load(Ordering::Relaxed),
            )),
            2 => Some(MibValue::Counter64(
                self.packets_received.load(Ordering::Relaxed),
            )),
            3 => Some(MibValue::Counter64(
                self.packets_dropped.load(Ordering::Relaxed),
            )),
            4 => Some(MibValue::Counter64(
                self.bytes_transmitted.load(Ordering::Relaxed),
            )),
            5 => Some(MibValue::Counter64(
                self.bytes_received.load(Ordering::Relaxed),
            )),
            6 => Some(MibValue::Gauge32(
                self.active_connections.load(Ordering::Relaxed),
            )),
            7 => Some(MibValue::Counter64(
                self.total_connections_established.load(Ordering::Relaxed),
            )),
            _ => None,
        }
    }

    fn get_security_value(&self, object: u32) -> Option<MibValue> {
        match object {
            1 => Some(MibValue::Counter64(
                self.hmac_validation_failures.load(Ordering::Relaxed),
            )),
            2 => Some(MibValue::Counter64(
                self.replay_attacks_detected.load(Ordering::Relaxed),
            )),
            3 => Some(MibValue::Counter64(
                self.authentication_failures.load(Ordering::Relaxed),
            )),
            4 => Some(MibValue::Counter64(
                self.fragment_bombs_detected.load(Ordering::Relaxed),
            )),
            5 => Some(MibValue::Counter64(
                self.rate_limit_violations.load(Ordering::Relaxed),
            )),
            6 => Some(MibValue::Gauge32(
                self.blocked_sources.load(Ordering::Relaxed),
            )),
            _ => None,
        }
    }

    fn get_porthop_value(&self, object: u32) -> Option<MibValue> {
        match object {
            1 => Some(MibValue::Counter64(
                self.port_transitions.load(Ordering::Relaxed),
            )),
            2 => Some(MibValue::Counter64(
                self.port_transition_failures.load(Ordering::Relaxed),
            )),
            3 => Some(MibValue::Gauge32(
                self.current_listening_ports.load(Ordering::Relaxed),
            )),
            4 => Some(MibValue::Integer(
                self.time_sync_drift_ms.load(Ordering::Relaxed) as i32,
            )),
            _ => None,
        }
    }

    fn get_performance_value(&self, object: u32) -> Option<MibValue> {
        match object {
            1 => Some(MibValue::Gauge32(
                self.avg_latency_us.load(Ordering::Relaxed),
            )),
            2 => Some(MibValue::Gauge32(
                self.max_latency_us.load(Ordering::Relaxed),
            )),
            3 => Some(MibValue::Gauge32(
                self.p99_latency_us.load(Ordering::Relaxed),
            )),
            4 => Some(MibValue::Gauge32(
                self.throughput_bps.load(Ordering::Relaxed),
            )),
            _ => None,
        }
    }

    // Statistics Group setters
    pub fn inc_packets_transmitted(&self, count: u64) {
        self.packets_transmitted.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_packets_received(&self, count: u64) {
        self.packets_received.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_packets_dropped(&self, count: u64) {
        self.packets_dropped.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_bytes_transmitted(&self, count: u64) {
        self.bytes_transmitted.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_bytes_received(&self, count: u64) {
        self.bytes_received.fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_active_connections(&self, count: u32) {
        self.active_connections.store(count, Ordering::Relaxed);
    }

    pub fn inc_total_connections_established(&self) {
        self.total_connections_established
            .fetch_add(1, Ordering::Relaxed);
    }

    // Security Group setters
    pub fn inc_hmac_validation_failures(&self) {
        self.hmac_validation_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_replay_attacks_detected(&self) {
        self.replay_attacks_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_authentication_failures(&self) {
        self.authentication_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fragment_bombs_detected(&self) {
        self.fragment_bombs_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limit_violations(&self) {
        self.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_blocked_sources(&self, count: u32) {
        self.blocked_sources.store(count, Ordering::Relaxed);
    }

    // Port Hopping Group setters
    pub fn inc_port_transitions(&self) {
        self.port_transitions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_port_transition_failures(&self) {
        self.port_transition_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_current_listening_ports(&self, count: u32) {
        self.current_listening_ports.store(count, Ordering::Relaxed);
    }

    pub fn set_time_sync_drift_ms(&self, drift: i32) {
        self.time_sync_drift_ms
            .store(drift as u32, Ordering::Relaxed);
    }

    // Performance Group setters
    pub fn set_avg_latency_us(&self, latency: u32) {
        self.avg_latency_us.store(latency, Ordering::Relaxed);
    }

    pub fn set_max_latency_us(&self, latency: u32) {
        self.max_latency_us.store(latency, Ordering::Relaxed);
    }

    pub fn set_p99_latency_us(&self, latency: u32) {
        self.p99_latency_us.store(latency, Ordering::Relaxed);
    }

    pub fn set_throughput_bps(&self, throughput: u32) {
        self.throughput_bps.store(throughput, Ordering::Relaxed);
    }
}

/// MIB value types
#[derive(Debug, Clone)]
pub enum MibValue {
    Integer(i32),
    Counter32(u32),
    Counter64(u64),
    Gauge32(u32),
    OctetString(Vec<u8>),
    ObjectId(ObjectIdentifier),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mib_objects_creation() {
        let mib = MibObjects::new();
        assert_eq!(mib.packets_transmitted.load(Ordering::Relaxed), 0);
        assert_eq!(mib.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stats_counters() {
        let mib = MibObjects::new();
        mib.inc_packets_transmitted(100);
        mib.inc_packets_received(50);
        mib.inc_bytes_transmitted(1024);

        assert_eq!(mib.packets_transmitted.load(Ordering::Relaxed), 100);
        assert_eq!(mib.packets_received.load(Ordering::Relaxed), 50);
        assert_eq!(mib.bytes_transmitted.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn test_get_stats_value() {
        let mib = MibObjects::new();
        mib.inc_packets_transmitted(42);

        let value = mib.get_stats_value(1);
        assert!(matches!(value, Some(MibValue::Counter64(42))));
    }

    #[test]
    fn test_get_oid() {
        let mib = MibObjects::new();
        let oid = mib.get_oid("stats", 1);
        assert!(oid.is_some());

        let parts: Vec<u32> = oid
            .unwrap()
            .as_ref()
            .iter()
            .filter_map(|n| u32::try_from(*n).ok())
            .collect();
        assert_eq!(parts, vec![1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
    }

    #[test]
    fn test_get_next_oid() {
        let mib = MibObjects::new();
        let oid1 = mib.get_oid("stats", 1).unwrap();
        let oid2 = mib.get_next_oid(&oid1).unwrap();

        let parts: Vec<u32> = oid2
            .as_ref()
            .iter()
            .filter_map(|n| u32::try_from(*n).ok())
            .collect();
        assert_eq!(parts, vec![1, 3, 6, 1, 4, 1, 99999, 1, 1, 2]);
    }

    #[test]
    fn test_session_entry() {
        let session =
            SessionEntry::new(1, 42, "192.168.1.1".to_string(), SessionState::Established);
        assert_eq!(session.index, 1);
        assert_eq!(session.session_id, 42);
        assert_eq!(session.state, SessionState::Established);

        let oid = session.get_oid(2);
        let parts: Vec<u32> = oid
            .as_ref()
            .iter()
            .filter_map(|n| u32::try_from(*n).ok())
            .collect();
        assert_eq!(parts, vec![1, 3, 6, 1, 4, 1, 99999, 1, 4, 1, 1, 2, 1]);
    }
}
