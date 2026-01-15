use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::logging::performance::PerformanceLogger;

/// Errors that can occur during SNMP operations
#[derive(Error, Debug)]
pub enum SnmpError {
    #[error("Failed to bind SNMP agent to port {port}: {source}")]
    BindError { port: u16, source: std::io::Error },

    #[error("SNMP agent not initialized")]
    NotInitialized,

    #[error("Invalid OID: {0}")]
    InvalidOid(String),

    #[error("MIB operation failed: {0}")]
    MibError(String),
}

/// SNMP Object Identifier (OID) definitions for Buckwild protocol
pub mod oids {
    pub const BUCKWILD_BASE: &str = "1.3.6.1.4.1.99999"; // Private enterprise number (example)

    // System information
    pub const SYSTEM_UPTIME: &str = "1.3.6.1.4.1.99999.1.1.1";
    pub const SYSTEM_VERSION: &str = "1.3.6.1.4.1.99999.1.1.2";
    pub const SYSTEM_STATUS: &str = "1.3.6.1.4.1.99999.1.1.3";

    // Connection statistics
    pub const ACTIVE_CONNECTIONS: &str = "1.3.6.1.4.1.99999.1.2.1";
    pub const TOTAL_CONNECTIONS: &str = "1.3.6.1.4.1.99999.1.2.2";
    pub const FAILED_CONNECTIONS: &str = "1.3.6.1.4.1.99999.1.2.3";
    pub const CONNECTION_SUCCESS_RATE: &str = "1.3.6.1.4.1.99999.1.2.4";

    // Port hopping statistics
    pub const TOTAL_PORT_HOPS: &str = "1.3.6.1.4.1.99999.1.3.1";
    pub const SUCCESSFUL_PORT_HOPS: &str = "1.3.6.1.4.1.99999.1.3.2";
    pub const FAILED_PORT_HOPS: &str = "1.3.6.1.4.1.99999.1.3.3";
    pub const CURRENT_PORT: &str = "1.3.6.1.4.1.99999.1.3.4";
    pub const PORT_HOP_SUCCESS_RATE: &str = "1.3.6.1.4.1.99999.1.3.5";
    pub const AVERAGE_HOP_TIME: &str = "1.3.6.1.4.1.99999.1.3.6";

    // Session management
    pub const ACTIVE_SESSIONS: &str = "1.3.6.1.4.1.99999.1.4.1";
    pub const TOTAL_SESSIONS: &str = "1.3.6.1.4.1.99999.1.4.2";
    pub const EXPIRED_SESSIONS: &str = "1.3.6.1.4.1.99999.1.4.3";
    pub const SESSION_MEMORY_USAGE: &str = "1.3.6.1.4.1.99999.1.4.4";

    // Cryptographic performance
    pub const ECDH_OPERATIONS_PER_SEC: &str = "1.3.6.1.4.1.99999.1.5.1";
    pub const HMAC_OPERATIONS_PER_SEC: &str = "1.3.6.1.4.1.99999.1.5.2";
    pub const KEY_CACHE_HIT_RATE: &str = "1.3.6.1.4.1.99999.1.5.3";
    pub const AVERAGE_ECDH_TIME: &str = "1.3.6.1.4.1.99999.1.5.4";

    // Fragment processing
    pub const FRAGMENTS_RECEIVED: &str = "1.3.6.1.4.1.99999.1.6.1";
    pub const FRAGMENTS_PROCESSED: &str = "1.3.6.1.4.1.99999.1.6.2";
    pub const FRAGMENTS_DROPPED: &str = "1.3.6.1.4.1.99999.1.6.3";
    pub const REASSEMBLY_SUCCESS_RATE: &str = "1.3.6.1.4.1.99999.1.6.4";
    pub const FRAGMENT_MEMORY_USAGE: &str = "1.3.6.1.4.1.99999.1.6.5";

    // Security events
    pub const SECURITY_EVENTS_TOTAL: &str = "1.3.6.1.4.1.99999.1.7.1";
    pub const AUTHENTICATION_FAILURES: &str = "1.3.6.1.4.1.99999.1.7.2";
    pub const ATTACK_ATTEMPTS: &str = "1.3.6.1.4.1.99999.1.7.3";
    pub const RATE_LIMIT_VIOLATIONS: &str = "1.3.6.1.4.1.99999.1.7.4";

    // Network performance
    pub const PACKET_LOSS_RATE: &str = "1.3.6.1.4.1.99999.1.8.1";
    pub const ROUND_TRIP_TIME: &str = "1.3.6.1.4.1.99999.1.8.2";
    pub const THROUGHPUT_BPS: &str = "1.3.6.1.4.1.99999.1.8.3";
}

/// SNMP data types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnmpValue {
    Integer(i64),
    Counter32(u32),
    Counter64(u64),
    Gauge32(u32),
    TimeTicks(u32),
    OctetString(String),
    ObjectIdentifier(String),
}

impl SnmpValue {
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            SnmpValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_counter64(&self) -> Option<u64> {
        match self {
            SnmpValue::Counter64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_gauge32(&self) -> Option<u32> {
        match self {
            SnmpValue::Gauge32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            SnmpValue::OctetString(v) => Some(v),
            _ => None,
        }
    }
}

/// SNMP Management Information Base (MIB) entry
#[derive(Debug, Clone)]
pub struct MibEntry {
    pub oid: String,
    pub value: SnmpValue,
    pub description: String,
    pub last_updated: SystemTime,
}

/// SNMP agent for Buckwild protocol monitoring
pub struct SnmpAgent {
    mib: Arc<RwLock<HashMap<String, MibEntry>>>,
    performance_logger: Arc<PerformanceLogger>,
    start_time: SystemTime,
    update_interval: Duration,
}

impl SnmpAgent {
    pub fn new(performance_logger: Arc<PerformanceLogger>) -> Result<Self, SnmpError> {
        let agent = Self {
            mib: Arc::new(RwLock::new(HashMap::new())),
            performance_logger,
            start_time: SystemTime::now(),
            update_interval: Duration::from_secs(30), // Update MIB every 30 seconds
        };

        // Initialize MIB with default values
        tokio::spawn({
            let agent_clone = agent.clone();
            async move {
                if let Err(e) = agent_clone.initialize_mib().await {
                    error!("Failed to initialize SNMP MIB: {}", e);
                }
            }
        });

        Ok(agent)
    }

    /// Initialize MIB with default values
    async fn initialize_mib(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut mib = self.mib.write().await;

        // System information
        mib.insert(
            oids::SYSTEM_VERSION.to_string(),
            MibEntry {
                oid: oids::SYSTEM_VERSION.to_string(),
                value: SnmpValue::OctetString("Buckwild 1.0.0".to_string()),
                description: "System version".to_string(),
                last_updated: SystemTime::now(),
            },
        );

        mib.insert(
            oids::SYSTEM_STATUS.to_string(),
            MibEntry {
                oid: oids::SYSTEM_STATUS.to_string(),
                value: SnmpValue::Integer(1), // 1 = running, 2 = stopped, 3 = error
                description: "System operational status".to_string(),
                last_updated: SystemTime::now(),
            },
        );

        // Initialize counters to zero
        let counter_oids = vec![
            (oids::ACTIVE_CONNECTIONS, "Active connections"),
            (oids::TOTAL_CONNECTIONS, "Total connections established"),
            (oids::FAILED_CONNECTIONS, "Failed connection attempts"),
            (oids::TOTAL_PORT_HOPS, "Total port hops performed"),
            (oids::SUCCESSFUL_PORT_HOPS, "Successful port hops"),
            (oids::FAILED_PORT_HOPS, "Failed port hops"),
            (oids::CURRENT_PORT, "Current listening port"),
            (oids::ACTIVE_SESSIONS, "Active sessions"),
            (oids::TOTAL_SESSIONS, "Total sessions created"),
            (oids::EXPIRED_SESSIONS, "Expired sessions"),
            (oids::FRAGMENTS_RECEIVED, "Fragments received"),
            (oids::FRAGMENTS_PROCESSED, "Fragments processed"),
            (oids::FRAGMENTS_DROPPED, "Fragments dropped"),
            (oids::SECURITY_EVENTS_TOTAL, "Total security events"),
            (oids::AUTHENTICATION_FAILURES, "Authentication failures"),
            (oids::ATTACK_ATTEMPTS, "Attack attempts detected"),
            (oids::RATE_LIMIT_VIOLATIONS, "Rate limit violations"),
        ];

        for (oid, description) in counter_oids {
            mib.insert(
                oid.to_string(),
                MibEntry {
                    oid: oid.to_string(),
                    value: SnmpValue::Counter64(0),
                    description: description.to_string(),
                    last_updated: SystemTime::now(),
                },
            );
        }

        // Initialize gauges to zero
        let gauge_oids = vec![
            (
                oids::CONNECTION_SUCCESS_RATE,
                "Connection success rate (percentage)",
            ),
            (
                oids::PORT_HOP_SUCCESS_RATE,
                "Port hop success rate (percentage)",
            ),
            (
                oids::AVERAGE_HOP_TIME,
                "Average port hop time (milliseconds)",
            ),
            (oids::SESSION_MEMORY_USAGE, "Session memory usage (bytes)"),
            (oids::ECDH_OPERATIONS_PER_SEC, "ECDH operations per second"),
            (oids::HMAC_OPERATIONS_PER_SEC, "HMAC operations per second"),
            (oids::KEY_CACHE_HIT_RATE, "Key cache hit rate (percentage)"),
            (
                oids::AVERAGE_ECDH_TIME,
                "Average ECDH operation time (microseconds)",
            ),
            (
                oids::REASSEMBLY_SUCCESS_RATE,
                "Fragment reassembly success rate (percentage)",
            ),
            (
                oids::FRAGMENT_MEMORY_USAGE,
                "Fragment reassembly memory usage (bytes)",
            ),
            (oids::PACKET_LOSS_RATE, "Packet loss rate (percentage)"),
            (oids::ROUND_TRIP_TIME, "Round trip time (milliseconds)"),
            (oids::THROUGHPUT_BPS, "Throughput (bits per second)"),
        ];

        for (oid, description) in gauge_oids {
            mib.insert(
                oid.to_string(),
                MibEntry {
                    oid: oid.to_string(),
                    value: SnmpValue::Gauge32(0),
                    description: description.to_string(),
                    last_updated: SystemTime::now(),
                },
            );
        }

        info!("SNMP MIB initialized with {} entries", mib.len());
        Ok(())
    }

    /// Start the SNMP agent background task
    pub async fn start(&self) -> Result<(), SnmpError> {
        info!("Starting SNMP agent");

        let mib_clone = Arc::clone(&self.mib);
        let performance_logger_clone = Arc::clone(&self.performance_logger);
        let update_interval = self.update_interval;
        let start_time = self.start_time;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(update_interval);

            loop {
                interval.tick().await;

                if let Err(e) =
                    Self::update_mib_values(&mib_clone, &performance_logger_clone, start_time).await
                {
                    error!("Failed to update SNMP MIB values: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Update MIB values from performance metrics
    async fn update_mib_values(
        mib: &Arc<RwLock<HashMap<String, MibEntry>>>,
        performance_logger: &Arc<PerformanceLogger>,
        start_time: SystemTime,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let report = performance_logger.generate_performance_report();
        let mut mib_guard = mib.write().await;
        let now = SystemTime::now();

        // Update system uptime
        let uptime_ticks = (start_time
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
            * 100) as u32; // Convert to centiseconds (TimeTicks)

        Self::update_mib_entry(
            &mut mib_guard,
            oids::SYSTEM_UPTIME,
            SnmpValue::TimeTicks(uptime_ticks),
            now,
        );

        // Update connection statistics
        Self::update_mib_entry(
            &mut mib_guard,
            oids::ACTIVE_CONNECTIONS,
            SnmpValue::Gauge32(report.connection_health.active_connections),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::TOTAL_CONNECTIONS,
            SnmpValue::Counter64(report.connection_health.total_connections),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::FAILED_CONNECTIONS,
            SnmpValue::Counter64(report.connection_health.failed_connections),
            now,
        );

        // Calculate connection success rate
        let connection_success_rate = if report.connection_health.total_connections > 0 {
            (((report.connection_health.total_connections
                - report.connection_health.failed_connections) as f64
                / report.connection_health.total_connections as f64)
                * 100.0) as u32
        } else {
            0
        };
        Self::update_mib_entry(
            &mut mib_guard,
            oids::CONNECTION_SUCCESS_RATE,
            SnmpValue::Gauge32(connection_success_rate),
            now,
        );

        // Update port hopping statistics
        Self::update_mib_entry(
            &mut mib_guard,
            oids::TOTAL_PORT_HOPS,
            SnmpValue::Counter64(report.port_hopping.total_hops),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::SUCCESSFUL_PORT_HOPS,
            SnmpValue::Counter64(report.port_hopping.successful_hops),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::FAILED_PORT_HOPS,
            SnmpValue::Counter64(report.port_hopping.failed_hops),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::CURRENT_PORT,
            SnmpValue::Gauge32(report.port_hopping.current_port.as_u16() as u32),
            now,
        );

        // Calculate port hop success rate
        let port_hop_success_rate = if report.port_hopping.total_hops > 0 {
            ((report.port_hopping.successful_hops as f64 / report.port_hopping.total_hops as f64)
                * 100.0) as u32
        } else {
            0
        };
        Self::update_mib_entry(
            &mut mib_guard,
            oids::PORT_HOP_SUCCESS_RATE,
            SnmpValue::Gauge32(port_hop_success_rate),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::AVERAGE_HOP_TIME,
            SnmpValue::Gauge32(report.port_hopping.average_hop_time.as_millis() as u32),
            now,
        );

        // Update session statistics
        Self::update_mib_entry(
            &mut mib_guard,
            oids::ACTIVE_SESSIONS,
            SnmpValue::Gauge32(report.session_stats.active_sessions.as_u32()),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::TOTAL_SESSIONS,
            SnmpValue::Counter64(report.session_stats.total_sessions_created),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::EXPIRED_SESSIONS,
            SnmpValue::Counter64(report.session_stats.sessions_expired),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::SESSION_MEMORY_USAGE,
            SnmpValue::Gauge32(report.session_stats.memory_usage_bytes as u32),
            now,
        );

        // Update cryptographic performance
        Self::update_mib_entry(
            &mut mib_guard,
            oids::ECDH_OPERATIONS_PER_SEC,
            SnmpValue::Gauge32(report.crypto_performance.ecdh_operations_per_second as u32),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::HMAC_OPERATIONS_PER_SEC,
            SnmpValue::Gauge32(report.crypto_performance.hmac_operations_per_second as u32),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::KEY_CACHE_HIT_RATE,
            SnmpValue::Gauge32((report.crypto_performance.key_cache_hit_rate * 100.0) as u32),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::AVERAGE_ECDH_TIME,
            SnmpValue::Gauge32(report.crypto_performance.average_ecdh_time.as_millis() as u32),
            now,
        );

        // Update fragment processing statistics
        Self::update_mib_entry(
            &mut mib_guard,
            oids::FRAGMENTS_RECEIVED,
            SnmpValue::Counter64(report.fragment_processing.fragments_received),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::FRAGMENTS_PROCESSED,
            SnmpValue::Counter64(report.fragment_processing.fragments_processed),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::FRAGMENTS_DROPPED,
            SnmpValue::Counter64(report.fragment_processing.fragments_dropped),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::REASSEMBLY_SUCCESS_RATE,
            SnmpValue::Gauge32((report.fragment_processing.reassembly_success_rate * 100.0) as u32),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::FRAGMENT_MEMORY_USAGE,
            SnmpValue::Gauge32(report.fragment_processing.memory_usage_bytes as u32),
            now,
        );

        // Update network performance
        Self::update_mib_entry(
            &mut mib_guard,
            oids::PACKET_LOSS_RATE,
            SnmpValue::Gauge32((report.connection_health.packet_loss_rate * 100.0) as u32),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::ROUND_TRIP_TIME,
            SnmpValue::Gauge32(report.connection_health.round_trip_time.as_millis() as u32),
            now,
        );
        Self::update_mib_entry(
            &mut mib_guard,
            oids::THROUGHPUT_BPS,
            SnmpValue::Gauge32(report.connection_health.throughput_bps as u32),
            now,
        );

        debug!("Updated {} SNMP MIB entries", mib_guard.len());
        Ok(())
    }

    /// Update a single MIB entry
    fn update_mib_entry(
        mib: &mut HashMap<String, MibEntry>,
        oid: &str,
        value: SnmpValue,
        timestamp: SystemTime,
    ) {
        if let Some(entry) = mib.get_mut(oid) {
            entry.value = value;
            entry.last_updated = timestamp;
        }
    }

    /// Get MIB entry by OID
    pub async fn get_mib_entry(&self, oid: &str) -> Option<MibEntry> {
        let mib = self.mib.read().await;
        mib.get(oid).cloned()
    }

    /// Get all MIB entries
    pub async fn get_all_mib_entries(&self) -> HashMap<String, MibEntry> {
        let mib = self.mib.read().await;
        mib.clone()
    }

    /// Handle SNMP GET request
    pub async fn handle_get_request(&self, oid: &str) -> Result<SnmpValue, String> {
        match self.get_mib_entry(oid).await {
            Some(entry) => Ok(entry.value),
            None => Err(format!("OID {} not found", oid)),
        }
    }

    /// Handle SNMP GETNEXT request
    pub async fn handle_getnext_request(&self, oid: &str) -> Result<(String, SnmpValue), String> {
        let mib = self.mib.read().await;
        let mut sorted_oids: Vec<_> = mib.keys().collect();
        sorted_oids.sort();

        // Find the next OID lexicographically
        for next_oid in sorted_oids {
            if next_oid.as_str() > oid {
                if let Some(entry) = mib.get(next_oid.as_str()) {
                    return Ok((next_oid.clone(), entry.value.clone()));
                }
            }
        }

        Err("No next OID found".to_string())
    }

    /// Handle SNMP GETBULK request
    pub async fn handle_getbulk_request(
        &self,
        oid: &str,
        max_repetitions: usize,
    ) -> Result<Vec<(String, SnmpValue)>, String> {
        let mib = self.mib.read().await;
        let mut sorted_oids: Vec<_> = mib.keys().collect();
        sorted_oids.sort();

        let mut results = Vec::new();
        let mut found_start = false;

        for next_oid in sorted_oids {
            if !found_start {
                if next_oid.as_str() > oid {
                    found_start = true;
                } else {
                    continue;
                }
            }

            if results.len() >= max_repetitions {
                break;
            }

            if let Some(entry) = mib.get(next_oid.as_str()) {
                results.push((next_oid.clone(), entry.value.clone()));
            }
        }

        if results.is_empty() {
            Err("No OIDs found".to_string())
        } else {
            Ok(results)
        }
    }

    /// Get SNMP agent statistics
    pub async fn get_agent_statistics(&self) -> SnmpAgentStatistics {
        let mib = self.mib.read().await;

        SnmpAgentStatistics {
            total_oids: mib.len(),
            uptime: self.start_time.elapsed().unwrap_or(Duration::from_secs(0)),
            last_update: mib
                .values()
                .map(|entry| entry.last_updated)
                .max()
                .unwrap_or(self.start_time),
        }
    }
}

impl Clone for SnmpAgent {
    fn clone(&self) -> Self {
        Self {
            mib: Arc::clone(&self.mib),
            performance_logger: Arc::clone(&self.performance_logger),
            start_time: self.start_time,
            update_interval: self.update_interval,
        }
    }
}

/// SNMP agent statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpAgentStatistics {
    pub total_oids: usize,
    pub uptime: Duration,
    pub last_update: SystemTime,
}
