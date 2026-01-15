use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

use super::correlation::CorrelationId;
use buckwild_common::protocol::types::{SessionCount, Timeout, Timestamp};

/// Performance metrics for different system components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub timestamp: Timestamp,
    pub component: String,
    pub correlation_id: Option<CorrelationId>,
    pub metrics: HashMap<String, MetricValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
    Duration(Timeout),
}

impl MetricValue {
    pub fn as_counter(&self) -> Option<u64> {
        match self {
            MetricValue::Counter(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_gauge(&self) -> Option<f64> {
        match self {
            MetricValue::Gauge(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_duration(&self) -> Option<Timeout> {
        match self {
            MetricValue::Duration(v) => Some(*v),
            _ => None,
        }
    }
}

/// Port hopping statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortHoppingStats {
    pub total_hops: u64,
    pub successful_hops: u64,
    pub failed_hops: u64,
    pub average_hop_time: Timeout,
    pub current_port: crate::protocol::types::Port,
    pub next_hop_time: Timestamp,
    pub synchronization_accuracy: Timeout,
}

/// Connection health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionHealthMetrics {
    pub active_connections: u32,
    pub total_connections: u64,
    pub failed_connections: u64,
    pub average_connection_duration: Timeout,
    pub packet_loss_rate: f64,
    pub round_trip_time: Timeout,
    pub throughput_bps: u64,
}

/// Session management statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub active_sessions: crate::protocol::types::SessionCount,
    pub total_sessions_created: u64,
    pub sessions_expired: u64,
    pub average_session_lifetime: Timeout,
    pub memory_usage_bytes: u64,
}

/// Cryptographic operation performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoPerformanceStats {
    pub ecdh_operations_per_second: f64,
    pub hmac_operations_per_second: f64,
    pub average_ecdh_time: Timeout,
    pub average_hmac_time: Timeout,
    pub key_cache_hit_rate: f64,
}

/// Fragment processing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentStats {
    pub fragments_received: u64,
    pub fragments_processed: u64,
    pub fragments_dropped: u64,
    pub reassembly_success_rate: f64,
    pub average_reassembly_time: Timeout,
    pub memory_usage_bytes: u64,
}

/// Performance logger with metrics collection
pub struct PerformanceLogger {
    metrics_counter: AtomicU64,
    port_hopping_stats: Arc<RwLock<PortHoppingStats>>,
    connection_health: Arc<RwLock<ConnectionHealthMetrics>>,
    session_stats: Arc<RwLock<SessionStats>>,
    crypto_stats: Arc<RwLock<CryptoPerformanceStats>>,
    fragment_stats: Arc<RwLock<FragmentStats>>,
    custom_metrics: Arc<DashMap<String, MetricValue>>,
    start_time: Timestamp,
}

impl Default for PerformanceLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceLogger {
    pub fn new() -> Self {
        Self {
            metrics_counter: AtomicU64::new(0),
            port_hopping_stats: Arc::new(RwLock::new(PortHoppingStats {
                total_hops: 0,
                successful_hops: 0,
                failed_hops: 0,
                average_hop_time: Timeout::from_millis(0),
                current_port: crate::protocol::types::Port::from_u16_unchecked(0),
                next_hop_time: Timestamp::now(),
                synchronization_accuracy: Timeout::from_millis(0),
            })),
            connection_health: Arc::new(RwLock::new(ConnectionHealthMetrics {
                active_connections: 0,
                total_connections: 0,
                failed_connections: 0,
                average_connection_duration: Timeout::from_secs(0),
                packet_loss_rate: 0.0,
                round_trip_time: Timeout::from_millis(0),
                throughput_bps: 0,
            })),
            session_stats: Arc::new(RwLock::new(SessionStats {
                active_sessions: crate::protocol::types::SessionCount::zero(),
                total_sessions_created: 0,
                sessions_expired: 0,
                average_session_lifetime: Timeout::from_secs(0),
                memory_usage_bytes: 0,
            })),
            crypto_stats: Arc::new(RwLock::new(CryptoPerformanceStats {
                ecdh_operations_per_second: 0.0,
                hmac_operations_per_second: 0.0,
                average_ecdh_time: Timeout::from_millis(0),
                average_hmac_time: Timeout::from_millis(0),
                key_cache_hit_rate: 0.0,
            })),
            fragment_stats: Arc::new(RwLock::new(FragmentStats {
                fragments_received: 0,
                fragments_processed: 0,
                fragments_dropped: 0,
                reassembly_success_rate: 0.0,
                average_reassembly_time: Timeout::from_millis(0),
                memory_usage_bytes: 0,
            })),
            custom_metrics: Arc::new(DashMap::new()),
            start_time: Timestamp::now(),
        }
    }

    /// Log performance metrics
    pub fn log_metrics(&self, metrics: PerformanceMetrics) {
        self.metrics_counter.fetch_add(1, Ordering::Relaxed);

        info!(
            component = %metrics.component,
            correlation_id = ?metrics.correlation_id,
            metrics = ?metrics.metrics,
            "Performance metrics recorded"
        );

        // Update component-specific metrics
        match metrics.component.as_str() {
            "port_hopping" => self.update_port_hopping_stats(&metrics.metrics),
            "connection" => self.update_connection_health(&metrics.metrics),
            "session" => self.update_session_stats(&metrics.metrics),
            "crypto" => self.update_crypto_stats(&metrics.metrics),
            "fragment" => self.update_fragment_stats(&metrics.metrics),
            _ => {
                // Store custom metrics
                for (key, value) in metrics.metrics {
                    self.custom_metrics
                        .insert(format!("{}_{}", metrics.component, key), value);
                }
            }
        }
    }

    /// Update port hopping statistics
    pub fn update_port_hopping_stats(&self, metrics: &HashMap<String, MetricValue>) {
        let mut stats = self.port_hopping_stats.write();

        if let Some(MetricValue::Counter(total)) = metrics.get("total_hops") {
            stats.total_hops = *total;
        }
        if let Some(MetricValue::Counter(successful)) = metrics.get("successful_hops") {
            stats.successful_hops = *successful;
        }
        if let Some(MetricValue::Counter(failed)) = metrics.get("failed_hops") {
            stats.failed_hops = *failed;
        }
        if let Some(MetricValue::Duration(avg_time)) = metrics.get("average_hop_time") {
            stats.average_hop_time = *avg_time;
        }
        if let Some(MetricValue::Counter(port)) = metrics.get("current_port") {
            stats.current_port = crate::protocol::types::Port::from_u16_unchecked(*port as u16);
        }
        if let Some(MetricValue::Duration(sync_accuracy)) = metrics.get("synchronization_accuracy")
        {
            stats.synchronization_accuracy = *sync_accuracy;
        }
    }

    /// Update connection health metrics
    pub fn update_connection_health(&self, metrics: &HashMap<String, MetricValue>) {
        let mut health = self.connection_health.write();

        if let Some(MetricValue::Counter(active)) = metrics.get("active_connections") {
            health.active_connections = *active as u32;
        }
        if let Some(MetricValue::Counter(total)) = metrics.get("total_connections") {
            health.total_connections = *total;
        }
        if let Some(MetricValue::Counter(failed)) = metrics.get("failed_connections") {
            health.failed_connections = *failed;
        }
        if let Some(MetricValue::Duration(avg_duration)) =
            metrics.get("average_connection_duration")
        {
            health.average_connection_duration = *avg_duration;
        }
        if let Some(MetricValue::Gauge(loss_rate)) = metrics.get("packet_loss_rate") {
            health.packet_loss_rate = *loss_rate;
        }
        if let Some(MetricValue::Duration(rtt)) = metrics.get("round_trip_time") {
            health.round_trip_time = *rtt;
        }
        if let Some(MetricValue::Counter(throughput)) = metrics.get("throughput_bps") {
            health.throughput_bps = *throughput;
        }
    }

    /// Update session statistics
    pub fn update_session_stats(&self, metrics: &HashMap<String, MetricValue>) {
        let mut stats = self.session_stats.write();

        if let Some(MetricValue::Counter(active)) = metrics.get("active_sessions") {
            stats.active_sessions = SessionCount::new(*active as u32);
        }
        if let Some(MetricValue::Counter(total)) = metrics.get("total_sessions_created") {
            stats.total_sessions_created = *total;
        }
        if let Some(MetricValue::Counter(expired)) = metrics.get("sessions_expired") {
            stats.sessions_expired = *expired;
        }
        if let Some(MetricValue::Duration(avg_lifetime)) = metrics.get("average_session_lifetime") {
            stats.average_session_lifetime = *avg_lifetime;
        }
        if let Some(MetricValue::Counter(memory)) = metrics.get("memory_usage_bytes") {
            stats.memory_usage_bytes = *memory;
        }
    }

    /// Update cryptographic performance statistics
    pub fn update_crypto_stats(&self, metrics: &HashMap<String, MetricValue>) {
        let mut stats = self.crypto_stats.write();

        if let Some(MetricValue::Gauge(ecdh_ops)) = metrics.get("ecdh_operations_per_second") {
            stats.ecdh_operations_per_second = *ecdh_ops;
        }
        if let Some(MetricValue::Gauge(hmac_ops)) = metrics.get("hmac_operations_per_second") {
            stats.hmac_operations_per_second = *hmac_ops;
        }
        if let Some(MetricValue::Duration(ecdh_time)) = metrics.get("average_ecdh_time") {
            stats.average_ecdh_time = *ecdh_time;
        }
        if let Some(MetricValue::Duration(hmac_time)) = metrics.get("average_hmac_time") {
            stats.average_hmac_time = *hmac_time;
        }
        if let Some(MetricValue::Gauge(hit_rate)) = metrics.get("key_cache_hit_rate") {
            stats.key_cache_hit_rate = *hit_rate;
        }
    }

    /// Update fragment processing statistics
    pub fn update_fragment_stats(&self, metrics: &HashMap<String, MetricValue>) {
        let mut stats = self.fragment_stats.write();

        if let Some(MetricValue::Counter(received)) = metrics.get("fragments_received") {
            stats.fragments_received = *received;
        }
        if let Some(MetricValue::Counter(processed)) = metrics.get("fragments_processed") {
            stats.fragments_processed = *processed;
        }
        if let Some(MetricValue::Counter(dropped)) = metrics.get("fragments_dropped") {
            stats.fragments_dropped = *dropped;
        }
        if let Some(MetricValue::Gauge(success_rate)) = metrics.get("reassembly_success_rate") {
            stats.reassembly_success_rate = *success_rate;
        }
        if let Some(MetricValue::Duration(avg_time)) = metrics.get("average_reassembly_time") {
            stats.average_reassembly_time = *avg_time;
        }
        if let Some(MetricValue::Counter(memory)) = metrics.get("memory_usage_bytes") {
            stats.memory_usage_bytes = *memory;
        }
    }

    /// Get current port hopping statistics
    pub fn get_port_hopping_stats(&self) -> PortHoppingStats {
        self.port_hopping_stats.read().clone()
    }

    /// Get current connection health metrics
    pub fn get_connection_health(&self) -> ConnectionHealthMetrics {
        self.connection_health.read().clone()
    }

    /// Get current session statistics
    pub fn get_session_stats(&self) -> SessionStats {
        self.session_stats.read().clone()
    }

    /// Get current cryptographic performance statistics
    pub fn get_crypto_stats(&self) -> CryptoPerformanceStats {
        self.crypto_stats.read().clone()
    }

    /// Get current fragment processing statistics
    pub fn get_fragment_stats(&self) -> FragmentStats {
        self.fragment_stats.read().clone()
    }

    /// Get total metrics count
    pub fn get_metrics_count(&self) -> u64 {
        self.metrics_counter.load(Ordering::Relaxed)
    }

    /// Get system uptime
    pub fn get_uptime(&self) -> Timeout {
        let current = Timestamp::now();
        let elapsed_nanos = current
            .as_nanos()
            .saturating_sub(self.start_time.as_nanos());
        Timeout::from_millis(elapsed_nanos / 1_000_000)
    }

    /// Get custom metric value
    pub fn get_custom_metric(&self, key: &str) -> Option<MetricValue> {
        self.custom_metrics.get(key).map(|v| v.clone())
    }

    /// Set custom metric value
    pub fn set_custom_metric(&self, key: String, value: MetricValue) {
        self.custom_metrics.insert(key, value);
    }

    /// Get all custom metrics
    pub fn get_all_custom_metrics(&self) -> HashMap<String, MetricValue> {
        self.custom_metrics
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Generate comprehensive performance report
    pub fn generate_performance_report(&self) -> PerformanceReport {
        PerformanceReport {
            timestamp: Timestamp::now(),
            uptime: self.get_uptime(),
            total_metrics_recorded: self.get_metrics_count(),
            port_hopping: self.get_port_hopping_stats(),
            connection_health: self.get_connection_health(),
            session_stats: self.get_session_stats(),
            crypto_performance: self.get_crypto_stats(),
            fragment_processing: self.get_fragment_stats(),
            custom_metrics: self.get_all_custom_metrics(),
        }
    }
}

/// Comprehensive performance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub timestamp: Timestamp,
    pub uptime: Timeout,
    pub total_metrics_recorded: u64,
    pub port_hopping: PortHoppingStats,
    pub connection_health: ConnectionHealthMetrics,
    pub session_stats: SessionStats,
    pub crypto_performance: CryptoPerformanceStats,
    pub fragment_processing: FragmentStats,
    pub custom_metrics: HashMap<String, MetricValue>,
}

/// Performance measurement helper
pub struct PerformanceMeasurement {
    start_time: Timestamp,
    component: String,
    operation: String,
    correlation_id: Option<CorrelationId>,
}

impl PerformanceMeasurement {
    pub fn new(component: &str, operation: &str, correlation_id: Option<CorrelationId>) -> Self {
        Self {
            start_time: Timestamp::now(),
            component: component.to_string(),
            operation: operation.to_string(),
            correlation_id,
        }
    }

    pub fn finish(self, logger: &PerformanceLogger) {
        let current = Timestamp::now();
        let elapsed_nanos = current
            .as_nanos()
            .saturating_sub(self.start_time.as_nanos());
        let duration = Timeout::from_millis(elapsed_nanos / 1_000_000);

        let mut metrics = HashMap::new();
        metrics.insert(
            format!("{}_duration", self.operation),
            MetricValue::Duration(duration),
        );

        let perf_metrics = PerformanceMetrics {
            timestamp: Timestamp::now(),
            component: self.component,
            correlation_id: self.correlation_id,
            metrics,
        };

        logger.log_metrics(perf_metrics);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let logger = PerformanceLogger::new();
        let initial_count = logger.metrics_counter.load(Ordering::Relaxed);

        let mut metrics = HashMap::new();
        metrics.insert("test_counter".to_string(), MetricValue::Counter(42));

        let perf_metrics = PerformanceMetrics {
            timestamp: Timestamp::now(),
            component: "test".to_string(),
            correlation_id: None,
            metrics,
        };

        logger.log_metrics(perf_metrics);

        let updated_count = logger.metrics_counter.load(Ordering::Relaxed);
        assert_eq!(updated_count, initial_count + 1);
    }

    #[test]
    fn test_gauge_value_reporting() {
        let logger = PerformanceLogger::new();

        let mut metrics = HashMap::new();
        metrics.insert("packet_loss_rate".to_string(), MetricValue::Gauge(0.05));
        metrics.insert("active_connections".to_string(), MetricValue::Counter(10));

        let perf_metrics = PerformanceMetrics {
            timestamp: Timestamp::now(),
            component: "connection".to_string(),
            correlation_id: None,
            metrics,
        };

        logger.log_metrics(perf_metrics);

        let health = logger.connection_health.read();
        assert_eq!(health.packet_loss_rate, 0.05);
        assert_eq!(health.active_connections, 10);
    }
}
