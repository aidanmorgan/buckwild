// Health monitoring system
//
// This module provides health check functionality for the Buckwild protocol,
// enabling monitoring of system health and component status.

use crate::error::BuckwildError;
use crate::protocol::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Health monitoring system
pub struct HealthMonitor {
    /// Health checks registry
    checks: Arc<RwLock<HashMap<String, Box<dyn HealthCheck + Send + Sync>>>>,
    /// Health status cache
    status_cache: Arc<RwLock<HashMap<String, HealthStatus>>>,
    /// Monitor configuration
    config: HealthConfig,
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Check interval
    pub check_interval: Duration,
    /// Timeout for individual checks
    pub check_timeout: Duration,
    /// Number of consecutive failures before marking unhealthy
    pub failure_threshold: crate::protocol::types::FailureCount,
    /// Cache TTL for health status
    pub cache_ttl: Duration,
}

/// Health check trait
pub trait HealthCheck {
    /// Perform the health check
    fn check(&self) -> Result<HealthStatus, BuckwildError>;

    /// Get the name of this health check
    fn name(&self) -> &str;

    /// Get the description of this health check
    fn description(&self) -> &str;
}

/// Health status result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Check name
    pub name: String,
    /// Overall health status
    pub status: HealthState,
    /// Status message
    pub message: String,
    /// Additional details
    pub details: HashMap<String, String>,
    /// Timestamp of the check (nanoseconds since UNIX epoch)
    pub timestamp: Timestamp,
    /// Check duration (nanoseconds)
    pub duration: ProtocolDuration,
}

// Use consolidated HealthState from protocol types
use crate::protocol::types::HealthState;

/// Overall system health summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    /// Overall system status
    pub status: HealthState,
    /// Individual check results
    pub checks: Vec<HealthStatus>,
    /// Summary message
    pub message: String,
    /// Total checks performed
    pub total_checks: PacketCount,
    /// Number of healthy checks
    pub healthy_checks: PacketCount,
    /// Number of warning checks
    pub warning_checks: PacketCount,
    /// Number of unhealthy checks
    pub unhealthy_checks: PacketCount,
    /// Timestamp of the summary (nanoseconds since UNIX epoch)
    pub timestamp: Timestamp,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(config: HealthConfig) -> Self {
        Self {
            checks: Arc::new(RwLock::new(HashMap::new())),
            status_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Register a health check
    pub async fn register_check(&self, check: Box<dyn HealthCheck + Send + Sync>) {
        let name = check.name().to_string();
        let mut checks = self.checks.write().await;
        checks.insert(name, check);
    }

    /// Perform all health checks
    pub async fn check_all(&self) -> SystemHealth {
        let checks = self.checks.read().await;
        let mut results = Vec::new();
        let mut healthy_count: u64 = 0;
        let mut warning_count: u64 = 0;
        let mut unhealthy_count = 0;

        for (name, check) in checks.iter() {
            let start_time = Instant::now();

            let status = match tokio::time::timeout(self.config.check_timeout, async {
                check.check()
            })
            .await
            {
                Ok(Ok(mut status)) => {
                    status.duration = ProtocolDuration::new(start_time.elapsed().as_nanos() as u64);
                    status.timestamp = Timestamp::from_nanos(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                    );
                    status
                }
                Ok(Err(e)) => HealthStatus {
                    name: name.clone(),
                    status: HealthState::Critical,
                    message: format!("Check failed: {}", e),
                    details: HashMap::new(),
                    timestamp: Timestamp::from_nanos(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                    ),
                    duration: ProtocolDuration::new(start_time.elapsed().as_nanos() as u64),
                },
                Err(_) => HealthStatus {
                    name: name.clone(),
                    status: HealthState::Critical,
                    message: "Check timed out".to_string(),
                    details: HashMap::new(),
                    timestamp: Timestamp::from_nanos(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                    ),
                    duration: ProtocolDuration::new(self.config.check_timeout.as_nanos() as u64),
                },
            };

            match status.status {
                HealthState::Healthy => healthy_count += 1,
                HealthState::Warning => warning_count += 1,
                HealthState::Critical => unhealthy_count += 1,
                HealthState::Unknown => {}
            }

            results.push(status);
        }

        // Update cache
        let mut cache = self.status_cache.write().await;
        for result in &results {
            cache.insert(result.name.clone(), result.clone());
        }

        // Determine overall status
        let overall_status = if unhealthy_count > 0 {
            HealthState::Critical
        } else if warning_count > 0 {
            HealthState::Warning
        } else if healthy_count > 0 {
            HealthState::Healthy
        } else {
            HealthState::Unknown
        };

        let message = format!(
            "{} healthy, {} warnings, {} unhealthy",
            healthy_count, warning_count, unhealthy_count
        );

        SystemHealth {
            status: overall_status,
            checks: results,
            message,
            total_checks: PacketCount::new(checks.len() as u64),
            healthy_checks: PacketCount::new(healthy_count),
            warning_checks: PacketCount::new(warning_count),
            unhealthy_checks: PacketCount::new(unhealthy_count),
            timestamp: Timestamp::from_nanos(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
            ),
        }
    }

    /// Get cached health status for a specific check
    pub async fn get_check_status(&self, name: &str) -> Option<HealthStatus> {
        let cache = self.status_cache.read().await;
        cache.get(name).cloned()
    }

    /// Start periodic health monitoring
    pub async fn start_monitoring(&self) {
        let mut interval = tokio::time::interval(self.config.check_interval);

        loop {
            interval.tick().await;
            let _health = self.check_all().await;
            // In a real implementation, you might want to log or alert on health changes
        }
    }
}

/// Basic connectivity health check
pub struct ConnectivityCheck {
    name: String,
    description: String,
}

impl Default for ConnectivityCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectivityCheck {
    pub fn new() -> Self {
        Self {
            name: "connectivity".to_string(),
            description: "Checks basic network connectivity".to_string(),
        }
    }
}

impl HealthCheck for ConnectivityCheck {
    fn check(&self) -> Result<HealthStatus, BuckwildError> {
        // Basic connectivity check - reports healthy by default
        // Integration: extend with actual network connectivity tests (ping, socket status, etc.)

        Ok(HealthStatus {
            name: self.name.clone(),
            status: HealthState::Healthy,
            message: "Network layer initialized".to_string(),
            details: HashMap::new(),
            timestamp: Timestamp::now(),
            duration: ProtocolDuration::new(1_000_000), // 1ms in nanoseconds
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// Memory usage health check
pub struct MemoryCheck {
    name: String,
    description: String,
    warning_threshold: ThresholdValue,
    critical_threshold: ThresholdValue,
}

impl MemoryCheck {
    pub fn new(warning_threshold: f64, critical_threshold: f64) -> Self {
        Self {
            name: "memory".to_string(),
            description: "Checks memory usage".to_string(),
            warning_threshold: ThresholdValue::new(warning_threshold),
            critical_threshold: ThresholdValue::new(critical_threshold),
        }
    }

    /// Get system memory usage as a percentage (0.0 to 1.0)
    ///
    /// On Linux, reads from /proc/meminfo. On other platforms, returns 0.0.
    fn get_system_memory_usage(&self) -> f64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
                let mut mem_total: u64 = 0;
                let mut mem_available: u64 = 0;

                for line in content.lines() {
                    if line.starts_with("MemTotal:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            mem_total = parts[1].parse().unwrap_or(0);
                        }
                    } else if line.starts_with("MemAvailable:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            mem_available = parts[1].parse().unwrap_or(0);
                        }
                    }
                }

                if mem_total > 0 {
                    let mem_used = mem_total.saturating_sub(mem_available);
                    return mem_used as f64 / mem_total as f64;
                }
            }
            0.0
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Platform-specific metrics not implemented for non-Linux systems
            0.0
        }
    }
}

impl HealthCheck for MemoryCheck {
    fn check(&self) -> Result<HealthStatus, BuckwildError> {
        // Read actual memory usage from system
        let memory_usage = self.get_system_memory_usage();

        let (status, message) = if self.critical_threshold.exceeded_by(memory_usage) {
            (
                HealthState::Critical,
                format!(
                    "Memory usage critical: {:.1}%",
                    Rate::from_raw(memory_usage as f32 * 100.0).0
                ),
            )
        } else if self.warning_threshold.exceeded_by(memory_usage) {
            (
                HealthState::Warning,
                format!(
                    "Memory usage high: {:.1}%",
                    Rate::from_raw(memory_usage as f32 * 100.0).0
                ),
            )
        } else {
            (
                HealthState::Healthy,
                format!(
                    "Memory usage normal: {:.1}%",
                    Rate::from_raw(memory_usage as f32 * 100.0).0
                ),
            )
        };

        let mut details = HashMap::new();
        details.insert(
            "usage_percent".to_string(),
            format!("{:.1}", Rate::from_raw(memory_usage as f32 * 100.0).0),
        );
        details.insert(
            "warning_threshold".to_string(),
            format!("{:.1}", self.warning_threshold.as_f64() * 100.0),
        );
        details.insert(
            "critical_threshold".to_string(),
            format!("{:.1}", self.critical_threshold.as_f64() * 100.0),
        );

        Ok(HealthStatus {
            name: self.name.clone(),
            status,
            message,
            details,
            timestamp: Timestamp::now(),
            duration: ProtocolDuration::new(5_000_000), // 5ms in nanoseconds
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// Session health check
pub struct SessionHealthCheck {
    name: String,
    description: String,
}

impl Default for SessionHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionHealthCheck {
    pub fn new() -> Self {
        Self {
            name: "sessions".to_string(),
            description: "Checks session management health".to_string(),
        }
    }
}

impl HealthCheck for SessionHealthCheck {
    fn check(&self) -> Result<HealthStatus, BuckwildError> {
        // Basic session health check - reports healthy by default
        // Integration: Pass in Arc<SessionManager> to check actual session counts
        // and health metrics from the live session manager

        // Default values when no session manager is integrated
        let active_sessions = 0;
        let max_sessions = 1000;

        let usage_percent = (active_sessions as f64 / max_sessions as f64) * 100.0;

        let (status, message) = if usage_percent >= 90.0 {
            (
                HealthState::Warning,
                format!("High session usage: {:.1}%", usage_percent),
            )
        } else {
            (
                HealthState::Healthy,
                "Session manager ready (no active sessions tracked)".to_string(),
            )
        };

        let mut details = HashMap::new();
        details.insert("active_sessions".to_string(), active_sessions.to_string());
        details.insert("max_sessions".to_string(), max_sessions.to_string());
        details.insert("usage_percent".to_string(), format!("{:.1}", usage_percent));

        Ok(HealthStatus {
            name: self.name.clone(),
            status,
            message,
            details,
            timestamp: Timestamp::now(),
            duration: ProtocolDuration::new(2_000_000), // 2ms in nanoseconds
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            check_timeout: Duration::from_secs(5),
            failure_threshold: FailureCount::new(3),
            cache_ttl: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_monitor() {
        let config = HealthConfig::default();
        let monitor = HealthMonitor::new(config);

        // Register a test health check
        let check = Box::new(ConnectivityCheck::new());
        monitor.register_check(check).await;

        // Perform health checks
        let health = monitor.check_all().await;
        assert_eq!(health.total_checks.as_u64(), 1);
        assert_eq!(health.healthy_checks.as_u64(), 1);
        assert_eq!(health.status, HealthState::Healthy);
    }

    #[test]
    fn test_connectivity_check() {
        let check = ConnectivityCheck::new();
        let result = check.check().unwrap();

        assert_eq!(result.name, "connectivity");
        assert_eq!(result.status, HealthState::Healthy);
    }

    #[test]
    fn test_memory_check() {
        let check = MemoryCheck::new(0.8, 0.9);
        let result = check.check().unwrap();

        assert_eq!(result.name, "memory");
        assert!(result.details.contains_key("usage_percent"));
    }

    #[test]
    fn test_session_health_check() {
        let check = SessionHealthCheck::new();
        let result = check.check().unwrap();

        assert_eq!(result.name, "sessions");
        assert!(result.details.contains_key("active_sessions"));
    }

    #[test]
    fn test_health_state_display() {
        assert_eq!(format!("{}", HealthState::Healthy), "HEALTHY");
        assert_eq!(format!("{}", HealthState::Warning), "WARNING");
        assert_eq!(format!("{}", HealthState::Critical), "CRITICAL");
        assert_eq!(format!("{}", HealthState::Unknown), "UNKNOWN");
    }
}
