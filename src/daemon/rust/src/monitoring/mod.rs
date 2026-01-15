pub mod debug;
pub mod health;
pub mod snmp;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use crate::logging::{LoggingManager, performance::PerformanceLogger, security::SecurityLogger};
use snmp::SnmpAgent;

/// Errors that can occur during monitoring operations
#[derive(Error, Debug)]
pub enum MonitoringError {
    #[error("SNMP agent error: {0}")]
    SnmpError(#[from] snmp::SnmpError),

    #[error("Monitoring service already started")]
    AlreadyStarted,

    #[error("Monitoring service not configured")]
    NotConfigured,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_snmp: bool,
    pub snmp_port: crate::protocol::types::Port,
    pub snmp_community: String,
    pub metrics_update_interval_seconds: u64,
    pub enable_prometheus: bool,
    pub prometheus_port: crate::protocol::types::Port,
    pub enable_syslog: bool,
    pub syslog_facility: String,
    pub syslog_server: Option<String>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_snmp: true,
            snmp_port: crate::protocol::types::Port::from_well_known(161),
            snmp_community: "public".to_string(),
            metrics_update_interval_seconds: 30,
            enable_prometheus: false,
            prometheus_port: crate::protocol::types::Port::from_well_known(9090),
            enable_syslog: true,
            syslog_facility: "daemon".to_string(),
            syslog_server: None, // Use local syslog by default
        }
    }
}

/// Comprehensive monitoring manager
pub struct MonitoringManager {
    config: Arc<RwLock<MonitoringConfig>>,
    snmp_agent: Option<SnmpAgent>,
    performance_logger: Arc<PerformanceLogger>,
    security_logger: Arc<SecurityLogger>,
    logging_manager: Arc<LoggingManager>,
}

impl MonitoringManager {
    pub async fn new(
        config: MonitoringConfig,
        performance_logger: Arc<PerformanceLogger>,
        security_logger: Arc<SecurityLogger>,
        logging_manager: Arc<LoggingManager>,
    ) -> Result<Self, MonitoringError> {
        let snmp_agent = if config.enable_snmp {
            Some(SnmpAgent::new(Arc::clone(&performance_logger))?)
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            snmp_agent,
            performance_logger,
            security_logger,
            logging_manager,
        })
    }

    /// Start all monitoring services
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting monitoring services");

        // Start SNMP agent if enabled
        if let Some(ref snmp_agent) = self.snmp_agent {
            snmp_agent.start().await?;
            info!("SNMP agent started");
        }

        // Start metrics collection task
        self.start_metrics_collection().await?;

        // Start log cleanup task
        self.start_log_cleanup().await?;

        info!("All monitoring services started successfully");
        Ok(())
    }

    /// Start metrics collection background task
    async fn start_metrics_collection(&self) -> Result<(), MonitoringError> {
        let config = self.config.read().await.clone();
        let performance_logger = Arc::clone(&self.performance_logger);
        let logging_manager = Arc::clone(&self.logging_manager);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.metrics_update_interval_seconds));

            loop {
                interval.tick().await;

                // Generate performance report
                let report = performance_logger.generate_performance_report();

                // Log performance metrics
                info!(
                    uptime_seconds = report.uptime.as_secs(),
                    active_connections = report.connection_health.active_connections,
                    active_sessions = report.session_stats.active_sessions.as_u32(),
                    port_hop_success_rate = (report.port_hopping.successful_hops as f64
                        / report.port_hopping.total_hops.max(1) as f64)
                        * 100.0,
                    "System performance metrics"
                );

                // Clean up expired correlations
                logging_manager.cleanup_correlations();
            }
        });

        Ok(())
    }

    /// Start log cleanup background task
    async fn start_log_cleanup(&self) -> Result<(), MonitoringError> {
        let logging_manager = Arc::clone(&self.logging_manager);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour

            loop {
                interval.tick().await;
                logging_manager.cleanup_correlations();
            }
        });

        Ok(())
    }

    /// Get monitoring statistics
    pub async fn get_monitoring_statistics(&self) -> MonitoringStatistics {
        let logging_stats = self.logging_manager.get_statistics();
        let performance_report = self.performance_logger.generate_performance_report();

        let snmp_stats = if let Some(ref snmp_agent) = self.snmp_agent {
            Some(snmp_agent.get_agent_statistics().await)
        } else {
            None
        };

        MonitoringStatistics {
            logging_stats,
            performance_report,
            snmp_stats,
            security_events_count: self.security_logger.get_event_count(),
        }
    }

    /// Update monitoring configuration
    pub async fn update_config(
        &self,
        new_config: MonitoringConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        *self.config.write().await = new_config;
        info!("Monitoring configuration updated");
        Ok(())
    }

    /// Get current monitoring configuration
    pub async fn get_config(&self) -> MonitoringConfig {
        self.config.read().await.clone()
    }

    /// Handle SNMP request (if SNMP is enabled)
    pub async fn handle_snmp_get(&self, oid: &str) -> Result<snmp::SnmpValue, String> {
        if let Some(ref snmp_agent) = self.snmp_agent {
            snmp_agent.handle_get_request(oid).await
        } else {
            Err("Snmp agent not enabled".to_string())
        }
    }

    /// Handle SNMP GETNEXT request
    pub async fn handle_snmp_getnext(
        &self,
        oid: &str,
    ) -> Result<(String, snmp::SnmpValue), String> {
        if let Some(ref snmp_agent) = self.snmp_agent {
            snmp_agent.handle_getnext_request(oid).await
        } else {
            Err("Snmp agent not enabled".to_string())
        }
    }

    /// Handle SNMP GETBULK request
    pub async fn handle_snmp_getbulk(
        &self,
        oid: &str,
        max_repetitions: usize,
    ) -> Result<Vec<(String, snmp::SnmpValue)>, String> {
        if let Some(ref snmp_agent) = self.snmp_agent {
            snmp_agent
                .handle_getbulk_request(oid, max_repetitions)
                .await
        } else {
            Err("Snmp agent not enabled".to_string())
        }
    }
}

/// Comprehensive monitoring statistics
#[derive(Debug, Serialize)]
pub struct MonitoringStatistics {
    pub logging_stats: crate::logging::LoggingStatistics,
    pub performance_report: crate::logging::performance::PerformanceReport,
    pub snmp_stats: Option<snmp::SnmpAgentStatistics>,
    pub security_events_count: u64,
}
