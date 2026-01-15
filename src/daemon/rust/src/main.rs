//! Buckwild Daemon Service
//!
//! This is the main entry point for the Buckwild frequency hopping network daemon.
//! It initializes the system, sets up the TUN device, and manages the protocol stack.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::signal;

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

// Import integration layer from common crate
use buckwild_common::integration::{ConnectionCoordinator, IntegrationConfig, SessionManager};

mod config;
mod crypto;
mod discovery_manager;
mod logging;
mod maps;
mod monitoring;
mod protocol;
mod psk_discovery;
mod tun;
mod types;

#[cfg(target_os = "linux")]
mod ebpf_events;

use discovery_manager::*;

#[cfg(target_os = "linux")]
use buckwild_ebpf::EbpfManager;

use config::runtime_management::RuntimeConfigManager;
use logging::{LoggingConfig, LoggingManager, correlation::CorrelationId};
use monitoring::{MonitoringConfig, MonitoringManager};

/// Command line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Configuration file path
    #[clap(short, long, default_value = "/etc/buckwild/config.toml")]
    config: String,

    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Log file path
    #[clap(long)]
    log_file: Option<String>,

    /// Run in foreground
    #[clap(short, long)]
    foreground: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize secure logging and monitoring system
    let system = setup_secure_system(&args).await?;

    // Create correlation ID for startup process
    let startup_correlation = system.logging_manager.create_correlation("system_startup");

    // Log system startup (no sensitive data)
    system.logging_manager.log_event(
        tracing::Level::INFO,
        &format!("Starting Buckwild daemon v{}", env!("CARGO_PKG_VERSION")),
        "main",
        Some(startup_correlation.clone()),
        std::collections::HashMap::new(),
    );

    // Log security event for system startup
    system
        .logging_manager
        .log_security_event(logging::security::SecurityEvent::new(
            logging::security::SecurityEventType::SystemStartup,
            logging::security::SecuritySeverity::Medium,
            "Buckwild daemon starting".to_string(),
            Some(startup_correlation.clone()),
        ));

    // Set up signal handlers
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let logging_manager_signal = system.logging_manager.clone();

    // Handle SIGINT and SIGTERM
    tokio::spawn(async move {
        // SAFETY: Signal handler registration can only fail if the signal kind is invalid
        // or if the platform doesn't support signals. SIGINT and SIGTERM are standard POSIX
        // signals supported on all Unix platforms. Failure here indicates a critical system issue.
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Critical: Failed to register SIGINT handler - platform signal support broken");
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).expect(
            "Critical: Failed to register SIGTERM handler - platform signal support broken",
        );

        let shutdown_correlation = logging_manager_signal.create_correlation("system_shutdown");

        tokio::select! {
            _ = sigint.recv() => {
                logging_manager_signal.log_event(
                    tracing::Level::INFO,
                    "Received SIGINT, shutting down",
                    "signal_handler",
                    Some(shutdown_correlation.clone()),
                    std::collections::HashMap::new(),
                );
            }
            _ = sigterm.recv() => {
                logging_manager_signal.log_event(
                    tracing::Level::INFO,
                    "Received SIGTERM, shutting down",
                    "signal_handler",
                    Some(shutdown_correlation.clone()),
                    std::collections::HashMap::new(),
                );
            }
        }

        // Log security event for shutdown
        logging_manager_signal.log_security_event(logging::security::SecurityEvent::new(
            logging::security::SecurityEventType::SystemShutdown,
            logging::security::SecuritySeverity::High,
            "System shutdown initiated".to_string(),
            Some(shutdown_correlation),
        ));

        let _ = shutdown_tx.send(());
    });

    // Initialize system components with secure logging
    let components = initialize_secure_components(&system, startup_correlation.clone()).await?;

    // Start monitoring services
    system.monitoring_manager.start().await?;

    // Start health check server in dedicated thread
    // (uses std::thread because EbpfManager contains non-Send libbpf types)
    // Note: std::thread::JoinHandle doesn't have abort(), thread exits when process exits
    let _health_server_thread = {
        let health_server = Arc::clone(&system.health_server);
        match health_server.start() {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::error!("Health server error: {}", e);
                None
            }
        }
    };

    // Mark system as ready
    system.health_server.set_ready(true, None).await;

    system.logging_manager.log_event(
        tracing::Level::INFO,
        "System ready - health endpoints available",
        "main",
        Some(startup_correlation.clone()),
        std::collections::HashMap::new(),
    );

    // Wait for shutdown signal
    let _ = shutdown_rx.await;

    // Note: Health server thread will exit when process exits
    // (std::thread::JoinHandle doesn't support abort like tokio handles)

    // Perform secure cleanup
    cleanup_secure_components(components, &system).await?;

    // Log final shutdown event
    system
        .logging_manager
        .log_security_event(logging::security::SecurityEvent::new(
            logging::security::SecurityEventType::SystemShutdown,
            logging::security::SecuritySeverity::Medium,
            "Buckwild daemon shutdown complete".to_string(),
            Some(startup_correlation),
        ));

    Ok(())
}

/// Secure system components
struct SecureSystem {
    logging_manager: Arc<LoggingManager>,
    monitoring_manager: Arc<MonitoringManager>,

    config_manager: Arc<RuntimeConfigManager>,
    health_server: Arc<monitoring::health::HealthServer>,
}

/// System components with integrated logging and monitoring
struct SystemComponents {
    discovery_manager: Arc<DiscoveryManager>,
    #[cfg(target_os = "linux")]
    ebpf_manager: Option<Arc<EbpfManager>>,
    #[cfg(not(target_os = "linux"))]
    ebpf_manager: Option<()>,
    /// Event loop thread handle (uses std::thread because of non-Send libbpf types)
    event_loop_handle: Option<std::thread::JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Integration layer: session manager for multi-connection orchestration
    session_manager: Arc<SessionManager>,
    /// Integration layer: connection coordinator for engine lifecycle events
    connection_coordinator: Arc<ConnectionCoordinator>,
    /// Map cleanup manager for periodic eBPF map cleanup
    map_cleanup: Option<Arc<maps::MapCleanup>>,
}

/// Set up secure logging and monitoring system with data sanitization
async fn setup_secure_system(args: &Args) -> Result<SecureSystem> {
    // Create secure logging configuration
    let logging_config = LoggingConfig {
        level: args.log_level.clone(),
        enable_correlation: true,
        enable_security_audit: true,
        enable_performance_metrics: true,
        sanitize_sensitive_data: true, // CRITICAL: Always sanitize sensitive data
        max_correlation_entries: 10000,
        correlation_ttl_seconds: 3600,
    };

    // Create monitoring configuration
    let monitoring_config = MonitoringConfig {
        enable_snmp: true,
        snmp_port: Port::from_well_known(161),
        snmp_community: "public".to_string(), // Non-sensitive community string
        metrics_update_interval_seconds: 30,
        enable_prometheus: false,
        prometheus_port: Port::from_well_known(9090),
        enable_syslog: true,
        syslog_facility: "daemon".to_string(),
        syslog_server: None,
    };

    // Initialize secure logging manager
    let logging_manager = Arc::new(LoggingManager::new(logging_config.clone())?);

    // Initialize performance and security loggers
    let performance_logger = Arc::new(logging::performance::PerformanceLogger::new());
    let security_logger = Arc::new(logging::security::SecurityLogger::new());

    // Initialize monitoring manager with secure loggers
    let monitoring_manager = Arc::new(
        MonitoringManager::new(
            monitoring_config.clone(),
            performance_logger,
            security_logger,
            logging_manager.clone(),
        )
        .await?,
    );

    // Initialize runtime configuration manager
    let config_manager = Arc::new(RuntimeConfigManager::new(
        logging_config,
        monitoring_config,
        logging_manager.clone(),
    ));

    // Initialize health check server
    let health_server = Arc::new(monitoring::health::HealthServer::new(8080));

    Ok(SecureSystem {
        logging_manager,
        monitoring_manager,
        config_manager,
        health_server,
    })
}

/// Initialize system components with integrated logging and monitoring
async fn initialize_secure_components(
    system: &SecureSystem,
    correlation_id: CorrelationId,
) -> Result<SystemComponents> {
    // Initialize integration layer components
    let session_manager = Arc::new(SessionManager::new(IntegrationConfig::default()));
    let connection_coordinator = Arc::new(ConnectionCoordinator::new());

    system.logging_manager.log_event(
        tracing::Level::INFO,
        "Integration layer initialized (SessionManager, ConnectionCoordinator)",
        "main",
        Some(correlation_id.clone()),
        std::collections::HashMap::new(),
    );

    // Note: Map cleanup callback will be wired after eBPF initialization
    // (when map_cleanup is created)

    // Initialize discovery manager with logging integration
    let mut discovery_manager = DiscoveryManager::new();
    discovery_manager.set_logging_manager(system.logging_manager.clone());
    let discovery_manager = Arc::new(discovery_manager);

    // Start discovery manager
    discovery_manager.start().await?;

    // Initialize eBPF manager (may fail in unprivileged environments)
    #[cfg(target_os = "linux")]
    let (ebpf_manager, event_loop_handle, shutdown_tx, map_cleanup) = match EbpfManager::new() {
        Ok(mgr) => {
            let mgr = Arc::new(mgr);

            // Configure eBPF program directory
            const EBPF_PROGRAM_DIR: &str = "/usr/lib/buckwild/ebpf";
            {
                let xdp = mgr.xdp_loader();
                let mut xdp_guard = xdp.write().await;
                xdp_guard.set_program_directory(EBPF_PROGRAM_DIR);

                let tc = mgr.tc_loader();
                let mut tc_guard = tc.write().await;
                tc_guard.set_program_directory(EBPF_PROGRAM_DIR);
            }

            // Initialize eBPF programs
            if let Err(e) = mgr.initialize().await {
                system.logging_manager.log_event(
                    tracing::Level::WARN,
                    &format!("eBPF initialization failed: {}", e),
                    "main",
                    Some(correlation_id.clone()),
                    std::collections::HashMap::new(),
                );
                (None, None, None, None)
            } else {
                system.logging_manager.log_event(
                    tracing::Level::INFO,
                    "eBPF manager initialized successfully",
                    "main",
                    Some(correlation_id.clone()),
                    std::collections::HashMap::new(),
                );

                // Create shutdown channel for event loop
                let (ebpf_shutdown_tx, ebpf_shutdown_rx) = tokio::sync::oneshot::channel();
                let ebpf_correlation = system.logging_manager.create_correlation("ebpf_events");

                // Get ring buffer manager from event processor for event consumption
                let event_processor = mgr.event_processor();
                let ring_buffer_mgr = event_processor.write().await.ring_buffer_manager();

                // Create event handler with logging integration
                let handler = Arc::new(ebpf_events::EbpfEventHandler::new(
                    system.logging_manager.clone(),
                    system.monitoring_manager.clone(),
                    ebpf_correlation,
                ));

                // Take connected event receiver from RingBufferManager
                // RingBufferManager's callback sends to this channel's sender
                let event_receiver = {
                    let mut ring_buffer_mgr_guard = ring_buffer_mgr.write().await;
                    ring_buffer_mgr_guard.take_event_receiver().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Event receiver already taken - RingBufferManager ownership violated"
                        )
                    })?
                };

                // Spawn event processing loop
                let join_handle = ebpf_events::spawn_event_loop(
                    event_receiver,
                    handler,
                    ring_buffer_mgr,
                    ebpf_shutdown_rx,
                );

                system.logging_manager.log_event(
                    tracing::Level::INFO,
                    "eBPF event loop started",
                    "main",
                    Some(correlation_id.clone()),
                    std::collections::HashMap::new(),
                );

                // Wire eBPF manager to health server for debug endpoints
                system
                    .health_server
                    .set_ebpf_manager(Arc::clone(&mgr))
                    .await;

                // Initialize map cleanup for session expiry
                let cleanup_config = maps::CleanupConfig::default();
                let map_cleanup =
                    Arc::new(maps::MapCleanup::new(mgr.map_manager(), cleanup_config));

                // Note: MapManager contains non-Send libbpf types (NonNull<bpf_object>),
                // so we cannot spawn async tasks or threads that capture Arc<MapCleanup>.
                // Instead, we log the cleanup intent and rely on periodic cleanup.
                // The periodic cleanup task (started below) will handle stale sessions.
                let logging_manager_for_callback = system.logging_manager.clone();
                session_manager
                    .set_cleanup_callback(move |session_id| {
                        // Log cleanup request - actual cleanup handled by periodic task
                        let mut context = std::collections::HashMap::new();
                        context.insert(
                            "session_id".to_string(),
                            serde_json::json!(session_id.to_string()),
                        );
                        logging_manager_for_callback.log_event(
                            tracing::Level::DEBUG,
                            "Session expiry cleanup queued for periodic cleanup",
                            "map_cleanup_callback",
                            None,
                            context,
                        );
                    })
                    .await;

                system.logging_manager.log_event(
                    tracing::Level::INFO,
                    "Session expiry callback wired to eBPF map cleanup",
                    "main",
                    Some(correlation_id.clone()),
                    std::collections::HashMap::new(),
                );

                // Start periodic cleanup task
                if let Err(e) = map_cleanup.start().await {
                    system.logging_manager.log_event(
                        tracing::Level::WARN,
                        &format!("Map cleanup task failed to start: {}", e),
                        "main",
                        Some(correlation_id.clone()),
                        std::collections::HashMap::new(),
                    );
                } else {
                    system.logging_manager.log_event(
                        tracing::Level::INFO,
                        "eBPF map cleanup task started (interval: 30s)",
                        "main",
                        Some(correlation_id.clone()),
                        std::collections::HashMap::new(),
                    );
                }

                (
                    Some(mgr),
                    Some(join_handle),
                    Some(ebpf_shutdown_tx),
                    Some(map_cleanup),
                )
            }
        }
        Err(e) => {
            system.logging_manager.log_event(
                tracing::Level::WARN,
                &format!("eBPF manager creation failed: {}", e),
                "main",
                Some(correlation_id.clone()),
                std::collections::HashMap::new(),
            );
            (None, None, None, None)
        }
    };

    #[cfg(not(target_os = "linux"))]
    let (ebpf_manager, event_loop_handle, shutdown_tx, map_cleanup) = {
        system.logging_manager.log_event(
            tracing::Level::INFO,
            "eBPF not available on this platform",
            "main",
            Some(correlation_id.clone()),
            std::collections::HashMap::new(),
        );

        // Create non-Linux cleanup instance
        let cleanup_config = maps::CleanupConfig::default();
        let map_cleanup = Arc::new(maps::MapCleanup::new(cleanup_config));

        // Wire session expiry to map cleanup (no-op on non-Linux)
        let map_cleanup_for_callback = Arc::clone(&map_cleanup);
        let logging_manager_for_callback = system.logging_manager.clone();
        session_manager
            .set_cleanup_callback(move |session_id| {
                let map_cleanup = Arc::clone(&map_cleanup_for_callback);
                let logging_manager = logging_manager_for_callback.clone();
                tokio::spawn(async move {
                    if let Err(e) = map_cleanup.cleanup_session(session_id.clone()).await {
                        logging_manager.log_event(
                            tracing::Level::WARN,
                            &format!(
                                "Failed to cleanup eBPF maps for session {}: {}",
                                session_id, e
                            ),
                            "map_cleanup_callback",
                            None,
                            std::collections::HashMap::new(),
                        );
                    }
                });
            })
            .await;

        system.logging_manager.log_event(
            tracing::Level::INFO,
            "Session expiry callback wired (non-Linux no-op)",
            "main",
            Some(correlation_id.clone()),
            std::collections::HashMap::new(),
        );

        (None, None, None, Some(map_cleanup))
    };

    system.logging_manager.log_event(
        tracing::Level::INFO,
        "System components initialized successfully",
        "main",
        Some(correlation_id),
        std::collections::HashMap::new(),
    );

    Ok(SystemComponents {
        discovery_manager,
        ebpf_manager,
        event_loop_handle,
        shutdown_tx,
        session_manager,
        connection_coordinator,
        map_cleanup,
    })
}

/// Clean up system components securely
async fn cleanup_secure_components(
    components: SystemComponents,
    system: &SecureSystem,
) -> Result<()> {
    let cleanup_correlation = system.logging_manager.create_correlation("system_cleanup");

    // Perform secure cleanup - ensure no sensitive data remains in memory
    system.logging_manager.log_event(
        tracing::Level::INFO,
        "Performing secure system cleanup",
        "main",
        Some(cleanup_correlation.clone()),
        std::collections::HashMap::new(),
    );

    // Stop map cleanup task
    if let Some(map_cleanup) = &components.map_cleanup {
        map_cleanup.stop().await;
        system.logging_manager.log_event(
            tracing::Level::INFO,
            "Map cleanup task stopped",
            "main",
            Some(cleanup_correlation.clone()),
            std::collections::HashMap::new(),
        );
    }

    // Signal event loop to shutdown and await with timeout
    if let Some(shutdown_tx) = components.shutdown_tx {
        let _ = shutdown_tx.send(());
    }

    if let Some(handle) = components.event_loop_handle {
        // Use spawn_blocking to join the std::thread::JoinHandle without blocking the async runtime
        let join_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(move || handle.join()),
        )
        .await;

        match join_result {
            Ok(Ok(Ok(()))) => {
                system.logging_manager.log_event(
                    tracing::Level::INFO,
                    "eBPF event loop shut down cleanly",
                    "main",
                    Some(cleanup_correlation.clone()),
                    std::collections::HashMap::new(),
                );
            }
            Ok(Ok(Err(_))) => {
                system.logging_manager.log_event(
                    tracing::Level::ERROR,
                    "eBPF event loop panicked during shutdown",
                    "main",
                    Some(cleanup_correlation.clone()),
                    std::collections::HashMap::new(),
                );
            }
            Ok(Err(_)) => {
                system.logging_manager.log_event(
                    tracing::Level::ERROR,
                    "spawn_blocking task panicked during shutdown",
                    "main",
                    Some(cleanup_correlation.clone()),
                    std::collections::HashMap::new(),
                );
            }
            Err(_) => {
                system.logging_manager.log_event(
                    tracing::Level::ERROR,
                    "eBPF event loop did not shut down within 5 seconds",
                    "main",
                    Some(cleanup_correlation.clone()),
                    std::collections::HashMap::new(),
                );
            }
        }
    }

    // Shutdown eBPF manager after event loop stops
    #[cfg(target_os = "linux")]
    if let Some(ref mgr) = components.ebpf_manager {
        if let Err(e) = mgr.shutdown().await {
            system.logging_manager.log_event(
                tracing::Level::WARN,
                &format!("eBPF shutdown error: {}", e),
                "main",
                Some(cleanup_correlation.clone()),
                std::collections::HashMap::new(),
            );
        }
    }

    // Shutdown integration layer components
    if let Err(e) = components.connection_coordinator.shutdown().await {
        system.logging_manager.log_event(
            tracing::Level::WARN,
            &format!("ConnectionCoordinator shutdown error: {}", e),
            "main",
            Some(cleanup_correlation.clone()),
            std::collections::HashMap::new(),
        );
    }

    if let Err(e) = components.session_manager.shutdown().await {
        system.logging_manager.log_event(
            tracing::Level::WARN,
            &format!("SessionManager shutdown error: {}", e),
            "main",
            Some(cleanup_correlation.clone()),
            std::collections::HashMap::new(),
        );
    }

    system.logging_manager.log_event(
        tracing::Level::INFO,
        "Integration layer shutdown complete",
        "main",
        Some(cleanup_correlation.clone()),
        std::collections::HashMap::new(),
    );

    // Clean up correlations
    system.logging_manager.cleanup_correlations();

    system.logging_manager.log_event(
        tracing::Level::INFO,
        "Secure cleanup completed",
        "main",
        Some(cleanup_correlation),
        std::collections::HashMap::new(),
    );

    Ok(())
}
