//! Buckwild CLI Utilities
//!
//! This is the main entry point for the Buckwild CLI utilities.
//! It provides command-line tools for managing and monitoring the
//! Buckwild frequency hopping network.

use std::path::PathBuf;

use buckwild_common::prelude::*;
// Import ALL types from the authoritative consolidated types module
#[cfg(target_os = "linux")]
use anyhow::Context;
use buckwild_common::protocol::types::*;
#[cfg(target_os = "linux")]
use buckwild_ebpf::EbpfManager;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

// Type alias for convenience
type Result<T> = std::result::Result<T, buckwild_common::error::BuckwildError>;

/// Command line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Subcommand
    #[clap(subcommand)]
    command: Command,
}

/// Subcommands
#[derive(Subcommand, Debug)]
enum Command {
    /// Manage PSK files
    #[clap(subcommand)]
    Psk(PskCommand),

    /// Manage hosts
    #[clap(subcommand)]
    Host(HostCommand),

    /// Show status information
    Status {
        /// Show detailed information
        #[clap(short, long)]
        detailed: bool,
    },

    /// Manage daemon service
    #[clap(subcommand)]
    Service(ServiceCommand),

    /// Manage eBPF programs
    #[clap(subcommand)]
    Ebpf(EbpfCommand),
}

/// PSK management commands
#[derive(Subcommand, Debug)]
enum PskCommand {
    /// Generate a new PSK
    Generate {
        /// Output file path
        #[clap(short, long)]
        output: PathBuf,

        /// Key size in bits
        #[clap(short, long, default_value = "256")]
        size: usize, // Note: Keep.as_raw() as usize for CLI parsing, convert to proper type internally
    },

    /// List available PSKs
    List {
        /// PSK directory
        #[clap(short, long, default_value = "/etc/buckwild/psk")]
        directory: PathBuf,
    },

    /// Calculate PSK fingerprint
    Fingerprint {
        /// PSK file path
        #[clap(short, long)]
        file: PathBuf,
    },
}

/// Host management commands
#[derive(Subcommand, Debug)]
enum HostCommand {
    /// Add a new host
    Add {
        /// Host IP address
        #[clap(short, long)]
        ip: String,

        /// PSK fingerprint
        #[clap(short, long)]
        fingerprint: String,

        /// Host description
        #[clap(short, long)]
        description: Option<String>,
    },

    /// Remove a host
    Remove {
        /// Host IP address
        #[clap(short, long)]
        ip: String,
    },

    /// List configured hosts
    List,
}

// Host configuration types (CLI-specific)

/// Host configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Host {
    ip: String,
    psk_fingerprint: String,
    description: String,
}

/// Host management settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    #[serde(default)]
    default_psk_fingerprint: String,
    #[serde(default = "default_tun_device")]
    tun_device: String,
    #[serde(default = "default_update_interval")]
    update_interval_ms: u64,
}

fn default_tun_device() -> String {
    "tun0".to_string()
}

fn default_update_interval() -> u64 {
    500
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_psk_fingerprint: String::new(),
            tun_device: default_tun_device(),
            update_interval_ms: default_update_interval(),
        }
    }
}

/// Host configuration file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HostConfig {
    #[serde(default)]
    settings: Settings,
    #[serde(default)]
    hosts: Vec<Host>,
}

/// Service management commands
#[derive(Subcommand, Debug)]
enum ServiceCommand {
    /// Start the daemon service
    Start,

    /// Stop the daemon service
    Stop,

    /// Restart the daemon service
    Restart,

    /// Show service status
    Status,
}

/// eBPF management commands
#[derive(Subcommand, Debug)]
enum EbpfCommand {
    /// Load eBPF program on network interface
    Load {
        /// Network interface name
        #[clap(short, long)]
        interface: String,
    },

    /// Unload eBPF program from network interface
    Unload {
        /// Network interface name
        #[clap(short, long)]
        interface: String,
    },

    /// Show eBPF program status
    Status {
        /// Optional interface name to check
        #[clap(help = "Optional interface name to check")]
        interface: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    setup_logging(&args.log_level)?;

    // Execute command
    match &args.command {
        Command::Psk(cmd) => handle_psk_command(cmd).await?,
        Command::Host(cmd) => handle_host_command(cmd).await?,
        Command::Status { detailed } => handle_status_command(*detailed).await?,
        Command::Service(cmd) => handle_service_command(cmd).await?,
        Command::Ebpf(cmd) => handle_ebpf_command(cmd).await?,
    }

    Ok(())
}

/// Handle PSK management commands
async fn handle_psk_command(cmd: &PskCommand) -> Result<()> {
    match cmd {
        PskCommand::Generate { output, size } => {
            info!("Generating PSK with size {} bits", size);

            // Generate cryptographically secure random bytes
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();

            let key_size = MemorySize::new((size / 8) as u64);
            let mut psk_data = vec![0u8; key_size.as_usize()];

            rng.fill(&mut psk_data).map_err(|_| {
                buckwild_common::error::BuckwildError::invalid_input(
                    "Failed to generate random PSK".to_string(),
                )
            })?;

            // Write PSK to file with secure permissions (atomic on Unix)
            #[cfg(unix)]
            {
                use tokio::fs::OpenOptions;
                use tokio::io::AsyncWriteExt;

                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600) // Owner read/write only
                    .open(output)
                    .await
                    .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

                file.write_all(&psk_data)
                    .await
                    .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;
            }

            // On non-Unix platforms, write normally (best effort)
            #[cfg(not(unix))]
            {
                use tokio::fs;
                fs::write(output, &psk_data)
                    .await
                    .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;
            }

            info!(
                "PSK generated and saved to {} ({} bytes)",
                output.display(),
                key_size.as_usize()
            );
        }
        PskCommand::List { directory } => {
            info!("Listing PSKs in {}", directory.display());

            use tokio::fs;
            let mut entries = fs::read_dir(directory)
                .await
                .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

            let mut psk_files = Vec::new();

            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?
            {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "psk") {
                    let metadata = entry.metadata().await.map_err(|e| {
                        buckwild_common::error::BuckwildError::io_error(e.to_string())
                    })?;

                    let file_size = MemorySize::new(metadata.len());
                    psk_files.push((path, file_size));
                }
            }

            if psk_files.is_empty() {
                info!("No PSK files found in {}", directory.display());
            } else {
                let file_count = Counter::new(psk_files.len() as u64);
                info!("Found {} PSK files:", file_count.as_raw());
                for (path, size) in psk_files {
                    let fingerprint = calculate_psk_fingerprint(&path).await?;
                    let filename = path
                        .file_name()
                        .ok_or_else(|| {
                            buckwild_common::error::BuckwildError::invalid_input(format!(
                                "Invalid path: no filename component in '{}'",
                                path.display()
                            ))
                        })?
                        .to_string_lossy();
                    info!(
                        "  {} ({} bytes) - fingerprint: {}",
                        filename,
                        size.as_usize(),
                        fingerprint
                    );
                }
            }
        }
        PskCommand::Fingerprint { file } => {
            info!("Calculating fingerprint for {}", file.display());

            let fingerprint = calculate_psk_fingerprint(file).await?;
            info!("Fingerprint: {}", fingerprint);
        }
    }

    Ok(())
}

/// Calculate PSK fingerprint using SHA-256
async fn calculate_psk_fingerprint(file: &PathBuf) -> Result<String> {
    use ring::digest::{SHA256, digest};
    use tokio::fs;

    let psk_data = fs::read(file)
        .await
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    let hash = digest(&SHA256, &psk_data);
    let fingerprint = hex::encode(hash.as_ref());

    Ok(fingerprint)
}

/// Handle host management commands
async fn handle_host_command(cmd: &HostCommand) -> Result<()> {
    const HOSTS_CONFIG_PATH: &str = "/etc/buckwild/hosts.toml";

    match cmd {
        HostCommand::Add {
            ip,
            fingerprint,
            description,
        } => {
            info!("Adding host {} with fingerprint {}", ip, fingerprint);
            if let Some(desc) = description {
                info!("Description: {}", desc);
            }

            // Validate IP address
            use std::net::IpAddr;
            let _parsed_ip: IpAddr = ip.parse().map_err(|_| {
                buckwild_common::error::BuckwildError::invalid_input(format!(
                    "Invalid IP address: {}",
                    ip
                ))
            })?;

            // Validate fingerprint format (should be hex)
            let fingerprint_length = MemorySize::new(fingerprint.len() as u64);
            if fingerprint_length.as_usize() != 64
                || !fingerprint.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(buckwild_common::error::BuckwildError::invalid_input(
                    "Fingerprint must be 64 hex characters".to_string(),
                ));
            }

            // Load existing configuration
            let mut config = load_hosts_config(HOSTS_CONFIG_PATH).await?;

            // Check if host already exists
            if config.hosts.iter().any(|h| h.ip == *ip) {
                return Err(buckwild_common::error::BuckwildError::invalid_input(
                    format!("Host {} already exists", ip),
                ));
            }

            // Add new host
            config.hosts.push(Host {
                ip: ip.clone(),
                psk_fingerprint: fingerprint.clone(),
                description: description.clone().unwrap_or_default(),
            });

            // Save configuration
            save_hosts_config(HOSTS_CONFIG_PATH, &config).await?;

            info!("Host {} added successfully", ip);
        }
        HostCommand::Remove { ip } => {
            info!("Removing host {}", ip);

            // Load existing configuration
            let mut config = load_hosts_config(HOSTS_CONFIG_PATH).await?;

            // Find and remove host
            let initial_count = Counter::new(config.hosts.len() as u64);
            config.hosts.retain(|h| h.ip != *ip);
            let final_count = Counter::new(config.hosts.len() as u64);

            if final_count.as_raw() == initial_count.as_raw() {
                return Err(buckwild_common::error::BuckwildError::invalid_input(
                    format!("Host {} not found", ip),
                ));
            }

            // Save configuration
            save_hosts_config(HOSTS_CONFIG_PATH, &config).await?;

            info!("Host {} removed successfully", ip);
        }
        HostCommand::List => {
            info!("Listing configured hosts");

            let config = load_hosts_config(HOSTS_CONFIG_PATH).await?;

            if config.hosts.is_empty() {
                info!("No hosts configured");
            } else {
                let host_count = Counter::new(config.hosts.len() as u64);
                info!("Configured hosts ({}):", host_count.as_raw());
                for host in &config.hosts {
                    let desc = if host.description.is_empty() {
                        "No description"
                    } else {
                        &host.description
                    };
                    info!("  {} - {} ({})", host.ip, host.psk_fingerprint, desc);
                }
            }
        }
    }

    Ok(())
}

/// Load hosts configuration from file
async fn load_hosts_config(path: &str) -> Result<HostConfig> {
    use tokio::fs;

    match fs::read_to_string(path).await {
        Ok(content) => toml::from_str(&content).map_err(|e| {
            buckwild_common::error::BuckwildError::configuration_error(format!(
                "Failed to parse hosts config: {}",
                e
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Create default configuration
            Ok(HostConfig {
                settings: Settings {
                    default_psk_fingerprint: String::new(),
                    tun_device: "tun0".to_string(),
                    update_interval_ms: Interval::from_millis(500).as_millis(),
                },
                hosts: Vec::new(),
            })
        }
        Err(e) => Err(buckwild_common::error::BuckwildError::io_error(
            e.to_string(),
        )),
    }
}

/// Save hosts configuration to file
async fn save_hosts_config(path: &str, config: &HostConfig) -> Result<()> {
    use tokio::fs;

    let content = toml::to_string_pretty(config).map_err(|e| {
        buckwild_common::error::BuckwildError::configuration_error(format!(
            "Failed to serialize config: {}",
            e
        ))
    })?;

    // Create directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;
    }

    fs::write(path, content)
        .await
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    Ok(())
}

/// Handle status command
async fn handle_status_command(detailed: bool) -> Result<()> {
    info!("Showing status information");

    // Check daemon status
    let daemon_status = check_daemon_status().await?;
    info!(
        "Daemon status: {}",
        if daemon_status { "Running" } else { "Stopped" }
    );

    if detailed && daemon_status {
        // Get detailed status from daemon
        match get_detailed_status().await {
            Ok(status) => {
                info!("Detailed status:");
                info!("  Active sessions: {}", status.active_sessions.as_u32());
                info!("  Total packets sent: {}", status.packets_sent.as_raw());
                info!(
                    "  Total packets received: {}",
                    status.packets_received.as_raw()
                );
                info!("  Current port: {}", status.current_port.as_u16());
                info!(
                    "  Last port hop: {} seconds ago",
                    status.last_port_hop_seconds.as_secs()
                );
                info!("  PSK count: {}", status.psk_count.as_raw());
                info!("  Configured hosts: {}", status.configured_hosts.as_raw());

                if !status.recent_errors.is_empty() {
                    info!("  Recent errors:");
                    for error in &status.recent_errors {
                        info!("    {}", error);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get detailed status: {}", e);
            }
        }
    }

    // Check configuration files
    let config_status = check_configuration_status().await?;
    info!("Configuration status:");
    info!(
        "  Hosts config: {}",
        if config_status.hosts_config_exists {
            "Present"
        } else {
            "Missing"
        }
    );
    info!(
        "  PSK directory: {}",
        if config_status.psk_directory_exists {
            "Present"
        } else {
            "Missing"
        }
    );
    info!("  PSK count: {}", config_status.psk_count.as_raw());

    Ok(())
}

#[derive(Debug)]
struct DetailedStatus {
    active_sessions: SessionCount,
    packets_sent: Counter,
    packets_received: Counter,
    current_port: Port,
    last_port_hop_seconds: ProtocolDuration,
    psk_count: Counter,
    configured_hosts: Counter,
    recent_errors: Vec<String>,
}

#[derive(Debug)]
struct ConfigurationStatus {
    hosts_config_exists: bool,
    psk_directory_exists: bool,
    psk_count: Counter,
}

/// Check if daemon is running
async fn check_daemon_status() -> Result<bool> {
    // Check if daemon process is running by looking for PID file or process
    use tokio::fs;

    const PID_FILE: &str = "/var/run/buckwild.pid";

    match fs::read_to_string(PID_FILE).await {
        Ok(pid_str) => {
            if let Ok(pid_raw) = pid_str.trim().parse::<u32>() {
                let process_id = ProcessId::new(pid_raw);
                // Check if process is actually running
                check_process_running(process_id).await
            } else {
                Ok(false)
            }
        }
        Err(_) => Ok(false),
    }
}

/// Check if process is running
async fn check_process_running(pid: ProcessId) -> Result<bool> {
    use tokio::process::Command;

    let output = Command::new("kill")
        .arg("-0")
        .arg(pid.as_u32().to_string())
        .output()
        .await
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    Ok(output.status.success())
}

/// Get detailed status from daemon
async fn get_detailed_status() -> Result<DetailedStatus> {
    use http_body_util::BodyExt;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    const HEALTH_ENDPOINT: &str = "http://127.0.0.1:8080/health/detail";
    const REQUEST_TIMEOUT_MS: u64 = 5000;

    let client = Client::builder(TokioExecutor::new()).build_http();

    let timeout_duration = ProtocolDuration::from_millis(REQUEST_TIMEOUT_MS);
    let uri: hyper::Uri = HEALTH_ENDPOINT.parse().map_err(|e| {
        buckwild_common::error::BuckwildError::invalid_input(format!(
            "Invalid health endpoint URL: {}",
            e
        ))
    })?;

    let request = hyper::Request::builder()
        .uri(uri)
        .method(hyper::Method::GET)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| {
            buckwild_common::error::BuckwildError::io_error(format!(
                "Failed to build HTTP request: {}",
                e
            ))
        })?;

    let response = tokio::time::timeout(timeout_duration.to_std(), client.request(request))
        .await
        .map_err(|_| {
            buckwild_common::error::BuckwildError::timeout_error(
                "Daemon health endpoint request timed out",
                timeout_duration.to_std(),
            )
        })?
        .map_err(|e| {
            buckwild_common::error::BuckwildError::io_error(format!(
                "Failed to connect to daemon health endpoint: {}",
                e
            ))
        })?;

    if !response.status().is_success() {
        return Err(buckwild_common::error::BuckwildError::invalid_state(
            format!(
                "Health endpoint returned non-success status: {}",
                response.status()
            ),
        ));
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            buckwild_common::error::BuckwildError::io_error(format!(
                "Failed to read health endpoint response body: {}",
                e
            ))
        })?
        .to_bytes();

    // Parse JSON response from daemon health endpoint
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        buckwild_common::error::BuckwildError::configuration_error(format!(
            "Failed to parse health endpoint JSON: {}",
            e
        ))
    })?;

    // Extract actual values from daemon response
    // Note: Current daemon implementation only provides basic health status.
    // Session statistics (active_sessions, packets, etc.) will be added when
    // daemon exposes statistics endpoint.

    let status = json
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let subsystems_ready = json
        .get("subsystems")
        .and_then(|s| s.get("ready"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let ready_reason = json
        .get("subsystems")
        .and_then(|s| s.get("ready_reason"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Build error list from actual daemon response
    let mut errors = Vec::new();

    if !subsystems_ready {
        errors.push(ready_reason.unwrap_or_else(|| "System not ready".to_string()));
    }

    if status != "healthy" && status != "degraded" {
        errors.push(format!("Unexpected health status: {}", status));
    }

    // Extract statistics fields (will be 0 until daemon provides them)
    let active_sessions = json
        .get("active_sessions")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let packets_sent = json
        .get("packets_sent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let packets_received = json
        .get("packets_received")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let current_port = json
        .get("current_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    let last_hop_secs = json
        .get("last_port_hop_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let psk_count = json.get("psk_count").and_then(|v| v.as_u64()).unwrap_or(0);

    let configured_hosts = json
        .get("configured_hosts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Ok(DetailedStatus {
        active_sessions: SessionCount::new(active_sessions),
        packets_sent: Counter::new(packets_sent),
        packets_received: Counter::new(packets_received),
        current_port: Port::from_raw(current_port),
        last_port_hop_seconds: ProtocolDuration::from_secs(last_hop_secs),
        psk_count: Counter::new(psk_count),
        configured_hosts: Counter::new(configured_hosts),
        recent_errors: errors,
    })
}

/// Check configuration status
async fn check_configuration_status() -> Result<ConfigurationStatus> {
    use tokio::fs;

    const HOSTS_CONFIG_PATH: &str = "/etc/buckwild/hosts.toml";
    const PSK_DIRECTORY: &str = "/etc/buckwild/psk";

    let hosts_config_exists = fs::metadata(HOSTS_CONFIG_PATH).await.is_ok();
    let psk_directory_exists = fs::metadata(PSK_DIRECTORY).await.is_ok();

    let mut psk_count_value = 0u64;
    if psk_directory_exists {
        if let Ok(mut entries) = fs::read_dir(PSK_DIRECTORY).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.path().extension().is_some_and(|ext| ext == "psk") {
                    psk_count_value += 1;
                }
            }
        }
    }
    let psk_count = Counter::new(psk_count_value);

    Ok(ConfigurationStatus {
        hosts_config_exists,
        psk_directory_exists,
        psk_count,
    })
}

/// Handle service management commands
async fn handle_service_command(cmd: &ServiceCommand) -> Result<()> {
    match cmd {
        ServiceCommand::Start => {
            info!("Starting daemon service");

            // Check if already running
            if check_daemon_status().await? {
                info!("Daemon is already running");
                return Ok(());
            }

            // Start the daemon
            match start_daemon().await {
                Ok(()) => info!("Daemon started successfully"),
                Err(e) => {
                    error!("Failed to start daemon: {}", e);
                    return Err(e);
                }
            }
        }
        ServiceCommand::Stop => {
            info!("Stopping daemon service");

            // Check if running
            if !check_daemon_status().await? {
                info!("Daemon is not running");
                return Ok(());
            }

            // Stop the daemon
            match stop_daemon().await {
                Ok(()) => info!("Daemon stopped successfully"),
                Err(e) => {
                    error!("Failed to stop daemon: {}", e);
                    return Err(e);
                }
            }
        }
        ServiceCommand::Restart => {
            info!("Restarting daemon service");

            // Stop if running
            if check_daemon_status().await? {
                stop_daemon().await?;

                // Wait a moment for cleanup
                let cleanup_wait = ProtocolDuration::from_secs(1);
                tokio::time::sleep(cleanup_wait.to_std()).await;
            }

            // Start the daemon
            start_daemon().await?;
            info!("Daemon restarted successfully");
        }
        ServiceCommand::Status => {
            info!("Showing service status");

            let is_running = check_daemon_status().await?;
            if is_running {
                info!("Daemon is running");

                // Show additional status information
                if let Ok(status) = get_detailed_status().await {
                    info!("Active sessions: {}", status.active_sessions.as_u32());
                    info!("Current port: {}", status.current_port.as_u16());
                }
            } else {
                info!("Daemon is not running");
            }
        }
    }

    Ok(())
}

/// Start the daemon service
async fn start_daemon() -> Result<()> {
    use tokio::process::Command;

    const DAEMON_BINARY: &str = "/usr/bin/buckwild-daemon";
    const PID_FILE: &str = "/var/run/buckwild.pid";

    // Check if daemon binary exists
    if !std::path::Path::new(DAEMON_BINARY).exists() {
        return Err(buckwild_common::error::BuckwildError::invalid_input(
            format!("Daemon binary not found at {}", DAEMON_BINARY),
        ));
    }

    // Start daemon as background process
    let mut child = Command::new(DAEMON_BINARY)
        .arg("--daemon")
        .arg("--pid-file")
        .arg(PID_FILE)
        .spawn()
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    // Wait a moment to see if it starts successfully
    let startup_wait = ProtocolDuration::from_millis(500);
    tokio::time::sleep(startup_wait.to_std()).await;

    // Check if process is still running
    match child.try_wait() {
        Ok(Some(status)) => {
            if !status.success() {
                return Err(buckwild_common::error::BuckwildError::invalid_state(
                    format!("Daemon exited with status: {}", status),
                ));
            }
        }
        Ok(None) => {
            // Process is still running, which is good
        }
        Err(e) => {
            return Err(buckwild_common::error::BuckwildError::io_error(
                e.to_string(),
            ));
        }
    }

    Ok(())
}

/// Stop the daemon service
async fn stop_daemon() -> Result<()> {
    use tokio::fs;

    const PID_FILE: &str = "/var/run/buckwild.pid";

    // Read PID from file
    let pid_str = fs::read_to_string(PID_FILE)
        .await
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    let pid_raw: u32 = pid_str.trim().parse().map_err(|_| {
        buckwild_common::error::BuckwildError::invalid_input("Invalid PID in file".to_string())
    })?;
    let pid = ProcessId::new(pid_raw);

    // Send SIGTERM to daemon
    use tokio::process::Command;

    let output = Command::new("kill")
        .arg("-TERM")
        .arg(pid.as_u32().to_string())
        .output()
        .await
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    if !output.status.success() {
        return Err(buckwild_common::error::BuckwildError::invalid_state(
            "Failed to send SIGTERM to daemon".to_string(),
        ));
    }

    // Wait for daemon to exit gracefully
    let max_attempts = AttemptCount::new(10);
    for _attempt in 0..max_attempts.as_u32() {
        let wait_duration = ProtocolDuration::from_millis(500);
        tokio::time::sleep(wait_duration.to_std()).await;

        if !check_process_running(pid).await? {
            // Process has exited
            let _ = fs::remove_file(PID_FILE).await;
            return Ok(());
        }
    }

    // If still running, send SIGKILL
    warn!("Daemon did not exit gracefully, sending SIGKILL");

    let output = Command::new("kill")
        .arg("-KILL")
        .arg(pid.as_u32().to_string())
        .output()
        .await
        .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

    if !output.status.success() {
        return Err(buckwild_common::error::BuckwildError::invalid_state(
            "Failed to send SIGKILL to daemon".to_string(),
        ));
    }

    // Clean up PID file
    let _ = fs::remove_file(PID_FILE).await;

    Ok(())
}

/// Handle eBPF management commands
#[cfg(target_os = "linux")]
async fn handle_ebpf_command(cmd: &EbpfCommand) -> Result<()> {
    match cmd {
        EbpfCommand::Load { interface } => {
            info!("Loading eBPF programs and attaching to {}", interface);

            let manager = EbpfManager::new()
                .context("Failed to create eBPF manager")
                .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

            // Configure XDP loader with target interface
            {
                let xdp = manager.xdp_loader();
                let mut xdp_guard = xdp.write().await;
                xdp_guard.set_target_interfaces(vec![interface.clone()]);
                xdp_guard.set_program_directory("/usr/lib/buckwild/ebpf");
            }

            // Initialize loads and attaches programs
            manager
                .initialize()
                .await
                .context(format!("Failed to load/attach to interface {}", interface))
                .map_err(|e| buckwild_common::error::BuckwildError::io_error(e.to_string()))?;

            info!("eBPF programs loaded and attached to {}", interface);
            Ok(())
        }
        EbpfCommand::Unload { interface } => {
            info!("Unloading eBPF programs from {}", interface);

            // Verify interface exists before attempting detachment
            let ifindex = match nix::net::if_::if_nametoindex(interface.as_str()) {
                Ok(idx) => idx,
                Err(e) => {
                    return Err(buckwild_common::error::BuckwildError::invalid_input(
                        format!("Interface {} not found: {}", interface, e),
                    ));
                }
            };

            info!("Found interface {} with ifindex {}", interface, ifindex);

            // Detach XDP program using netlink via `ip link` command
            use tokio::process::Command;
            let output = Command::new("ip")
                .args(&["link", "set", "dev", interface, "xdp", "off"])
                .output()
                .await
                .map_err(|e| {
                    buckwild_common::error::BuckwildError::io_error(format!(
                        "Failed to execute ip command: {}",
                        e
                    ))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);

                // Device not found is a hard error
                if stderr.contains("No such device") || stderr.contains("Cannot find device") {
                    return Err(buckwild_common::error::BuckwildError::invalid_input(
                        format!("Interface {} not found", interface),
                    ));
                }

                // Any other non-success is a detachment failure
                return Err(buckwild_common::error::BuckwildError::invalid_state(
                    format!(
                        "Failed to detach XDP from {} (exit code {}): {}",
                        interface,
                        output.status.code().unwrap_or(-1),
                        stderr
                    ),
                ));
            }

            // Verify XDP was successfully detached
            let verify_output = Command::new("ip")
                .args(&["link", "show", "dev", interface])
                .output()
                .await
                .map_err(|e| {
                    buckwild_common::error::BuckwildError::io_error(format!(
                        "Failed to verify XDP detachment: {}",
                        e
                    ))
                })?;

            if !verify_output.status.success() {
                return Err(buckwild_common::error::BuckwildError::io_error(format!(
                    "Failed to verify interface {} after detachment",
                    interface
                )));
            }

            let link_info = String::from_utf8_lossy(&verify_output.stdout);

            // Check for XDP indicators in link output
            if link_info.contains("prog/xdp") {
                return Err(buckwild_common::error::BuckwildError::invalid_state(
                    format!(
                        "XDP program still attached to {} after detachment attempt",
                        interface
                    ),
                ));
            }

            info!(
                "Successfully detached and verified XDP program removal from {}",
                interface
            );
            Ok(())
        }
        EbpfCommand::Status { interface } => {
            info!("eBPF program status:");

            // Query XDP state for specific interface or show general info
            match interface {
                Some(iface) => {
                    // Check if interface exists and show ifindex
                    match nix::net::if_::if_nametoindex(iface.as_str()) {
                        Ok(ifindex) => {
                            println!("Interface: {} (ifindex={})", iface, ifindex);
                            println!("To check XDP state: ip link show {} | grep -i xdp", iface);
                        }
                        Err(_) => {
                            eprintln!("Interface {} not found", iface);
                        }
                    }
                }
                None => {
                    println!("eBPF CLI Status:");
                    println!("  CLI processes cannot query kernel XDP attachment state.");
                    println!("  Use 'ip link show' to check XDP attachment on interfaces.");
                    println!("  For daemon status, use daemon status command.");
                }
            }

            Ok(())
        }
    }
}

/// Handle eBPF management commands (non-Linux platforms)
#[cfg(not(target_os = "linux"))]
async fn handle_ebpf_command(_cmd: &EbpfCommand) -> Result<()> {
    Err(buckwild_common::error::BuckwildError::invalid_state(
        "eBPF functionality is only available on Linux".to_string(),
    ))
}

/// Set up logging
fn setup_logging(log_level: &str) -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    fmt().with_env_filter(env_filter).init();

    Ok(())
}

#[cfg(test)]
mod common_tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_psk_list_handles_invalid_paths() {
        use tempfile::TempDir;
        use tokio::fs;

        let temp_dir = TempDir::new().unwrap();
        let psk_dir = temp_dir.path();

        // Create valid PSK files
        let valid_psk = psk_dir.join("valid.psk");
        fs::write(&valid_psk, vec![0u8; 32]).await.unwrap();

        // Test that valid paths work
        let mut entries = fs::read_dir(psk_dir).await.unwrap();
        let mut psk_files = Vec::new();

        while let Some(entry) = entries.next_entry().await.unwrap() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "psk") {
                let metadata = entry.metadata().await.unwrap();
                let file_size = MemorySize::new(metadata.len());
                psk_files.push((path, file_size));
            }
        }

        // Test our error handling by simulating the extraction
        for (path, _size) in psk_files {
            let filename = path.file_name().ok_or_else(|| {
                buckwild_common::error::BuckwildError::invalid_input(format!(
                    "Invalid path: no filename component in '{}'",
                    path.display()
                ))
            });
            assert!(filename.is_ok(), "Valid path should have filename");
            assert_eq!(filename.unwrap().to_string_lossy(), "valid.psk");
        }
    }

    #[test]
    fn test_file_name_error_handling() {
        // Test paths that would cause file_name() to return None
        let test_cases = vec![
            (PathBuf::from("/"), "root path"),
            (PathBuf::from(".."), "parent directory"),
            (PathBuf::from(""), "empty path"),
        ];

        for (path, description) in test_cases {
            let result = path.file_name().ok_or_else(|| {
                buckwild_common::error::BuckwildError::invalid_input(format!(
                    "Invalid path: no filename component in '{}'",
                    path.display()
                ))
            });

            assert!(
                result.is_err(),
                "Path '{}' ({}) should return error",
                path.display(),
                description
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_psk_generation_with_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::TempDir;
        use tokio::fs;

        let temp_dir = TempDir::new().unwrap();
        let psk_path = temp_dir.path().join("test.psk");

        // Generate a PSK
        let cmd = PskCommand::Generate {
            output: psk_path.clone(),
            size: 256,
        };

        let result = handle_psk_command(&cmd).await;
        assert!(result.is_ok(), "PSK generation should succeed");

        // Verify file exists
        assert!(psk_path.exists(), "PSK file should exist");

        // Verify file permissions are 0600 (owner read/write only)
        let metadata = fs::metadata(&psk_path).await.unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Mask to get file permission bits (last 9 bits)
        let file_perms = mode & 0o777;
        assert_eq!(
            file_perms, 0o600,
            "PSK file should have 0600 permissions, got {:o}",
            file_perms
        );

        // Verify file size is correct (256 bits = 32 bytes)
        assert_eq!(
            metadata.len(),
            32,
            "PSK file should be 32 bytes for 256-bit key"
        );
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn test_psk_generation_on_non_unix() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let psk_path = temp_dir.path().join("test.psk");

        // Generate a PSK
        let cmd = PskCommand::Generate {
            output: psk_path.clone(),
            size: 256,
        };

        let result = handle_psk_command(&cmd).await;
        assert!(result.is_ok(), "PSK generation should succeed on non-Unix");

        // Verify file exists
        assert!(psk_path.exists(), "PSK file should exist");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ebpf_unload_nonexistent_interface() {
        let cmd = EbpfCommand::Unload {
            interface: "nonexistent_iface_12345".to_string(),
        };

        let result = handle_ebpf_command(&cmd).await;
        assert!(result.is_err(), "Should fail for nonexistent interface");

        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("not found") || err_msg.contains("nonexistent"),
            "Error should indicate interface not found: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_ebpf_unload_valid_interface_without_xdp() {
        // Use loopback interface which exists but likely has no XDP program
        let cmd = EbpfCommand::Unload {
            interface: "lo".to_string(),
        };

        let result = handle_ebpf_command(&cmd).await;

        // Should succeed even if no XDP program is attached
        // The ip command will succeed with no-op
        if let Err(e) = result {
            // If it fails, it should be a clear error message
            let err_msg = e.to_string();
            println!("Unload error: {}", err_msg);
            // Some systems may not support XDP on loopback
            assert!(
                err_msg.contains("Failed to detach") || err_msg.contains("not supported"),
                "Unexpected error: {}",
                err_msg
            );
        }
    }

    #[tokio::test]
    async fn test_ebpf_status_with_interface() {
        let cmd = EbpfCommand::Status {
            interface: Some("lo".to_string()),
        };

        let result = handle_ebpf_command(&cmd).await;
        assert!(result.is_ok(), "Status check should succeed");
    }

    #[tokio::test]
    async fn test_ebpf_status_without_interface() {
        let cmd = EbpfCommand::Status { interface: None };

        let result = handle_ebpf_command(&cmd).await;
        assert!(result.is_ok(), "Status check should succeed");
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ebpf_not_supported_on_non_linux() {
        let cmd = EbpfCommand::Unload {
            interface: "any".to_string(),
        };

        let result = handle_ebpf_command(&cmd).await;
        assert!(result.is_err(), "eBPF should not be supported on non-Linux");

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("only available on Linux"),
            "Error should indicate Linux-only support"
        );
    }
}
