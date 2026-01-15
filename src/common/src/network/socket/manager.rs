// Socket manager engine for lifecycle management

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::binding::{BindingInfo, BindingRequest, PortBinding, PortBindingManager};
use crate::error::{BuckwildError, BuckwildResult};
use crate::memory::ZeroCopyBuffer;
use crate::protocol::types::{
    BufferSize, ByteCount, ErrorCount, NetworkEndpoint, PacketCount, Port, SizeLimit, SocketId,
};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval};

/// Socket manager for handling UDP socket lifecycle and management
pub struct SocketManager {
    /// Map of socket ID to managed socket
    sockets: Arc<RwLock<HashMap<SocketId, Arc<ManagedSocket>>>>,
    /// Port binding manager
    port_manager: Arc<PortBindingManager>,
    /// Manager configuration
    config: SocketManagerConfig,
    /// Manager state
    state: Arc<RwLock<SocketManagerState>>,
    /// Background tasks
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Socket event handlers
    event_handlers: Arc<RwLock<Vec<Box<dyn SocketEventHandler>>>>,
    /// Next socket ID
    next_socket_id: Arc<Mutex<u64>>,
}

/// Socket manager configuration
#[derive(Debug, Clone)]
pub struct SocketManagerConfig {
    /// Maximum number of sockets to manage
    pub max_sockets: SizeLimit,
    /// Socket timeout for inactive sockets
    pub socket_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Enable socket reuse
    pub enable_socket_reuse: bool,
    /// Socket buffer sizes
    pub send_buffer_size: BufferSize,
    pub receive_buffer_size: BufferSize,
    /// Enable automatic port allocation
    pub enable_auto_port_allocation: bool,
    /// Port range for automatic allocation
    pub auto_port_range: (Port, Port),
}

/// Socket manager state
#[derive(Debug, Clone, PartialEq)]
pub enum SocketManagerState {
    /// Manager is not initialized
    Uninitialized,
    /// Manager is starting up
    Starting,
    /// Manager is running
    Running,
    /// Manager is shutting down
    ShuttingDown,
    /// Manager is shut down
    Shutdown,
}

/// Managed socket with lifecycle tracking
#[derive(Debug)]
pub struct ManagedSocket {
    /// Socket ID
    id: SocketId,
    /// Underlying UDP socket
    socket: Arc<TokioUdpSocket>,
    /// Socket binding information
    binding: PortBinding,
    /// Socket configuration
    config: SocketConfig,
    /// Socket state
    state: Arc<RwLock<SocketState>>,
    /// Socket statistics
    stats: Arc<RwLock<SocketStats>>,
    /// Last activity timestamp
    last_activity: Arc<RwLock<std::time::Instant>>,
}

/// Socket configuration
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// Local endpoint
    pub local_endpoint: NetworkEndpoint,
    /// Socket options
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub send_buffer_size: Option<usize>,
    pub receive_buffer_size: Option<usize>,
    /// Socket timeout
    pub timeout: Option<Duration>,
}

// Use consolidated SocketState from protocol types
use crate::protocol::types::SocketState;

/// Socket statistics
#[derive(Debug, Default, Clone)]
pub struct SocketStats {
    /// Packets sent
    pub packets_sent: PacketCount,
    /// Packets received
    pub packets_received: PacketCount,
    /// Bytes sent
    pub bytes_sent: ByteCount,
    /// Bytes received
    pub bytes_received: ByteCount,
    /// Send errors
    pub send_errors: ErrorCount,
    /// Receive errors
    pub receive_errors: ErrorCount,
    /// Socket creation time
    pub created_at: Option<std::time::Instant>,
    /// Last activity time
    pub last_activity: Option<std::time::Instant>,
}

/// Socket creation request
#[derive(Debug, Clone)]
pub struct SocketCreateRequest {
    /// Desired local endpoint (port can be 0 for auto-allocation)
    pub local_endpoint: NetworkEndpoint,
    /// Socket configuration
    pub config: SocketConfig,
    /// Whether to enable port binding management
    pub enable_binding_management: bool,
}

/// Socket information
#[derive(Debug, Clone)]
pub struct SocketInfo {
    /// Socket ID
    pub id: SocketId,
    /// Socket configuration
    pub config: SocketConfig,
    /// Current state
    pub state: SocketState,
    /// Statistics
    pub stats: SocketStats,
    /// Binding information
    pub binding: BindingInfo,
}

/// Event handler for socket events
pub trait SocketEventHandler: Send + Sync {
    /// Called when a socket is created
    fn on_socket_created(&self, socket_id: SocketId, endpoint: &NetworkEndpoint);

    /// Called when a socket becomes active
    fn on_socket_active(&self, socket_id: SocketId);

    /// Called when a socket encounters an error
    fn on_socket_error(&self, socket_id: SocketId, error: &str);

    /// Called when a socket is closed
    fn on_socket_closed(&self, socket_id: SocketId);

    /// Called when data is sent
    fn on_data_sent(&self, socket_id: SocketId, bytes: usize);

    /// Called when data is received
    fn on_data_received(&self, socket_id: SocketId, bytes: usize);
}

impl Default for SocketManagerConfig {
    fn default() -> Self {
        Self {
            max_sockets: SizeLimit::new(1024),
            socket_timeout: Duration::from_secs(300), // 5 minutes
            health_check_interval: Duration::from_secs(60),
            enable_socket_reuse: true,
            send_buffer_size: BufferSize::new(65536),
            receive_buffer_size: BufferSize::new(65536),
            enable_auto_port_allocation: true,
            auto_port_range: (
                Port(49152), // Start of dynamic/private port range
                Port(65535), // End of port range
            ),
        }
    }
}

impl SocketManager {
    /// Create a new socket manager
    pub fn new(config: SocketManagerConfig) -> Self {
        let port_manager = Arc::new(PortBindingManager::new(Default::default()));

        Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
            port_manager,
            config,
            state: Arc::new(RwLock::new(SocketManagerState::Uninitialized)),
            tasks: Arc::new(Mutex::new(Vec::new())),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            next_socket_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Start the socket manager
    pub async fn start(&self) -> BuckwildResult<()> {
        let mut state = self.state.write().await;
        if *state != SocketManagerState::Uninitialized {
            return Err(BuckwildError::invalid_state("Manager already started"));
        }

        *state = SocketManagerState::Starting;
        drop(state);

        // Start port binding manager
        self.port_manager.start().await?;

        // Start background tasks
        self.start_background_tasks().await?;

        // Update state to running
        let mut state = self.state.write().await;
        *state = SocketManagerState::Running;

        Ok(())
    }

    /// Start background tasks
    async fn start_background_tasks(&self) -> BuckwildResult<()> {
        let mut tasks = self.tasks.lock().await;

        // Health check and cleanup task
        if self.config.health_check_interval > Duration::ZERO {
            let cleanup_task = self.spawn_cleanup_task();
            tasks.push(cleanup_task);
        }

        Ok(())
    }

    /// Spawn cleanup task for inactive sockets
    fn spawn_cleanup_task(&self) -> JoinHandle<()> {
        let sockets: Arc<RwLock<HashMap<SocketId, Arc<ManagedSocket>>>> = Arc::clone(&self.sockets);
        let interval_duration = self.config.health_check_interval;
        let socket_timeout = self.config.socket_timeout;
        let event_handlers = Arc::clone(&self.event_handlers);

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                let mut sockets_to_close = Vec::new();

                // Check for inactive sockets
                {
                    let sockets_guard = sockets.read().await;
                    let now = std::time::Instant::now();

                    for (socket_id, socket) in sockets_guard.iter() {
                        let last_activity = *socket.last_activity.read().await;
                        if now.duration_since(last_activity) > socket_timeout {
                            let state = socket.state.read().await;
                            if *state == SocketState::Active {
                                sockets_to_close.push(*socket_id);
                            }
                        }
                    }
                }

                // Close inactive sockets
                for socket_id in sockets_to_close {
                    if let Some(socket) = {
                        let mut sockets_guard = sockets.write().await;
                        sockets_guard.remove(&socket_id)
                    } {
                        // Update socket state
                        {
                            let mut state = socket.state.write().await;
                            *state = SocketState::Closing;
                        }

                        // Notify event handlers
                        let handlers = event_handlers.read().await;
                        for handler in handlers.iter() {
                            handler.on_socket_closed(socket_id);
                        }

                        // Socket will be dropped and closed automatically
                    }
                }
            }
        })
    }

    /// Create a new socket
    pub async fn create_socket(&self, request: SocketCreateRequest) -> BuckwildResult<SocketId> {
        let state = self.state.read().await;
        if *state != SocketManagerState::Running {
            return Err(BuckwildError::invalid_state("Manager is not running"));
        }
        drop(state);

        // Check socket limit
        {
            let sockets = self.sockets.read().await;
            if sockets.len() >= self.config.max_sockets.as_usize() {
                return Err(BuckwildError::resource_exhausted(format!(
                    "Maximum number of sockets ({}) reached",
                    self.config.max_sockets.as_usize()
                )));
            }
        }

        // Generate socket ID
        let socket_id = {
            let mut next_id = self.next_socket_id.lock().await;
            let id = SocketId::new((*next_id).try_into().unwrap_or(u32::MAX));
            *next_id += 1;
            id
        };

        // Handle port allocation
        let local_endpoint = if request.local_endpoint.port.as_u16() == 0
            && self.config.enable_auto_port_allocation
        {
            // Auto-allocate port
            let allocated_port = self.allocate_port().await?;
            NetworkEndpoint::new(request.local_endpoint.ip, allocated_port)
        } else {
            request.local_endpoint
        };

        // Create socket binding if requested
        let binding = if request.enable_binding_management {
            let binding_request = BindingRequest {
                port: local_endpoint.port,
                address: Some(local_endpoint.ip),
                protocol: crate::network::socket::binding::Protocol::Udp,
                exclusive: false,
            };
            self.port_manager.bind_port(binding_request).await?
        } else {
            // Create a simple binding without management
            PortBinding::new(local_endpoint.port, local_endpoint.ip)
        };

        // Create the actual socket
        let socket_addr = local_endpoint.to_socket_addr();
        let socket = TokioUdpSocket::bind(socket_addr).await.map_err(|e| {
            BuckwildError::io_error(format!("Failed to bind socket to {}: {}", socket_addr, e))
        })?;

        // Configure socket options
        // Note: Tokio UdpSocket doesn't expose buffer size configuration
        // This would need to be done at the OS level or with raw sockets

        // Create managed socket
        let managed_socket = Arc::new(ManagedSocket {
            id: socket_id,
            socket: Arc::new(socket),
            binding,
            config: request.config.clone(),
            state: Arc::new(RwLock::new(SocketState::Active)),
            stats: Arc::new(RwLock::new(SocketStats {
                created_at: Some(std::time::Instant::now()),
                ..Default::default()
            })),
            last_activity: Arc::new(RwLock::new(std::time::Instant::now())),
        });

        // Add to managed sockets
        {
            let mut sockets = self.sockets.write().await;
            sockets.insert(socket_id, managed_socket);
        }

        // Notify event handlers
        {
            let handlers = self.event_handlers.read().await;
            for handler in handlers.iter() {
                handler.on_socket_created(socket_id, &local_endpoint);
                handler.on_socket_active(socket_id);
            }
        }

        Ok(socket_id)
    }

    /// Allocate an available port
    async fn allocate_port(&self) -> BuckwildResult<Port> {
        let start_port = self.config.auto_port_range.0;
        let end_port = self.config.auto_port_range.1;

        for port_num in start_port.0..=end_port.0 {
            if let Ok(port) = Port::new(port_num) {
                // Try to bind to this port to check availability
                let test_addr = SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    port.as_u16(),
                );
                if UdpSocket::bind(test_addr).is_ok() {
                    return Ok(port);
                }
            }
        }

        Err(BuckwildError::resource_exhausted(
            "No available ports in range",
        ))
    }

    /// Get a socket by ID
    pub async fn get_socket(&self, socket_id: SocketId) -> Option<Arc<ManagedSocket>> {
        let sockets = self.sockets.read().await;
        sockets.get(&socket_id).cloned()
    }

    /// Send data through a socket
    pub async fn send_to(
        &self,
        socket_id: SocketId,
        data: &ZeroCopyBuffer,
        target: &NetworkEndpoint,
    ) -> BuckwildResult<usize> {
        let socket = self
            .get_socket(socket_id)
            .await
            .ok_or_else(|| BuckwildError::not_found(format!("Socket {} not found", socket_id)))?;

        // Check socket state
        {
            let state = socket.state.read().await;
            if *state != SocketState::Active {
                return Err(BuckwildError::invalid_state("Socket is not active"));
            }
        }

        // Send data
        let target_addr = target.to_socket_addr();
        let bytes_sent = socket
            .socket
            .send_to(data.as_slice(), target_addr)
            .await
            .map_err(|e| BuckwildError::io_error(format!("Failed to send data: {}", e)))?;

        // Update statistics and activity
        {
            let mut stats = socket.stats.write().await;
            stats.packets_sent += 1;
            stats.bytes_sent = ByteCount::new(
                stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed) + bytes_sent as u64,
            );
            stats.last_activity = Some(std::time::Instant::now());
        }

        {
            let mut last_activity = socket.last_activity.write().await;
            *last_activity = std::time::Instant::now();
        }

        // Notify event handlers
        {
            let handlers = self.event_handlers.read().await;
            for handler in handlers.iter() {
                handler.on_data_sent(socket_id, bytes_sent);
            }
        }

        Ok(bytes_sent)
    }

    /// Receive data from a socket
    pub async fn receive_from(
        &self,
        socket_id: SocketId,
        buffer: &mut [u8],
    ) -> BuckwildResult<(usize, NetworkEndpoint)> {
        let socket = self
            .get_socket(socket_id)
            .await
            .ok_or_else(|| BuckwildError::not_found(format!("Socket {} not found", socket_id)))?;

        // Check socket state
        {
            let state = socket.state.read().await;
            if *state != SocketState::Active {
                return Err(BuckwildError::invalid_state("Socket is not active"));
            }
        }

        // Receive data
        let (bytes_received, source_addr) = socket
            .socket
            .recv_from(buffer)
            .await
            .map_err(|e| BuckwildError::io_error(format!("Failed to receive data: {}", e)))?;

        let source_endpoint = NetworkEndpoint::from_socket_addr(source_addr);

        // Update statistics and activity
        {
            let mut stats = socket.stats.write().await;
            stats.packets_received += 1;
            stats.bytes_received = ByteCount::new(
                stats
                    .bytes_received
                    .load(std::sync::atomic::Ordering::Relaxed)
                    + bytes_received as u64,
            );
            stats.last_activity = Some(std::time::Instant::now());
        }

        {
            let mut last_activity = socket.last_activity.write().await;
            *last_activity = std::time::Instant::now();
        }

        // Notify event handlers
        {
            let handlers = self.event_handlers.read().await;
            for handler in handlers.iter() {
                handler.on_data_received(socket_id, bytes_received);
            }
        }

        Ok((bytes_received, source_endpoint))
    }

    /// Close a socket
    pub async fn close_socket(&self, socket_id: SocketId) -> BuckwildResult<()> {
        let socket = {
            let mut sockets = self.sockets.write().await;
            sockets.remove(&socket_id)
        };

        if let Some(socket) = socket {
            // Update socket state
            {
                let mut state = socket.state.write().await;
                *state = SocketState::Closing;
            }

            // Release port binding if managed
            if let Err(e) = self.port_manager.release_port(socket.binding.port()).await {
                tracing::warn!("Failed to release port binding: {}", e);
            }

            // Notify event handlers
            {
                let handlers = self.event_handlers.read().await;
                for handler in handlers.iter() {
                    handler.on_socket_closed(socket_id);
                }
            }

            // Socket will be dropped and closed automatically
            Ok(())
        } else {
            Err(BuckwildError::not_found(format!(
                "Socket {} not found",
                socket_id
            )))
        }
    }

    /// List all managed sockets
    pub async fn list_sockets(&self) -> Vec<SocketInfo> {
        let sockets = self.sockets.read().await;
        let mut socket_infos = Vec::new();

        for (_, socket) in sockets.iter() {
            let info = SocketInfo {
                id: socket.id,
                config: socket.config.clone(),
                state: *socket.state.read().await,
                stats: socket.stats.read().await.clone(),
                binding: socket.binding.info(),
            };
            socket_infos.push(info);
        }

        socket_infos
    }

    /// Get socket statistics
    pub async fn get_socket_stats(&self, socket_id: SocketId) -> Option<SocketStats> {
        let socket = self.get_socket(socket_id).await?;
        let stats = socket.stats.read().await.clone();
        Some(stats)
    }

    /// Add an event handler
    pub async fn add_event_handler(&self, handler: Box<dyn SocketEventHandler>) {
        let mut handlers = self.event_handlers.write().await;
        handlers.push(handler);
    }

    /// Get current manager state
    pub async fn state(&self) -> SocketManagerState {
        self.state.read().await.clone()
    }

    /// Check if manager is running
    pub async fn is_running(&self) -> bool {
        matches!(*self.state.read().await, SocketManagerState::Running)
    }

    /// Get number of managed sockets
    pub async fn socket_count(&self) -> usize {
        self.sockets.read().await.len()
    }

    /// Shutdown the manager and all sockets
    pub async fn shutdown(&self) -> BuckwildResult<()> {
        let mut state = self.state.write().await;
        if *state == SocketManagerState::Shutdown {
            return Ok(());
        }

        *state = SocketManagerState::ShuttingDown;
        drop(state);

        // Stop background tasks
        {
            let mut tasks = self.tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
        }

        // Close all sockets
        let socket_ids: Vec<_> = {
            let sockets = self.sockets.read().await;
            sockets.keys().cloned().collect()
        };

        for socket_id in socket_ids {
            if let Err(e) = self.close_socket(socket_id).await {
                tracing::warn!("Error closing socket {}: {}", socket_id, e);
            }
        }

        // Shutdown port manager
        self.port_manager.shutdown().await?;

        // Update state
        let mut state = self.state.write().await;
        *state = SocketManagerState::Shutdown;

        Ok(())
    }
}

impl Drop for SocketManager {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd want to ensure proper cleanup
        // This is a simplified version for the restructuring task
    }
}

/// Default event handler that logs socket events
#[derive(Debug)]
pub struct LoggingSocketEventHandler;

impl SocketEventHandler for LoggingSocketEventHandler {
    fn on_socket_created(&self, socket_id: SocketId, endpoint: &NetworkEndpoint) {
        tracing::info!("Socket created: {} at {}", socket_id, endpoint);
    }

    fn on_socket_active(&self, socket_id: SocketId) {
        tracing::info!("Socket active: {}", socket_id);
    }

    fn on_socket_error(&self, socket_id: SocketId, error: &str) {
        tracing::error!("Socket error on {}: {}", socket_id, error);
    }

    fn on_socket_closed(&self, socket_id: SocketId) {
        tracing::info!("Socket closed: {}", socket_id);
    }

    fn on_data_sent(&self, socket_id: SocketId, bytes: usize) {
        tracing::debug!("Data sent on socket {}: {} bytes", socket_id, bytes);
    }

    fn on_data_received(&self, socket_id: SocketId, bytes: usize) {
        tracing::debug!("Data received on socket {}: {} bytes", socket_id, bytes);
    }
}
