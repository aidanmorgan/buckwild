// Connection-specific thread pools with CPU affinity management
//
// This implements the thread pool architecture specified in design/architecture.md
// with dedicated RX/TX thread pools per connection and CPU affinity optimization.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::BuckwildError;
use crate::protocol::types::{ConnectionId, PoolSize, ThreadCount};

/// Thread pool configuration
#[derive(Debug, Clone)]
pub struct ThreadPoolConfig {
    /// Threads per RX pool
    pub rx_threads_per_connection: ThreadCount,

    /// Threads per TX pool
    pub tx_threads_per_connection: ThreadCount,

    /// Connection establishment pool size
    pub establishment_pool_size: PoolSize,

    /// Enable CPU affinity
    pub enable_cpu_affinity: bool,

    /// CPU cores to use (None = use all available)
    pub cpu_cores: Option<Vec<usize>>,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        let cpu_count = num_cpus::get();
        Self {
            rx_threads_per_connection: ThreadCount::new(2),
            tx_threads_per_connection: ThreadCount::new(2),
            establishment_pool_size: PoolSize::new(cpu_count as u32),
            enable_cpu_affinity: true,
            cpu_cores: None, // Use all available cores
        }
    }
}

/// CPU affinity manager for optimal thread placement
pub struct CpuAffinityManager {
    /// Available CPU cores
    available_cores: Vec<usize>,

    /// Core assignments per connection
    core_assignments: RwLock<HashMap<ConnectionId, CoreAssignment>>,

    /// Next core index for round-robin assignment
    next_core_index: std::sync::atomic::AtomicUsize,

    /// Enable CPU affinity
    enabled: bool,
}

/// Core assignment for a connection
#[derive(Debug, Clone)]
pub struct CoreAssignment {
    rx_cores: Vec<usize>,
    tx_cores: Vec<usize>,
    establishment_cores: Vec<usize>,
}

impl CpuAffinityManager {
    /// Create new CPU affinity manager
    pub fn new(enabled: bool, cpu_cores: Option<Vec<usize>>) -> Self {
        let available_cores = cpu_cores.unwrap_or_else(|| (0..num_cpus::get()).collect());

        Self {
            available_cores,
            core_assignments: RwLock::new(HashMap::new()),
            next_core_index: std::sync::atomic::AtomicUsize::new(0),
            enabled,
        }
    }

    /// Assign cores for a new connection
    pub async fn assign_connection_cores(
        &self,
        connection_id: ConnectionId,
        rx_threads: u32,
        tx_threads: u32,
    ) -> Result<CoreAssignment, BuckwildError> {
        if !self.enabled {
            return Ok(CoreAssignment {
                rx_cores: vec![0; rx_threads as usize],
                tx_cores: vec![0; tx_threads as usize],
                establishment_cores: vec![0],
            });
        }

        let core_count = self.available_cores.len();
        if core_count == 0 {
            return Err(BuckwildError::configuration_error(
                "No CPU cores available".to_string(),
            ));
        }

        // Assign cores in round-robin fashion
        let mut rx_cores = Vec::new();
        let mut tx_cores = Vec::new();

        // Assign RX cores
        for _ in 0..rx_threads {
            let core_index = self
                .next_core_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % core_count;
            rx_cores.push(self.available_cores[core_index]);
        }

        // Assign TX cores (try to use different cores from RX)
        for _ in 0..tx_threads {
            let core_index = self
                .next_core_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % core_count;
            tx_cores.push(self.available_cores[core_index]);
        }

        // Assign establishment core
        let establishment_core_index = self
            .next_core_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % core_count;
        let establishment_cores = vec![self.available_cores[establishment_core_index]];

        let assignment = CoreAssignment {
            rx_cores,
            tx_cores,
            establishment_cores,
        };

        // Store assignment
        {
            let mut assignments = self.core_assignments.write().await;
            assignments.insert(connection_id, assignment.clone());
        }

        debug!(
            connection_id = %connection_id.clone(),
            rx_cores = ?assignment.rx_cores,
            tx_cores = ?assignment.tx_cores,
            establishment_cores = ?assignment.establishment_cores,
            "CPU cores assigned to connection"
        );

        Ok(assignment)
    }

    /// Remove core assignment for connection
    pub async fn remove_connection_assignment(&self, connection_id: ConnectionId) {
        let mut assignments = self.core_assignments.write().await;
        if assignments.remove(&connection_id).is_some() {
            debug!(
                connection_id = %connection_id.clone(),
                "CPU core assignment removed"
            );
        }
    }

    /// Get core assignment for connection
    pub async fn get_assignment(&self, connection_id: ConnectionId) -> Option<CoreAssignment> {
        let assignments = self.core_assignments.read().await;
        assignments.get(&connection_id).cloned()
    }
}

/// Connection-specific thread pools
pub struct ConnectionThreadPools {
    /// Configuration
    config: ThreadPoolConfig,

    /// RX thread pools per connection
    rx_pools: DashMap<ConnectionId, Arc<rayon::ThreadPool>>,

    /// TX thread pools per connection
    tx_pools: DashMap<ConnectionId, Arc<rayon::ThreadPool>>,

    /// Shared connection establishment pool
    establishment_pool: Arc<rayon::ThreadPool>,

    /// CPU affinity manager
    cpu_affinity: Arc<CpuAffinityManager>,
}

impl ConnectionThreadPools {
    /// Create new connection thread pools
    pub fn new(total_threads: u32, enable_cpu_affinity: bool) -> Result<Self, BuckwildError> {
        let config = ThreadPoolConfig {
            rx_threads_per_connection: ThreadCount::new(2),
            tx_threads_per_connection: ThreadCount::new(2),
            establishment_pool_size: PoolSize::new(total_threads),
            enable_cpu_affinity,
            cpu_cores: None,
        };

        // Create shared establishment pool
        let establishment_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(config.establishment_pool_size.as_usize())
                .thread_name(|index| format!("conn-establish-{}", index))
                .build()
                .map_err(|e| {
                    BuckwildError::invalid_state(format!(
                        "Failed to create establishment thread pool: {}",
                        e
                    ))
                })?,
        );

        let cpu_affinity = Arc::new(CpuAffinityManager::new(
            config.enable_cpu_affinity,
            config.cpu_cores.clone(),
        ));

        Ok(Self {
            config,
            rx_pools: DashMap::new(),
            tx_pools: DashMap::new(),
            establishment_pool,
            cpu_affinity,
        })
    }

    /// Assign thread pools to a connection
    pub async fn assign_connection(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(), BuckwildError> {
        // Get CPU core assignment
        let core_assignment = self
            .cpu_affinity
            .assign_connection_cores(
                connection_id,
                self.config.rx_threads_per_connection.as_u32(),
                self.config.tx_threads_per_connection.as_u32(),
            )
            .await?;

        // Create RX thread pool
        let rx_pool = self.create_thread_pool(
            format!("conn-{}-rx", connection_id.0),
            self.config.rx_threads_per_connection.as_usize(),
            core_assignment.rx_cores.clone(),
        )?;

        // Create TX thread pool
        let tx_pool = self.create_thread_pool(
            format!("conn-{}-tx", connection_id.0),
            self.config.tx_threads_per_connection.as_usize(),
            core_assignment.tx_cores.clone(),
        )?;

        // Store pools
        self.rx_pools.insert(connection_id, Arc::new(rx_pool));
        self.tx_pools.insert(connection_id, Arc::new(tx_pool));

        info!(
            connection_id = %connection_id.clone(),
            rx_threads = self.config.rx_threads_per_connection.as_u32(),
            tx_threads = self.config.tx_threads_per_connection.as_u32(),
            "Thread pools assigned to connection"
        );

        Ok(())
    }

    /// Remove thread pools for a connection
    pub async fn remove_connection(&self, connection_id: ConnectionId) {
        self.rx_pools.remove(&connection_id);
        self.tx_pools.remove(&connection_id);
        self.cpu_affinity
            .remove_connection_assignment(connection_id)
            .await;

        debug!(
            connection_id = %connection_id.clone(),
            "Thread pools removed for connection"
        );
    }

    /// Get RX thread pool for connection
    pub fn get_rx_pool(&self, connection_id: ConnectionId) -> Option<Arc<rayon::ThreadPool>> {
        self.rx_pools.get(&connection_id).map(|entry| entry.clone())
    }

    /// Get TX thread pool for connection
    pub fn get_tx_pool(&self, connection_id: ConnectionId) -> Option<Arc<rayon::ThreadPool>> {
        self.tx_pools.get(&connection_id).map(|entry| entry.clone())
    }

    /// Get establishment thread pool (shared)
    pub fn get_establishment_pool(&self) -> Arc<rayon::ThreadPool> {
        self.establishment_pool.clone()
    }

    /// Execute task in RX pool
    pub async fn execute_rx_task<F, R>(
        &self,
        connection_id: ConnectionId,
        task: F,
    ) -> Result<R, BuckwildError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = self
            .get_rx_pool(connection_id)
            .ok_or_else(|| BuckwildError::network_error("RX pool not found".to_string()))?;

        let (sender, receiver) = tokio::sync::oneshot::channel();

        pool.spawn(move || {
            let result = task();
            let _ = sender.send(result);
        });

        receiver
            .await
            .map_err(|_| BuckwildError::internal_error("RX task execution failed".to_string()))
    }

    /// Execute task in TX pool
    pub async fn execute_tx_task<F, R>(
        &self,
        connection_id: ConnectionId,
        task: F,
    ) -> Result<R, BuckwildError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = self
            .get_tx_pool(connection_id)
            .ok_or_else(|| BuckwildError::network_error("TX pool not found".to_string()))?;

        let (sender, receiver) = tokio::sync::oneshot::channel();

        pool.spawn(move || {
            let result = task();
            let _ = sender.send(result);
        });

        receiver
            .await
            .map_err(|_| BuckwildError::internal_error("TX task execution failed".to_string()))
    }

    /// Execute task in establishment pool
    pub async fn execute_establishment_task<F, R>(&self, task: F) -> Result<R, BuckwildError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();

        self.establishment_pool.spawn(move || {
            let result = task();
            let _ = sender.send(result);
        });

        receiver.await.map_err(|_| {
            BuckwildError::internal_error("Establishment task execution failed".to_string())
        })
    }

    /// Create thread pool with CPU affinity
    fn create_thread_pool(
        &self,
        name_prefix: String,
        num_threads: usize,
        cpu_cores: Vec<usize>,
    ) -> Result<rayon::ThreadPool, BuckwildError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(move |index| format!("{}-{}", name_prefix, index));

        // Set CPU affinity if enabled
        if self.config.enable_cpu_affinity && !cpu_cores.is_empty() {
            builder = builder.start_handler(move |index| {
                if let Some(&core) = cpu_cores.get(index) {
                    if let Err(e) = set_thread_affinity(core) {
                        warn!(
                            thread_index = index,
                            core = core,
                            error = %e,
                            "Failed to set thread CPU affinity"
                        );
                    }
                }
            });
        }

        builder.build().map_err(|e| {
            BuckwildError::internal_error(format!("Failed to create thread pool: {}", e))
        })
    }

    /// Get thread pool statistics
    pub fn get_stats(&self) -> ThreadPoolStats {
        ThreadPoolStats {
            active_rx_pools: ThreadCount::new(self.rx_pools.len() as u32),
            active_tx_pools: ThreadCount::new(self.tx_pools.len() as u32),
            establishment_pool_threads: self.config.establishment_pool_size,
            total_threads: ThreadCount::new(
                self.rx_pools.len() as u32 * self.config.rx_threads_per_connection.as_u32()
                    + self.tx_pools.len() as u32 * self.config.tx_threads_per_connection.as_u32()
                    + self.config.establishment_pool_size.as_u32(),
            ),
            cpu_affinity_enabled: self.config.enable_cpu_affinity,
        }
    }

    /// Shutdown all thread pools
    pub async fn shutdown(&self) {
        // Clear all connection pools
        self.rx_pools.clear();
        self.tx_pools.clear();

        info!("All thread pools shut down");
    }
}

/// Thread pool statistics
#[derive(Debug, Clone)]
pub struct ThreadPoolStats {
    pub active_rx_pools: ThreadCount,
    pub active_tx_pools: ThreadCount,
    pub establishment_pool_threads: PoolSize,
    pub total_threads: ThreadCount,
    pub cpu_affinity_enabled: bool,
}

/// Set CPU affinity for current thread (platform-specific)
fn set_thread_affinity(core: usize) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use libc::{CPU_SET, CPU_ZERO, cpu_set_t, sched_setaffinity};
        use std::mem;

        unsafe {
            let mut cpu_set: cpu_set_t = mem::zeroed();
            CPU_ZERO(&mut cpu_set);
            CPU_SET(core, &mut cpu_set);

            let result = sched_setaffinity(0, mem::size_of::<cpu_set_t>(), &cpu_set);
            if result != 0 {
                return Err(format!("sched_setaffinity failed: {}", result).into());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS doesn't support CPU affinity in the same way
        // This is a no-op on macOS
        debug!(core = core, "CPU affinity not supported on macOS");
    }

    #[cfg(target_os = "windows")]
    {
        use winapi::um::processthreadsapi::{GetCurrentThread, SetThreadAffinityMask};

        unsafe {
            let thread_handle = GetCurrentThread();
            let affinity_mask = 1u64 << core;
            let result = SetThreadAffinityMask(thread_handle, affinity_mask);
            if result == 0 {
                return Err("SetThreadAffinityMask failed".into());
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        debug!(
            core = core,
            "CPU affinity not implemented for this platform"
        );
    }

    Ok(())
}
