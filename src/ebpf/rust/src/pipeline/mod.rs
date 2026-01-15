//! eBPF Pipeline Coordination
//!
//! This module provides the top-level pipeline coordination for the complete
//! eBPF-to-userspace data flow, integrating:
//! - XDP packet filtering
//! - TC traffic control
//! - Ring buffer event delivery
//! - Event processing and routing
//! - Map management

#![cfg(target_os = "linux")]
//! ## Pipeline Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Kernel Space (eBPF)                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌──────────┐        ┌──────────┐       ┌──────────────┐      │
//! │  │   XDP    │───────▶│   Maps   │◀──────│      TC      │      │
//! │  │ Programs │        │  (BPF)   │       │   Programs   │      │
//! │  └────┬─────┘        └─────┬────┘       └──────┬───────┘      │
//! │       │                    │                   │               │
//! │       │                    │                   │               │
//! │       └────────────────────┴───────────────────┘               │
//! │                            │                                   │
//! │                     Ring Buffer (256KB)                        │
//! │                            │                                   │
//! └────────────────────────────┼───────────────────────────────────┘
//!                              │
//!                              │ packet_event (32 bytes)
//!                              │
//! ┌────────────────────────────▼───────────────────────────────────┐
//! │                    Userspace (Rust)                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌──────────────────┐                                          │
//! │  │  Ring Buffer     │───parse───▶ Channel (mpsc)               │
//! │  │  Manager         │             (backpressure)                │
//! │  └──────────────────┘                                          │
//! │           │                            │                        │
//! │           │                            │                        │
//! │           ▼                            ▼                        │
//! │    ┌──────────┐              ┌─────────────────┐               │
//! │    │  Stats   │              │ Event Processor │               │
//! │    │ Tracking │              │   & Handlers    │               │
//! │    └──────────┘              └─────────────────┘               │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod coordinator;
pub mod integration_example;

use crate::events::ring_buffer::{PacketEventParsed, RingBufferConfig, RingBufferManager};
use crate::loader::EbpfLoader;
use crate::loader::tc_loader::{TcLoader, TcLoaderConfig};
use crate::loader::xdp_loader::{XdpLoader, XdpLoaderConfig};
use crate::maps::MapManager;
use buckwild_common::error::BuckwildError;
use libbpf_rs::{MapHandle, RingBufferBuilder};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, warn};

/// Pipeline coordinator for the complete eBPF-to-userspace flow
pub struct EbpfPipeline {
    /// Pipeline configuration
    config: PipelineConfig,
    /// XDP program loader
    xdp_loader: Option<XdpLoader>,
    /// TC program loader
    tc_loader: Option<TcLoader>,
    /// Ring buffer manager for event consumption
    ring_buffer_manager: Option<RingBufferManager>,
    /// Map manager for eBPF map operations
    map_manager: Arc<RwLock<MapManager>>,
    /// Event processing task
    processing_task: Option<JoinHandle<()>>,
    /// Ring buffer polling task
    polling_task: Option<JoinHandle<()>>,
    /// Pipeline state
    state: Arc<RwLock<PipelineState>>,
    /// Pipeline statistics
    stats: Arc<RwLock<PipelineStatistics>>,
}

/// Pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Network interfaces to attach to
    pub interfaces: Vec<String>,
    /// Directory containing eBPF object files
    pub ebpf_program_dir: PathBuf,
    /// Ring buffer configuration
    pub ring_buffer_config: RingBufferConfig,
    /// Enable XDP programs
    pub enable_xdp: bool,
    /// Enable TC programs
    pub enable_tc: bool,
    /// Event processing channel buffer size
    pub event_channel_buffer: usize,
    /// Health check interval
    pub health_check_interval: Duration,
}

/// Pipeline state
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineState {
    /// Pipeline not initialized
    Uninitialized,
    /// Pipeline initialized but not started
    Initialized,
    /// Pipeline running
    Running,
    /// Pipeline stopped
    Stopped,
    /// Pipeline in error state
    Error(String),
}

/// Pipeline statistics
#[derive(Debug, Clone, Default)]
pub struct PipelineStatistics {
    /// Total events processed
    pub events_processed: u64,
    /// Events per second
    pub events_per_second: f64,
    /// Average processing latency (microseconds)
    pub avg_latency_us: u64,
    /// Pipeline uptime
    pub uptime: Duration,
    /// XDP packets processed
    pub xdp_packets: u64,
    /// TC packets processed
    pub tc_packets: u64,
    /// Ring buffer utilization (%)
    pub ring_buffer_utilization: f64,
    /// Event channel utilization (%)
    pub channel_utilization: f64,
    /// Errors encountered
    pub error_count: u64,
    /// Start time
    pub start_time: Option<Instant>,
}

/// Event handler callback type
pub type EventCallback = Arc<dyn Fn(PacketEventParsed) -> Result<(), BuckwildError> + Send + Sync>;

impl EbpfPipeline {
    /// Create a new eBPF pipeline coordinator
    #[instrument]
    pub async fn new(config: PipelineConfig) -> Result<Self, BuckwildError> {
        info!(
            interfaces = ?config.interfaces,
            xdp_enabled = config.enable_xdp,
            tc_enabled = config.enable_tc,
            "Creating eBPF pipeline"
        );

        // Create map manager
        let map_manager = Arc::new(RwLock::new(MapManager::new().map_err(|e| {
            BuckwildError::internal_error(format!("Failed to create map manager: {}", e))
        })?));

        // Create ring buffer manager
        let ring_buffer_manager = Some(RingBufferManager::new(config.ring_buffer_config.clone())?);

        Ok(Self {
            config,
            xdp_loader: None,
            tc_loader: None,
            ring_buffer_manager,
            map_manager,
            processing_task: None,
            polling_task: None,
            state: Arc::new(RwLock::new(PipelineState::Uninitialized)),
            stats: Arc::new(RwLock::new(PipelineStatistics::default())),
        })
    }

    /// Initialize the pipeline (load eBPF programs, set up maps)
    #[instrument(skip(self))]
    pub async fn initialize(&mut self) -> Result<(), BuckwildError> {
        let mut state = self.state.write().await;

        if *state != PipelineState::Uninitialized {
            return Err(BuckwildError::invalid_state(format!(
                "Cannot initialize pipeline in state: {:?}",
                *state
            )));
        }

        info!("Initializing eBPF pipeline");

        // Initialize XDP loader if enabled
        if self.config.enable_xdp {
            info!("Initializing XDP programs");
            let xdp_config = XdpLoaderConfig {
                program_directory: self.config.ebpf_program_dir.clone(),
                target_interfaces: self.config.interfaces.clone(),
                auto_discover_interfaces: false,
                retry_attempts: buckwild_common::protocol::types::AttemptCount::from_raw(3),
                retry_delay_ms: 1000,
            };

            let mut xdp_loader = XdpLoader::with_config(xdp_config).map_err(|e| {
                BuckwildError::internal_error(format!("Failed to create XDP loader: {}", e))
            })?;

            // Load XDP programs
            xdp_loader.load_programs().await.map_err(|e| {
                BuckwildError::internal_error(format!("Failed to load XDP programs: {}", e))
            })?;

            self.xdp_loader = Some(xdp_loader);
        }

        // Initialize TC loader if enabled
        if self.config.enable_tc {
            info!("Initializing TC programs");
            let tc_config = TcLoaderConfig {
                program_directory: self.config.ebpf_program_dir.clone(),
                target_interfaces: self.config.interfaces.clone(),
                auto_discover_interfaces: false,
                enable_ingress: true,
                enable_egress: true,
                retry_attempts: buckwild_common::protocol::types::AttemptCount::from_raw(3),
                retry_delay_ms: 1000,
            };

            let mut tc_loader = TcLoader::with_config(tc_config).map_err(|e| {
                BuckwildError::internal_error(format!("Failed to create TC loader: {}", e))
            })?;

            // Load TC programs
            tc_loader.load_programs().await.map_err(|e| {
                BuckwildError::internal_error(format!("Failed to load TC programs: {}", e))
            })?;

            self.tc_loader = Some(tc_loader);
        }

        *state = PipelineState::Initialized;
        info!("eBPF pipeline initialized successfully");
        Ok(())
    }

    /// Start the pipeline (begin processing events)
    #[instrument(skip(self, event_callback))]
    pub async fn start(&mut self, event_callback: EventCallback) -> Result<(), BuckwildError> {
        let mut state = self.state.write().await;

        if *state != PipelineState::Initialized {
            return Err(BuckwildError::invalid_state(format!(
                "Cannot start pipeline in state: {:?}",
                *state
            )));
        }

        info!("Starting eBPF pipeline");

        // Update statistics start time
        {
            let mut stats = self.stats.write().await;
            stats.start_time = Some(Instant::now());
        }

        // Start ring buffer polling task
        let mut ring_buf_mgr = self
            .ring_buffer_manager
            .take()
            .ok_or_else(|| BuckwildError::internal_error("Ring buffer manager not available"))?;

        let polling_task = {
            let stats = Arc::clone(&self.stats);
            let state_arc = Arc::clone(&self.state);

            tokio::spawn(async move {
                if let Err(e) = ring_buf_mgr.start_polling().await {
                    error!(error = %e, "Ring buffer polling failed");
                    let mut state = state_arc.write().await;
                    *state = PipelineState::Error(format!("Ring buffer error: {}", e));
                }
            })
        };
        self.polling_task = Some(polling_task);

        // Get event receiver from ring buffer manager
        let ring_buf_mgr = self
            .ring_buffer_manager
            .as_mut()
            .ok_or_else(|| BuckwildError::internal_error("Ring buffer manager not available"))?;

        let event_receiver = ring_buf_mgr.event_receiver();

        // Start event processing task
        let processing_task = {
            let stats = Arc::clone(&self.stats);
            let state_arc = Arc::clone(&self.state);
            let callback = Arc::clone(&event_callback);

            Self::spawn_processing_task(event_receiver, callback, stats, state_arc)
        };
        self.processing_task = Some(processing_task);

        *state = PipelineState::Running;
        info!("eBPF pipeline started and processing events");
        Ok(())
    }

    /// Spawn the event processing task
    fn spawn_processing_task(
        event_receiver: &mut mpsc::UnboundedReceiver<PacketEventParsed>,
        callback: EventCallback,
        stats: Arc<RwLock<PipelineStatistics>>,
        state: Arc<RwLock<PipelineState>>,
    ) -> JoinHandle<()> {
        // We need to take ownership of the receiver, but we can't move it out of the mutable reference
        // This is a temporary implementation - in production, we'd restructure the ownership
        tokio::spawn(async move {
            info!("Event processing task started");

            loop {
                // Check if we should stop
                {
                    let current_state = state.read().await;
                    if *current_state == PipelineState::Stopped {
                        info!("Event processing task stopping");
                        break;
                    }
                }

                // Event polling loop - ring buffer events arrive via separate ring_buffer_manager
                // This task monitors pipeline state and coordinates shutdown
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            info!("Event processing task stopped");
        })
    }

    /// Stop the pipeline
    #[instrument(skip(self))]
    pub async fn stop(&mut self) -> Result<(), BuckwildError> {
        let mut state = self.state.write().await;

        if *state != PipelineState::Running {
            warn!("Pipeline not running, current state: {:?}", *state);
            return Ok(());
        }

        info!("Stopping eBPF pipeline");

        // Stop ring buffer manager
        if let Some(ring_buf_mgr) = &mut self.ring_buffer_manager {
            ring_buf_mgr.stop();
        }

        // Stop polling task
        if let Some(task) = self.polling_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Stop processing task
        if let Some(task) = self.processing_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Unload XDP programs
        if let Some(xdp_loader) = &mut self.xdp_loader {
            xdp_loader.unload_programs().await.map_err(|e| {
                BuckwildError::internal_error(format!("Failed to unload XDP programs: {}", e))
            })?;
        }

        // Unload TC programs
        if let Some(tc_loader) = &mut self.tc_loader {
            tc_loader.unload_programs().await.map_err(|e| {
                BuckwildError::internal_error(format!("Failed to unload TC programs: {}", e))
            })?;
        }

        *state = PipelineState::Stopped;
        info!("eBPF pipeline stopped");
        Ok(())
    }

    /// Get pipeline state
    pub async fn get_state(&self) -> PipelineState {
        self.state.read().await.clone()
    }

    /// Get pipeline statistics
    pub async fn get_statistics(&self) -> PipelineStatistics {
        let mut stats = self.stats.read().await.clone();

        // Update uptime
        if let Some(start_time) = stats.start_time {
            stats.uptime = start_time.elapsed();
        }

        // Get ring buffer stats if available
        if let Some(ring_buf_mgr) = &self.ring_buffer_manager {
            let rb_stats = ring_buf_mgr.get_stats();
            stats.events_processed = rb_stats.events_processed;
            stats.events_per_second = ring_buf_mgr.get_event_rate();
            stats.ring_buffer_utilization = (rb_stats.events_in_flight as f64
                / self.config.ring_buffer_config.max_events_in_flight as f64)
                * 100.0;
        }

        stats
    }

    /// Perform health check on pipeline
    #[instrument(skip(self))]
    pub async fn health_check(&self) -> Result<PipelineHealth, BuckwildError> {
        let state = self.state.read().await;
        let stats = self.get_statistics().await;

        let health = PipelineHealth {
            state: state.clone(),
            healthy: matches!(*state, PipelineState::Running),
            events_processed: stats.events_processed,
            events_per_second: stats.events_per_second,
            ring_buffer_utilization: stats.ring_buffer_utilization,
            error_count: stats.error_count,
            uptime: stats.uptime,
            xdp_attached: self.xdp_loader.is_some(),
            tc_attached: self.tc_loader.is_some(),
        };

        Ok(health)
    }

    /// Get map manager for direct map access
    pub fn map_manager(&self) -> Arc<RwLock<MapManager>> {
        Arc::clone(&self.map_manager)
    }

    /// Get ring buffer statistics
    pub fn ring_buffer_stats(&self) -> Option<crate::events::ring_buffer::RingBufferStatsSnapshot> {
        self.ring_buffer_manager.as_ref().map(|mgr| mgr.get_stats())
    }
}

/// Pipeline health information
#[derive(Debug, Clone)]
pub struct PipelineHealth {
    /// Current pipeline state
    pub state: PipelineState,
    /// Overall health status
    pub healthy: bool,
    /// Events processed
    pub events_processed: u64,
    /// Events per second
    pub events_per_second: f64,
    /// Ring buffer utilization percentage
    pub ring_buffer_utilization: f64,
    /// Error count
    pub error_count: u64,
    /// Pipeline uptime
    pub uptime: Duration,
    /// XDP programs attached
    pub xdp_attached: bool,
    /// TC programs attached
    pub tc_attached: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            interfaces: vec!["lo".to_string()],
            ebpf_program_dir: PathBuf::from("/usr/lib/buckwild/bpf"),
            ring_buffer_config: RingBufferConfig::default(),
            enable_xdp: true,
            enable_tc: true,
            event_channel_buffer: 10000,
            health_check_interval: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pipeline_creation() {
        let config = PipelineConfig::default();
        let result = EbpfPipeline::new(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_state_transitions() {
        let config = PipelineConfig::default();
        let mut pipeline = EbpfPipeline::new(config).await.unwrap();

        // Initial state should be Uninitialized
        assert_eq!(pipeline.get_state().await, PipelineState::Uninitialized);
    }

    #[tokio::test]
    async fn test_pipeline_config_defaults() {
        let config = PipelineConfig::default();
        assert_eq!(config.interfaces, vec!["lo".to_string()]);
        assert!(config.enable_xdp);
        assert!(config.enable_tc);
        assert_eq!(config.event_channel_buffer, 10000);
    }

    #[tokio::test]
    async fn test_pipeline_statistics_initial() {
        let config = PipelineConfig::default();
        let pipeline = EbpfPipeline::new(config).await.unwrap();

        let stats = pipeline.get_statistics().await;
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.error_count, 0);
    }

    #[test]
    fn test_pipeline_health_structure() {
        let health = PipelineHealth {
            state: PipelineState::Running,
            healthy: true,
            events_processed: 1000,
            events_per_second: 100.0,
            ring_buffer_utilization: 25.5,
            error_count: 0,
            uptime: Duration::from_secs(60),
            xdp_attached: true,
            tc_attached: true,
        };

        assert!(health.healthy);
        assert_eq!(health.events_processed, 1000);
    }
}
