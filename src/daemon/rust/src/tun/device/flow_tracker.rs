use anyhow::Result;
use buckwild_common::protocol::types::{Port, SequenceNumber, SessionId};
use buckwild_common::types::time::Timestamp;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, instrument, warn};

/// TCP flow identifier using 5-tuple
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Port,
    pub dst_port: Port,
    pub protocol: u8,
}

/// TCP flow state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub flow_id: FlowId,
    pub session_id: Option<SessionId>,
    pub state: TcpState,
    pub seq_num: SequenceNumber,
    pub ack_num: SequenceNumber,
    pub window_size: u16,
    pub last_activity: Timestamp,
    pub created_at: Timestamp,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u32,
    pub packets_received: u32,
}

// Use TcpState from daemon types (daemon-specific, not a protocol type)
use crate::types::TcpState;

/// Lock-free TCP flow tracker for concurrent access
#[derive(Debug)]
pub struct FlowTracker {
    flows: DashMap<u64, Arc<RwLock<FlowState>>>,
    flow_timeout: Duration,
    cleanup_interval: Duration,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl FlowTracker {
    /// Create a new flow tracker
    #[instrument]
    pub fn new(flow_timeout: Duration, cleanup_interval: Duration) -> Self {
        info!(
            "Creating flow tracker with timeout: {:?}, cleanup interval: {:?}",
            flow_timeout, cleanup_interval
        );

        FlowTracker {
            flows: DashMap::new(),
            flow_timeout,
            cleanup_interval,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the flow tracker with automatic cleanup
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Acquire) {
            warn!("Flow tracker already running");
            return Ok(());
        }

        info!("Starting flow tracker");
        self.running
            .store(true, std::sync::atomic::Ordering::Release);

        // Start cleanup task
        let flows = self.flows.clone();
        let timeout = self.flow_timeout;
        let running = Arc::clone(&self.running);
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            while running.load(std::sync::atomic::Ordering::Acquire) {
                interval.tick().await;

                let now = Timestamp::now();
                let mut expired_flows = Vec::new();

                // Collect expired flows
                for entry in flows.iter() {
                    let flow_hash = *entry.key();
                    let flow_state = entry.value();

                    if let Ok(state) = flow_state.try_read() {
                        if Duration::from_nanos(
                            now.as_nanos()
                                .saturating_sub(state.last_activity.as_nanos()),
                        ) > timeout
                        {
                            expired_flows.push(flow_hash);
                        }
                    }
                }

                // Remove expired flows
                for flow_hash in expired_flows {
                    if let Some((_, flow_state)) = flows.remove(&flow_hash) {
                        if let Ok(state) = flow_state.try_read() {
                            debug!("Cleaning up expired flow: {:?}", state.flow_id);
                        }
                    }
                }

                debug!("Flow cleanup completed, active flows: {}", flows.len());
            }

            info!("Flow tracker cleanup task terminated");
        });

        Ok(())
    }

    /// Stop the flow tracker
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping flow tracker");
        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Clear all flows
        self.flows.clear();

        info!("Flow tracker stopped");
    }

    /// Create or update a flow
    #[instrument(skip(self))]
    pub async fn create_or_update_flow(
        &self,
        flow_id: FlowId,
        seq_num: crate::protocol::types::SequenceNumber,
        ack_num: crate::protocol::types::SequenceNumber,
        window_size: u16,
        tcp_flags: u8,
    ) -> Result<Arc<RwLock<FlowState>>> {
        let flow_hash = self.hash_flow_id(&flow_id);
        let now = Timestamp::now();

        // Determine TCP state from flags
        let new_state = self.determine_tcp_state(tcp_flags);

        if let Some(existing_flow) = self.flows.get(&flow_hash) {
            // Update existing flow
            let flow_state = existing_flow.value();
            let mut state = flow_state.write().await;

            state.seq_num = seq_num;
            state.ack_num = ack_num;
            state.window_size = window_size;
            state.last_activity = now;
            state.state = new_state;
            state.packets_sent += 1;

            debug!("Updated existing flow: {:?} -> {:?}", flow_id, new_state);
            Ok(Arc::clone(flow_state))
        } else {
            // Create new flow
            let flow_state = FlowState {
                flow_id: flow_id.clone(),
                session_id: None,
                state: new_state,
                seq_num,
                ack_num,
                window_size,
                last_activity: now,
                created_at: now,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 1,
                packets_received: 0,
            };

            let flow_arc = Arc::new(RwLock::new(flow_state));
            self.flows.insert(flow_hash, Arc::clone(&flow_arc));

            info!("Created new flow: {:?} -> {:?}", flow_id, new_state);
            Ok(flow_arc)
        }
    }

    /// Get a flow by flow ID
    #[instrument(skip(self))]
    pub fn get_flow(&self, flow_id: &FlowId) -> Option<Arc<RwLock<FlowState>>> {
        let flow_hash = self.hash_flow_id(flow_id);
        self.flows
            .get(&flow_hash)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Remove a flow
    #[instrument(skip(self))]
    pub fn remove_flow(&self, flow_id: &FlowId) -> Option<Arc<RwLock<FlowState>>> {
        let flow_hash = self.hash_flow_id(flow_id);
        self.flows
            .remove(&flow_hash)
            .map(|(_, flow_state)| flow_state)
    }

    /// Get all active flows
    pub fn get_all_flows(&self) -> Vec<Arc<RwLock<FlowState>>> {
        self.flows
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Get flow statistics
    pub async fn get_statistics(&self) -> FlowStatistics {
        let mut stats = FlowStatistics::default();

        for entry in self.flows.iter() {
            let flow_state = entry.value();
            if let Ok(state) = flow_state.try_read() {
                stats.total_flows += 1;
                stats.total_bytes_sent += state.bytes_sent;
                stats.total_bytes_received += state.bytes_received;
                stats.total_packets_sent += state.packets_sent as u64;
                stats.total_packets_received += state.packets_received as u64;

                match state.state {
                    TcpState::Established => stats.established_flows += 1,
                    TcpState::SynSent | TcpState::SynReceived => stats.connecting_flows += 1,
                    TcpState::FinWait1
                    | TcpState::FinWait2
                    | TcpState::CloseWait
                    | TcpState::Closing
                    | TcpState::LastAck
                    | TcpState::TimeWait => stats.closing_flows += 1,
                    _ => {}
                }
            }
        }

        stats
    }

    /// Hash flow ID for efficient lookup
    fn hash_flow_id(&self, flow_id: &FlowId) -> u64 {
        let mut hasher = DefaultHasher::new();
        flow_id.hash(&mut hasher);
        hasher.finish()
    }

    /// Determine TCP state from flags
    fn determine_tcp_state(&self, tcp_flags: u8) -> TcpState {
        const TCP_FIN: u8 = 0x01;
        const TCP_SYN: u8 = 0x02;
        const TCP_RST: u8 = 0x04;
        const TCP_ACK: u8 = 0x10;

        match tcp_flags {
            flags if flags & TCP_RST != 0 => TcpState::Closed,
            flags if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 => TcpState::SynSent,
            flags if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 => TcpState::SynReceived,
            flags if flags & TCP_FIN != 0 => TcpState::FinWait1,
            flags if flags & TCP_ACK != 0 => TcpState::Established,
            _ => TcpState::Closed,
        }
    }
}

/// Flow statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FlowStatistics {
    pub total_flows: u32,
    pub established_flows: u32,
    pub connecting_flows: u32,
    pub closing_flows: u32,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
}

impl FlowId {
    /// Create a new flow ID
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Port,
        dst_port: Port,
        protocol: u8,
    ) -> Self {
        FlowId {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Create reverse flow ID (for bidirectional flows)
    pub fn reverse(&self) -> Self {
        FlowId {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Check if this is a TCP flow
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6 // IPPROTO_TCP
    }

    /// Check if this is a UDP flow
    pub fn is_udp(&self) -> bool {
        self.protocol == 17 // IPPROTO_UDP
    }
}

impl std::fmt::Display for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

// Display implementation is provided by the consolidated TcpState type
