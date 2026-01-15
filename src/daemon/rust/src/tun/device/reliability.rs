use anyhow::{Context, Result};
use buckwild_common::protocol::types::{SequenceNumber, SessionId};
use buckwild_common::types::time::Timestamp;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

/// TCP reliability emulation engine
pub struct ReliabilityEngine {
    connections: Arc<RwLock<HashMap<SessionId, Arc<Mutex<ConnectionReliability>>>>>,
    retransmission_timeout: Duration,
    max_retries: u32,
    initial_window_size: u32,
    max_window_size: u32,
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Per-connection reliability state
#[derive(Debug)]
struct ConnectionReliability {
    session_id: SessionId,
    send_buffer: VecDeque<UnackedPacket>,
    receive_buffer: HashMap<SequenceNumber, ReceivedPacket>,
    send_window: WindowState,
    receive_window: WindowState,
    congestion_control: CongestionControl,
    rtt_estimator: RttEstimator,
    last_activity: Timestamp,
}

/// Unacknowledged packet in send buffer
#[derive(Debug, Clone)]
struct UnackedPacket {
    sequence: SequenceNumber,
    data: Bytes,
    sent_time: Timestamp,
    retry_count: u32,
    acked: bool,
}

/// Received packet in receive buffer
#[derive(Debug, Clone)]
struct ReceivedPacket {
    sequence: SequenceNumber,
    data: Bytes,
    received_time: Timestamp,
}

/// Window state for flow control
#[derive(Debug, Clone)]
struct WindowState {
    base: u32,
    next: u32,
    size: u32,
    max_size: u32,
    advertised_window: u32,
}

/// Congestion control state
#[derive(Debug, Clone)]
struct CongestionControl {
    cwnd: u32,     // Congestion window
    ssthresh: u32, // Slow start threshold
    state: CongestionState,
    duplicate_acks: u32,
    last_ack: u32,
}

// Use consolidated CongestionState from protocol types
use crate::protocol::types::CongestionState;

/// RTT estimation for timeout calculation
#[derive(Debug, Clone)]
struct RttEstimator {
    srtt: f64,     // Smoothed RTT
    rttvar: f64,   // RTT variation
    rto: Duration, // Retransmission timeout
    last_measurement: Option<Timestamp>,
}

/// Acknowledgment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckInfo {
    pub ack_number: u32,
    pub window_size: u16,
    pub selective_acks: Vec<(u32, u32)>, // SACK ranges
}

/// Reliability statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReliabilityStatistics {
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub total_retransmissions: u64,
    pub total_duplicate_acks: u64,
    pub average_rtt_ms: f64,
    pub current_cwnd: u32,
    pub packet_loss_rate: f64,
}

impl ReliabilityEngine {
    /// Create a new reliability engine
    #[instrument]
    pub fn new(
        retransmission_timeout: Duration,
        max_retries: u32,
        initial_window_size: u32,
        max_window_size: u32,
    ) -> Self {
        info!(
            "Creating reliability engine with RTO: {:?}, max retries: {}, initial window: {}",
            retransmission_timeout, max_retries, initial_window_size
        );

        ReliabilityEngine {
            connections: Arc::new(RwLock::new(HashMap::new())),
            retransmission_timeout,
            max_retries,
            initial_window_size,
            max_window_size,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the reliability engine
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Acquire) {
            warn!("Reliability engine already running");
            return Ok(());
        }

        info!("Starting reliability engine");
        self.running
            .store(true, std::sync::atomic::Ordering::Release);

        // Start retransmission timer task
        let connections = Arc::clone(&self.connections);
        let running = Arc::clone(&self.running);
        let max_retries = self.max_retries;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100)); // Check every 100ms

            while running.load(std::sync::atomic::Ordering::Acquire) {
                interval.tick().await;

                let connections_guard = connections.read().await;
                for (_session_id, connection) in connections_guard.iter() {
                    let mut conn = connection.lock().await;
                    Self::check_retransmissions(&mut conn, max_retries).await;
                }
            }

            info!("Reliability engine retransmission task terminated");
        });

        Ok(())
    }

    /// Stop the reliability engine
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping reliability engine");
        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Clear all connections
        self.connections.write().await.clear();

        info!("Reliability engine stopped");
    }

    /// Create a new reliable connection
    #[instrument(skip(self))]
    pub async fn create_connection(&self, session_id: SessionId) -> Result<()> {
        debug!("Creating reliable connection for session: {:?}", session_id);

        let connection = ConnectionReliability {
            session_id: session_id.clone(),
            send_buffer: VecDeque::new(),
            receive_buffer: HashMap::new(),
            send_window: WindowState {
                base: 0,
                next: 0,
                size: self.initial_window_size,
                max_size: self.max_window_size,
                advertised_window: self.max_window_size,
            },
            receive_window: WindowState {
                base: 0,
                next: 0,
                size: self.max_window_size,
                max_size: self.max_window_size,
                advertised_window: self.max_window_size,
            },
            congestion_control: CongestionControl {
                cwnd: self.initial_window_size,
                ssthresh: self.max_window_size / 2,
                state: CongestionState::SlowStart,
                duplicate_acks: 0,
                last_ack: 0,
            },
            rtt_estimator: RttEstimator {
                srtt: 100.0, // Initial RTT estimate: 100ms
                rttvar: 50.0,
                rto: Duration::from_millis(200),
                last_measurement: None,
            },
            last_activity: Timestamp::now(),
        };

        self.connections
            .write()
            .await
            .insert(session_id.clone(), Arc::new(Mutex::new(connection)));
        info!("Created reliable connection for session: {}", session_id);
        Ok(())
    }

    /// Send data reliably
    #[instrument(skip(self, data))]
    pub async fn send_data(&self, session_id: SessionId, data: Bytes) -> Result<Vec<Bytes>> {
        let connections = self.connections.read().await;
        let connection = connections
            .get(&session_id)
            .context("Connection not found")?;

        let mut conn = connection.lock().await;
        let mut packets = Vec::new();

        // Fragment data if necessary (simplified - assume MTU of 1460 bytes)
        const MAX_SEGMENT_SIZE: usize = 1460;
        let mut offset = 0;

        while offset < data.len() {
            let end = std::cmp::min(offset + MAX_SEGMENT_SIZE, data.len());
            let segment = data.slice(offset..end);

            let packet = UnackedPacket {
                sequence: SequenceNumber::new(conn.send_window.next),
                data: segment.clone(),
                sent_time: Timestamp::now(),
                retry_count: 0,
                acked: false,
            };

            conn.send_buffer.push_back(packet);
            conn.send_window.next += segment.len() as u32;
            packets.push(segment);

            offset = end;
        }

        conn.last_activity = Timestamp::now();
        debug!(
            "Queued {} packets for transmission on session: {}",
            packets.len(),
            session_id
        );
        Ok(packets)
    }

    /// Process received acknowledgment
    #[instrument(skip(self))]
    pub async fn process_ack(&self, session_id: SessionId, ack_info: AckInfo) -> Result<()> {
        let connections = self.connections.read().await;
        let connection = connections
            .get(&session_id)
            .context("Connection not found")?;

        let mut conn = connection.lock().await;

        // Update RTT if this is a new ACK
        if ack_info.ack_number > conn.congestion_control.last_ack {
            self.update_rtt(&mut conn.rtt_estimator).await;
            conn.congestion_control.duplicate_acks = 0;

            // Remove acknowledged packets from send buffer
            let ack_seq = SequenceNumber::new(ack_info.ack_number);
            conn.send_buffer.retain(|packet| {
                if packet.sequence < ack_seq {
                    false // Remove acknowledged packet
                } else {
                    true // Keep unacknowledged packet
                }
            });

            // Update congestion window
            self.update_congestion_window(&mut conn.congestion_control, false)
                .await;
            conn.congestion_control.last_ack = ack_info.ack_number;
        } else if ack_info.ack_number == conn.congestion_control.last_ack {
            // Duplicate ACK
            conn.congestion_control.duplicate_acks += 1;

            if conn.congestion_control.duplicate_acks >= 3 {
                // Fast retransmit
                debug!("Fast retransmit triggered for session: {}", session_id);
                self.update_congestion_window(&mut conn.congestion_control, true)
                    .await;
            }
        }

        // Update send window
        conn.send_window.advertised_window = ack_info.window_size as u32;
        conn.last_activity = Timestamp::now();

        debug!(
            "Processed ACK for session: {}, ack_num: {}, window: {}",
            session_id, ack_info.ack_number, ack_info.window_size
        );
        Ok(())
    }

    /// Process received data
    #[instrument(skip(self, data))]
    pub async fn process_received_data(
        &self,
        session_id: SessionId,
        sequence: SequenceNumber,
        data: Bytes,
    ) -> Result<Vec<Bytes>> {
        let connections = self.connections.read().await;
        let connection = connections
            .get(&session_id)
            .context("Connection not found")?;

        let mut conn = connection.lock().await;

        // Store received packet
        let received_packet = ReceivedPacket {
            sequence,
            data: data.clone(),
            received_time: Timestamp::now(),
        };

        conn.receive_buffer.insert(sequence, received_packet);
        conn.last_activity = Timestamp::now();

        // Try to deliver in-order packets
        let mut delivered_packets = Vec::new();
        loop {
            let next_seq = SequenceNumber::new(conn.receive_window.next);
            if let Some(packet) = conn.receive_buffer.remove(&next_seq) {
                let data_len = packet.data.len() as u32;
                delivered_packets.push(packet.data);
                conn.receive_window.next += data_len;
            } else {
                break;
            }
        }

        debug!(
            "Processed received data for session: {}, sequence: {}, delivered: {} packets",
            session_id,
            sequence,
            delivered_packets.len()
        );
        Ok(delivered_packets)
    }

    /// Remove connection
    #[instrument(skip(self))]
    pub async fn remove_connection(&self, session_id: SessionId) -> Result<()> {
        self.connections.write().await.remove(&session_id);
        info!("Removed reliable connection for session: {:?}", session_id);
        Ok(())
    }

    /// Get connection statistics
    pub async fn get_statistics(&self, session_id: SessionId) -> Option<ReliabilityStatistics> {
        let connections = self.connections.read().await;
        let connection = connections.get(&session_id)?;
        let conn = connection.lock().await;

        Some(ReliabilityStatistics {
            total_packets_sent: conn.send_buffer.len() as u64,
            total_packets_received: conn.receive_buffer.len() as u64,
            total_retransmissions: conn.send_buffer.iter().map(|p| p.retry_count as u64).sum(),
            total_duplicate_acks: conn.congestion_control.duplicate_acks as u64,
            average_rtt_ms: conn.rtt_estimator.srtt,
            current_cwnd: conn.congestion_control.cwnd,
            packet_loss_rate: 0.0, // Would be calculated from statistics
        })
    }

    /// Check for retransmissions
    async fn check_retransmissions(conn: &mut ConnectionReliability, max_retries: u32) {
        let now = Timestamp::now();

        for packet in &mut conn.send_buffer {
            let elapsed_nanos = now.as_nanos().saturating_sub(packet.sent_time.as_nanos());
            if !packet.acked && elapsed_nanos > conn.rtt_estimator.rto.as_nanos() as u64 {
                if packet.retry_count < max_retries {
                    packet.retry_count += 1;
                    packet.sent_time = now;
                    debug!(
                        "Retransmitting packet sequence: {} (retry {})",
                        packet.sequence, packet.retry_count
                    );
                } else {
                    error!(
                        "Max retries exceeded for packet sequence: {}",
                        packet.sequence
                    );
                }
            }
        }
    }

    /// Update RTT estimation
    async fn update_rtt(&self, rtt_estimator: &mut RttEstimator) {
        if let Some(last_measurement) = rtt_estimator.last_measurement {
            let now = Timestamp::now();
            let sample_rtt_nanos = now.as_nanos().saturating_sub(last_measurement.as_nanos());
            let sample_rtt = (sample_rtt_nanos / 1_000_000) as f64; // Convert to millis

            // RFC 6298 RTT estimation
            if rtt_estimator.srtt == 0.0 {
                rtt_estimator.srtt = sample_rtt;
                rtt_estimator.rttvar = sample_rtt / 2.0;
            } else {
                let alpha = 0.125;
                let beta = 0.25;

                rtt_estimator.rttvar = (1.0 - beta) * rtt_estimator.rttvar
                    + beta * (rtt_estimator.srtt - sample_rtt).abs();
                rtt_estimator.srtt = (1.0 - alpha) * rtt_estimator.srtt + alpha * sample_rtt;
            }

            // Calculate RTO
            let rto_ms = rtt_estimator.srtt + 4.0 * rtt_estimator.rttvar;
            rtt_estimator.rto = Duration::from_millis(rto_ms.max(200.0) as u64);
            // Min 200ms
        }

        rtt_estimator.last_measurement = Some(Timestamp::now());
    }

    /// Update congestion window
    async fn update_congestion_window(&self, cc: &mut CongestionControl, packet_loss: bool) {
        if packet_loss {
            // Packet loss detected
            cc.ssthresh = cc.cwnd / 2;
            cc.cwnd = cc.ssthresh;
            cc.state = CongestionState::FastRecovery;
        } else {
            match cc.state {
                CongestionState::SlowStart => {
                    cc.cwnd += 1;
                    if cc.cwnd >= cc.ssthresh {
                        cc.state = CongestionState::CongestionAvoidance;
                    }
                }
                CongestionState::CongestionAvoidance => {
                    cc.cwnd += 1 / cc.cwnd; // Additive increase
                }
                CongestionState::FastRecovery => {
                    cc.state = CongestionState::CongestionAvoidance;
                }
            }
        }
    }
}
