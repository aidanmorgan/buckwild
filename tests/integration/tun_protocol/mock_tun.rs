//! Mock TUN Device for Integration Testing
//!
//! This module provides a mock TUN device that simulates a real TUN interface
//! without requiring actual kernel privileges or network configuration.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, Context};

use buckwild_common::protocol::types::*;
use crate::protocol_helpers::{parse_protocol_packet, ParsedPacket};

/// Mock TUN device for testing
///
/// This simulates a TUN device by:
/// - Accepting injected packets (simulates packets arriving from network)
/// - Queuing packets for reading (simulates read from TUN device)
/// - Parsing packets according to protocol specification
pub struct MockTunDevice {
    /// Device name (e.g., "test0")
    name: String,

    /// Queue of packets waiting to be read
    packet_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,

    /// Optional PSK for HMAC validation
    psk: Option<Psk>,

    /// Statistics
    stats: Arc<Mutex<MockTunStats>>,
}

/// Statistics for mock TUN device
#[derive(Debug, Default)]
struct MockTunStats {
    packets_injected: usize,
    packets_read: usize,
    parse_errors: usize,
}

impl MockTunDevice {
    /// Create a new mock TUN device without PSK
    pub async fn new(name: &str) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            packet_queue: Arc::new(Mutex::new(VecDeque::new())),
            psk: None,
            stats: Arc::new(Mutex::new(MockTunStats::default())),
        })
    }

    /// Create a new mock TUN device with PSK for authentication
    pub async fn new_with_psk(name: &str, psk: Psk) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            packet_queue: Arc::new(Mutex::new(VecDeque::new())),
            psk: Some(psk),
            stats: Arc::new(Mutex::new(MockTunStats::default())),
        })
    }

    /// Inject a packet into the mock TUN device
    ///
    /// This simulates a packet arriving on the network interface.
    /// The packet will be queued for reading.
    pub async fn inject_packet(&self, packet: &[u8]) -> Result<()> {
        let mut queue = self.packet_queue.lock().await;
        queue.push_back(packet.to_vec());

        let mut stats = self.stats.lock().await;
        stats.packets_injected += 1;

        Ok(())
    }

    /// Inject raw bytes into the mock TUN device
    ///
    /// Alias for inject_packet for clarity in tests
    pub async fn inject_raw_bytes(&self, bytes: &[u8]) -> Result<()> {
        self.inject_packet(bytes).await
    }

    /// Read and parse the next packet from the queue
    ///
    /// This simulates reading from a TUN device and parsing the packet
    /// according to the protocol specification.
    ///
    /// Returns None if queue is empty (would block on real TUN device)
    pub async fn read_parsed_packet(&self) -> Result<ParsedPacket> {
        // Get next packet from queue
        let packet_bytes = {
            let mut queue = self.packet_queue.lock().await;
            queue.pop_front()
                .context("No packets in queue")?
        };

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.packets_read += 1;
        }

        // Parse packet according to protocol specification
        match parse_protocol_packet(&packet_bytes) {
            Ok(parsed) => {
                // If we have a PSK, verify HMAC for authenticated packets
                if let Some(ref psk) = self.psk {
                    // Note: HMAC validation is done in ParsedPacket.validate_hmac()
                    // We just make PSK available for tests
                }
                Ok(parsed)
            }
            Err(e) => {
                let mut stats = self.stats.lock().await;
                stats.parse_errors += 1;
                Err(e).context("Failed to parse packet")
            }
        }
    }

    /// Get device name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get current packet queue length
    pub async fn queue_length(&self) -> usize {
        let queue = self.packet_queue.lock().await;
        queue.len()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> MockTunStatsSnapshot {
        let stats = self.stats.lock().await;
        MockTunStatsSnapshot {
            packets_injected: stats.packets_injected,
            packets_read: stats.packets_read,
            parse_errors: stats.parse_errors,
        }
    }

    /// Clear the packet queue
    pub async fn clear_queue(&self) {
        let mut queue = self.packet_queue.lock().await;
        queue.clear();
    }
}

/// Snapshot of mock TUN statistics
#[derive(Debug, Clone)]
pub struct MockTunStatsSnapshot {
    pub packets_injected: usize,
    pub packets_read: usize,
    pub parse_errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_tun_creation() {
        let tun = MockTunDevice::new("test0").await.unwrap();
        assert_eq!(tun.name(), "test0");
        assert_eq!(tun.queue_length().await, 0);
    }

    #[tokio::test]
    async fn test_mock_tun_packet_injection() {
        let tun = MockTunDevice::new("test0").await.unwrap();

        let packet = vec![0x01, 0x02, 0x03, 0x04];
        tun.inject_packet(&packet).await.unwrap();

        assert_eq!(tun.queue_length().await, 1);

        let stats = tun.get_stats().await;
        assert_eq!(stats.packets_injected, 1);
    }

    #[tokio::test]
    async fn test_mock_tun_multiple_packets() {
        let tun = MockTunDevice::new("test0").await.unwrap();

        tun.inject_packet(&[0x01]).await.unwrap();
        tun.inject_packet(&[0x02]).await.unwrap();
        tun.inject_packet(&[0x03]).await.unwrap();

        assert_eq!(tun.queue_length().await, 3);
    }

    #[tokio::test]
    async fn test_mock_tun_clear_queue() {
        let tun = MockTunDevice::new("test0").await.unwrap();

        tun.inject_packet(&[0x01]).await.unwrap();
        tun.inject_packet(&[0x02]).await.unwrap();

        assert_eq!(tun.queue_length().await, 2);

        tun.clear_queue().await;
        assert_eq!(tun.queue_length().await, 0);
    }
}
