use std::net::{IpAddr, Ipv4Addr};
use bytes::Bytes;
use tokio::sync::mpsc;

use buckwild_daemon::tun::device::{TunDeviceManager, FlowId};

/// Create a test flow ID
pub fn create_test_flow_id(src_port: u16, dst_port: u16) -> FlowId {
    FlowId::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        src_port,
        dst_port,
        6, // TCP
    )
}

/// Create a test TUN device manager (may fail without root)
pub async fn create_test_tun_manager() -> Result<TunDeviceManager, Box<dyn std::error::Error>> {
    let (packet_sender, _packet_receiver) = mpsc::unbounded_channel();
    let (_write_sender, write_receiver) = mpsc::unbounded_channel();

    TunDeviceManager::new("test-tun", 1500, packet_sender, write_receiver).await
}

/// Create test packet data
pub fn create_test_packet(size: usize) -> Bytes {
    let data = vec![0x42; size]; // Fill with test pattern
    Bytes::from(data)
}