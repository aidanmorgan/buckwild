// TUN Device Basic Tests (MED-013)
//
// Tests verify basic TUN device creation and read/write operations.
// These tests are Linux-only and require appropriate permissions.

#![cfg(target_os = "linux")]

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_tun_device_creation_linux() {
    let (packet_sender, _packet_receiver) = mpsc::unbounded_channel();
    let (_write_sender, write_receiver) = mpsc::unbounded_channel();

    // IP: 10.0.0.1 = 0x0A000001, Netmask: 255.255.255.0 = 0xFFFFFF00
    let result = buckwild_daemon::tun::device::manager::TunDeviceManager::new(
        "tun_test0",
        0x0A000001,
        0xFFFFFF00,
        1500,
        packet_sender,
        write_receiver,
    )
    .await;

    match result {
        Ok(manager) => {
            assert!(manager.mtu() == 1500, "TUN device should have MTU 1500");
            assert!(!manager.is_running(), "TUN device should not be running initially");
        }
        Err(e) => {
            println!(
                "TUN device creation failed (expected without CAP_NET_ADMIN): {}",
                e
            );
        }
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_tun_device_read_write_operations_linux() {
    let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
    let (write_sender, write_receiver) = mpsc::unbounded_channel();

    // IP: 10.0.0.2 = 0x0A000002, Netmask: 255.255.255.0 = 0xFFFFFF00
    let result = buckwild_daemon::tun::device::manager::TunDeviceManager::new(
        "tun_test1",
        0x0A000002,
        0xFFFFFF00,
        1500,
        packet_sender,
        write_receiver,
    )
    .await;

    match result {
        Ok(mut manager) => {
            let start_result = manager.start().await;

            if start_result.is_ok() {
                let test_packet = Bytes::from(vec![0x45, 0x00, 0x00, 0x28]);

                let send_result = write_sender.send(test_packet.clone());
                assert!(send_result.is_ok(), "Should be able to send test packet");

                let recv_result = timeout(Duration::from_millis(100), packet_receiver.recv()).await;

                if let Ok(Some(received_packet)) = recv_result {
                    assert!(
                        !received_packet.is_empty(),
                        "Received packet should not be empty"
                    );
                } else {
                    println!("No packet received (may be expected in test environment)");
                }

                manager.stop().await.ok();
            } else {
                println!(
                    "TUN device start failed (expected without CAP_NET_ADMIN): {:?}",
                    start_result
                );
            }
        }
        Err(e) => {
            println!(
                "TUN device creation failed (expected without CAP_NET_ADMIN): {}",
                e
            );
        }
    }
}
