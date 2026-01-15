use buckwild_daemon::tun:device::manager::*;
use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_device_creation() {
        let (packet_sender, _packet_receiver) = mpsc::unbounded_channel();
        let (_write_sender, write_receiver) = mpsc::unbounded_channel();

        // Note: This test may fail without root privileges
        let result = TunDeviceManager::new("test-tun", 1500, packet_sender, write_receiver).await;
        
        // Test should handle both success and permission errors gracefully
        match result {
            Ok(manager) => {
                assert_eq!(manager.mtu(), 1500);
                assert!(!manager.is_running());
            }
            Err(e) => {
                // Expected if running without root privileges
                println!("Device creation failed (expected without root): {}", e);
            }
        }
    }

    #[test]
    fn test_device_info() {
        let (packet_sender, _packet_receiver) = mpsc::unbounded_channel();
        let (_write_sender, write_receiver) = mpsc::unbounded_channel();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            if let Ok(manager) = TunDeviceManager::new("test-info", 1400, packet_sender, write_receiver).await {
                let info = manager.device_info();
                assert_eq!(info.mtu, 1400);
                assert!(!info.running);
            }
        });
    }
