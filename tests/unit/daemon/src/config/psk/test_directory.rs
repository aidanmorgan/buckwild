use buckwild_daemon::config:psk::directory::*;
use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_psk_directory_monitor() {
        // Create temporary directory
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        
        // Create fingerprint calculator
        let fingerprint_calculator = Arc::new(
            crate::config::psk::fingerprint::FingerprintCalculator::new(4)
        );
        
        // Create monitor
        let config = PskDirectoryConfig {
            base_dir: temp_path.to_path_buf(),
            debounce_ms: 100,
            recursive: true,
        };
        
        let mut monitor = PskDirectoryMonitor::new(config, fingerprint_calculator).unwrap();
        monitor.start_watching().unwrap();
        
        // Create PSK file
        let psk_path = temp_path.join("test.psk");
        let mut file = File::create(&psk_path).unwrap();
        file.write_all(b"test psk data").unwrap();
        
        // Wait for processing
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Check that PSK was loaded
        assert_eq!(monitor.psk_count(), 1);
        
        // Create subdirectory
        let subdir_path = temp_path.join("subdir");
        fs::create_dir(&subdir_path).unwrap();
        
        // Create PSK in subdirectory
        let subdir_psk_path = subdir_path.join("subdir.psk");
        let mut file = File::create(&subdir_psk_path).unwrap();
        file.write_all(b"subdir psk data").unwrap();
        
        // Wait for processing
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Check that both PSKs were loaded
        assert_eq!(monitor.psk_count(), 2);
        
        // Remove PSK file
        fs::remove_file(&psk_path).unwrap();
        
        // Wait for processing
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Check that PSK was removed
        assert_eq!(monitor.psk_count(), 1);
    }
