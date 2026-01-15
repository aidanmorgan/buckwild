use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::tempdir;
use tokio::time::sleep;

use buckwild_daemon::config::psk::directory::{PskDirectoryConfig, PskDirectoryMonitor};
use buckwild_daemon::config::psk::fingerprint::FingerprintCalculator;

#[tokio::test]
async fn test_psk_directory_monitor() {
    // Create temporary directory
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Create fingerprint calculator
    let fingerprint_calculator = Arc::new(FingerprintCalculator::new(2));
    
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
    sleep(Duration::from_millis(200)).await;
    
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
    sleep(Duration::from_millis(200)).await;
    
    // Check that both PSKs were loaded
    assert_eq!(monitor.psk_count(), 2);
    
    // Remove PSK file
    fs::remove_file(&psk_path).unwrap();
    
    // Wait for processing
    sleep(Duration::from_millis(200)).await;
    
    // Check that PSK was removed
    assert_eq!(monitor.psk_count(), 1);
}

#[tokio::test]
async fn test_psk_fingerprint() {
    // Create temporary directory
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Create fingerprint calculator
    let fingerprint_calculator = Arc::new(FingerprintCalculator::new(2));
    
    // Create monitor
    let config = PskDirectoryConfig {
        base_dir: temp_path.to_path_buf(),
        debounce_ms: 100,
        recursive: true,
    };
    
    let mut monitor = PskDirectoryMonitor::new(config, fingerprint_calculator.clone()).unwrap();
    monitor.start_watching().unwrap();
    
    // Create PSK files with different content
    let psk1_path = temp_path.join("test1.psk");
    let psk2_path = temp_path.join("test2.psk");
    
    let mut file = File::create(&psk1_path).unwrap();
    file.write_all(b"test psk data 1").unwrap();
    
    let mut file = File::create(&psk2_path).unwrap();
    file.write_all(b"test psk data 2").unwrap();
    
    // Wait for processing
    sleep(Duration::from_millis(200)).await;
    
    // Check that both PSKs were loaded
    assert_eq!(monitor.psk_count(), 2);
    
    // Get fingerprints
    let fingerprints = monitor.get_all_fingerprints();
    assert_eq!(fingerprints.len(), 2);
    
    // Fingerprints should be different
    assert_ne!(fingerprints[0], fingerprints[1]);
}

#[tokio::test]
async fn test_psk_directory_non_psk_files() {
    // Create temporary directory
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Create fingerprint calculator
    let fingerprint_calculator = Arc::new(FingerprintCalculator::new(2));
    
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
    
    // Create non-PSK file
    let non_psk_path = temp_path.join("test.txt");
    let mut file = File::create(&non_psk_path).unwrap();
    file.write_all(b"not a psk file").unwrap();
    
    // Wait for processing
    sleep(Duration::from_millis(200)).await;
    
    // Check that only PSK file was loaded
    assert_eq!(monitor.psk_count(), 1);
}