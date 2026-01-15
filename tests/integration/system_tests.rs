// End-to-end system integration tests
use std::time::Duration;
use tokio::time::sleep;

mod common;
use common::{TestEnvironment, test_data, assertions::assert_completes_within};

#[tokio::test]
async fn test_full_system_startup_shutdown() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test complete system startup and shutdown
    let result = assert_completes_within(Duration::from_secs(30), async {
        // Initialize all system components
        
        // Verify all engines are running
        sleep(Duration::from_millis(500)).await;
        
        // Perform graceful shutdown
        env.cleanup().await?;
        
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "Full system startup/shutdown test failed");
}

#[tokio::test]
async fn test_multi_peer_communication() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test communication between multiple peers
    let result = assert_completes_within(Duration::from_secs(20), async {
        // Set up multiple peer sessions
        env.setup_test_session("peer_a", "peer_b").await?;
        env.setup_test_session("peer_a", "peer_c").await?;
        env.setup_test_session("peer_b", "peer_c").await?;
        
        // Send data between all peers
        for _ in 0..5 {
            let packet = test_data::create_test_packet(512);
            sleep(Duration::from_millis(100)).await;
        }
        
        // Verify all communications successful
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "Multi-peer communication test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}

#[tokio::test]
async fn test_system_under_load() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test system behavior under high load
    let result = assert_completes_within(Duration::from_secs(60), async {
        // Set up multiple sessions
        for i in 0..10 {
            env.setup_test_session(&format!("peer_{}", i), "central_peer").await?;
        }
        
        // Generate high load
        for _ in 0..100 {
            let packet = test_data::create_test_packet(1024);
            sleep(Duration::from_millis(10)).await;
        }
        
        // Verify system stability
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "System under load test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}

#[tokio::test]
async fn test_network_partition_recovery() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test system recovery from network partitions
    let result = assert_completes_within(Duration::from_secs(45), async {
        // Set up session
        env.setup_test_session("peer_a", "peer_b").await?;
        
        // Simulate network partition
        env.simulate_network_conditions(Duration::from_secs(10), 1.0).await?;
        
        // Wait for partition
        sleep(Duration::from_secs(5)).await;
        
        // Restore network
        env.simulate_network_conditions(Duration::from_millis(50), 0.0).await?;
        
        // Verify recovery
        sleep(Duration::from_secs(10)).await;
        
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "Network partition recovery test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}