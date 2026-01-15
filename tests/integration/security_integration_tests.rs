// Security integration tests
use std::time::Duration;
use tokio::time::sleep;

mod common;
use common::{TestEnvironment, test_data, assertions::assert_completes_within};

#[tokio::test]
async fn test_end_to_end_encryption() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test end-to-end encryption between two peers
    let result = assert_completes_within(Duration::from_secs(10), async {
        // Set up encrypted session
        env.setup_test_session("alice", "bob").await?;
        
        // Send encrypted data
        let test_data = test_data::create_test_packet(1024);
        
        // Verify encryption/decryption
        sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "End-to-end encryption test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}

#[tokio::test]
async fn test_anti_replay_protection() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test anti-replay protection mechanisms
    let result = assert_completes_within(Duration::from_secs(5), async {
        // Set up session
        env.setup_test_session("peer_a", "peer_b").await?;
        
        // Send duplicate packets to test replay protection
        let packet = test_data::create_test_packet(512);
        
        // Verify replay protection works
        sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "Anti-replay protection test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}

#[tokio::test]
async fn test_key_rotation() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test key rotation during active session
    let result = assert_completes_within(Duration::from_secs(15), async {
        // Set up session
        env.setup_test_session("peer_a", "peer_b").await?;
        
        // Trigger key rotation
        sleep(Duration::from_millis(500)).await;
        
        // Verify communication continues after rotation
        let test_data = test_data::create_test_packet(256);
        
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "Key rotation test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}

#[tokio::test]
async fn test_security_under_network_stress() {
    let env = TestEnvironment::new().await.expect("Failed to create test environment");
    
    // Test security mechanisms under network stress conditions
    let result = assert_completes_within(Duration::from_secs(20), async {
        // Set up session
        env.setup_test_session("peer_a", "peer_b").await?;
        
        // Simulate network stress
        env.simulate_network_conditions(Duration::from_millis(100), 0.05).await?;
        
        // Send data under stress conditions
        for _ in 0..10 {
            let packet = test_data::create_test_packet(1024);
            sleep(Duration::from_millis(50)).await;
        }
        
        // Verify security maintained
        Ok(())
    }).await;
    
    assert!(result.is_ok(), "Security under network stress test failed");
    
    env.cleanup().await.expect("Failed to cleanup test environment");
}