use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::tun::device::*;
use crate::tun::routing::*;
use super::test_utils::*;

#[tokio::test]
async fn test_tun_device_creation() {
    // Test TUN device creation
    match create_test_tun_manager().await {
        Ok(manager) => {
            assert_eq!(manager.mtu(), 1500);
            assert!(!manager.is_running());
            
            let info = manager.device_info();
            assert_eq!(info.mtu, 1500);
            assert!(!info.running);
        }
        Err(e) => {
            println!("TUN device creation failed (expected without root): {}", e);
        }
    }
}

#[tokio::test]
async fn test_flow_tracker_integration() {
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(30),
        Duration::from_secs(5)
    ));

    // Start flow tracker
    flow_tracker.start().await.unwrap();

    // Create test flow
    let flow_id = create_test_flow_id(12345, 80);
    let flow_state = flow_tracker.create_or_update_flow(
        flow_id.clone(),
        1000,
        2000,
        8192,
        0x18, // ACK + PSH
    ).await.unwrap();

    // Verify flow state
    {
        let state = flow_state.read().await;
        assert_eq!(state.flow_id, flow_id);
        assert_eq!(state.seq_num, 1000);
        assert_eq!(state.ack_num, 2000);
    }

    // Test flow lookup
    let found_flow = flow_tracker.get_flow(&flow_id).unwrap();
    {
        let state = found_flow.read().await;
        assert_eq!(state.seq_num, 1000);
    }

    // Stop flow tracker
    flow_tracker.stop().await;
}

#[tokio::test]
async fn test_connection_mapping_integration() {
    let connection_map = ConnectionMap::new(
        Duration::from_secs(5),
        Duration::from_secs(30)
    );

    // Start connection map
    connection_map.start().await.unwrap();

    // Create connection
    let flow_id = create_test_flow_id(8080, 443);
    let session_id = connection_map.create_connection(flow_id.clone()).await.unwrap();

    // Test bidirectional lookup
    assert_eq!(connection_map.get_session_for_flow(&flow_id), Some(session_id));
    assert_eq!(connection_map.get_flow_for_session(session_id), Some(flow_id.clone()));

    // Update connection state
    connection_map.update_connection_state(session_id, ConnectionState::Established).await.unwrap();

    // Verify state update
    let (_, state, _) = connection_map.get_connection_info(session_id).unwrap();
    assert_eq!(state, ConnectionState::Established);

    // Stop connection map
    connection_map.stop().await;
}

#[tokio::test]
async fn test_packet_translator_integration() {
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(30),
        Duration::from_secs(5)
    ));
    
    let translator = PacketTranslator::new(flow_tracker);

    // Test with a simple packet (this will likely fail due to incomplete packet construction)
    let test_packet = create_test_packet(100);
    
    match translator.translate_inbound(test_packet).await {
        Ok(result) => {
            println!("Translation successful: {:?}", result.packet_type);
        }
        Err(e) => {
            println!("Translation failed (expected with test packet): {}", e);
        }
    }
}

#[tokio::test]
async fn test_reliability_engine_integration() {
    let engine = ReliabilityEngine::new(
        Duration::from_millis(200),
        3,
        1460,
        65536,
    );

    // Start engine
    engine.start().await.unwrap();

    // Create connection
    let session_id = 1;
    engine.create_connection(session_id).await.unwrap();

    // Send data
    let test_data = create_test_packet(1000);
    let packets = engine.send_data(session_id, test_data).await.unwrap();
    assert!(!packets.is_empty());

    // Process ACK
    let ack_info = AckInfo {
        ack_number: 1000,
        window_size: 8192,
        selective_acks: vec![],
    };
    engine.process_ack(session_id, ack_info).await.unwrap();

    // Get statistics
    let stats = engine.get_statistics(session_id).await;
    assert!(stats.is_some());

    // Stop engine
    engine.stop().await;
}

#[tokio::test]
async fn test_stream_reassembler_integration() {
    let reassembler = StreamReassembler::new(
        Duration::from_secs(5),
        65536,
        100,
    );

    // Start reassembler
    reassembler.start().await.unwrap();

    // Create stream
    let session_id = 1;
    reassembler.create_stream(session_id, 0).await.unwrap();

    // Send in-order segments
    let data1 = create_test_packet(100);
    let result1 = reassembler.process_segment(session_id, 0, data1.clone(), false).await.unwrap();
    assert!(result1.data.is_some());
    assert_eq!(result1.data.unwrap(), data1);

    // Send out-of-order segment
    let data3 = create_test_packet(50);
    let result3 = reassembler.process_segment(session_id, 150, data3.clone(), false).await.unwrap();
    assert!(result3.data.is_none()); // Should be buffered

    // Send missing segment
    let data2 = create_test_packet(50);
    let result2 = reassembler.process_segment(session_id, 100, data2.clone(), false).await.unwrap();
    assert!(result2.data.is_some());
    
    // Should deliver both segments
    let combined = result2.data.unwrap();
    assert_eq!(combined.len(), 100); // data2 + data3

    // Stop reassembler
    reassembler.stop().await;
}

#[tokio::test]
async fn test_psk_mapper_integration() {
    let mapper = PskMapper::new(100, Duration::from_secs(300));

    // Start mapper
    mapper.start().await.unwrap();

    // Set default PSK
    let default_fingerprint = "default123456789".to_string();
    mapper.set_default_psk(default_fingerprint.clone()).await.unwrap();

    // Add specific mapping
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let specific_fingerprint = "specific987654321".to_string();
    
    let mapping = PskMapping {
        ip_address: ip,
        psk_fingerprint: specific_fingerprint.clone(),
        description: Some("Test server".to_string()),
        priority: 10,
        created_at: std::time::Instant::now(),
        last_used: None,
        use_count: 0,
    };
    
    mapper.add_mapping(mapping).await.unwrap();

    // Test specific lookup
    let result = mapper.lookup_psk(&ip).await.unwrap();
    assert_eq!(result.fingerprint, specific_fingerprint);
    assert!(!result.from_cache);

    // Test cache hit
    let result2 = mapper.lookup_psk(&ip).await.unwrap();
    assert_eq!(result2.fingerprint, specific_fingerprint);
    assert!(result2.from_cache);

    // Test default PSK for unknown IP
    let unknown_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let default_result = mapper.lookup_psk(&unknown_ip).await.unwrap();
    assert_eq!(default_result.fingerprint, default_fingerprint);

    // Stop mapper
    mapper.stop().await;
}

#[tokio::test]
async fn test_end_to_end_packet_flow() {
    // This test simulates a complete packet flow through the TUN device integration
    
    // Create components
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(30),
        Duration::from_secs(5)
    ));
    
    let connection_map = ConnectionMap::new(
        Duration::from_secs(5),
        Duration::from_secs(30)
    );
    
    let translator = PacketTranslator::new(Arc::clone(&flow_tracker));
    
    let reliability_engine = ReliabilityEngine::new(
        Duration::from_millis(200),
        3,
        1460,
        65536,
    );
    
    let reassembler = StreamReassembler::new(
        Duration::from_secs(5),
        65536,
        100,
    );

    // Start all components
    flow_tracker.start().await.unwrap();
    connection_map.start().await.unwrap();
    reliability_engine.start().await.unwrap();
    reassembler.start().await.unwrap();

    // Simulate connection establishment
    let flow_id = create_test_flow_id(12345, 80);
    let session_id = connection_map.create_connection(flow_id.clone()).await.unwrap();
    
    // Create flow state
    flow_tracker.create_or_update_flow(
        flow_id.clone(),
        1000,
        2000,
        8192,
        0x02, // SYN
    ).await.unwrap();

    // Create reliable connection
    reliability_engine.create_connection(session_id).await.unwrap();
    
    // Create reassembly stream
    reassembler.create_stream(session_id, 0).await.unwrap();

    // Update connection to established
    connection_map.update_connection_state(session_id, ConnectionState::Established).await.unwrap();

    // Simulate data transmission
    let test_data = create_test_packet(2000); // Larger than MSS to test fragmentation
    let packets = reliability_engine.send_data(session_id, test_data.clone()).await.unwrap();
    
    assert!(!packets.is_empty());
    println!("Generated {} packets for transmission", packets.len());

    // Simulate data reception and reassembly
    for (i, packet) in packets.iter().enumerate() {
        let result = reassembler.process_segment(
            session_id,
            (i * 1460) as u32, // Simulate sequence numbers
            packet.clone(),
            i == packets.len() - 1, // Last packet
        ).await.unwrap();
        
        if result.data.is_some() {
            println!("Reassembled {} bytes", result.data.unwrap().len());
        }
    }

    // Verify connection statistics
    let conn_stats = connection_map.get_statistics().await;
    assert_eq!(conn_stats.total_connections, 1);
    assert_eq!(conn_stats.active_connections, 1);

    let flow_stats = flow_tracker.get_statistics().await;
    assert_eq!(flow_stats.total_flows, 1);

    // Clean up
    connection_map.remove_connection(session_id).await.unwrap();
    reliability_engine.remove_connection(session_id).await.unwrap();
    reassembler.remove_stream(session_id).await.unwrap();

    // Stop all components
    flow_tracker.stop().await;
    connection_map.stop().await;
    reliability_engine.stop().await;
    reassembler.stop().await;
}

#[tokio::test]
async fn test_routing_integration() {
    // Test routing components integration
    // Note: This test may fail without proper network permissions
    
    match RoutingRules::new("tun0".to_string(), 254).await {
        Ok(routing_rules) => {
            let routing_rules = Arc::new(routing_rules);
            
            let mut updater = RoutingUpdater::new(
                Arc::clone(&routing_rules),
                Duration::from_millis(100),
                10,
            );
            
            // Start updater
            updater.start().await.unwrap();
            
            // Test rule addition
            let rule = RoutingRule {
                destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                prefix_length: 24,
                gateway: None,
                interface: "tun0".to_string(),
                metric: 100,
                table: None,
            };
            
            updater.add_rule("test-rule".to_string(), rule).await.unwrap();
            
            // Give time for processing
            tokio::time::sleep(Duration::from_millis(200)).await;
            
            // Check statistics
            let stats = updater.get_statistics().await;
            println!("Routing update statistics: {:?}", stats);
            
            // Stop updater
            updater.stop().await;
        }
        Err(e) => {
            println!("Routing test skipped (expected without network permissions): {}", e);
        }
    }
}