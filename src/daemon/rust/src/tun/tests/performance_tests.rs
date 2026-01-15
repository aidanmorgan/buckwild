use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::tun::device::*;
use crate::tun::routing::*;
use super::test_utils::*;

#[tokio::test]
async fn test_flow_tracker_performance() {
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(30),
        Duration::from_secs(5)
    ));

    flow_tracker.start().await.unwrap();

    let start_time = Instant::now();
    let num_flows = 1000;

    // Create many flows concurrently
    let mut handles = Vec::new();
    for i in 0..num_flows {
        let tracker = Arc::clone(&flow_tracker);
        let handle = tokio::spawn(async move {
            let flow_id = create_test_flow_id((8000 + i) as u16, 80);
            tracker.create_or_update_flow(flow_id, 1000, 2000, 8192, 0x18).await
        });
        handles.push(handle);
    }

    // Wait for all flows to be created
    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    let creation_time = start_time.elapsed();
    println!("Created {} flows in {:?} ({:.2} flows/sec)", 
             num_flows, creation_time, num_flows as f64 / creation_time.as_secs_f64());

    // Test lookup performance
    let lookup_start = Instant::now();
    let mut lookup_count = 0;

    for i in 0..num_flows {
        let flow_id = create_test_flow_id((8000 + i) as u16, 80);
        if flow_tracker.get_flow(&flow_id).is_some() {
            lookup_count += 1;
        }
    }

    let lookup_time = lookup_start.elapsed();
    println!("Performed {} lookups in {:?} ({:.2} lookups/sec)", 
             lookup_count, lookup_time, lookup_count as f64 / lookup_time.as_secs_f64());

    assert_eq!(lookup_count, num_flows);

    flow_tracker.stop().await;
}

#[tokio::test]
async fn test_connection_mapping_performance() {
    let connection_map = ConnectionMap::new(
        Duration::from_secs(5),
        Duration::from_secs(30)
    );

    connection_map.start().await.unwrap();

    let start_time = Instant::now();
    let num_connections = 1000;

    // Create connections concurrently
    let mut handles = Vec::new();
    for i in 0..num_connections {
        let map = &connection_map;
        let handle = tokio::spawn(async move {
            let flow_id = create_test_flow_id((9000 + i) as u16, 443);
            map.create_connection(flow_id).await
        });
        handles.push(handle);
    }

    let mut session_ids = Vec::new();
    for handle in handles {
        let session_id = handle.await.unwrap().unwrap();
        session_ids.push(session_id);
    }

    let creation_time = start_time.elapsed();
    println!("Created {} connections in {:?} ({:.2} connections/sec)", 
             num_connections, creation_time, num_connections as f64 / creation_time.as_secs_f64());

    // Test bidirectional lookup performance
    let lookup_start = Instant::now();
    let mut successful_lookups = 0;

    for session_id in &session_ids {
        if let Some(flow_id) = connection_map.get_flow_for_session(*session_id) {
            if connection_map.get_session_for_flow(&flow_id).is_some() {
                successful_lookups += 1;
            }
        }
    }

    let lookup_time = lookup_start.elapsed();
    println!("Performed {} bidirectional lookups in {:?} ({:.2} lookups/sec)", 
             successful_lookups, lookup_time, successful_lookups as f64 / lookup_time.as_secs_f64());

    assert_eq!(successful_lookups, num_connections);

    connection_map.stop().await;
}

#[tokio::test]
async fn test_reliability_engine_performance() {
    let engine = ReliabilityEngine::new(
        Duration::from_millis(200),
        3,
        1460,
        65536,
    );

    engine.start().await.unwrap();

    let num_connections = 100;
    let packets_per_connection = 100;

    // Create connections
    for i in 0..num_connections {
        engine.create_connection(i as u64).await.unwrap();
    }

    let start_time = Instant::now();

    // Send data on all connections concurrently
    let mut handles = Vec::new();
    for i in 0..num_connections {
        let engine_ref = &engine;
        let handle = tokio::spawn(async move {
            let session_id = i as u64;
            let mut total_packets = 0;
            
            for _ in 0..packets_per_connection {
                let test_data = create_test_packet(1000);
                let packets = engine_ref.send_data(session_id, test_data).await.unwrap();
                total_packets += packets.len();
            }
            
            total_packets
        });
        handles.push(handle);
    }

    let mut total_packets_sent = 0;
    for handle in handles {
        total_packets_sent += handle.await.unwrap();
    }

    let send_time = start_time.elapsed();
    println!("Sent {} packets across {} connections in {:?} ({:.2} packets/sec)", 
             total_packets_sent, num_connections, send_time, 
             total_packets_sent as f64 / send_time.as_secs_f64());

    // Test ACK processing performance
    let ack_start = Instant::now();
    let mut acks_processed = 0;

    for i in 0..num_connections {
        let session_id = i as u64;
        for j in 0..packets_per_connection {
            let ack_info = AckInfo {
                ack_number: (j * 1000) as u32,
                window_size: 8192,
                selective_acks: vec![],
            };
            engine.process_ack(session_id, ack_info).await.unwrap();
            acks_processed += 1;
        }
    }

    let ack_time = ack_start.elapsed();
    println!("Processed {} ACKs in {:?} ({:.2} ACKs/sec)", 
             acks_processed, ack_time, acks_processed as f64 / ack_time.as_secs_f64());

    engine.stop().await;
}

#[tokio::test]
async fn test_stream_reassembler_performance() {
    let reassembler = StreamReassembler::new(
        Duration::from_secs(5),
        1024 * 1024, // 1MB buffer
        1000,
    );

    reassembler.start().await.unwrap();

    let num_streams = 50;
    let segments_per_stream = 200;

    // Create streams
    for i in 0..num_streams {
        reassembler.create_stream(i as u64, 0).await.unwrap();
    }

    let start_time = Instant::now();

    // Send segments to all streams concurrently
    let mut handles = Vec::new();
    for i in 0..num_streams {
        let reassembler_ref = &reassembler;
        let handle = tokio::spawn(async move {
            let session_id = i as u64;
            let mut segments_processed = 0;
            
            for j in 0..segments_per_stream {
                let data = create_test_packet(500);
                let sequence = (j * 500) as u32;
                let is_last = j == segments_per_stream - 1;
                
                let result = reassembler_ref.process_segment(
                    session_id, sequence, data, is_last
                ).await.unwrap();
                
                segments_processed += 1;
                
                if result.data.is_some() {
                    // Data was delivered
                }
            }
            
            segments_processed
        });
        handles.push(handle);
    }

    let mut total_segments = 0;
    for handle in handles {
        total_segments += handle.await.unwrap();
    }

    let processing_time = start_time.elapsed();
    println!("Processed {} segments across {} streams in {:?} ({:.2} segments/sec)", 
             total_segments, num_streams, processing_time, 
             total_segments as f64 / processing_time.as_secs_f64());

    // Test out-of-order performance
    let ooo_start = Instant::now();
    let test_session = 999u64;
    reassembler.create_stream(test_session, 0).await.unwrap();

    // Send segments out of order
    let ooo_segments = 100;
    for i in (0..ooo_segments).rev() { // Reverse order
        let data = create_test_packet(100);
        let sequence = (i * 100) as u32;
        reassembler.process_segment(test_session, sequence, data, false).await.unwrap();
    }

    let ooo_time = ooo_start.elapsed();
    println!("Processed {} out-of-order segments in {:?} ({:.2} segments/sec)", 
             ooo_segments, ooo_time, ooo_segments as f64 / ooo_time.as_secs_f64());

    reassembler.stop().await;
}

#[tokio::test]
async fn test_psk_mapper_performance() {
    let mapper = PskMapper::new(1000, Duration::from_secs(300));
    mapper.start().await.unwrap();

    let num_mappings = 1000;

    // Create mappings
    let creation_start = Instant::now();
    let mut mappings = std::collections::HashMap::new();
    
    for i in 0..num_mappings {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, (i / 256) as u8, (i % 256) as u8
        ));
        
        let mapping = PskMapping {
            ip_address: ip,
            psk_fingerprint: format!("fingerprint{:08x}", i),
            description: Some(format!("Server {}", i)),
            priority: i as u32,
            created_at: std::time::Instant::now(),
            last_used: None,
            use_count: 0,
        };
        
        mappings.insert(ip, mapping);
    }

    let updated_ips = mapper.update_mappings_batch(mappings).await.unwrap();
    let creation_time = creation_start.elapsed();
    
    println!("Created {} PSK mappings in {:?} ({:.2} mappings/sec)", 
             updated_ips.len(), creation_time, 
             updated_ips.len() as f64 / creation_time.as_secs_f64());

    // Test lookup performance (cold cache)
    let lookup_start = Instant::now();
    let mut successful_lookups = 0;

    for i in 0..num_mappings {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, (i / 256) as u8, (i % 256) as u8
        ));
        
        if mapper.lookup_psk(&ip).await.is_ok() {
            successful_lookups += 1;
        }
    }

    let cold_lookup_time = lookup_start.elapsed();
    println!("Performed {} cold lookups in {:?} ({:.2} lookups/sec)", 
             successful_lookups, cold_lookup_time, 
             successful_lookups as f64 / cold_lookup_time.as_secs_f64());

    // Test lookup performance (warm cache)
    let warm_lookup_start = Instant::now();
    let mut warm_successful_lookups = 0;

    for i in 0..num_mappings {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, (i / 256) as u8, (i % 256) as u8
        ));
        
        if mapper.lookup_psk(&ip).await.is_ok() {
            warm_successful_lookups += 1;
        }
    }

    let warm_lookup_time = warm_lookup_start.elapsed();
    println!("Performed {} warm lookups in {:?} ({:.2} lookups/sec)", 
             warm_successful_lookups, warm_lookup_time, 
             warm_successful_lookups as f64 / warm_lookup_time.as_secs_f64());

    // Verify cache performance improvement
    let speedup = cold_lookup_time.as_nanos() as f64 / warm_lookup_time.as_nanos() as f64;
    println!("Cache speedup: {:.2}x", speedup);

    let stats = mapper.get_statistics().await;
    println!("PSK mapper statistics: {:?}", stats);

    mapper.stop().await;
}

#[tokio::test]
async fn test_memory_usage_under_load() {
    // Test memory usage patterns under high load
    
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(30),
        Duration::from_secs(5)
    ));
    
    let connection_map = ConnectionMap::new(
        Duration::from_secs(5),
        Duration::from_secs(30)
    );
    
    let reassembler = StreamReassembler::new(
        Duration::from_secs(5),
        1024 * 1024, // 1MB buffer
        1000,
    );

    // Start components
    flow_tracker.start().await.unwrap();
    connection_map.start().await.unwrap();
    reassembler.start().await.unwrap();

    let num_connections = 500;
    let data_per_connection = 10240; // 10KB

    println!("Starting memory usage test with {} connections", num_connections);

    let start_time = Instant::now();

    // Create connections and send data
    for i in 0..num_connections {
        let flow_id = create_test_flow_id((10000 + i) as u16, 80);
        let session_id = connection_map.create_connection(flow_id.clone()).await.unwrap();
        
        flow_tracker.create_or_update_flow(
            flow_id, 1000, 2000, 8192, 0x18
        ).await.unwrap();
        
        reassembler.create_stream(session_id, 0).await.unwrap();
        
        // Send fragmented data
        let mut sequence = 0u32;
        let mut remaining = data_per_connection;
        
        while remaining > 0 {
            let chunk_size = std::cmp::min(remaining, 1000);
            let data = create_test_packet(chunk_size);
            
            reassembler.process_segment(
                session_id, sequence, data, remaining == chunk_size
            ).await.unwrap();
            
            sequence += chunk_size as u32;
            remaining -= chunk_size;
        }
    }

    let setup_time = start_time.elapsed();
    println!("Setup completed in {:?}", setup_time);

    // Get statistics
    let flow_stats = flow_tracker.get_statistics().await;
    let conn_stats = connection_map.get_statistics().await;
    let reassembly_stats = reassembler.get_global_statistics().await;

    println!("Flow tracker: {} flows", flow_stats.total_flows);
    println!("Connection map: {} connections", conn_stats.total_connections);
    println!("Reassembler: {} streams, {} bytes buffered", 
             reassembly_stats.active_streams, reassembly_stats.total_bytes_buffered);

    // Clean up
    flow_tracker.stop().await;
    connection_map.stop().await;
    reassembler.stop().await;

    let total_time = start_time.elapsed();
    println!("Memory usage test completed in {:?}", total_time);
}