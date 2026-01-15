use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::tun::device::*;
use crate::tun::routing::*;
use super::test_utils::*;

#[tokio::test]
async fn test_concurrent_flow_operations() {
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(30),
        Duration::from_secs(5)
    ));

    flow_tracker.start().await.unwrap();

    let num_threads = 10;
    let operations_per_thread = 100;
    let total_operations = num_threads * operations_per_thread;

    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));

    println!("Starting concurrent flow operations test: {} threads, {} ops/thread", 
             num_threads, operations_per_thread);

    let start_time = Instant::now();

    // Spawn concurrent tasks
    let mut handles = Vec::new();
    for thread_id in 0..num_threads {
        let tracker = Arc::clone(&flow_tracker);
        let success_counter = Arc::clone(&success_counter);
        let error_counter = Arc::clone(&error_counter);

        let handle = tokio::spawn(async move {
            for op_id in 0..operations_per_thread {
                let port = (thread_id * 1000 + op_id) as u16;
                let flow_id = create_test_flow_id(port, 80);

                // Create flow
                match tracker.create_or_update_flow(
                    flow_id.clone(), 1000, 2000, 8192, 0x18
                ).await {
                    Ok(_) => {
                        success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        
                        // Immediately try to lookup
                        if tracker.get_flow(&flow_id).is_some() {
                            success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Small delay to increase contention
                if op_id % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start_time.elapsed();
    let successes = success_counter.load(Ordering::Relaxed);
    let errors = error_counter.load(Ordering::Relaxed);

    println!("Concurrent flow operations completed in {:?}", elapsed);
    println!("Successes: {}, Errors: {}, Total: {}", successes, errors, successes + errors);
    println!("Success rate: {:.2}%", (successes as f64 / (successes + errors) as f64) * 100.0);
    println!("Operations/sec: {:.2}", (successes + errors) as f64 / elapsed.as_secs_f64());

    // Verify final state
    let final_stats = flow_tracker.get_statistics().await;
    println!("Final flow count: {}", final_stats.total_flows);

    flow_tracker.stop().await;
}

#[tokio::test]
async fn test_connection_mapping_stress() {
    let connection_map = ConnectionMap::new(
        Duration::from_secs(5),
        Duration::from_secs(30)
    );

    connection_map.start().await.unwrap();

    let num_concurrent_connections = 1000;
    let operations_per_connection = 50;

    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));

    println!("Starting connection mapping stress test: {} connections, {} ops/connection", 
             num_concurrent_connections, operations_per_connection);

    let start_time = Instant::now();

    // Create connections concurrently
    let mut connection_handles = Vec::new();
    for i in 0..num_concurrent_connections {
        let map = &connection_map;
        let success_counter = Arc::clone(&success_counter);
        let error_counter = Arc::clone(&error_counter);

        let handle = tokio::spawn(async move {
            let flow_id = create_test_flow_id((20000 + i) as u16, 443);
            
            match map.create_connection(flow_id.clone()).await {
                Ok(session_id) => {
                    success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    
                    // Perform multiple operations on this connection
                    for _ in 0..operations_per_connection {
                        // Test bidirectional lookup
                        if map.get_session_for_flow(&flow_id).is_some() &&
                           map.get_flow_for_session(session_id).is_some() {
                            success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        }

                        // Update connection state
                        if map.update_connection_state(session_id, ConnectionState::Established).await.is_ok() {
                            success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        }

                        // Update statistics
                        if map.update_connection_stats(session_id, 1024, 1).await.is_ok() {
                            success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        }

                        tokio::task::yield_now().await;
                    }
                    
                    session_id
                }
                Err(_) => {
                    error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    0 // Dummy session ID
                }
            }
        });
        connection_handles.push(handle);
    }

    // Wait for all connections to be processed
    let mut session_ids = Vec::new();
    for handle in connection_handles {
        let session_id = handle.await.unwrap();
        if session_id != 0 {
            session_ids.push(session_id);
        }
    }

    let elapsed = start_time.elapsed();
    let successes = success_counter.load(Ordering::Relaxed);
    let errors = error_counter.load(Ordering::Relaxed);

    println!("Connection mapping stress test completed in {:?}", elapsed);
    println!("Successes: {}, Errors: {}, Total: {}", successes, errors, successes + errors);
    println!("Success rate: {:.2}%", (successes as f64 / (successes + errors) as f64) * 100.0);

    // Verify final statistics
    let final_stats = connection_map.get_statistics().await;
    println!("Final connection count: {}", final_stats.total_connections);
    println!("Active connections: {}", final_stats.active_connections);

    // Clean up connections
    let cleanup_start = Instant::now();
    for session_id in session_ids {
        connection_map.remove_connection(session_id).await.unwrap();
    }
    let cleanup_time = cleanup_start.elapsed();
    println!("Cleanup completed in {:?}", cleanup_time);

    connection_map.stop().await;
}

#[tokio::test]
async fn test_reliability_engine_under_load() {
    let engine = ReliabilityEngine::new(
        Duration::from_millis(100), // Aggressive timeout for stress testing
        5, // More retries
        1460,
        65536,
    );

    engine.start().await.unwrap();

    let num_connections = 100;
    let packets_per_connection = 200;
    let packet_size = 1000;

    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));

    println!("Starting reliability engine stress test: {} connections, {} packets/connection", 
             num_connections, packets_per_connection);

    // Create all connections first
    for i in 0..num_connections {
        engine.create_connection(i as u64).await.unwrap();
    }

    let start_time = Instant::now();

    // Send data on all connections concurrently
    let mut send_handles = Vec::new();
    for i in 0..num_connections {
        let engine_ref = &engine;
        let success_counter = Arc::clone(&success_counter);
        let error_counter = Arc::clone(&error_counter);

        let handle = tokio::spawn(async move {
            let session_id = i as u64;
            
            for packet_id in 0..packets_per_connection {
                let test_data = create_test_packet(packet_size);
                
                match engine_ref.send_data(session_id, test_data).await {
                    Ok(packets) => {
                        success_counter.fetch_add(packets.len() as u64, Ordering::Relaxed);
                    }
                    Err(_) => {
                        error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Simulate some ACKs
                if packet_id % 10 == 0 {
                    let ack_info = AckInfo {
                        ack_number: (packet_id * packet_size) as u32,
                        window_size: 8192,
                        selective_acks: vec![],
                    };
                    
                    if engine_ref.process_ack(session_id, ack_info).await.is_ok() {
                        success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Yield occasionally to increase contention
                if packet_id % 20 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        send_handles.push(handle);
    }

    // Wait for all sending to complete
    for handle in send_handles {
        handle.await.unwrap();
    }

    let elapsed = start_time.elapsed();
    let successes = success_counter.load(Ordering::Relaxed);
    let errors = error_counter.load(Ordering::Relaxed);

    println!("Reliability engine stress test completed in {:?}", elapsed);
    println!("Successes: {}, Errors: {}, Total: {}", successes, errors, successes + errors);
    println!("Success rate: {:.2}%", (successes as f64 / (successes + errors) as f64) * 100.0);
    println!("Packets/sec: {:.2}", successes as f64 / elapsed.as_secs_f64());

    // Test statistics collection under load
    let stats_start = Instant::now();
    let mut total_stats_collected = 0;
    
    for i in 0..num_connections {
        if engine.get_statistics(i as u64).await.is_some() {
            total_stats_collected += 1;
        }
    }
    
    let stats_time = stats_start.elapsed();
    println!("Collected {} statistics in {:?}", total_stats_collected, stats_time);

    engine.stop().await;
}

#[tokio::test]
async fn test_stream_reassembler_fragmentation_stress() {
    let reassembler = StreamReassembler::new(
        Duration::from_secs(10),
        2 * 1024 * 1024, // 2MB buffer
        2000, // Allow many out-of-order segments
    );

    reassembler.start().await.unwrap();

    let num_streams = 50;
    let segments_per_stream = 500;
    let segment_size = 200;

    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));
    let delivered_bytes = Arc::new(AtomicU64::new(0));

    println!("Starting stream reassembler fragmentation stress test: {} streams, {} segments/stream", 
             num_streams, segments_per_stream);

    // Create all streams
    for i in 0..num_streams {
        reassembler.create_stream(i as u64, 0).await.unwrap();
    }

    let start_time = Instant::now();

    // Send segments in random order to stress reassembly
    let mut reassembly_handles = Vec::new();
    for stream_id in 0..num_streams {
        let reassembler_ref = &reassembler;
        let success_counter = Arc::clone(&success_counter);
        let error_counter = Arc::clone(&error_counter);
        let delivered_bytes = Arc::clone(&delivered_bytes);

        let handle = tokio::spawn(async move {
            let session_id = stream_id as u64;
            
            // Create segments in reverse order to maximize out-of-order processing
            for segment_id in (0..segments_per_stream).rev() {
                let data = create_test_packet(segment_size);
                let sequence = (segment_id * segment_size) as u32;
                let is_last = segment_id == segments_per_stream - 1;
                
                match reassembler_ref.process_segment(
                    session_id, sequence, data, is_last
                ).await {
                    Ok(result) => {
                        success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                        
                        if let Some(delivered_data) = result.data {
                            delivered_bytes.fetch_add(delivered_data.len() as u64, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Yield to increase contention
                if segment_id % 50 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        reassembly_handles.push(handle);
    }

    // Wait for all reassembly to complete
    for handle in reassembly_handles {
        handle.await.unwrap();
    }

    let elapsed = start_time.elapsed();
    let successes = success_counter.load(Ordering::Relaxed);
    let errors = error_counter.load(Ordering::Relaxed);
    let total_delivered = delivered_bytes.load(Ordering::Relaxed);

    println!("Stream reassembler stress test completed in {:?}", elapsed);
    println!("Successes: {}, Errors: {}, Total: {}", successes, errors, successes + errors);
    println!("Success rate: {:.2}%", (successes as f64 / (successes + errors) as f64) * 100.0);
    println!("Segments/sec: {:.2}", successes as f64 / elapsed.as_secs_f64());
    println!("Delivered bytes: {}, Rate: {:.2} MB/sec", 
             total_delivered, total_delivered as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0);

    // Force delivery of any remaining buffered data
    let force_delivery_start = Instant::now();
    let mut force_delivered_bytes = 0u64;
    
    for i in 0..num_streams {
        if let Ok(Some(data)) = reassembler.force_delivery(i as u64).await {
            force_delivered_bytes += data.len() as u64;
        }
    }
    
    let force_delivery_time = force_delivery_start.elapsed();
    println!("Force delivered {} bytes in {:?}", force_delivered_bytes, force_delivery_time);

    // Check final statistics
    let final_stats = reassembler.get_global_statistics().await;
    println!("Final reassembler stats: {:?}", final_stats);

    reassembler.stop().await;
}

#[tokio::test]
async fn test_integrated_system_stress() {
    // Comprehensive stress test of all components working together
    
    let flow_tracker = Arc::new(FlowTracker::new(
        Duration::from_secs(60),
        Duration::from_secs(10)
    ));
    
    let connection_map = ConnectionMap::new(
        Duration::from_secs(10),
        Duration::from_secs(60)
    );
    
    let reliability_engine = ReliabilityEngine::new(
        Duration::from_millis(500),
        3,
        1460,
        65536,
    );
    
    let reassembler = StreamReassembler::new(
        Duration::from_secs(10),
        4 * 1024 * 1024, // 4MB buffer
        1000,
    );

    let psk_mapper = PskMapper::new(1000, Duration::from_secs(300));

    println!("Starting integrated system stress test");

    // Start all components
    flow_tracker.start().await.unwrap();
    connection_map.start().await.unwrap();
    reliability_engine.start().await.unwrap();
    reassembler.start().await.unwrap();
    psk_mapper.start().await.unwrap();

    let num_connections = 200;
    let data_per_connection = 50000; // 50KB per connection
    let fragment_size = 1000;

    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));
    let bytes_processed = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();

    // Create connections and process data
    let mut integration_handles = Vec::new();
    for i in 0..num_connections {
        let flow_tracker = Arc::clone(&flow_tracker);
        let connection_map = &connection_map;
        let reliability_engine = &reliability_engine;
        let reassembler = &reassembler;
        let psk_mapper = &psk_mapper;
        let success_counter = Arc::clone(&success_counter);
        let error_counter = Arc::clone(&error_counter);
        let bytes_processed = Arc::clone(&bytes_processed);

        let handle = tokio::spawn(async move {
            let port = (30000 + i) as u16;
            let flow_id = create_test_flow_id(port, 80);
            
            // Create flow
            let flow_result = flow_tracker.create_or_update_flow(
                flow_id.clone(), 1000, 2000, 8192, 0x02
            ).await;
            
            if flow_result.is_err() {
                error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                return;
            }

            // Create connection mapping
            let session_id = match connection_map.create_connection(flow_id.clone()).await {
                Ok(id) => {
                    success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    id
                }
                Err(_) => {
                    error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };

            // Create reliable connection
            if reliability_engine.create_connection(session_id).await.is_err() {
                error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                return;
            }

            // Create reassembly stream
            if reassembler.create_stream(session_id, 0).await.is_err() {
                error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                return;
            }

            // Add PSK mapping
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, (i / 256) as u8, (i % 256) as u8
            ));
            
            let psk_mapping = PskMapping {
                ip_address: ip,
                psk_fingerprint: format!("stress_test_{:08x}", i),
                description: Some(format!("Stress test connection {}", i)),
                priority: i as u32,
                created_at: std::time::Instant::now(),
                last_used: None,
                use_count: 0,
            };
            
            if psk_mapper.add_mapping(psk_mapping).await.is_ok() {
                success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
            } else {
                error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
            }

            // Update connection to established
            if connection_map.update_connection_state(session_id, ConnectionState::Established).await.is_ok() {
                success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
            }

            // Send data through reliability engine
            let mut remaining_data = data_per_connection;
            let mut sequence = 0u32;
            
            while remaining_data > 0 {
                let chunk_size = std::cmp::min(remaining_data, fragment_size);
                let test_data = create_test_packet(chunk_size);
                
                // Send through reliability engine
                match reliability_engine.send_data(session_id, test_data.clone()).await {
                    Ok(packets) => {
                        success_counter.fetch_add(packets.len() as u64, Ordering::Relaxed);
                        
                        // Process through reassembler
                        for packet in packets {
                            match reassembler.process_segment(
                                session_id, sequence, packet.clone(), remaining_data == chunk_size
                            ).await {
                                Ok(result) => {
                                    success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                                    
                                    if let Some(delivered_data) = result.data {
                                        bytes_processed.fetch_add(delivered_data.len() as u64, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => {
                                    error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            
                            sequence += packet.len() as u32;
                        }
                    }
                    Err(_) => {
                        error_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                
                remaining_data -= chunk_size;
                
                // Simulate some ACKs
                if sequence % 5000 == 0 {
                    let ack_info = AckInfo {
                        ack_number: sequence,
                        window_size: 8192,
                        selective_acks: vec![],
                    };
                    
                    if reliability_engine.process_ack(session_id, ack_info).await.is_ok() {
                        success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Test PSK lookup
                if psk_mapper.lookup_psk(&ip).await.is_ok() {
                    success_counter.fetch_add(1, Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
                }

                tokio::task::yield_now().await;
            }
        });
        integration_handles.push(handle);
    }

    // Wait for all integration tests to complete
    for handle in integration_handles {
        handle.await.unwrap();
    }

    let elapsed = start_time.elapsed();
    let successes = success_counter.load(Ordering::Relaxed);
    let errors = error_counter.load(Ordering::Relaxed);
    let total_bytes = bytes_processed.load(Ordering::Relaxed);

    println!("Integrated system stress test completed in {:?}", elapsed);
    println!("Successes: {}, Errors: {}, Total: {}", successes, errors, successes + errors);
    println!("Success rate: {:.2}%", (successes as f64 / (successes + errors) as f64) * 100.0);
    println!("Operations/sec: {:.2}", (successes + errors) as f64 / elapsed.as_secs_f64());
    println!("Bytes processed: {}, Rate: {:.2} MB/sec", 
             total_bytes, total_bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0);

    // Collect final statistics from all components
    let flow_stats = flow_tracker.get_statistics().await;
    let conn_stats = connection_map.get_statistics().await;
    let reassembly_stats = reassembler.get_global_statistics().await;
    let psk_stats = psk_mapper.get_statistics().await;

    println!("Final statistics:");
    println!("  Flows: {}", flow_stats.total_flows);
    println!("  Connections: {}", conn_stats.total_connections);
    println!("  Active streams: {}", reassembly_stats.active_streams);
    println!("  PSK mappings: {}", psk_stats.total_mappings);
    println!("  PSK cache hit rate: {:.2}%", psk_stats.cache_hit_rate);

    // Stop all components
    flow_tracker.stop().await;
    connection_map.stop().await;
    reliability_engine.stop().await;
    reassembler.stop().await;
    psk_mapper.stop().await;

    println!("Integrated system stress test completed successfully");
}