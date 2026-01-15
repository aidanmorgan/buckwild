use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use buckwild_common::protocol::{
    ZeroCopyPacket, PacketBuilder, PacketChain, ZeroCopyPacketQueue,
    BoundedPacketQueue, UnboundedPacketQueue, ArrayPacketQueue, PriorityPacketQueue, Priority,
};
use buckwild_common::protocol::types::{
    AlignedAtomicU64, AlignedAtomicU32, PacketCounters, AtomicRateLimiter, PerformanceMetrics,
    AlignedSessionState, AlignedPortState, AlignedTimeState, LockFreeSessionManager,
};
use buckwild_common::memory::{PacketPool, init_packet_pool};
use bytes::{Bytes, BufMut};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

fn create_test_packet_data(size: usize) -> Bytes {
    let mut data = vec![0u8; size];
    
    // Create realistic packet header
    data[0] = 0x01; // version
    data[1] = 0x02; // type
    data[2] = 0x03; // sub_type
    data[3] = 0x04; // flags
    data[4] = 0x12; data[5] = 0x34; // 16-bit session ID
    data[6] = 0x56; data[7] = 0x78; // 16-bit timestamp
    data[8] = 0x9a; data[9] = 0xbc; data[10] = 0xde; data[11] = 0xf0; // sequence
    
    // HMAC (8 bytes for LIGHT policy)
    for i in 12..20 {
        data[i] = (i as u8).wrapping_mul(17);
    }
    
    // Fill payload with test data
    for i in 20..size {
        data[i] = (i as u8).wrapping_mul(7);
    }
    
    Bytes::from(data)
}

fn bench_zero_copy_packet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy_packet_creation");
    
    for size in [64, 256, 1024, 4096, 8192].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let data = create_test_packet_data(*size);
        
        group.bench_with_input(BenchmarkId::new("create", size), size, |b, _| {
            b.iter(|| {
                let packet = ZeroCopyPacket::new(data.clone()).unwrap();
                black_box(packet);
            });
        });
        
        group.bench_with_input(BenchmarkId::new("header_access", size), size, |b, _| {
            let packet = ZeroCopyPacket::new(data.clone()).unwrap();
            b.iter(|| {
                let header = packet.header();
                black_box(header);
            });
        });
        
        group.bench_with_input(BenchmarkId::new("payload_access", size), size, |b, _| {
            let packet = ZeroCopyPacket::new(data.clone()).unwrap();
            b.iter(|| {
                let payload = packet.payload();
                black_box(payload);
            });
        });
        
        group.bench_with_input(BenchmarkId::new("fragment", size), size, |b, _| {
            let packet = ZeroCopyPacket::new(data.clone()).unwrap();
            b.iter(|| {
                let fragment = packet.fragment(20, 100).unwrap();
                black_box(fragment);
            });
        });
    }
    
    group.finish();
}

fn bench_packet_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_builder");
    
    // Initialize packet pool for testing
    let _ = init_packet_pool(1000, 100);
    
    for size in [64, 256, 1024, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let payload_size = size - 20; // Account for header
        let payload = vec![0xAA; payload_size];
        
        group.bench_with_input(BenchmarkId::new("build_packet", size), size, |b, _| {
            b.iter(|| {
                let mut builder = PacketBuilder::new(*size).unwrap();
                
                // Write header manually for test
                let header_bytes = [
                    0x01, 0x02, 0x03, 0x04, // version, type, sub_type, flags
                    0x12, 0x34, // session ID
                    0x56, 0x78, // timestamp
                    0x9a, 0xbc, 0xde, 0xf0, // sequence
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // HMAC
                ];
                builder.write_header_bytes(&header_bytes).unwrap();
                
                builder.append_payload(&payload).unwrap();
                let packet = builder.build().unwrap();
                black_box(packet);
            });
        });
    }
    
    group.finish();
}

fn bench_packet_chain_reassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_chain_reassembly");
    
    for fragment_count in [2, 4, 8, 16].iter() {
        group.bench_with_input(BenchmarkId::new("reassemble", fragment_count), fragment_count, |b, &count| {
            // Create fragments
            let fragments: Vec<_> = (0..count).map(|i| {
                let data = create_test_packet_data(256);
                ZeroCopyPacket::new(data).unwrap()
            }).collect();
            
            b.iter(|| {
                let mut chain = PacketChain::new();
                for fragment in &fragments {
                    chain.add_fragment(fragment.clone());
                }
                let reassembled = chain.reassemble().unwrap();
                black_box(reassembled);
            });
        });
    }
    
    group.finish();
}

fn bench_lock_free_queues(c: &mut Criterion) {
    let mut group = c.benchmark_group("lock_free_queues");
    
    let test_packet = {
        let data = create_test_packet_data(1024);
        ZeroCopyPacket::new(data).unwrap()
    };
    
    // Bounded queue benchmarks
    group.bench_function("bounded_queue_single_thread", |b| {
        let queue = BoundedPacketQueue::new(1000);
        b.iter(|| {
            for _ in 0..100 {
                queue.try_send(test_packet.clone()).unwrap();
            }
            for _ in 0..100 {
                let _ = queue.try_recv().unwrap();
            }
        });
    });
    
    // Unbounded queue benchmarks
    group.bench_function("unbounded_queue_single_thread", |b| {
        let queue = UnboundedPacketQueue::new();
        b.iter(|| {
            for _ in 0..100 {
                queue.send(test_packet.clone()).unwrap();
            }
            for _ in 0..100 {
                let _ = queue.try_recv().unwrap();
            }
        });
    });
    
    // Array queue benchmarks
    group.bench_function("array_queue_single_thread", |b| {
        let queue = ArrayPacketQueue::new(1000);
        b.iter(|| {
            for _ in 0..100 {
                queue.push(test_packet.clone()).unwrap();
            }
            for _ in 0..100 {
                let _ = queue.pop().unwrap();
            }
        });
    });
    
    // Priority queue benchmarks
    group.bench_function("priority_queue_single_thread", |b| {
        let queue = PriorityPacketQueue::new();
        b.iter(|| {
            for i in 0..100 {
                let priority = match i % 3 {
                    0 => Priority::High,
                    1 => Priority::Medium,
                    _ => Priority::Low,
                };
                queue.send(test_packet.clone(), priority).unwrap();
            }
            for _ in 0..100 {
                let _ = queue.recv().unwrap();
            }
        });
    });
    
    group.finish();
}

fn bench_concurrent_queue_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_queue_access");
    
    let test_packet = {
        let data = create_test_packet_data(1024);
        ZeroCopyPacket::new(data).unwrap()
    };
    
    // Multi-producer, single-consumer
    group.bench_function("mpsc_unbounded", |b| {
        b.iter(|| {
            let queue = Arc::new(UnboundedPacketQueue::new());
            let mut handles = vec![];
            
            // Spawn producer threads
            for _ in 0..4 {
                let queue_clone = queue.clone();
                let packet_clone = test_packet.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..250 {
                        queue_clone.send(packet_clone.clone()).unwrap();
                    }
                });
                handles.push(handle);
            }
            
            // Consumer thread
            let consumer_queue = queue.clone();
            let consumer_handle = thread::spawn(move || {
                for _ in 0..1000 {
                    while consumer_queue.try_recv().is_err() {
                        thread::yield_now();
                    }
                }
            });
            
            // Wait for all threads
            for handle in handles {
                handle.join().unwrap();
            }
            consumer_handle.join().unwrap();
        });
    });
    
    // Multi-producer, multi-consumer
    group.bench_function("mpmc_array", |b| {
        b.iter(|| {
            let queue = Arc::new(ArrayPacketQueue::new(2000));
            let mut handles = vec![];
            
            // Spawn producer threads
            for _ in 0..2 {
                let queue_clone = queue.clone();
                let packet_clone = test_packet.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..500 {
                        while queue_clone.push(packet_clone.clone()).is_err() {
                            thread::yield_now();
                        }
                    }
                });
                handles.push(handle);
            }
            
            // Spawn consumer threads
            for _ in 0..2 {
                let queue_clone = queue.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..500 {
                        while queue_clone.pop().is_none() {
                            thread::yield_now();
                        }
                    }
                });
                handles.push(handle);
            }
            
            // Wait for all threads
            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
    
    group.finish();
}

fn bench_atomic_counters(c: &mut Criterion) {
    let mut group = c.benchmark_group("atomic_counters");
    
    // Single-threaded atomic operations
    group.bench_function("aligned_atomic_u64_single", |b| {
        let counter = AlignedAtomicU64::new(0);
        b.iter(|| {
            for _ in 0..1000 {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
    });
    
    group.bench_function("aligned_atomic_u32_single", |b| {
        let counter = AlignedAtomicU32::new(0);
        b.iter(|| {
            for _ in 0..1000 {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
    });
    
    // Packet counters
    group.bench_function("packet_counters_single", |b| {
        let counters = PacketCounters::new();
        b.iter(|| {
            for i in 0..1000 {
                counters.record_packet_sent(1500);
                if i % 10 == 0 {
                    counters.record_packet_dropped();
                }
                if i % 20 == 0 {
                    counters.record_retransmission();
                }
            }
        });
    });
    
    // Multi-threaded atomic operations
    group.bench_function("aligned_atomic_u64_concurrent", |b| {
        b.iter(|| {
            let counter = Arc::new(AlignedAtomicU64::new(0));
            let mut handles = vec![];
            
            for _ in 0..4 {
                let counter_clone = counter.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..250 {
                        counter_clone.fetch_add(1, Ordering::Relaxed);
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            assert_eq!(counter.load(Ordering::Relaxed), 1000);
        });
    });
    
    group.finish();
}

fn bench_rate_limiter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter");
    
    group.bench_function("rate_limiter_single", |b| {
        let limiter = AtomicRateLimiter::new(1000, 1000); // 1000 tokens, 1000/sec
        b.iter(|| {
            for _ in 0..100 {
                let _ = limiter.try_consume(1);
            }
        });
    });
    
    group.bench_function("rate_limiter_concurrent", |b| {
        b.iter(|| {
            let limiter = Arc::new(AtomicRateLimiter::new(10000, 10000));
            let mut handles = vec![];
            
            for _ in 0..4 {
                let limiter_clone = limiter.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..250 {
                        let _ = limiter_clone.try_consume(1);
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
    
    group.finish();
}

fn bench_session_management(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_management");
    
    // Single-threaded session operations
    group.bench_function("session_state_single", |b| {
        let session = AlignedSessionState::new(12345);
        b.iter(|| {
            for _ in 0..1000 {
                session.increment_sequence();
                session.update_ack(session.sequence_number.load(Ordering::Relaxed));
                session.touch();
            }
        });
    });
    
    // Lock-free session manager
    group.bench_function("session_manager_single", |b| {
        let manager = LockFreeSessionManager::default();
        b.iter(|| {
            for i in 0..100 {
                let session_id = i as u64;
                let session = manager.create_session(session_id);
                session.increment_sequence();
                let _ = manager.get_session(session_id);
                manager.remove_session(session_id);
            }
        });
    });
    
    // Concurrent session access
    group.bench_function("session_state_concurrent", |b| {
        b.iter(|| {
            let session = Arc::new(AlignedSessionState::new(12345));
            let mut handles = vec![];
            
            for _ in 0..4 {
                let session_clone = session.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..250 {
                        session_clone.increment_sequence();
                        session_clone.touch();
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            assert_eq!(session.sequence_number.load(Ordering::Relaxed), 1000);
        });
    });
    
    // Concurrent session manager
    group.bench_function("session_manager_concurrent", |b| {
        b.iter(|| {
            let manager = Arc::new(LockFreeSessionManager::default());
            let mut handles = vec![];
            
            for thread_id in 0..4 {
                let manager_clone = manager.clone();
                let handle = thread::spawn(move || {
                    for i in 0..25 {
                        let session_id = (thread_id * 25 + i) as u64;
                        let session = manager_clone.create_session(session_id);
                        session.increment_sequence();
                        let _ = manager_clone.get_session(session_id);
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            assert_eq!(manager.session_count(), 100);
        });
    });
    
    group.finish();
}

fn bench_performance_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_metrics");
    
    group.bench_function("metrics_single", |b| {
        let metrics = PerformanceMetrics::new(Duration::from_secs(1));
        b.iter(|| {
            for i in 0..1000 {
                let latency = (i % 1000) * 1000; // Vary latency
                metrics.record_operation(latency);
                if i % 100 == 0 {
                    metrics.record_failure();
                }
            }
        });
    });
    
    group.bench_function("metrics_concurrent", |b| {
        b.iter(|| {
            let metrics = Arc::new(PerformanceMetrics::new(Duration::from_secs(1)));
            let mut handles = vec![];
            
            for thread_id in 0..4 {
                let metrics_clone = metrics.clone();
                let handle = thread::spawn(move || {
                    for i in 0..250 {
                        let latency = ((thread_id * 250 + i) % 1000) * 1000;
                        metrics_clone.record_operation(latency);
                        if i % 25 == 0 {
                            metrics_clone.record_failure();
                        }
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            assert_eq!(metrics.total_operations.load(Ordering::Relaxed), 1000);
        });
    });
    
    group.finish();
}

fn bench_memory_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_pool");
    
    group.bench_function("pool_allocation_single", |b| {
        let pool = PacketPool::new(1000);
        pool.preallocate(100).unwrap();
        
        b.iter(|| {
            let mut buffers = Vec::new();
            for _ in 0..100 {
                let buffer = pool.allocate(1500).unwrap();
                buffers.push(buffer);
            }
            for buffer in buffers {
                pool.deallocate(buffer);
            }
        });
    });
    
    group.bench_function("pool_allocation_concurrent", |b| {
        b.iter(|| {
            let pool = Arc::new(PacketPool::new(1000));
            pool.preallocate(400).unwrap();
            let mut handles = vec![];
            
            for _ in 0..4 {
                let pool_clone = pool.clone();
                let handle = thread::spawn(move || {
                    let mut buffers = Vec::new();
                    for _ in 0..100 {
                        let buffer = pool_clone.allocate(1500).unwrap();
                        buffers.push(buffer);
                    }
                    for buffer in buffers {
                        pool_clone.deallocate(buffer);
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_zero_copy_packet_creation,
    bench_packet_builder,
    bench_packet_chain_reassembly,
    bench_lock_free_queues,
    bench_concurrent_queue_access,
    bench_atomic_counters,
    bench_rate_limiter,
    bench_session_management,
    bench_performance_metrics,
    bench_memory_pool,
);

criterion_main!(benches);