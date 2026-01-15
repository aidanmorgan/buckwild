use buckwild_common::protocol:types::counters::*;
use std::thread;
    use std::time::Duration;

    #[test]
    fn test_aligned_atomic_u64() {
        let counter = AlignedAtomicU64::new(0);
        
        // Test basic operations
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        counter.store(42, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 42);
        
        let old = counter.fetch_add(8, Ordering::Relaxed);
        assert_eq!(old, 42);
        assert_eq!(counter.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn test_packet_counters() {
        let counters = PacketCounters::new();
        
        // Test packet recording
        counters.record_packet_sent(1500);
        counters.record_packet_received(1400);
        
        assert_eq!(counters.packets_sent.load(Ordering::Relaxed), 1);
        assert_eq!(counters.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(counters.bytes_sent.load(Ordering::Relaxed), 1500);
        assert_eq!(counters.bytes_received.load(Ordering::Relaxed), 1400);
        
        // Test connection tracking
        counters.record_connection_attempt();
        counters.record_successful_connection();
        
        assert_eq!(counters.connection_success_rate(), 1.0);
        assert_eq!(counters.active_sessions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = AtomicRateLimiter::new(10, 10); // 10 tokens, 10 per second
        
        // Should be able to consume initial tokens
        assert!(limiter.try_consume(5));
        assert!(limiter.try_consume(5));
        assert!(!limiter.try_consume(1)); // Should fail, no tokens left
        
        // Wait for refill
        thread::sleep(Duration::from_millis(200));
        assert!(limiter.try_consume(1)); // Should succeed after refill
    }

    #[test]
    fn test_performance_metrics() {
        let metrics = PerformanceMetrics::new(Duration::from_secs(1));
        
        // Record some operations
        metrics.record_operation(1000); // 1 microsecond
        metrics.record_operation(2000); // 2 microseconds
        metrics.record_failure();
        
        assert_eq!(metrics.total_operations.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.failed_operations.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.success_rate(), 0.5);
        assert_eq!(metrics.peak_latency_ns(), 2000);
    }

    #[test]
    fn test_concurrent_access() {
        let counters = Arc::new(PacketCounters::new());
        let mut handles = vec![];
        
        // Spawn multiple threads to increment counters
        for _ in 0..10 {
            let counters_clone = counters.clone();
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    counters_clone.record_packet_sent(100);
                }
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify final counts
        assert_eq!(counters.packets_sent.load(Ordering::Relaxed), 10000);
        assert_eq!(counters.bytes_sent.load(Ordering::Relaxed), 1000000);
    }

    #[test]
    fn test_cache_line_alignment() {
        let counter = AlignedAtomicU64::new(0);
        let ptr = &counter as *const _ as usize;
        assert_eq!(ptr % 64, 0); // Should be 64-byte aligned
    }
