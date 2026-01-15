use buckwild_common::performance::metrics::*;
use std::thread;
    use std::time::Duration;

    #[test]
    fn test_atomic_counter() {
        let counter = AtomicCounter::new();
        
        assert_eq!(counter.get(), 0);
        assert_eq!(counter.increment(), 0);
        assert_eq!(counter.get(), 1);
        assert_eq!(counter.add(5), 1);
        assert_eq!(counter.get(), 6);
        assert_eq!(counter.reset(), 6);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_atomic_gauge() {
        let gauge = AtomicGauge::new();
        
        assert_eq!(gauge.get(), 0);
        gauge.set(10);
        assert_eq!(gauge.get(), 10);
        assert_eq!(gauge.increment(), 10);
        assert_eq!(gauge.get(), 11);
        assert_eq!(gauge.decrement(), 11);
        assert_eq!(gauge.get(), 10);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new(vec![1, 5, 10, 50, 100]);
        
        histogram.observe(3);
        histogram.observe(7);
        histogram.observe(25);
        histogram.observe(75);
        
        assert_eq!(histogram.count(), 4);
        assert_eq!(histogram.sum(), 110);
        assert_eq!(histogram.average(), 27.5);
        
        let counts = histogram.bucket_counts();
        assert_eq!(counts[0], 0); // < 1
        assert_eq!(counts[1], 1); // 1-5 (value 3)
        assert_eq!(counts[2], 1); // 5-10 (value 7)
        assert_eq!(counts[3], 1); // 10-50 (value 25)
        assert_eq!(counts[4], 1); // 50-100 (value 75)
        assert_eq!(counts[5], 0); // > 100
    }

    #[test]
    fn test_latency_tracker() {
        let tracker = LatencyTracker::new();
        
        {
            let _measurement = tracker.start_measurement();
            thread::sleep(Duration::from_millis(1));
        }
        
        assert_eq!(tracker.total_measurements(), 1);
        assert!(tracker.average_latency() > Duration::from_micros(500));
    }

    #[test]
    fn test_throughput_tracker() {
        let tracker = ThroughputTracker::new(Duration::from_millis(100));
        
        tracker.record_operation();
        tracker.record_operations(9);
        
        assert_eq!(tracker.total_operations(), 10);
        
        // Wait a bit and check throughput
        thread::sleep(Duration::from_millis(50));
        let throughput = tracker.current_throughput();
        assert!(throughput > 0.0);
    }

    #[test]
    fn test_performance_metrics() {
        let metrics = PerformanceMetrics::new();
        
        let counter = metrics.counter("test_counter");
        counter.increment();
        
        let gauge = metrics.gauge("test_gauge");
        gauge.set(42);
        
        let histogram = metrics.histogram("test_histogram", vec![1, 10, 100]);
        histogram.observe(5);
        
        let snapshot = metrics.export_metrics();
        
        assert_eq!(snapshot.counters.get("test_counter"), Some(&1));
        assert_eq!(snapshot.gauges.get("test_gauge"), Some(&42));
        assert!(snapshot.histograms.contains_key("test_histogram"));
    }
