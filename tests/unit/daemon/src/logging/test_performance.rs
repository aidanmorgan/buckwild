use buckwild_daemon::logging::performance::*;
#[tokio::test]
    async fn test_performance_logger_creation() {
        let logger = PerformanceLogger::new().unwrap();
        assert_eq!(logger.get_metrics_count(), 0);
        assert!(logger.get_uptime().as_millis() > 0);
    }

    #[tokio::test]
    async fn test_metrics_logging() {
        let logger = PerformanceLogger::new().unwrap();
        
        let mut metrics = HashMap::new();
        metrics.insert("test_counter".to_string(), MetricValue::Counter(42));
        metrics.insert("test_gauge".to_string(), MetricValue::Gauge(3.14));
        
        let perf_metrics = PerformanceMetrics {
            timestamp: Utc::now(),
            component: "test_component".to_string(),
            correlation_id: None,
            metrics,
        };
        
        logger.log_metrics(perf_metrics);
        assert_eq!(logger.get_metrics_count(), 1);
    }

    #[tokio::test]
    async fn test_port_hopping_stats_update() {
        let logger = PerformanceLogger::new().unwrap();
        
        let mut metrics = HashMap::new();
        metrics.insert("total_hops".to_string(), MetricValue::Counter(100));
        metrics.insert("successful_hops".to_string(), MetricValue::Counter(95));
        metrics.insert("failed_hops".to_string(), MetricValue::Counter(5));
        
        logger.update_port_hopping_stats(&metrics);
        
        let stats = logger.get_port_hopping_stats();
        assert_eq!(stats.total_hops, 100);
        assert_eq!(stats.successful_hops, 95);
        assert_eq!(stats.failed_hops, 5);
    }

    #[tokio::test]
    async fn test_performance_measurement() {
        let logger = PerformanceLogger::new().unwrap();
        
        let measurement = PerformanceMeasurement::new("test_component", "test_operation", None);
        
        // Simulate some work
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        
        measurement.finish(&logger);
        
        assert_eq!(logger.get_metrics_count(), 1);
    }

    #[tokio::test]
    async fn test_custom_metrics() {
        let logger = PerformanceLogger::new().unwrap();
        
        logger.set_custom_metric("custom_counter".to_string(), MetricValue::Counter(123));
        logger.set_custom_metric("custom_gauge".to_string(), MetricValue::Gauge(45.67));
        
        assert_eq!(logger.get_custom_metric("custom_counter").unwrap().as_counter(), Some(123));
        assert_eq!(logger.get_custom_metric("custom_gauge").unwrap().as_gauge(), Some(45.67));
        
        let all_metrics = logger.get_all_custom_metrics();
        assert_eq!(all_metrics.len(), 2);
    }

    #[tokio::test]
    async fn test_performance_report_generation() {
        let logger = PerformanceLogger::new().unwrap();
        
        // Add some test data
        logger.set_custom_metric("test_metric".to_string(), MetricValue::Counter(42));
        
        let report = logger.generate_performance_report();
        
        assert!(report.uptime.as_millis() > 0);
        assert_eq!(report.custom_metrics.len(), 1);
        assert!(report.timestamp <= Utc::now());
    }
