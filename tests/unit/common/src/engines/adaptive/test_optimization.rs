use buckwild_common::engines:adaptive::optimization::*;
use crate::engines::adaptive::AdaptiveDelayState;
    
    #[tokio::test]
    async fn test_optimization_creation() {
        let optimization = ParameterOptimization::new();
        let stats = optimization.get_optimization_stats();
        
        assert_eq!(stats.total_optimizations, 0);
        assert_eq!(stats.current_performance_score, 0.0);
    }
    
    #[test]
    fn test_performance_metrics_calculation() {
        let mut metrics = PerformanceMetrics {
            delivery_success_rate: 0.95,
            average_latency: 100.0,
            jitter_level: 20.0,
            throughput_efficiency: 0.8,
            overall_score: 0.0,
        };
        
        metrics.calculate_overall_score();
        assert!(metrics.overall_score > 0.0);
        assert!(metrics.overall_score <= 1.0);
    }
    
    #[tokio::test]
    async fn test_optimization_strategy_determination() {
        let optimization = ParameterOptimization::new();
        optimization.initialize().unwrap();
        
        // Test with poor performance
        let poor_metrics = PerformanceMetrics {
            delivery_success_rate: 0.4,
            average_latency: 500.0,
            jitter_level: 200.0,
            throughput_efficiency: 0.3,
            overall_score: 0.3,
        };
        
        let strategy = optimization.determine_optimization_strategy(&poor_metrics).unwrap();
        assert_eq!(strategy, OptimizationStrategy::Aggressive);
    }
    
    #[tokio::test]
    async fn test_window_optimization() {
        let optimization = ParameterOptimization::new();
        let state = AdaptiveDelayState::new();
        
        let old_window = state.current_delay_window.load(Ordering::Relaxed);
        let new_window = old_window + 2;
        
        optimization.apply_window_optimization(&state, old_window, new_window, "test").unwrap();
        
        assert_eq!(state.current_delay_window.load(Ordering::Relaxed), new_window);
        
        let stats = optimization.get_optimization_stats();
        assert_eq!(stats.total_optimizations, 1);
    }
    
    #[tokio::test]
    async fn test_optimization_enable_disable() {
        let optimization = ParameterOptimization::new();
        
        // Test enabling/disabling
        optimization.set_optimization_enabled(false);
        assert_eq!(optimization.optimization_enabled.load(Ordering::Relaxed), 0);
        
        optimization.set_optimization_enabled(true);
        assert_eq!(optimization.optimization_enabled.load(Ordering::Relaxed), 1);
    }
    
    #[tokio::test]
    async fn test_optimization_history() {
        let optimization = ParameterOptimization::new();
        let state = AdaptiveDelayState::new();
        
        // Apply several optimizations
        optimization.apply_window_optimization(&state, 1, 2, "test1").unwrap();
        optimization.apply_window_optimization(&state, 2, 3, "test2").unwrap();
        
        let history = optimization.get_optimization_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].parameter, "delay_window");
        assert_eq!(history[1].new_value, 3.0);
    }
