use buckwild_common::engines:port_hopping::coordination::*;
use std::sync::atomic::AtomicBool;
    
    #[tokio::test]
    async fn test_port_binding() {
        let mut coordination = PortHoppingCoordination::new();
        
        // Set up mock callbacks
        let bound_ports = Arc::new(Mutex::new(HashSet::new()));
        let bound_ports_clone = bound_ports.clone();
        
        coordination.set_bind_port_callback(move |port| {
            bound_ports_clone.lock().insert(port);
            true
        });
        
        let bound_ports_clone = bound_ports.clone();
        coordination.set_unbind_port_callback(move |port| {
            bound_ports_clone.lock().remove(&port);
            true
        });
        
        // Bind to a port
        let result = coordination.bind_to_port(8000).await;
        assert!(result.is_ok());
        assert!(bound_ports.lock().contains(&8000));
        
        // Check port status
        assert_eq!(coordination.get_port_status(8000), Some(PortBindingStatus::Active));
        assert_eq!(coordination.get_port_ref_count(8000), Some(1));
        
        // Bind to same port again (should increment ref count)
        let result = coordination.bind_to_port(8000).await;
        assert!(result.is_ok());
        assert_eq!(coordination.get_port_ref_count(8000), Some(2));
        
        // Unbind from port (should decrement ref count)
        let result = coordination.unbind_from_port(8000).await;
        assert!(result.is_ok());
        assert_eq!(coordination.get_port_ref_count(8000), Some(1));
        assert!(bound_ports.lock().contains(&8000)); // Still bound
        
        // Unbind again (should actually unbind)
        let result = coordination.unbind_from_port(8000).await;
        assert!(result.is_ok());
        assert!(!bound_ports.lock().contains(&8000));
    }
    
    #[tokio::test]
    async fn test_coordination_stats() {
        let mut coordination = PortHoppingCoordination::new();
        
        // Set up mock callbacks
        coordination.set_bind_port_callback(|_| true);
        coordination.set_unbind_port_callback(|_| true);
        
        // Initial stats
        let stats = coordination.get_coordination_stats();
        assert_eq!(stats.total_bindings, 0);
        assert_eq!(stats.total_unbindings, 0);
        assert_eq!(stats.active_ports, 0);
        
        // Bind to ports
        coordination.bind_to_port(8000).await.unwrap();
        coordination.bind_to_port(8001).await.unwrap();
        
        let stats = coordination.get_coordination_stats();
        assert_eq!(stats.total_bindings, 2);
        assert_eq!(stats.active_ports, 2);
        
        // Unbind from port
        coordination.unbind_from_port(8000).await.unwrap();
        
        let stats = coordination.get_coordination_stats();
        assert_eq!(stats.total_unbindings, 1);
        assert_eq!(stats.active_ports, 1);
    }
    
    #[tokio::test]
    async fn test_port_history() {
        let coordination = PortHoppingCoordination::new();
        
        // Create test transition event
        let event = PortTransitionEvent {
            old_port: 8000,
            new_port: 8001,
            time_window: 100,
            transition_time: 1234567890,
        };
        
        // Add to history
        coordination.add_to_history(event.clone()).await;
        
        // Check history
        let history = coordination.get_port_history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].old_port, 8000);
        assert_eq!(history[0].new_port, 8001);
        
        // Clear history
        coordination.clear_port_history().await;
        let history = coordination.get_port_history().await;
        assert_eq!(history.len(), 0);
    }
    
    #[tokio::test]
    async fn test_adaptive_delay_window() {
        let coordination = PortHoppingCoordination::new();
        
        // Test with low delay and jitter
        let window_size = coordination.update_adaptive_delay_window(50.0, 25.0);
        assert_eq!(window_size, 4); // Base (3) + Delay (1) + Jitter (0) = 4
        
        // Test with higher delay and jitter
        let window_size = coordination.update_adaptive_delay_window(150.0, 75.0);
        assert_eq!(window_size, 8); // Base (3) + Delay (2) + Jitter (3) = 8
        
        // Test with extreme conditions (should cap at 10)
        let window_size = coordination.update_adaptive_delay_window(500.0, 200.0);
        assert_eq!(window_size, 10);
    }
    
    #[tokio::test]
    async fn test_bound_ports() {
        let mut coordination = PortHoppingCoordination::new();
        
        // Set up mock callbacks
        coordination.set_bind_port_callback(|_| true);
        coordination.set_unbind_port_callback(|_| true);
        
        // Initially no bound ports
        let bound_ports = coordination.get_bound_ports();
        assert!(bound_ports.is_empty());
        
        // Bind to some ports
        coordination.bind_to_port(8000).await.unwrap();
        coordination.bind_to_port(8001).await.unwrap();
        coordination.bind_to_port(8002).await.unwrap();
        
        let mut bound_ports = coordination.get_bound_ports();
        bound_ports.sort();
        assert_eq!(bound_ports, vec![8000, 8001, 8002]);
        
        // Unbind from one port
        coordination.unbind_from_port(8001).await.unwrap();
        
        let mut bound_ports = coordination.get_bound_ports();
        bound_ports.sort();
        assert_eq!(bound_ports, vec![8000, 8002]);
    }
    
    #[tokio::test]
    async fn test_shutdown() {
        let mut coordination = PortHoppingCoordination::new();
        
        // Set up mock callbacks
        let unbound_ports = Arc::new(Mutex::new(Vec::new()));
        let unbound_ports_clone = unbound_ports.clone();
        
        coordination.set_bind_port_callback(|_| true);
        coordination.set_unbind_port_callback(move |port| {
            unbound_ports_clone.lock().push(port);
            true
        });
        
        // Bind to some ports
        coordination.bind_to_port(8000).await.unwrap();
        coordination.bind_to_port(8001).await.unwrap();
        
        // Shutdown should unbind all ports
        coordination.shutdown().await.unwrap();
        
        let mut unbound_ports = unbound_ports.lock().clone();
        unbound_ports.sort();
        assert_eq!(unbound_ports, vec![8000, 8001]);
        
        // History should be cleared
        let history = coordination.get_port_history().await;
        assert!(history.is_empty());
    }
