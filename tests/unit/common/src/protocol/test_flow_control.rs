use buckwild_common::protocol::flow_control::*;
use crate::session::SessionId;
    
    #[test]
    fn test_flow_control_header() {
        let header = FlowControlHeader::new(1024);
        assert_eq!(header.window_size, 1024);
        assert_eq!(header.reserved, 0);
        
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]); // 1024 in big-endian + reserved
        
        let parsed = FlowControlHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.window_size, 1024);
        assert_eq!(parsed.reserved, 0);
    }
    
    #[test]
    fn test_flow_control_state_creation() {
        let state = FlowControlState::new(1000, 2000);
        
        assert_eq!(state.send_next.load(Ordering::Relaxed), 1000);
        assert_eq!(state.send_unacked.load(Ordering::Relaxed), 1000);
        assert_eq!(state.receive_next.load(Ordering::Relaxed), 2000);
        assert_eq!(state.send_window.load(Ordering::Relaxed), INITIAL_SEND_WINDOW);
        assert_eq!(state.receive_window.load(Ordering::Relaxed), INITIAL_RECEIVE_WINDOW);
        assert_eq!(state.advertised_window.load(Ordering::Relaxed), INITIAL_RECEIVE_WINDOW);
    }
    
    #[test]
    fn test_congestion_control_state_creation() {
        let state = CongestionControlState::new();
        
        assert_eq!(state.congestion_window.load(Ordering::Relaxed), INITIAL_CONGESTION_WINDOW);
        assert_eq!(state.slow_start_threshold.load(Ordering::Relaxed), SLOW_START_THRESHOLD);
        assert_eq!(state.duplicate_ack_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.bytes_acked.load(Ordering::Relaxed), 0);
    }
    
    #[test]
    fn test_rtt_measurement() {
        let rtt = RttMeasurement::new();
        
        // Initial values
        assert_eq!(rtt.get_srtt(), RTT_INITIAL_MS);
        assert_eq!(rtt.get_rto(), RTT_INITIAL_MS * 3);
        
        // First measurement
        rtt.update_rtt(100);
        assert_eq!(rtt.get_srtt(), 100);
        assert_eq!(rtt.get_rto(), max(RTO_MIN_MS, 100 + max(1, 4 * 50)));
        
        // Second measurement
        rtt.update_rtt(200);
        let expected_srtt = (7 * 100 + 200) / 8;
        assert_eq!(rtt.get_srtt(), expected_srtt);
    }
    
    #[tokio::test]
    async fn test_flow_control_engine_creation() {
        let session_id = SessionId(12345);
        let engine = FlowControlEngine::new(session_id, 1000, 2000);
        
        assert_eq!(engine.flow_control.send_next.load(Ordering::Relaxed), 1000);
        assert_eq!(engine.flow_control.send_unacked.load(Ordering::Relaxed), 1000);
        assert_eq!(engine.flow_control.receive_next.load(Ordering::Relaxed), 2000);
        assert_eq!(engine.get_congestion_window(), INITIAL_CONGESTION_WINDOW);
        assert_eq!(engine.get_send_window(), INITIAL_SEND_WINDOW);
        assert_eq!(engine.get_receive_window(), INITIAL_RECEIVE_WINDOW);
    }
    
    #[tokio::test]
    async fn test_can_send_data() {
        let session_id = SessionId(12345);
        let engine = FlowControlEngine::new(session_id, 1000, 2000);
        
        // Should be able to send data within window
        assert!(engine.can_send_data(1000));
        
        // Should not be able to send data larger than MSS
        assert!(!engine.can_send_data(MSS + 1));
    }
    
    #[tokio::test]
    async fn test_effective_window_calculation() {
        let session_id = SessionId(12345);
        let engine = FlowControlEngine::new(session_id, 1000, 2000);
        
        // Initially, effective window should be minimum of congestion and flow control windows
        let effective_window = engine.calculate_effective_window();
        assert_eq!(effective_window, min(INITIAL_CONGESTION_WINDOW, INITIAL_SEND_WINDOW));
        
        // Reduce congestion window
        engine.congestion_control.congestion_window.store(1000, Ordering::Relaxed);
        let effective_window = engine.calculate_effective_window();
        assert_eq!(effective_window, 1000);
        
        // Reduce flow control window
        engine.flow_control.send_window.store(500, Ordering::Relaxed);
        let effective_window = engine.calculate_effective_window();
        assert_eq!(effective_window, 500);
    }
    
    #[tokio::test]
    async fn test_zero_window_probing() {
        let session_id = SessionId(12345);
        let engine = FlowControlEngine::new(session_id, 1000, 2000);
        
        // Start zero window probing
        engine.start_zero_window_probing().await;
        assert!(engine.flow_control.zero_window_probing.load(Ordering::Relaxed));
        
        // Stop zero window probing
        engine.stop_zero_window_probing().await;
        assert!(!engine.flow_control.zero_window_probing.load(Ordering::Relaxed));
    }
    
    #[tokio::test]
    async fn test_sack_info_building() {
        let session_id = SessionId(12345);
        let engine = FlowControlEngine::new(session_id, 1000, 2000);
        
        // Add some out-of-order data to receive buffer
        {
            let mut receive_buffer = engine.flow_control.receive_buffer.lock().await;
            receive_buffer.insert(2002, ReceivedData {
                data: Bytes::from("test1"),
                sequence_number: 2002,
                timestamp: Instant::now(),
            });
            receive_buffer.insert(2004, ReceivedData {
                data: Bytes::from("test2"),
                sequence_number: 2004,
                timestamp: Instant::now(),
            });
        }
        
        let sack_info = engine.build_sack_info().await;
        
        // Should have bitmap bits set for sequences 2002 and 2004
        assert_ne!(sack_info.bitmap, 0);
        assert!(!sack_info.ranges.is_empty());
    }
