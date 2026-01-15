use buckwild_common::engines:flow_control::congestion::*;
#[test]
    fn test_congestion_control_creation() {
        let cc = CongestionControl::new(1460, 65536);
        assert_eq!(cc.get_congestion_window(), 1460);
        assert_eq!(cc.get_slow_start_threshold(), 65536);
        assert_eq!(cc.get_congestion_state(), CongestionState::SlowStart);
    }
    
    #[test]
    fn test_slow_start_growth() {
        let cc = CongestionControl::new(1460, 65536);
        
        // Process ACK in slow start
        cc.process_ack(1000, 1460).unwrap();
        assert_eq!(cc.get_congestion_window(), 2920); // 1460 + 1460
        
        cc.process_ack(2000, 1460).unwrap();
        assert_eq!(cc.get_congestion_window(), 4380); // 2920 + 1460
    }
    
    #[test]
    fn test_duplicate_ack_handling() {
        let cc = CongestionControl::new(10000, 65536);
        
        // Send 3 duplicate ACKs
        cc.process_ack(1000, 0).unwrap(); // First (not duplicate)
        cc.process_ack(1000, 0).unwrap(); // Duplicate 1
        cc.process_ack(1000, 0).unwrap(); // Duplicate 2
        cc.process_ack(1000, 0).unwrap(); // Duplicate 3 - should trigger fast recovery
        
        assert_eq!(cc.get_congestion_state(), CongestionState::FastRecovery);
        assert!(cc.get_congestion_window() > 5000); // Should be ssthresh + 3*MSS
    }
    
    #[test]
    fn test_timeout_handling() {
        let cc = CongestionControl::new(10000, 65536);
        
        cc.handle_timeout().unwrap();
        
        assert_eq!(cc.get_congestion_window(), 1460); // Reset to MSS
        assert_eq!(cc.get_slow_start_threshold(), 5000); // cwnd/2
        assert_eq!(cc.get_congestion_state(), CongestionState::SlowStart);
    }
    
    #[test]
    fn test_rtt_measurement() {
        let rtt = RttMeasurement::new();
        
        rtt.update_rtt(100);
        assert_eq!(rtt.get_srtt(), 100);
        
        rtt.update_rtt(200);
        // SRTT should be between 100 and 200 due to smoothing
        let srtt = rtt.get_srtt();
        assert!(srtt > 100 && srtt < 200);
    }
