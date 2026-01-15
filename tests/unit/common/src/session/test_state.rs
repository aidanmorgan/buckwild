use buckwild_common::session::state::*;
use std::thread;
    use std::sync::Arc;
    
    #[test]
    fn test_session_status() {
        assert_eq!(SessionStatus::from_u8(0), Some(SessionStatus::Initializing));
        assert_eq!(SessionStatus::from_u8(1), Some(SessionStatus::Established));
        assert_eq!(SessionStatus::from_u8(2), Some(SessionStatus::Closing));
        assert_eq!(SessionStatus::from_u8(3), Some(SessionStatus::Closed));
        assert_eq!(SessionStatus::from_u8(4), None);
    }
    
    #[test]
    fn test_window_state() {
        let window = WindowState::new();
        
        // Test default values
        assert_eq!(window.send_window(), 65535);
        assert_eq!(window.recv_window(), 65535);
        assert_eq!(window.congestion_window(), 1460);
        assert_eq!(window.ssthresh(), 65535);
        assert_eq!(window.rtt(), 100_000);
        assert_eq!(window.rtt_var(), 50_000);
        assert_eq!(window.rto(), 300_000);
        
        // Test setters
        window.set_send_window(32768);
        window.set_recv_window(16384);
        window.set_congestion_window(2920);
        window.set_ssthresh(32768);
        window.set_rtt(200_000);
        window.set_rtt_var(100_000);
        window.set_rto(600_000);
        
        assert_eq!(window.send_window(), 32768);
        assert_eq!(window.recv_window(), 16384);
        assert_eq!(window.congestion_window(), 2920);
        assert_eq!(window.ssthresh(), 32768);
        assert_eq!(window.rtt(), 200_000);
        assert_eq!(window.rtt_var(), 100_000);
        assert_eq!(window.rto(), 600_000);
        
        // Test RTT update
        window.update_rtt(150_000);
        assert!(window.rtt() < 200_000);  // Should decrease toward 150_000
        assert!(window.rtt() > 150_000);  // But not all the way in one update
        
        // Test RTO backoff
        let initial_rto = window.rto();
        window.backoff_rto();
        assert_eq!(window.rto(), initial_rto * 2);
    }
    
    #[test]
    fn test_session_state() {
        let session = SessionState::new();
        
        // Test default values
        assert_eq!(session.status(), SessionStatus::Initializing);
        assert_eq!(session.local_seq(), 0);
        assert_eq!(session.remote_seq(), 0);
        assert_eq!(session.local_port(), 0);
        assert_eq!(session.remote_port(), 0);
        assert_eq!(session.time_offset(), 0);
        
        // Test setters
        session.set_status(SessionStatus::Established);
        session.set_local_seq(1000);
        session.set_remote_seq(2000);
        session.set_local_port(8000);
        session.set_remote_port(9000);
        session.set_time_offset(50);
        
        assert_eq!(session.status(), SessionStatus::Established);
        assert_eq!(session.local_seq(), 1000);
        assert_eq!(session.remote_seq(), 2000);
        assert_eq!(session.local_port(), 8000);
        assert_eq!(session.remote_port(), 9000);
        assert_eq!(session.time_offset(), 50);
        
        // Test sequence number increment
        assert_eq!(session.increment_local_seq(), 1001);
        assert_eq!(session.local_seq(), 1001);
        
        // Test remote sequence update
        assert!(session.update_remote_seq(2500));
        assert_eq!(session.remote_seq(), 2500);
        assert!(!session.update_remote_seq(2000));  // Lower value should be ignored
        assert_eq!(session.remote_seq(), 2500);  // Value should not change
        
        // Test activity update
        let initial_activity = session.last_activity();
        std::thread::sleep(std::time::Duration::from_secs(1));
        session.update_activity();
        assert!(session.last_activity() > initial_activity);
        
        // Test idle detection
        assert!(!session.is_idle(Duration::from_secs(10)));
        assert!(session.is_idle(Duration::from_millis(1)));
        
        // Test parameter access
        assert_eq!(session.port_hop_param(0), Some(0));
        assert_eq!(session.session_param(0), Some(0));
        assert_eq!(session.port_hop_param(100), None);
        assert_eq!(session.session_param(100), None);
        
        // Test parameter setting
        assert!(session.set_port_hop_param(0, 1234));
        assert!(session.set_session_param(0, 5678));
        assert!(!session.set_port_hop_param(100, 1234));
        assert!(!session.set_session_param(100, 5678));
        
        assert_eq!(session.port_hop_param(0), Some(1234));
        assert_eq!(session.session_param(0), Some(5678));
    }
    
    #[test]
    fn test_concurrent_access() {
        let session = Arc::new(SessionState::new());
        let session_clone = session.clone();
        
        // Spawn a thread to update the session
        let thread = thread::spawn(move || {
            for i in 0..1000 {
                session_clone.increment_local_seq();
                session_clone.update_remote_seq(i + 1);
                
                if i % 100 == 0 {
                    session_clone.update_activity();
                }
            }
        });
        
        // Update the session in the main thread
        for i in 0..1000 {
            session.increment_local_seq();
            session.update_remote_seq(1000 + i + 1);
            
            if i % 100 == 0 {
                session.update_activity();
            }
        }
        
        // Wait for the thread to finish
        thread.join().unwrap();
        
        // Check the final values
        assert_eq!(session.local_seq(), 2000);
        assert!(session.remote_seq() >= 1000);
    }
