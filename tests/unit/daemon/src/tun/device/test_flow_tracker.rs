use buckwild_daemon::tun:device::flow_tracker::*;
use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_flow_creation() {
        let tracker = FlowTracker::new(Duration::from_secs(30), Duration::from_secs(5));
        
        let flow_id = FlowId::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            12345,
            80,
            6, // TCP
        );

        let flow = tracker.create_or_update_flow(flow_id.clone(), 1000, 2000, 8192, 0x02).await.unwrap();
        
        {
            let state = flow.read().await;
            assert_eq!(state.flow_id, flow_id);
            assert_eq!(state.seq_num, 1000);
            assert_eq!(state.ack_num, 2000);
            assert_eq!(state.window_size, 8192);
            assert_eq!(state.state, TcpState::SynSent);
        }
    }

    #[tokio::test]
    async fn test_flow_lookup() {
        let tracker = FlowTracker::new(Duration::from_secs(30), Duration::from_secs(5));
        
        let flow_id = FlowId::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
            443,
            6,
        );

        // Create flow
        tracker.create_or_update_flow(flow_id.clone(), 5000, 6000, 4096, 0x18).await.unwrap();
        
        // Lookup flow
        let found_flow = tracker.get_flow(&flow_id).unwrap();
        let state = found_flow.read().await;
        assert_eq!(state.seq_num, 5000);
        assert_eq!(state.ack_num, 6000);
    }

    #[test]
    fn test_flow_id_reverse() {
        let flow_id = FlowId::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            1234,
            5678,
            6,
        );

        let reverse = flow_id.reverse();
        assert_eq!(reverse.src_ip, flow_id.dst_ip);
        assert_eq!(reverse.dst_ip, flow_id.src_ip);
        assert_eq!(reverse.src_port, flow_id.dst_port);
        assert_eq!(reverse.dst_port, flow_id.src_port);
        assert_eq!(reverse.protocol, flow_id.protocol);
    }

    #[tokio::test]
    async fn test_flow_statistics() {
        let tracker = FlowTracker::new(Duration::from_secs(30), Duration::from_secs(5));
        
        // Create multiple flows
        for i in 0..5 {
            let flow_id = FlowId::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                (8000 + i) as u16,
                80,
                6,
            );
            tracker.create_or_update_flow(flow_id, 1000, 2000, 8192, 0x18).await.unwrap();
        }

        let stats = tracker.get_statistics().await;
        assert_eq!(stats.total_flows, 5);
        assert_eq!(stats.established_flows, 5);
    }
