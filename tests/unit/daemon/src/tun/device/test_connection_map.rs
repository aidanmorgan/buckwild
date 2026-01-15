use buckwild_daemon::tun:device::connection_map::*;
use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_connection_creation() {
        let connection_map = ConnectionMap::new(
            Duration::from_secs(5),
            Duration::from_secs(30)
        );

        let flow_id = FlowId::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            12345,
            80,
            6,
        );

        let session_id = connection_map.create_connection(flow_id.clone()).await.unwrap();
        assert_eq!(session_id, 1);

        // Test bidirectional lookup
        assert_eq!(connection_map.get_session_for_flow(&flow_id), Some(session_id));
        assert_eq!(connection_map.get_flow_for_session(session_id), Some(flow_id));
    }

    #[tokio::test]
    async fn test_connection_state_updates() {
        let connection_map = ConnectionMap::new(
            Duration::from_secs(5),
            Duration::from_secs(30)
        );

        let flow_id = FlowId::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
            443,
            6,
        );

        let session_id = connection_map.create_connection(flow_id.clone()).await.unwrap();
        
        // Update state
        connection_map.update_connection_state(session_id, ConnectionState::Established).await.unwrap();
        
        let (_, state, _) = connection_map.get_connection_info(session_id).unwrap();
        assert_eq!(state, ConnectionState::Established);
    }

    #[tokio::test]
    async fn test_connection_statistics() {
        let connection_map = ConnectionMap::new(
            Duration::from_secs(5),
            Duration::from_secs(30)
        );

        // Create multiple connections
        for i in 0..3 {
            let flow_id = FlowId::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                (8000 + i) as u16,
                80,
                6,
            );
            let session_id = connection_map.create_connection(flow_id).await.unwrap();
            connection_map.update_connection_stats(session_id, 1024, 10).await.unwrap();
        }

        let stats = connection_map.get_statistics().await;
        assert_eq!(stats.total_connections, 3);
        assert_eq!(stats.establishing_connections, 3);
        assert_eq!(stats.total_bytes_transferred, 3072);
        assert_eq!(stats.total_packets_transferred, 30);
    }

    #[tokio::test]
    async fn test_connection_removal() {
        let connection_map = ConnectionMap::new(
            Duration::from_secs(5),
            Duration::from_secs(30)
        );

        let flow_id = FlowId::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
            9000,
            22,
            6,
        );

        let session_id = connection_map.create_connection(flow_id.clone()).await.unwrap();
        assert!(connection_map.connection_exists(session_id));

        connection_map.remove_connection(session_id).await.unwrap();
        assert!(!connection_map.connection_exists(session_id));
        assert_eq!(connection_map.get_session_for_flow(&flow_id), None);
    }

    #[test]
    fn test_next_session_id_increment() {
        let connection_map = ConnectionMap::new(
            Duration::from_secs(5),
            Duration::from_secs(30)
        );

        assert_eq!(connection_map.peek_next_session_id(), 1);
        
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let flow_id = FlowId::new(
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
                1234,
                5678,
                6,
            );
            connection_map.create_connection(flow_id).await.unwrap();
            assert_eq!(connection_map.peek_next_session_id(), 2);
        });
    }
