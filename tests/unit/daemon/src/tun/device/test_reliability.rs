use buckwild_daemon::tun:device::reliability::*;
#[tokio::test]
    async fn test_connection_creation() {
        let engine = ReliabilityEngine::new(
            Duration::from_millis(200),
            3,
            1460,
            65536,
        );

        engine.create_connection(1).await.unwrap();
        
        let stats = engine.get_statistics(1).await;
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().current_cwnd, 1460);
    }

    #[tokio::test]
    async fn test_data_sending() {
        let engine = ReliabilityEngine::new(
            Duration::from_millis(200),
            3,
            1460,
            65536,
        );

        engine.create_connection(1).await.unwrap();
        
        let data = Bytes::from("Hello, World!");
        let packets = engine.send_data(1, data).await.unwrap();
        
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], Bytes::from("Hello, World!"));
    }

    #[tokio::test]
    async fn test_ack_processing() {
        let engine = ReliabilityEngine::new(
            Duration::from_millis(200),
            3,
            1460,
            65536,
        );

        engine.create_connection(1).await.unwrap();
        
        let ack_info = AckInfo {
            ack_number: 100,
            window_size: 8192,
            selective_acks: vec![],
        };
        
        engine.process_ack(1, ack_info).await.unwrap();
        
        // Test should complete without errors
    }

    #[tokio::test]
    async fn test_data_reception() {
        let engine = ReliabilityEngine::new(
            Duration::from_millis(200),
            3,
            1460,
            65536,
        );

        engine.create_connection(1).await.unwrap();
        
        let data = Bytes::from("Received data");
        let delivered = engine.process_received_data(1, 0, data.clone()).await.unwrap();
        
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], data);
    }
