use buckwild_daemon::tun:device::reassembly::*;
#[tokio::test]
    async fn test_stream_creation() {
        let reassembler = StreamReassembler::new(
            Duration::from_secs(5),
            65536,
            100,
        );

        reassembler.create_stream(1, 0).await.unwrap();
        assert!(reassembler.stream_exists(1).await);
        assert_eq!(reassembler.get_expected_sequence(1).await, Some(0));
    }

    #[tokio::test]
    async fn test_in_order_segments() {
        let reassembler = StreamReassembler::new(
            Duration::from_secs(5),
            65536,
            100,
        );

        reassembler.create_stream(1, 0).await.unwrap();

        // Send segments in order
        let data1 = Bytes::from("Hello, ");
        let result1 = reassembler.process_segment(1, 0, data1.clone(), false).await.unwrap();
        assert!(result1.data.is_some());
        assert_eq!(result1.data.unwrap(), data1);

        let data2 = Bytes::from("World!");
        let result2 = reassembler.process_segment(1, 7, data2.clone(), true).await.unwrap();
        assert!(result2.data.is_some());
        assert_eq!(result2.data.unwrap(), data2);
        assert!(result2.end_of_stream);
    }

    #[tokio::test]
    async fn test_out_of_order_segments() {
        let reassembler = StreamReassembler::new(
            Duration::from_secs(5),
            65536,
            100,
        );

        reassembler.create_stream(1, 0).await.unwrap();

        // Send segments out of order
        let data2 = Bytes::from("World!");
        let result2 = reassembler.process_segment(1, 7, data2.clone(), false).await.unwrap();
        assert!(result2.data.is_none()); // Should be buffered

        let data1 = Bytes::from("Hello, ");
        let result1 = reassembler.process_segment(1, 0, data1.clone(), false).await.unwrap();
        assert!(result1.data.is_some());
        
        // Should deliver both segments
        let combined = result1.data.unwrap();
        assert_eq!(combined.len(), 13); // "Hello, World!"
    }

    #[tokio::test]
    async fn test_duplicate_segments() {
        let reassembler = StreamReassembler::new(
            Duration::from_secs(5),
            65536,
            100,
        );

        reassembler.create_stream(1, 0).await.unwrap();

        let data = Bytes::from("Hello");
        
        // Send same segment twice
        let result1 = reassembler.process_segment(1, 0, data.clone(), false).await.unwrap();
        assert!(result1.data.is_some());

        let result2 = reassembler.process_segment(1, 0, data.clone(), false).await.unwrap();
        assert!(result2.data.is_none()); // Duplicate should be ignored

        let stats = reassembler.get_stream_statistics(1).await.unwrap();
        assert_eq!(stats.segments_duplicate, 1);
    }

    #[tokio::test]
    async fn test_force_delivery() {
        let reassembler = StreamReassembler::new(
            Duration::from_secs(5),
            65536,
            100,
        );

        reassembler.create_stream(1, 0).await.unwrap();

        // Send out-of-order segment
        let data = Bytes::from("World!");
        reassembler.process_segment(1, 7, data.clone(), false).await.unwrap();

        // Force delivery should return the buffered data
        let result = reassembler.force_delivery(1).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[tokio::test]
    async fn test_global_statistics() {
        let reassembler = StreamReassembler::new(
            Duration::from_secs(5),
            65536,
            100,
        );

        // Create multiple streams
        for i in 0..3 {
            reassembler.create_stream(i, 0).await.unwrap();
        }

        let stats = reassembler.get_global_statistics().await;
        assert_eq!(stats.active_streams, 3);
    }
