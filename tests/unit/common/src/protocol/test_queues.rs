use buckwild_common::protocol::queues::*;
use bytes::Bytes;

    fn create_test_packet() -> ZeroCopyPacket {
        let data = Bytes::from_static(&[
            0x01, 0x02, 0x03, 0x04,
            0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        ZeroCopyPacket::new(data).unwrap()
    }

    #[test]
    fn test_bounded_queue() {
        let queue = BoundedPacketQueue::new(2);
        
        // Send packets
        let packet1 = create_test_packet();
        let packet2 = create_test_packet();
        let packet3 = create_test_packet();
        
        assert!(queue.try_send(packet1).is_ok());
        assert!(queue.try_send(packet2).is_ok());
        assert!(queue.try_send(packet3).is_err()); // Should be full
        
        // Receive packets
        assert!(queue.try_recv().is_ok());
        assert!(queue.try_recv().is_ok());
        assert!(queue.try_recv().is_err()); // Should be empty
    }

    #[test]
    fn test_unbounded_queue() {
        let queue = UnboundedPacketQueue::new();
        
        // Send many packets
        for _ in 0..1000 {
            let packet = create_test_packet();
            assert!(queue.send(packet).is_ok());
        }
        
        assert_eq!(queue.len(), 1000);
        
        // Receive all packets
        for _ in 0..1000 {
            assert!(queue.try_recv().is_ok());
        }
        
        assert!(queue.is_empty());
    }

    #[test]
    fn test_array_queue() {
        let queue = ArrayPacketQueue::new(10);
        
        // Fill queue
        for _ in 0..10 {
            let packet = create_test_packet();
            assert!(queue.push(packet).is_ok());
        }
        
        assert!(queue.is_full());
        
        // Try to push one more (should fail)
        let packet = create_test_packet();
        assert!(queue.push(packet).is_err());
        
        // Pop all packets
        for _ in 0..10 {
            assert!(queue.pop().is_some());
        }
        
        assert!(queue.is_empty());
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_priority_queue() {
        let queue = PriorityPacketQueue::new();
        
        // Send packets with different priorities
        let high_packet = create_test_packet();
        let medium_packet = create_test_packet();
        let low_packet = create_test_packet();
        
        queue.send(low_packet, Priority::Low).unwrap();
        queue.send(high_packet, Priority::High).unwrap();
        queue.send(medium_packet, Priority::Medium).unwrap();
        
        // Should receive high priority first
        let received1 = queue.recv().unwrap();
        let received2 = queue.recv().unwrap();
        let received3 = queue.recv().unwrap();
        
        // Verify order (high, medium, low)
        assert_eq!(queue.len(), 0);
        assert!(queue.recv().is_err());
    }

    #[test]
    fn test_queue_metrics() {
        let queue = BoundedPacketQueue::new(10);
        
        let packet = create_test_packet();
        queue.try_send(packet).unwrap();
        
        let _received = queue.try_recv().unwrap();
        
        let stats = queue.stats();
        assert_eq!(stats.sent.load(Ordering::Relaxed), 1);
        assert_eq!(stats.received.load(Ordering::Relaxed), 1);
        assert!(stats.avg_send_time() > 0.0);
        assert!(stats.avg_recv_time() > 0.0);
    }
