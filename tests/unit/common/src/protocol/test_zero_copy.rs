use buckwild_common::protocol::zero_copy::*;
#[test]
    fn test_zero_copy_packet_creation() {
        let data = Bytes::from_static(&[
            0x01, 0x02, 0x03, 0x04, // version, type, sub_type, flags
            0x12, 0x34, // 16-bit session ID
            0x56, 0x78, // 16-bit timestamp
            0x9a, 0xbc, 0xde, 0xf0, // sequence
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // HMAC
            0xaa, 0xbb, 0xcc, 0xdd, // payload
        ]);

        let packet = ZeroCopyPacket::new(data).unwrap();
        assert_eq!(packet.len(), 20);
        
        let header = packet.header();
        assert_eq!(header.len(), 16); // 4 + 2 + 2 + 4 + 8
        
        let payload = packet.payload();
        assert_eq!(payload.len(), 4);
        assert_eq!(&payload[..], &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_packet_builder() {
        let mut builder = PacketBuilder::new(1500).unwrap();
        
        // This would normally use a real PacketHeader
        // For test, we'll write raw bytes
        builder.buffer.put_u8(0x01); // version
        builder.buffer.put_u8(0x02); // type
        builder.buffer.put_u8(0x03); // sub_type
        builder.buffer.put_u8(0x04); // flags
        builder.buffer.put_u16(0x1234); // session ID
        builder.buffer.put_u16(0x5678); // timestamp
        builder.buffer.put_u32(0x9abcdef0); // sequence
        builder.buffer.put_u64(0x1122334455667788); // HMAC
        builder.header_written = true;
        
        let payload = b"Hello, World!";
        builder.append_payload(payload).unwrap();
        
        let packet = builder.build().unwrap();
        assert_eq!(packet.payload().len(), payload.len());
    }

    #[test]
    fn test_packet_queue() {
        let queue = PacketQueue::new();
        assert!(queue.is_empty());
        
        let data = Bytes::from_static(&[
            0x01, 0x02, 0x03, 0x04,
            0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        
        let packet = ZeroCopyPacket::new(data).unwrap();
        queue.enqueue(packet);
        
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
        
        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.len(), 20);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_packet_fragmentation() {
        let data = Bytes::from_static(&[
            0x01, 0x02, 0x03, 0x04,
            0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        
        let packet = ZeroCopyPacket::new(data).unwrap();
        
        // Fragment the payload
        let fragment1 = packet.fragment(16, 3).unwrap(); // First 3 bytes of payload
        let fragment2 = packet.fragment(19, 3).unwrap(); // Next 3 bytes of payload
        
        assert_eq!(fragment1.len(), 3);
        assert_eq!(fragment2.len(), 3);
        assert_eq!(&fragment1[..], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(&fragment2[..], &[0xdd, 0xee, 0xff]);
    }
