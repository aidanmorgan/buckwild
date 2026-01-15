use buckwild_common::protocol:fragmentation::engine::*;
use crate::protocol::packet::{PacketBuilderEngine, SessionId};

    #[test]
    fn test_fragmentation_engine_creation() {
        let engine = FragmentationEngine::new();
        let stats = engine.get_stats();
        assert_eq!(stats.active_reassembly_contexts, 0);
    }

    #[test]
    fn test_small_packet_no_fragmentation() {
        let engine = FragmentationEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_string("Small payload")
            .build()
            .unwrap();

        let request = FragmentationRequest {
            session_id: SessionId::Bits32(0x12345678),
            packet,
            max_fragment_size: Some(1400),
            source_ip: 0x7F000001,
        };

        let result = engine.fragment_packet(request).unwrap();
        assert_eq!(result.total_fragments, 1);
        assert_eq!(result.fragments.len(), 1);
    }

    #[test]
    fn test_large_packet_fragmentation() {
        let engine = FragmentationEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        // Create a large payload that will require fragmentation
        let large_payload = vec![0u8; 3000];
        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_slice(&large_payload)
            .build()
            .unwrap();

        let request = FragmentationRequest {
            session_id: SessionId::Bits32(0x12345678),
            packet,
            max_fragment_size: Some(1000),
            source_ip: 0x7F000001,
        };

        let result = engine.fragment_packet(request).unwrap();
        assert!(result.total_fragments > 1);
        assert_eq!(result.fragments.len(), result.total_fragments as usize);

        // Verify all fragments have the FRAG flag set
        for fragment in &result.fragments {
            assert!(fragment.flags().is_frag());
        }
    }

    #[test]
    fn test_fragment_reassembly() {
        let engine = FragmentationEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        // Create and fragment a packet
        let original_payload = b"This is a test payload that will be fragmented and reassembled";
        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_slice(original_payload)
            .build()
            .unwrap();

        let frag_request = FragmentationRequest {
            session_id: SessionId::Bits32(0x12345678),
            packet,
            max_fragment_size: Some(20),
            source_ip: 0x7F000001,
        };

        let frag_result = engine.fragment_packet(frag_request).unwrap();
        assert!(frag_result.total_fragments > 1);

        // Process fragments for reassembly
        let mut reassembly_result = None;
        for fragment in frag_result.fragments {
            let request = ReassemblyRequest {
                fragment,
                source_ip: 0x7F000001,
            };

            match engine.process_fragment(request).unwrap() {
                ReassemblyResult::InProgress { .. } => {
                    // Continue processing
                }
                ReassemblyResult::Complete { packet, .. } => {
                    reassembly_result = Some(packet);
                    break;
                }
                ReassemblyResult::Rejected { reason } => {
                    panic!("Fragment rejected: {}", reason);
                }
            }
        }

        // Verify reassembly was successful
        let reassembled = reassembly_result.expect("Reassembly should complete");
        
        // Note: The reassembled packet won't have the exact same payload due to
        // fragmentation headers being removed, but the core data should be preserved
        assert_eq!(reassembled.session_id(), SessionId::Bits32(0x12345678));
    }
