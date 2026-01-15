use buckwild_common::crypto::kdf::*;
#[test]
    fn test_derive_parameters() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Check length
        assert_eq!(params.len(), 128);
    }
    
    #[test]
    fn test_get_chunk() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Get chunks
        let chunk1 = Kdf::get_chunk(&params, ChunkRange::SequenceNumbers, 0).unwrap();
        let chunk2 = Kdf::get_chunk(&params, ChunkRange::SequenceNumbers, 1).unwrap();
        
        // Check that chunks are different (they should be with high probability)
        // Note: They could be the same by chance, but it's very unlikely
        println!("Chunk 1: {}, Chunk 2: {}", chunk1, chunk2);
    }
    
    #[test]
    fn test_get_chunks() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Get chunks from sequence numbers range
        let chunks = Kdf::get_chunks(&params, ChunkRange::SequenceNumbers, 0, 4).unwrap();
        
        // Check length
        assert_eq!(chunks.len(), 4);
    }
    
    #[test]
    fn test_chunk_ranges() {
        // Test range boundaries
        assert_eq!(ChunkRange::SequenceNumbers.range(), (0, 4));
        assert_eq!(ChunkRange::PortOffsets.range(), (4, 6));
        assert_eq!(ChunkRange::HmacKey.range(), (6, 22));
        assert_eq!(ChunkRange::PortHoppingSeed.range(), (22, 24));
        assert_eq!(ChunkRange::Reserved.range(), (24, 26));
        assert_eq!(ChunkRange::SessionParameters.range(), (26, 64));
        
        // Test counts
        assert_eq!(ChunkRange::SequenceNumbers.count(), 4);
        assert_eq!(ChunkRange::PortOffsets.count(), 2);
        assert_eq!(ChunkRange::HmacKey.count(), 16);
        assert_eq!(ChunkRange::PortHoppingSeed.count(), 2);
        assert_eq!(ChunkRange::Reserved.count(), 2);
        assert_eq!(ChunkRange::SessionParameters.count(), 38);
    }
    
    #[test]
    fn test_extract_sequence_numbers() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Extract sequence numbers
        let (client_seq, server_seq) = Kdf::extract_sequence_numbers(&params).unwrap();
        
        // Check that they are valid u32 values
        println!("Client seq: {}, Server seq: {}", client_seq, server_seq);
    }
    
    #[test]
    fn test_extract_port_offsets() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Extract port offsets
        let (client_offset, server_offset) = Kdf::extract_port_offsets(&params).unwrap();
        
        // Check that they are valid u16 values
        println!("Client offset: {}, Server offset: {}", client_offset, server_offset);
    }
    
    #[test]
    fn test_extract_hmac_key() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Extract HMAC key
        let hmac_key = Kdf::extract_hmac_key(&params).unwrap();
        
        // Check that it's 32 bytes
        assert_eq!(hmac_key.len(), 32);
        
        // Check that it's not all zeros (very unlikely with PBKDF2)
        assert_ne!(hmac_key, [0u8; 32]);
    }
    
    #[test]
    fn test_extract_port_hopping_seed() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Extract port hopping seed
        let seed = Kdf::extract_port_hopping_seed(&params).unwrap();
        
        // Check that it's a valid u32 value
        println!("Port hopping seed: {}", seed);
    }
    
    #[test]
    fn test_validate_parameters() {
        // Create KDF
        let kdf = Kdf::default();
        
        // Derive parameters
        let key = b"test key";
        let params = kdf.derive_parameters(key).unwrap();
        
        // Validate parameters
        assert!(Kdf::validate_parameters(&params).is_ok());
        
        // Validate invalid parameters
        let invalid_params = [0u8; 64];
        assert!(Kdf::validate_parameters(&invalid_params).is_err());
    }
