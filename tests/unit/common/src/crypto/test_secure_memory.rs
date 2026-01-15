use buckwild_common::crypto::secure_memory::*;
#[test]
    fn test_secure_bytes() {
        // Create secure bytes
        let mut secure_bytes = SecureBytes::new(32).unwrap();
        assert_eq!(secure_bytes.len(), 32);
        
        // Fill with data
        for i in 0..32 {
            secure_bytes[i] = i as u8;
        }
        
        // Check data
        for i in 0..32 {
            assert_eq!(secure_bytes[i], i as u8);
        }
        
        // Clear data
        secure_bytes.clear();
        
        // Check that data is cleared
        for i in 0..32 {
            assert_eq!(secure_bytes[i], 0);
        }
    }
    
    #[test]
    fn test_secure_bytes_from_slice() {
        // Create data
        let data = [1, 2, 3, 4, 5];
        
        // Create secure bytes from slice
        let secure_bytes = SecureBytes::from_slice(&data).unwrap();
        
        // Check data
        assert_eq!(secure_bytes.len(), 5);
        for i in 0..5 {
            assert_eq!(secure_bytes[i], data[i]);
        }
    }
    
    #[test]
    fn test_secure_bytes_resize() {
        // Create secure bytes
        let mut secure_bytes = SecureBytes::new(5).unwrap();
        assert_eq!(secure_bytes.len(), 5);
        
        // Fill with data
        for i in 0..5 {
            secure_bytes[i] = i as u8;
        }
        
        // Resize to larger
        secure_bytes.resize(10, 0);
        assert_eq!(secure_bytes.len(), 10);
        
        // Check data
        for i in 0..5 {
            assert_eq!(secure_bytes[i], i as u8);
        }
        for i in 5..10 {
            assert_eq!(secure_bytes[i], 0);
        }
        
        // Resize to smaller
        secure_bytes.resize(3, 0);
        assert_eq!(secure_bytes.len(), 3);
        
        // Check data
        for i in 0..3 {
            assert_eq!(secure_bytes[i], i as u8);
        }
    }
