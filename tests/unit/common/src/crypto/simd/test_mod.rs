use buckwild_common::crypto:simd::mod::*;
#[test]
    fn test_cpu_feature_detection() {
        // Just make sure this doesn't crash
        detect_cpu_features();
        
        // Check features
        let _has_avx2 = has_avx2();
        let _has_avx512 = has_avx512();
    }
    
    #[test]
    fn test_hmac_sha256() {
        // Test HMAC-SHA256
        let key = b"test key";
        let data = b"test data";
        
        let output = hmac_sha256(key, data).unwrap();
        
        // Verify with ring
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let tag = ring::hmac::sign(&hmac_key, data);
        
        assert_eq!(output, tag.as_ref());
    }
