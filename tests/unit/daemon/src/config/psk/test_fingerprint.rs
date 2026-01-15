use buckwild_daemon::config:psk::fingerprint::*;
#[test]
    fn test_calculate_fingerprint() {
        let data = b"test psk data";
        let secure_data = SecureBytes::new(data);
        
        let fingerprint = calculate_fingerprint(&secure_data);
        
        // SHA-256 of "test psk data" should be consistent
        assert_eq!(fingerprint.len(), 64); // SHA-256 is 32 bytes, 64 hex chars
    }
    
    #[tokio::test]
    async fn test_fingerprint_calculator() {
        let calculator = FingerprintCalculator::new(2);
        
        let data1 = b"test psk data 1";
        let secure_data1 = Arc::new(SecureBytes::new(data1));
        
        let data2 = b"test psk data 2";
        let secure_data2 = Arc::new(SecureBytes::new(data2));
        
        // Calculate fingerprints
        let fingerprint1 = calculator.calculate(secure_data1.clone()).await.unwrap();
        let fingerprint2 = calculator.calculate(secure_data2.clone()).await.unwrap();
        
        // Fingerprints should be different
        assert_ne!(fingerprint1, fingerprint2);
        
        // Calculate batch
        let batch_input = vec![
            ("id1".to_string(), secure_data1),
            ("id2".to_string(), secure_data2),
        ];
        
        let batch_results = calculator.calculate_batch(batch_input).await.unwrap();
        
        // Check batch results
        assert_eq!(batch_results.len(), 2);
        assert_eq!(batch_results[0].0, "id1");
        assert_eq!(batch_results[1].0, "id2");
        
        // Check stats
        let (total, cache_hits, in_progress) = calculator.get_stats();
        assert_eq!(total, 4); // 2 individual + 2 batch
        assert_eq!(in_progress, 0);
    }
