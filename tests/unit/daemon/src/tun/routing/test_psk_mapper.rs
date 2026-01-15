use buckwild_daemon::tun:routing::psk_mapper::*;
use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_psk_mapping_creation() {
        let mapper = PskMapper::new(100, Duration::from_secs(300));
        
        let mapping = PskMapping {
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            psk_fingerprint: "abcdef0123456789".to_string(),
            description: Some("Test server".to_string()),
            priority: 10,
            created_at: Instant::now(),
            last_used: None,
            use_count: 0,
        };

        mapper.add_mapping(mapping.clone()).await.unwrap();
        
        let retrieved = mapper.get_mapping(&mapping.ip_address).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().psk_fingerprint, mapping.psk_fingerprint);
    }

    #[tokio::test]
    async fn test_psk_lookup() {
        let mapper = PskMapper::new(100, Duration::from_secs(300));
        
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let fingerprint = "fedcba9876543210".to_string();
        
        let mapping = PskMapping {
            ip_address: ip,
            psk_fingerprint: fingerprint.clone(),
            description: None,
            priority: 5,
            created_at: Instant::now(),
            last_used: None,
            use_count: 0,
        };

        mapper.add_mapping(mapping).await.unwrap();
        
        let result = mapper.lookup_psk(&ip).await.unwrap();
        assert_eq!(result.fingerprint, fingerprint);
        assert!(!result.from_cache);
        
        // Second lookup should be from cache
        let result2 = mapper.lookup_psk(&ip).await.unwrap();
        assert_eq!(result2.fingerprint, fingerprint);
        assert!(result2.from_cache);
    }

    #[tokio::test]
    async fn test_default_psk() {
        let mapper = PskMapper::new(100, Duration::from_secs(300));
        
        let default_fingerprint = "default123456789".to_string();
        mapper.set_default_psk(default_fingerprint.clone()).await.unwrap();
        
        let unknown_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let result = mapper.lookup_psk(&unknown_ip).await.unwrap();
        
        assert_eq!(result.fingerprint, default_fingerprint);
        assert_eq!(result.mapping.description, Some("Default PSK".to_string()));
    }

    #[tokio::test]
    async fn test_batch_update() {
        let mapper = PskMapper::new(100, Duration::from_secs(300));
        
        let mut mappings = HashMap::new();
        for i in 1..=5 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
            let mapping = PskMapping {
                ip_address: ip,
                psk_fingerprint: format!("fingerprint{}", i),
                description: Some(format!("Server {}", i)),
                priority: i as u32,
                created_at: Instant::now(),
                last_used: None,
                use_count: 0,
            };
            mappings.insert(ip, mapping);
        }

        let updated_ips = mapper.update_mappings_batch(mappings).await.unwrap();
        assert_eq!(updated_ips.len(), 5);
        
        let stats = mapper.get_statistics().await;
        assert_eq!(stats.total_mappings, 5);
    }

    #[tokio::test]
    async fn test_mapping_removal() {
        let mapper = PskMapper::new(100, Duration::from_secs(300));
        
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let mapping = PskMapping {
            ip_address: ip,
            psk_fingerprint: "toberemoved123".to_string(),
            description: None,
            priority: 1,
            created_at: Instant::now(),
            last_used: None,
            use_count: 0,
        };

        mapper.add_mapping(mapping).await.unwrap();
        assert!(mapper.mapping_exists(&ip).await);
        
        mapper.remove_mapping(&ip).await.unwrap();
        assert!(!mapper.mapping_exists(&ip).await);
    }
