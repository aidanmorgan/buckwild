use buckwild_ebpf::lib::*;
#[tokio::test]
    async fn test_ebpf_loader_creation() {
        let loader = EbpfLoader::new().await;
        assert!(loader.is_ok());
    }
