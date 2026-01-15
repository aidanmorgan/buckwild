use buckwild_daemon::config::watcher::*;
use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_file_watcher() {
        // Create temporary directory
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        
        // Create test file
        let file_path = temp_path.join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"initial content").unwrap();
        
        // Create watcher
        let config = WatcherConfig::new(temp_path)
            .recursive(true)
            .debounce(100);
        
        let watcher = FileWatcher::new(config).unwrap();
        
        // Subscribe to events
        let mut subscriber = watcher.subscribe();
        
        // Modify file
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"modified content").unwrap();
        
        // Wait for event
        let events = tokio::time::timeout(Duration::from_millis(500), subscriber.recv())
            .await
            .unwrap()
            .unwrap();
        
        // Check event
        assert!(!events.is_empty());
        assert_eq!(events[0].paths[0], file_path);
    }
    
    #[tokio::test]
    async fn test_watcher_manager() {
        // Create temporary directory
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        
        // Create test files
        let file1_path = temp_path.join("test1.txt");
        let file2_path = temp_path.join("test2.txt");
        
        File::create(&file1_path).unwrap().write_all(b"file1").unwrap();
        File::create(&file2_path).unwrap().write_all(b"file2").unwrap();
        
        // Create manager
        let manager = WatcherManager::new();
        
        // Add watchers
        let config1 = WatcherConfig::new(&file1_path).debounce(100);
        let config2 = WatcherConfig::new(&file2_path).debounce(100);
        
        let watcher1 = manager.add_watcher(config1).unwrap();
        let watcher2 = manager.add_watcher(config2).unwrap();
        
        // Check watcher count
        assert_eq!(manager.watcher_count(), 2);
        
        // Subscribe to events
        let mut subscriber1 = watcher1.subscribe();
        let mut subscriber2 = watcher2.subscribe();
        
        // Modify files
        tokio::time::sleep(Duration::from_millis(200)).await;
        File::create(&file1_path).unwrap().write_all(b"file1 modified").unwrap();
        
        // Wait for event
        let events = tokio::time::timeout(Duration::from_millis(500), subscriber1.recv())
            .await
            .unwrap()
            .unwrap();
        
        // Check event
        assert!(!events.is_empty());
        assert_eq!(events[0].paths[0], file1_path);
        
        // Remove watcher
        manager.remove_watcher(&file1_path).unwrap();
        
        // Check watcher count
        assert_eq!(manager.watcher_count(), 1);
        
        // Get watcher
        let watcher = manager.get_watcher(&file2_path).unwrap();
        assert_eq!(watcher.watched_path(), &file2_path);
    }
