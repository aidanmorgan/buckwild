use buckwild_common::performance::queues::*;
use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_bounded_queue() {
        let queue = BoundedQueue::new(4);
        
        // Test basic operations
        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_ok());
        assert!(queue.push(3).is_ok());
        
        assert_eq!(queue.len(), 3);
        assert!(!queue.is_empty());
        assert!(!queue.is_full());
        
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
        
        assert!(queue.is_empty());
    }

    #[test]
    fn test_bounded_queue_full() {
        let queue = BoundedQueue::new(2);
        
        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_err()); // Should be full (capacity - 1)
        
        assert!(queue.is_full());
    }

    #[test]
    fn test_unbounded_queue() {
        let queue = UnboundedQueue::new();
        
        queue.push(1);
        queue.push(2);
        queue.push(3);
        
        assert_eq!(queue.len(), 3);
        assert!(!queue.is_empty());
        
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
        
        assert!(queue.is_empty());
    }

    #[test]
    fn test_priority_queue() {
        let queue = PriorityQueue::new();
        
        queue.push("low", 1);
        queue.push("high", 10);
        queue.push("medium", 5);
        
        assert_eq!(queue.len(), 3);
        
        // Should pop in priority order (highest first)
        assert_eq!(queue.pop(), Some("high"));
        assert_eq!(queue.pop(), Some("medium"));
        assert_eq!(queue.pop(), Some("low"));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_zero_copy_buffer() {
        let buffer = ZeroCopyBuffer::new(1024);
        
        let data = b"Hello, World!";
        assert_eq!(buffer.write(data).unwrap(), data.len());
        assert_eq!(buffer.len(), data.len());
        
        let mut read_buf = vec![0u8; data.len()];
        assert_eq!(buffer.read(&mut read_buf), data.len());
        assert_eq!(&read_buf, data);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_cache_optimized_queue() {
        let queue = CacheOptimizedQueue::new(8);
        
        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_ok());
        assert!(queue.push(3).is_ok());
        
        assert_eq!(queue.len(), 3);
        
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_concurrent_bounded_queue() {
        let queue = Arc::new(BoundedQueue::new(1024));
        let queue_clone = Arc::clone(&queue);
        
        let producer = thread::spawn(move || {
            for i in 0..500 {
                while queue_clone.push(i).is_err() {
                    thread::yield_now();
                }
            }
        });
        
        let consumer = thread::spawn(move || {
            let mut count = 0;
            while count < 500 {
                if queue.pop().is_some() {
                    count += 1;
                }
                thread::yield_now();
            }
        });
        
        producer.join().unwrap();
        consumer.join().unwrap();
    }
