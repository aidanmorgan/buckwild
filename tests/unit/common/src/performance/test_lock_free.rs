use buckwild_common::performance::lock_free::*;
use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_lock_free_stack() {
        let stack = Arc::new(LockFreeStack::new());
        let stack_clone = Arc::clone(&stack);

        // Test basic operations
        stack.push(1);
        stack.push(2);
        stack.push(3);

        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        assert!(stack.is_empty());

        // Test concurrent operations
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let stack = Arc::clone(&stack_clone);
                thread::spawn(move || {
                    for j in 0..100 {
                        stack.push(i * 100 + j);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let mut count = 0;
        while stack_clone.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_lock_free_queue() {
        let queue = Arc::new(LockFreeQueue::new());
        
        // Test basic operations
        queue.enqueue(1);
        queue.enqueue(2);
        queue.enqueue(3);

        assert_eq!(queue.dequeue(), Some(1));
        assert_eq!(queue.dequeue(), Some(2));
        assert_eq!(queue.dequeue(), Some(3));
        assert_eq!(queue.dequeue(), None);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_lock_free_hashmap() {
        let map = LockFreeHashMap::new();
        
        // Test basic operations
        assert_eq!(map.insert("key1".to_string(), 1), None);
        assert_eq!(map.insert("key2".to_string(), 2), None);
        assert_eq!(map.insert("key1".to_string(), 10), Some(1)); // Update

        assert_eq!(map.get(&"key1".to_string()), Some(10));
        assert_eq!(map.get(&"key2".to_string()), Some(2));
        assert_eq!(map.get(&"key3".to_string()), None);

        assert_eq!(map.remove(&"key1".to_string()), Some(10));
        assert_eq!(map.get(&"key1".to_string()), None);
        assert_eq!(map.len(), 1);
    }
