use crate::protocol::types::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::mem;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

/// Lock-free stack implementation using atomic operations
pub struct LockFreeStack<T> {
    head: AtomicPtr<Node<T>>,
}

struct Node<T> {
    data: T,
    next: *mut Node<T>,
}

impl<T> Default for LockFreeStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LockFreeStack<T> {
    pub fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
        }
    }

    pub fn push(&self, data: T) {
        let new_node = Box::into_raw(Box::new(Node {
            data,
            next: ptr::null_mut(),
        }));

        loop {
            let head = self.head.load(Ordering::Acquire);
            unsafe {
                (*new_node).next = head;
            }

            match self.head.compare_exchange_weak(
                head,
                new_node,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    pub fn pop(&self) -> Option<T> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            if head.is_null() {
                return None;
            }

            let next = unsafe { (*head).next };

            match self
                .head
                .compare_exchange_weak(head, next, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => {
                    let data = unsafe { Box::from_raw(head).data };
                    return Some(data);
                }
                Err(_) => continue,
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }
}

impl<T> Drop for LockFreeStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

unsafe impl<T: Send> Send for LockFreeStack<T> {}
unsafe impl<T: Send> Sync for LockFreeStack<T> {}

/// Lock-free queue implementation using atomic operations
pub struct LockFreeQueue<T> {
    head: AtomicPtr<QueueNode<T>>,
    tail: AtomicPtr<QueueNode<T>>,
}

struct QueueNode<T> {
    data: Option<T>,
    next: AtomicPtr<QueueNode<T>>,
}

impl<T> Default for LockFreeQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LockFreeQueue<T> {
    pub fn new() -> Self {
        let dummy = Box::into_raw(Box::new(QueueNode {
            data: None,
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        Self {
            head: AtomicPtr::new(dummy),
            tail: AtomicPtr::new(dummy),
        }
    }

    pub fn enqueue(&self, data: T) {
        let new_node = Box::into_raw(Box::new(QueueNode {
            data: Some(data),
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*tail).next.load(Ordering::Acquire) };

            if tail == self.tail.load(Ordering::Acquire) {
                if next.is_null() {
                    match unsafe {
                        (*tail).next.compare_exchange_weak(
                            next,
                            new_node,
                            Ordering::Release,
                            Ordering::Relaxed,
                        )
                    } {
                        Ok(_) => break,
                        Err(_) => continue,
                    }
                }
                let _ = self.tail.compare_exchange_weak(
                    tail,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            }
        }

        let _ = self.tail.compare_exchange_weak(
            self.tail.load(Ordering::Acquire),
            new_node,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    pub fn dequeue(&self) -> Option<T> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*head).next.load(Ordering::Acquire) };

            if head == self.head.load(Ordering::Acquire) {
                if head == tail {
                    if next.is_null() {
                        return None;
                    }
                    let _ = self.tail.compare_exchange_weak(
                        tail,
                        next,
                        Ordering::Release,
                        Ordering::Relaxed,
                    );
                } else {
                    if next.is_null() {
                        continue;
                    }

                    let data = unsafe { (*next).data.take() };

                    match self.head.compare_exchange_weak(
                        head,
                        next,
                        Ordering::Release,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            unsafe { drop(Box::from_raw(head)) };
                            return data;
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail && unsafe { (*head).next.load(Ordering::Acquire).is_null() }
    }
}

impl<T> Drop for LockFreeQueue<T> {
    fn drop(&mut self) {
        while self.dequeue().is_some() {}

        // Clean up the dummy node
        let head = self.head.load(Ordering::Acquire);
        if !head.is_null() {
            unsafe { drop(Box::from_raw(head)) };
        }
    }
}

unsafe impl<T: Send> Send for LockFreeQueue<T> {}
unsafe impl<T: Send> Sync for LockFreeQueue<T> {}

/// Lock-free hash map implementation with atomic operations
pub struct LockFreeHashMap<K, V> {
    buckets: Vec<AtomicPtr<HashNode<K, V>>>,
    size: AtomicUsize,
    capacity: Capacity,
}

struct HashNode<K, V> {
    key: K,
    value: V,
    hash: u64, // Keep as u64 for hash compatibility
    next: AtomicPtr<HashNode<K, V>>,
}

impl<K: std::hash::Hash + Eq + Clone, V: Clone> Default for LockFreeHashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Hash + Eq + Clone, V: Clone> LockFreeHashMap<K, V> {
    pub fn new() -> Self {
        Self::with_capacity(16)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut buckets = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buckets.push(AtomicPtr::new(ptr::null_mut()));
        }

        Self {
            buckets,
            size: AtomicUsize::new(0),
            capacity: Capacity::new(capacity as u32),
        }
    }

    fn hash_key(&self, key: &K) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn bucket_index(&self, hash: u64) -> usize {
        (hash as usize) % self.capacity.as_usize()
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let hash = self.hash_key(&key);
        let bucket_idx = self.bucket_index(hash);
        let bucket = &self.buckets[bucket_idx];

        let new_node = Box::into_raw(Box::new(HashNode {
            key: key.clone(),
            value,
            hash,
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let head = bucket.load(Ordering::Acquire);

            // Check if key already exists
            let mut current = head;
            while !current.is_null() {
                unsafe {
                    if (*current).hash == hash && (*current).key == key {
                        // Key exists, update value
                        let old_value =
                            mem::replace(&mut (*current).value, (*new_node).value.clone());
                        drop(Box::from_raw(new_node)); // Clean up unused node
                        return Some(old_value);
                    }
                    current = (*current).next.load(Ordering::Acquire);
                }
            }

            // Key doesn't exist, insert new node
            unsafe {
                (*new_node)
                    .next
                    .store(head, std::sync::atomic::Ordering::Relaxed);
            }

            match bucket.compare_exchange_weak(head, new_node, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => {
                    self.size.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }
                Err(_) => continue,
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let hash = self.hash_key(key);
        let bucket_idx = self.bucket_index(hash);
        let bucket = &self.buckets[bucket_idx];

        let mut current = bucket.load(Ordering::Acquire);
        while !current.is_null() {
            unsafe {
                if (*current).hash == hash && (*current).key == *key {
                    return Some((*current).value.clone());
                }
                current = (*current).next.load(Ordering::Acquire);
            }
        }
        None
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        let hash = self.hash_key(key);
        let bucket_idx = self.bucket_index(hash);
        let bucket = &self.buckets[bucket_idx];

        loop {
            let head = bucket.load(Ordering::Acquire);
            if head.is_null() {
                return None;
            }

            unsafe {
                // Check if head node is the target
                if (*head).hash == hash && (*head).key == *key {
                    let next = (*head).next.load(Ordering::Acquire);
                    match bucket.compare_exchange_weak(
                        head,
                        next,
                        Ordering::Release,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            let node = Box::from_raw(head);
                            self.size.fetch_sub(1, Ordering::Relaxed);
                            return Some(node.value);
                        }
                        Err(_) => continue,
                    }
                }

                // Search in the chain
                let mut prev = head;
                let mut current = (*head).next.load(Ordering::Acquire);

                while !current.is_null() {
                    if (*current).hash == hash && (*current).key == *key {
                        let next = (*current).next.load(Ordering::Acquire);
                        match (*prev).next.compare_exchange_weak(
                            current,
                            next,
                            Ordering::Release,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => {
                                let node = Box::from_raw(current);
                                self.size.fetch_sub(1, Ordering::Relaxed);
                                return Some(node.value);
                            }
                            Err(_) => break, // Retry from the beginning
                        }
                    }
                    prev = current;
                    current = (*current).next.load(Ordering::Acquire);
                }
            }

            // If we reach here, key wasn't found in this iteration
            return None;
        }
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity.as_usize()
    }
}

impl<K, V> Drop for LockFreeHashMap<K, V> {
    fn drop(&mut self) {
        for bucket in &self.buckets {
            let mut current = bucket.load(Ordering::Acquire);
            while !current.is_null() {
                unsafe {
                    let next = (*current).next.load(Ordering::Acquire);
                    drop(Box::from_raw(current));
                    current = next;
                }
            }
        }
    }
}

unsafe impl<K: Send, V: Send> Send for LockFreeHashMap<K, V> {}
unsafe impl<K: Send + Sync, V: Send + Sync> Sync for LockFreeHashMap<K, V> {}

/// Memory ordering utilities for consistent atomic operations
pub mod memory_ordering {
    use std::sync::atomic::Ordering;

    /// Acquire ordering for loading shared data
    pub const ACQUIRE: Ordering = Ordering::Acquire;

    /// Release ordering for storing shared data
    pub const RELEASE: Ordering = Ordering::Release;

    /// Relaxed ordering for non-synchronizing operations
    pub const RELAXED: Ordering = Ordering::Relaxed;

    /// Sequential consistency for strong ordering guarantees
    pub const SEQ_CST: Ordering = Ordering::SeqCst;

    /// Acquire-Release ordering for read-modify-write operations
    pub const ACQ_REL: Ordering = Ordering::AcqRel;
}
