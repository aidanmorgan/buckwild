use std::alloc::{Layout, alloc, dealloc};
use std::cmp::{Ord, Ordering as CmpOrdering};
use std::collections::{BinaryHeap, VecDeque};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QueueError {
    #[error("allocation failed")]
    AllocationFailed,
    #[error("invalid capacity: {0} (must be power of two and > 0)")]
    InvalidCapacity(usize),
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("buffer overflow")]
    BufferOverflow,
}

/// High-performance bounded queue with zero-copy operations
pub struct BoundedQueue<T> {
    buffer: *mut T,
    capacity: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
    layout: Layout,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Result<Self, QueueError> {
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(QueueError::InvalidCapacity(capacity));
        }

        let layout = Layout::array::<T>(capacity).map_err(|_| QueueError::AllocationFailed)?;
        let buffer = unsafe { alloc(layout) as *mut T };

        if buffer.is_null() {
            return Err(QueueError::AllocationFailed);
        }

        Ok(Self {
            buffer,
            capacity,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            layout,
        })
    }

    pub fn push(&self, item: T) -> Result<(), T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) & (self.capacity - 1);

        if next_tail == self.head.load(Ordering::Acquire) {
            return Err(item); // Queue is full
        }

        unsafe {
            ptr::write(self.buffer.add(tail), item);
        }

        self.tail.store(next_tail, Ordering::Release);
        Ok(())
    }

    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);

        if head == self.tail.load(Ordering::Acquire) {
            return None; // Queue is empty
        }

        let item = unsafe { ptr::read(self.buffer.add(head)) };
        let next_head = (head + 1) & (self.capacity - 1);
        self.head.store(next_head, Ordering::Release);

        Some(item)
    }

    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        (tail.wrapping_sub(head)) & (self.capacity - 1)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    pub fn is_full(&self) -> bool {
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) & (self.capacity - 1);
        next_tail == self.head.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T> Drop for BoundedQueue<T> {
    fn drop(&mut self) {
        // Drop all remaining items
        while self.pop().is_some() {}

        // Deallocate buffer
        unsafe {
            dealloc(self.buffer as *mut u8, self.layout);
        }
    }
}

unsafe impl<T: Send> Send for BoundedQueue<T> {}
unsafe impl<T: Send> Sync for BoundedQueue<T> {}

/// High-performance unbounded queue with dynamic growth
pub struct UnboundedQueue<T> {
    inner: Mutex<VecDeque<T>>,
    not_empty: Condvar,
    size: AtomicUsize,
}

impl<T> UnboundedQueue<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            not_empty: Condvar::new(),
            size: AtomicUsize::new(0),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            not_empty: Condvar::new(),
            size: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, item: T) -> Result<(), QueueError> {
        {
            let mut queue = self.inner.lock().map_err(|_| QueueError::LockPoisoned)?;
            queue.push_back(item);
        }
        self.size.fetch_add(1, Ordering::Relaxed);
        self.not_empty.notify_one();
        Ok(())
    }

    pub fn pop(&self) -> Result<Option<T>, QueueError> {
        let mut queue = self.inner.lock().map_err(|_| QueueError::LockPoisoned)?;
        if let Some(item) = queue.pop_front() {
            self.size.fetch_sub(1, Ordering::Relaxed);
            Ok(Some(item))
        } else {
            Ok(None)
        }
    }

    pub fn pop_blocking(&self) -> Result<T, QueueError> {
        let mut queue = self.inner.lock().map_err(|_| QueueError::LockPoisoned)?;
        loop {
            if let Some(item) = queue.pop_front() {
                self.size.fetch_sub(1, Ordering::Relaxed);
                return Ok(item);
            }
            queue = self
                .not_empty
                .wait(queue)
                .map_err(|_| QueueError::LockPoisoned)?;
        }
    }

    pub fn try_pop_timeout(&self, timeout: std::time::Duration) -> Result<Option<T>, QueueError> {
        let mut queue = self.inner.lock().map_err(|_| QueueError::LockPoisoned)?;
        if let Some(item) = queue.pop_front() {
            self.size.fetch_sub(1, Ordering::Relaxed);
            return Ok(Some(item));
        }

        let (mut queue_guard, _) = self
            .not_empty
            .wait_timeout(queue, timeout)
            .map_err(|_| QueueError::LockPoisoned)?;
        if let Some(item) = queue_guard.pop_front() {
            self.size.fetch_sub(1, Ordering::Relaxed);
            Ok(Some(item))
        } else {
            Ok(None)
        }
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for UnboundedQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Priority queue item wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityItem<T, P> {
    pub item: T,
    pub priority: P,
}

impl<T: Eq, P: Ord> Ord for PriorityItem<T, P> {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.priority.cmp(&other.priority)
    }
}

impl<T: Eq, P: Ord> PartialOrd for PriorityItem<T, P> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

/// High-performance priority queue
pub struct PriorityQueue<T, P> {
    heap: Mutex<BinaryHeap<PriorityItem<T, P>>>,
    not_empty: Condvar,
    size: AtomicUsize,
}

impl<T: Eq, P: Ord> PriorityQueue<T, P> {
    pub fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            not_empty: Condvar::new(),
            size: AtomicUsize::new(0),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::with_capacity(capacity)),
            not_empty: Condvar::new(),
            size: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, item: T, priority: P) -> Result<(), QueueError> {
        {
            let mut heap = self.heap.lock().map_err(|_| QueueError::LockPoisoned)?;
            heap.push(PriorityItem { item, priority });
        }
        self.size.fetch_add(1, Ordering::Relaxed);
        self.not_empty.notify_one();
        Ok(())
    }

    pub fn pop(&self) -> Result<Option<T>, QueueError> {
        let mut heap = self.heap.lock().map_err(|_| QueueError::LockPoisoned)?;
        if let Some(priority_item) = heap.pop() {
            self.size.fetch_sub(1, Ordering::Relaxed);
            Ok(Some(priority_item.item))
        } else {
            Ok(None)
        }
    }

    pub fn pop_with_priority(&self) -> Result<Option<(T, P)>, QueueError> {
        let mut heap = self.heap.lock().map_err(|_| QueueError::LockPoisoned)?;
        if let Some(priority_item) = heap.pop() {
            self.size.fetch_sub(1, Ordering::Relaxed);
            Ok(Some((priority_item.item, priority_item.priority)))
        } else {
            Ok(None)
        }
    }

    pub fn peek(&self) -> Result<Option<P>, QueueError>
    where
        P: Clone,
    {
        let heap = self.heap.lock().map_err(|_| QueueError::LockPoisoned)?;
        Ok(heap.peek().map(|item| item.priority.clone()))
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Eq, P: Ord> Default for PriorityQueue<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Zero-copy buffer for efficient data transfer
pub struct ZeroCopyBuffer {
    data: *mut u8,
    capacity: usize,
    len: AtomicUsize,
    layout: Layout,
}

impl ZeroCopyBuffer {
    pub fn new(capacity: usize) -> Result<Self, QueueError> {
        let layout = Layout::array::<u8>(capacity).map_err(|_| QueueError::AllocationFailed)?;
        let data = unsafe { alloc(layout) };

        if data.is_null() {
            return Err(QueueError::AllocationFailed);
        }

        Ok(Self {
            data,
            capacity,
            len: AtomicUsize::new(0),
            layout,
        })
    }

    pub fn write(&self, src: &[u8]) -> Result<usize, QueueError> {
        let current_len = self.len.load(Ordering::Acquire);
        let available = self.capacity - current_len;

        if src.len() > available {
            return Err(QueueError::BufferOverflow);
        }

        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.data.add(current_len), src.len());
        }

        self.len.store(current_len + src.len(), Ordering::Release);
        Ok(src.len())
    }

    pub fn read(&self, dst: &mut [u8]) -> usize {
        let current_len = self.len.load(Ordering::Acquire);
        let to_read = dst.len().min(current_len);

        if to_read > 0 {
            unsafe {
                ptr::copy_nonoverlapping(self.data, dst.as_mut_ptr(), to_read);

                // Shift remaining data
                if current_len > to_read {
                    ptr::copy(self.data.add(to_read), self.data, current_len - to_read);
                }
            }

            self.len.store(current_len - to_read, Ordering::Release);
        }

        to_read
    }

    pub fn peek(&self, dst: &mut [u8]) -> usize {
        let current_len = self.len.load(Ordering::Acquire);
        let to_read = dst.len().min(current_len);

        if to_read > 0 {
            unsafe {
                ptr::copy_nonoverlapping(self.data, dst.as_mut_ptr(), to_read);
            }
        }

        to_read
    }

    pub fn as_slice(&self) -> &[u8] {
        let len = self.len.load(Ordering::Acquire);
        unsafe { std::slice::from_raw_parts(self.data, len) }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn clear(&self) {
        self.len.store(0, Ordering::Release);
    }
}

impl Drop for ZeroCopyBuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.data, self.layout);
        }
    }
}

unsafe impl Send for ZeroCopyBuffer {}
unsafe impl Sync for ZeroCopyBuffer {}

/// Cache-optimized queue for better performance
pub struct CacheOptimizedQueue<T> {
    // Separate cache lines for head and tail to avoid false sharing
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
    buffer: *mut T,
    capacity: usize,
    layout: Layout,
}

#[repr(align(64))] // Align to cache line size
struct CachePadded<T> {
    value: T,
}

impl<T> CachePadded<T> {
    fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> std::ops::Deref for CachePadded<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> CacheOptimizedQueue<T> {
    pub fn new(capacity: usize) -> Result<Self, QueueError> {
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(QueueError::InvalidCapacity(capacity));
        }

        let layout = Layout::array::<T>(capacity).map_err(|_| QueueError::AllocationFailed)?;
        let buffer = unsafe { alloc(layout) as *mut T };

        if buffer.is_null() {
            return Err(QueueError::AllocationFailed);
        }

        Ok(Self {
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
            buffer,
            capacity,
            layout,
        })
    }

    pub fn push(&self, item: T) -> Result<(), T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) & (self.capacity - 1);

        if next_tail == self.head.load(Ordering::Acquire) {
            return Err(item); // Queue is full
        }

        unsafe {
            ptr::write(self.buffer.add(tail), item);
        }

        self.tail.store(next_tail, Ordering::Release);
        Ok(())
    }

    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);

        if head == self.tail.load(Ordering::Acquire) {
            return None; // Queue is empty
        }

        let item = unsafe { ptr::read(self.buffer.add(head)) };
        let next_head = (head + 1) & (self.capacity - 1);
        self.head.store(next_head, Ordering::Release);

        Some(item)
    }

    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        (tail.wrapping_sub(head)) & (self.capacity - 1)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    pub fn is_full(&self) -> bool {
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) & (self.capacity - 1);
        next_tail == self.head.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T> Drop for CacheOptimizedQueue<T> {
    fn drop(&mut self) {
        // Drop all remaining items
        while self.pop().is_some() {}

        // Deallocate buffer
        unsafe {
            dealloc(self.buffer as *mut u8, self.layout);
        }
    }
}

unsafe impl<T: Send> Send for CacheOptimizedQueue<T> {}
unsafe impl<T: Send> Sync for CacheOptimizedQueue<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_queue_creation() {
        // Valid creation
        let queue = BoundedQueue::<i32>::new(16);
        assert!(queue.is_ok());

        // Invalid capacity (not power of two)
        let queue = BoundedQueue::<i32>::new(10);
        assert!(matches!(queue, Err(QueueError::InvalidCapacity(10))));

        // Zero capacity
        let queue = BoundedQueue::<i32>::new(0);
        assert!(matches!(queue, Err(QueueError::InvalidCapacity(0))));
    }

    #[test]
    fn test_unbounded_queue_creation() {
        let queue = UnboundedQueue::<i32>::new();
        // UnboundedQueue::new() always succeeds
        assert!(queue.is_empty());
    }

    #[test]
    fn test_priority_queue_creation() {
        let queue = PriorityQueue::<i32, u8>::new();
        // PriorityQueue::new() always succeeds
        assert!(queue.is_empty());
    }

    #[test]
    fn test_zero_copy_buffer_creation() {
        let buffer = ZeroCopyBuffer::new(1024);
        // ZeroCopyBuffer::new() returns Result
        assert!(buffer.is_ok());
    }

    #[test]
    fn test_cache_optimized_queue_creation() {
        // Valid creation
        let queue = CacheOptimizedQueue::<i32>::new(16);
        assert!(queue.is_ok());

        // Invalid capacity
        let queue = CacheOptimizedQueue::<i32>::new(10);
        assert!(matches!(queue, Err(QueueError::InvalidCapacity(10))));
    }
}
