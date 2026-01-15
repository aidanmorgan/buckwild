#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Memory pool engine with lock-free operations
use crate::error::BuckwildError;
use crate::protocol::types::*;
use crossbeam::utils::CachePadded;
use std::alloc::{Layout, alloc, dealloc};
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

/// Lock-free memory pool for fixed-size allocations
pub struct MemoryPool {
    /// Free list head (lock-free stack)
    free_head: AtomicPtr<PoolNode>,
    /// Block size for this pool
    block_size: BufferSize,
    /// Total capacity
    capacity: SizeLimit,
    /// Current allocation count
    allocated_count: UsageCount,
    /// Pool memory region
    memory_region: NonNull<u8>,
    /// Layout for deallocation
    layout: Layout,
}

/// Node in the free list
struct PoolNode {
    next: *mut PoolNode,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new(block_size: BufferSize, capacity: SizeLimit) -> Result<Self, BuckwildError> {
        let block_size_raw = block_size.as_usize();
        let capacity_raw = capacity.as_usize();

        if block_size_raw < mem::size_of::<PoolNode>() {
            return Err(BuckwildError::internal_error(
                "Block size too small for pool node",
            ));
        }

        if capacity_raw == 0 {
            return Err(BuckwildError::internal_error(
                "Pool capacity cannot be zero",
            ));
        }

        // Align block size to pointer size
        let aligned_block_size =
            (block_size_raw + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1);

        let total_size = aligned_block_size * capacity_raw;
        let layout = Layout::from_size_align(total_size, mem::align_of::<usize>())
            .map_err(|_| BuckwildError::internal_error("Invalid memory layout"))?;

        // Allocate the memory region
        let memory_region = unsafe {
            let ptr = alloc(layout);
            if ptr.is_null() {
                return Err(BuckwildError::internal_error("Memory allocation failed"));
            }
            NonNull::new_unchecked(ptr)
        };

        // Initialize the free list
        let current_ptr = memory_region.as_ptr();
        let mut prev_node: *mut PoolNode = ptr::null_mut();

        // Build the free list in reverse order
        for i in (0..capacity_raw).rev() {
            let node_ptr = unsafe { current_ptr.add(i * aligned_block_size) as *mut PoolNode };
            unsafe {
                (*node_ptr).next = prev_node;
            }
            prev_node = node_ptr;
        }

        Ok(Self {
            free_head: AtomicPtr::new(prev_node),
            block_size: BufferSize::new(aligned_block_size),
            capacity,
            allocated_count: UsageCount::new(0),
            memory_region,
            layout,
        })
    }

    /// Allocate a block from the pool
    pub fn allocate(&self) -> Option<PooledMemory> {
        loop {
            let head = self.free_head.load(Ordering::Acquire);
            if head.is_null() {
                // Pool is exhausted
                return None;
            }

            let next = unsafe { (*head).next };

            // Try to update the head to the next node
            match self.free_head.compare_exchange_weak(
                head,
                next,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Successfully allocated
                    self.allocated_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Safety: head was checked to be non-null before CAS
                    let ptr = NonNull::new(head as *mut u8)?;

                    return Some(PooledMemory {
                        ptr,
                        size: MemorySize::new(self.block_size.as_usize() as u64),
                        pool: self as *const Self,
                    });
                }
                Err(_) => {
                    // CAS failed, retry
                    continue;
                }
            }
        }
    }

    /// Deallocate a block back to the pool
    fn deallocate(&self, ptr: NonNull<u8>) {
        let node = ptr.as_ptr() as *mut PoolNode;

        loop {
            let head = self.free_head.load(Ordering::Acquire);
            unsafe {
                (*node).next = head;
            }

            match self.free_head.compare_exchange_weak(
                head,
                node,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.allocated_count.fetch_sub(1, Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    // CAS failed, retry
                    continue;
                }
            }
        }
    }

    /// Get the block size
    pub fn block_size(&self) -> BufferSize {
        self.block_size
    }

    /// Get the total capacity
    pub fn capacity(&self) -> SizeLimit {
        self.capacity
    }

    /// Get the current allocation count
    pub fn allocated_count(&self) -> usize {
        self.allocated_count.load(Ordering::Relaxed) as usize
    }

    /// Get the available count
    pub fn available_count(&self) -> usize {
        self.capacity.as_usize() - self.allocated_count()
    }

    /// Check if the pool is full
    pub fn is_full(&self) -> bool {
        self.allocated_count() >= self.capacity.as_usize()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.allocated_count() == 0
    }

    /// Get utilization percentage
    pub fn utilization(&self) -> f64 {
        self.allocated_count() as f64 / self.capacity.as_usize() as f64
    }
}

impl Drop for MemoryPool {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.memory_region.as_ptr(), self.layout);
        }
    }
}

unsafe impl Send for MemoryPool {}
unsafe impl Sync for MemoryPool {}

/// Memory allocated from a pool
pub struct PooledMemory {
    ptr: NonNull<u8>,
    size: MemorySize,
    pool: *const MemoryPool,
}

impl PooledMemory {
    /// Get the memory as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size.as_usize()) }
    }

    /// Get the memory as a slice
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size.as_usize()) }
    }

    /// Get the size of the allocated memory
    pub fn size(&self) -> usize {
        self.size.as_usize()
    }

    /// Get a raw pointer to the memory
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for PooledMemory {
    fn drop(&mut self) {
        unsafe {
            (*self.pool).deallocate(self.ptr);
        }
    }
}

unsafe impl Send for PooledMemory {}
unsafe impl Sync for PooledMemory {}

/// Multi-size memory pool manager
pub struct MemoryPoolManager {
    pools: Vec<CachePadded<Arc<MemoryPool>>>,
    size_classes: Vec<usize>,
}

impl MemoryPoolManager {
    /// Create a new pool manager with standard size classes
    pub fn new() -> Result<Self, BuckwildError> {
        // Standard size classes: 64, 128, 256, 512, 1024, 2048, 4096, 8192 bytes
        let size_classes = vec![64, 128, 256, 512, 1024, 2048, 4096, 8192];
        let capacity_per_pool = 1024; // Adjust based on needs

        let mut pools = Vec::new();
        for &size in &size_classes {
            let pool = Arc::new(MemoryPool::new(
                BufferSize::new(size),
                SizeLimit::new(capacity_per_pool),
            )?);
            pools.push(CachePadded::new(pool));
        }

        Ok(Self {
            pools,
            size_classes,
        })
    }

    /// Create a new pool manager with custom size classes
    pub fn with_size_classes(
        size_classes: Vec<usize>,
        capacity_per_pool: Capacity,
    ) -> Result<Self, BuckwildError> {
        let mut pools = Vec::new();
        for &size in &size_classes {
            let pool = Arc::new(MemoryPool::new(
                BufferSize::new(size),
                SizeLimit::new(capacity_per_pool.as_usize()),
            )?);
            pools.push(CachePadded::new(pool));
        }

        Ok(Self {
            pools,
            size_classes,
        })
    }

    /// Allocate memory of the requested size
    pub fn allocate(&self, size: usize) -> Option<PooledMemory> {
        // Find the appropriate size class
        let pool_index = self
            .size_classes
            .iter()
            .position(|&class_size| class_size >= size)?;

        self.pools[pool_index].allocate()
    }

    /// Get the best size class for the given size
    pub fn size_class_for(&self, size: usize) -> Option<usize> {
        self.size_classes
            .iter()
            .find(|&&class_size| class_size >= size)
            .copied()
    }

    /// Get pool statistics
    pub fn statistics(&self) -> PoolManagerStatistics {
        let mut stats = PoolManagerStatistics {
            total_pools: Capacity::new(self.pools.len() as u32),
            pool_stats: Vec::new(),
        };

        for (i, pool) in self.pools.iter().enumerate() {
            stats.pool_stats.push(PoolStatistics {
                size_class: MemorySize::new(self.size_classes[i] as u64),
                capacity: Capacity::new(pool.capacity().as_usize() as u32),
                allocated: PacketCount::new(pool.allocated_count() as u64),
                available: PacketCount::new(pool.available_count() as u64),
                utilization: MetricValue::new(pool.utilization()),
            });
        }

        stats
    }
}

impl Default for MemoryPoolManager {
    /// Creates a default memory pool manager
    ///
    /// # Panics
    ///
    /// Note: This implementation uses unwrap_or_else to handle allocation failures
    /// gracefully by falling back to an empty manager. For explicit error handling,
    /// use `MemoryPoolManager::new()` instead.
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback to an empty manager if default creation fails
            MemoryPoolManager {
                pools: Vec::new(),
                size_classes: Vec::new(),
            }
        })
    }
}

/// Statistics for a single pool
#[derive(Debug, Clone)]
pub struct PoolStatistics {
    pub size_class: MemorySize,
    pub capacity: Capacity,
    pub allocated: PacketCount,
    pub available: PacketCount,
    pub utilization: MetricValue,
}

/// Statistics for the pool manager
#[derive(Debug, Clone)]
pub struct PoolManagerStatistics {
    pub total_pools: Capacity,
    pub pool_stats: Vec<PoolStatistics>,
}

impl PoolManagerStatistics {
    /// Get total allocated memory across all pools
    pub fn total_allocated(&self) -> MemorySize {
        let total = self
            .pool_stats
            .iter()
            .map(|stat| stat.allocated.as_u64() as usize * stat.size_class.as_usize())
            .sum::<usize>() as u64;
        MemorySize::new(total)
    }

    /// Get total available memory across all pools
    pub fn total_available(&self) -> MemorySize {
        let total = self
            .pool_stats
            .iter()
            .map(|stat| stat.available.as_u64() as usize * stat.size_class.as_usize())
            .sum::<usize>() as u64;
        MemorySize::new(total)
    }

    /// Get overall utilization
    pub fn overall_utilization(&self) -> MetricValue {
        let total_allocated = self.total_allocated().as_usize() as f64;
        let total_capacity = self
            .pool_stats
            .iter()
            .map(|stat| stat.capacity.as_usize() * stat.size_class.as_usize())
            .sum::<usize>() as f64;

        if total_capacity > 0.0 {
            MetricValue::new(total_allocated / total_capacity)
        } else {
            MetricValue::new(0.0)
        }
    }
}

/// PacketPool is an alias for MemoryPool specialized for packet buffers
pub type PacketPool = MemoryPool;

/// Global packet pool for zero-copy packet operations
static GLOBAL_PACKET_POOL: std::sync::OnceLock<Arc<PacketPool>> = std::sync::OnceLock::new();

/// Get or initialize the global packet pool
pub fn global_packet_pool() -> &'static Arc<PacketPool> {
    GLOBAL_PACKET_POOL.get_or_init(|| {
        // Default packet pool: 2KB blocks, 1024 capacity
        Arc::new(
            PacketPool::new(BufferSize::new(2048), SizeLimit::new(1024))
                .unwrap_or_else(|e| panic!("Failed to initialize global packet pool: {e}")),
        )
    })
}
