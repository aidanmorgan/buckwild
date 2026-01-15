// Fragment memory management
//
// This module provides memory management for fragment storage and reassembly
// with efficient allocation, deallocation, and memory pool management.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

// Import ALL types from the authoritative consolidated types module
use crate::error::{FragmentationError, FragmentationResult};
use crate::protocol::types::*;

/// Fragment memory manager for efficient fragment storage
pub struct FragmentMemoryManager {
    /// Memory pools for different fragment sizes
    memory_pools: Arc<RwLock<HashMap<usize, MemoryPool>>>,
    /// Fragment storage
    fragment_storage: Arc<RwLock<HashMap<FragmentKey, StoredFragment>>>,
    /// Memory configuration
    config: MemoryConfig,
    /// Statistics
    stats: Arc<RwLock<FragmentMemoryStats>>,
}

/// Memory configuration for fragment management
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Maximum memory usage in bytes
    pub max_memory_usage: usize,
    /// Pool sizes for different fragment sizes
    pub pool_sizes: Vec<(usize, usize)>, // (fragment_size.clone(), pool_size)
    /// Fragment timeout in seconds
    pub fragment_timeout_sec: FragmentTimeout,
    /// Enable memory pooling
    pub enable_pooling: bool,
    /// Enable memory compression
    pub enable_compression: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_memory_usage: 64 * 1024 * 1024, // 64MB
            pool_sizes: vec![
                (64, 1000),  // Small fragments
                (256, 500),  // Medium fragments
                (1024, 200), // Large fragments
                (1400, 100), // MTU-sized fragments
            ],
            fragment_timeout_sec: FragmentTimeout::new(30),
            enable_pooling: true,
            enable_compression: false, // Disabled by default for performance
        }
    }
}

/// Memory pool for fragment buffers
#[derive(Debug)]
struct MemoryPool {
    /// Fragment size for this pool
    fragment_size: usize,
    /// Available buffers
    available_buffers: Vec<BytesMut>,
    /// Maximum pool size
    max_size: usize,
    /// Current pool size
    #[allow(dead_code)]
    current_size: usize,
    /// Pool statistics
    allocations: Counter,
    deallocations: Counter,
    hits: Counter,
    misses: Counter,
}

/// Key for fragment storage
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FragmentKey {
    session_id: SessionId,
    fragment_id: FragmentId,
    fragment_index: FragmentIndex,
}

/// Stored fragment with metadata
#[derive(Debug, Clone)]
struct StoredFragment {
    /// Fragment data
    data: Bytes,
    /// Storage timestamp
    stored_at: SystemTime,
    /// Fragment size
    size: usize,
    /// Compression status
    compressed: bool,
}

/// Fragment memory statistics
#[derive(Debug, Clone)]
pub struct FragmentMemoryStats {
    /// Total memory usage in bytes
    pub total_memory_usage: usize,
    /// Number of stored fragments
    pub stored_fragments: usize,
    /// Memory pool statistics
    pub pool_stats: Vec<PoolStats>,
    /// Total allocations
    pub total_allocations: Counter,
    /// Total deallocations
    pub total_deallocations: Counter,
    /// Cache hit rate
    pub cache_hit_rate: f64,
}

/// Memory pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Fragment size for this pool
    pub fragment_size: usize,
    /// Current pool size
    pub current_size: usize,
    /// Maximum pool size
    pub max_size: usize,
    /// Total allocations from this pool
    pub allocations: Counter,
    /// Total deallocations to this pool
    pub deallocations: Counter,
    /// Cache hits
    pub hits: Counter,
    /// Cache misses
    pub misses: Counter,
    /// Hit rate
    pub hit_rate: f64,
}

impl FragmentMemoryManager {
    /// Create a new fragment memory manager
    pub fn new() -> Self {
        Self::with_config(MemoryConfig::default())
    }

    /// Create a new fragment memory manager with custom configuration
    pub fn with_config(config: MemoryConfig) -> Self {
        let mut memory_pools = HashMap::new();

        // Initialize memory pools
        if config.enable_pooling {
            for (fragment_size, pool_size) in &config.pool_sizes {
                memory_pools.insert(
                    *fragment_size,
                    MemoryPool {
                        fragment_size: *fragment_size,
                        available_buffers: Vec::with_capacity(*pool_size),
                        max_size: *pool_size,
                        current_size: 0,
                        allocations: Counter::new(0),
                        deallocations: Counter::new(0),
                        hits: Counter::new(0),
                        misses: Counter::new(0),
                    },
                );
            }
        }

        Self {
            memory_pools: Arc::new(RwLock::new(memory_pools)),
            fragment_storage: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(FragmentMemoryStats {
                total_memory_usage: 0,
                stored_fragments: 0,
                pool_stats: Vec::new(),
                total_allocations: Counter::new(0),
                total_deallocations: Counter::new(0),
                cache_hit_rate: 0.0,
            })),
        }
    }

    /// Allocate a buffer for fragment storage
    pub fn allocate_buffer(&self, size: usize) -> BytesMut {
        if !self.config.enable_pooling {
            self.update_allocation_stats();
            return BytesMut::with_capacity(size);
        }

        // Find the best-fit pool
        let pool_size = self.find_best_pool_size(size);

        let mut pools = self.memory_pools.write().unwrap_or_else(|e| e.into_inner());
        if let Some(pool) = pools.get_mut(&pool_size) {
            pool.allocations += 1;

            if let Some(buffer) = pool.available_buffers.pop() {
                pool.hits += 1;
                self.update_allocation_stats();
                return buffer;
            }
            pool.misses += 1;
        }

        // No available buffer in pool, allocate new one
        self.update_allocation_stats();
        BytesMut::with_capacity(size)
    }

    /// Deallocate a buffer back to the pool
    pub fn deallocate_buffer(&self, mut buffer: BytesMut) {
        if !self.config.enable_pooling {
            self.update_deallocation_stats();
            return;
        }

        let capacity = buffer.capacity();
        let pool_size = self.find_best_pool_size(capacity);

        // Clear the buffer for reuse
        buffer.clear();

        let mut pools = self.memory_pools.write().unwrap_or_else(|e| e.into_inner());
        if let Some(pool) = pools.get_mut(&pool_size) {
            pool.deallocations += 1;

            if pool.available_buffers.len() < pool.max_size {
                pool.available_buffers.push(buffer);
            }
        }

        self.update_deallocation_stats();
    }

    /// Store a fragment in memory
    pub fn store_fragment(
        &self,
        session_id: SessionId,
        fragment_id: FragmentId,
        fragment_index: FragmentIndex,
        data: Bytes,
    ) -> FragmentationResult<()> {
        let session_id_for_error = session_id.clone();
        let key = FragmentKey {
            session_id,
            fragment_id,
            fragment_index,
        };

        // Check memory limits
        let current_usage = self.get_current_memory_usage();
        if current_usage + data.len() > self.config.max_memory_usage {
            return Err(FragmentationError::ReassemblyMemoryExhausted {
                session_id: session_id_for_error,
            });
        }

        let stored_fragment = StoredFragment {
            size: data.len(),
            data: if self.config.enable_compression {
                self.compress_data(data)?
            } else {
                data
            },
            stored_at: SystemTime::now(),
            compressed: self.config.enable_compression,
        };

        let mut storage = self
            .fragment_storage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        storage.insert(key, stored_fragment);

        self.update_storage_stats();
        Ok(())
    }

    /// Retrieve a stored fragment
    pub fn retrieve_fragment(
        &self,
        session_id: SessionId,
        fragment_id: FragmentId,
        fragment_index: FragmentIndex,
    ) -> Option<Bytes> {
        let key = FragmentKey {
            session_id,
            fragment_id,
            fragment_index,
        };

        let storage = self
            .fragment_storage
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(stored_fragment) = storage.get(&key) {
            if stored_fragment.compressed {
                self.decompress_data(stored_fragment.data.clone()).ok()
            } else {
                Some(stored_fragment.data.clone())
            }
        } else {
            None
        }
    }

    /// Remove a stored fragment
    pub fn remove_fragment(
        &self,
        session_id: SessionId,
        fragment_id: FragmentId,
        fragment_index: FragmentIndex,
    ) -> bool {
        let key = FragmentKey {
            session_id,
            fragment_id,
            fragment_index,
        };

        let mut storage = self
            .fragment_storage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let removed = storage.remove(&key).is_some();

        if removed {
            self.update_storage_stats();
        }

        removed
    }

    /// Clean up expired fragments
    pub fn cleanup_expired_fragments(&self) {
        let timeout_ns = self.config.fragment_timeout_sec.as_u64() * 1_000_000_000;
        let timeout = std::time::Duration::from_nanos(timeout_ns);
        let now = SystemTime::now();

        {
            let mut storage = self
                .fragment_storage
                .write()
                .unwrap_or_else(|e| e.into_inner());
            storage.retain(|_, fragment| {
                now.duration_since(fragment.stored_at).unwrap_or_default() < timeout
            });
        } // Write lock released here before calling update_storage_stats

        self.update_storage_stats();
    }

    /// Get current memory usage
    fn get_current_memory_usage(&self) -> usize {
        let storage = self
            .fragment_storage
            .read()
            .unwrap_or_else(|e| e.into_inner());
        storage.values().map(|f| f.size).sum()
    }

    /// Find the best pool size for a given fragment size
    fn find_best_pool_size(&self, size: usize) -> usize {
        self.config
            .pool_sizes
            .iter()
            .find(|(pool_size, _)| *pool_size >= size)
            .map(|(pool_size, _)| *pool_size)
            .unwrap_or(size)
    }

    /// Compress fragment data
    ///
    /// Currently implements pass-through (no compression) for performance.
    /// Compression is disabled by default via config.enable_compression = false.
    /// Future enhancement: integrate lz4 or zstd compression when needed.
    fn compress_data(&self, data: Bytes) -> FragmentationResult<Bytes> {
        // Small fragments don't benefit from compression
        if data.len() < 64 {
            return Ok(data);
        }

        // Pass-through implementation - compression disabled for performance
        // This is intentional and controlled by config.enable_compression flag
        Ok(data)
    }

    /// Decompress fragment data
    ///
    /// Currently implements pass-through (no decompression) matching compress_data.
    /// Future enhancement: integrate lz4 or zstd decompression when compression is enabled.
    fn decompress_data(&self, data: Bytes) -> FragmentationResult<Bytes> {
        // Pass-through implementation - decompression not needed when compression is disabled
        Ok(data)
    }

    /// Update allocation statistics
    fn update_allocation_stats(&self) {
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.total_allocations += 1;
    }

    /// Update deallocation statistics
    fn update_deallocation_stats(&self) {
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.total_deallocations += 1;
    }

    /// Update storage statistics
    fn update_storage_stats(&self) {
        let storage = self
            .fragment_storage
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());

        stats.total_memory_usage = storage.values().map(|f| f.size).sum::<usize>();
        stats.stored_fragments = storage.len();
    }

    /// Get memory statistics
    pub fn get_stats(&self) -> FragmentMemoryStats {
        let pools = self.memory_pools.read().unwrap_or_else(|e| e.into_inner());
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());

        // Update pool statistics
        stats.pool_stats = pools
            .values()
            .map(|pool| {
                let hit_rate = if pool.allocations > Counter::new(0) {
                    f64::from(pool.hits) / f64::from(pool.allocations)
                } else {
                    0.0
                };

                PoolStats {
                    fragment_size: pool.fragment_size,
                    current_size: pool.available_buffers.len(),
                    max_size: pool.max_size,
                    allocations: pool.allocations,
                    deallocations: pool.deallocations,
                    hits: pool.hits,
                    misses: pool.misses,
                    hit_rate,
                }
            })
            .collect();

        // Calculate overall cache hit rate
        let total_hits: u64 = pools.values().map(|p| p.hits).sum::<u64>();
        let total_allocations: u64 = pools.values().map(|p| p.allocations).sum::<u64>();
        stats.cache_hit_rate = if total_allocations > 0 {
            total_hits as f64 / total_allocations as f64
        } else {
            0.0
        };

        stats.clone()
    }

    /// Optimize memory usage
    pub fn optimize_memory(&self) {
        // Clean up expired fragments
        self.cleanup_expired_fragments();

        // Trim memory pools if they're too large
        let mut pools = self.memory_pools.write().unwrap_or_else(|e| e.into_inner());
        for pool in pools.values_mut() {
            let target_size = pool.max_size / 2;
            if pool.available_buffers.len() > target_size {
                pool.available_buffers.truncate(target_size);
            }
        }
    }

    /// Get memory pool information
    pub fn get_pool_info(&self) -> Vec<PoolStats> {
        self.get_stats().pool_stats
    }
}

impl Default for FragmentMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}
