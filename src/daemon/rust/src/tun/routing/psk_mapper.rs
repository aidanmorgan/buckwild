use anyhow::{Result, bail};
use buckwild_common::types::time::Timestamp;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

/// PSK mapping entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskMapping {
    pub ip_address: IpAddr,
    pub psk_fingerprint: String,
    pub description: Option<String>,
    pub priority: u32,
    pub created_at: Timestamp,
    pub last_used: Option<Timestamp>,
    pub use_count: u64,
}

/// PSK lookup result
#[derive(Debug, Clone)]
pub struct PskLookupResult {
    pub fingerprint: String,
    pub mapping: PskMapping,
    pub from_cache: bool,
}

/// PSK mapping statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PskMappingStatistics {
    pub total_mappings: u32,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub default_psk_uses: u64,
    pub average_lookup_time_us: f64,
}

/// IP-to-PSK mapping manager with caching
pub struct PskMapper {
    mappings: Arc<RwLock<HashMap<IpAddr, PskMapping>>>,
    lookup_cache: Arc<RwLock<LruCache<IpAddr, PskLookupResult>>>,
    default_psk_fingerprint: Arc<RwLock<Option<String>>>,
    statistics: Arc<RwLock<PskMappingStatistics>>,
    cache_size: usize,
    cache_ttl: Duration,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl PskMapper {
    /// Create a new PSK mapper
    #[instrument]
    pub fn new(cache_size: usize, cache_ttl: Duration) -> Self {
        info!(
            "Creating PSK mapper with cache size: {}, TTL: {:?}",
            cache_size, cache_ttl
        );

        PskMapper {
            mappings: Arc::new(RwLock::new(HashMap::new())),
            lookup_cache: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(cache_size)
                    .unwrap_or(std::num::NonZeroUsize::new(1000).unwrap()),
            ))),
            default_psk_fingerprint: Arc::new(RwLock::new(None)),
            statistics: Arc::new(RwLock::new(PskMappingStatistics::default())),
            cache_size,
            cache_ttl,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the PSK mapper
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Acquire) {
            warn!("PSK mapper already running");
            return Ok(());
        }

        info!("Starting PSK mapper");
        self.running
            .store(true, std::sync::atomic::Ordering::Release);

        // Start cache cleanup task
        let lookup_cache = Arc::clone(&self.lookup_cache);
        let statistics = Arc::clone(&self.statistics);
        let running = Arc::clone(&self.running);
        let _cache_ttl = self.cache_ttl;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Cleanup every minute

            while running.load(std::sync::atomic::Ordering::Acquire) {
                interval.tick().await;

                // Note: LruCache doesn't have built-in TTL, so this is a simplified cleanup
                // In a real implementation, you'd track timestamps and remove expired entries
                let cache_size = {
                    let cache = lookup_cache.read().await;
                    cache.len()
                };

                debug!("Cache cleanup completed, cache size: {}", cache_size);

                // Update statistics
                let mut stats = statistics.write().await;
                if stats.cache_hits + stats.cache_misses > 0 {
                    stats.cache_hit_rate = (stats.cache_hits as f64
                        / (stats.cache_hits + stats.cache_misses) as f64)
                        * 100.0;
                }
            }

            info!("PSK mapper cleanup task terminated");
        });

        Ok(())
    }

    /// Stop the PSK mapper
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping PSK mapper");
        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Clear caches
        self.lookup_cache.write().await.clear();

        info!("PSK mapper stopped");
    }

    /// Set default PSK fingerprint
    #[instrument(skip(self))]
    pub async fn set_default_psk(&self, fingerprint: String) -> Result<()> {
        debug!("Setting default PSK fingerprint: {}", fingerprint);

        if fingerprint.is_empty() {
            bail!("Default PSK fingerprint cannot be empty");
        }

        *self.default_psk_fingerprint.write().await = Some(fingerprint.clone());

        // Clear cache to ensure new default is used
        self.lookup_cache.write().await.clear();

        info!("Set default PSK fingerprint");
        Ok(())
    }

    /// Add PSK mapping
    #[instrument(skip(self))]
    pub async fn add_mapping(&self, mapping: PskMapping) -> Result<()> {
        debug!(
            "Adding PSK mapping: {} -> {}",
            mapping.ip_address, mapping.psk_fingerprint
        );

        if mapping.psk_fingerprint.is_empty() {
            bail!("PSK fingerprint cannot be empty");
        }

        // Validate IP address format
        match mapping.ip_address {
            IpAddr::V4(_) | IpAddr::V6(_) => {} // Valid
        }

        // Add to mappings
        self.mappings
            .write()
            .await
            .insert(mapping.ip_address, mapping.clone());

        // Invalidate cache entry
        self.lookup_cache.write().await.pop(&mapping.ip_address);

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.total_mappings = self.mappings.read().await.len() as u32;

        info!(
            "Added PSK mapping: {} -> {}",
            mapping.ip_address, mapping.psk_fingerprint
        );
        Ok(())
    }

    /// Remove PSK mapping
    #[instrument(skip(self))]
    pub async fn remove_mapping(&self, ip_address: &IpAddr) -> Result<()> {
        debug!("Removing PSK mapping for: {}", ip_address);

        let removed = self.mappings.write().await.remove(ip_address);

        if removed.is_some() {
            // Invalidate cache entry
            self.lookup_cache.write().await.pop(ip_address);

            // Update statistics
            let mut stats = self.statistics.write().await;
            stats.total_mappings = self.mappings.read().await.len() as u32;

            info!("Removed PSK mapping for: {}", ip_address);
        } else {
            warn!(
                "Attempted to remove non-existent mapping for: {}",
                ip_address
            );
        }

        Ok(())
    }

    /// Update PSK mapping batch
    #[instrument(skip(self, mappings))]
    pub async fn update_mappings_batch(
        &self,
        mappings: HashMap<IpAddr, PskMapping>,
    ) -> Result<Vec<IpAddr>> {
        debug!(
            "Updating PSK mappings batch with {} entries",
            mappings.len()
        );

        let mut updated_ips = Vec::new();
        let mut failed_ips = Vec::new();

        for (ip, mapping) in mappings {
            if mapping.psk_fingerprint.is_empty() {
                error!("Invalid PSK fingerprint for IP {}", ip);
                failed_ips.push(ip);
                continue;
            }

            match self.add_mapping(mapping).await {
                Ok(()) => updated_ips.push(ip),
                Err(e) => {
                    error!("Failed to add mapping for {}: {}", ip, e);
                    failed_ips.push(ip);
                }
            }
        }

        if !failed_ips.is_empty() {
            warn!(
                "Failed to update {} mappings: {:?}",
                failed_ips.len(),
                failed_ips
            );
        }

        info!("Updated {} PSK mappings successfully", updated_ips.len());
        Ok(updated_ips)
    }

    /// Lookup PSK fingerprint for IP address
    #[instrument(skip(self))]
    pub async fn lookup_psk(&self, ip_address: &IpAddr) -> Result<PskLookupResult> {
        let start_time = Timestamp::now();

        // Check cache first
        {
            let mut cache = self.lookup_cache.write().await;
            if let Some(cached_result) = cache.get(ip_address) {
                let mut stats = self.statistics.write().await;
                stats.cache_hits += 1;

                debug!("Cache hit for PSK lookup: {}", ip_address);
                return Ok(PskLookupResult {
                    fingerprint: cached_result.fingerprint.clone(),
                    mapping: cached_result.mapping.clone(),
                    from_cache: true,
                });
            }
        }

        // Cache miss - lookup in mappings
        let lookup_result = {
            let mut mappings = self.mappings.write().await;

            if let Some(mapping) = mappings.get_mut(ip_address) {
                // Update usage statistics
                mapping.last_used = Some(Timestamp::now());
                mapping.use_count += 1;

                PskLookupResult {
                    fingerprint: mapping.psk_fingerprint.clone(),
                    mapping: mapping.clone(),
                    from_cache: false,
                }
            } else {
                // Use default PSK if available
                let default_fingerprint = self.default_psk_fingerprint.read().await.clone();

                if let Some(fingerprint) = default_fingerprint {
                    let mut stats = self.statistics.write().await;
                    stats.default_psk_uses += 1;

                    debug!("Using default PSK for: {}", ip_address);

                    PskLookupResult {
                        fingerprint: fingerprint.clone(),
                        mapping: PskMapping {
                            ip_address: *ip_address,
                            psk_fingerprint: fingerprint,
                            description: Some("Default PSK".to_string()),
                            priority: 0,
                            created_at: Timestamp::now(),
                            last_used: Some(Timestamp::now()),
                            use_count: 1,
                        },
                        from_cache: false,
                    }
                } else {
                    bail!(
                        "No PSK mapping found for {} and no default PSK configured",
                        ip_address
                    );
                }
            }
        };

        // Cache the result
        {
            let mut cache = self.lookup_cache.write().await;
            cache.put(*ip_address, lookup_result.clone());
        }

        // Update statistics
        let end_time = Timestamp::now();
        let lookup_time_micros = end_time.as_micros() - start_time.as_micros();
        let mut stats = self.statistics.write().await;
        stats.cache_misses += 1;

        // Update average lookup time
        let total_lookups = stats.cache_hits + stats.cache_misses;
        let total_time =
            stats.average_lookup_time_us * (total_lookups - 1) as f64 + lookup_time_micros as f64;
        stats.average_lookup_time_us = total_time / total_lookups as f64;

        debug!(
            "PSK lookup completed for {}: {} ({}μs)",
            ip_address, lookup_result.fingerprint, lookup_time_micros
        );

        Ok(lookup_result)
    }

    /// Get all mappings
    pub async fn get_all_mappings(&self) -> HashMap<IpAddr, PskMapping> {
        self.mappings.read().await.clone()
    }

    /// Get mapping for specific IP
    pub async fn get_mapping(&self, ip_address: &IpAddr) -> Option<PskMapping> {
        self.mappings.read().await.get(ip_address).cloned()
    }

    /// Check if mapping exists
    pub async fn mapping_exists(&self, ip_address: &IpAddr) -> bool {
        self.mappings.read().await.contains_key(ip_address)
    }

    /// Clear all mappings
    #[instrument(skip(self))]
    pub async fn clear_all_mappings(&self) -> Result<()> {
        info!("Clearing all PSK mappings");

        self.mappings.write().await.clear();
        self.lookup_cache.write().await.clear();

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.total_mappings = 0;

        info!("Cleared all PSK mappings");
        Ok(())
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> PskMappingStatistics {
        let mut stats = self.statistics.read().await.clone();
        stats.total_mappings = self.mappings.read().await.len() as u32;

        if stats.cache_hits + stats.cache_misses > 0 {
            stats.cache_hit_rate =
                (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64) * 100.0;
        }

        stats
    }

    /// Preload mappings from configuration
    #[instrument(skip(self, mappings))]
    pub async fn preload_mappings(&self, mappings: Vec<PskMapping>) -> Result<()> {
        info!("Preloading {} PSK mappings", mappings.len());

        let mut mapping_map = HashMap::new();
        for mapping in mappings {
            mapping_map.insert(mapping.ip_address, mapping);
        }

        let updated_ips = self.update_mappings_batch(mapping_map).await?;

        info!("Preloaded {} PSK mappings successfully", updated_ips.len());
        Ok(())
    }
}
