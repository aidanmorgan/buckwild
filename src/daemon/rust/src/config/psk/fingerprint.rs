use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use rayon::ThreadPool;
use thiserror::Error;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::{instrument, warn};

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

use crate::crypto::secure_storage::SecureBytes;

/// Errors that can occur during fingerprint calculation
#[derive(Error, Debug)]
pub enum FingerprintError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid PSK data")]
    InvalidPskData,

    #[error("Calculation queue is full")]
    QueueFull,

    #[error("Calculation was cancelled")]
    Cancelled,
}

/// Type alias for batch fingerprint results
pub type BatchResult = Vec<(String, Result<String, FingerprintError>)>;

/// Result of a fingerprint calculation
#[derive(Debug)]

struct CalculationResult {
    /// The calculated fingerprint
    fingerprint: String,

    /// The PSK data
    psk: Arc<SecureBytes>,

    /// Optional identifier for tracking
    id: Option<String>,
}

/// Request for fingerprint calculation
#[derive(Debug)]
struct CalculationRequest {
    /// The PSK data to calculate fingerprint for
    psk: Arc<SecureBytes>,

    /// Optional identifier for tracking
    id: Option<String>,

    /// Channel for sending the result
    result_sender: Option<tokio::sync::oneshot::Sender<Result<String, FingerprintError>>>,
}

/// Manages fingerprint calculation with a thread pool
pub struct FingerprintCalculator {
    /// Thread pool for calculation
    thread_pool: Arc<ThreadPool>,

    /// Channel for sending calculation requests
    request_sender: UnboundedSender<CalculationRequest>,

    /// Cache of calculated fingerprints
    fingerprint_cache: Arc<DashMap<String, String>>,

    /// Counter for total calculations
    total_calculations: AtomicUsize,

    /// Counter for cache hits
    cache_hits: AtomicUsize,

    /// Counter for in-progress calculations
    in_progress: AtomicUsize,
}

impl FingerprintCalculator {
    /// Create a new fingerprint calculator with the specified number of threads
    pub fn new(num_threads: WorkerThreadCount) -> Self {
        // Create thread pool
        let thread_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads.as_raw() as usize)
                .build()
                .expect("Failed to create thread pool"),
        );

        // Create channels
        let (request_sender, request_receiver) = mpsc::unbounded_channel();

        // Create cache
        let fingerprint_cache = Arc::new(DashMap::new());

        // Create calculator
        let calculator = Self {
            thread_pool: thread_pool.clone(),
            request_sender,
            fingerprint_cache: fingerprint_cache.clone(),
            total_calculations: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
            in_progress: AtomicUsize::new(0),
        };

        // Start processing loop
        Self::start_processing_loop(request_receiver, thread_pool, fingerprint_cache);

        calculator
    }

    /// Start the processing loop for calculation requests
    fn start_processing_loop(
        mut request_receiver: UnboundedReceiver<CalculationRequest>,
        thread_pool: Arc<ThreadPool>,
        fingerprint_cache: Arc<DashMap<String, String>>,
    ) {
        tokio::spawn(async move {
            while let Some(request) = request_receiver.recv().await {
                let thread_pool = thread_pool.clone();
                let fingerprint_cache = fingerprint_cache.clone();

                // Process the request
                tokio::task::spawn_blocking(move || {
                    thread_pool.spawn(move || {
                        // Calculate fingerprint
                        let result = calculate_fingerprint_internal(&request.psk);

                        match result {
                            Ok(fingerprint) => {
                                // Cache the result
                                if let Some(id) = &request.id {
                                    fingerprint_cache.insert(id.clone(), fingerprint.clone());
                                }

                                // Send result if requested
                                if let Some(sender) = request.result_sender {
                                    let _ = sender.send(Ok(fingerprint));
                                }
                            }
                            Err(e) => {
                                // Send error if requested
                                if let Some(sender) = request.result_sender {
                                    let _ = sender.send(Err(e));
                                }
                            }
                        }
                    });
                });
            }
        });
    }

    /// Calculate a fingerprint for the given PSK data
    #[instrument(skip(self, psk), err)]
    pub async fn calculate(&self, psk: Arc<SecureBytes>) -> Result<String, FingerprintError> {
        self.total_calculations.fetch_add(1, Ordering::Relaxed);
        self.in_progress.fetch_add(1, Ordering::Relaxed);

        // Create channel for result
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();

        // Create request
        let request = CalculationRequest {
            psk,
            id: None,
            result_sender: Some(result_sender),
        };

        // Send request
        self.request_sender
            .send(request)
            .map_err(|_| FingerprintError::QueueFull)?;

        // Wait for result
        let result = result_receiver
            .await
            .map_err(|_| FingerprintError::Cancelled)?;

        self.in_progress.fetch_sub(1, Ordering::Relaxed);

        result
    }

    /// Calculate fingerprints for multiple PSKs in batch
    #[instrument(skip(self, psks), err)]
    pub async fn calculate_batch(
        &self,
        psks: Vec<(String, Arc<SecureBytes>)>,
    ) -> Result<BatchResult, FingerprintError> {
        let mut results = Vec::with_capacity(psks.len());
        let mut receivers = Vec::with_capacity(psks.len());

        // Submit all calculations
        for (id, psk) in psks {
            self.total_calculations.fetch_add(1, Ordering::Relaxed);
            self.in_progress.fetch_add(1, Ordering::Relaxed);

            // Check cache first
            if let Some(cached) = self.fingerprint_cache.get(&id) {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.in_progress.fetch_sub(1, Ordering::Relaxed);
                results.push((id, Ok(cached.clone())));
                continue;
            }

            // Create channel for result
            let (result_sender, result_receiver) = tokio::sync::oneshot::channel();

            // Create request
            let request = CalculationRequest {
                psk,
                id: Some(id.clone()),
                result_sender: Some(result_sender),
            };

            // Send request
            if self.request_sender.send(request).is_err() {
                self.in_progress.fetch_sub(1, Ordering::Relaxed);
                return Err(FingerprintError::QueueFull);
            }

            receivers.push((id, result_receiver));
        }

        // Wait for all results
        for (id, receiver) in receivers {
            let result = match receiver.await {
                Ok(r) => r,
                Err(_) => {
                    self.in_progress.fetch_sub(1, Ordering::Relaxed);
                    Err(FingerprintError::Cancelled)
                }
            };

            self.in_progress.fetch_sub(1, Ordering::Relaxed);
            results.push((id, result));
        }

        Ok(results)
    }

    /// Get statistics about the calculator
    pub fn get_stats(&self) -> (Counter, Counter, Counter) {
        (
            Counter::new(self.total_calculations.load(Ordering::Relaxed) as u64),
            Counter::new(self.cache_hits.load(Ordering::Relaxed) as u64),
            Counter::new(self.in_progress.load(Ordering::Relaxed) as u64),
        )
    }

    /// Clear the fingerprint cache
    pub fn clear_cache(&self) {
        self.fingerprint_cache.clear();
    }
}

/// Calculate a fingerprint for the given PSK data
#[instrument(skip(psk))]
pub fn calculate_fingerprint(psk: &SecureBytes) -> String {
    match calculate_fingerprint_internal(psk) {
        Ok(fingerprint) => fingerprint,
        Err(_) => {
            // Fallback to a simple hash in case of error
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            psk.hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        }
    }
}

/// Internal implementation of fingerprint calculation
fn calculate_fingerprint_internal(psk: &SecureBytes) -> Result<String, FingerprintError> {
    // Use ring for SHA-256 calculation
    use ring::digest::{Context, SHA256};

    let mut context = Context::new(&SHA256);
    context.update(psk.as_slice());
    let digest = context.finish();

    // Convert to hex string
    let result = digest
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(result)
}
