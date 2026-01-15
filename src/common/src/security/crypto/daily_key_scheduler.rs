#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Daily Key Scheduler
//!
//! Manages automatic rotation of daily keys at UTC midnight with configurable grace period.
//! This module provides:
//! - Automatic key derivation at UTC midnight using PBKDF2
//! - Grace period support for smooth transitions (default 5 minutes)
//! - Current and previous key caching for lookups
//! - Key rotation events for observability
//!
//! ## Protocol Reference
//! - design/protocol/10-port-hopping.md - PBKDF2-based daily key derivation
//! - design/rules.md - Security constants and iteration counts
//!
//! ## Audit Reference
//! TASK-009: Daily Key Scheduler (HIGH-004)
//! Dependencies: TASK-003 (PBKDF2 port derivation)

use chrono::{DateTime, Utc};
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::protocol::types::DailyKey;

/// PBKDF2 iterations for daily key derivation
/// Per design/protocol/10-port-hopping.md:133
const PBKDF2_ITERATIONS_DAILY: u32 = 2048;

/// Default grace period duration (5 minutes)
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(5 * 60);

/// Daily key scheduler errors
#[derive(Error, Debug)]
pub enum DailyKeyError {
    #[error("Invalid grace period: {0:?}")]
    InvalidGracePeriod(Duration),

    #[error("PSK too short: expected at least 32 bytes, got {0}")]
    PskTooShort(usize),

    #[error("Key derivation failed")]
    DerivationFailed,
}

/// Daily key scheduler configuration
#[derive(Debug, Clone)]
pub struct DailyKeySchedulerConfig {
    /// Grace period after midnight during which old key remains valid
    pub grace_period: Duration,
}

impl Default for DailyKeySchedulerConfig {
    fn default() -> Self {
        Self {
            grace_period: DEFAULT_GRACE_PERIOD,
        }
    }
}

impl DailyKeySchedulerConfig {
    /// Create new configuration with custom grace period
    pub fn new(grace_period: Duration) -> Result<Self, DailyKeyError> {
        if grace_period > Duration::from_secs(60 * 60) {
            return Err(DailyKeyError::InvalidGracePeriod(grace_period));
        }
        Ok(Self { grace_period })
    }
}

/// Key rotation event for observability
#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    /// UTC timestamp of rotation
    pub rotation_time: DateTime<Utc>,
    /// Previous date (YYYY-MM-DD)
    pub previous_date: String,
    /// New date (YYYY-MM-DD)
    pub new_date: String,
}

/// Cached daily key with metadata
#[derive(Clone)]
struct CachedDailyKey {
    /// The derived key
    key: DailyKey,
    /// Date this key was derived for (YYYY-MM-DD)
    date: String,
    /// UTC timestamp when this key becomes invalid (for previous keys during grace period)
    valid_until: Option<DateTime<Utc>>,
}

/// Daily Key Scheduler
///
/// Manages automatic rotation of daily keys at UTC midnight.
/// Maintains current and previous day's keys with configurable grace period.
pub struct DailyKeyScheduler {
    /// PSK used for key derivation
    psk: Arc<Vec<u8>>,
    /// Configuration
    config: DailyKeySchedulerConfig,
    /// Current daily key
    current_key: Arc<RwLock<Option<CachedDailyKey>>>,
    /// Previous daily key (valid during grace period)
    previous_key: Arc<RwLock<Option<CachedDailyKey>>>,
}

impl DailyKeyScheduler {
    /// Create new daily key scheduler
    ///
    /// # Arguments
    /// * `psk` - Pre-shared key for derivation (minimum 32 bytes recommended)
    /// * `config` - Scheduler configuration
    pub fn new(psk: Vec<u8>, config: DailyKeySchedulerConfig) -> Result<Self, DailyKeyError> {
        if psk.len() < 32 {
            return Err(DailyKeyError::PskTooShort(psk.len()));
        }

        Ok(Self {
            psk: Arc::new(psk),
            config,
            current_key: Arc::new(RwLock::new(None)),
            previous_key: Arc::new(RwLock::new(None)),
        })
    }

    /// Create new daily key scheduler with default configuration
    pub fn with_defaults(psk: Vec<u8>) -> Result<Self, DailyKeyError> {
        Self::new(psk, DailyKeySchedulerConfig::default())
    }

    /// Derive daily key for specific date using PBKDF2
    ///
    /// Uses PBKDF2-HMAC-SHA256 with date-based salt.
    /// Salt format: SHA256("daily_key" || date_string)
    /// Iterations: 2048 (PBKDF2_ITERATIONS_DAILY)
    ///
    /// # Arguments
    /// * `date` - Date string in YYYY-MM-DD format
    fn derive_key_for_date(&self, date: &str) -> Result<DailyKey, DailyKeyError> {
        // Create date salt: SHA256("daily_key" || date)
        let mut salt_input = Vec::with_capacity(9 + date.len());
        salt_input.extend_from_slice(b"daily_key");
        salt_input.extend_from_slice(date.as_bytes());
        let salt_digest = digest::digest(&digest::SHA256, &salt_input);

        // Use PBKDF2 to derive daily key
        let mut daily_key_bytes = [0u8; 32];
        let iterations =
            NonZeroU32::new(PBKDF2_ITERATIONS_DAILY).ok_or(DailyKeyError::DerivationFailed)?;

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt_digest.as_ref(),
            &self.psk,
            &mut daily_key_bytes,
        );

        debug!(
            date = %date,
            iterations = PBKDF2_ITERATIONS_DAILY,
            "Derived daily key"
        );

        Ok(DailyKey::new(daily_key_bytes))
    }

    /// Get UTC date string in YYYY-MM-DD format
    fn get_utc_date(now: DateTime<Utc>) -> String {
        now.format("%Y-%m-%d").to_string()
    }

    /// Update keys based on current UTC time
    ///
    /// This handles:
    /// - Initial key derivation
    /// - Midnight rotation to new key
    /// - Grace period management for previous key
    pub async fn update(&self) -> Result<Option<KeyRotationEvent>, DailyKeyError> {
        let now = Utc::now();
        let current_date = Self::get_utc_date(now);

        let mut current_key = self.current_key.write().await;

        // Check if we need to rotate (either first run or date changed)
        let needs_rotation = match &*current_key {
            None => true,
            Some(cached) => cached.date != current_date,
        };

        if !needs_rotation {
            return Ok(None);
        }

        // Derive new key for current date
        let new_key = self.derive_key_for_date(&current_date)?;

        // Calculate grace period expiry
        let grace_expiry = now
            + chrono::Duration::from_std(self.config.grace_period)
                .map_err(|_| DailyKeyError::InvalidGracePeriod(self.config.grace_period))?;

        let event = if let Some(old_current) = current_key.take() {
            // Rotation: move current to previous
            let event = KeyRotationEvent {
                rotation_time: now,
                previous_date: old_current.date.clone(),
                new_date: current_date.clone(),
            };

            info!(
                previous_date = %event.previous_date,
                new_date = %event.new_date,
                grace_period_minutes = self.config.grace_period.as_secs() / 60,
                "Daily key rotated at UTC midnight"
            );

            // Store old key as previous with grace period expiry
            let mut previous_key = self.previous_key.write().await;
            *previous_key = Some(CachedDailyKey {
                key: old_current.key,
                date: old_current.date,
                valid_until: Some(grace_expiry),
            });

            Some(event)
        } else {
            // Initial key derivation
            info!(
                date = %current_date,
                "Initial daily key derived"
            );
            None
        };

        // Store new current key
        *current_key = Some(CachedDailyKey {
            key: new_key,
            date: current_date,
            valid_until: None, // Current key has no expiry
        });

        Ok(event)
    }

    /// Get current daily key
    ///
    /// Returns None if no key has been derived yet (call update() first)
    pub async fn get_current_key(&self) -> Option<DailyKey> {
        let current_key = self.current_key.read().await;
        current_key.as_ref().map(|cached| cached.key.clone())
    }

    /// Get previous daily key if still valid (within grace period)
    pub async fn get_previous_key(&self) -> Option<DailyKey> {
        let now = Utc::now();
        let previous_key = self.previous_key.read().await;

        previous_key.as_ref().and_then(|cached| {
            if let Some(valid_until) = cached.valid_until {
                if now <= valid_until {
                    Some(cached.key.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Try to authenticate with either current or previous key
    ///
    /// Returns the key if available, trying current first then previous (if in grace period)
    pub async fn get_valid_key(&self) -> Option<DailyKey> {
        // Try current key first
        if let Some(key) = self.get_current_key().await {
            return Some(key);
        }

        // Fall back to previous key if in grace period
        self.get_previous_key().await
    }

    /// Check if midnight rotation should occur
    ///
    /// Returns true if current UTC date differs from cached current key date
    pub async fn should_rotate(&self) -> bool {
        let now = Utc::now();
        let current_date = Self::get_utc_date(now);

        let current_key = self.current_key.read().await;
        match &*current_key {
            None => true, // No key yet, should initialize
            Some(cached) => cached.date != current_date,
        }
    }

    /// Clean up expired previous keys
    ///
    /// Removes previous key if grace period has expired
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut previous_key = self.previous_key.write().await;

        if let Some(cached) = &*previous_key {
            if let Some(valid_until) = cached.valid_until {
                if now > valid_until {
                    warn!(
                        date = %cached.date,
                        expired_at = %valid_until,
                        "Cleaning up expired previous daily key"
                    );
                    *previous_key = None;
                }
            }
        }
    }

    /// Get configuration
    pub fn config(&self) -> &DailyKeySchedulerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_psk() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    #[tokio::test]
    async fn test_scheduler_creation() {
        let psk = create_test_psk();
        let scheduler = DailyKeyScheduler::with_defaults(psk);
        assert!(scheduler.is_ok());
    }

    #[tokio::test]
    async fn test_psk_too_short() {
        let psk = vec![0x42u8; 16]; // Only 16 bytes
        let result = DailyKeyScheduler::with_defaults(psk);
        assert!(matches!(result, Err(DailyKeyError::PskTooShort(16))));
    }

    #[tokio::test]
    async fn test_invalid_grace_period() {
        let _psk = create_test_psk();
        let config = DailyKeySchedulerConfig::new(Duration::from_secs(2 * 60 * 60));
        assert!(matches!(config, Err(DailyKeyError::InvalidGracePeriod(_))));
    }

    #[tokio::test]
    async fn test_initial_key_derivation() {
        let psk = create_test_psk();
        let scheduler = DailyKeyScheduler::with_defaults(psk).expect("Failed to create scheduler");

        // No key initially
        assert!(scheduler.get_current_key().await.is_none());

        // Update should derive initial key
        let event = scheduler.update().await.expect("Failed to update");
        assert!(event.is_none()); // No rotation event on first run

        // Should now have current key
        assert!(scheduler.get_current_key().await.is_some());
        assert!(scheduler.get_previous_key().await.is_none());
    }

    #[tokio::test]
    async fn test_key_derivation_deterministic() {
        let psk = create_test_psk();
        let scheduler = DailyKeyScheduler::with_defaults(psk).expect("Failed to create scheduler");

        let key1 = scheduler
            .derive_key_for_date("2024-01-15")
            .expect("Failed to derive key");
        let key2 = scheduler
            .derive_key_for_date("2024-01-15")
            .expect("Failed to derive key");

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[tokio::test]
    async fn test_different_dates_different_keys() {
        let psk = create_test_psk();
        let scheduler = DailyKeyScheduler::with_defaults(psk).expect("Failed to create scheduler");

        let key1 = scheduler
            .derive_key_for_date("2024-01-15")
            .expect("Failed to derive key");
        let key2 = scheduler
            .derive_key_for_date("2024-01-16")
            .expect("Failed to derive key");

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[tokio::test]
    async fn test_date_format() {
        let now = Utc::now();
        let date_string = DailyKeyScheduler::get_utc_date(now);

        // Should be YYYY-MM-DD format (10 characters)
        assert_eq!(date_string.len(), 10);
        assert_eq!(date_string.chars().nth(4), Some('-'));
        assert_eq!(date_string.chars().nth(7), Some('-'));
    }

    #[tokio::test]
    async fn test_should_rotate() {
        let psk = create_test_psk();
        let scheduler = DailyKeyScheduler::with_defaults(psk).expect("Failed to create scheduler");

        // Should rotate initially (no key)
        assert!(scheduler.should_rotate().await);

        // Update to derive initial key
        let _ = scheduler.update().await;

        // Should not rotate immediately after update (same day)
        assert!(!scheduler.should_rotate().await);
    }

    #[tokio::test]
    async fn test_get_valid_key() {
        let psk = create_test_psk();
        let scheduler = DailyKeyScheduler::with_defaults(psk).expect("Failed to create scheduler");

        // No valid key initially
        assert!(scheduler.get_valid_key().await.is_none());

        // Update to derive key
        let _ = scheduler.update().await;

        // Should now have valid key
        assert!(scheduler.get_valid_key().await.is_some());
    }

    #[tokio::test]
    async fn test_pbkdf2_iterations() {
        // Verify we use 2048 iterations
        assert_eq!(PBKDF2_ITERATIONS_DAILY, 2048);
    }

    #[tokio::test]
    async fn test_grace_period_configuration() {
        let psk = create_test_psk();

        // Default should be 5 minutes
        let config = DailyKeySchedulerConfig::default();
        assert_eq!(config.grace_period, Duration::from_secs(5 * 60));

        // Custom grace period
        let custom_config = DailyKeySchedulerConfig::new(Duration::from_secs(10 * 60))
            .expect("Failed to create config");
        assert_eq!(custom_config.grace_period, Duration::from_secs(10 * 60));

        let scheduler =
            DailyKeyScheduler::new(psk, custom_config).expect("Failed to create scheduler");
        assert_eq!(
            scheduler.config().grace_period,
            Duration::from_secs(10 * 60)
        );
    }

    #[tokio::test]
    async fn test_default_grace_period_constant() {
        assert_eq!(DEFAULT_GRACE_PERIOD, Duration::from_secs(5 * 60));
    }
}
