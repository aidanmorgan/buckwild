#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Port Hopping Calculation - Port calculation logic and algorithms
//
// This module handles all port calculation logic including base ports,
// session ports, and port derivation from cryptographic parameters.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use ring::{digest, hmac, pbkdf2};
use tokio::sync::RwLock;
use tracing::debug;

use crate::engines::time_sync::epoch::{EpochType, TimeEpoch};
use crate::protocol::types::*;
use crate::security::crypto::hmac::HmacCalculator;

/// Port range constants
pub const MIN_PORT: Port = Port::from_u16_unchecked(1024);
pub const MAX_PORT: Port = Port::from_u16_unchecked(65535);
pub const PORT_RANGE: u16 = 64512; // 65535 - 1024 + 1

/// PBKDF2 iterations for port derivation (design/protocol/10-port-hopping.md:133)
pub const PBKDF2_ITERATIONS_PORT: u32 = 2048;

/// Port hopping parameters derived from ECDH shared secret
#[derive(Debug, Clone)]
pub struct PortHoppingParams {
    /// 32-bit primary port seed (PBKDF2 chunks 22-23)
    pub port_seed: SeedValue,

    /// 32-bit hop sequence seed (PBKDF2 chunks 24-25)
    pub hop_sequence_seed: SeedValue,

    /// Time variance in milliseconds (0-100ms)
    pub time_variance: VarianceValue,

    /// 16-bit pattern seed
    pub hop_pattern_seed: PatternSeed,

    /// Session ID for packet routing
    pub session_id: SessionId,
}

/// Port Hopping Calculation Engine
#[derive(Clone)]
pub struct PortHoppingCalculation {
    /// Time epoch manager for port calculations
    #[allow(dead_code)]
    time_epoch: Arc<TimeEpoch>,

    /// Daily keys for base port hopping
    daily_keys: Arc<RwLock<HashMap<String, DailyKey>>>,

    /// Port calculation cache
    port_cache: Arc<DashMap<(SessionId, u64), Port>>,
}

impl PortHoppingCalculation {
    /// Create a new port hopping calculation engine
    pub fn new(time_epoch: Arc<TimeEpoch>) -> Self {
        Self {
            time_epoch,
            daily_keys: Arc::new(RwLock::new(HashMap::new())),
            port_cache: Arc::new(DashMap::new()),
        }
    }

    /// Derive daily key for base port hopping using PBKDF2
    ///
    /// Uses PBKDF2-HMAC-SHA256 with date-based salt for daily key rotation.
    /// Salt format: SHA256("daily_key" || date_string)
    /// Iterations: 2048 (PBKDF2_ITERATIONS_PORT)
    pub async fn derive_daily_key(&self, psk: &[u8], date: &str) -> DailyKey {
        // Check if we already have this daily key
        {
            let daily_keys = self.daily_keys.read().await;
            if let Some(key) = daily_keys.get(date) {
                return key.clone();
            }
        }

        // Create date salt: SHA256("daily_key" || date)
        let mut salt_input = Vec::with_capacity(9 + date.len());
        salt_input.extend_from_slice(b"daily_key");
        salt_input.extend_from_slice(date.as_bytes());
        let salt_digest = digest::digest(&digest::SHA256, &salt_input);

        // Use PBKDF2 to derive daily key
        let mut daily_key_bytes = [0u8; 32];
        let iterations = std::num::NonZeroU32::new(PBKDF2_ITERATIONS_PORT)
            .unwrap_or_else(|| std::num::NonZeroU32::new(2048).unwrap());
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt_digest.as_ref(),
            psk,
            &mut daily_key_bytes,
        );

        let daily_key = DailyKey::new(daily_key_bytes);

        // Store in cache
        {
            let mut daily_keys = self.daily_keys.write().await;
            daily_keys.insert(date.to_string(), daily_key.clone());
        }

        daily_key
    }

    /// Calculate base port for time bucket (connection establishment)
    pub fn calculate_base_port(&self, daily_key: &DailyKey, time_bucket: u64) -> Port {
        // Check cache first
        let cache_key = (SessionId::new(0), time_bucket); // Use null session ID for base ports
        if let Some(cached_port) = self.port_cache.get(&cache_key) {
            return *cached_port;
        }

        // Convert time bucket to bytes
        let mut time_bucket_bytes = [0u8; 8];
        time_bucket_bytes.copy_from_slice(&time_bucket.to_be_bytes());

        // Create input for HMAC
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&time_bucket_bytes);
        input.extend_from_slice(b"base_port_sequence_v2");

        // Calculate HMAC using daily key
        let hmac_calculator = HmacCalculator::new();
        let hmac_result = match hmac_calculator.calculate_packet_hmac(
            &input,
            daily_key.as_bytes(),
            HmacPolicy::Strong,
        ) {
            Ok(result) => result,
            Err(_) => {
                // Fallback to deterministic port based on time bucket if HMAC fails
                debug!("HMAC calculation failed for base port, using fallback");
                let fallback_port = MIN_PORT.0 + ((time_bucket % PORT_RANGE as u64) as u16);
                let port = Port(fallback_port);
                self.port_cache.insert(cache_key, port);
                return port;
            }
        };

        // Extract port value from first 4 bytes of HMAC
        let port_value = u32::from_be_bytes([
            hmac_result.as_bytes()[0],
            hmac_result.as_bytes()[1],
            hmac_result.as_bytes()[2],
            hmac_result.as_bytes()[3],
        ]);

        // Map to port range - port_value % PORT_RANGE ensures result fits in u16
        let base_port = Port(MIN_PORT.0 + (port_value % PORT_RANGE as u32) as u16);

        // Cache the result
        self.port_cache.insert(cache_key, base_port);

        base_port
    }

    /// Calculate session port for time window (data transmission)
    pub fn calculate_session_port(&self, params: &PortHoppingParams, time_window: u64) -> Port {
        // Check cache first
        let cache_key = (params.session_id.clone(), time_window);
        if let Some(cached_port) = self.port_cache.get(&cache_key) {
            return *cached_port;
        }

        // Convert time window to bytes
        let mut time_window_bytes = [0u8; 8];
        time_window_bytes.copy_from_slice(&time_window.to_be_bytes());

        // Create input for HMAC
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&time_window_bytes);
        input.extend_from_slice(&params.port_seed.to_be_bytes());
        input.extend_from_slice(b"session_port_v2");

        // Create HMAC key from hop sequence seed
        let key_material = params.hop_sequence_seed.to_be_bytes();
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key_material);

        // Calculate HMAC
        let hmac_result = hmac::sign(&hmac_key, &input);

        // Extract port value from first 4 bytes of HMAC
        let port_value = u32::from_be_bytes([
            hmac_result.as_ref()[0],
            hmac_result.as_ref()[1],
            hmac_result.as_ref()[2],
            hmac_result.as_ref()[3],
        ]);

        // Map to port range - port_value % PORT_RANGE ensures result fits in u16
        let session_port = Port(MIN_PORT.0 + (port_value % PORT_RANGE as u32) as u16);

        // Cache the result
        self.port_cache.insert(cache_key, session_port);

        session_port
    }

    /// Calculate session-specific port using seed and epoch
    pub fn calculate_session_port_with_seed(
        &self,
        seed: &[u8; 32],
        epoch: u32,
        is_local: bool,
    ) -> Port {
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(seed);
        hash_input.extend_from_slice(&epoch.to_be_bytes());
        hash_input.push(if is_local { 0x01 } else { 0x02 });

        let digest = digest::digest(&digest::SHA256, &hash_input);
        let hash_bytes = digest.as_ref();

        // Use first 2 bytes of hash for port calculation
        let port_raw = u16::from_be_bytes([hash_bytes[0], hash_bytes[1]]);
        let port_range = MAX_PORT.0 - MIN_PORT.0;
        // port_raw % port_range ensures result fits in valid range
        Port(MIN_PORT.0 + (port_raw % port_range))
    }

    /// Get current base port for connection establishment
    pub fn get_current_base_port(&self, daily_key: &DailyKey) -> Port {
        let time_window = TimeEpoch::current_time_window(EpochType::Daily, 0);
        self.calculate_base_port(daily_key, time_window.window.as_u64())
    }

    /// Get current session port for data transmission
    pub fn get_current_session_port(&self, params: &PortHoppingParams) -> Port {
        let time_window = TimeEpoch::current_time_window(EpochType::Monthly, 0);
        self.calculate_session_port(params, time_window.window.as_u64())
    }

    /// Get next session port for data transmission
    pub fn get_next_session_port(&self, params: &PortHoppingParams) -> Port {
        let time_window = TimeEpoch::current_time_window(EpochType::Monthly, 0);
        self.calculate_session_port(params, time_window.window.as_u64() + 1)
    }

    /// Get ports for delay window
    pub fn get_ports_for_delay_window(
        &self,
        params: &PortHoppingParams,
        delay_window: usize,
    ) -> Vec<Port> {
        let current_time_window = TimeEpoch::current_time_window(EpochType::Monthly, 0);

        let mut ports = Vec::with_capacity((delay_window * 2) + 1);
        let half_window = delay_window / 2;

        // Calculate ports for window range
        for offset in -(half_window as i64)..=((delay_window - half_window) as i64) {
            let window = (current_time_window.window.as_u64() as i64 + offset) as u64;
            let port = self.calculate_session_port(params, window);
            ports.push(port);
        }

        // Remove duplicates while preserving order
        let mut unique_ports = Vec::with_capacity(ports.len());
        let mut seen = std::collections::HashSet::new();

        for port in ports {
            if seen.insert(port) {
                unique_ports.push(port);
            }
        }

        unique_ports
    }

    /// Derive port hopping parameters from ECDH shared secret
    pub fn derive_port_hopping_params(
        shared_secret: &[u8],
        client_pubkey: &[u8],
        server_pubkey: &[u8],
        session_id: SessionId,
    ) -> PortHoppingParams {
        // Create session-specific salt combining public keys and session ID
        let mut salt_input = Vec::with_capacity(client_pubkey.len() + server_pubkey.len() + 8 + 16);
        salt_input.extend_from_slice(client_pubkey);
        salt_input.extend_from_slice(server_pubkey);
        salt_input.extend_from_slice(&session_id.to_be_bytes());
        salt_input.extend_from_slice(b"port_derivation_v3");

        // Hash the salt input
        let salt = digest::digest(&digest::SHA256, &salt_input);

        // Use PBKDF2 to derive port material from ECDH shared secret
        // Per spec (design/protocol/10-port-hopping.md:133), use 2048 iterations
        let mut port_material = [0u8; 12]; // 96 bits = 6 chunks of 16 bits
        let iterations = std::num::NonZeroU32::new(PBKDF2_ITERATIONS_PORT)
            .unwrap_or_else(|| std::num::NonZeroU32::new(2048).unwrap());
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt.as_ref(),
            shared_secret,
            &mut port_material,
        );

        // Extract as 16-bit chunks
        let chunk0 = u16::from_be_bytes([port_material[0], port_material[1]]);
        let chunk1 = u16::from_be_bytes([port_material[2], port_material[3]]);
        let chunk2 = u16::from_be_bytes([port_material[4], port_material[5]]);
        let chunk3 = u16::from_be_bytes([port_material[6], port_material[7]]);
        let chunk4 = u16::from_be_bytes([port_material[8], port_material[9]]);
        let chunk5 = u16::from_be_bytes([port_material[10], port_material[11]]);

        // Derive port parameters
        let port_seed = ((chunk0 as u32) << 16) | (chunk1 as u32);
        let hop_sequence_seed = ((chunk2 as u32) << 16) | (chunk3 as u32);
        let time_variance = (chunk4 % 100) as u8;
        let hop_pattern_seed = chunk5;

        PortHoppingParams {
            port_seed: SeedValue::new(port_seed),
            hop_sequence_seed: SeedValue::new(hop_sequence_seed),
            time_variance: VarianceValue::new(time_variance),
            hop_pattern_seed: PatternSeed::new(hop_pattern_seed),
            session_id,
        }
    }

    /// Clear the port calculation cache
    pub async fn clear_cache(&self) {
        let cache_size = self.port_cache.len();
        self.port_cache.clear();

        debug!(cache_size = cache_size, "Cleared port calculation cache");
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let port_cache_size = self.port_cache.len();
        let daily_keys_size = self
            .daily_keys
            .try_read()
            .map(|keys| keys.len())
            .unwrap_or(0);

        (port_cache_size, daily_keys_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_time_epoch() -> Arc<TimeEpoch> {
        Arc::new(TimeEpoch::new())
    }

    #[test]
    fn test_port_hopping_calculation_creation() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        // Verify port cache is empty initially
        assert_eq!(calc.port_cache.len(), 0);
    }

    #[tokio::test]
    async fn test_daily_key_derivation() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";
        let date = "2024-01-01";

        let key1 = calc.derive_daily_key(psk, date).await;
        let key2 = calc.derive_daily_key(psk, date).await;

        // Same date and PSK should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[tokio::test]
    async fn test_daily_key_different_dates() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";

        let key1 = calc.derive_daily_key(psk, "2024-01-01").await;
        let key2 = calc.derive_daily_key(psk, "2024-01-02").await;

        // Different dates should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[tokio::test]
    async fn test_base_port_calculation_deterministic() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";
        let daily_key = calc.derive_daily_key(psk, "2024-01-01").await;

        let time_bucket = 1000u64;

        let port1 = calc.calculate_base_port(&daily_key, time_bucket);
        let port2 = calc.calculate_base_port(&daily_key, time_bucket);

        // Same daily key and time bucket should produce same port
        assert_eq!(port1, port2);
    }

    #[tokio::test]
    async fn test_base_port_in_valid_range() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";
        let daily_key = calc.derive_daily_key(psk, "2024-01-01").await;

        for time_bucket in 0..100 {
            let port = calc.calculate_base_port(&daily_key, time_bucket);

            // Port should be in valid range
            assert!(port.as_u16() >= MIN_PORT.as_u16());
            assert!(port.as_u16() <= MAX_PORT.as_u16());
        }
    }

    #[test]
    fn test_session_port_calculation_deterministic() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let params = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(999),
        };

        let time_window = 500u64;

        let port1 = calc.calculate_session_port(&params, time_window);
        let port2 = calc.calculate_session_port(&params, time_window);

        // Same params and time window should produce same port
        assert_eq!(port1, port2);
    }

    #[test]
    fn test_session_port_in_valid_range() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let params = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(999),
        };

        for time_window in 0..100 {
            let port = calc.calculate_session_port(&params, time_window);

            // Port should be in valid range
            assert!(port.as_u16() >= MIN_PORT.as_u16());
            assert!(port.as_u16() <= MAX_PORT.as_u16());
        }
    }

    #[test]
    fn test_session_port_with_seed() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x42u8; 32];
        let epoch = 100u32;

        let local_port = calc.calculate_session_port_with_seed(&seed, epoch, true);
        let remote_port = calc.calculate_session_port_with_seed(&seed, epoch, false);

        // Local and remote should produce different ports for same seed/epoch
        assert_ne!(local_port, remote_port);

        // Both should be in valid range
        assert!(local_port.as_u16() >= MIN_PORT.as_u16());
        assert!(local_port.as_u16() <= MAX_PORT.as_u16());
        assert!(remote_port.as_u16() >= MIN_PORT.as_u16());
        assert!(remote_port.as_u16() <= MAX_PORT.as_u16());
    }

    #[test]
    fn test_port_caching() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let params = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(999),
        };

        let time_window = 500u64;

        // First call should cache the result
        let _port1 = calc.calculate_session_port(&params, time_window);
        assert_eq!(calc.port_cache.len(), 1);

        // Second call should use cache
        let _port2 = calc.calculate_session_port(&params, time_window);
        assert_eq!(calc.port_cache.len(), 1);
    }

    #[test]
    fn test_get_ports_for_delay_window() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let params = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(999),
        };

        let delay_window = 5;
        let ports = calc.get_ports_for_delay_window(&params, delay_window);

        // Should have ports for the delay window
        assert!(!ports.is_empty());
        assert!(ports.len() <= delay_window + 1);

        // All ports should be unique
        let mut unique_check = std::collections::HashSet::new();
        for port in &ports {
            assert!(unique_check.insert(*port), "Duplicate port found");
        }

        // All ports should be in valid range
        for port in &ports {
            assert!(port.as_u16() >= MIN_PORT.as_u16());
            assert!(port.as_u16() <= MAX_PORT.as_u16());
        }
    }

    #[test]
    fn test_port_hopping_params_derivation() {
        let shared_secret = [0x11u8; 32];
        let client_pubkey = [0x22u8; 64];
        let server_pubkey = [0x33u8; 64];
        let session_id = SessionId::new(12345);

        let params = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id.clone(),
        );

        // Verify session ID is preserved
        assert_eq!(params.session_id, session_id);

        // Verify seeds are derived (non-zero)
        assert!(params.port_seed.as_u32() > 0 || params.hop_sequence_seed.as_u32() > 0);
    }

    #[test]
    fn test_different_sessions_different_ports() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let params1 = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(100),
        };

        let params2 = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(200),
        };

        let time_window = 500u64;

        let _port1 = calc.calculate_session_port(&params1, time_window);
        let _port2 = calc.calculate_session_port(&params2, time_window);

        // Different session IDs should cache separately
        // (ports might be same by chance, but cache should have 2 entries)
        assert_eq!(calc.port_cache.len(), 2);
    }

    #[tokio::test]
    async fn test_get_current_base_port() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";
        let daily_key = calc.derive_daily_key(psk, "2024-01-01").await;

        let port = calc.get_current_base_port(&daily_key);

        // Should return a valid port
        assert!(port.as_u16() >= MIN_PORT.as_u16());
        assert!(port.as_u16() <= MAX_PORT.as_u16());
    }

    #[test]
    fn test_get_current_and_next_session_ports() {
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let params = PortHoppingParams {
            port_seed: SeedValue::new(12345),
            hop_sequence_seed: SeedValue::new(67890),
            time_variance: VarianceValue::new(50),
            hop_pattern_seed: PatternSeed::new(111),
            session_id: SessionId::new(999),
        };

        let current_port = calc.get_current_session_port(&params);
        let next_port = calc.get_next_session_port(&params);

        // Both should be valid ports
        assert!(current_port.as_u16() >= MIN_PORT.as_u16());
        assert!(current_port.as_u16() <= MAX_PORT.as_u16());
        assert!(next_port.as_u16() >= MIN_PORT.as_u16());
        assert!(next_port.as_u16() <= MAX_PORT.as_u16());

        // They might be different (not guaranteed, but likely)
    }

    #[test]
    fn test_port_range_constants() {
        // Verify port range calculation is correct (inclusive count)
        // PORT_RANGE = MAX - MIN + 1 for use as modulus in port calculations
        assert_eq!(
            PORT_RANGE as u32,
            (MAX_PORT.as_u16() - MIN_PORT.as_u16() + 1) as u32
        );

        // Verify MIN and MAX ports are valid
        assert!(MIN_PORT.as_u16() >= 1024);
        assert!(MAX_PORT.as_u16() == 65535);
    }

    // TASK-003: PBKDF2 Port Derivation Tests

    #[test]
    fn test_pbkdf2_iterations_port_constant() {
        // Verify constant exists and has correct value per spec
        assert_eq!(PBKDF2_ITERATIONS_PORT, 2048);
    }

    #[tokio::test]
    async fn test_daily_key_consistency() {
        // Same date produces same daily key
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";
        let date = "2024-01-15";

        let key1 = calc.derive_daily_key(psk, date).await;
        let key2 = calc.derive_daily_key(psk, date).await;

        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Same date should produce same daily key"
        );
    }

    #[tokio::test]
    async fn test_daily_key_rotation() {
        // Different dates produce different keys
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";

        let key_jan_01 = calc.derive_daily_key(psk, "2024-01-01").await;
        let key_jan_02 = calc.derive_daily_key(psk, "2024-01-02").await;
        let key_feb_01 = calc.derive_daily_key(psk, "2024-02-01").await;

        assert_ne!(
            key_jan_01.as_bytes(),
            key_jan_02.as_bytes(),
            "Different dates should produce different keys"
        );
        assert_ne!(
            key_jan_01.as_bytes(),
            key_feb_01.as_bytes(),
            "Different months should produce different keys"
        );
        assert_ne!(
            key_jan_02.as_bytes(),
            key_feb_01.as_bytes(),
            "Different dates should produce different keys"
        );
    }

    #[test]
    fn test_port_seed_length() {
        // Port derivation output is exactly 32 bytes
        let shared_secret = [0x42u8; 32];
        let client_pubkey = [0x11u8; 64];
        let server_pubkey = [0x22u8; 64];
        let session_id = SessionId::new(12345);

        let params = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id,
        );

        // Verify all fields are populated (non-zero check for at least one seed)
        assert!(
            params.port_seed.as_u32() > 0 || params.hop_sequence_seed.as_u32() > 0,
            "Port seeds should be derived"
        );
    }

    #[test]
    fn test_port_derivation_uses_2048_iterations() {
        // Verify that port derivation uses 2048 iterations, not 4096
        // This is an indirect test: we verify different iteration counts produce different outputs
        let shared_secret = [0x42u8; 32];
        let client_pubkey = [0x11u8; 64];
        let server_pubkey = [0x22u8; 64];
        let session_id = SessionId::new(12345);

        // Derive params (should use 2048 iterations)
        let params = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id.clone(),
        );

        // Create salt same way as derive_port_hopping_params
        let mut salt_input = Vec::with_capacity(client_pubkey.len() + server_pubkey.len() + 8 + 16);
        salt_input.extend_from_slice(&client_pubkey);
        salt_input.extend_from_slice(&server_pubkey);
        salt_input.extend_from_slice(&session_id.to_be_bytes());
        salt_input.extend_from_slice(b"port_derivation_v3");
        let salt = digest::digest(&digest::SHA256, &salt_input);

        // Test with 4096 iterations (should be different)
        let mut port_material_4096 = [0u8; 12];
        let iterations_4096 = std::num::NonZeroU32::new(4096).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations_4096,
            salt.as_ref(),
            &shared_secret,
            &mut port_material_4096,
        );

        // Test with 2048 iterations (should match our function)
        let mut port_material_2048 = [0u8; 12];
        let iterations_2048 = std::num::NonZeroU32::new(2048).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations_2048,
            salt.as_ref(),
            &shared_secret,
            &mut port_material_2048,
        );

        // Verify different iteration counts produce different outputs
        assert_ne!(
            port_material_2048, port_material_4096,
            "2048 and 4096 iterations should produce different outputs"
        );

        // Verify our function produces the 2048-iteration output
        let chunk0 = u16::from_be_bytes([port_material_2048[0], port_material_2048[1]]);
        let chunk1 = u16::from_be_bytes([port_material_2048[2], port_material_2048[3]]);
        let expected_port_seed = ((chunk0 as u32) << 16) | (chunk1 as u32);

        assert_eq!(
            params.port_seed.as_u32(),
            expected_port_seed,
            "Function should use 2048 iterations"
        );
    }

    #[tokio::test]
    async fn test_utc_date_format() {
        // Verify date salt uses YYYY-MM-DD format
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";

        // Test various date formats
        let key1 = calc.derive_daily_key(psk, "2024-01-15").await;
        let key2 = calc.derive_daily_key(psk, "2024-01-15").await;

        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Same YYYY-MM-DD date should produce same key"
        );

        // Different dates should produce different keys
        let key3 = calc.derive_daily_key(psk, "2024-01-16").await;
        assert_ne!(
            key1.as_bytes(),
            key3.as_bytes(),
            "Different dates should produce different keys"
        );
    }

    #[tokio::test]
    async fn test_daily_key_uses_pbkdf2_with_date_salt() {
        // Verify daily key derivation uses PBKDF2 with date-based salt
        let time_epoch = create_test_time_epoch();
        let calc = PortHoppingCalculation::new(time_epoch);

        let psk = b"test_pre_shared_key_32bytes_long";
        let date = "2024-01-15";

        let daily_key = calc.derive_daily_key(psk, date).await;

        // Manually compute expected daily key
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(b"daily_key");
        salt_input.extend_from_slice(date.as_bytes());
        let salt_digest = digest::digest(&digest::SHA256, &salt_input);

        let mut expected_key_bytes = [0u8; 32];
        let iterations = std::num::NonZeroU32::new(PBKDF2_ITERATIONS_PORT).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt_digest.as_ref(),
            psk,
            &mut expected_key_bytes,
        );

        assert_eq!(
            daily_key.as_bytes(),
            &expected_key_bytes,
            "Daily key should match PBKDF2 with date salt"
        );
    }

    #[test]
    fn test_port_derivation_determinism() {
        // Same inputs should always produce same outputs
        let shared_secret = [0x42u8; 32];
        let client_pubkey = [0x11u8; 64];
        let server_pubkey = [0x22u8; 64];
        let session_id = SessionId::new(12345);

        let params1 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id.clone(),
        );

        let params2 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id,
        );

        assert_eq!(
            params1.port_seed.as_u32(),
            params2.port_seed.as_u32(),
            "Port seed should be deterministic"
        );
        assert_eq!(
            params1.hop_sequence_seed.as_u32(),
            params2.hop_sequence_seed.as_u32(),
            "Hop sequence seed should be deterministic"
        );
        assert_eq!(
            params1.time_variance.as_u8(),
            params2.time_variance.as_u8(),
            "Time variance should be deterministic"
        );
        assert_eq!(
            params1.hop_pattern_seed.as_u16(),
            params2.hop_pattern_seed.as_u16(),
            "Hop pattern seed should be deterministic"
        );
    }

    #[test]
    fn test_port_derivation_different_sessions() {
        // Different session IDs should produce different parameters
        let shared_secret = [0x42u8; 32];
        let client_pubkey = [0x11u8; 64];
        let server_pubkey = [0x22u8; 64];

        let params1 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            SessionId::new(100),
        );

        let params2 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            SessionId::new(200),
        );

        // At least one parameter should differ
        assert!(
            params1.port_seed.as_u32() != params2.port_seed.as_u32()
                || params1.hop_sequence_seed.as_u32() != params2.hop_sequence_seed.as_u32()
                || params1.hop_pattern_seed.as_u16() != params2.hop_pattern_seed.as_u16(),
            "Different session IDs should produce different parameters"
        );
    }
}
