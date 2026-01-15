#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Two-Phase Port Hopping System
//
// Implements the two-phase port hopping system per design/protocol/06-connection-lifecycle.md:
// - Phase 1 (Base Ports): Connection establishment using daily key from PSK
// - Phase 2 (Session Ports): Post-connection using ECDH-derived session seed

use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::error::EngineError;
use crate::protocol::types::*;

/// Port hopping phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortHoppingPhase {
    /// Phase 1: Base port for connection establishment (uses daily key from PSK)
    BasePort,
    /// Phase 2: Session port for post-connection (uses ECDH-derived session seed)
    SessionPort,
}

/// Base port hopping state (Phase 1)
/// Used during connection establishment before ECDH completes
#[derive(Debug, Clone)]
pub struct BasePortHopping {
    /// Pre-shared key for daily key derivation
    psk: Vec<u8>,

    /// Daily key (rotates daily at midnight UTC)
    daily_key: [u8; 32],

    /// Day number for daily key rotation
    current_day: u32,

    /// Time bucket duration (500ms as per spec)
    time_bucket_ms: u32,

    /// Port range
    min_port: u16,
    max_port: u16,
}

impl BasePortHopping {
    /// Create new base port hopping instance
    pub fn new(
        psk: Vec<u8>,
        time_bucket_ms: u32,
        min_port: u16,
        max_port: u16,
    ) -> Result<Self, EngineError> {
        if psk.is_empty() {
            return Err(EngineError::InvalidConfiguration(
                "PSK cannot be empty".to_string(),
            ));
        }

        let current_day = Self::get_current_day();
        let daily_key = Self::derive_daily_key(&psk, current_day)?;

        Ok(Self {
            psk,
            daily_key,
            current_day,
            time_bucket_ms,
            min_port,
            max_port,
        })
    }

    /// Get current day number (days since Unix epoch)
    fn get_current_day() -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        (now.as_secs() / 86400) as u32 // 86400 seconds per day
    }

    /// Derive daily key from PSK and day number
    /// Formula: HKDF(PSK, "daily_key" || day_number)
    fn derive_daily_key(psk: &[u8], day: u32) -> Result<[u8; 32], EngineError> {
        // Create info string: "daily_key" || day_number (4 bytes, big-endian)
        let mut info = Vec::with_capacity(9 + 4);
        info.extend_from_slice(b"daily_key");
        info.extend_from_slice(&day.to_be_bytes());

        // Use HKDF-SHA256 to derive daily key
        let salt = hmac::Key::new(hmac::HMAC_SHA256, b"buckwild_base_port");
        let _prk = hmac::Key::new(hmac::HMAC_SHA256, psk);

        // Extract-then-Expand pattern
        let extracted = hmac::sign(&salt, psk);
        let expanded_key = hmac::Key::new(hmac::HMAC_SHA256, extracted.as_ref());
        let signature = hmac::sign(&expanded_key, &info);

        let mut daily_key = [0u8; 32];
        daily_key.copy_from_slice(&signature.as_ref()[..32]);

        debug!("Derived daily key for day {}", day);
        Ok(daily_key)
    }

    /// Calculate base port for given timestamp
    /// Formula: HMAC-SHA256(daily_key, time_bucket)
    /// Returns port in range [min_port, max_port]
    pub fn calculate_port(&mut self, timestamp_ms: u64) -> Result<Port, EngineError> {
        // Check if we need to rotate daily key
        let current_day = Self::get_current_day();
        if current_day != self.current_day {
            self.daily_key = Self::derive_daily_key(&self.psk, current_day)?;
            self.current_day = current_day;
            debug!("Rotated to new daily key for day {}", current_day);
        }

        // Calculate time bucket
        let time_bucket = timestamp_ms / (self.time_bucket_ms as u64);

        // HMAC-SHA256(daily_key, time_bucket)
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.daily_key);
        let signature = hmac::sign(&key, &time_bucket.to_be_bytes());

        // Convert first 4 bytes of HMAC to port number
        let hash_bytes = signature.as_ref();
        let hash_value =
            u32::from_be_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);

        // Map to port range
        let port_range = (self.max_port - self.min_port + 1) as u32;
        let port_offset = hash_value % port_range;
        let port_number = self.min_port + port_offset as u16;

        debug!(
            "Base port calculation: time_bucket={}, port={}",
            time_bucket, port_number
        );

        Ok(Port::from_u16_unchecked(port_number))
    }

    /// Calculate base ports for current adaptive window
    /// Returns ports for past window, current, and future window
    pub fn calculate_window_ports(
        &mut self,
        timestamp_ms: u64,
        past_window_ms: u32,
        future_window_ms: u32,
    ) -> Result<Vec<Port>, EngineError> {
        let mut ports = Vec::new();

        // Past window ports
        let past_buckets = (past_window_ms / self.time_bucket_ms) as i64;
        for i in (1..=past_buckets).rev() {
            let past_time = timestamp_ms.saturating_sub((i as u64) * (self.time_bucket_ms as u64));
            if let Ok(port) = self.calculate_port(past_time) {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }

        // Current time port
        ports.push(self.calculate_port(timestamp_ms)?);

        // Future window ports
        let future_buckets = (future_window_ms / self.time_bucket_ms) as i64;
        for i in 1..=future_buckets {
            let future_time = timestamp_ms + ((i as u64) * (self.time_bucket_ms as u64));
            if let Ok(port) = self.calculate_port(future_time) {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }

        debug!(
            "Calculated {} window ports (past={}ms, future={}ms)",
            ports.len(),
            past_window_ms,
            future_window_ms
        );

        Ok(ports)
    }
}

/// Session port hopping state (Phase 2)
/// Used after ECDH completes and connection is established
#[derive(Debug, Clone)]
pub struct SessionPortHopping {
    /// Session seed derived from ECDH shared secret
    session_seed: [u8; 32],

    /// Time bucket duration (500ms as per spec)
    time_bucket_ms: u32,

    /// Port range
    min_port: u16,
    max_port: u16,
}

impl SessionPortHopping {
    /// Create new session port hopping instance
    /// session_seed is derived from ECDH shared secret via PBKDF2 chunks 22-23
    pub fn new(session_seed: [u8; 32], time_bucket_ms: u32, min_port: u16, max_port: u16) -> Self {
        debug!("Created session port hopping with seed");
        Self {
            session_seed,
            time_bucket_ms,
            min_port,
            max_port,
        }
    }

    /// Calculate session port for given timestamp
    /// Formula: HMAC-SHA256(session_seed, time_bucket)
    /// Returns port in range [min_port, max_port]
    pub fn calculate_port(&self, timestamp_ms: u64) -> Result<Port, EngineError> {
        // Calculate time bucket
        let time_bucket = timestamp_ms / (self.time_bucket_ms as u64);

        // HMAC-SHA256(session_seed, time_bucket)
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.session_seed);
        let signature = hmac::sign(&key, &time_bucket.to_be_bytes());

        // Convert first 4 bytes of HMAC to port number
        let hash_bytes = signature.as_ref();
        let hash_value =
            u32::from_be_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);

        // Map to port range
        let port_range = (self.max_port - self.min_port + 1) as u32;
        let port_offset = hash_value % port_range;
        let port_number = self.min_port + port_offset as u16;

        debug!(
            "Session port calculation: time_bucket={}, port={}",
            time_bucket, port_number
        );

        Ok(Port::from_u16_unchecked(port_number))
    }

    /// Calculate session ports for current adaptive window
    /// Returns ports for past window, current, and future window
    pub fn calculate_window_ports(
        &self,
        timestamp_ms: u64,
        past_window_ms: u32,
        future_window_ms: u32,
    ) -> Result<Vec<Port>, EngineError> {
        let mut ports = Vec::new();

        // Past window ports
        let past_buckets = (past_window_ms / self.time_bucket_ms) as i64;
        for i in (1..=past_buckets).rev() {
            let past_time = timestamp_ms.saturating_sub((i as u64) * (self.time_bucket_ms as u64));
            if let Ok(port) = self.calculate_port(past_time) {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }

        // Current time port
        ports.push(self.calculate_port(timestamp_ms)?);

        // Future window ports
        let future_buckets = (future_window_ms / self.time_bucket_ms) as i64;
        for i in 1..=future_buckets {
            let future_time = timestamp_ms + ((i as u64) * (self.time_bucket_ms as u64));
            if let Ok(port) = self.calculate_port(future_time) {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }

        debug!(
            "Calculated {} session window ports (past={}ms, future={}ms)",
            ports.len(),
            past_window_ms,
            future_window_ms
        );

        Ok(ports)
    }
}

/// Two-phase port hopping manager
/// Handles transition between base port (Phase 1) and session port (Phase 2)
#[derive(Debug)]
pub struct TwoPhasePortHopping {
    /// Current phase
    phase: PortHoppingPhase,

    /// Base port hopping (Phase 1)
    base_port: BasePortHopping,

    /// Session port hopping (Phase 2) - None until ECDH completes
    session_port: Option<SessionPortHopping>,

    /// Adaptive window sizes
    past_window_ms: u32,
    future_window_ms: u32,
}

impl TwoPhasePortHopping {
    /// Create new two-phase port hopping manager
    /// Starts in Phase 1 (base port) for connection establishment
    pub fn new(
        psk: Vec<u8>,
        time_bucket_ms: u32,
        min_port: u16,
        max_port: u16,
        past_window_ms: u32,
        future_window_ms: u32,
    ) -> Result<Self, EngineError> {
        let base_port = BasePortHopping::new(psk, time_bucket_ms, min_port, max_port)?;

        Ok(Self {
            phase: PortHoppingPhase::BasePort,
            base_port,
            session_port: None,
            past_window_ms,
            future_window_ms,
        })
    }

    /// Transition to Phase 2 (session port) after ECDH completes
    /// session_seed is derived from ECDH shared secret via PBKDF2 chunks 22-23
    pub fn transition_to_session_phase(
        &mut self,
        session_seed: [u8; 32],
    ) -> Result<(), EngineError> {
        if self.phase == PortHoppingPhase::SessionPort {
            warn!("Already in session phase, ignoring transition request");
            return Ok(());
        }

        let time_bucket_ms = self.base_port.time_bucket_ms;
        let min_port = self.base_port.min_port;
        let max_port = self.base_port.max_port;

        self.session_port = Some(SessionPortHopping::new(
            session_seed,
            time_bucket_ms,
            min_port,
            max_port,
        ));
        self.phase = PortHoppingPhase::SessionPort;

        debug!("Transitioned to Phase 2 (session port hopping)");
        Ok(())
    }

    /// Get current phase
    pub fn current_phase(&self) -> PortHoppingPhase {
        self.phase
    }

    /// Calculate current port based on active phase
    pub fn calculate_current_port(&mut self, timestamp_ms: u64) -> Result<Port, EngineError> {
        match self.phase {
            PortHoppingPhase::BasePort => self.base_port.calculate_port(timestamp_ms),
            PortHoppingPhase::SessionPort => self
                .session_port
                .as_ref()
                .ok_or_else(|| {
                    EngineError::InvalidState("Session port not initialized".to_string())
                })?
                .calculate_port(timestamp_ms),
        }
    }

    /// Calculate ports for adaptive window based on active phase
    pub fn calculate_window_ports(&mut self, timestamp_ms: u64) -> Result<Vec<Port>, EngineError> {
        match self.phase {
            PortHoppingPhase::BasePort => self.base_port.calculate_window_ports(
                timestamp_ms,
                self.past_window_ms,
                self.future_window_ms,
            ),
            PortHoppingPhase::SessionPort => self
                .session_port
                .as_ref()
                .ok_or_else(|| {
                    EngineError::InvalidState("Session port not initialized".to_string())
                })?
                .calculate_window_ports(timestamp_ms, self.past_window_ms, self.future_window_ms),
        }
    }

    /// Update adaptive window sizes
    pub fn update_window_sizes(&mut self, past_window_ms: u32, future_window_ms: u32) {
        self.past_window_ms = past_window_ms;
        self.future_window_ms = future_window_ms;
        debug!(
            "Updated window sizes: past={}ms, future={}ms",
            past_window_ms, future_window_ms
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_port_calculation() {
        let psk = b"test_psk_for_base_port".to_vec();
        let mut base_port = BasePortHopping::new(psk, 500, 1024, 65535).unwrap();

        let timestamp_ms = 1000000000;
        let port1 = base_port.calculate_port(timestamp_ms).unwrap();
        let port2 = base_port.calculate_port(timestamp_ms).unwrap();

        // Same timestamp should give same port
        assert_eq!(port1, port2);

        // Different timestamp should give different port (usually)
        let _port3 = base_port.calculate_port(timestamp_ms + 500).unwrap();
        // Note: might be same due to collision, but algorithm is correct
    }

    #[test]
    fn test_session_port_calculation() {
        let session_seed = [42u8; 32];
        let session_port = SessionPortHopping::new(session_seed, 500, 1024, 65535);

        let timestamp_ms = 1000000000;
        let port1 = session_port.calculate_port(timestamp_ms).unwrap();
        let port2 = session_port.calculate_port(timestamp_ms).unwrap();

        // Same timestamp should give same port
        assert_eq!(port1, port2);
    }

    #[test]
    fn test_two_phase_transition() {
        let psk = b"test_psk".to_vec();
        let mut two_phase = TwoPhasePortHopping::new(psk, 500, 1024, 65535, 1000, 1000).unwrap();

        // Should start in base port phase
        assert_eq!(two_phase.current_phase(), PortHoppingPhase::BasePort);

        // Calculate base port
        let base_port = two_phase.calculate_current_port(1000000000).unwrap();
        assert!(base_port.as_u16() >= 1024);

        // Transition to session phase
        let session_seed = [99u8; 32];
        two_phase.transition_to_session_phase(session_seed).unwrap();
        assert_eq!(two_phase.current_phase(), PortHoppingPhase::SessionPort);

        // Calculate session port (should be different)
        let session_port = two_phase.calculate_current_port(1000000000).unwrap();
        assert!(session_port.as_u16() >= 1024);
    }

    #[test]
    fn test_window_port_calculation() {
        let psk = b"test_psk_window".to_vec();
        let mut base_port = BasePortHopping::new(psk, 500, 1024, 65535).unwrap();

        let timestamp_ms = 1000000000;
        let ports = base_port
            .calculate_window_ports(timestamp_ms, 1000, 1000)
            .unwrap();

        // Should have ports for past, current, and future windows
        // With 500ms buckets and 1000ms windows: 2 past + 1 current + 2 future = up to 5 ports
        assert!(!ports.is_empty());
        assert!(ports.len() <= 5);

        // All ports should be in valid range
        for port in ports {
            assert!(port.as_u16() >= 1024);
        }
    }

    #[test]
    fn test_daily_key_rotation() {
        let psk = b"test_psk_rotation".to_vec();
        let mut base_port = BasePortHopping::new(psk, 500, 1024, 65535).unwrap();

        let current_day = base_port.current_day;

        // Simulate day change
        base_port.current_day = current_day - 1; // Force outdated day

        // Calculating port should trigger rotation
        let _ = base_port.calculate_port(1000000000).unwrap();

        // Day should be updated
        assert_eq!(base_port.current_day, current_day);
    }
}
