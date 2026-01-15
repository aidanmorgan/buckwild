// Rate limiting configuration
//
// Configurable packet rate limits for global and per-session enforcement.
// Implements token bucket rate limiting with burst support.

use serde::{Deserialize, Serialize};

/// Rate limiting configuration for packet processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum packets per second globally
    #[serde(default = "default_global_pps_limit")]
    pub global_pps_limit: u32,

    /// Maximum packets per second per session
    #[serde(default = "default_session_pps_limit")]
    pub session_pps_limit: u32,

    /// Burst allowance (tokens available above sustained rate)
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_pps_limit: default_global_pps_limit(),
            session_pps_limit: default_session_pps_limit(),
            burst_size: default_burst_size(),
        }
    }
}

fn default_global_pps_limit() -> u32 {
    100_000
}

fn default_session_pps_limit() -> u32 {
    10_000
}

fn default_burst_size() -> u32 {
    1_000
}

impl RateLimitConfig {
    /// Validate rate limit configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.global_pps_limit == 0 {
            return Err("global_pps_limit must be greater than 0".to_string());
        }

        if self.session_pps_limit == 0 {
            return Err("session_pps_limit must be greater than 0".to_string());
        }

        if self.session_pps_limit > self.global_pps_limit {
            return Err("session_pps_limit cannot exceed global_pps_limit".to_string());
        }

        if self.burst_size == 0 {
            return Err("burst_size must be greater than 0".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.global_pps_limit, 100_000);
        assert_eq!(config.session_pps_limit, 10_000);
        assert_eq!(config.burst_size, 1_000);
    }

    #[test]
    fn test_config_validation() {
        let config = RateLimitConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_zero_global_limit_invalid() {
        let config = RateLimitConfig {
            global_pps_limit: 0,
            session_pps_limit: 10_000,
            burst_size: 1_000,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_session_limit_invalid() {
        let config = RateLimitConfig {
            global_pps_limit: 100_000,
            session_pps_limit: 0,
            burst_size: 1_000,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_session_exceeds_global_invalid() {
        let config = RateLimitConfig {
            global_pps_limit: 10_000,
            session_pps_limit: 20_000,
            burst_size: 1_000,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_burst_invalid() {
        let config = RateLimitConfig {
            global_pps_limit: 100_000,
            session_pps_limit: 10_000,
            burst_size: 0,
        };
        assert!(config.validate().is_err());
    }
}
