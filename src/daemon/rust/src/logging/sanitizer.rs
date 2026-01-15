use hex;
use once_cell::sync::Lazy;
use regex::{self, Regex};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Patterns for detecting sensitive information
static SENSITIVE_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        // IP addresses (will be partially masked)
        (
            Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
            "ip_address",
        ),
        // IPv6 addresses
        (
            Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b").unwrap(),
            "ipv6_address",
        ),
        // MAC addresses
        (
            Regex::new(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b").unwrap(),
            "mac_address",
        ),
        // Cryptographic keys (hex strings longer than 32 chars)
        (Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap(), "crypto_key"),
        // Session IDs (UUID-like patterns)
        (
            Regex::new(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            )
            .unwrap(),
            "session_id",
        ),
        // Base64 encoded data (potential keys/tokens)
        (
            Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").unwrap(),
            "base64_data",
        ),
    ]
});

/// Fields that should never be logged in full
static SENSITIVE_FIELD_NAMES: &[&str] = &[
    "password",
    "secret",
    "key",
    "token",
    "private_key",
    "shared_secret",
    "psk",
    "hmac_key",
    "session_key",
    "ecdh_private",
    "ecdh_secret",
    "auth_token",
    "api_key",
    "credential",
];

/// Fields that should be hashed instead of logged directly
static HASH_FIELD_NAMES: &[&str] = &[
    "session_id",
    "connection_id",
    "peer_id",
    "user_id",
    "client_id",
];

/// Log sanitizer for preventing sensitive data leakage
pub struct LogSanitizer {
    hash_salt: [u8; 32],
}

impl LogSanitizer {
    pub fn new() -> Self {
        // Generate a random salt for hashing (in production, this should be configurable)
        let mut salt = [0u8; 32];
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        rng.fill(&mut salt).expect("Failed to generate salt");

        Self { hash_salt: salt }
    }

    /// Sanitize a map of fields, removing or masking sensitive data
    pub fn sanitize_fields(&self, mut fields: HashMap<String, Value>) -> HashMap<String, Value> {
        let mut sanitized = HashMap::new();

        for (key, value) in fields.drain() {
            let sanitized_key = key.to_lowercase();

            // Check if field name indicates sensitive data
            if SENSITIVE_FIELD_NAMES
                .iter()
                .any(|&sensitive| sanitized_key.contains(sensitive))
            {
                sanitized.insert(key, Value::String("[REDACTED]".to_string()));
                continue;
            }

            // Check if field should be hashed
            if HASH_FIELD_NAMES
                .iter()
                .any(|&hash_field| sanitized_key.contains(hash_field))
            {
                let hashed_value = self.hash_value(&value);
                sanitized.insert(key, Value::String(format!("hash:{}", hashed_value)));
                continue;
            }

            // Sanitize the value content
            let sanitized_value = self.sanitize_value(value);
            sanitized.insert(key, sanitized_value);
        }

        sanitized
    }

    /// Sanitize a single JSON value
    pub fn sanitize_value(&self, value: Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.sanitize_string(s)),
            Value::Object(obj) => {
                let mut sanitized_obj = serde_json::Map::new();
                for (key, val) in obj {
                    let sanitized_key = key.to_lowercase();

                    if SENSITIVE_FIELD_NAMES
                        .iter()
                        .any(|&sensitive| sanitized_key.contains(sensitive))
                    {
                        sanitized_obj.insert(key, Value::String("[REDACTED]".to_string()));
                    } else if HASH_FIELD_NAMES
                        .iter()
                        .any(|&hash_field| sanitized_key.contains(hash_field))
                    {
                        let hashed_value = self.hash_value(&val);
                        sanitized_obj.insert(key, Value::String(format!("hash:{}", hashed_value)));
                    } else {
                        sanitized_obj.insert(key, self.sanitize_value(val));
                    }
                }
                Value::Object(sanitized_obj)
            }
            Value::Array(arr) => {
                Value::Array(arr.into_iter().map(|v| self.sanitize_value(v)).collect())
            }
            _ => value, // Numbers, booleans, null are safe
        }
    }

    /// Sanitize a string by masking sensitive patterns
    pub fn sanitize_string(&self, input: String) -> String {
        let mut result = input;

        for (pattern, data_type) in SENSITIVE_PATTERNS.iter() {
            result = pattern
                .replace_all(&result, |caps: &regex::Captures| {
                    let matched = caps.get(0).unwrap().as_str();
                    match *data_type {
                        "ip_address" => self.mask_ip_address(matched),
                        "ipv6_address" => self.mask_ipv6_address(matched),
                        "mac_address" => "[MAC_REDACTED]".to_string(),
                        "crypto_key" => format!("[KEY_{}]", &matched[..8]),
                        "session_id" => format!("hash:{}", self.hash_string(matched)),
                        "base64_data" => {
                            if matched.len() > 40 {
                                format!("[B64_{}...]", &matched[..8])
                            } else {
                                matched.to_string() // Short base64 might not be sensitive
                            }
                        }
                        _ => "[REDACTED]".to_string(),
                    }
                })
                .to_string();
        }

        result
    }

    /// Mask IP address (show first two octets, mask last two)
    fn mask_ip_address(&self, ip: &str) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.xxx.xxx", parts[0], parts[1])
        } else {
            "[IP_REDACTED]".to_string()
        }
    }

    /// Mask IPv6 address (show first two groups, mask the rest)
    fn mask_ipv6_address(&self, ip: &str) -> String {
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() >= 2 {
            format!("{}:{}:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx", parts[0], parts[1])
        } else {
            "[IPV6_REDACTED]".to_string()
        }
    }

    /// Hash a value for consistent anonymization
    fn hash_value(&self, value: &Value) -> String {
        let value_str = match value {
            Value::String(s) => s.clone(),
            _ => value.to_string(),
        };
        self.hash_string(&value_str)
    }

    /// Hash a string with salt for consistent anonymization
    fn hash_string(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.hash_salt);
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8]) // Use first 8 bytes for shorter hash
    }

    /// Sanitize error messages that might contain sensitive data
    pub fn sanitize_error_message(&self, error: &str) -> String {
        self.sanitize_string(error.to_string())
    }

    /// Check if a string contains potentially sensitive data
    pub fn contains_sensitive_data(&self, input: &str) -> bool {
        SENSITIVE_PATTERNS
            .iter()
            .any(|(pattern, _)| pattern.is_match(input))
    }

    /// Get sanitization statistics
    pub fn get_sanitization_stats(
        &self,
        original: &HashMap<String, Value>,
        sanitized: &HashMap<String, Value>,
    ) -> SanitizationStats {
        let mut redacted_fields = 0;
        let mut hashed_fields = 0;
        let mut masked_values = 0;

        for value in sanitized.values() {
            match value {
                Value::String(s) if s == "[REDACTED]" => redacted_fields += 1,
                Value::String(s) if s.starts_with("hash:") => hashed_fields += 1,
                Value::String(s) if s.contains("xxx") || s.contains("[") => masked_values += 1,
                _ => {}
            }
        }

        SanitizationStats {
            total_fields: original.len(),
            redacted_fields,
            hashed_fields,
            masked_values,
        }
    }
}

/// Statistics about sanitization operations
#[derive(Debug, Clone)]
pub struct SanitizationStats {
    pub total_fields: usize,
    pub redacted_fields: usize,
    pub hashed_fields: usize,
    pub masked_values: usize,
}

impl Default for LogSanitizer {
    fn default() -> Self {
        Self::new()
    }
}
