#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Cryptographic operations

pub mod daily_key_scheduler;
pub mod ecdh;
pub mod hmac;
pub mod hmac_policy;
pub mod kdf;
pub mod keys;
pub mod sequence;
pub mod session_derivation;
pub mod timestamp;
pub mod tls;

// Re-export crypto types
pub use daily_key_scheduler::{
    DEFAULT_GRACE_PERIOD, DailyKeyError, DailyKeyScheduler, DailyKeySchedulerConfig,
    KeyRotationEvent,
};
pub use ecdh::{EcdhManager, EcdhResult, ThreadSafeEcdhManager, create_default_ecdh_manager};
pub use hmac::{
    HmacCalculator, HmacContext, HmacPolicyNegotiation, HmacResult, ThreadSafeHmacContext,
};
pub use hmac_policy::{MinimumPolicy, PolicyMismatchHandler, PolicyNegotiator};
pub use kdf::{ChunkRange, HkdfParams, Kdf, KdfResult};
pub use keys::{KeyManager, KeyMetadata, KeyResult, KeyState, SecureKey, ThreadSafeKeyManager};
pub use sequence::{PBKDF2_ITERATIONS_SEQUENCE, SequenceKeyResult, derive_sequence_key};
pub use session_derivation::{DerivedSessionParams, SessionDerivation, SessionDerivationResult};
pub use timestamp::{TimestampKeyResult, generate_timestamp_key};
pub use tls::{TlsConfig, TlsError, TlsVersion};
