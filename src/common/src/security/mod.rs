#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Security layer

pub mod anti_replay;
pub mod crypto;
pub mod validation;

// Re-export security types
pub use anti_replay::{
    AntiReplayConfig, AntiReplayEngine, AntiReplayResult, AntiReplayStatistics,
    DuplicateDetectionConfig, DuplicateDetector, DuplicateResult, HandshakeCacheResult,
    HandshakeReplayCache, SequenceResult, SequenceValidationConfig, SequenceValidator,
    SequenceWindow, ThreadSafeAntiReplayEngine, ThreadSafeDuplicateDetector,
    ThreadSafeHandshakeCache, ThreadSafeTimestampCache, TimestampCache, TimestampCacheResult,
    TimestampResult, TimestampValidationConfig, TimestampValidator, TimestampWindow,
};
pub use crypto::{
    ChunkRange, DerivedSessionParams, EcdhManager, EcdhResult, HkdfParams, HmacCalculator,
    HmacContext, HmacPolicyNegotiation, HmacResult, Kdf, KdfResult, KeyManager, KeyMetadata,
    KeyResult, KeyState, MinimumPolicy, PBKDF2_ITERATIONS_SEQUENCE, PolicyMismatchHandler,
    PolicyNegotiator, SecureKey, SequenceKeyResult, SessionDerivation, SessionDerivationResult,
    ThreadSafeEcdhManager, ThreadSafeHmacContext, ThreadSafeKeyManager, TlsConfig, TlsError,
    TlsVersion, create_default_ecdh_manager, derive_sequence_key,
};
pub use validation::*;
