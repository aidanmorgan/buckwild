// Cryptographic layer errors
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CryptographicError {
    #[error("Key generation failed: {key_type}")]
    KeyGenerationFailed { key_type: String },

    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    #[error("HMAC generation failed: {reason}")]
    HmacGenerationFailed { reason: String },

    #[error("HMAC verification failed")]
    HmacVerificationFailed,
}

pub type CryptographicResult<T> = Result<T, CryptographicError>;
