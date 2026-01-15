//! TLS configuration with minimum version enforcement
//!
//! Implements secure TLS configuration with:
//! - TLS 1.3 as default minimum version
//! - TLS 1.2 fallback support (configurable)
//! - TLS 1.0/1.1 explicitly disabled
//! - Secure cipher suite selection

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, Error as RustlsError, RootCertStore};
use thiserror::Error;

#[cfg(test)]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(test)]
use rustls::pki_types::{ServerName, UnixTime};
#[cfg(test)]
use rustls::{DigitallySignedStruct, SignatureScheme};
#[cfg(test)]
use std::sync::Arc;

/// TLS configuration errors
#[derive(Error, Debug)]
pub enum TlsError {
    #[error("TLS configuration error: {0}")]
    ConfigurationError(String),

    #[error("TLS connection error: {0}")]
    ConnectionError(String),

    #[error("Invalid TLS version: {0}")]
    InvalidVersion(String),

    #[error("Certificate validation error: {0}")]
    CertificateError(String),

    #[error("Rustls error: {0}")]
    Rustls(#[from] RustlsError),
}

/// Supported TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2 (minimum acceptable for legacy compatibility)
    Tls12,
    /// TLS 1.3 (recommended default)
    Tls13,
}

impl TlsVersion {
    /// Get human-readable name
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
        }
    }
}

/// TLS configuration builder
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Minimum TLS version to accept
    min_version: TlsVersion,
    /// Whether to skip certificate verification (INSECURE - for testing only)
    skip_cert_verification: bool,
    /// Custom root certificates (if any)
    root_certs: Vec<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::Tls13,
            skip_cert_verification: false,
            root_certs: Vec::new(),
        }
    }
}

impl TlsConfig {
    /// Create a new TLS configuration with secure defaults
    ///
    /// Default configuration:
    /// - TLS 1.3 minimum version
    /// - Certificate verification enabled
    /// - System root certificates
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum TLS version
    ///
    /// # Security Warning
    /// Setting TLS 1.2 reduces security. Only use for legacy compatibility.
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_version = version;
        self
    }

    /// Skip certificate verification (INSECURE - testing only)
    ///
    /// # Security Warning
    /// This disables certificate validation and should NEVER be used in production.
    /// Only enable for testing with self-signed certificates.
    #[cfg(test)]
    pub fn with_skip_verification(mut self) -> Self {
        self.skip_cert_verification = true;
        self
    }

    /// Add a custom root certificate
    pub fn with_root_cert(mut self, cert_der: Vec<u8>) -> Self {
        self.root_certs.push(cert_der);
        self
    }

    /// Build a rustls ClientConfig
    ///
    /// Returns a configured ClientConfig with:
    /// - Specified minimum TLS version (1.2 or 1.3)
    /// - Secure cipher suites only
    /// - Certificate verification (unless explicitly disabled for testing)
    pub fn build_client_config(&self) -> Result<ClientConfig, TlsError> {
        let protocol_versions = self.get_supported_versions();

        let mut root_store = RootCertStore::empty();

        // Load system root certificates
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_store.add(cert).map_err(|e| {
                TlsError::CertificateError(format!("Failed to add system cert: {}", e))
            })?;
        }

        // Log errors loading system certs but continue if we got some certs
        if let Some(err) = native_certs.errors.first() {
            tracing::warn!("Some system certificates failed to load: {}", err);
        }

        // Add custom root certificates
        for cert_der in &self.root_certs {
            root_store
                .add(CertificateDer::from(cert_der.clone()))
                .map_err(|e| {
                    TlsError::CertificateError(format!("Failed to add custom cert: {}", e))
                })?;
        }

        let config_builder = ClientConfig::builder_with_protocol_versions(&protocol_versions);

        let config = if self.skip_cert_verification {
            // INSECURE: Skip certificate verification (testing only)
            #[cfg(test)]
            {
                config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth()
            }
            #[cfg(not(test))]
            {
                return Err(TlsError::ConfigurationError(
                    "Certificate verification cannot be disabled in production builds".to_string(),
                ));
            }
        } else {
            // Secure: Use system root certificates
            config_builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        Ok(config)
    }

    /// Get supported protocol versions based on minimum version
    fn get_supported_versions(&self) -> Vec<&'static rustls::SupportedProtocolVersion> {
        match self.min_version {
            TlsVersion::Tls13 => {
                // TLS 1.3 only
                vec![&rustls::version::TLS13]
            }
            TlsVersion::Tls12 => {
                // TLS 1.3 and TLS 1.2 (in preference order)
                vec![&rustls::version::TLS13, &rustls::version::TLS12]
            }
        }
    }

    /// Get minimum version
    pub fn min_version(&self) -> TlsVersion {
        self.min_version
    }

    /// Check if TLS 1.0/1.1 are disabled (always true)
    pub fn legacy_tls_disabled(&self) -> bool {
        true
    }
}

/// No-op certificate verifier for testing only
#[cfg(test)]
#[derive(Debug)]
struct NoVerifier;

#[cfg(test)]
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TlsConfig::default();
        assert_eq!(config.min_version(), TlsVersion::Tls13);
        assert!(config.legacy_tls_disabled());
        assert!(!config.skip_cert_verification);
    }

    #[test]
    fn test_tls12_config() {
        let config = TlsConfig::new().with_min_version(TlsVersion::Tls12);
        assert_eq!(config.min_version(), TlsVersion::Tls12);
        assert!(config.legacy_tls_disabled());
    }

    #[test]
    fn test_tls13_only_config() {
        let config = TlsConfig::new().with_min_version(TlsVersion::Tls13);
        assert_eq!(config.min_version(), TlsVersion::Tls13);

        let versions = config.get_supported_versions();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn test_tls12_fallback_config() {
        let config = TlsConfig::new().with_min_version(TlsVersion::Tls12);

        let versions = config.get_supported_versions();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, rustls::ProtocolVersion::TLSv1_3);
        assert_eq!(versions[1].version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_version_names() {
        assert_eq!(TlsVersion::Tls12.as_str(), "TLS 1.2");
        assert_eq!(TlsVersion::Tls13.as_str(), "TLS 1.3");
    }

    #[test]
    fn test_skip_verification_in_tests() {
        let config = TlsConfig::new().with_skip_verification();
        assert!(config.skip_cert_verification);

        // Should build successfully with skip verification in test builds
        let client_config = config.build_client_config();
        assert!(client_config.is_ok());
    }

    #[test]
    fn test_build_client_config_tls13() {
        let config = TlsConfig::new().with_min_version(TlsVersion::Tls13);

        // This may fail if no system certs are available, but should not panic
        let result = config.build_client_config();
        // Just verify it doesn't panic - may fail in CI without certs
        let _ = result;
    }

    #[test]
    fn test_build_client_config_tls12() {
        let config = TlsConfig::new().with_min_version(TlsVersion::Tls12);

        // This may fail if no system certs are available, but should not panic
        let result = config.build_client_config();
        // Just verify it doesn't panic - may fail in CI without certs
        let _ = result;
    }
}
