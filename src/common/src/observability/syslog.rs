//! Syslog forwarding for SIEM integration
//!
//! Implements RFC 5424 structured syslog forwarding with buffering, batching,
//! and connection retry logic for enterprise SIEM integration.

use crate::error::BuckwildError;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::sleep;

/// Syslog error types
#[derive(Error, Debug)]
pub enum SyslogError {
    #[error("Connection failed to {endpoint}: {source}")]
    ConnectionFailed {
        endpoint: SocketAddr,
        source: std::io::Error,
    },

    #[error("Send failed: {source}")]
    SendFailed { source: std::io::Error },

    #[error("Buffer full: {current_size}/{max_size} messages")]
    BufferFull {
        current_size: usize,
        max_size: usize,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Transport not connected")]
    NotConnected,

    #[error("Retry limit exceeded after {attempts} attempts")]
    RetryLimitExceeded { attempts: usize },
}

/// Transport protocol for syslog
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    TcpTls,
}

/// Syslog facility codes (RFC 5424)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFacility {
    Kernel = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    Lpr = 6,
    News = 7,
    Uucp = 8,
    Cron = 9,
    Authpriv = 10,
    Ftp = 11,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl SyslogFacility {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Syslog severity levels (RFC 5424) - maps to SIEM event severities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyslogSeverity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
}

impl SyslogSeverity {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Convert from SIEM event severity level
    pub fn from_syslog_severity(level: u8) -> Self {
        match level {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Informational,
            7 => Self::Debug,
            _ => Self::Informational,
        }
    }
}

/// SIEM event category mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventCategory {
    Auth,
    Conn,
    SecViolation,
    ProtoAnomaly,
    Config,
    Audit,
}

impl EventCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "AUTH",
            Self::Conn => "CONN",
            Self::SecViolation => "SEC_VIOLATION",
            Self::ProtoAnomaly => "PROTO_ANOMALY",
            Self::Config => "CONFIG",
            Self::Audit => "AUDIT",
        }
    }
}

/// SIEM event for syslog forwarding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub event_id: String,
    pub event_type: String,
    pub event_category: EventCategory,
    pub timestamp: String,
    pub severity: String,
    pub syslog_severity: u8,
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    pub session_id: Option<String>,
    pub correlation_id: String,
    pub payload: serde_json::Value,
}

/// Syslog forwarder configuration
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub endpoint: SocketAddr,
    pub transport: SyslogTransport,
    pub facility: SyslogFacility,
    pub hostname: String,
    pub app_name: String,
    pub buffer_size: usize,
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
    pub max_retries: usize,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            endpoint: "127.0.0.1:514".parse().expect("valid default endpoint"),
            transport: SyslogTransport::Udp,
            facility: SyslogFacility::Local0,
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "buckwild".to_string()),
            app_name: "buckwild".to_string(),
            buffer_size: 10000,
            batch_size: 100,
            batch_timeout_ms: 1000,
            max_retries: 5,
            initial_backoff_ms: 100,
            max_backoff_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Internal transport connection state
enum TransportConnection {
    Tcp(BufWriter<TcpStream>),
    Udp(Arc<UdpSocket>),
    Disconnected,
}

/// Syslog forwarder implementation
pub struct SyslogForwarder {
    config: SyslogConfig,
    buffer: Arc<Mutex<VecDeque<String>>>,
    connection: Arc<Mutex<TransportConnection>>,
    last_flush: Arc<Mutex<Instant>>,
}

impl SyslogForwarder {
    /// Create a new syslog forwarder
    pub fn new(config: SyslogConfig) -> Result<Self, SyslogError> {
        if config.buffer_size == 0 {
            return Err(SyslogError::InvalidConfig(
                "buffer_size must be > 0".to_string(),
            ));
        }
        if config.batch_size == 0 {
            return Err(SyslogError::InvalidConfig(
                "batch_size must be > 0".to_string(),
            ));
        }

        Ok(Self {
            config,
            buffer: Arc::new(Mutex::new(VecDeque::new())),
            connection: Arc::new(Mutex::new(TransportConnection::Disconnected)),
            last_flush: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// Format a SIEM event as RFC 5424 structured syslog message
    fn format_syslog_message(&self, event: &SiemEvent) -> Result<String, SyslogError> {
        let priority = (self.config.facility.as_u8() * 8) + event.syslog_severity;
        let version = 1;
        let timestamp = &event.timestamp;
        let hostname = &self.config.hostname;
        let app_name = &self.config.app_name;
        let proc_id = std::process::id();
        let msg_id = &event.event_type;

        let mut structured_data = format!(
            "[buckwild@48577 eventId=\"{}\" eventType=\"{}\" eventCategory=\"{}\" severity=\"{}\" correlationId=\"{}\"",
            event.event_id,
            event.event_type,
            event.event_category.as_str(),
            event.severity,
            event.correlation_id
        );

        if let Some(ref ip) = event.source_ip {
            structured_data.push_str(&format!(" sourceIp=\"{}\"", ip));
        }
        if let Some(port) = event.source_port {
            structured_data.push_str(&format!(" sourcePort=\"{}\"", port));
        }
        if let Some(ref ip) = event.dest_ip {
            structured_data.push_str(&format!(" destIp=\"{}\"", ip));
        }
        if let Some(port) = event.dest_port {
            structured_data.push_str(&format!(" destPort=\"{}\"", port));
        }
        if let Some(ref session_id) = event.session_id {
            structured_data.push_str(&format!(" sessionId=\"{}\"", session_id));
        }

        structured_data.push(']');

        let payload_json = serde_json::to_string(&event.payload)
            .map_err(|e| SyslogError::SerializationFailed(e.to_string()))?;

        let message = format!(
            "<{}>{} {} {} {} {} {} {} {}",
            priority,
            version,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            structured_data,
            payload_json
        );

        Ok(message)
    }

    /// Send an event to syslog
    pub async fn send_event(&self, event: SiemEvent) -> Result<(), SyslogError> {
        let message = self.format_syslog_message(&event)?;

        let mut buffer = self.buffer.lock().await;
        if buffer.len() >= self.config.buffer_size {
            return Err(SyslogError::BufferFull {
                current_size: buffer.len(),
                max_size: self.config.buffer_size,
            });
        }

        buffer.push_back(message);

        let should_flush = buffer.len() >= self.config.batch_size;
        drop(buffer);

        if should_flush {
            self.flush_internal().await?;
        } else {
            let last_flush = *self.last_flush.lock().await;
            if last_flush.elapsed().as_millis() > self.config.batch_timeout_ms as u128 {
                self.flush_internal().await?;
            }
        }

        Ok(())
    }

    /// Ensure transport connection is established
    async fn ensure_connected(&self) -> Result<(), SyslogError> {
        let mut conn = self.connection.lock().await;

        match *conn {
            TransportConnection::Tcp(_) | TransportConnection::Udp(_) => return Ok(()),
            TransportConnection::Disconnected => {}
        }

        let new_conn = match self.config.transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
                    SyslogError::ConnectionFailed {
                        endpoint: self.config.endpoint,
                        source: e,
                    }
                })?;
                socket.connect(self.config.endpoint).await.map_err(|e| {
                    SyslogError::ConnectionFailed {
                        endpoint: self.config.endpoint,
                        source: e,
                    }
                })?;
                TransportConnection::Udp(Arc::new(socket))
            }
            SyslogTransport::Tcp | SyslogTransport::TcpTls => {
                if self.config.transport == SyslogTransport::TcpTls {
                    tracing::warn!(
                        "TLS transport requested but not yet implemented, falling back to TCP"
                    );
                }
                let stream = TcpStream::connect(self.config.endpoint)
                    .await
                    .map_err(|e| SyslogError::ConnectionFailed {
                        endpoint: self.config.endpoint,
                        source: e,
                    })?;
                TransportConnection::Tcp(BufWriter::new(stream))
            }
        };

        *conn = new_conn;
        Ok(())
    }

    /// Send buffered messages with retry logic
    async fn send_with_retry(&self, messages: Vec<String>) -> Result<(), SyslogError> {
        let mut attempts = 0;
        let mut backoff_ms = self.config.initial_backoff_ms;

        loop {
            match self.send_batch(&messages).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempts += 1;
                    if attempts >= self.config.max_retries {
                        return Err(SyslogError::RetryLimitExceeded { attempts });
                    }

                    tracing::warn!(
                        error = %e,
                        attempt = attempts,
                        backoff_ms = backoff_ms,
                        "Syslog send failed, retrying"
                    );

                    let mut conn = self.connection.lock().await;
                    *conn = TransportConnection::Disconnected;
                    drop(conn);

                    sleep(Duration::from_millis(backoff_ms)).await;

                    backoff_ms = ((backoff_ms as f64 * self.config.backoff_multiplier) as u64)
                        .min(self.config.max_backoff_ms);
                }
            }
        }
    }

    /// Send a batch of messages
    async fn send_batch(&self, messages: &[String]) -> Result<(), SyslogError> {
        self.ensure_connected().await?;

        let mut conn = self.connection.lock().await;

        match &mut *conn {
            TransportConnection::Udp(socket) => {
                for message in messages {
                    let bytes = message.as_bytes();
                    socket
                        .send(bytes)
                        .await
                        .map_err(|e| SyslogError::SendFailed { source: e })?;
                }
                Ok(())
            }
            TransportConnection::Tcp(writer) => {
                for message in messages {
                    let frame = format!("{} {}\n", message.len(), message);
                    writer
                        .write_all(frame.as_bytes())
                        .await
                        .map_err(|e| SyslogError::SendFailed { source: e })?;
                }
                writer
                    .flush()
                    .await
                    .map_err(|e| SyslogError::SendFailed { source: e })?;
                Ok(())
            }
            TransportConnection::Disconnected => Err(SyslogError::NotConnected),
        }
    }

    /// Flush buffered messages
    async fn flush_internal(&self) -> Result<(), SyslogError> {
        let messages: Vec<String> = {
            let mut buffer = self.buffer.lock().await;
            if buffer.is_empty() {
                return Ok(());
            }
            buffer.drain(..).collect()
        };

        if !messages.is_empty() {
            self.send_with_retry(messages).await?;
            *self.last_flush.lock().await = Instant::now();
        }

        Ok(())
    }

    /// Flush buffered messages (public API)
    pub async fn flush(&self) -> Result<(), SyslogError> {
        self.flush_internal().await
    }

    /// Get current buffer size
    pub async fn buffer_size(&self) -> usize {
        self.buffer.lock().await.len()
    }

    /// Close the connection
    pub async fn close(&self) -> Result<(), SyslogError> {
        self.flush().await?;
        let mut conn = self.connection.lock().await;
        *conn = TransportConnection::Disconnected;
        Ok(())
    }
}

impl Drop for SyslogForwarder {
    fn drop(&mut self) {
        tracing::debug!("SyslogForwarder dropped, buffered messages may be lost");
    }
}

/// Convert BuckwildError to SyslogError
impl From<BuckwildError> for SyslogError {
    fn from(err: BuckwildError) -> Self {
        SyslogError::SerializationFailed(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syslog_severity_mapping() {
        assert_eq!(SyslogSeverity::from_syslog_severity(0).as_u8(), 0);
        assert_eq!(SyslogSeverity::from_syslog_severity(2).as_u8(), 2);
        assert_eq!(SyslogSeverity::from_syslog_severity(6).as_u8(), 6);
        assert_eq!(SyslogSeverity::from_syslog_severity(99).as_u8(), 6);
    }

    #[test]
    fn test_syslog_facility() {
        assert_eq!(SyslogFacility::Kernel.as_u8(), 0);
        assert_eq!(SyslogFacility::Local0.as_u8(), 16);
        assert_eq!(SyslogFacility::Local7.as_u8(), 23);
    }

    #[test]
    fn test_event_category_string() {
        assert_eq!(EventCategory::Auth.as_str(), "AUTH");
        assert_eq!(EventCategory::SecViolation.as_str(), "SEC_VIOLATION");
        assert_eq!(EventCategory::Audit.as_str(), "AUDIT");
    }

    #[test]
    fn test_syslog_config_validation() {
        let mut config = SyslogConfig::default();
        config.buffer_size = 0;
        let result = SyslogForwarder::new(config);
        assert!(result.is_err());

        let mut config = SyslogConfig::default();
        config.batch_size = 0;
        let result = SyslogForwarder::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_syslog_message() {
        let config = SyslogConfig::default();
        let forwarder = SyslogForwarder::new(config).expect("valid config");

        let event = SiemEvent {
            event_id: "01936f5a-8c4e-7000-9f8a-123456789abc".to_string(),
            event_type: "AUTH_SUCCESS".to_string(),
            event_category: EventCategory::Auth,
            timestamp: "2026-01-11T14:23:45.123456Z".to_string(),
            severity: "Info".to_string(),
            syslog_severity: 6,
            source_ip: Some("192.168.1.100".to_string()),
            source_port: Some(45123),
            dest_ip: Some("10.0.1.50".to_string()),
            dest_port: Some(12345),
            session_id: Some("a1b2c3d4".to_string()),
            correlation_id: "01936f5a-8c4e-7000-9f8a-correlation001".to_string(),
            payload: serde_json::json!({
                "auth_method": "ECDH_PSK",
                "session_key_derived": true
            }),
        };

        let message = forwarder
            .format_syslog_message(&event)
            .expect("valid format");
        assert!(message.contains("<134>"));
        assert!(message.contains("AUTH_SUCCESS"));
        assert!(message.contains("192.168.1.100"));
        assert!(message.contains("buckwild@48577"));
    }

    #[tokio::test]
    async fn test_buffer_overflow() {
        let mut config = SyslogConfig::default();
        config.buffer_size = 2;
        config.endpoint = "127.0.0.1:9999".parse().expect("valid endpoint");

        let forwarder = SyslogForwarder::new(config).expect("valid config");

        let event = SiemEvent {
            event_id: "test".to_string(),
            event_type: "TEST".to_string(),
            event_category: EventCategory::Audit,
            timestamp: "2026-01-11T00:00:00Z".to_string(),
            severity: "Info".to_string(),
            syslog_severity: 6,
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: None,
            session_id: None,
            correlation_id: "test".to_string(),
            payload: serde_json::json!({}),
        };

        assert!(forwarder.send_event(event.clone()).await.is_ok());
        assert!(forwarder.send_event(event.clone()).await.is_ok());

        let result = forwarder.send_event(event).await;
        assert!(matches!(result, Err(SyslogError::BufferFull { .. })));
    }

    #[tokio::test]
    async fn test_buffer_size() {
        let config = SyslogConfig::default();
        let forwarder = SyslogForwarder::new(config).expect("valid config");

        assert_eq!(forwarder.buffer_size().await, 0);

        let event = SiemEvent {
            event_id: "test".to_string(),
            event_type: "TEST".to_string(),
            event_category: EventCategory::Audit,
            timestamp: "2026-01-11T00:00:00Z".to_string(),
            severity: "Info".to_string(),
            syslog_severity: 6,
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: None,
            session_id: None,
            correlation_id: "test".to_string(),
            payload: serde_json::json!({}),
        };

        let _ = forwarder.send_event(event).await;
        assert!(forwarder.buffer_size().await > 0);
    }
}
