//! Protocol translation between TUN device and Buckwild protocol
//!
//! ## TDD Status: GREEN Phase (Task 2)
//!
//! Implementation for TUN Packet Translator following REQ-TRANS-001 through REQ-TRANS-018.

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::error::{TranslatorError, TranslatorResult};
use crate::protocol::types::{FragmentId, SessionId};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::instrument;

/// Protocol translator configuration
#[derive(Debug, Clone)]
pub struct TranslatorConfig {
    /// Maximum fragments per second per session (REQ-TRANS-013)
    pub max_fragments_per_sec: u32,
    /// Maximum reassembly buffer size in bytes (REQ-TRANS-015)
    pub max_reassembly_buffer_size: usize,
    /// Fragment timeout in milliseconds (REQ-TRANS-016)
    pub fragment_timeout_ms: u64,
    /// Maximum allowed fragments in a set (REQ-TRANS-015)
    pub max_fragments_per_set: u16,
    /// MTU for fragmentation decisions
    pub mtu: u16,
}

impl Default for TranslatorConfig {
    fn default() -> Self {
        Self {
            max_fragments_per_sec: 100,
            max_reassembly_buffer_size: 65536,
            fragment_timeout_ms: 5000,
            max_fragments_per_set: 100,
            mtu: 1400,
        }
    }
}

/// TCP 4-tuple for session tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpTuple {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

/// Session state for connection tracking
#[derive(Debug)]
struct SessionState {
    session_id: SessionId,
}

/// Fragment reassembly state
#[derive(Debug)]
struct FragmentState {
    session_id: SessionId,
    total_fragments: u16,
    received_fragments: DashMap<u16, Vec<u8>>,
    total_size: usize,
    created_at: Instant,
}

/// Rate limiter state per session
#[derive(Debug)]
struct RateLimiter {
    count: AtomicU64,
    window_start: parking_lot::Mutex<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            window_start: parking_lot::Mutex::new(Instant::now()),
        }
    }

    fn check_and_increment(&self, max_per_sec: u32) -> bool {
        let now = Instant::now();
        let mut window_start = self.window_start.lock();

        if now.duration_since(*window_start).as_secs() >= 1 {
            *window_start = now;
            self.count.store(0, Ordering::SeqCst);
        }

        let current = self.count.fetch_add(1, Ordering::SeqCst);
        current < max_per_sec as u64
    }
}

/// Protocol translator for TCP ↔ Buckwild protocol conversion
pub struct ProtocolTranslator {
    config: TranslatorConfig,
    sessions: DashMap<TcpTuple, SessionState>,
    fragments: DashMap<FragmentId, FragmentState>,
    rate_limiters: DashMap<SessionId, Arc<RateLimiter>>,
}

impl ProtocolTranslator {
    /// Create a new protocol translator
    pub fn new(config: TranslatorConfig) -> Self {
        Self {
            config,
            sessions: DashMap::new(),
            fragments: DashMap::new(),
            rate_limiters: DashMap::new(),
        }
    }

    /// Translate ingress TCP packet to protocol packet(s)
    ///
    /// REQ-TRANS-001: TCP → Protocol translation
    /// REQ-TRANS-007: Fragment large payloads
    #[instrument(name = "translator.ingress", skip(self, packet), fields(packet_len = packet.len()))]
    pub async fn translate_ingress(&mut self, packet: &[u8]) -> TranslatorResult<Vec<Vec<u8>>> {
        if packet.is_empty() {
            return Err(TranslatorError::InvalidPacket {
                reason: "Empty packet".to_string(),
            });
        }

        let payload_per_fragment = (self.config.mtu as usize).saturating_sub(50);

        if packet.len() <= payload_per_fragment {
            Ok(vec![self.create_protocol_packet(packet)])
        } else {
            let fragment_count = packet.len().div_ceil(payload_per_fragment);
            let mut fragments = Vec::new();

            for i in 0..fragment_count {
                let start = i * payload_per_fragment;
                let end = std::cmp::min(start + payload_per_fragment, packet.len());
                let fragment_payload = &packet[start..end];
                fragments.push(self.create_protocol_packet(fragment_payload));
            }

            Ok(fragments)
        }
    }

    /// Translate egress protocol packet to TCP packet
    ///
    /// REQ-TRANS-001: Protocol → TCP translation
    #[instrument(name = "translator.egress", skip(self, packet), fields(packet_len = packet.len()))]
    pub async fn translate_egress(&mut self, packet: &[u8]) -> TranslatorResult<Vec<u8>> {
        if packet.is_empty() {
            return Err(TranslatorError::InvalidPacket {
                reason: "Empty packet".to_string(),
            });
        }

        Ok(self.create_tcp_packet(packet))
    }

    /// Create new session for TCP connection
    ///
    /// REQ-TRANS-002, REQ-TRANS-003: Session creation and tracking
    pub fn create_session(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> SessionId {
        let tuple = TcpTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        if let Some(state) = self.sessions.get(&tuple) {
            return state.session_id.clone();
        }

        let session_id = SessionId::generate();
        self.sessions.insert(
            tuple,
            SessionState {
                session_id: session_id.clone(),
            },
        );

        session_id
    }

    /// Process fragment for reassembly
    ///
    /// REQ-TRANS-012 through REQ-TRANS-018: Fragment security and reassembly
    #[instrument(name = "translator.process_fragment", skip(self, payload), fields(
        fragment_id = %fragment_id.as_u16(),
        fragment_index = fragment_index,
        total_fragments = total_fragments,
        session_id = %session_id.get()
    ))]
    pub async fn process_fragment(
        &mut self,
        fragment_id: FragmentId,
        fragment_index: u16,
        total_fragments: u16,
        session_id: SessionId,
        payload: &[u8],
    ) -> TranslatorResult<Option<Vec<u8>>> {
        self.check_fragment_bomb(total_fragments)?;

        self.check_rate_limit(session_id.clone())?;

        self.check_buffer_limit(payload.len(), session_id.clone())?;

        if let Some(mut state) = self.fragments.get_mut(&fragment_id) {
            self.check_session_binding(&state, session_id.clone(), fragment_id)?;

            self.check_timeout(&state, fragment_id)?;

            self.check_overlap(&state, fragment_index)?;

            state.total_size += payload.len();
            if state.total_size > self.config.max_reassembly_buffer_size {
                return Err(TranslatorError::ReassemblyBufferExceeded {
                    session_id,
                    current_size: state.total_size - payload.len(),
                    attempted_add: payload.len(),
                    max_size: self.config.max_reassembly_buffer_size,
                });
            }

            state
                .received_fragments
                .insert(fragment_index, payload.to_vec());

            if state.received_fragments.len() == state.total_fragments as usize {
                return Ok(Some(self.reassemble_fragments(&state)));
            }
        } else {
            let state = FragmentState {
                session_id,
                total_fragments,
                received_fragments: DashMap::new(),
                total_size: payload.len(),
                created_at: Instant::now(),
            };
            state
                .received_fragments
                .insert(fragment_index, payload.to_vec());
            self.fragments.insert(fragment_id, state);
        }

        Ok(None)
    }

    /// Get translator configuration
    pub fn config(&self) -> &TranslatorConfig {
        &self.config
    }

    fn check_fragment_bomb(&self, total_fragments: u16) -> TranslatorResult<()> {
        if total_fragments > self.config.max_fragments_per_set {
            return Err(TranslatorError::FragmentBomb {
                total_fragments,
                max_allowed: self.config.max_fragments_per_set,
            });
        }
        Ok(())
    }

    fn check_rate_limit(&mut self, session_id: SessionId) -> TranslatorResult<()> {
        let limiter = self
            .rate_limiters
            .entry(session_id.clone())
            .or_insert_with(|| Arc::new(RateLimiter::new()))
            .clone();

        if !limiter.check_and_increment(self.config.max_fragments_per_sec) {
            return Err(TranslatorError::RateLimitExceeded { session_id });
        }
        Ok(())
    }

    fn check_buffer_limit(
        &self,
        payload_len: usize,
        session_id: SessionId,
    ) -> TranslatorResult<()> {
        if payload_len > self.config.max_reassembly_buffer_size {
            return Err(TranslatorError::ReassemblyBufferExceeded {
                session_id,
                current_size: 0,
                attempted_add: payload_len,
                max_size: self.config.max_reassembly_buffer_size,
            });
        }
        Ok(())
    }

    fn check_session_binding(
        &self,
        state: &FragmentState,
        session_id: SessionId,
        fragment_id: FragmentId,
    ) -> TranslatorResult<()> {
        if state.session_id != session_id {
            return Err(TranslatorError::SessionMismatch { fragment_id });
        }
        Ok(())
    }

    fn check_timeout(
        &self,
        state: &FragmentState,
        fragment_id: FragmentId,
    ) -> TranslatorResult<()> {
        let elapsed = state.created_at.elapsed().as_millis() as u64;
        if elapsed > self.config.fragment_timeout_ms {
            return Err(TranslatorError::FragmentTimeout {
                fragment_id,
                timeout_ms: self.config.fragment_timeout_ms,
            });
        }
        Ok(())
    }

    fn check_overlap(&self, state: &FragmentState, fragment_index: u16) -> TranslatorResult<()> {
        if state.received_fragments.contains_key(&fragment_index) {
            return Err(TranslatorError::FragmentOverlap {
                fragment_id: FragmentId::new(0),
                index: fragment_index,
            });
        }
        Ok(())
    }

    fn reassemble_fragments(&self, state: &FragmentState) -> Vec<u8> {
        let mut result = Vec::with_capacity(state.total_size);
        for i in 0..state.total_fragments {
            if let Some(fragment) = state.received_fragments.get(&i) {
                result.extend_from_slice(&fragment);
            }
        }
        result
    }

    fn create_protocol_packet(&self, payload: &[u8]) -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let mut packet = Vec::with_capacity(50 + payload.len());

        packet.extend_from_slice(&[0u8; 18]);
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(payload);

        packet
    }

    fn create_tcp_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20 + payload.len());

        packet.extend_from_slice(&[0u8; 20]);
        packet.extend_from_slice(payload);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translator_creation() {
        let translator = ProtocolTranslator::new(TranslatorConfig::default());
        assert_eq!(translator.config().mtu, 1400);
    }

    #[tokio::test]
    async fn test_basic_translation() {
        let mut translator = ProtocolTranslator::new(TranslatorConfig::default());
        let result = translator.translate_ingress(b"test").await;
        assert!(result.is_ok());
    }
}
