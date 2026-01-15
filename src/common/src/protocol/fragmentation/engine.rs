// Unified fragmentation engine
//
// This module provides the main FragmentationEngine that coordinates all fragmentation
// operations including fragmentation, reassembly, security, memory management, overlap
// detection, and rate limiting.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

// Import ALL types from the authoritative consolidated types module
use super::memory::FragmentMemoryManager;
use super::overlap::OverlapDetector;
use super::rate_limit::FragmentRateLimiter;
use super::security::FragmentSecurityEngine;
use crate::error::ProtocolError;
use crate::protocol::packet::{DataPacket, FragmentHeader, Packet, PacketHeader};
use crate::protocol::types::*;

/// Unified fragmentation engine that coordinates all fragmentation operations
pub struct FragmentationEngine {
    /// Security engine for fragment validation
    security_engine: Arc<FragmentSecurityEngine>,
    /// Memory manager for fragment storage
    memory_manager: Arc<FragmentMemoryManager>,
    /// Overlap detector for fragment validation
    overlap_detector: Arc<OverlapDetector>,
    /// Rate limiter for fragment processing
    rate_limiter: Arc<FragmentRateLimiter>,
    /// Active reassembly contexts
    reassembly_contexts: RwLock<HashMap<ReassemblyKey, ReassemblyContext>>,
    /// Recent fragment IDs (circular buffer for duplicate detection)
    recent_fragment_ids: RwLock<VecDeque<FragmentId>>,
    /// Configuration
    config: FragmentationConfig,
}

/// Configuration for the fragmentation engine
#[derive(Debug, Clone)]
pub struct FragmentationConfig {
    /// Maximum fragment size in bytes
    pub max_fragment_size: FragmentSize,
    /// Maximum number of fragments per packet
    pub max_fragments_per_packet: FragmentCount,
    /// Reassembly timeout
    pub reassembly_timeout: FragmentTimeout,
    /// Maximum concurrent reassembly contexts
    pub max_reassembly_contexts: usize,
    /// Enable overlap detection
    pub enable_overlap_detection: bool,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Enable security validation
    pub enable_security_validation: bool,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self {
            max_fragment_size: FragmentSize::new(1400), // Typical MTU minus headers
            max_fragments_per_packet: FragmentCount::new(256),
            reassembly_timeout: FragmentTimeout::new(FragmentTimeout::FRAGMENT_TIMEOUT_MS),
            max_reassembly_contexts: 1000,
            enable_overlap_detection: true,
            enable_rate_limiting: true,
            enable_security_validation: true,
        }
    }
}

/// Key for identifying reassembly contexts
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ReassemblyKey {
    session_id: SessionId,
    fragment_id: FragmentId,
}

/// Context for packet reassembly
#[derive(Debug)]
struct ReassemblyContext {
    /// Session ID
    session_id: SessionId,
    /// Fragment ID
    #[allow(dead_code)]
    fragment_id: FragmentId,
    /// Total expected fragments
    fragment_count: FragmentCount,
    /// Received fragments (index -> fragment data)
    fragments: HashMap<FragmentIndex, FragmentData>,
    /// Total expected size
    #[allow(dead_code)]
    expected_size: Option<usize>,
    /// Creation timestamp
    #[allow(dead_code)]
    created_at: SystemTime,
    /// Last activity timestamp
    last_activity: SystemTime,
    /// Original packet header (from first fragment)
    original_header: Option<PacketHeader>,
}

/// Fragment data with metadata
#[derive(Debug, Clone)]
struct FragmentData {
    /// Fragment index
    #[allow(dead_code)]
    index: FragmentIndex,
    /// Fragment payload
    payload: Bytes,
    /// Fragment timestamp
    #[allow(dead_code)]
    timestamp: SystemTime,
    /// Security validation status
    #[allow(dead_code)]
    security_validated: bool,
}

/// Fragmentation request
#[derive(Debug)]
pub struct FragmentationRequest {
    /// Session ID
    pub session_id: SessionId,
    /// Packet to fragment
    pub packet: DataPacket,
    /// Maximum fragment size
    pub max_fragment_size: Option<usize>,
    /// Source IP for rate limiting
    pub source_ip: u32,
}

/// Fragmentation result
#[derive(Debug)]
pub struct FragmentationResult {
    /// Generated fragments
    pub fragments: Vec<DataPacket>,
    /// Fragment ID used
    pub fragment_id: FragmentId,
    /// Total fragments created
    pub fragment_count: FragmentCount,
}

/// Reassembly request
#[derive(Debug)]
pub struct ReassemblyRequest {
    /// Fragment packet
    pub fragment: DataPacket,
    /// Source IP for rate limiting
    pub source_ip: u32,
}

/// Reassembly result
#[derive(Debug)]
pub enum ReassemblyResult {
    /// Fragment accepted, reassembly in progress
    InProgress {
        fragment_id: FragmentId,
        received_fragments: ReceivedFragments,
        fragment_count: FragmentCount,
    },
    /// Packet fully reassembled
    Complete {
        packet: Box<DataPacket>,
        fragment_id: FragmentId,
        fragment_count: FragmentCount,
    },
    /// Fragment rejected due to validation failure
    Rejected { reason: String },
}

impl FragmentationEngine {
    /// Create a new fragmentation engine with default configuration
    pub fn new() -> Self {
        Self::with_config(FragmentationConfig::default())
    }

    /// Create a new fragmentation engine with custom configuration
    pub fn with_config(config: FragmentationConfig) -> Self {
        Self {
            security_engine: Arc::new(FragmentSecurityEngine::new()),
            memory_manager: Arc::new(FragmentMemoryManager::new()),
            overlap_detector: Arc::new(OverlapDetector::new()),
            rate_limiter: Arc::new(FragmentRateLimiter::new()),
            reassembly_contexts: RwLock::new(HashMap::new()),
            recent_fragment_ids: RwLock::new(VecDeque::with_capacity(FRAGMENT_DUPLICATE_WINDOW)),
            config,
        }
    }

    /// Fragment a packet into smaller fragments
    pub fn fragment_packet(
        &self,
        request: FragmentationRequest,
    ) -> Result<FragmentationResult, ProtocolError> {
        // Validate request
        if request.packet.payload.is_empty() {
            return Err(ProtocolError::fragmentation_error(
                "Cannot fragment empty packet",
            ));
        }

        let max_fragment_size = request
            .max_fragment_size
            .unwrap_or(self.config.max_fragment_size.as_usize());

        // Even single "fragments" need proper fragment headers for consistency
        // This ensures process_fragment can handle all fragments uniformly

        // Generate fragment ID
        let fragment_id = self.generate_fragment_id();

        // Calculate fragment parameters
        // Reserve 8 bytes for fragment header in each fragment
        const FRAGMENT_HEADER_SIZE: usize = 8;
        let effective_fragment_size = max_fragment_size.saturating_sub(FRAGMENT_HEADER_SIZE);

        if effective_fragment_size == 0 {
            return Err(ProtocolError::fragmentation_error(
                "Fragment size too small for header",
            ));
        }

        let payload = &request.packet.payload;
        let total_size = payload.len();
        let fragments_needed =
            (total_size as u32).div_ceil(effective_fragment_size as u32) as usize;

        if fragments_needed > self.config.max_fragments_per_packet.as_usize() {
            return Err(ProtocolError::fragmentation_error(format!(
                "Too many fragments needed: {}",
                fragments_needed
            )));
        }

        let total_fragments = FragmentCount::new(fragments_needed as u16);
        let mut fragments = Vec::with_capacity(fragments_needed);

        // Create fragments
        for i in 0..fragments_needed {
            let fragment_index = FragmentIndex::new(i as u16);
            let start_offset = i * effective_fragment_size;
            let end_offset = std::cmp::min(start_offset + effective_fragment_size, total_size);
            let fragment_payload = payload.slice(start_offset..end_offset);

            // Create fragment packet
            let fragment = self.create_fragment_packet(
                &request.packet,
                fragment_id,
                fragment_index,
                total_fragments,
                fragment_payload,
            )?;

            fragments.push(fragment);
        }

        Ok(FragmentationResult {
            fragments,
            fragment_id,
            fragment_count: total_fragments,
        })
    }

    /// Process a received fragment for reassembly
    pub fn process_fragment(
        &self,
        request: ReassemblyRequest,
    ) -> Result<ReassemblyResult, ProtocolError> {
        // Periodic cleanup of stale fragment state (MED-008)
        // Called on new fragment to prevent memory exhaustion from incomplete fragments
        self.cleanup_stale_fragment_state();

        // Extract fragment information
        let fragment_info = self.extract_fragment_info(&request.fragment)?;

        // Rate limiting check
        if self.config.enable_rate_limiting {
            let rate_limit_request = super::rate_limit::RateLimitRequest {
                session_id: fragment_info.session_id.clone(),
                source_ip: IpAddress::from_std(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    request.source_ip,
                ))),
                fragment_size: PacketSize::new(request.fragment.payload.len()),
                fragment_id: fragment_info.fragment_id,
                timestamp: SystemTime::now(),
            };

            if let Some(violation) = self.rate_limiter.check_rate_limit(&rate_limit_request) {
                return Ok(ReassemblyResult::Rejected {
                    reason: format!("Rate limit exceeded: {:?}", violation),
                });
            }
        }

        // Security validation
        if self.config.enable_security_validation {
            let packet = Packet::Data(request.fragment.clone());
            if let Err(e) = self.security_engine.validate_fragment(&packet) {
                return Ok(ReassemblyResult::Rejected {
                    reason: format!("Security validation failed: {}", e),
                });
            }
        }

        // Overlap detection
        if self.config.enable_overlap_detection {
            let reassembly_key = ReassemblyKey {
                session_id: fragment_info.session_id.clone(),
                fragment_id: fragment_info.fragment_id,
            };

            // Convert to overlap detector types
            let overlap_key = super::overlap::ReassemblyKey {
                session_id: reassembly_key.session_id.clone(),
                fragment_id: reassembly_key.fragment_id,
            };
            let overlap_info = super::overlap::FragmentInfo {
                session_id: fragment_info.session_id.clone(),
                fragment_id: fragment_info.fragment_id,
                fragment_index: fragment_info.fragment_index,
                fragment_count: fragment_info.fragment_count,
                payload_size: FragmentSize::new(fragment_info.payload.len() as u16),
            };

            if let Err(e) = self
                .overlap_detector
                .check_overlap(&overlap_key, &overlap_info)
            {
                return Ok(ReassemblyResult::Rejected {
                    reason: format!("Overlap detected: {}", e),
                });
            }
        }

        // Process fragment for reassembly
        self.process_fragment_for_reassembly(request.fragment, fragment_info)
    }

    /// Create a fragment packet from the original packet
    fn create_fragment_packet(
        &self,
        original: &DataPacket,
        fragment_id: FragmentId,
        fragment_index: FragmentIndex,
        fragment_count: FragmentCount,
        fragment_payload: Bytes,
    ) -> Result<DataPacket, ProtocolError> {
        use crate::protocol::packet::{PacketBuilderEngine, PacketFlags};

        let _engine = PacketBuilderEngine::new();
        let mut flags = original.header.flags();
        flags.set(PacketFlags::FRAGMENT);

        // Create fragmentation header (8 bytes)
        let mut frag_header = BytesMut::with_capacity(8);
        frag_header.put_u16(fragment_id.as_u16());
        frag_header.put_u16(fragment_index.as_u16());
        frag_header.put_u16(fragment_count.as_u16());
        frag_header.put_u16(0); // Reserved

        // Combine fragmentation header with fragment payload
        let mut combined_payload = BytesMut::with_capacity(8 + fragment_payload.len());
        combined_payload.put_slice(&frag_header);
        combined_payload.put_slice(&fragment_payload);

        // Build fragment packet using PacketBuilderEngine
        let packet_builder = PacketBuilderEngine::with_defaults(
            original.header.version_byte(),
            original.header.hmac_policy(),
        );

        let fragment_packet = packet_builder
            .data()
            .session_id(original.header.session_id())
            .sequence_number(original.header.sequence_number())
            .ack_number(original.header.ack_number())
            .window_size(original.window_size)
            .flags(flags)
            .timestamp(original.header.timestamp())
            .hmac(original.hmac.clone())
            .fragment_header(FragmentHeader {
                fragment_id,
                fragment_index,
                fragment_count,
                fragment_size: FragmentSize::new(combined_payload.len() as u16),
            })
            .payload(combined_payload.freeze())
            .build()
            .map_err(|e| ProtocolError::FragmentationError {
                reason: format!("Fragment packet builder failed: {:?}", e),
            })?;

        Ok(fragment_packet)
    }

    /// Extract fragment information from a packet
    fn extract_fragment_info(&self, packet: &DataPacket) -> Result<FragmentInfo, ProtocolError> {
        if !packet.header.flags().is_frag() {
            return Err(ProtocolError::fragmentation_error(
                "Packet is not fragmented",
            ));
        }

        let payload = &packet.payload;
        if payload.len() < 8 {
            return Err(ProtocolError::fragmentation_error(
                "Fragment header too small",
            ));
        }

        let fragment_id = FragmentId::new(u16::from_be_bytes([payload[0], payload[1]]));
        let fragment_index = FragmentIndex::new(u16::from_be_bytes([payload[2], payload[3]]));
        let total_fragments = FragmentCount::new(u16::from_be_bytes([payload[4], payload[5]]));

        if fragment_index.as_u16() >= total_fragments.as_u16() {
            return Err(ProtocolError::fragmentation_error("Invalid fragment index"));
        }

        if total_fragments.as_u16() == 0 {
            return Err(ProtocolError::fragmentation_error(
                "Invalid total fragments",
            ));
        }

        Ok(FragmentInfo {
            session_id: packet.header.session_id(),
            fragment_id,
            fragment_index,
            fragment_count: total_fragments,
            payload: payload.slice(8..),
        })
    }

    /// Process fragment for reassembly
    fn process_fragment_for_reassembly(
        &self,
        packet: DataPacket,
        fragment_info: FragmentInfo,
    ) -> Result<ReassemblyResult, ProtocolError> {
        let reassembly_key = ReassemblyKey {
            session_id: fragment_info.session_id.clone(),
            fragment_id: fragment_info.fragment_id,
        };

        // Recover from poisoned RwLock - data can still be updated
        let mut contexts = self
            .reassembly_contexts
            .write()
            .unwrap_or_else(|e| e.into_inner());

        // Get or create reassembly context
        let is_new_context = !contexts.contains_key(&reassembly_key);
        let context = contexts
            .entry(reassembly_key.clone())
            .or_insert_with(|| ReassemblyContext {
                session_id: fragment_info.session_id.clone(),
                fragment_id: fragment_info.fragment_id,
                fragment_count: fragment_info.fragment_count,
                fragments: HashMap::new(),
                expected_size: None,
                created_at: SystemTime::now(),
                last_activity: SystemTime::now(),
                original_header: None,
            });

        // Store original header from first fragment
        if is_new_context && context.original_header.is_none() {
            context.original_header = Some(packet.header.clone());
        }

        // Validate fragment consistency
        if context.fragment_count.as_u16() != fragment_info.fragment_count.as_u16() {
            return Err(ProtocolError::fragmentation_error(
                "Fragment total count mismatch",
            ));
        }

        // Check for duplicate fragment
        if context
            .fragments
            .contains_key(&fragment_info.fragment_index)
        {
            return Ok(ReassemblyResult::Rejected {
                reason: "Duplicate fragment".to_string(),
            });
        }

        // Add fragment to context
        context.fragments.insert(
            fragment_info.fragment_index,
            FragmentData {
                index: fragment_info.fragment_index,
                payload: fragment_info.payload.clone(),
                timestamp: SystemTime::now(),
                security_validated: true,
            },
        );

        context.last_activity = SystemTime::now();

        // Check if reassembly is complete
        if context.fragments.len() == context.fragment_count.as_u16() as usize {
            // Reassemble the packet
            let reassembled = self.reassemble_packet(context)?;
            contexts.remove(&reassembly_key);

            Ok(ReassemblyResult::Complete {
                packet: Box::new(reassembled),
                fragment_id: fragment_info.fragment_id,
                fragment_count: fragment_info.fragment_count,
            })
        } else {
            Ok(ReassemblyResult::InProgress {
                fragment_id: fragment_info.fragment_id,
                received_fragments: ReceivedFragments::new(context.fragments.len() as u16),
                fragment_count: fragment_info.fragment_count,
            })
        }
    }

    /// Reassemble fragments into a complete packet
    fn reassemble_packet(&self, context: &ReassemblyContext) -> Result<DataPacket, ProtocolError> {
        // Calculate total payload size
        let total_size: u64 = context
            .fragments
            .values()
            .map(|f| f.payload.len())
            .sum::<usize>() as u64;

        // Create reassembled payload
        let mut reassembled_payload = BytesMut::with_capacity(total_size as usize);

        // Add fragments in order
        for i in 0..context.fragment_count.as_u16() {
            let fragment_index = FragmentIndex::new(i);
            if let Some(fragment) = context.fragments.get(&fragment_index) {
                reassembled_payload.put_slice(&fragment.payload);
            } else {
                return Err(ProtocolError::fragmentation_error(format!(
                    "Missing fragment {}",
                    i
                )));
            }
        }

        // Create reassembled packet, preserving original header
        use crate::protocol::packet::PacketBuilderEngine;

        if let Some(ref original_header) = context.original_header {
            let engine = PacketBuilderEngine::with_defaults(
                original_header.version_byte(),
                original_header.hmac_policy(),
            );

            let packet = engine
                .data()
                .session_id(original_header.session_id())
                .sequence_number(original_header.sequence_number())
                .ack_number(original_header.ack_number())
                .payload(reassembled_payload.freeze())
                .build()?;

            Ok(packet)
        } else {
            // Fallback if no header stored (shouldn't happen)
            let engine = PacketBuilderEngine::new();
            let packet = engine
                .data()
                .session_id(context.session_id.clone())
                .payload(reassembled_payload.freeze())
                .build()?;

            Ok(packet)
        }
    }

    /// Generate a unique fragment ID
    fn generate_fragment_id(&self) -> FragmentId {
        static FRAGMENT_ID_COUNTER: AtomicFragmentId = AtomicFragmentId::from_raw(1);
        let fragment_id = FRAGMENT_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Track in recent IDs circular buffer
        let mut recent_ids = self
            .recent_fragment_ids
            .write()
            .unwrap_or_else(|e| e.into_inner());

        // Maintain FRAGMENT_DUPLICATE_WINDOW size
        if recent_ids.len() >= FRAGMENT_DUPLICATE_WINDOW {
            recent_ids.pop_front();
        }
        recent_ids.push_back(fragment_id);

        fragment_id
    }

    /// Clean up expired reassembly contexts
    pub fn cleanup_expired_contexts(&self) {
        let timeout = self.config.reassembly_timeout.to_duration();
        let now = SystemTime::now();

        // Recover from poisoned RwLock - data can still be updated
        let mut contexts = self
            .reassembly_contexts
            .write()
            .unwrap_or_else(|e| e.into_inner());
        contexts.retain(|_, context| {
            now.duration_since(context.last_activity)
                .unwrap_or_default()
                < timeout
        });
    }

    /// Clean up stale fragment state across all subsystems (MED-008)
    /// Maximum fragment lifetime: 30 seconds (configurable via reassembly_timeout)
    /// This method provides memory protection against fragment flooding attacks
    pub fn cleanup_stale_fragment_state(&self) {
        // Clean up expired reassembly contexts in main engine
        self.cleanup_expired_contexts();

        // Clean up expired states in security engine
        if self.config.enable_security_validation {
            self.security_engine.cleanup_expired_states();
        }

        // Clean up expired fragment storage in memory manager
        self.memory_manager.cleanup_expired_fragments();

        // Clean up expired overlap detection contexts
        if self.config.enable_overlap_detection {
            self.overlap_detector.cleanup_expired_contexts();
        }

        // Clean up expired rate limiters
        if self.config.enable_rate_limiting {
            self.rate_limiter.cleanup_expired_limiters();
        }
    }

    /// Get fragmentation engine statistics
    pub fn get_stats(&self) -> FragmentationStats {
        // Recover from poisoned RwLock - stats are still readable
        let contexts = self
            .reassembly_contexts
            .read()
            .unwrap_or_else(|e| e.into_inner());

        FragmentationStats {
            active_reassembly_contexts: contexts.len(),
            max_reassembly_contexts: self.config.max_reassembly_contexts,
            rate_limit_stats: self.rate_limiter.get_rate_limit_stats(),
            security_stats: self.security_engine.get_stats(),
            memory_stats: self.memory_manager.get_stats(),
        }
    }
}

impl Default for FragmentationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Fragment information extracted from packet
#[derive(Debug, Clone)]
struct FragmentInfo {
    session_id: SessionId,
    fragment_id: FragmentId,
    fragment_index: FragmentIndex,
    fragment_count: FragmentCount,
    payload: Bytes,
}

/// Fragmentation engine statistics
#[derive(Debug, Clone)]
pub struct FragmentationStats {
    /// Number of active reassembly contexts
    pub active_reassembly_contexts: usize,
    /// Maximum allowed reassembly contexts
    pub max_reassembly_contexts: usize,
    /// Rate limiting statistics
    pub rate_limit_stats: super::rate_limit::FragmentRateLimitStats,
    /// Security validation statistics
    pub security_stats: super::security::FragmentSecurityStats,
    /// Memory management statistics
    pub memory_stats: super::memory::FragmentMemoryStats,
}
