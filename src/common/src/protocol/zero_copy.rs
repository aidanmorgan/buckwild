use bytes::{BufMut, Bytes, BytesMut};
use crossbeam::queue::SegQueue;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// Import ALL types from the authoritative consolidated types module
use crate::protocol::types::*;

/// Zero-copy packet buffer with reference counting
#[derive(Debug, Clone)]
pub struct ZeroCopyPacket {
    data: Bytes,
    header_len: HeaderSize,
    payload_offset: ByteOffset,
}

impl ZeroCopyPacket {
    /// Create a new zero-copy packet from bytes
    pub fn new(data: Bytes) -> Result<Self, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::TooSmall);
        }

        // Parse header to determine header length
        let version = data[0];
        let header_len = Self::calculate_header_length(version)?;

        if data.len() < header_len {
            return Err(PacketError::InvalidHeader);
        }

        Ok(ZeroCopyPacket {
            data,
            header_len: HeaderSize::new(header_len as u16),
            payload_offset: ByteOffset::new(header_len),
        })
    }

    /// Create packet from mutable buffer
    pub fn from_mut(buffer: BytesMut, header_len: HeaderSize) -> Self {
        let header_len_usize = header_len.as_u16() as usize;
        ZeroCopyPacket {
            data: buffer.freeze(),
            header_len,
            payload_offset: ByteOffset::new(header_len_usize),
        }
    }

    /// Get header as zero-copy slice
    pub fn header(&self) -> Bytes {
        self.data.slice(0..self.header_len.as_u16() as usize)
    }

    /// Get payload as zero-copy slice
    pub fn payload(&self) -> Bytes {
        self.data.slice(self.payload_offset.as_usize()..)
    }

    /// Get entire packet data
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Split packet at given offset (zero-copy)
    pub fn split_at(&self, offset: ByteOffset) -> Result<(Bytes, Bytes), PacketError> {
        if offset.as_usize() > self.data.len() {
            return Err(PacketError::InvalidOffset);
        }

        let offset_usize = offset.as_usize();
        let left = self.data.slice(0..offset_usize);
        let right = self.data.slice(offset_usize..);
        Ok((left, right))
    }

    /// Create fragment from packet (zero-copy)
    pub fn fragment(&self, start: ByteOffset, len: ByteCount) -> Result<Bytes, PacketError> {
        let start_usize = start.as_usize();
        let len_usize = len.as_usize();
        let end = start_usize
            .checked_add(len_usize)
            .ok_or(PacketError::InvalidOffset)?;
        if end > self.data.len() {
            return Err(PacketError::InvalidOffset);
        }

        Ok(self.data.slice(start_usize..end))
    }

    /// Calculate header length from version byte
    fn calculate_header_length(version: u8) -> Result<usize, PacketError> {
        let version_byte = VersionByte::from_raw(version);
        let session_id_len = version_byte.session_id_length().len();
        let timestamp_len = version_byte.timestamp_config().len();

        // Base header: version(1) + type(1) + sub_type(1) + flags(1) = 4 bytes
        // Variable: session_id + timestamp + sequence(4) + hmac(variable)
        let base_len = 4 + session_id_len + timestamp_len + 4; // sequence is always 4 bytes

        // HMAC length depends on packet type and policy
        let hmac_len = HmacPolicy::Light.tag_size(); // Default to LIGHT policy

        Ok(base_len + hmac_len)
    }

    /// Get packet length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if packet is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Zero-copy packet builder
pub struct PacketBuilder {
    buffer: BytesMut,
    header_written: bool,
}

impl PacketBuilder {
    /// Create new packet builder with capacity
    pub fn new(capacity: BufferSize) -> Result<Self, PacketError> {
        let buffer = BytesMut::with_capacity(capacity.as_usize());

        Ok(PacketBuilder {
            buffer,
            header_written: false,
        })
    }

    /// Write packet header (placeholder implementation)
    pub fn write_header_bytes(&mut self, header_bytes: &[u8]) -> Result<(), PacketError> {
        if self.header_written {
            return Err(PacketError::HeaderAlreadyWritten);
        }

        if self.buffer.remaining_mut() < header_bytes.len() {
            return Err(PacketError::InsufficientCapacity);
        }

        self.buffer.put_slice(header_bytes);
        self.header_written = true;
        Ok(())
    }

    /// Append payload data (zero-copy if possible)
    pub fn append_payload(&mut self, data: &[u8]) -> Result<(), PacketError> {
        if !self.header_written {
            return Err(PacketError::HeaderNotWritten);
        }

        if self.buffer.remaining_mut() < data.len() {
            return Err(PacketError::InsufficientCapacity);
        }

        self.buffer.put_slice(data);
        Ok(())
    }

    /// Append bytes payload (zero-copy)
    pub fn append_bytes(&mut self, data: Bytes) -> Result<(), PacketError> {
        if !self.header_written {
            return Err(PacketError::HeaderNotWritten);
        }

        if self.buffer.remaining_mut() < data.len() {
            return Err(PacketError::InsufficientCapacity);
        }

        self.buffer.put(data);
        Ok(())
    }

    /// Build final packet
    pub fn build(self) -> Result<ZeroCopyPacket, PacketError> {
        if !self.header_written {
            return Err(PacketError::HeaderNotWritten);
        }

        let header_len = self.calculate_header_len()?;
        Ok(ZeroCopyPacket::from_mut(self.buffer, header_len))
    }

    fn calculate_header_len(&self) -> Result<HeaderSize, PacketError> {
        if self.buffer.len() < 4 {
            return Err(PacketError::TooSmall);
        }

        let version = self.buffer[0];
        let header_len = ZeroCopyPacket::calculate_header_length(version)?;
        Ok(HeaderSize::new(header_len as u16))
    }
}

/// Zero-copy packet chain for fragmentation
#[derive(Debug)]
pub struct PacketChain {
    fragments: Vec<ZeroCopyPacket>,
    total_len: PacketSize,
}

impl Default for PacketChain {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketChain {
    /// Create new packet chain
    pub fn new() -> Self {
        Self {
            fragments: Vec::new(),
            total_len: PacketSize::new(0),
        }
    }

    /// Add fragment to chain
    pub fn add_fragment(&mut self, fragment: ZeroCopyPacket) {
        self.total_len = PacketSize::new(self.total_len.as_usize() + fragment.len());
        self.fragments.push(fragment);
    }

    /// Reassemble fragments into single packet (zero-copy when possible)
    pub fn reassemble(self) -> Result<ZeroCopyPacket, PacketError> {
        if self.fragments.is_empty() {
            return Err(PacketError::EmptyChain);
        }

        if self.fragments.len() == 1 {
            // Single fragment, return as-is (zero-copy)
            // Safety: We've verified len() == 1, so next() cannot be None
            return self.fragments.into_iter().next().ok_or_else(|| {
                PacketError::Internal("Fragment iterator unexpectedly empty".to_string())
            });
        }

        // Multiple fragments, need to concatenate
        let mut builder = PacketBuilder::new(BufferSize::new(self.total_len.as_usize()))?;

        // Copy header from first fragment
        let first_fragment = &self.fragments[0];
        let header_bytes = first_fragment.header();
        builder.buffer.put(header_bytes);
        builder.header_written = true;

        // Concatenate payloads
        for fragment in &self.fragments {
            let payload = fragment.payload();
            builder.append_bytes(payload)?;
        }

        builder.build()
    }

    /// Get total length
    pub fn total_len(&self) -> PacketSize {
        self.total_len
    }

    /// Get fragment count
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
}

/// Lock-free packet queue for zero-copy packet passing
pub struct PacketQueue {
    queue: SegQueue<ZeroCopyPacket>,
    stats: Arc<QueueStats>,
}

#[derive(Debug, Default)]
pub struct QueueStats {
    pub enqueued: AtomicUsize,
    pub dequeued: AtomicUsize,
    pub current_size: AtomicUsize,
    pub max_size: AtomicUsize,
}

impl PacketQueue {
    /// Create new packet queue
    pub fn new() -> Self {
        Self {
            queue: SegQueue::new(),
            stats: Arc::new(QueueStats::default()),
        }
    }

    /// Enqueue packet (zero-copy)
    pub fn enqueue(&self, packet: ZeroCopyPacket) {
        self.queue.push(packet);
        self.stats
            .enqueued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let current = self
            .stats
            .current_size
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        // Update max size
        let mut max = self.stats.max_size.load(Ordering::Relaxed);
        while current > max {
            match self.stats.max_size.compare_exchange_weak(
                max,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => max = x,
            }
        }
    }

    /// Dequeue packet (zero-copy)
    pub fn dequeue(&self) -> Option<ZeroCopyPacket> {
        let packet = self.queue.pop()?;
        self.stats
            .dequeued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.current_size.fetch_sub(1, Ordering::Relaxed);
        Some(packet)
    }

    /// Get current queue size
    pub fn len(&self) -> usize {
        self.stats.current_size.load(Ordering::Relaxed)
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get queue statistics
    pub fn stats(&self) -> Arc<QueueStats> {
        self.stats.clone()
    }
}

impl Default for PacketQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet processing errors
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("Packet too small")]
    TooSmall,
    #[error("Invalid packet header")]
    InvalidHeader,
    #[error("Invalid packet version")]
    InvalidVersion,
    #[error("Invalid offset")]
    InvalidOffset,
    #[error("Allocation failed")]
    AllocationFailed,
    #[error("Header already written")]
    HeaderAlreadyWritten,
    #[error("Header not written")]
    HeaderNotWritten,
    #[error("Insufficient capacity")]
    InsufficientCapacity,
    #[error("Empty packet chain")]
    EmptyChain,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Internal error: {0}")]
    Internal(String),
}
