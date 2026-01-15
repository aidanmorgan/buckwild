// Zero-copy abstractions using bytes::Bytes
use crate::error::BuckwildError;
use crate::protocol::types::{Length, StartOffset};
use bytes::{BufMut, Bytes, BytesMut};
use std::ops::{Deref, DerefMut};

/// Zero-copy buffer that can be shared between threads
#[derive(Debug, Clone)]
pub struct ZeroCopyBuffer {
    inner: Bytes,
}

impl ZeroCopyBuffer {
    /// Create a new zero-copy buffer from bytes
    pub fn new(bytes: Bytes) -> Self {
        Self { inner: bytes }
    }

    /// Create from a byte slice (will copy data)
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: Bytes::copy_from_slice(data),
        }
    }

    /// Create from a vector (will take ownership)
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self {
            inner: Bytes::from(data),
        }
    }

    /// Create an empty buffer
    pub fn empty() -> Self {
        Self {
            inner: Bytes::new(),
        }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a slice of the buffer data
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Split the buffer at the given index
    pub fn split_at(&mut self, at: usize) -> ZeroCopyBuffer {
        ZeroCopyBuffer {
            inner: self.inner.split_to(at),
        }
    }

    /// Split off a portion from the end
    pub fn split_off(&mut self, at: usize) -> ZeroCopyBuffer {
        ZeroCopyBuffer {
            inner: self.inner.split_off(at),
        }
    }

    /// Get a slice of the buffer
    pub fn slice(&self, range: std::ops::Range<usize>) -> ZeroCopyBuffer {
        ZeroCopyBuffer {
            inner: self.inner.slice(range),
        }
    }

    /// Concatenate with another buffer
    pub fn concat(&self, other: &ZeroCopyBuffer) -> ZeroCopyBuffer {
        let mut combined = Vec::with_capacity(self.len() + other.len());
        combined.extend_from_slice(&self.inner);
        combined.extend_from_slice(&other.inner);
        ZeroCopyBuffer::from_vec(combined)
    }

    /// Convert to bytes
    pub fn into_bytes(self) -> Bytes {
        self.inner
    }

    /// Get reference to inner bytes
    pub fn bytes(&self) -> &Bytes {
        &self.inner
    }

    /// Check if this buffer shares memory with another
    pub fn shares_memory_with(&self, other: &ZeroCopyBuffer) -> bool {
        // This is a heuristic - if the pointers are the same, they likely share memory
        self.inner.as_ptr() == other.inner.as_ptr()
    }
}

impl Deref for ZeroCopyBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<[u8]> for ZeroCopyBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl From<Bytes> for ZeroCopyBuffer {
    fn from(bytes: Bytes) -> Self {
        Self::new(bytes)
    }
}

impl From<Vec<u8>> for ZeroCopyBuffer {
    fn from(vec: Vec<u8>) -> Self {
        Self::from_vec(vec)
    }
}

impl From<&[u8]> for ZeroCopyBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

/// Mutable zero-copy buffer for building data
#[derive(Debug)]
pub struct ZeroCopyBufferMut {
    inner: BytesMut,
}

impl ZeroCopyBufferMut {
    /// Create a new mutable buffer with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
        }
    }

    /// Create a new empty mutable buffer
    pub fn new() -> Self {
        Self {
            inner: BytesMut::new(),
        }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Get remaining capacity
    pub fn remaining_mut(&self) -> usize {
        self.inner.remaining_mut()
    }

    /// Reserve additional capacity
    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    /// Extend the buffer with data
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }

    /// Put a byte
    pub fn put_u8(&mut self, val: u8) {
        self.inner.put_u8(val);
    }

    /// Put a u16 in network byte order
    pub fn put_u16(&mut self, val: u16) {
        self.inner.put_u16(val);
    }

    /// Put a u32 in network byte order
    pub fn put_u32(&mut self, val: u32) {
        self.inner.put_u32(val);
    }

    /// Put a u64 in network byte order
    pub fn put_u64(&mut self, val: u64) {
        self.inner.put_u64(val);
    }

    /// Put bytes from a slice
    pub fn put_slice(&mut self, src: &[u8]) {
        self.inner.put_slice(src);
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Truncate the buffer to the specified length
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Split the buffer at the given index, returning the left part as immutable
    pub fn split_to(&mut self, at: usize) -> ZeroCopyBuffer {
        ZeroCopyBuffer {
            inner: self.inner.split_to(at).freeze(),
        }
    }

    /// Split off the right part of the buffer
    pub fn split_off(&mut self, at: usize) -> ZeroCopyBufferMut {
        ZeroCopyBufferMut {
            inner: self.inner.split_off(at),
        }
    }

    /// Freeze the buffer into an immutable zero-copy buffer
    pub fn freeze(self) -> ZeroCopyBuffer {
        ZeroCopyBuffer {
            inner: self.inner.freeze(),
        }
    }

    /// Get a slice of the current data
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get a mutable slice of the current data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Default for ZeroCopyBufferMut {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ZeroCopyBufferMut {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ZeroCopyBufferMut {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Zero-copy slice that references a portion of a buffer
#[derive(Debug, Clone)]
pub struct ZeroCopySlice {
    buffer: ZeroCopyBuffer,
    start: StartOffset,
    len: Length,
}

impl ZeroCopySlice {
    /// Create a new zero-copy slice
    pub fn new(buffer: ZeroCopyBuffer, start: usize, len: usize) -> Result<Self, BuckwildError> {
        if start + len > buffer.len() {
            // Function params still use usize
            return Err(BuckwildError::internal_error(
                "Slice bounds exceed buffer length",
            ));
        }

        Ok(Self {
            buffer,
            start: StartOffset::new(start),
            len: Length::new(len),
        })
    }

    /// Get the length of the slice
    pub fn len(&self) -> usize {
        self.len.as_usize()
    }

    /// Check if the slice is empty
    pub fn is_empty(&self) -> bool {
        self.len.as_usize() == 0
    }

    /// Get the slice data
    pub fn as_slice(&self) -> &[u8] {
        let start_idx = self.start.as_usize();
        let len = self.len.as_usize();
        &self.buffer.as_slice()[start_idx..start_idx + len]
    }

    /// Create a sub-slice
    pub fn slice(&self, range: std::ops::Range<usize>) -> Result<ZeroCopySlice, BuckwildError> {
        if range.end > self.len.as_usize() {
            return Err(BuckwildError::internal_error("Slice range out of bounds"));
        }

        Ok(ZeroCopySlice {
            buffer: self.buffer.clone(),
            start: StartOffset::new(self.start.as_usize() + range.start),
            len: Length::new(range.end - range.start),
        })
    }

    /// Convert to a zero-copy buffer (will create a new buffer with the slice data)
    pub fn to_buffer(&self) -> ZeroCopyBuffer {
        let start_idx = self.start.as_usize();
        let len = self.len.as_usize();
        self.buffer.slice(start_idx..start_idx + len)
    }
}

impl Deref for ZeroCopySlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for ZeroCopySlice {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Builder for constructing zero-copy buffers efficiently
#[derive(Debug)]
pub struct ZeroCopyBuilder {
    buffer: ZeroCopyBufferMut,
}

impl ZeroCopyBuilder {
    /// Create a new builder with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: ZeroCopyBufferMut::with_capacity(capacity),
        }
    }

    /// Create a new builder
    pub fn new() -> Self {
        Self {
            buffer: ZeroCopyBufferMut::new(),
        }
    }

    /// Append data to the builder
    pub fn append(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(data);
        self
    }

    /// Append a zero-copy buffer
    pub fn append_buffer(&mut self, buffer: &ZeroCopyBuffer) -> &mut Self {
        self.buffer.extend_from_slice(buffer.as_slice());
        self
    }

    /// Append a u8
    pub fn append_u8(&mut self, val: u8) -> &mut Self {
        self.buffer.put_u8(val);
        self
    }

    /// Append a u16 in network byte order
    pub fn append_u16(&mut self, val: u16) -> &mut Self {
        self.buffer.put_u16(val);
        self
    }

    /// Append a u32 in network byte order
    pub fn append_u32(&mut self, val: u32) -> &mut Self {
        self.buffer.put_u32(val);
        self
    }

    /// Append a u64 in network byte order
    pub fn append_u64(&mut self, val: u64) -> &mut Self {
        self.buffer.put_u64(val);
        self
    }

    /// Get the current length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Build the final zero-copy buffer
    pub fn build(self) -> ZeroCopyBuffer {
        self.buffer.freeze()
    }
}

impl Default for ZeroCopyBuilder {
    fn default() -> Self {
        Self::new()
    }
}
