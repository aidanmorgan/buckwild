use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, info, instrument, warn};

use buckwild_common::protocol::types::{SequenceNumber, SessionId};
use buckwild_common::types::time::Timestamp;

/// Stream reassembly engine for ordered packet delivery
pub struct StreamReassembler {
    streams: Arc<RwLock<HashMap<SessionId, Arc<Mutex<StreamState>>>>>,
    reassembly_timeout: Duration,
    max_buffer_size: usize,
    max_out_of_order: usize,
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Per-stream reassembly state
#[derive(Debug)]
struct StreamState {
    session_id: SessionId,
    expected_sequence: SequenceNumber,
    reassembly_buffer: BTreeMap<SequenceNumber, StreamSegment>,
    completed_data: BytesMut,
    total_buffered_bytes: usize,
    last_activity: Timestamp,
    statistics: StreamStatistics,
}

/// Stream segment with metadata
#[derive(Debug, Clone)]
struct StreamSegment {
    sequence: SequenceNumber,
    data: Bytes,
    received_time: Timestamp,
    end_of_stream: bool,
}

/// Stream reassembly statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StreamStatistics {
    pub total_segments_received: u64,
    pub segments_in_order: u64,
    pub segments_out_of_order: u64,
    pub segments_duplicate: u64,
    pub bytes_reassembled: u64,
    pub reassembly_timeouts: u64,
    pub buffer_overflows: u64,
}

/// Reassembly result
#[derive(Debug, Clone)]
pub struct ReassemblyResult {
    pub data: Option<Bytes>,
    pub end_of_stream: bool,
    pub bytes_consumed: usize,
}

/// Global reassembly statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GlobalReassemblyStatistics {
    pub active_streams: u32,
    pub total_bytes_buffered: u64,
    pub total_segments_buffered: u64,
    pub average_reassembly_delay_ms: f64,
    pub buffer_utilization_percent: f64,
}

impl StreamReassembler {
    /// Create a new stream reassembler
    #[instrument]
    pub fn new(
        reassembly_timeout: Duration,
        max_buffer_size: usize,
        max_out_of_order: usize,
    ) -> Self {
        info!(
            "Creating stream reassembler with timeout: {:?}, max buffer: {} bytes, max out-of-order: {}",
            reassembly_timeout, max_buffer_size, max_out_of_order
        );

        StreamReassembler {
            streams: Arc::new(RwLock::new(HashMap::new())),
            reassembly_timeout,
            max_buffer_size,
            max_out_of_order,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the stream reassembler
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Acquire) {
            warn!("Stream reassembler already running");
            return Ok(());
        }

        info!("Starting stream reassembler");
        self.running
            .store(true, std::sync::atomic::Ordering::Release);

        // Start timeout cleanup task
        let streams = Arc::clone(&self.streams);
        let running = Arc::clone(&self.running);
        let timeout = self.reassembly_timeout;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1)); // Check every second

            while running.load(std::sync::atomic::Ordering::Acquire) {
                interval.tick().await;

                let now = Timestamp::now();
                let streams_guard = streams.read().await;
                let mut expired_streams = Vec::new();

                for (session_id, stream) in streams_guard.iter() {
                    let mut stream_state = stream.lock().await;

                    // Check for expired segments
                    let mut expired_segments = Vec::new();
                    for (seq, segment) in &stream_state.reassembly_buffer {
                        let elapsed_nanos = now
                            .as_nanos()
                            .saturating_sub(segment.received_time.as_nanos());
                        if elapsed_nanos > timeout.as_nanos() as u64 {
                            expired_segments.push(*seq);
                        }
                    }

                    // Remove expired segments
                    for seq in expired_segments {
                        if let Some(segment) = stream_state.reassembly_buffer.remove(&seq) {
                            stream_state.total_buffered_bytes -= segment.data.len();
                            stream_state.statistics.reassembly_timeouts += 1;
                            debug!("Removed expired segment {} from stream {}", seq, session_id);
                        }
                    }

                    // Check if entire stream is expired
                    let stream_elapsed_nanos = now
                        .as_nanos()
                        .saturating_sub(stream_state.last_activity.as_nanos());
                    if stream_elapsed_nanos > (timeout.as_nanos() as u64) * 2 {
                        expired_streams.push(session_id.clone());
                    }
                }

                // Remove expired streams
                drop(streams_guard);
                if !expired_streams.is_empty() {
                    let mut streams_guard = streams.write().await;
                    for session_id in expired_streams {
                        streams_guard.remove(&session_id);
                        info!("Removed expired stream: {}", session_id);
                    }
                }
            }

            info!("Stream reassembler cleanup task terminated");
        });

        Ok(())
    }

    /// Stop the stream reassembler
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping stream reassembler");
        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Clear all streams
        self.streams.write().await.clear();

        info!("Stream reassembler stopped");
    }

    /// Create a new stream
    #[instrument(skip(self))]
    pub async fn create_stream(
        &self,
        session_id: SessionId,
        initial_sequence: SequenceNumber,
    ) -> Result<()> {
        debug!(
            "Creating stream for session: {:?}, initial sequence: {:?}",
            session_id, initial_sequence
        );

        let stream_state = StreamState {
            session_id: session_id.clone(),
            expected_sequence: initial_sequence,
            reassembly_buffer: BTreeMap::new(),
            completed_data: BytesMut::new(),
            total_buffered_bytes: 0,
            last_activity: Timestamp::now(),
            statistics: StreamStatistics::default(),
        };

        self.streams
            .write()
            .await
            .insert(session_id.clone(), Arc::new(Mutex::new(stream_state)));
        info!("Created stream for session: {}", session_id);
        Ok(())
    }

    /// Process received segment
    #[instrument(skip(self, data))]
    pub async fn process_segment(
        &self,
        session_id: SessionId,
        sequence: SequenceNumber,
        data: Bytes,
        end_of_stream: bool,
    ) -> Result<ReassemblyResult> {
        let streams = self.streams.read().await;
        let stream = streams.get(&session_id).context("Stream not found")?;

        let mut stream_state = stream.lock().await;
        stream_state.last_activity = Timestamp::now();
        stream_state.statistics.total_segments_received += 1;

        debug!(
            "Processing segment for session: {}, sequence: {}, size: {}, EOS: {}",
            session_id,
            sequence,
            data.len(),
            end_of_stream
        );

        // Check for duplicate segment
        if stream_state.reassembly_buffer.contains_key(&sequence) {
            stream_state.statistics.segments_duplicate += 1;
            debug!("Duplicate segment received: {}", sequence);
            return Ok(ReassemblyResult {
                data: None,
                end_of_stream: false,
                bytes_consumed: 0,
            });
        }

        // Check buffer limits
        if stream_state.total_buffered_bytes + data.len() > self.max_buffer_size {
            stream_state.statistics.buffer_overflows += 1;
            warn!(
                "Buffer overflow for stream {}, dropping segment {}",
                session_id, sequence
            );
            return Ok(ReassemblyResult {
                data: None,
                end_of_stream: false,
                bytes_consumed: 0,
            });
        }

        // Check out-of-order limits
        if stream_state.reassembly_buffer.len() >= self.max_out_of_order {
            stream_state.statistics.buffer_overflows += 1;
            warn!(
                "Too many out-of-order segments for stream {}, dropping segment {}",
                session_id, sequence
            );
            return Ok(ReassemblyResult {
                data: None,
                end_of_stream: false,
                bytes_consumed: 0,
            });
        }

        let segment = StreamSegment {
            sequence,
            data: data.clone(),
            received_time: Timestamp::now(),
            end_of_stream,
        };

        // Check if this is the expected segment
        if sequence == stream_state.expected_sequence {
            // In-order segment
            stream_state.statistics.segments_in_order += 1;
            let data_len = data.len() as u32;
            stream_state.completed_data.put(data);
            stream_state.expected_sequence += data_len;

            // Check for additional consecutive segments in buffer
            let mut additional_data = BytesMut::new();
            let mut final_end_of_stream = end_of_stream;

            loop {
                let expected_seq = stream_state.expected_sequence;
                if let Some(next_segment) = stream_state.reassembly_buffer.remove(&expected_seq) {
                    additional_data.put(next_segment.data.clone());
                    stream_state.total_buffered_bytes -= next_segment.data.len();
                    stream_state.expected_sequence += next_segment.data.len() as u32;

                    if next_segment.end_of_stream {
                        final_end_of_stream = true;
                        break;
                    }
                } else {
                    break;
                }
            }

            // Combine all consecutive data
            if !additional_data.is_empty() {
                stream_state.completed_data.put(additional_data);
            }

            let result_data = stream_state.completed_data.split().freeze();
            let bytes_consumed = result_data.len();
            stream_state.statistics.bytes_reassembled += bytes_consumed as u64;

            debug!(
                "Delivered {} bytes in-order for stream {}",
                bytes_consumed, session_id
            );

            Ok(ReassemblyResult {
                data: Some(result_data),
                end_of_stream: final_end_of_stream,
                bytes_consumed,
            })
        } else if sequence > stream_state.expected_sequence {
            // Out-of-order segment - buffer it
            stream_state.statistics.segments_out_of_order += 1;
            stream_state.total_buffered_bytes += data.len();
            stream_state.reassembly_buffer.insert(sequence, segment);

            debug!(
                "Buffered out-of-order segment {} for stream {} (expected: {})",
                sequence, session_id, stream_state.expected_sequence
            );

            Ok(ReassemblyResult {
                data: None,
                end_of_stream: false,
                bytes_consumed: 0,
            })
        } else {
            // Old segment - ignore
            stream_state.statistics.segments_duplicate += 1;
            debug!(
                "Ignoring old segment {} for stream {} (expected: {})",
                sequence, session_id, stream_state.expected_sequence
            );

            Ok(ReassemblyResult {
                data: None,
                end_of_stream: false,
                bytes_consumed: 0,
            })
        }
    }

    /// Force delivery of buffered data (for connection close)
    #[instrument(skip(self))]
    pub async fn force_delivery(&self, session_id: SessionId) -> Result<Option<Bytes>> {
        let streams = self.streams.read().await;
        let stream = streams.get(&session_id).context("Stream not found")?;

        let mut stream_state = stream.lock().await;

        // Deliver all buffered segments in order
        let mut result_data = BytesMut::new();

        // First, add any completed data
        if !stream_state.completed_data.is_empty() {
            result_data.put(stream_state.completed_data.split());
        }

        // Then add buffered segments in sequence order
        let buffer = std::mem::take(&mut stream_state.reassembly_buffer);
        for (_, segment) in buffer {
            let segment_len = segment.data.len();
            result_data.put(segment.data);
            stream_state.total_buffered_bytes -= segment_len;
        }

        if result_data.is_empty() {
            Ok(None)
        } else {
            let bytes_delivered = result_data.len();
            stream_state.statistics.bytes_reassembled += bytes_delivered as u64;

            info!(
                "Force delivered {} bytes for stream {}",
                bytes_delivered, session_id
            );
            Ok(Some(result_data.freeze()))
        }
    }

    /// Remove stream
    #[instrument(skip(self))]
    pub async fn remove_stream(&self, session_id: SessionId) -> Result<()> {
        self.streams.write().await.remove(&session_id);
        info!("Removed stream: {:?}", session_id);
        Ok(())
    }

    /// Get stream statistics
    pub async fn get_stream_statistics(&self, session_id: SessionId) -> Option<StreamStatistics> {
        let streams = self.streams.read().await;
        let stream = streams.get(&session_id)?;
        let stream_state = stream.lock().await;
        Some(stream_state.statistics.clone())
    }

    /// Get global statistics
    pub async fn get_global_statistics(&self) -> GlobalReassemblyStatistics {
        let streams = self.streams.read().await;
        let mut stats = GlobalReassemblyStatistics {
            active_streams: streams.len() as u32,
            ..Default::default()
        };

        let mut total_buffered_bytes = 0u64;
        let mut total_buffered_segments = 0u64;
        let mut total_delay_ms = 0f64;
        let mut delay_samples = 0u64;

        for stream in streams.values() {
            let stream_state = stream.lock().await;
            total_buffered_bytes += stream_state.total_buffered_bytes as u64;
            total_buffered_segments += stream_state.reassembly_buffer.len() as u64;

            // Calculate average delay for buffered segments
            let now = Timestamp::now();
            for segment in stream_state.reassembly_buffer.values() {
                let delay_nanos = now
                    .as_nanos()
                    .saturating_sub(segment.received_time.as_nanos());
                total_delay_ms += (delay_nanos / 1_000_000) as f64; // Convert nanos to millis
                delay_samples += 1;
            }
        }

        stats.total_bytes_buffered = total_buffered_bytes;
        stats.total_segments_buffered = total_buffered_segments;

        if delay_samples > 0 {
            stats.average_reassembly_delay_ms = total_delay_ms / delay_samples as f64;
        }

        stats.buffer_utilization_percent = (total_buffered_bytes as f64
            / (self.max_buffer_size * streams.len()).max(1) as f64)
            * 100.0;

        stats
    }

    /// Check if stream exists
    pub async fn stream_exists(&self, session_id: SessionId) -> bool {
        self.streams.read().await.contains_key(&session_id)
    }

    /// Get expected sequence number for stream
    pub async fn get_expected_sequence(&self, session_id: SessionId) -> Option<SequenceNumber> {
        let streams = self.streams.read().await;
        let stream = streams.get(&session_id)?;
        let stream_state = stream.lock().await;
        Some(stream_state.expected_sequence)
    }
}
