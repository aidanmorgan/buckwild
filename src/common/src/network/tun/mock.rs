//! Mock TUN device for testing
//!
//! This module provides a test-only TUN device implementation with injectable
//! packet queues and error injection for testing protocol logic without requiring
//! actual TUN device creation (CAP_NET_ADMIN, Linux kernel, etc.).
//!
//! ## Thread Safety
//!
//! TestTunDevice is thread-safe using Arc<Mutex<>> for shared state. All operations
//! acquire locks for short durations to prevent contention.

#![cfg(test)]

use super::TunDevice;
use super::error::{TunError, TunResult};
use super::types::{DeviceName, Mtu, TunConfig};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Internal state for TestTunDevice
#[derive(Debug)]
struct TestTunState {
    /// Packets available for reading (injected by tests)
    rx_queue: VecDeque<Vec<u8>>,
    /// Packets written by the device (captured for assertions)
    tx_queue: VecDeque<Vec<u8>>,
    /// Next error to inject on read (if any)
    next_read_error: Option<TunError>,
    /// Next error to inject on write (if any)
    next_write_error: Option<TunError>,
    /// Total packets read
    packets_read: usize,
    /// Total packets written
    packets_written: usize,
}

/// Mock TUN device for testing
///
/// Provides a TunDevice implementation that does not require Linux kernel support
/// or CAP_NET_ADMIN. Instead, tests can:
/// - Inject packets into the read queue via `inject_packet()`
/// - Capture written packets via `captured_packets()`
/// - Inject errors for error path testing via `inject_read_error()` and `inject_write_error()`
///
/// ## Thread Safety
///
/// All methods use interior mutability via Arc<Mutex<>> to enable concurrent access
/// from multiple tasks/threads.
///
/// ## Example
///
/// ```
/// use buckwild_common::network::tun::{TestTunDevice, TunDevice, TunConfig, DeviceName, Mtu};
/// use std::net::IpAddr;
///
/// #[tokio::test]
/// async fn test_packet_flow() {
///     let config = TunConfig::new(
///         DeviceName::new("test0").unwrap(),
///         "10.0.0.1".parse().unwrap(),
///         "255.255.255.0".parse().unwrap(),
///         Mtu::default(),
///     );
///
///     let mut device = TestTunDevice::create(config).await.unwrap();
///
///     // Inject a packet to be read
///     device.inject_packet(vec![0x45, 0x00, 0x00, 0x28]);
///
///     // Read the packet
///     let mut buf = [0u8; 1500];
///     let len = device.read_packet(&mut buf).await.unwrap();
///     assert_eq!(len, 4);
///     assert_eq!(&buf[..len], &[0x45, 0x00, 0x00, 0x28]);
///
///     // Write a packet
///     device.write_packet(&[0xaa, 0xbb, 0xcc]).await.unwrap();
///
///     // Verify captured packets
///     let captured = device.captured_packets();
///     assert_eq!(captured.len(), 1);
///     assert_eq!(captured[0], vec![0xaa, 0xbb, 0xcc]);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TestTunDevice {
    state: Arc<Mutex<TestTunState>>,
    name: DeviceName,
    mtu: Mtu,
}

impl TestTunDevice {
    /// Inject a packet into the read queue
    ///
    /// The next call to `read_packet()` will return this packet.
    /// Multiple packets can be injected; they are returned in FIFO order.
    ///
    /// # Example
    ///
    /// ```
    /// # use buckwild_common::network::tun::{TestTunDevice, TunDevice, TunConfig, DeviceName, Mtu};
    /// # #[tokio::test]
    /// # async fn example() {
    /// # let config = TunConfig::new(
    /// #     DeviceName::new("test0").unwrap(),
    /// #     "10.0.0.1".parse().unwrap(),
    /// #     "255.255.255.0".parse().unwrap(),
    /// #     Mtu::default(),
    /// # );
    /// # let mut device = TestTunDevice::create(config).await.unwrap();
    /// device.inject_packet(vec![0x45, 0x00, 0x00, 0x20]);
    /// device.inject_packet(vec![0x60, 0x00, 0x00, 0x00]); // IPv6
    ///
    /// let mut buf = [0u8; 1500];
    /// let len = device.read_packet(&mut buf).await.unwrap();
    /// assert_eq!(&buf[..len], &[0x45, 0x00, 0x00, 0x20]); // First packet
    /// # }
    /// ```
    pub fn inject_packet(&self, packet: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.rx_queue.push_back(packet);
    }

    /// Get all packets captured from write operations
    ///
    /// Returns a vector of all packets written via `write_packet()`.
    /// Packets are in the order they were written.
    ///
    /// # Example
    ///
    /// ```
    /// # use buckwild_common::network::tun::{TestTunDevice, TunDevice, TunConfig, DeviceName, Mtu};
    /// # #[tokio::test]
    /// # async fn example() {
    /// # let config = TunConfig::new(
    /// #     DeviceName::new("test0").unwrap(),
    /// #     "10.0.0.1".parse().unwrap(),
    /// #     "255.255.255.0".parse().unwrap(),
    /// #     Mtu::default(),
    /// # );
    /// # let mut device = TestTunDevice::create(config).await.unwrap();
    /// device.write_packet(&[0xaa, 0xbb]).await.unwrap();
    /// device.write_packet(&[0xcc, 0xdd]).await.unwrap();
    ///
    /// let captured = device.captured_packets();
    /// assert_eq!(captured.len(), 2);
    /// assert_eq!(captured[0], vec![0xaa, 0xbb]);
    /// assert_eq!(captured[1], vec![0xcc, 0xdd]);
    /// # }
    /// ```
    pub fn captured_packets(&self) -> Vec<Vec<u8>> {
        let state = self.state.lock().unwrap();
        state.tx_queue.iter().cloned().collect()
    }

    /// Inject an error to be returned on the next read operation
    ///
    /// The next call to `read_packet()` will return this error instead of reading
    /// a packet. Subsequent reads will succeed (unless another error is injected).
    ///
    /// # Example
    ///
    /// ```
    /// # use buckwild_common::network::tun::{TestTunDevice, TunDevice, TunConfig, DeviceName, Mtu};
    /// # use buckwild_common::network::tun::TunError;
    /// # #[tokio::test]
    /// # async fn example() {
    /// # let config = TunConfig::new(
    /// #     DeviceName::new("test0").unwrap(),
    /// #     "10.0.0.1".parse().unwrap(),
    /// #     "255.255.255.0".parse().unwrap(),
    /// #     Mtu::default(),
    /// # );
    /// # let mut device = TestTunDevice::create(config).await.unwrap();
    /// device.inject_read_error(TunError::InvalidState {
    ///     reason: "device not ready".to_string(),
    /// });
    ///
    /// let mut buf = [0u8; 1500];
    /// let result = device.read_packet(&mut buf).await;
    /// assert!(result.is_err());
    /// # }
    /// ```
    pub fn inject_read_error(&self, error: TunError) {
        let mut state = self.state.lock().unwrap();
        state.next_read_error = Some(error);
    }

    /// Inject an error to be returned on the next write operation
    ///
    /// The next call to `write_packet()` will return this error instead of writing
    /// the packet. Subsequent writes will succeed (unless another error is injected).
    ///
    /// # Example
    ///
    /// ```
    /// # use buckwild_common::network::tun::{TestTunDevice, TunDevice, TunConfig, DeviceName, Mtu};
    /// # use buckwild_common::network::tun::TunError;
    /// # #[tokio::test]
    /// # async fn example() {
    /// # let config = TunConfig::new(
    /// #     DeviceName::new("test0").unwrap(),
    /// #     "10.0.0.1".parse().unwrap(),
    /// #     "255.255.255.0".parse().unwrap(),
    /// #     Mtu::default(),
    /// # );
    /// # let mut device = TestTunDevice::create(config).await.unwrap();
    /// device.inject_write_error(TunError::Io {
    ///     operation: "write".to_string(),
    ///     source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken"),
    /// });
    ///
    /// let result = device.write_packet(&[0xaa, 0xbb]).await;
    /// assert!(result.is_err());
    /// # }
    /// ```
    pub fn inject_write_error(&self, error: TunError) {
        let mut state = self.state.lock().unwrap();
        state.next_write_error = Some(error);
    }

    /// Get the number of packets read from the device
    pub fn packets_read(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.packets_read
    }

    /// Get the number of packets written to the device
    pub fn packets_written(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.packets_written
    }

    /// Clear all queued packets and errors
    ///
    /// Resets the device to a clean state with:
    /// - Empty rx_queue
    /// - Empty tx_queue
    /// - No pending errors
    /// - Counters reset to zero
    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.rx_queue.clear();
        state.tx_queue.clear();
        state.next_read_error = None;
        state.next_write_error = None;
        state.packets_read = 0;
        state.packets_written = 0;
    }
}

#[async_trait::async_trait]
impl TunDevice for TestTunDevice {
    async fn create(config: TunConfig) -> TunResult<Self> {
        let name = config.name.clone();
        let mtu = config.mtu;
        Ok(Self {
            state: Arc::new(Mutex::new(TestTunState {
                rx_queue: VecDeque::new(),
                tx_queue: VecDeque::new(),
                next_read_error: None,
                next_write_error: None,
                packets_read: 0,
                packets_written: 0,
            })),
            name,
            mtu,
        })
    }

    async fn read_packet(&mut self, buf: &mut [u8]) -> TunResult<usize> {
        let mut state = self.state.lock().unwrap();

        if let Some(error) = state.next_read_error.take() {
            return Err(error);
        }

        if let Some(packet) = state.rx_queue.pop_front() {
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            state.packets_read += 1;
            Ok(len)
        } else {
            Err(TunError::Io {
                operation: "read packet from empty queue".to_string(),
                source: std::io::Error::new(std::io::ErrorKind::WouldBlock, "no packets available"),
            })
        }
    }

    async fn write_packet(&mut self, buf: &[u8]) -> TunResult<()> {
        let mut state = self.state.lock().unwrap();

        if let Some(error) = state.next_write_error.take() {
            return Err(error);
        }

        state.tx_queue.push_back(buf.to_vec());
        state.packets_written += 1;
        Ok(())
    }

    fn name(&self) -> &DeviceName {
        &self.name
    }

    fn mtu(&self) -> Mtu {
        self.mtu
    }
}

impl AsyncRead for TestTunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut state = self.state.lock().unwrap();

        if let Some(error) = state.next_read_error.take() {
            return Poll::Ready(Err(std::io::Error::other(error.to_string())));
        }

        if let Some(packet) = state.rx_queue.pop_front() {
            let len = packet.len().min(buf.remaining());
            buf.put_slice(&packet[..len]);
            state.packets_read += 1;
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no packets available",
            )))
        }
    }
}

impl AsyncWrite for TestTunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut state = self.state.lock().unwrap();

        if let Some(error) = state.next_write_error.take() {
            return Poll::Ready(Err(std::io::Error::other(error.to_string())));
        }

        state.tx_queue.push_back(buf.to_vec());
        state.packets_written += 1;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_config() -> TunConfig {
        TunConfig::new(
            DeviceName::new("test0").unwrap(),
            "10.0.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            Mtu::default(),
        )
    }

    #[tokio::test]
    async fn test_create() {
        let config = make_test_config();
        let device = TestTunDevice::create(config).await.unwrap();
        assert_eq!(device.name().as_str(), "test0");
        assert_eq!(device.mtu().get(), Mtu::DEFAULT);
    }

    #[tokio::test]
    async fn test_inject_and_read_packet() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        device.inject_packet(vec![0x45, 0x00, 0x00, 0x28]);

        let mut buf = [0u8; 1500];
        let len = device.read_packet(&mut buf).await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[..len], &[0x45, 0x00, 0x00, 0x28]);
        assert_eq!(device.packets_read(), 1);
    }

    #[tokio::test]
    async fn test_read_empty_queue() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        let mut buf = [0u8; 1500];
        let result = device.read_packet(&mut buf).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TunError::Io { .. }));
    }

    #[tokio::test]
    async fn test_write_and_capture() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        device.write_packet(&[0xaa, 0xbb, 0xcc]).await.unwrap();
        device.write_packet(&[0xdd, 0xee]).await.unwrap();

        let captured = device.captured_packets();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0], vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(captured[1], vec![0xdd, 0xee]);
        assert_eq!(device.packets_written(), 2);
    }

    #[tokio::test]
    async fn test_inject_read_error() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        device.inject_read_error(TunError::InvalidState {
            reason: "test error".to_string(),
        });

        let mut buf = [0u8; 1500];
        let result = device.read_packet(&mut buf).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TunError::InvalidState { .. }));

        device.inject_packet(vec![0x45]);
        let len = device.read_packet(&mut buf).await.unwrap();
        assert_eq!(len, 1);
    }

    #[tokio::test]
    async fn test_inject_write_error() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        device.inject_write_error(TunError::Io {
            operation: "write".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken"),
        });

        let result = device.write_packet(&[0xaa, 0xbb]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TunError::Io { .. }));

        device.write_packet(&[0xcc, 0xdd]).await.unwrap();
        let captured = device.captured_packets();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], vec![0xcc, 0xdd]);
    }

    #[tokio::test]
    async fn test_clear() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        device.inject_packet(vec![0x45]);
        device.write_packet(&[0xaa]).await.unwrap();

        device.clear();

        assert_eq!(device.packets_read(), 0);
        assert_eq!(device.packets_written(), 0);
        assert_eq!(device.captured_packets().len(), 0);

        let mut buf = [0u8; 1500];
        let result = device.read_packet(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fifo_order() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        device.inject_packet(vec![0x01]);
        device.inject_packet(vec![0x02]);
        device.inject_packet(vec![0x03]);

        let mut buf = [0u8; 1500];

        let len = device.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[0x01]);

        let len = device.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[0x02]);

        let len = device.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[0x03]);
    }

    #[tokio::test]
    async fn test_buffer_truncation() {
        let config = make_test_config();
        let mut device = TestTunDevice::create(config).await.unwrap();

        let large_packet = vec![0xaa; 2000];
        device.inject_packet(large_packet);

        let mut small_buf = [0u8; 100];
        let len = device.read_packet(&mut small_buf).await.unwrap();
        assert_eq!(len, 100);
        assert_eq!(&small_buf[..len], &vec![0xaa; 100][..]);
    }

    #[tokio::test]
    async fn test_thread_safety() {
        let config = make_test_config();
        let device = TestTunDevice::create(config).await.unwrap();

        let device_clone1 = device.clone();
        let device_clone2 = device.clone();

        let handle1 = tokio::spawn(async move {
            for i in 0..10 {
                device_clone1.inject_packet(vec![i]);
            }
        });

        let handle2 = tokio::spawn(async move {
            for i in 10..20 {
                device_clone2.inject_packet(vec![i]);
            }
        });

        handle1.await.unwrap();
        handle2.await.unwrap();

        let state = device.state.lock().unwrap();
        assert_eq!(state.rx_queue.len(), 20);
    }
}
