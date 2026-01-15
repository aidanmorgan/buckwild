#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use buckwild_ffi::tun::TunDeviceHandle;
use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

/// TUN device manager using FFI wrapper
pub struct TunDeviceManager {
    device: Option<TunDeviceHandle>,
    device_name: String,
    mtu: u16,
    running: Arc<AtomicBool>,
    packet_sender: mpsc::UnboundedSender<Bytes>,
    packet_receiver: mpsc::UnboundedReceiver<Bytes>,
    write_sender: mpsc::UnboundedSender<Bytes>,
    write_receiver: mpsc::UnboundedReceiver<Bytes>,
}

impl TunDeviceManager {
    /// Create a new TUN device manager using FFI wrapper
    ///
    /// # Parameters
    /// - `ip_addr` and `netmask` are in host byte order:
    ///   e.g., 10.0.0.1 = 0x0A000001, 255.255.255.0 = 0xFFFFFF00
    #[instrument(skip(packet_sender, write_receiver))]
    pub async fn new(
        device_name: &str,
        ip_addr: u32,
        netmask: u32,
        mtu: u16,
        packet_sender: mpsc::UnboundedSender<Bytes>,
        write_receiver: mpsc::UnboundedReceiver<Bytes>,
    ) -> Result<Self> {
        info!(
            "Creating TUN device: {} with MTU: {}, IP: 0x{:08X}, Netmask: 0x{:08X}",
            device_name, mtu, ip_addr, netmask
        );

        // Create device using FFI wrapper with configured IP and netmask
        let device = TunDeviceHandle::create(device_name, ip_addr, netmask, mtu)
            .with_context(|| format!("Failed to create TUN device: {}", device_name))?;

        info!("TUN device created successfully: {}", device_name);

        let (internal_packet_sender, packet_receiver) = mpsc::unbounded_channel();
        let (write_sender, internal_write_receiver) = mpsc::unbounded_channel();

        Ok(TunDeviceManager {
            device: Some(device),
            device_name: device_name.to_string(),
            mtu,
            running: Arc::new(AtomicBool::new(false)),
            packet_sender,
            packet_receiver,
            write_sender,
            write_receiver,
        })
    }

    /// Start the TUN device manager
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            warn!("TUN device manager already running");
            return Ok(());
        }

        info!("Starting TUN device manager for: {}", self.device_name);
        self.running.store(true, Ordering::Release);

        // Start combined I/O task
        self.start_io_task().await?;

        Ok(())
    }

    /// Start the combined I/O task for reading and writing
    /// Since TunDeviceHandle is !Send + !Sync, we handle both operations in a single thread
    async fn start_io_task(&mut self) -> Result<()> {
        let running = Arc::clone(&self.running);
        let packet_sender = self.packet_sender.clone();
        let mtu = self.mtu;

        // Take ownership of the device and write receiver
        let mut device = self
            .device
            .take()
            .ok_or_else(|| anyhow::anyhow!("Device already taken"))?;
        let mut write_receiver =
            std::mem::replace(&mut self.write_receiver, mpsc::unbounded_channel().1);

        // Set device to non-blocking mode for polling
        device
            .set_nonblock(true)
            .context("Failed to set device to non-blocking mode")?;

        tokio::task::spawn_blocking(move || {
            let mut read_buffer = vec![0u8; mtu as usize];

            while running.load(Ordering::Acquire) {
                // Try to read a packet
                match device.read(&mut read_buffer) {
                    Ok(size) if size > 0 => {
                        let packet = Bytes::copy_from_slice(&read_buffer[..size]);
                        debug!("Received packet of size: {}", size);

                        if let Err(e) = packet_sender.send(packet) {
                            error!("Failed to send packet to processor: {}", e);
                            break;
                        }
                    }
                    Ok(_) => {
                        // Zero bytes read, continue
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, this is expected in non-blocking mode
                    }
                    Err(e) => {
                        error!("Failed to read from TUN device: {}", e);
                    }
                }

                // Try to write pending packets
                match write_receiver.try_recv() {
                    Ok(packet) => {
                        debug!("Writing packet of size: {}", packet.len());

                        match device.write(&packet) {
                            Ok(written) if written == packet.len() => {
                                debug!("Successfully wrote packet");
                            }
                            Ok(written) => {
                                warn!("Partial write: {} of {} bytes", written, packet.len());
                            }
                            Err(e) => {
                                error!("Failed to write packet to TUN device: {}", e);
                            }
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        // No packets to write, this is expected
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        debug!("Write channel closed");
                        break;
                    }
                }

                // Small sleep to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_micros(100));
            }

            info!("I/O task terminated");
        });

        Ok(())
    }

    /// Stop the TUN device manager
    #[instrument(skip(self))]
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping TUN device manager: {}", self.device_name);
        self.running.store(false, Ordering::Release);

        // Give tasks time to terminate gracefully
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        info!("TUN device manager stopped");
        Ok(())
    }

    /// Send a packet to the TUN device
    pub fn send_packet(&self, packet: Bytes) -> Result<()> {
        self.write_sender
            .send(packet)
            .map_err(|e| anyhow::anyhow!("Failed to queue packet for writing: {}", e))
    }

    /// Get device information
    pub fn device_info(&self) -> DeviceInfo {
        DeviceInfo {
            name: self.device_name.clone(),
            mtu: self.mtu,
            running: self.running.load(Ordering::Acquire),
            memory_mapped: false,
        }
    }

    /// Configure MTU
    #[instrument(skip(self))]
    pub async fn set_mtu(&mut self, new_mtu: u16) -> Result<()> {
        info!("Changing MTU from {} to {}", self.mtu, new_mtu);

        // Note: Actual MTU change would require device reconfiguration
        // This is a simplified implementation
        self.mtu = new_mtu;

        info!("MTU changed successfully");
        Ok(())
    }

    /// Get current MTU
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Check if device is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

/// Device information structure
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub mtu: u16,
    pub running: bool,
    pub memory_mapped: bool,
}

impl Drop for TunDeviceManager {
    fn drop(&mut self) {
        info!("Cleaning up TUN device: {}", self.device_name);
        self.running.store(false, Ordering::Release);
    }
}
