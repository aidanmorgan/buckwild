// Import consolidated types from common crate

// Daemon-specific types
pub mod actors;
pub mod config;
pub mod crypto;
pub mod logging;
pub mod maps;
pub mod monitoring;
pub mod protocol;
pub mod runtime;
pub mod shutdown;
pub mod snmp;
pub mod supervisor;
pub mod telemetry;
pub mod time_sync;
pub mod types;

#[cfg(target_os = "linux")]
pub mod ebpf_events;

#[cfg(target_os = "linux")]
pub mod tun;

#[cfg(not(target_os = "linux"))]
pub mod tun {
    use anyhow::Result;
    use bytes::Bytes;
    use tokio::sync::mpsc;

    pub struct TunDeviceManager;

    impl TunDeviceManager {
        pub async fn new(
            _device_name: &str,
            _ip_addr: u32,
            _netmask: u32,
            _mtu: u16,
            _packet_sender: mpsc::UnboundedSender<Bytes>,
            _write_receiver: mpsc::UnboundedReceiver<Bytes>,
        ) -> Result<Self> {
            anyhow::bail!("TUN device functionality requires Linux")
        }
    }

    pub mod device {
        pub struct FlowTracker;
    }

    pub mod routing {
        use crate::config::hosts::parser::HostsConfig;
        use std::sync::Arc;
        use thiserror::Error;
        use tokio::sync::RwLock;

        #[derive(Error, Debug)]
        pub enum RoutingError {
            #[error("Operation not supported on this platform")]
            Unsupported,
        }

        pub mod manager {
            use super::*;

            pub struct RoutingManager;

            #[derive(Error, Debug)]
            pub enum RoutingError {
                #[error("Operation not supported on this platform")]
                Unsupported,
            }

            impl RoutingManager {
                pub fn new(_device_name: &str) -> Result<Self, RoutingError> {
                    Err(RoutingError::Unsupported)
                }

                pub async fn update_routes(
                    &self,
                    _config: Arc<RwLock<HostsConfig>>,
                ) -> Result<(), RoutingError> {
                    Err(RoutingError::Unsupported)
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use tun::*;
