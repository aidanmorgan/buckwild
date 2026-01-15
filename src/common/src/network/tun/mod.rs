// TUN/TAP device management

// Core modules
pub mod device;
pub mod error;
pub mod manager;
pub mod translator;
pub mod types;

// Test-only modules
#[cfg(test)]
pub mod mock;

// Re-export public types for convenience
pub use device::{LinuxTunHandle, TunDevice};
pub use error::{
    ManagerError, ManagerResult, TranslatorError, TranslatorResult, TunError, TunResult,
};
pub use manager::*;
pub use translator::{ProtocolTranslator, TranslatorConfig};
pub use types::{DeviceName, Mtu, TunConfig};

// Re-export test types for convenience
#[cfg(test)]
pub use mock::TestTunDevice;
