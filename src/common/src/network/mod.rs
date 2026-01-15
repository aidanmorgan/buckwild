// Network layer
pub mod ebpf;
pub mod integrated;
pub mod routing;
pub mod socket;
pub mod tun;

// Import consolidated types

// Re-export network types (specific to avoid conflicts)
pub use ebpf::{EbpfLoader, LoaderConfig};
pub use integrated::{IntegratedConfig, IntegratedError, IntegratedManager, IntegratedStats};
pub use routing::{RoutingConfig, RoutingTable};
pub use socket::{SocketConfig, SocketManager, SocketStats};
pub use tun::{TunConfig, TunDevice};
