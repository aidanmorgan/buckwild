// Network layer errors
use thiserror::Error;

// Import specific types to avoid circular dependencies
use crate::protocol::types::{
    ByteCount, DataRate, MtuSize, NetworkEndpoint, PacketSize, Port, ProtocolDuration,
};

/// Network layer error types
#[derive(Error, Debug, Clone)]
pub enum NetworkError {
    #[error("Connection failed: {endpoint}")]
    ConnectionFailed { endpoint: NetworkEndpoint },

    #[error("Connection timeout: {endpoint} after {timeout_ms:?}ms")]
    ConnectionTimeout {
        endpoint: NetworkEndpoint,
        timeout_ms: ProtocolDuration,
    },

    #[error("Connection refused: {endpoint}")]
    ConnectionRefused { endpoint: NetworkEndpoint },

    #[error("Connection reset: {endpoint}")]
    ConnectionReset { endpoint: NetworkEndpoint },

    #[error("Network unreachable: {endpoint}")]
    NetworkUnreachable { endpoint: NetworkEndpoint },

    #[error("Host unreachable: {endpoint}")]
    HostUnreachable { endpoint: NetworkEndpoint },

    #[error("Port unreachable: {port}")]
    PortUnreachable { port: Port },

    #[error("Invalid address: {address}")]
    InvalidAddress { address: String },

    #[error("Invalid port: {port}")]
    InvalidPort { port: Port },

    #[error("Socket bind failed: {endpoint}")]
    SocketBindFailed { endpoint: NetworkEndpoint },

    #[error("Socket listen failed: {endpoint}")]
    SocketListenFailed { endpoint: NetworkEndpoint },

    #[error("Socket accept failed: {endpoint}")]
    SocketAcceptFailed { endpoint: NetworkEndpoint },

    #[error("Socket connect failed: {endpoint}")]
    SocketConnectFailed { endpoint: NetworkEndpoint },

    #[error("Send failed: {bytes} bytes to {endpoint}")]
    SendFailed {
        endpoint: NetworkEndpoint,
        bytes: ByteCount,
    },

    #[error("Receive failed from {endpoint}")]
    ReceiveFailed { endpoint: NetworkEndpoint },

    #[error("MTU exceeded: {size} > {mtu}")]
    MtuExceeded { size: PacketSize, mtu: MtuSize },

    #[error("Network congestion detected")]
    NetworkCongestion,

    #[error("Bandwidth limit exceeded: {rate}")]
    BandwidthLimitExceeded { rate: DataRate },

    #[error("Interface not found: {interface}")]
    InterfaceNotFound { interface: String },

    #[error("Interface down: {interface}")]
    InterfaceDown { interface: String },

    #[error("Interface up failed: {interface}")]
    InterfaceUpFailed { interface: String },

    #[error("Interface create failed: {interface} - {reason}")]
    InterfaceCreateFailed { interface: String, reason: String },

    #[error("Interface configure failed: {interface} - {reason}")]
    InterfaceConfigureFailed { interface: String, reason: String },

    #[error("Routing error: {destination}")]
    RoutingError { destination: NetworkEndpoint },

    #[error("Route add failed: {destination} - {reason}")]
    RouteAddFailed { destination: String, reason: String },

    #[error("Route delete failed: {destination} - {reason}")]
    RouteDeleteFailed { destination: String, reason: String },

    #[error("Route lookup failed: {destination}")]
    RouteLookupFailed { destination: String },

    #[error("Route not found: {destination}")]
    RouteNotFound { destination: String },

    #[error("DNS resolution failed: {hostname}")]
    DnsResolutionFailed { hostname: String },

    #[error("Network configuration error: {parameter}")]
    NetworkConfigurationError { parameter: String },

    // TUN device errors
    #[error("TUN device creation failed: {reason}")]
    TunCreateFailed { reason: String },

    #[error("TUN device configuration failed: {reason}")]
    TunConfigureFailed { reason: String },

    #[error("TUN device read failed: {reason}")]
    TunReadFailed { reason: String },

    #[error("TUN device write failed: {bytes} bytes - {reason}")]
    TunWriteFailed { bytes: ByteCount, reason: String },

    #[error("TUN device not found: {name}")]
    TunDeviceNotFound { name: String },

    #[error("TUN device permission denied: {name}")]
    TunPermissionDenied { name: String },

    // eBPF errors
    #[error("eBPF program load failed: {program} - {reason}")]
    EbpfLoadFailed { program: String, reason: String },

    #[error("eBPF program attach failed: {program} to {interface} - {reason}")]
    EbpfAttachFailed {
        program: String,
        interface: String,
        reason: String,
    },

    #[error("eBPF map operation failed: {map} - {operation} - {reason}")]
    EbpfMapOperationFailed {
        map: String,
        operation: String,
        reason: String,
    },

    #[error("eBPF verification failed: {program} - {reason}")]
    EbpfVerificationFailed { program: String, reason: String },

    #[error("eBPF not supported on this system")]
    EbpfNotSupported,
}

impl NetworkError {
    /// Create a connection failed error
    pub fn connection_failed(endpoint: NetworkEndpoint) -> Self {
        Self::ConnectionFailed { endpoint }
    }

    /// Create a connection timeout error
    pub fn connection_timeout(endpoint: NetworkEndpoint, timeout_ms: ProtocolDuration) -> Self {
        Self::ConnectionTimeout {
            endpoint,
            timeout_ms,
        }
    }

    /// Create a send failed error
    pub fn send_failed(endpoint: NetworkEndpoint, bytes: ByteCount) -> Self {
        Self::SendFailed { endpoint, bytes }
    }

    /// Create an MTU exceeded error
    pub fn mtu_exceeded(size: PacketSize, mtu: MtuSize) -> Self {
        Self::MtuExceeded { size, mtu }
    }

    /// Create a socket bind failed error
    pub fn socket_bind_failed(endpoint: NetworkEndpoint) -> Self {
        Self::SocketBindFailed { endpoint }
    }

    /// Create a socket listen failed error
    pub fn socket_listen_failed(endpoint: NetworkEndpoint) -> Self {
        Self::SocketListenFailed { endpoint }
    }

    /// Create a socket accept failed error
    pub fn socket_accept_failed(endpoint: NetworkEndpoint) -> Self {
        Self::SocketAcceptFailed { endpoint }
    }

    /// Create a socket connect failed error
    pub fn socket_connect_failed(endpoint: NetworkEndpoint) -> Self {
        Self::SocketConnectFailed { endpoint }
    }

    /// Create a route add failed error
    pub fn route_add_failed(destination: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::RouteAddFailed {
            destination: destination.into(),
            reason: reason.into(),
        }
    }

    /// Create a route delete failed error
    pub fn route_delete_failed(destination: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::RouteDeleteFailed {
            destination: destination.into(),
            reason: reason.into(),
        }
    }

    /// Create a route lookup failed error
    pub fn route_lookup_failed(destination: impl Into<String>) -> Self {
        Self::RouteLookupFailed {
            destination: destination.into(),
        }
    }

    /// Create a route not found error
    pub fn route_not_found(destination: impl Into<String>) -> Self {
        Self::RouteNotFound {
            destination: destination.into(),
        }
    }

    /// Create an interface create failed error
    pub fn interface_create_failed(
        interface: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InterfaceCreateFailed {
            interface: interface.into(),
            reason: reason.into(),
        }
    }

    /// Create an interface configure failed error
    pub fn interface_configure_failed(
        interface: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InterfaceConfigureFailed {
            interface: interface.into(),
            reason: reason.into(),
        }
    }

    /// Create an interface up failed error
    pub fn interface_up_failed(interface: impl Into<String>) -> Self {
        Self::InterfaceUpFailed {
            interface: interface.into(),
        }
    }

    /// Create an interface down error
    pub fn interface_down(interface: impl Into<String>) -> Self {
        Self::InterfaceDown {
            interface: interface.into(),
        }
    }

    /// Create a network congestion error
    pub fn network_congestion() -> Self {
        Self::NetworkCongestion
    }

    /// Create a bandwidth limit exceeded error
    pub fn bandwidth_limit_exceeded(rate: DataRate) -> Self {
        Self::BandwidthLimitExceeded { rate }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ConnectionFailed { .. } => true,
            Self::ConnectionTimeout { .. } => true,
            Self::ConnectionRefused { .. } => true,
            Self::ConnectionReset { .. } => true,
            Self::NetworkUnreachable { .. } => true,
            Self::HostUnreachable { .. } => true,
            Self::PortUnreachable { .. } => false,
            Self::InvalidAddress { .. } => false,
            Self::InvalidPort { .. } => false,
            Self::SocketBindFailed { .. } => true,
            Self::SocketListenFailed { .. } => true,
            Self::SocketAcceptFailed { .. } => true,
            Self::SocketConnectFailed { .. } => true,
            Self::SendFailed { .. } => true,
            Self::ReceiveFailed { .. } => true,
            Self::MtuExceeded { .. } => true,
            Self::NetworkCongestion => true,
            Self::BandwidthLimitExceeded { .. } => true,
            Self::InterfaceNotFound { .. } => false,
            Self::InterfaceDown { .. } => true,
            Self::InterfaceUpFailed { .. } => true,
            Self::InterfaceCreateFailed { .. } => true,
            Self::InterfaceConfigureFailed { .. } => true,
            Self::RoutingError { .. } => true,
            Self::RouteAddFailed { .. } => true,
            Self::RouteDeleteFailed { .. } => true,
            Self::RouteLookupFailed { .. } => true,
            Self::RouteNotFound { .. } => false,
            Self::DnsResolutionFailed { .. } => true,
            Self::NetworkConfigurationError { .. } => false,
            Self::TunCreateFailed { .. } => true,
            Self::TunConfigureFailed { .. } => true,
            Self::TunReadFailed { .. } => true,
            Self::TunWriteFailed { .. } => true,
            Self::TunDeviceNotFound { .. } => false,
            Self::TunPermissionDenied { .. } => false,
            Self::EbpfLoadFailed { .. } => true,
            Self::EbpfAttachFailed { .. } => true,
            Self::EbpfMapOperationFailed { .. } => true,
            Self::EbpfVerificationFailed { .. } => false,
            Self::EbpfNotSupported => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::ConnectionFailed { .. } => Some("Retry connection"),
            Self::ConnectionTimeout { .. } => Some("Increase timeout or retry"),
            Self::ConnectionRefused { .. } => Some("Check if service is running"),
            Self::ConnectionReset { .. } => Some("Retry connection"),
            Self::NetworkUnreachable { .. } => Some("Check network connectivity"),
            Self::HostUnreachable { .. } => Some("Check host availability"),
            Self::SocketBindFailed { .. } => Some("Use different port or address"),
            Self::SocketListenFailed { .. } => Some("Check port availability"),
            Self::SocketAcceptFailed { .. } => Some("Retry accept operation"),
            Self::SocketConnectFailed { .. } => Some("Retry connection"),
            Self::SendFailed { .. } => Some("Retry send operation"),
            Self::ReceiveFailed { .. } => Some("Retry receive operation"),
            Self::MtuExceeded { .. } => Some("Fragment packet or reduce size"),
            Self::NetworkCongestion => Some("Reduce transmission rate"),
            Self::BandwidthLimitExceeded { .. } => Some("Reduce data rate"),
            Self::InterfaceDown { .. } => Some("Wait for interface to come up"),
            Self::InterfaceUpFailed { .. } => Some("Check interface configuration and retry"),
            Self::InterfaceCreateFailed { .. } => Some("Check permissions and system resources"),
            Self::InterfaceConfigureFailed { .. } => {
                Some("Verify configuration parameters and retry")
            }
            Self::RoutingError { .. } => Some("Check routing configuration"),
            Self::RouteAddFailed { .. } => Some("Verify route parameters and retry"),
            Self::RouteDeleteFailed { .. } => Some("Check route exists before deleting"),
            Self::RouteLookupFailed { .. } => Some("Verify routing table and retry"),
            Self::DnsResolutionFailed { .. } => Some("Check DNS configuration"),
            Self::TunCreateFailed { .. } => Some("Check TUN device support and permissions"),
            Self::TunConfigureFailed { .. } => Some("Verify TUN device configuration"),
            Self::TunReadFailed { .. } => Some("Retry TUN read operation"),
            Self::TunWriteFailed { .. } => Some("Retry TUN write operation"),
            Self::EbpfLoadFailed { .. } => Some("Check eBPF program and kernel support"),
            Self::EbpfAttachFailed { .. } => Some("Verify interface and permissions"),
            Self::EbpfMapOperationFailed { .. } => Some("Retry map operation"),
            _ => None,
        }
    }
}

/// Network layer result type
pub type NetworkResult<T> = Result<T, NetworkError>;
