// Integration test module
pub mod common;

// Engine interaction tests
pub mod engine_interaction_tests;

// Engine coordination tests (PortHopping + TimeSync)
pub mod test_engine_coordination;

// Security integration tests
pub mod security_integration_tests;

// eBPF integration tests
pub mod ebpf {
    pub mod ebpf_integration_tests;
}

// TUN-Protocol integration tests (TDD - Phase 1)
pub mod tun_protocol;

// End-to-end system tests
pub mod system_tests;

// Performance integration tests
pub mod performance_tests;

// Connection lifecycle integration tests
pub mod test_connection_lifecycle;

// Connection lifecycle with mock devices (MockClock + TestTunDevice)
pub mod connection_lifecycle_mock_devices;