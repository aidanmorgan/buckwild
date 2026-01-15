/// Protocol test modules

pub mod types;

// Existing test modules
pub mod test_adaptive_networking;
pub mod test_anti_replay;
pub mod test_boundary_conditions;
pub mod test_comprehensive_anti_replay;
pub mod test_connection;
pub mod test_duplicate_detection;
pub mod test_edge_cases;
pub mod test_edge_cases_test;
pub mod test_enumeration_detection;
pub mod test_flow_control;
pub mod test_fragment_memory;
pub mod test_fragment_overlap;
pub mod test_fragment_rate_limit;
pub mod test_fragment_reassembly;
pub mod test_fragment_security;
pub mod test_fragmentation;
pub mod test_header;
pub mod test_packet;
pub mod test_port_hopping;
pub mod test_queues;
pub mod test_recovery_engine;
pub mod test_replay_prevention;
pub mod test_security;
pub mod test_state;
pub mod test_timeout;
pub mod test_timeout_test;
pub mod test_validation;
pub mod test_zero_copy;

// Sub-modules
pub mod fragmentation;
pub mod packet;