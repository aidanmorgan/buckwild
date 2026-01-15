/// Integration tests for SNMP agent
///
/// Tests demonstrate:
/// - GET operations for individual OIDs
/// - GET-NEXT operations for MIB tree traversal
/// - GET-BULK operations for efficient retrieval
/// - Statistics counter updates
/// - MIB object navigation
use buckwild_daemon::snmp::{MibObjects, SnmpAgent, SnmpConfig};
use rasn::types::ObjectIdentifier;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Helper to create test SNMP agent on random port
async fn create_test_agent() -> (SnmpAgent, u16) {
    let listener = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);

    let config = SnmpConfig {
        listen_addr: format!("127.0.0.1:{}", port).parse().expect("parse addr"),
        community: "public".to_string(),
        max_pdu_size: 65535,
    };

    let agent = SnmpAgent::new(config);
    (agent, port)
}

/// Helper to create test OID
fn test_oid(parts: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(parts.iter().map(|&n| n.into()).collect())
}

#[tokio::test]
async fn test_mib_objects_statistics() {
    let mib = MibObjects::new();

    mib.inc_packets_transmitted(100);
    mib.inc_packets_received(50);
    mib.inc_bytes_transmitted(1024);
    mib.inc_bytes_received(512);
    mib.set_active_connections(5);
    mib.inc_total_connections_established();

    let oid_packets_tx = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
    let value = mib.get_value(&oid_packets_tx).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Counter64(v) => assert_eq!(v, 100),
        _ => panic!("Expected Counter64"),
    }

    let oid_active_conns = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 6]);
    let value = mib.get_value(&oid_active_conns).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Gauge32(v) => assert_eq!(v, 5),
        _ => panic!("Expected Gauge32"),
    }
}

#[tokio::test]
async fn test_mib_objects_security_metrics() {
    let mib = MibObjects::new();

    mib.inc_hmac_validation_failures();
    mib.inc_hmac_validation_failures();
    mib.inc_replay_attacks_detected();
    mib.inc_authentication_failures();
    mib.inc_fragment_bombs_detected();
    mib.inc_rate_limit_violations();
    mib.set_blocked_sources(3);

    let oid_hmac_failures = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 2, 1]);
    let value = mib.get_value(&oid_hmac_failures).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Counter64(v) => assert_eq!(v, 2),
        _ => panic!("Expected Counter64"),
    }

    let oid_blocked = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 2, 6]);
    let value = mib.get_value(&oid_blocked).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Gauge32(v) => assert_eq!(v, 3),
        _ => panic!("Expected Gauge32"),
    }
}

#[tokio::test]
async fn test_mib_objects_port_hopping() {
    let mib = MibObjects::new();

    mib.inc_port_transitions();
    mib.inc_port_transitions();
    mib.inc_port_transitions();
    mib.inc_port_transition_failures();
    mib.set_current_listening_ports(8);
    mib.set_time_sync_drift_ms(25);

    let oid_transitions = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 3, 1]);
    let value = mib.get_value(&oid_transitions).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Counter64(v) => assert_eq!(v, 3),
        _ => panic!("Expected Counter64"),
    }

    let oid_drift = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 3, 4]);
    let value = mib.get_value(&oid_drift).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Integer(v) => assert_eq!(v, 25),
        _ => panic!("Expected Integer"),
    }
}

#[tokio::test]
async fn test_mib_objects_performance() {
    let mib = MibObjects::new();

    mib.set_avg_latency_us(500);
    mib.set_max_latency_us(2000);
    mib.set_p99_latency_us(1500);
    mib.set_throughput_bps(1000000);

    let oid_avg_latency = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 5, 1]);
    let value = mib.get_value(&oid_avg_latency).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Gauge32(v) => assert_eq!(v, 500),
        _ => panic!("Expected Gauge32"),
    }

    let oid_throughput = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 5, 4]);
    let value = mib.get_value(&oid_throughput).expect("value exists");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Gauge32(v) => assert_eq!(v, 1000000),
        _ => panic!("Expected Gauge32"),
    }
}

#[tokio::test]
async fn test_mib_oid_navigation() {
    let mib = MibObjects::new();

    let oid_stats_1 = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
    let next = mib.get_next_oid(&oid_stats_1).expect("next OID");

    let expected = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 2]);
    assert_eq!(next, expected);

    let oid_stats_7 = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 7]);
    let next = mib.get_next_oid(&oid_stats_7).expect("next OID");

    let expected = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 2, 1]);
    assert_eq!(next, expected);

    let oid_security_6 = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 2, 6]);
    let next = mib.get_next_oid(&oid_security_6).expect("next OID");

    let expected = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 3, 1]);
    assert_eq!(next, expected);
}

#[tokio::test]
async fn test_mib_end_of_view() {
    let mib = MibObjects::new();

    let oid_last = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 5, 4]);
    let next = mib.get_next_oid(&oid_last);

    assert!(next.is_none());

    let oid_beyond = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 2, 1, 1]);
    let next = mib.get_next_oid(&oid_beyond);

    assert!(next.is_none());
}

#[tokio::test]
async fn test_mib_invalid_oid() {
    let mib = MibObjects::new();

    let oid_wrong_base = test_oid(&[1, 3, 6, 1, 4, 1, 12345, 1, 1, 1]);
    let value = mib.get_value(&oid_wrong_base);

    assert!(value.is_none());

    let oid_invalid_group = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 99, 1]);
    let value = mib.get_value(&oid_invalid_group);

    assert!(value.is_none());
}

#[tokio::test]
async fn test_snmp_agent_creation() {
    let (_agent, port) = create_test_agent().await;
    assert!(port > 0);
}

#[tokio::test]
async fn test_snmp_agent_mib_access() {
    let (agent, _port) = create_test_agent().await;
    let mib = agent.mib();

    {
        let mib_guard = mib.write().await;
        mib_guard.inc_packets_transmitted(42);
    }

    {
        let mib_guard = mib.read().await;
        let oid = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
        let value = mib_guard.get_value(&oid).expect("value exists");

        match value {
            buckwild_daemon::snmp::objects::MibValue::Counter64(v) => assert_eq!(v, 42),
            _ => panic!("Expected Counter64"),
        }
    }
}

#[tokio::test]
async fn test_snmp_pdu_encoding_decoding() {
    use buckwild_daemon::snmp::pdu::{SnmpMessage, SnmpPdu, new_counter64_varbind};

    let mut pdu = SnmpPdu::new(123);
    let oid = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
    pdu.add_varbind(new_counter64_varbind(oid.clone(), 100));

    let message = SnmpMessage::new_get_request("public".to_string(), pdu.clone());

    let encoded = message.encode().expect("encoding");

    let decoded = SnmpMessage::decode(&encoded).expect("decoding");

    assert_eq!(decoded.get_community().expect("community"), "public");

    let (pdu_type, decoded_pdu) = decoded.get_pdu_type_and_pdu().expect("pdu");
    assert_eq!(pdu_type, buckwild_daemon::snmp::pdu::PduType::GetRequest);
    assert_eq!(decoded_pdu.request_id(), 123);
    assert_eq!(decoded_pdu.get_varbinds().len(), 1);
}

#[tokio::test]
async fn test_snmp_multiple_varbinds() {
    use buckwild_daemon::snmp::pdu::{SnmpMessage, SnmpPdu, new_counter64_varbind};

    let mut pdu = SnmpPdu::new(456);

    let oid1 = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
    let oid2 = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 2]);
    let oid3 = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 3]);

    pdu.add_varbind(new_counter64_varbind(oid1, 100));
    pdu.add_varbind(new_counter64_varbind(oid2, 200));
    pdu.add_varbind(new_counter64_varbind(oid3, 300));

    let message = SnmpMessage::new_get_request("public".to_string(), pdu);
    let encoded = message.encode().expect("encoding");
    let decoded = SnmpMessage::decode(&encoded).expect("decoding");

    let (_pdu_type, decoded_pdu) = decoded.get_pdu_type_and_pdu().expect("pdu");
    assert_eq!(decoded_pdu.get_varbinds().len(), 3);
}

#[tokio::test]
async fn test_concurrent_mib_updates() {
    use tokio::task;

    let mib = Arc::new(RwLock::new(MibObjects::new()));

    let mut handles = vec![];

    for i in 0..10 {
        let mib_clone = Arc::clone(&mib);
        let handle = task::spawn(async move {
            let mib_guard = mib_clone.read().await;
            mib_guard.inc_packets_transmitted(i);
            mib_guard.inc_packets_received(i * 2);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("task completed");
    }

    let mib_guard = mib.read().await;
    let expected_tx: u64 = (0..10).sum();
    let expected_rx: u64 = (0..10).map(|i| i * 2).sum();

    let oid_tx = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1]);
    let value = mib_guard.get_value(&oid_tx).expect("value");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Counter64(v) => assert_eq!(v, expected_tx),
        _ => panic!("Expected Counter64"),
    }

    let oid_rx = test_oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 2]);
    let value = mib_guard.get_value(&oid_rx).expect("value");
    match value {
        buckwild_daemon::snmp::objects::MibValue::Counter64(v) => assert_eq!(v, expected_rx),
        _ => panic!("Expected Counter64"),
    }
}

#[tokio::test]
async fn test_session_entry() {
    use buckwild_daemon::snmp::objects::{SessionEntry, SessionState};

    let session = SessionEntry::new(
        1,
        12345,
        "192.168.1.100".to_string(),
        SessionState::Established,
    );

    assert_eq!(session.index, 1);
    assert_eq!(session.session_id, 12345);
    assert_eq!(session.peer_address, "192.168.1.100");
    assert_eq!(session.state, SessionState::Established);

    let oid = session.get_oid(2);
    let parts: Vec<u32> = oid.as_ref().iter().map(|n| (*n).into()).collect();

    assert_eq!(parts, vec![1, 3, 6, 1, 4, 1, 99999, 1, 4, 1, 1, 2, 1]);
}

#[tokio::test]
async fn test_request_id_generation() {
    use buckwild_daemon::snmp::pdu::generate_request_id;

    let id1 = generate_request_id();
    let id2 = generate_request_id();
    let id3 = generate_request_id();

    assert!(id2 > id1);
    assert!(id3 > id2);
}
