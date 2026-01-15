//! End-to-end test demonstrating multi-tenant isolation
//!
//! This test verifies:
//! - Two tenants created on same daemon
//! - Each tenant has separate PSKs
//! - Sessions established for each tenant
//! - Sessions are isolated (tenant A cannot access tenant B sessions)
//! - Port calculations differ by tenant

use buckwild_common::protocol::types::SessionId;
use buckwild_common::tenant::{
    CrossTenantSecurityEnforcer, PortAllocationManager, SharedPortStrategy, TenantId, TenantPsk,
    TenantPskStore, TenantSessionManager,
};

#[test]
#[ignore = "Test hangs on macOS - multi-tenant isolation verified by unit tests in tenant/multi_tenant_tests.rs"]
fn test_two_tenant_isolation_e2e() {
    // Create two tenants
    let tenant_a = TenantId::from_u64(1);
    let tenant_b = TenantId::from_u64(2);

    // Create separate PSK stores for each tenant
    let psk_store_a = TenantPskStore::new(tenant_a);
    let psk_store_b = TenantPskStore::new(tenant_b);

    // Add separate PSKs to each tenant
    let psk_material_a = vec![0xAA; 32];
    let psk_a = TenantPsk::new("psk-a".to_string(), &psk_material_a, tenant_a)
        .expect("Failed to create PSK for tenant A");

    let psk_material_b = vec![0xBB; 32];
    let psk_b = TenantPsk::new("psk-b".to_string(), &psk_material_b, tenant_b)
        .expect("Failed to create PSK for tenant B");

    psk_store_a
        .add_psk(psk_a)
        .expect("Failed to add PSK to tenant A");
    psk_store_b
        .add_psk(psk_b)
        .expect("Failed to add PSK to tenant B");

    // Verify PSKs are isolated
    assert_eq!(psk_store_a.psk_count(), 1);
    assert_eq!(psk_store_b.psk_count(), 1);

    // Create shared session manager
    let session_manager = TenantSessionManager::new();

    // Create sessions for each tenant
    let session_a1 = session_manager
        .create_session(tenant_a)
        .expect("Failed to create session for tenant A");
    let session_a2 = session_manager
        .create_session(tenant_a)
        .expect("Failed to create second session for tenant A");

    let session_b1 = session_manager
        .create_session(tenant_b)
        .expect("Failed to create session for tenant B");
    let session_b2 = session_manager
        .create_session(tenant_b)
        .expect("Failed to create second session for tenant B");

    // Verify sessions are created
    assert_eq!(session_a1.tenant_id(), tenant_a);
    assert_eq!(session_a2.tenant_id(), tenant_a);
    assert_eq!(session_b1.tenant_id(), tenant_b);
    assert_eq!(session_b2.tenant_id(), tenant_b);

    // Verify session counts per tenant
    assert_eq!(session_manager.tenant_session_count(tenant_a), 2);
    assert_eq!(session_manager.tenant_session_count(tenant_b), 2);
    assert_eq!(session_manager.total_session_count(), 4);

    // Verify session IDs are unique within each tenant
    assert_ne!(session_a1.session_id(), session_a2.session_id());
    assert_ne!(session_b1.session_id(), session_b2.session_id());

    // Verify session isolation - lookup by session ID returns correct tenant
    let routing_entry_a1 = session_manager
        .lookup_session(tenant_a, session_a1.session_id())
        .expect("Session A1 not found");
    assert_eq!(
        routing_entry_a1.tenant_session_id.tenant_id(),
        session_a1.tenant_id()
    );

    let routing_entry_b1 = session_manager
        .lookup_session(tenant_b, session_b1.session_id())
        .expect("Session B1 not found");
    assert_eq!(
        routing_entry_b1.tenant_session_id.tenant_id(),
        session_b1.tenant_id()
    );

    // Test cross-tenant access prevention
    let security_enforcer = CrossTenantSecurityEnforcer::new();

    // Tenant A trying to access session A1 (should succeed)
    let result = security_enforcer.validate_tenant_session(
        tenant_a,
        session_a1.session_id(),
        &routing_entry_a1,
    );
    assert!(result.is_ok(), "Tenant A should access its own session");

    // Tenant B trying to access session A1 (should fail)
    let result = security_enforcer.validate_tenant_session(
        tenant_b,
        session_a1.session_id(),
        &routing_entry_a1,
    );
    assert!(
        result.is_err(),
        "Tenant B should not access tenant A session"
    );

    // Tenant A trying to access session B1 (should fail)
    let result = security_enforcer.validate_tenant_session(
        tenant_a,
        session_b1.session_id(),
        &routing_entry_b1,
    );
    assert!(
        result.is_err(),
        "Tenant A should not access tenant B session"
    );

    // Tenant B trying to access session B1 (should succeed)
    let result = security_enforcer.validate_tenant_session(
        tenant_b,
        session_b1.session_id(),
        &routing_entry_b1,
    );
    assert!(result.is_ok(), "Tenant B should access its own session");

    // Test port allocation differs by tenant
    let port_manager = PortAllocationManager::new().expect("Failed to create port manager");

    let time_window = 1000;
    let port_hop_seed = 123;

    let port_a1 = port_manager.calculate_port(
        tenant_a,
        session_a1.session_id(),
        time_window,
        port_hop_seed,
    );
    let port_b1 = port_manager.calculate_port(
        tenant_b,
        session_b1.session_id(),
        time_window,
        port_hop_seed,
    );

    // Different tenants should (probabilistically) get different ports
    assert_ne!(
        port_a1, port_b1,
        "Tenants should use different ports for same session/time"
    );

    // Same tenant, same session, same time should get same port
    let port_a1_repeat = port_manager.calculate_port(
        tenant_a,
        session_a1.session_id(),
        time_window,
        port_hop_seed,
    );
    assert_eq!(
        port_a1, port_a1_repeat,
        "Port calculation should be deterministic"
    );

    // Different sessions for same tenant should get different ports
    let port_a2 = port_manager.calculate_port(
        tenant_a,
        session_a2.session_id(),
        time_window,
        port_hop_seed,
    );
    assert_ne!(
        port_a1, port_a2,
        "Different sessions should use different ports"
    );

    // Verify all ports are in valid range (>= 1024)
    assert!(port_a1.as_u16() >= 1024);
    assert!(port_a2.as_u16() >= 1024);
    assert!(port_b1.as_u16() >= 1024);

    // Cleanup: remove sessions
    session_manager.remove_session(tenant_a, session_a1.session_id());
    session_manager.remove_session(tenant_a, session_a2.session_id());
    session_manager.remove_session(tenant_b, session_b1.session_id());
    session_manager.remove_session(tenant_b, session_b2.session_id());

    assert_eq!(session_manager.total_session_count(), 0);
}

#[test]
fn test_port_allocation_distribution() {
    // Test that ports are well-distributed across tenants
    let port_manager = PortAllocationManager::new().expect("Failed to create port manager");
    let session_id = SessionId::new(42);
    let time_window = 1000;
    let port_hop_seed = 123;

    let mut ports = std::collections::HashSet::new();

    // Generate ports for 100 different tenants
    for tenant_num in 0..100 {
        let tenant_id = TenantId::from_u64(tenant_num);
        let port = port_manager.calculate_port(tenant_id, &session_id, time_window, port_hop_seed);
        ports.insert(port.as_u16());
    }

    // Should have good distribution (at least 90% unique)
    assert!(
        ports.len() >= 90,
        "Port distribution should be high: got {} unique ports out of 100",
        ports.len()
    );
}

#[test]
fn test_security_audit_logging() {
    let security_enforcer = CrossTenantSecurityEnforcer::new();
    let tenant_id = TenantId::from_u64(1);
    let source_ip = "192.168.1.1".parse().expect("Invalid IP");

    // Record several auth failures
    for _ in 0..3 {
        security_enforcer
            .record_auth_failure(tenant_id, source_ip)
            .expect("Failed to record auth failure");
    }

    // Verify events are logged
    let events = security_enforcer.get_recent_events(tenant_id, 10);
    assert_eq!(events.len(), 3);

    for event in &events {
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(
            event.event_type,
            buckwild_common::tenant::SecurityEventType::AuthenticationFailure
        );
        assert_eq!(event.source_ip, source_ip);
    }
}

#[test]
fn test_session_manager_list_operations() {
    let session_manager = TenantSessionManager::new();
    let tenant_a = TenantId::from_u64(1);
    let tenant_b = TenantId::from_u64(2);

    // Create multiple sessions for each tenant
    let mut sessions_a = Vec::new();
    for _ in 0..5 {
        sessions_a.push(
            session_manager
                .create_session(tenant_a)
                .expect("Failed to create session"),
        );
    }

    let mut sessions_b = Vec::new();
    for _ in 0..3 {
        sessions_b.push(
            session_manager
                .create_session(tenant_b)
                .expect("Failed to create session"),
        );
    }

    // List sessions for each tenant
    let listed_a = session_manager.list_tenant_sessions(tenant_a);
    let listed_b = session_manager.list_tenant_sessions(tenant_b);

    assert_eq!(listed_a.len(), 5);
    assert_eq!(listed_b.len(), 3);

    // Verify all created sessions are in the list
    for session in &sessions_a {
        assert!(listed_a.contains(session.session_id()));
    }

    for session in &sessions_b {
        assert!(listed_b.contains(session.session_id()));
    }

    // Verify cross-tenant isolation: looking up a session from tenant A with tenant B should fail.
    // Note: Session IDs are scoped per-tenant (each tenant starts from 0), so raw session IDs
    // may overlap. The isolation is at the (tenant_id, session_id) compound key level.
    for session in &sessions_a {
        // Lookup using tenant B for a session ID belonging to tenant A should fail
        let lookup_result = session_manager.lookup_session(tenant_b, session.session_id());
        // If lookup_result is Some, verify it's actually a different session (from tenant B, not A)
        if let Some(entry) = lookup_result {
            assert_eq!(
                entry.tenant_session_id.tenant_id(),
                tenant_b,
                "Cross-tenant lookup returned wrong tenant"
            );
        }
    }
}

#[test]
fn test_shared_port_strategy_consistency() {
    let strategy = SharedPortStrategy::full_range().expect("Failed to create shared port strategy");

    let tenant_id = TenantId::from_u64(1);
    let session_id = SessionId::new(42);

    // Same parameters should always produce same port
    let port1 = strategy.calculate_port(tenant_id, &session_id, 1000, 123);
    let port2 = strategy.calculate_port(tenant_id, &session_id, 1000, 123);
    let port3 = strategy.calculate_port(tenant_id, &session_id, 1000, 123);

    assert_eq!(port1, port2);
    assert_eq!(port2, port3);
}
