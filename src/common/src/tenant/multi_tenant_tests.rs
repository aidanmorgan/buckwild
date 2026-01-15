//! Multi-tenant isolation tests for MED-007 audit remediation
//!
//! This module contains comprehensive tests for:
//! - Tenant data isolation (cross-tenant access prevention)
//! - Quota enforcement per tenant
//! - Authentication boundary enforcement
//! - Concurrent tenant operations
//!
//! These tests validate that the multi-tenant architecture maintains
//! strong isolation boundaries between tenants for security and reliability.

use super::psk_store::{PskStoreError, TenantPsk, TenantPskStore};
use super::security::{CrossTenantSecurityEnforcer, SecurityError, SecurityEventType};
use super::session_manager::{SessionState, TenantSessionId, TenantSessionManager};
use super::tenant_id::TenantId;
use crate::protocol::types::SessionId;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;

// ============================================================================
// TENANT DATA ISOLATION TESTS (2 scenarios)
// ============================================================================

/// Test 1: Tenant A PSK data cannot be accessed by Tenant B
#[test]
fn test_cross_tenant_psk_isolation() {
    let tenant_a = TenantId::from_u64(1000);
    let tenant_b = TenantId::from_u64(2000);

    let store_a = TenantPskStore::new(tenant_a);
    let store_b = TenantPskStore::new(tenant_b);

    // Tenant A adds PSKs
    let psk_a1 = TenantPsk::new("psk-a-1".to_string(), &[0x11; 32], tenant_a).unwrap();
    let psk_a2 = TenantPsk::new("psk-a-2".to_string(), &[0x22; 32], tenant_a).unwrap();
    store_a.add_psk(psk_a1).unwrap();
    store_a.add_psk(psk_a2).unwrap();

    // Tenant B adds different PSKs
    let psk_b1 = TenantPsk::new("psk-b-1".to_string(), &[0x33; 32], tenant_b).unwrap();
    store_b.add_psk(psk_b1).unwrap();

    // Verify Tenant A has 2 PSKs
    assert_eq!(store_a.psk_count(), 2);
    assert_eq!(store_b.psk_count(), 1);

    // Verify Tenant A's PSK IDs
    let ids_a = store_a.list_psk_ids();
    assert!(ids_a.contains(&"psk-a-1".to_string()));
    assert!(ids_a.contains(&"psk-a-2".to_string()));
    assert!(!ids_a.contains(&"psk-b-1".to_string()));

    // Verify Tenant B's PSK IDs
    let ids_b = store_b.list_psk_ids();
    assert!(ids_b.contains(&"psk-b-1".to_string()));
    assert!(!ids_b.contains(&"psk-a-1".to_string()));
    assert!(!ids_b.contains(&"psk-a-2".to_string()));

    // Attempt to add Tenant B's PSK to Tenant A's store should fail
    let psk_b_wrong = TenantPsk::new("psk-b-2".to_string(), &[0x44; 32], tenant_b).unwrap();
    let result = store_a.add_psk(psk_b_wrong);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PskStoreError::InvalidPsk(_)));
}

/// Test 2: Tenant session isolation - sessions belong to specific tenants
#[test]
fn test_cross_tenant_session_isolation() {
    let manager = TenantSessionManager::new();
    let tenant_a = TenantId::from_u64(3000);
    let tenant_b = TenantId::from_u64(4000);

    // Create sessions for each tenant
    let session_a1 = manager.create_session(tenant_a).unwrap();
    let session_a2 = manager.create_session(tenant_a).unwrap();
    let session_b1 = manager.create_session(tenant_b).unwrap();

    // Verify tenant A has 2 sessions
    assert_eq!(manager.tenant_session_count(tenant_a), 2);
    assert_eq!(manager.tenant_session_count(tenant_b), 1);

    // List sessions for each tenant
    let sessions_a = manager.list_tenant_sessions(tenant_a);
    let sessions_b = manager.list_tenant_sessions(tenant_b);

    assert_eq!(sessions_a.len(), 2);
    assert_eq!(sessions_b.len(), 1);

    // Verify Tenant A's sessions are in Tenant A's list
    assert!(sessions_a.contains(&session_a1.session_id));
    assert!(sessions_a.contains(&session_a2.session_id));

    // Verify Tenant A can lookup its own sessions and they belong to Tenant A
    let lookup_a1 = manager.lookup_session(tenant_a, &session_a1.session_id);
    assert!(lookup_a1.is_some());
    assert_eq!(lookup_a1.unwrap().tenant_session_id.tenant_id(), tenant_a);

    // Verify Tenant B can lookup its own session and it belongs to Tenant B
    let lookup_b1 = manager.lookup_session(tenant_b, &session_b1.session_id);
    assert!(lookup_b1.is_some());
    assert_eq!(lookup_b1.unwrap().tenant_session_id.tenant_id(), tenant_b);

    // Cross-tenant isolation: even if session IDs happen to be the same numeric value,
    // the lookup is scoped by (tenant_id, session_id) tuple, so lookups are isolated.
    // If we try to lookup with wrong tenant ID, we either get None or a different session.
    if let Some(lookup_result) = manager.lookup_session(tenant_b, &session_a1.session_id) {
        // If a session is found, it must belong to Tenant B, not Tenant A
        assert_eq!(
            lookup_result.tenant_session_id.tenant_id(),
            tenant_b,
            "Lookup with tenant B should only return Tenant B's sessions"
        );
    }

    // Verify that Tenant A cannot access Tenant B's session metadata
    // We extract the tenant_id from the lookup result and drop the borrow immediately
    let lookup_tenant_id = manager
        .lookup_session(tenant_a, &session_b1.session_id)
        .map(|lookup_result| lookup_result.tenant_session_id.tenant_id());
    if let Some(found_tenant_id) = lookup_tenant_id {
        // If a session is found, it must belong to Tenant A, not Tenant B
        assert_eq!(
            found_tenant_id, tenant_a,
            "Lookup with tenant A should only return Tenant A's sessions"
        );
    }
}

// ============================================================================
// QUOTA ENFORCEMENT TESTS (2 scenarios)
// ============================================================================

/// Test 3: PSK quota enforcement - cannot exceed MAX_PSKS_PER_TENANT
#[test]
fn test_psk_quota_enforcement() {
    let tenant_id = TenantId::from_u64(5000);
    let store = TenantPskStore::new(tenant_id);

    // Add PSKs up to the limit (256)
    for i in 0..TenantPskStore::MAX_PSKS_PER_TENANT {
        let psk = TenantPsk::new(format!("psk-{}", i), &[i as u8; 32], tenant_id).unwrap();
        let result = store.add_psk(psk);
        assert!(
            result.is_ok(),
            "Failed to add PSK {} of {}",
            i,
            TenantPskStore::MAX_PSKS_PER_TENANT
        );
    }

    // Verify we're at the limit
    assert_eq!(store.psk_count(), TenantPskStore::MAX_PSKS_PER_TENANT);

    // Attempt to add one more PSK should fail
    let overflow_psk = TenantPsk::new("overflow".to_string(), &[0xFF; 32], tenant_id).unwrap();
    let result = store.add_psk(overflow_psk);

    assert!(result.is_err());
    match result.unwrap_err() {
        PskStoreError::MaxPsksExceeded {
            tenant_id: t,
            limit,
        } => {
            assert_eq!(t, tenant_id);
            assert_eq!(limit, TenantPskStore::MAX_PSKS_PER_TENANT);
        }
        _ => panic!("Expected MaxPsksExceeded error"),
    }

    // Verify count hasn't changed
    assert_eq!(store.psk_count(), TenantPskStore::MAX_PSKS_PER_TENANT);
}

/// Test 4: Quota enforcement is per-tenant (Tenant B quota independent of Tenant A)
#[test]
fn test_quota_enforcement_per_tenant_independence() {
    let tenant_a = TenantId::from_u64(6000);
    let tenant_b = TenantId::from_u64(7000);

    let store_a = TenantPskStore::new(tenant_a);
    let store_b = TenantPskStore::new(tenant_b);

    // Fill Tenant A to capacity
    for i in 0..TenantPskStore::MAX_PSKS_PER_TENANT {
        let psk = TenantPsk::new(format!("psk-a-{}", i), &[i as u8; 32], tenant_a).unwrap();
        store_a.add_psk(psk).unwrap();
    }

    // Tenant A is at capacity
    assert_eq!(store_a.psk_count(), TenantPskStore::MAX_PSKS_PER_TENANT);

    // Tenant B should still be able to add PSKs (independent quota)
    let psk_b1 = TenantPsk::new("psk-b-1".to_string(), &[0xBB; 32], tenant_b).unwrap();
    let psk_b2 = TenantPsk::new("psk-b-2".to_string(), &[0xCC; 32], tenant_b).unwrap();

    assert!(store_b.add_psk(psk_b1).is_ok());
    assert!(store_b.add_psk(psk_b2).is_ok());
    assert_eq!(store_b.psk_count(), 2);

    // Tenant A should still be at capacity and unable to add more
    let psk_a_overflow =
        TenantPsk::new("psk-a-overflow".to_string(), &[0xAA; 32], tenant_a).unwrap();
    assert!(store_a.add_psk(psk_a_overflow).is_err());
}

// ============================================================================
// AUTHENTICATION BOUNDARY ENFORCEMENT TESTS (2 scenarios)
// ============================================================================

/// Test 5: Cross-tenant authentication attempt detection
#[test]
fn test_cross_tenant_authentication_boundary() {
    let enforcer = CrossTenantSecurityEnforcer::new();
    let tenant_claimed = TenantId::from_u64(8000);
    let tenant_actual = TenantId::from_u64(9000);
    let session_id = SessionId::new(123);

    // Create routing entry belonging to tenant_actual
    let routing_entry = super::session_manager::SessionRoutingEntry {
        tenant_session_id: TenantSessionId::new(tenant_actual, session_id.clone()),
        last_packet_ns: 0,
        state: SessionState::Active,
    };

    // Attempt to validate with different tenant ID should fail
    let result = enforcer.validate_tenant_session(tenant_claimed, &session_id, &routing_entry);

    assert!(result.is_err());
    match result.unwrap_err() {
        SecurityError::CrossTenantAccessAttempt {
            claimed_tenant_id,
            actual_tenant_id,
        } => {
            assert_eq!(claimed_tenant_id, tenant_claimed);
            assert_eq!(actual_tenant_id, tenant_actual);
        }
        _ => panic!("Expected CrossTenantAccessAttempt error"),
    }

    // Verify security event was logged
    let events = enforcer.get_recent_events(tenant_claimed, 10);
    assert!(!events.is_empty());
    assert_eq!(
        events[0].event_type,
        SecurityEventType::CrossTenantAccessAttempt
    );
}

/// Test 6: Authentication failure tracking is per-tenant
#[test]
fn test_authentication_boundary_per_tenant_tracking() {
    let enforcer = CrossTenantSecurityEnforcer::new();
    let tenant_a = TenantId::from_u64(10000);
    let tenant_b = TenantId::from_u64(11000);
    let source_ip: IpAddr = "192.168.100.50".parse().unwrap();

    // Record 3 failures for Tenant A
    for _ in 0..3 {
        enforcer.record_auth_failure(tenant_a, source_ip).unwrap();
    }

    // Tenant B should have independent failure tracking
    for _ in 0..2 {
        enforcer.record_auth_failure(tenant_b, source_ip).unwrap();
    }

    // Neither should be blocked yet (limit is 5)
    assert!(!enforcer.is_blocked(tenant_a, source_ip));
    assert!(!enforcer.is_blocked(tenant_b, source_ip));

    // Push Tenant A to the limit (2 more failures = 5 total)
    enforcer.record_auth_failure(tenant_a, source_ip).unwrap();
    let result = enforcer.record_auth_failure(tenant_a, source_ip);

    // Tenant A should now be blocked
    assert!(result.is_err());
    assert!(enforcer.is_blocked(tenant_a, source_ip));

    // Tenant B should still NOT be blocked (only 2 failures)
    assert!(!enforcer.is_blocked(tenant_b, source_ip));
}

// ============================================================================
// CONCURRENT TENANT OPERATIONS TESTS (2 scenarios)
// ============================================================================

/// Test 7: Concurrent PSK operations across multiple tenants
#[test]
fn test_concurrent_psk_operations_multi_tenant() {
    let tenant_a = TenantId::from_u64(12000);
    let tenant_b = TenantId::from_u64(13000);
    let tenant_c = TenantId::from_u64(14000);

    let store_a = Arc::new(TenantPskStore::new(tenant_a));
    let store_b = Arc::new(TenantPskStore::new(tenant_b));
    let store_c = Arc::new(TenantPskStore::new(tenant_c));

    let mut handles = vec![];

    // Spawn thread for Tenant A - add 100 PSKs
    let store_a_clone = Arc::clone(&store_a);
    let handle_a = thread::spawn(move || {
        for i in 0..100 {
            let psk = TenantPsk::new(format!("tenant-a-psk-{}", i), &[0xAA; 32], tenant_a).unwrap();
            store_a_clone.add_psk(psk).unwrap();
        }
    });
    handles.push(handle_a);

    // Spawn thread for Tenant B - add 100 PSKs
    let store_b_clone = Arc::clone(&store_b);
    let handle_b = thread::spawn(move || {
        for i in 0..100 {
            let psk = TenantPsk::new(format!("tenant-b-psk-{}", i), &[0xBB; 32], tenant_b).unwrap();
            store_b_clone.add_psk(psk).unwrap();
        }
    });
    handles.push(handle_b);

    // Spawn thread for Tenant C - add 100 PSKs
    let store_c_clone = Arc::clone(&store_c);
    let handle_c = thread::spawn(move || {
        for i in 0..100 {
            let psk = TenantPsk::new(format!("tenant-c-psk-{}", i), &[0xCC; 32], tenant_c).unwrap();
            store_c_clone.add_psk(psk).unwrap();
        }
    });
    handles.push(handle_c);

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify each tenant has exactly 100 PSKs
    assert_eq!(store_a.psk_count(), 100);
    assert_eq!(store_b.psk_count(), 100);
    assert_eq!(store_c.psk_count(), 100);

    // Verify PSK IDs are tenant-specific
    let ids_a = store_a.list_psk_ids();
    let ids_b = store_b.list_psk_ids();
    let ids_c = store_c.list_psk_ids();

    assert!(ids_a.iter().all(|id| id.starts_with("tenant-a-")));
    assert!(ids_b.iter().all(|id| id.starts_with("tenant-b-")));
    assert!(ids_c.iter().all(|id| id.starts_with("tenant-c-")));
}

/// Test 8: Concurrent session creation across multiple tenants
#[test]
fn test_concurrent_session_operations_multi_tenant() {
    let manager = Arc::new(TenantSessionManager::new());
    let tenant_a = TenantId::from_u64(15000);
    let tenant_b = TenantId::from_u64(16000);

    let mut handles = vec![];

    // Spawn 5 threads for Tenant A - each creates 20 sessions
    for _ in 0..5 {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let mut session_ids = vec![];
            for _ in 0..20 {
                let ts_id = manager_clone.create_session(tenant_a).unwrap();
                session_ids.push(ts_id.session_id);
            }
            session_ids
        });
        handles.push(handle);
    }

    // Spawn 5 threads for Tenant B - each creates 20 sessions
    for _ in 0..5 {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let mut session_ids = vec![];
            for _ in 0..20 {
                let ts_id = manager_clone.create_session(tenant_b).unwrap();
                session_ids.push(ts_id.session_id);
            }
            session_ids
        });
        handles.push(handle);
    }

    // Collect all session IDs
    let mut all_session_ids_a = HashSet::new();
    let mut all_session_ids_b = HashSet::new();

    for (idx, handle) in handles.into_iter().enumerate() {
        let session_ids = handle.join().unwrap();
        if idx < 5 {
            for sid in session_ids {
                all_session_ids_a.insert(sid);
            }
        } else {
            for sid in session_ids {
                all_session_ids_b.insert(sid);
            }
        }
    }

    // Verify Tenant A has 100 unique sessions (5 threads * 20 sessions)
    assert_eq!(manager.tenant_session_count(tenant_a), 100);
    assert_eq!(all_session_ids_a.len(), 100);

    // Verify Tenant B has 100 unique sessions
    assert_eq!(manager.tenant_session_count(tenant_b), 100);
    assert_eq!(all_session_ids_b.len(), 100);

    // Verify no overlap between tenant session IDs
    assert_eq!(manager.total_session_count(), 200);

    // Verify each tenant can only see their own sessions
    let sessions_a = manager.list_tenant_sessions(tenant_a);
    let sessions_b = manager.list_tenant_sessions(tenant_b);

    assert_eq!(sessions_a.len(), 100);
    assert_eq!(sessions_b.len(), 100);

    // Verify cross-tenant lookup isolation: lookups are scoped by (tenant_id, session_id)
    // If Tenant B looks up using a session ID from Tenant A, it either gets None,
    // or it gets its own session (if it happens to have a session with the same numeric ID).
    for sid in &sessions_a {
        if let Some(lookup_from_b) = manager.lookup_session(tenant_b, sid) {
            // If a session is found, it MUST belong to Tenant B, not Tenant A
            assert_eq!(
                lookup_from_b.tenant_session_id.tenant_id(),
                tenant_b,
                "Lookup with tenant B should only return Tenant B's sessions"
            );
        }
    }

    // Similarly for Tenant A trying to lookup Tenant B's sessions
    for sid in &sessions_b {
        if let Some(lookup_from_a) = manager.lookup_session(tenant_a, sid) {
            // If a session is found, it MUST belong to Tenant A, not Tenant B
            assert_eq!(
                lookup_from_a.tenant_session_id.tenant_id(),
                tenant_a,
                "Lookup with tenant A should only return Tenant A's sessions"
            );
        }
    }
}
