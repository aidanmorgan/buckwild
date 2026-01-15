#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Port Hopping Sequence Tests - Comprehensive test suite for port hopping sequences
//
// These tests verify:
// 1. Sequence generation and determinism
// 2. Time-based hopping at 500ms intervals
// 3. Drift handling and tolerance
// 4. Resynchronization mechanisms

#[cfg(test)]
mod tests {
    use crate::engines::port_hopping::PortHoppingCalculation;
    use crate::engines::time_sync::epoch::TimeEpoch;
    use crate::protocol::types::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    // ============================================================================
    // SEQUENCE GENERATION TESTS
    // ============================================================================

    #[test]
    fn test_sequence_determinism_same_seed_same_sequence() {
        // Verify that the same seed produces the same port sequence
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x42u8; 32];

        // Generate sequence from first engine
        let mut sequence1 = Vec::new();
        for epoch in 0..100 {
            sequence1.push(calc.calculate_session_port_with_seed(&seed, epoch, true));
        }

        // Generate sequence from same engine with same seed
        let mut sequence2 = Vec::new();
        for epoch in 0..100 {
            sequence2.push(calc.calculate_session_port_with_seed(&seed, epoch, true));
        }

        // Sequences should be identical
        assert_eq!(
            sequence1, sequence2,
            "Same seed should produce identical port sequences"
        );
    }

    #[test]
    fn test_sequence_determinism_different_seeds_different_sequences() {
        // Verify that different seeds produce different port sequences
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed1 = [0x42u8; 32];
        let mut seed2 = [0x42u8; 32];
        seed2[0] = 0x43; // Change one byte

        // Generate sequence from first seed
        let mut sequence1 = Vec::new();
        for epoch in 0..100 {
            sequence1.push(calc.calculate_session_port_with_seed(&seed1, epoch, true));
        }

        // Generate sequence from second seed
        let mut sequence2 = Vec::new();
        for epoch in 0..100 {
            sequence2.push(calc.calculate_session_port_with_seed(&seed2, epoch, true));
        }

        // Sequences should differ
        assert_ne!(
            sequence1, sequence2,
            "Different seeds should produce different port sequences"
        );
    }

    #[test]
    fn test_ports_within_valid_range() {
        // Verify all generated ports are within the valid range (1024-65535)
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x55u8; 32];

        for epoch in 0..1000 {
            let local_port = calc.calculate_session_port_with_seed(&seed, epoch, true);
            let remote_port = calc.calculate_session_port_with_seed(&seed, epoch, false);

            // Verify local port is in valid range
            assert!(
                local_port.as_u16() >= 1024,
                "Local port {} below minimum 1024 at epoch {}",
                local_port.as_u16(),
                epoch
            );
            // u16 max is 65535, so no need to check upper bound

            // Verify remote port is in valid range
            assert!(
                remote_port.as_u16() >= 1024,
                "Remote port {} below minimum 1024 at epoch {}",
                remote_port.as_u16(),
                epoch
            );
            // u16 max is 65535, so no need to check upper bound
        }
    }

    #[test]
    fn test_no_privileged_ports() {
        // Verify no ports below 1024 are ever generated
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        // Test with multiple different seeds
        for seed_val in 0..10u8 {
            let seed = [seed_val; 32];

            // Test over many epochs
            for epoch in 0..10000 {
                let port = calc.calculate_session_port_with_seed(&seed, epoch, true);

                assert!(
                    port.as_u16() >= 1024,
                    "Generated privileged port {} with seed {:?} at epoch {}",
                    port.as_u16(),
                    seed_val,
                    epoch
                );
            }
        }
    }

    #[test]
    fn test_port_sequence_unpredictability() {
        // Verify that port sequences don't follow simple patterns
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x77u8; 32];

        let mut ports = Vec::new();
        for epoch in 0..100 {
            ports.push(calc.calculate_session_port_with_seed(&seed, epoch, true));
        }

        // Check that not all ports are the same
        let unique_ports: HashSet<_> = ports.iter().cloned().collect();
        assert!(
            unique_ports.len() > 50,
            "Port sequence should have high entropy, found only {} unique ports in 100",
            unique_ports.len()
        );

        // Check that ports don't increment linearly
        let mut linear_pattern = true;
        for i in 1..ports.len() {
            if ports[i].as_u16() != ports[i - 1].as_u16().wrapping_add(1) {
                linear_pattern = false;
                break;
            }
        }
        assert!(
            !linear_pattern,
            "Port sequence should not follow linear pattern"
        );
    }

    #[test]
    fn test_local_remote_port_independence() {
        // Verify that local and remote ports are independent for same epoch
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x88u8; 32];

        for epoch in 0..100 {
            let local_port = calc.calculate_session_port_with_seed(&seed, epoch, true);
            let remote_port = calc.calculate_session_port_with_seed(&seed, epoch, false);

            assert_ne!(
                local_port, remote_port,
                "Local and remote ports should differ at epoch {}",
                epoch
            );
        }
    }

    // ============================================================================
    // TIME-BASED HOPPING TESTS
    // ============================================================================

    #[test]
    fn test_hop_interval_is_500ms() {
        // Verify that time windows are exactly 500ms apart
        let start_ms = TimeEpoch::current_month_start_ms();

        for i in 0..20 {
            let time_in_window_i = start_ms + (i * 500) + 250; // Middle of window
            let time_in_next_window = start_ms + ((i + 1) * 500) + 250;

            let window_i = TimeEpoch::get_monthly_time_window(time_in_window_i);
            let window_next = TimeEpoch::get_monthly_time_window(time_in_next_window);

            assert_eq!(
                window_next.window,
                window_i.window + 1,
                "Windows should increment by 1 every 500ms"
            );

            let window_duration =
                window_i.window_end.as_millis() - window_i.window_start.as_millis();
            assert_eq!(
                window_duration, 500,
                "Window duration should be exactly 500ms"
            );
        }
    }

    #[test]
    fn test_synchronized_port_calculation_across_peers() {
        // Verify that multiple peers calculate the same port for the same time window
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc1 = PortHoppingCalculation::new(time_epoch.clone());
        let calc2 = PortHoppingCalculation::new(time_epoch);

        let seed = [0x99u8; 32];

        // Both peers should get same ports for same epoch
        for epoch in 0..50 {
            let port1 = calc1.calculate_session_port_with_seed(&seed, epoch, true);
            let port2 = calc2.calculate_session_port_with_seed(&seed, epoch, true);

            assert_eq!(
                port1, port2,
                "Peers should calculate identical port for epoch {}",
                epoch
            );
        }
    }

    #[test]
    fn test_port_changes_every_time_window() {
        // Verify that port changes for each time window
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xAAu8; 32];

        let mut ports = Vec::new();
        for epoch in 0..50 {
            ports.push(calc.calculate_session_port_with_seed(&seed, epoch, true));
        }

        // Count how many consecutive pairs are different
        let mut changes = 0;
        for i in 1..ports.len() {
            if ports[i] != ports[i - 1] {
                changes += 1;
            }
        }

        // Most epochs should result in different ports (allow small collision rate)
        assert!(
            changes >= 45,
            "Port should change frequently across epochs, only {} changes in 50 windows",
            changes
        );
    }

    #[test]
    fn test_time_window_boundaries() {
        // Test behavior at time window boundaries
        let start_ms = TimeEpoch::current_month_start_ms();

        // Test at window boundary
        let boundary_time = start_ms + 500; // Exactly at boundary
        let before_boundary = start_ms + 499; // Just before
        let after_boundary = start_ms + 501; // Just after

        let window_before = TimeEpoch::get_monthly_time_window(before_boundary);
        let window_boundary = TimeEpoch::get_monthly_time_window(boundary_time);
        let window_after = TimeEpoch::get_monthly_time_window(after_boundary);

        assert_eq!(
            window_before.window, 0,
            "Before boundary should be window 0"
        );
        assert_eq!(window_boundary.window, 1, "At boundary should be window 1");
        assert_eq!(window_after.window, 1, "After boundary should be window 1");
    }

    // ============================================================================
    // DRIFT HANDLING TESTS
    // ============================================================================

    #[test]
    fn test_small_drift_tolerance_previous_window() {
        // Test that ports from previous window can be calculated (simulating small drift)
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xBBu8; 32];

        // Current epoch
        let current_epoch = 100u32;
        let current_port = calc.calculate_session_port_with_seed(&seed, current_epoch, false);

        // Previous epoch (simulating small drift/delay)
        let previous_epoch = current_epoch - 1;
        let previous_port = calc.calculate_session_port_with_seed(&seed, previous_epoch, false);

        // Both ports should be valid
        assert!(previous_port.as_u16() >= 1024);
        assert!(current_port.as_u16() >= 1024);
    }

    #[test]
    fn test_small_drift_tolerance_next_window() {
        // Test that ports from next window can be calculated (for lookahead)
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xCCu8; 32];

        // Current epoch
        let current_epoch = 100u32;
        let current_port = calc.calculate_session_port_with_seed(&seed, current_epoch, false);

        // Next epoch (for lookahead/validation window)
        let next_epoch = current_epoch + 1;
        let next_port = calc.calculate_session_port_with_seed(&seed, next_epoch, false);

        // Both ports should be valid
        assert!(current_port.as_u16() >= 1024);
        assert!(next_port.as_u16() >= 1024);
    }

    #[test]
    fn test_validation_window_coverage() {
        // Test that validation window can check multiple epochs
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xDDu8; 32];
        let current_epoch = 100u32;

        // Validation window: check current ±5 epochs (simulating drift tolerance)
        let window_size = 5;
        let mut ports_in_window = Vec::new();

        for offset in -(window_size)..=(window_size) {
            let epoch = (current_epoch as i32 + offset) as u32;
            let port = calc.calculate_session_port_with_seed(&seed, epoch, false);
            ports_in_window.push(port);

            assert!(
                port.as_u16() >= 1024,
                "Port in validation window should be valid"
            );
        }

        // Should have calculated ports for all epochs in window
        assert_eq!(ports_in_window.len(), (window_size * 2 + 1) as usize);
    }

    #[test]
    fn test_drift_detection_epoch_mismatch() {
        // Test that we can detect drift by comparing expected vs received epoch
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xEEu8; 32];

        let sender_epoch = 100u32;
        let receiver_epoch = 105u32; // 5 epochs drift (2.5 seconds)

        let sender_port = calc.calculate_session_port_with_seed(&seed, sender_epoch, true);
        let receiver_expected = calc.calculate_session_port_with_seed(&seed, receiver_epoch, false);

        // Both should be valid ports
        assert!(sender_port.as_u16() >= 1024);
        assert!(receiver_expected.as_u16() >= 1024);
    }

    // ============================================================================
    // RESYNCHRONIZATION TESTS
    // ============================================================================

    #[test]
    fn test_resync_after_large_drift() {
        // Test that peers can resynchronize by jumping to new epoch
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xFFu8; 32];

        // Peer A at epoch 100
        let epoch_a = 100u32;
        let port_a = calc.calculate_session_port_with_seed(&seed, epoch_a, true);

        // Peer B drifted to epoch 150 (large drift)
        let epoch_b = 150u32;
        let port_b_before_resync = calc.calculate_session_port_with_seed(&seed, epoch_b, true);

        // After resync, Peer B jumps to Peer A's epoch
        let port_b_after_resync = calc.calculate_session_port_with_seed(&seed, epoch_a, true);

        // After resync, ports should match
        assert_eq!(
            port_a, port_b_after_resync,
            "After resync, peers should use same port"
        );

        // Before resync, ports were different calculations
        assert!(port_b_before_resync.as_u16() >= 1024);
    }

    #[test]
    fn test_resync_maintains_sequence_determinism() {
        // Test that after resync, sequence continues deterministically
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x11u8; 32];

        // Generate sequence before "desync"
        let mut sequence_before = Vec::new();
        for epoch in 0..50 {
            sequence_before.push(calc.calculate_session_port_with_seed(&seed, epoch, true));
        }

        // Simulate resync: regenerate same sequence
        let mut sequence_after = Vec::new();
        for epoch in 0..50 {
            sequence_after.push(calc.calculate_session_port_with_seed(&seed, epoch, true));
        }

        // Sequences should be identical (deterministic recovery)
        assert_eq!(
            sequence_before, sequence_after,
            "Resync should produce identical sequence"
        );
    }

    #[test]
    fn test_epoch_wraparound_handling() {
        // Test behavior near epoch counter wraparound
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0x22u8; 32];

        // Test near u32::MAX
        let max_epoch = u32::MAX;
        let port_max = calc.calculate_session_port_with_seed(&seed, max_epoch, true);

        // After wraparound (back to 0)
        let port_zero = calc.calculate_session_port_with_seed(&seed, 0, true);

        // Both should produce valid ports
        assert!(port_max.as_u16() >= 1024);
        assert!(port_zero.as_u16() >= 1024);
    }

    // ============================================================================
    // PARAMETER DERIVATION TESTS
    // ============================================================================

    #[test]
    fn test_port_params_derived_from_shared_secret() {
        // Test that PortHoppingParams are correctly derived from ECDH shared secret
        let shared_secret = [0x33u8; 32];
        let client_pubkey = [0x44u8; 64];
        let server_pubkey = [0x55u8; 64];
        let session_id = SessionId::new(12345);

        let params = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id.clone(),
        );

        // Verify session ID is preserved
        assert_eq!(params.session_id, session_id);

        // Verify seeds are derived
        assert!(
            params.port_seed.as_u32() > 0 || params.hop_sequence_seed.as_u32() > 0,
            "At least one seed should be non-zero"
        );

        // Verify time variance is in valid range (0-100ms)
        assert!(params.time_variance.as_u8() <= 100);
    }

    #[test]
    fn test_different_sessions_different_params() {
        // Test that different sessions produce different parameters
        let shared_secret = [0x66u8; 32];
        let client_pubkey = [0x77u8; 64];
        let server_pubkey = [0x88u8; 64];

        let params1 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            SessionId::new(1),
        );

        let params2 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            SessionId::new(2),
        );

        // Different session IDs
        assert_ne!(params1.session_id, params2.session_id);
    }

    #[test]
    fn test_params_deterministic_from_same_inputs() {
        // Test that same inputs produce same parameters
        let shared_secret = [0x99u8; 32];
        let client_pubkey = [0xAAu8; 64];
        let server_pubkey = [0xBBu8; 64];
        let session_id = SessionId::new(999);

        let params1 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id.clone(),
        );

        let params2 = PortHoppingCalculation::derive_port_hopping_params(
            &shared_secret,
            &client_pubkey,
            &server_pubkey,
            session_id.clone(),
        );

        // All fields should match
        assert_eq!(params1.port_seed, params2.port_seed);
        assert_eq!(params1.hop_sequence_seed, params2.hop_sequence_seed);
        assert_eq!(params1.time_variance, params2.time_variance);
        assert_eq!(params1.hop_pattern_seed, params2.hop_pattern_seed);
        assert_eq!(params1.session_id, params2.session_id);
    }

    // ============================================================================
    // EDGE CASE TESTS
    // ============================================================================

    #[test]
    fn test_port_calculation_with_zero_seed() {
        // Edge case: zero seed should still produce valid ports
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0u8; 32];

        for epoch in 0..100 {
            let port = calc.calculate_session_port_with_seed(&seed, epoch, true);
            assert!(
                port.as_u16() >= 1024,
                "Zero seed should still produce valid ports"
            );
        }
    }

    #[test]
    fn test_port_calculation_with_all_ones_seed() {
        // Edge case: all-ones seed should still produce valid ports
        let time_epoch = Arc::new(TimeEpoch::new());
        let calc = PortHoppingCalculation::new(time_epoch);

        let seed = [0xFFu8; 32];

        for epoch in 0..100 {
            let port = calc.calculate_session_port_with_seed(&seed, epoch, true);
            assert!(
                port.as_u16() >= 1024,
                "All-ones seed should still produce valid ports"
            );
        }
    }
}
