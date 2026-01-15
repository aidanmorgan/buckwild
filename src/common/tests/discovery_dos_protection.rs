// Integration tests for discovery DoS protection
//
// Tests rate limiting, computational puzzles, and stale discovery cleanup.

use buckwild_common::engines::discovery::{
    DiscoveryEngine, DiscoveryPhase, DiscoveryRateLimiter, DiscoveryTimeoutManager,
    PuzzleChallenge, PuzzleDifficulty, PuzzleSolution, PuzzleSolver, RateLimitConfig,
    TimeoutConfig,
};
use buckwild_common::protocol::types::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn test_discovery_rate_limit_enforced() {
    let limiter = DiscoveryRateLimiter::new();
    let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // Should allow 5 requests (default config)
    for i in 0..5 {
        assert!(
            limiter.check_rate_limit(source_ip).is_ok(),
            "Request {} should be allowed",
            i + 1
        );
    }

    // 6th request should be blocked
    assert!(
        limiter.check_rate_limit(source_ip).is_err(),
        "Request 6 should be blocked"
    );
}

#[test]
fn test_discovery_rate_limit_per_ip() {
    let limiter = DiscoveryRateLimiter::new();
    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // Exhaust IP1 rate limit
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(ip1).is_ok());
    }
    assert!(limiter.check_rate_limit(ip1).is_err());

    // IP2 should still have its own quota
    assert!(limiter.check_rate_limit(ip2).is_ok());
}

#[test]
fn test_discovery_rate_limit_blocks_abusive_ip() {
    let config = RateLimitConfig {
        max_attempts_per_minute: 3,
        block_duration: Duration::from_millis(200),
        cleanup_interval: Duration::from_secs(60),
    };
    let limiter = DiscoveryRateLimiter::with_config(config);
    let source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Exhaust quota
    for _ in 0..3 {
        assert!(limiter.check_rate_limit(source_ip).is_ok());
    }

    // Next request triggers block
    assert!(limiter.check_rate_limit(source_ip).is_err());

    // IP should be blocked
    assert!(limiter.is_blocked(&source_ip));

    // Wait for block to expire
    std::thread::sleep(Duration::from_millis(250));

    // Should no longer be blocked
    assert!(!limiter.is_blocked(&source_ip));
}

#[test]
fn test_computational_puzzle_solve_and_verify() {
    let difficulty = PuzzleDifficulty::EASY;
    let session_salt = 12345u32;
    let solver = PuzzleSolver::new(difficulty);

    // Generate challenge
    let challenge =
        PuzzleChallenge::generate(difficulty, session_salt).expect("Failed to generate challenge");

    // Solve puzzle
    let solution = solver
        .solve(&challenge, 100000)
        .expect("Failed to solve puzzle");

    // Verify solution
    assert!(solver.verify(&challenge, &solution).is_ok());
}

#[test]
fn test_computational_puzzle_invalid_solution_rejected() {
    let difficulty = PuzzleDifficulty::EASY;
    let session_salt = 67890u32;
    let solver = PuzzleSolver::new(difficulty);

    let challenge =
        PuzzleChallenge::generate(difficulty, session_salt).expect("Failed to generate challenge");

    // Create invalid solution
    let invalid_solution = PuzzleSolution::new(999999, [0u8; 32]);

    // Should fail verification
    assert!(solver.verify(&challenge, &invalid_solution).is_err());
}

#[test]
fn test_puzzle_difficulty_levels() {
    // Easy should solve quickly
    let solver_easy = PuzzleSolver::new(PuzzleDifficulty::EASY);
    let challenge_easy =
        PuzzleChallenge::generate(PuzzleDifficulty::EASY, 11111).expect("Failed to generate");

    let start = std::time::Instant::now();
    let solution_easy = solver_easy
        .solve(&challenge_easy, 10000)
        .expect("Failed to solve easy puzzle");
    let elapsed_easy = start.elapsed();

    assert!(solver_easy.verify(&challenge_easy, &solution_easy).is_ok());

    // Medium should take more attempts
    let solver_medium = PuzzleSolver::new(PuzzleDifficulty::MEDIUM);
    let challenge_medium =
        PuzzleChallenge::generate(PuzzleDifficulty::MEDIUM, 22222).expect("Failed to generate");

    let start = std::time::Instant::now();
    let solution_medium = solver_medium
        .solve(&challenge_medium, 100000)
        .expect("Failed to solve medium puzzle");
    let elapsed_medium = start.elapsed();

    assert!(
        solver_medium
            .verify(&challenge_medium, &solution_medium)
            .is_ok()
    );

    // Medium should generally take longer (probabilistic, but very likely)
    println!("Easy: {:?}, Medium: {:?}", elapsed_easy, elapsed_medium);
}

#[test]
fn test_stale_discovery_timeout() {
    let config = TimeoutConfig {
        discovery_timeout: Duration::from_millis(100),
        max_retries: 3,
        cleanup_interval: Duration::from_secs(30),
    };
    let manager = DiscoveryTimeoutManager::with_config(config);

    let discovery_id = DiscoveryId::new(12345);
    manager.register_attempt(discovery_id);

    // Should not be timed out immediately
    assert!(!manager.is_timed_out(&discovery_id));

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(150));

    // Should now be timed out
    assert!(manager.is_timed_out(&discovery_id));
}

#[test]
fn test_stale_discovery_cleanup() {
    let config = TimeoutConfig {
        discovery_timeout: Duration::from_millis(50),
        max_retries: 3,
        cleanup_interval: Duration::from_secs(30),
    };
    let manager = DiscoveryTimeoutManager::with_config(config);

    // Register multiple discoveries
    for i in 0..10 {
        manager.register_attempt(DiscoveryId::new(i));
    }

    assert_eq!(manager.active_count(), 10);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(100));

    // Cleanup should remove all timed out attempts
    manager.cleanup_expired();

    assert_eq!(manager.active_count(), 0);
}

#[test]
fn test_discovery_retry_limit() {
    let manager = DiscoveryTimeoutManager::new();
    let discovery_id = DiscoveryId::new(99999);

    manager.register_attempt(discovery_id);

    // Should allow retries up to max (3)
    assert!(manager.increment_retry(&discovery_id)); // retry 1
    assert!(manager.increment_retry(&discovery_id)); // retry 2
    assert!(!manager.increment_retry(&discovery_id)); // retry 3 - should fail

    assert_eq!(manager.get_retry_count(&discovery_id), Some(3));
}

#[test]
fn test_discovery_phase_tracking() {
    let manager = DiscoveryTimeoutManager::new();
    let discovery_id = DiscoveryId::new(55555);

    manager.register_attempt(discovery_id);

    // Initial phase
    assert_eq!(
        manager.get_phase(&discovery_id),
        Some(DiscoveryPhase::AwaitingResponse)
    );

    // Update to confirmation phase
    manager.update_phase(&discovery_id, DiscoveryPhase::AwaitingConfirmation);
    assert_eq!(
        manager.get_phase(&discovery_id),
        Some(DiscoveryPhase::AwaitingConfirmation)
    );

    // Mark completed
    manager.mark_completed(&discovery_id);
    assert_eq!(
        manager.get_phase(&discovery_id),
        Some(DiscoveryPhase::Completed)
    );
}

#[test]
fn test_integrated_dos_protection() {
    let engine = DiscoveryEngine::new(vec![]);
    let source_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

    // Rate limit should allow initial requests
    for i in 0..5 {
        assert!(
            engine.check_rate_limit(source_ip).is_ok(),
            "Request {} should be allowed",
            i + 1
        );
    }

    // 6th request should be blocked
    assert!(engine.check_rate_limit(source_ip).is_err());

    // Puzzle generation should work
    let challenge = engine
        .generate_puzzle_challenge(12345)
        .expect("Failed to generate puzzle");

    // Solve the puzzle
    let solver = PuzzleSolver::new(engine.puzzle_difficulty());
    let solution = solver
        .solve(&challenge, 100000)
        .expect("Failed to solve puzzle");

    // Verification should succeed
    assert!(engine.verify_puzzle_solution(&challenge, &solution).is_ok());

    // Timeout tracking should work
    let discovery_id = DiscoveryId::new(77777);
    engine.register_discovery_attempt(discovery_id);
    assert!(!engine.is_discovery_timed_out(&discovery_id));
}

#[test]
fn test_cleanup_integration() {
    let config_rate_limit = RateLimitConfig {
        max_attempts_per_minute: 5,
        block_duration: Duration::from_secs(1),
        cleanup_interval: Duration::from_millis(10),
    };

    let config_timeout = TimeoutConfig {
        discovery_timeout: Duration::from_millis(50),
        max_retries: 3,
        cleanup_interval: Duration::from_millis(10),
    };

    let engine = DiscoveryEngine::with_config(
        vec![],
        config_rate_limit,
        config_timeout,
        PuzzleDifficulty::EASY,
    );

    let source_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));

    // Create some rate limit entries
    for _ in 0..3 {
        let _ = engine.check_rate_limit(source_ip);
    }

    // Register discovery attempts
    for i in 0..5 {
        engine.register_discovery_attempt(DiscoveryId::new(i));
    }

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(100));

    // Cleanup should work
    engine.cleanup_stale_discoveries();
}
