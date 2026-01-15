// Zero Window and Persist Timer Tests
// Tests for flow control edge cases as defined in design/protocol/07-data-transmission.md

use std::time::{Duration, Instant};

/// Zero window probe configuration
const PERSIST_TIMER_INITIAL_MS: u64 = 1000;
const PERSIST_TIMER_MAX_MS: u64 = 60000;
const ZERO_WINDOW_PROBE_SIZE: usize = 1;
const SILLY_WINDOW_THRESHOLD: usize = 512;

/// Flow control state for zero window testing
struct FlowControlState {
    send_window: usize,
    receive_window: usize,
    advertised_window: usize,
    persist_timer_value: Duration,
    last_window_update: Instant,
    zero_window_probes_sent: u32,
    silly_window_syndrome_active: bool,
}

impl FlowControlState {
    fn new(initial_window: usize) -> Self {
        Self {
            send_window: initial_window,
            receive_window: initial_window,
            advertised_window: initial_window,
            persist_timer_value: Duration::from_millis(PERSIST_TIMER_INITIAL_MS),
            last_window_update: Instant::now(),
            zero_window_probes_sent: 0,
            silly_window_syndrome_active: false,
        }
    }

    /// Update advertised window from peer
    fn update_advertised_window(&mut self, new_window: usize) {
        self.advertised_window = new_window;
        self.send_window = new_window;
        self.last_window_update = Instant::now();

        // Reset persist timer on window update
        if new_window > 0 {
            self.persist_timer_value = Duration::from_millis(PERSIST_TIMER_INITIAL_MS);
            self.zero_window_probes_sent = 0;
        }
    }

    /// Check if zero window condition exists
    fn is_zero_window(&self) -> bool {
        self.advertised_window == 0
    }

    /// Send zero window probe
    fn send_zero_window_probe(&mut self) -> Vec<u8> {
        self.zero_window_probes_sent += 1;

        // Exponential backoff for persist timer
        self.persist_timer_value = std::cmp::min(
            self.persist_timer_value * 2,
            Duration::from_millis(PERSIST_TIMER_MAX_MS),
        );

        // Return 1-byte probe data
        vec![0u8; ZERO_WINDOW_PROBE_SIZE]
    }

    /// Check if persist timer has expired
    fn persist_timer_expired(&self) -> bool {
        self.last_window_update.elapsed() >= self.persist_timer_value
    }

    /// Check for silly window syndrome
    fn check_silly_window_syndrome(&mut self, available_window: usize, data_size: usize) -> bool {
        // Sender-side silly window syndrome avoidance
        // Don't send if:
        // 1. Available window is less than MSS, AND
        // 2. Can't send a full-sized segment, AND
        // 3. No urgent data

        if available_window < SILLY_WINDOW_THRESHOLD && data_size < SILLY_WINDOW_THRESHOLD {
            self.silly_window_syndrome_active = true;
            return true;
        }

        self.silly_window_syndrome_active = false;
        false
    }

    /// Receiver-side silly window syndrome avoidance
    fn should_advertise_window_update(&self, newly_freed_space: usize, max_segment_size: usize) -> bool {
        // Only advertise window update if:
        // 1. Can advertise at least one MSS, OR
        // 2. Can advertise at least 50% of the maximum receive buffer

        let half_buffer = self.receive_window / 2;
        newly_freed_space >= max_segment_size || newly_freed_space >= half_buffer
    }

    /// Get current persist timer value
    fn get_persist_timer_value(&self) -> Duration {
        self.persist_timer_value
    }

    /// Get zero window probe count
    fn get_zero_window_probe_count(&self) -> u32 {
        self.zero_window_probes_sent
    }
}

#[test]
fn test_zero_window_probe_sent() {
    let mut fc = FlowControlState::new(65536);

    // Simulate peer advertising zero window
    fc.update_advertised_window(0);
    assert!(fc.is_zero_window());

    // Send zero window probe
    let probe = fc.send_zero_window_probe();
    assert_eq!(probe.len(), ZERO_WINDOW_PROBE_SIZE);
    assert_eq!(fc.get_zero_window_probe_count(), 1);
}

#[test]
fn test_persist_timer_expiration() {
    let mut fc = FlowControlState::new(65536);

    // Set zero window
    fc.update_advertised_window(0);

    // Initial persist timer value
    let initial_timer = fc.get_persist_timer_value();
    assert_eq!(initial_timer, Duration::from_millis(PERSIST_TIMER_INITIAL_MS));

    // Send probe (should double timer)
    fc.send_zero_window_probe();
    let doubled_timer = fc.get_persist_timer_value();
    assert_eq!(doubled_timer, Duration::from_millis(PERSIST_TIMER_INITIAL_MS * 2));
}

#[test]
fn test_persist_timer_exponential_backoff() {
    let mut fc = FlowControlState::new(65536);
    fc.update_advertised_window(0);

    let mut expected_timer = PERSIST_TIMER_INITIAL_MS;

    // Send multiple probes and verify exponential backoff
    for _ in 0..5 {
        fc.send_zero_window_probe();
        expected_timer = std::cmp::min(expected_timer * 2, PERSIST_TIMER_MAX_MS);
        assert_eq!(
            fc.get_persist_timer_value(),
            Duration::from_millis(expected_timer)
        );
    }

    // Verify timer doesn't exceed maximum
    assert!(fc.get_persist_timer_value() <= Duration::from_millis(PERSIST_TIMER_MAX_MS));
}

#[test]
fn test_persist_timer_max_value() {
    let mut fc = FlowControlState::new(65536);
    fc.update_advertised_window(0);

    // Send many probes
    for _ in 0..20 {
        fc.send_zero_window_probe();
    }

    // Timer should be capped at maximum
    assert_eq!(
        fc.get_persist_timer_value(),
        Duration::from_millis(PERSIST_TIMER_MAX_MS)
    );
}

#[test]
fn test_silly_window_syndrome_prevention() {
    let mut fc = FlowControlState::new(65536);

    // Small available window and small data size (silly window condition)
    let available_window = 256;
    let data_size = 256;

    let is_silly = fc.check_silly_window_syndrome(available_window, data_size);
    assert!(is_silly);
    assert!(fc.silly_window_syndrome_active);
}

#[test]
fn test_silly_window_syndrome_allowed_transmission() {
    let mut fc = FlowControlState::new(65536);

    // Large enough available window (no silly window)
    let available_window = 1460; // Full MSS
    let data_size = 1460;

    let is_silly = fc.check_silly_window_syndrome(available_window, data_size);
    assert!(!is_silly);
    assert!(!fc.silly_window_syndrome_active);
}

#[test]
fn test_window_update_after_zero_window() {
    let mut fc = FlowControlState::new(65536);

    // Set zero window
    fc.update_advertised_window(0);
    assert!(fc.is_zero_window());
    assert_eq!(fc.send_window, 0);

    // Send a probe
    fc.send_zero_window_probe();
    assert_eq!(fc.get_zero_window_probe_count(), 1);

    // Receive window update
    fc.update_advertised_window(8192);
    assert!(!fc.is_zero_window());
    assert_eq!(fc.send_window, 8192);

    // Persist timer should be reset
    assert_eq!(
        fc.get_persist_timer_value(),
        Duration::from_millis(PERSIST_TIMER_INITIAL_MS)
    );

    // Probe count should be reset
    assert_eq!(fc.get_zero_window_probe_count(), 0);
}

#[test]
fn test_zero_window_deadlock_prevention() {
    let mut fc = FlowControlState::new(65536);

    // Simulate deadlock scenario
    fc.update_advertised_window(0);

    // Send probes periodically to detect window updates
    for i in 1..=5 {
        fc.send_zero_window_probe();
        assert_eq!(fc.get_zero_window_probe_count(), i);
    }

    // Even after many probes, we keep probing (prevents deadlock)
    assert!(fc.is_zero_window());
    assert!(fc.get_zero_window_probe_count() > 0);

    // When window finally opens, we can resume
    fc.update_advertised_window(1024);
    assert!(!fc.is_zero_window());
}

#[test]
fn test_receiver_side_silly_window_avoidance() {
    let fc = FlowControlState::new(65536);
    let max_segment_size = 1460;

    // Small freed space (less than MSS and less than 50% of buffer)
    let small_freed = 512;
    assert!(!fc.should_advertise_window_update(small_freed, max_segment_size));

    // Freed space >= MSS
    let mss_freed = 1460;
    assert!(fc.should_advertise_window_update(mss_freed, max_segment_size));

    // Freed space >= 50% of buffer
    let half_buffer_freed = 65536 / 2;
    assert!(fc.should_advertise_window_update(half_buffer_freed, max_segment_size));
}

#[test]
fn test_zero_window_probe_sequence() {
    let mut fc = FlowControlState::new(65536);
    fc.update_advertised_window(0);

    // Simulate a sequence of probes
    let probe_sequence = vec![
        (1000, 1),  // 1s timer, probe 1
        (2000, 2),  // 2s timer, probe 2
        (4000, 3),  // 4s timer, probe 3
        (8000, 4),  // 8s timer, probe 4
        (16000, 5), // 16s timer, probe 5
    ];

    for (expected_timer_ms, expected_probe_count) in probe_sequence {
        fc.send_zero_window_probe();
        assert_eq!(fc.get_zero_window_probe_count(), expected_probe_count);
        assert_eq!(
            fc.get_persist_timer_value(),
            Duration::from_millis(expected_timer_ms)
        );
    }
}

#[test]
fn test_zero_window_multiple_cycles() {
    let mut fc = FlowControlState::new(65536);

    // First zero window cycle
    fc.update_advertised_window(0);
    fc.send_zero_window_probe();
    fc.send_zero_window_probe();
    assert_eq!(fc.get_zero_window_probe_count(), 2);

    // Window opens
    fc.update_advertised_window(4096);
    assert_eq!(fc.get_zero_window_probe_count(), 0);

    // Second zero window cycle
    fc.update_advertised_window(0);
    fc.send_zero_window_probe();
    assert_eq!(fc.get_zero_window_probe_count(), 1);

    // Timer should be reset to initial value
    assert_eq!(
        fc.get_persist_timer_value(),
        Duration::from_millis(PERSIST_TIMER_INITIAL_MS * 2)
    );
}

#[test]
fn test_silly_window_with_partial_mss() {
    let mut fc = FlowControlState::new(65536);

    // Available window is less than MSS but data is also small
    let scenarios = vec![
        (256, 200, true),   // Both small - silly window
        (256, 1460, true),  // Small window, large data - silly window
        (1460, 200, false), // Large window, small data - ok (can send)
        (1460, 1460, false), // Both large - ok
    ];

    for (available_window, data_size, expected_silly) in scenarios {
        let is_silly = fc.check_silly_window_syndrome(available_window, data_size);
        assert_eq!(
            is_silly, expected_silly,
            "Failed for window={}, data={}", available_window, data_size
        );
    }
}

#[test]
fn test_zero_window_probe_size_constraint() {
    let mut fc = FlowControlState::new(65536);
    fc.update_advertised_window(0);

    // Zero window probes must be exactly 1 byte
    let probe = fc.send_zero_window_probe();
    assert_eq!(probe.len(), ZERO_WINDOW_PROBE_SIZE);
    assert_eq!(ZERO_WINDOW_PROBE_SIZE, 1);
}

#[test]
fn test_window_update_during_silly_window_syndrome() {
    let mut fc = FlowControlState::new(65536);

    // Trigger silly window syndrome
    fc.check_silly_window_syndrome(256, 256);
    assert!(fc.silly_window_syndrome_active);

    // Receive window update that's large enough
    fc.update_advertised_window(8192);

    // Check that we can now send
    let is_silly = fc.check_silly_window_syndrome(8192, 1460);
    assert!(!is_silly);
    assert!(!fc.silly_window_syndrome_active);
}

#[test]
fn test_persist_timer_reset_on_any_window_update() {
    let mut fc = FlowControlState::new(65536);
    fc.update_advertised_window(0);

    // Send multiple probes
    for _ in 0..3 {
        fc.send_zero_window_probe();
    }

    let large_timer = fc.get_persist_timer_value();
    assert!(large_timer > Duration::from_millis(PERSIST_TIMER_INITIAL_MS));

    // Even small window update should reset timer
    fc.update_advertised_window(512);
    assert_eq!(
        fc.get_persist_timer_value(),
        Duration::from_millis(PERSIST_TIMER_INITIAL_MS)
    );
}
