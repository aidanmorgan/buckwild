// Connection State Machine Tests
// Tests for state transitions as defined in design/protocol/06-connection-lifecycle.md

use std::sync::Arc;
use tokio::sync::RwLock;

// Connection states from design spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Closed = 0,
    Connecting = 1,
    Listening = 2,
    Established = 3,
    Closing = 4,
    Recovering = 5,
    Error = 6,
}

// Recovery sub-states from design spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverySubState {
    Normal = 0,
    Resync = 1,
    Rekey = 2,
    Repair = 3,
    Emergency = 4,
}

// Discovery sub-states from design spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoverySubState {
    Idle = 0,
    Request = 1,
    Response = 2,
    Confirm = 3,
    Completed = 4,
    Failed = 5,
}

/// Test state machine structure
struct TestStateMachine {
    state: Arc<RwLock<ConnectionState>>,
    sub_state: Arc<RwLock<RecoverySubState>>,
    discovery_state: Arc<RwLock<DiscoverySubState>>,
}

impl TestStateMachine {
    fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Closed)),
            sub_state: Arc::new(RwLock::new(RecoverySubState::Normal)),
            discovery_state: Arc::new(RwLock::new(DiscoverySubState::Idle)),
        }
    }

    async fn transition_to(&self, new_state: ConnectionState) -> Result<(), String> {
        let mut state = self.state.write().await;
        let current = *state;

        // Validate transition is legal
        if !self.is_valid_transition(current, new_state) {
            return Err(format!("Invalid transition from {:?} to {:?}", current, new_state));
        }

        *state = new_state;
        Ok(())
    }

    fn is_valid_transition(&self, from: ConnectionState, to: ConnectionState) -> bool {
        use ConnectionState::*;

        match (from, to) {
            // Closed can transition to Connecting or Listening
            (Closed, Connecting) => true,
            (Closed, Listening) => true,

            // Connecting can transition to Established or back to Closed (failed)
            (Connecting, Established) => true,
            (Connecting, Closed) => true,
            (Connecting, Error) => true,

            // Listening can transition to Established or Closed
            (Listening, Established) => true,
            (Listening, Closed) => true,

            // Established can transition to Closing, Recovering, or Error
            (Established, Closing) => true,
            (Established, Recovering) => true,
            (Established, Error) => true,

            // Recovering can transition to Established (success) or Error (failed)
            (Recovering, Established) => true,
            (Recovering, Error) => true,
            (Recovering, Closing) => true,

            // Closing transitions to Closed
            (Closing, Closed) => true,

            // Error transitions to Closed
            (Error, Closed) => true,

            // Allow staying in same state
            (s1, s2) if s1 == s2 => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    async fn transition_recovery_sub_state(&self, new_sub_state: RecoverySubState) -> Result<(), String> {
        let mut sub_state = self.sub_state.write().await;
        *sub_state = new_sub_state;
        Ok(())
    }

    async fn transition_discovery_sub_state(&self, new_discovery_state: DiscoverySubState) -> Result<(), String> {
        let mut discovery_state = self.discovery_state.write().await;
        *discovery_state = new_discovery_state;
        Ok(())
    }

    async fn get_state(&self) -> ConnectionState {
        *self.state.read().await
    }

    async fn get_sub_state(&self) -> RecoverySubState {
        *self.sub_state.read().await
    }

    async fn get_discovery_state(&self) -> DiscoverySubState {
        *self.discovery_state.read().await
    }
}

#[tokio::test]
async fn test_connection_state_closed_to_connecting() {
    let sm = TestStateMachine::new();

    // Initial state should be Closed
    assert_eq!(sm.get_state().await, ConnectionState::Closed);

    // Transition to Connecting (client initiating connection)
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Connecting);
}

#[tokio::test]
async fn test_connection_state_closed_to_listening() {
    let sm = TestStateMachine::new();

    // Transition to Listening (server waiting for connections)
    sm.transition_to(ConnectionState::Listening).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Listening);
}

#[tokio::test]
async fn test_connection_state_connecting_to_established() {
    let sm = TestStateMachine::new();

    // Closed -> Connecting -> Established
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Established);
}

#[tokio::test]
async fn test_connection_state_listening_to_established() {
    let sm = TestStateMachine::new();

    // Closed -> Listening -> Established (server accepting connection)
    sm.transition_to(ConnectionState::Listening).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Established);
}

#[tokio::test]
async fn test_connection_state_established_to_recovering() {
    let sm = TestStateMachine::new();

    // Closed -> Connecting -> Established -> Recovering
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    sm.transition_to(ConnectionState::Recovering).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Recovering);
}

#[tokio::test]
async fn test_connection_state_recovering_to_established() {
    let sm = TestStateMachine::new();

    // Simulate recovery success
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    sm.transition_to(ConnectionState::Recovering).await.unwrap();

    // Recovery successful, return to Established
    sm.transition_to(ConnectionState::Established).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Established);
}

#[tokio::test]
async fn test_connection_state_established_to_closing() {
    let sm = TestStateMachine::new();

    // Normal connection teardown
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    sm.transition_to(ConnectionState::Closing).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Closing);
}

#[tokio::test]
async fn test_connection_state_closing_to_closed() {
    let sm = TestStateMachine::new();

    // Complete connection teardown
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    sm.transition_to(ConnectionState::Closing).await.unwrap();
    sm.transition_to(ConnectionState::Closed).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Closed);
}

#[tokio::test]
async fn test_connection_state_error_recovery() {
    let sm = TestStateMachine::new();

    // Simulate error condition
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    sm.transition_to(ConnectionState::Error).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Error);

    // Error state transitions to Closed
    sm.transition_to(ConnectionState::Closed).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Closed);
}

#[tokio::test]
async fn test_invalid_state_transition_rejected() {
    let sm = TestStateMachine::new();

    // Try invalid transition: Closed -> Established (must go through Connecting/Listening)
    let result = sm.transition_to(ConnectionState::Established).await;
    assert!(result.is_err());
    assert_eq!(sm.get_state().await, ConnectionState::Closed);

    // Try invalid transition: Established -> Listening
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();
    let result = sm.transition_to(ConnectionState::Listening).await;
    assert!(result.is_err());
    assert_eq!(sm.get_state().await, ConnectionState::Established);
}

#[tokio::test]
async fn test_recovery_sub_state_normal_to_resync() {
    let sm = TestStateMachine::new();

    // Initial sub-state should be Normal
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Normal);

    // Transition to time resync recovery
    sm.transition_recovery_sub_state(RecoverySubState::Resync).await.unwrap();
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Resync);
}

#[tokio::test]
async fn test_recovery_sub_state_escalation_sequence() {
    let sm = TestStateMachine::new();

    // Test escalation: Normal -> Resync -> Rekey -> Repair -> Emergency
    sm.transition_recovery_sub_state(RecoverySubState::Normal).await.unwrap();
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Normal);

    sm.transition_recovery_sub_state(RecoverySubState::Resync).await.unwrap();
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Resync);

    sm.transition_recovery_sub_state(RecoverySubState::Rekey).await.unwrap();
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Rekey);

    sm.transition_recovery_sub_state(RecoverySubState::Repair).await.unwrap();
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Repair);

    sm.transition_recovery_sub_state(RecoverySubState::Emergency).await.unwrap();
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Emergency);
}

#[tokio::test]
async fn test_discovery_sub_state_transitions() {
    let sm = TestStateMachine::new();

    // Initial discovery state should be Idle
    assert_eq!(sm.get_discovery_state().await, DiscoverySubState::Idle);

    // PSK discovery sequence: Idle -> Request -> Response -> Confirm -> Completed
    sm.transition_discovery_sub_state(DiscoverySubState::Request).await.unwrap();
    assert_eq!(sm.get_discovery_state().await, DiscoverySubState::Request);

    sm.transition_discovery_sub_state(DiscoverySubState::Response).await.unwrap();
    assert_eq!(sm.get_discovery_state().await, DiscoverySubState::Response);

    sm.transition_discovery_sub_state(DiscoverySubState::Confirm).await.unwrap();
    assert_eq!(sm.get_discovery_state().await, DiscoverySubState::Confirm);

    sm.transition_discovery_sub_state(DiscoverySubState::Completed).await.unwrap();
    assert_eq!(sm.get_discovery_state().await, DiscoverySubState::Completed);
}

#[tokio::test]
async fn test_discovery_sub_state_failure() {
    let sm = TestStateMachine::new();

    // Discovery failure path: Idle -> Request -> Failed
    sm.transition_discovery_sub_state(DiscoverySubState::Request).await.unwrap();
    sm.transition_discovery_sub_state(DiscoverySubState::Failed).await.unwrap();
    assert_eq!(sm.get_discovery_state().await, DiscoverySubState::Failed);
}

#[tokio::test]
async fn test_concurrent_state_transitions_thread_safe() {
    let sm = Arc::new(TestStateMachine::new());

    // Set up initial state
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();

    // Spawn multiple concurrent tasks trying to transition state
    let mut handles = vec![];

    for i in 0..10 {
        let sm_clone = Arc::clone(&sm);
        let handle = tokio::spawn(async move {
            if i % 2 == 0 {
                // Try to transition to Recovering
                sm_clone.transition_to(ConnectionState::Recovering).await
            } else {
                // Try to transition to Closing
                sm_clone.transition_to(ConnectionState::Closing).await
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        let _ = handle.await;
    }

    // State should be either Recovering or Closing (but not corrupted)
    let final_state = sm.get_state().await;
    assert!(
        final_state == ConnectionState::Recovering ||
        final_state == ConnectionState::Closing ||
        final_state == ConnectionState::Established
    );
}

#[tokio::test]
async fn test_state_machine_complete_lifecycle() {
    let sm = TestStateMachine::new();

    // Test complete lifecycle: Closed -> Connecting -> Established -> Closing -> Closed
    assert_eq!(sm.get_state().await, ConnectionState::Closed);

    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Connecting);

    sm.transition_to(ConnectionState::Established).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Established);

    sm.transition_to(ConnectionState::Closing).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Closing);

    sm.transition_to(ConnectionState::Closed).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Closed);
}

#[tokio::test]
async fn test_state_machine_recovery_lifecycle() {
    let sm = TestStateMachine::new();

    // Test recovery lifecycle: Established -> Recovering -> Established
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();

    // Enter recovery
    sm.transition_to(ConnectionState::Recovering).await.unwrap();
    sm.transition_recovery_sub_state(RecoverySubState::Resync).await.unwrap();

    // Recovery successful
    sm.transition_recovery_sub_state(RecoverySubState::Normal).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();

    assert_eq!(sm.get_state().await, ConnectionState::Established);
    assert_eq!(sm.get_sub_state().await, RecoverySubState::Normal);
}

#[tokio::test]
async fn test_state_machine_failed_recovery() {
    let sm = TestStateMachine::new();

    // Test failed recovery: Established -> Recovering -> Error -> Closed
    sm.transition_to(ConnectionState::Connecting).await.unwrap();
    sm.transition_to(ConnectionState::Established).await.unwrap();

    // Enter recovery
    sm.transition_to(ConnectionState::Recovering).await.unwrap();

    // Escalate through recovery levels
    sm.transition_recovery_sub_state(RecoverySubState::Resync).await.unwrap();
    sm.transition_recovery_sub_state(RecoverySubState::Rekey).await.unwrap();
    sm.transition_recovery_sub_state(RecoverySubState::Repair).await.unwrap();
    sm.transition_recovery_sub_state(RecoverySubState::Emergency).await.unwrap();

    // All recovery failed, transition to Error
    sm.transition_to(ConnectionState::Error).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Error);

    // Cleanup
    sm.transition_to(ConnectionState::Closed).await.unwrap();
    assert_eq!(sm.get_state().await, ConnectionState::Closed);
}
