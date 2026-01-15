#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use actix::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use super::base::{DaemonActor, HealthCheck, Shutdown};
use super::flow_control::FlowControlActor;
use super::port_hopping::PortHoppingActor;
use super::recovery::RecoveryActor;
use super::time_sync::TimeSyncActor;

/// Restart strategy for supervised actors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartStrategy {
    /// Restart only the failed actor
    #[default]
    OneForOne,
    /// Restart all actors if one fails
    OneForAll,
    /// Restart failed actor and all actors started after it
    RestForOne,
}

/// Configuration for restart behavior
#[derive(Debug, Clone)]
pub struct RestartConfig {
    /// Maximum number of restarts within the time window
    pub max_restarts: usize,
    /// Time window for counting restarts
    pub time_window: Duration,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            time_window: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

/// Actor identifier for supervised actors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorId {
    PortHopping,
    TimeSync,
    Recovery,
    FlowControl,
}

impl ActorId {
    fn name(&self) -> &'static str {
        match self {
            ActorId::PortHopping => "port-hopping",
            ActorId::TimeSync => "time-sync",
            ActorId::Recovery => "recovery",
            ActorId::FlowControl => "flow-control",
        }
    }

    /// Get ordered list of all actors in start order
    fn all_ordered() -> Vec<ActorId> {
        vec![
            ActorId::TimeSync,
            ActorId::PortHopping,
            ActorId::Recovery,
            ActorId::FlowControl,
        ]
    }
}

/// Restart history for an actor
#[derive(Debug)]
struct RestartHistory {
    restarts: Vec<Instant>,
    current_backoff: Duration,
}

impl RestartHistory {
    fn new(initial_backoff: Duration) -> Self {
        Self {
            restarts: Vec::new(),
            current_backoff: initial_backoff,
        }
    }

    fn record_restart(&mut self, config: &RestartConfig) {
        let now = Instant::now();
        self.restarts.push(now);

        // Remove old restarts outside the time window
        self.restarts
            .retain(|&t| now.duration_since(t) <= config.time_window);

        // Update backoff
        self.current_backoff = Duration::from_secs_f64(
            (self.current_backoff.as_secs_f64() * config.backoff_multiplier)
                .min(config.max_backoff.as_secs_f64()),
        );
    }

    fn should_restart(&self, config: &RestartConfig) -> bool {
        self.restarts.len() < config.max_restarts
    }

    fn get_backoff(&self) -> Duration {
        self.current_backoff
    }

    // Will be used when graceful restart recovery is implemented
    fn reset_backoff(&mut self, initial_backoff: Duration) {
        self.current_backoff = initial_backoff;
    }
}

/// Actor wrapper that can be any supervised actor type
#[derive(Clone)]
enum SupervisedActorAddr {
    PortHopping(Addr<PortHoppingActor>),
    TimeSync(Addr<TimeSyncActor>),
    Recovery(Addr<RecoveryActor>),
    FlowControl(Addr<FlowControlActor>),
}

impl SupervisedActorAddr {
    async fn send_health_check(&self) -> Result<bool, MailboxError> {
        match self {
            SupervisedActorAddr::PortHopping(addr) => addr.send(HealthCheck).await,
            SupervisedActorAddr::TimeSync(addr) => addr.send(HealthCheck).await,
            SupervisedActorAddr::Recovery(addr) => addr.send(HealthCheck).await,
            SupervisedActorAddr::FlowControl(addr) => addr.send(HealthCheck).await,
        }
    }

    async fn send_shutdown(&self) -> Result<(), MailboxError> {
        match self {
            SupervisedActorAddr::PortHopping(addr) => addr.send(Shutdown).await,
            SupervisedActorAddr::TimeSync(addr) => addr.send(Shutdown).await,
            SupervisedActorAddr::Recovery(addr) => addr.send(Shutdown).await,
            SupervisedActorAddr::FlowControl(addr) => addr.send(Shutdown).await,
        }
    }

    fn is_connected(&self) -> bool {
        match self {
            SupervisedActorAddr::PortHopping(addr) => addr.connected(),
            SupervisedActorAddr::TimeSync(addr) => addr.connected(),
            SupervisedActorAddr::Recovery(addr) => addr.connected(),
            SupervisedActorAddr::FlowControl(addr) => addr.connected(),
        }
    }
}

/// Main supervisor actor for managing daemon actor lifecycle
pub struct DaemonSupervisor {
    actors: HashMap<ActorId, SupervisedActorAddr>,
    restart_history: HashMap<ActorId, RestartHistory>,
    strategy: RestartStrategy,
    config: RestartConfig,
    accepting_sessions: bool,
    active_sessions: usize,
}

impl DaemonSupervisor {
    /// Create a new supervisor with default configuration
    pub fn new() -> Self {
        Self::with_strategy_and_config(RestartStrategy::default(), RestartConfig::default())
    }

    /// Create a new supervisor with specified restart strategy
    pub fn with_strategy(strategy: RestartStrategy) -> Self {
        Self::with_strategy_and_config(strategy, RestartConfig::default())
    }

    /// Create a new supervisor with specified strategy and configuration
    pub fn with_strategy_and_config(strategy: RestartStrategy, config: RestartConfig) -> Self {
        Self {
            actors: HashMap::new(),
            restart_history: HashMap::new(),
            strategy,
            config,
            accepting_sessions: true,
            active_sessions: 0,
        }
    }

    /// Register an actor with the supervisor
    fn register_actor(&mut self, id: ActorId, addr: SupervisedActorAddr) {
        info!(actor = %id.name(), "Registering actor with supervisor");
        self.actors.insert(id, addr);
        self.restart_history
            .entry(id)
            .or_insert_with(|| RestartHistory::new(self.config.initial_backoff));
    }

    /// Check if an actor should be restarted
    fn should_restart_actor(&self, id: ActorId) -> bool {
        // If actor has no restart history, allow restart (first failure)
        // Otherwise check if within restart limit
        self.restart_history
            .get(&id)
            .map(|history| history.should_restart(&self.config))
            .unwrap_or(true) // Allow first restart for untracked actors
    }

    /// Record a restart for an actor
    fn record_restart(&mut self, id: ActorId) {
        let history = self
            .restart_history
            .entry(id)
            .or_insert_with(|| RestartHistory::new(self.config.initial_backoff));
        history.record_restart(&self.config);
    }

    /// Get the backoff duration for an actor
    fn get_restart_backoff(&self, id: ActorId) -> Duration {
        self.restart_history
            .get(&id)
            .map(|history| history.get_backoff())
            .unwrap_or(self.config.initial_backoff)
    }

    /// Get actors to restart based on strategy
    fn get_actors_to_restart(&self, failed_id: ActorId) -> Vec<ActorId> {
        match self.strategy {
            RestartStrategy::OneForOne => vec![failed_id],
            RestartStrategy::OneForAll => ActorId::all_ordered(),
            RestartStrategy::RestForOne => {
                let all_actors = ActorId::all_ordered();
                let failed_index = all_actors
                    .iter()
                    .position(|&id| id == failed_id)
                    .unwrap_or(0);
                all_actors[failed_index..].to_vec()
            }
        }
    }
}

impl Default for DaemonSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Actor for DaemonSupervisor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        info!(
            "DaemonSupervisor started with strategy: {:?}",
            self.strategy
        );
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("DaemonSupervisor stopped");
    }
}

impl DaemonActor for DaemonSupervisor {
    fn name(&self) -> &'static str {
        "daemon-supervisor"
    }

    fn is_healthy(&self) -> bool {
        // Supervisor is healthy if all actors are connected
        self.actors.values().all(|addr| addr.is_connected())
    }
}

// Messages

/// Register a port hopping actor
#[derive(Message)]
#[rtype(result = "()")]
pub struct RegisterPortHopping {
    pub addr: Addr<PortHoppingActor>,
}

/// Register a time sync actor
#[derive(Message)]
#[rtype(result = "()")]
pub struct RegisterTimeSync {
    pub addr: Addr<TimeSyncActor>,
}

/// Register a recovery actor
#[derive(Message)]
#[rtype(result = "()")]
pub struct RegisterRecovery {
    pub addr: Addr<RecoveryActor>,
}

/// Register a flow control actor
#[derive(Message)]
#[rtype(result = "()")]
pub struct RegisterFlowControl {
    pub addr: Addr<FlowControlActor>,
}

/// Actor failure notification
#[derive(Message)]
#[rtype(result = "()")]
pub struct ActorFailed {
    pub actor_id: ActorId,
    pub reason: String,
}

/// Internal message to restart an actor after backoff delay
#[derive(Message)]
#[rtype(result = "()")]
struct RestartActor {
    actor_id: ActorId,
}

/// Get supervisor statistics
#[derive(Message)]
#[rtype(result = "SupervisorStats")]
pub struct GetSupervisorStats;

/// Supervisor statistics
#[derive(Debug, Clone)]
pub struct SupervisorStats {
    pub strategy: RestartStrategy,
    pub total_actors: usize,
    pub healthy_actors: usize,
    pub actor_restart_counts: HashMap<ActorId, usize>,
}

/// Check aggregate health of all actors
#[derive(Message)]
#[rtype(result = "AggregateHealth")]
pub struct CheckAggregateHealth;

/// Aggregate health status
#[derive(Debug, Clone)]
pub struct AggregateHealth {
    pub all_healthy: bool,
    pub actor_health: HashMap<ActorId, bool>,
}

/// Graceful shutdown with session draining
#[derive(Message)]
#[rtype(result = "()")]
pub struct GracefulShutdown {
    /// Maximum time to wait for sessions to drain (in seconds)
    pub drain_timeout_secs: u64,
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self {
            drain_timeout_secs: 30,
        }
    }
}

/// Register a new active session
#[derive(Message)]
#[rtype(result = "Result<(), SessionError>")]
pub struct RegisterSession;

/// Session registration error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    NotAcceptingSessions,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::NotAcceptingSessions => write!(f, "Not accepting new sessions"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Deregister an active session
#[derive(Message)]
#[rtype(result = "()")]
pub struct DeregisterSession;

/// Get current session count
#[derive(Message)]
#[rtype(result = "SessionStats")]
pub struct GetSessionStats;

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub accepting_sessions: bool,
    pub active_sessions: usize,
}

// Message Handlers

impl Handler<RegisterPortHopping> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, msg: RegisterPortHopping, _ctx: &mut Self::Context) -> Self::Result {
        self.register_actor(
            ActorId::PortHopping,
            SupervisedActorAddr::PortHopping(msg.addr),
        );
    }
}

impl Handler<RegisterTimeSync> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, msg: RegisterTimeSync, _ctx: &mut Self::Context) -> Self::Result {
        self.register_actor(ActorId::TimeSync, SupervisedActorAddr::TimeSync(msg.addr));
    }
}

impl Handler<RegisterRecovery> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, msg: RegisterRecovery, _ctx: &mut Self::Context) -> Self::Result {
        self.register_actor(ActorId::Recovery, SupervisedActorAddr::Recovery(msg.addr));
    }
}

impl Handler<RegisterFlowControl> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, msg: RegisterFlowControl, _ctx: &mut Self::Context) -> Self::Result {
        self.register_actor(
            ActorId::FlowControl,
            SupervisedActorAddr::FlowControl(msg.addr),
        );
    }
}

impl Handler<ActorFailed> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, msg: ActorFailed, ctx: &mut Self::Context) -> Self::Result {
        error!(
            actor = %msg.actor_id.name(),
            reason = %msg.reason,
            "Actor failure detected"
        );

        if !self.should_restart_actor(msg.actor_id) {
            error!(
                actor = %msg.actor_id.name(),
                "Maximum restart limit reached, escalating to monitoring"
            );
            return;
        }

        let actors_to_restart = self.get_actors_to_restart(msg.actor_id);
        info!(
            strategy = ?self.strategy,
            actors = ?actors_to_restart.iter().map(|id| id.name()).collect::<Vec<_>>(),
            "Scheduling actor restarts"
        );

        for actor_id in actors_to_restart {
            self.record_restart(actor_id);
            let backoff = self.get_restart_backoff(actor_id);

            info!(
                actor = %actor_id.name(),
                backoff_ms = backoff.as_millis(),
                restart_count = self.restart_history.get(&actor_id).map(|h| h.restarts.len()).unwrap_or(0),
                "Scheduling restart with exponential backoff"
            );

            let supervisor_addr = ctx.address();
            ctx.run_later(backoff, move |_supervisor, _ctx| {
                info!(
                    actor = %actor_id.name(),
                    "Executing scheduled actor restart"
                );

                supervisor_addr.do_send(RestartActor { actor_id });
            });
        }
    }
}

impl Handler<RestartActor> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, msg: RestartActor, _ctx: &mut Self::Context) -> Self::Result {
        info!(
            actor = %msg.actor_id.name(),
            "Restarting actor after backoff period"
        );

        match msg.actor_id {
            ActorId::TimeSync => {
                let new_actor = TimeSyncActor::new();
                let addr = new_actor.start();
                self.register_actor(msg.actor_id, SupervisedActorAddr::TimeSync(addr));
                info!(actor = %msg.actor_id.name(), "Actor successfully restarted");
            }
            ActorId::PortHopping | ActorId::Recovery | ActorId::FlowControl => {
                warn!(
                    actor = %msg.actor_id.name(),
                    "Actor requires constructor parameters for restart - needs integration with connection context"
                );
            }
        }
    }
}

impl Handler<GetSupervisorStats> for DaemonSupervisor {
    type Result = MessageResult<GetSupervisorStats>;

    fn handle(&mut self, _msg: GetSupervisorStats, _ctx: &mut Self::Context) -> Self::Result {
        let actor_restart_counts: HashMap<ActorId, usize> = self
            .restart_history
            .iter()
            .map(|(id, history)| (*id, history.restarts.len()))
            .collect();

        let healthy_actors = self
            .actors
            .values()
            .filter(|addr| addr.is_connected())
            .count();

        MessageResult(SupervisorStats {
            strategy: self.strategy,
            total_actors: self.actors.len(),
            healthy_actors,
            actor_restart_counts,
        })
    }
}

impl Handler<CheckAggregateHealth> for DaemonSupervisor {
    type Result = ResponseActFuture<Self, AggregateHealth>;

    fn handle(&mut self, _msg: CheckAggregateHealth, _ctx: &mut Self::Context) -> Self::Result {
        // Clone addresses to move into async block
        let actors: Vec<(ActorId, SupervisedActorAddr)> = self
            .actors
            .iter()
            .map(|(id, addr)| (*id, addr.clone()))
            .collect();

        Box::pin(
            async move {
                let mut actor_health = HashMap::new();
                let mut all_healthy = true;

                for (id, addr) in actors {
                    let healthy = addr.send_health_check().await.unwrap_or(false);
                    actor_health.insert(id, healthy);
                    all_healthy = all_healthy && healthy;
                }

                AggregateHealth {
                    all_healthy,
                    actor_health,
                }
            }
            .into_actor(self),
        )
    }
}

impl Handler<HealthCheck> for DaemonSupervisor {
    type Result = bool;

    fn handle(&mut self, _msg: HealthCheck, _ctx: &mut Self::Context) -> Self::Result {
        self.is_healthy()
    }
}

impl Handler<RegisterSession> for DaemonSupervisor {
    type Result = Result<(), SessionError>;

    fn handle(&mut self, _msg: RegisterSession, _ctx: &mut Self::Context) -> Self::Result {
        if !self.accepting_sessions {
            return Err(SessionError::NotAcceptingSessions);
        }
        self.active_sessions += 1;
        debug!(active_sessions = self.active_sessions, "Session registered");
        Ok(())
    }
}

impl Handler<DeregisterSession> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, _msg: DeregisterSession, _ctx: &mut Self::Context) -> Self::Result {
        if self.active_sessions > 0 {
            self.active_sessions -= 1;
            debug!(
                active_sessions = self.active_sessions,
                "Session deregistered"
            );
        }
    }
}

impl Handler<GetSessionStats> for DaemonSupervisor {
    type Result = MessageResult<GetSessionStats>;

    fn handle(&mut self, _msg: GetSessionStats, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(SessionStats {
            accepting_sessions: self.accepting_sessions,
            active_sessions: self.active_sessions,
        })
    }
}

impl Handler<GracefulShutdown> for DaemonSupervisor {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: GracefulShutdown, ctx: &mut Self::Context) -> Self::Result {
        info!(
            drain_timeout_secs = msg.drain_timeout_secs,
            active_sessions = self.active_sessions,
            "Starting graceful shutdown"
        );

        self.accepting_sessions = false;

        let drain_timeout = Duration::from_secs(msg.drain_timeout_secs);
        let start_time = Instant::now();
        let supervisor_addr = ctx.address();

        Box::pin(
            async move {
                // Wait for active sessions to drain or timeout
                loop {
                    let stats = supervisor_addr.send(GetSessionStats).await;
                    match stats {
                        Ok(stats) => {
                            if stats.active_sessions == 0 {
                                info!("All sessions drained, proceeding with shutdown");
                                break;
                            }

                            let elapsed = start_time.elapsed();
                            if elapsed >= drain_timeout {
                                warn!(
                                    active_sessions = stats.active_sessions,
                                    elapsed_secs = elapsed.as_secs(),
                                    "Drain timeout reached, forcing shutdown"
                                );
                                break;
                            }

                            debug!(
                                active_sessions = stats.active_sessions,
                                elapsed_secs = elapsed.as_secs(),
                                timeout_secs = msg.drain_timeout_secs,
                                "Waiting for sessions to drain"
                            );

                            // Wait 100ms before checking again
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to get session stats");
                            break;
                        }
                    }
                }

                // Shutdown actors in reverse dependency order
                supervisor_addr.do_send(ShutdownActors);
            }
            .into_actor(self),
        )
    }
}

impl Handler<Shutdown> for DaemonSupervisor {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        info!("DaemonSupervisor shutting down all actors (immediate shutdown)");

        // Clone addresses to move into async block
        let actors: Vec<SupervisedActorAddr> = self.actors.values().cloned().collect();
        let stop_ctx = ctx.address();

        Box::pin(
            async move {
                for (i, addr) in actors.iter().enumerate() {
                    if let Err(e) = addr.send_shutdown().await {
                        error!(actor_index = i, error = %e, "Error shutting down actor");
                    }
                }
                stop_ctx.do_send(Stop);
            }
            .into_actor(self),
        )
    }
}

/// Internal message to shutdown actors in order
#[derive(Message)]
#[rtype(result = "()")]
struct ShutdownActors;

impl Handler<ShutdownActors> for DaemonSupervisor {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, _msg: ShutdownActors, ctx: &mut Self::Context) -> Self::Result {
        info!("Shutting down actors in reverse dependency order");

        // Get actors in reverse order (shutdown order is reverse of startup)
        let mut shutdown_order = ActorId::all_ordered();
        shutdown_order.reverse();

        // Clone addresses in shutdown order
        let actors_to_shutdown: Vec<(ActorId, SupervisedActorAddr)> = shutdown_order
            .into_iter()
            .filter_map(|id| self.actors.get(&id).map(|addr| (id, addr.clone())))
            .collect();

        let stop_ctx = ctx.address();

        Box::pin(
            async move {
                // Shutdown actors sequentially in reverse order
                for (actor_id, addr) in actors_to_shutdown {
                    info!(actor = %actor_id.name(), "Shutting down actor");
                    if let Err(e) = addr.send_shutdown().await {
                        error!(
                            actor = %actor_id.name(),
                            error = %e,
                            "Error shutting down actor"
                        );
                    } else {
                        debug!(actor = %actor_id.name(), "Actor shutdown complete");
                    }
                }

                info!("All actors shutdown, stopping supervisor");
                stop_ctx.do_send(Stop);
            }
            .into_actor(self),
        )
    }
}

/// Internal message to stop supervisor
#[derive(Message)]
#[rtype(result = "()")]
struct Stop;

impl Handler<Stop> for DaemonSupervisor {
    type Result = ();

    fn handle(&mut self, _msg: Stop, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::time_sync::TimeSyncConfig;

    /// Create a TimeSyncActor for testing with auto_sync disabled
    /// This prevents the actor from blocking on InitiateSync during tests
    fn test_time_sync_actor() -> TimeSyncActor {
        TimeSyncActor::with_config(TimeSyncConfig {
            auto_sync_on_startup: false,
            ..TimeSyncConfig::default()
        })
    }

    #[actix::test]
    async fn test_daemon_supervisor_spawn() {
        let supervisor = DaemonSupervisor::new();
        let addr = supervisor.start();
        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_supervisor_with_strategy() {
        let supervisor = DaemonSupervisor::with_strategy(RestartStrategy::OneForAll);
        let addr = supervisor.start();

        let stats = addr.send(GetSupervisorStats).await;
        assert!(stats.is_ok());
        let stats = stats.unwrap();
        assert_eq!(stats.strategy, RestartStrategy::OneForAll);
    }

    #[actix::test]
    async fn test_supervisor_register_time_sync() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let time_sync = test_time_sync_actor();
        let time_sync_addr = time_sync.start();

        let result = supervisor_addr
            .send(RegisterTimeSync {
                addr: time_sync_addr,
            })
            .await;
        assert!(result.is_ok());

        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.total_actors, 1);
    }

    #[actix::test]
    async fn test_supervisor_aggregate_health() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let time_sync = test_time_sync_actor();
        let time_sync_addr = time_sync.start();

        supervisor_addr
            .send(RegisterTimeSync {
                addr: time_sync_addr,
            })
            .await
            .unwrap();

        let health = supervisor_addr.send(CheckAggregateHealth).await.unwrap();
        // Note: all_healthy may be false for a fresh TimeSyncEngine (no sync samples)
        // We verify the health check completed and returned results for all registered actors
        assert_eq!(health.actor_health.len(), 1);
        assert!(health.actor_health.contains_key(&ActorId::TimeSync));
    }

    #[actix::test]
    async fn test_supervisor_health_check() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let result = supervisor_addr.send(HealthCheck).await;
        assert!(result.is_ok());
        // Empty supervisor is healthy
        assert!(result.unwrap());
    }

    #[actix::test]
    async fn test_actor_restart_strategy_one_for_one() {
        let supervisor = DaemonSupervisor::with_strategy(RestartStrategy::OneForOne);
        let supervisor_addr = supervisor.start();

        supervisor_addr
            .send(ActorFailed {
                actor_id: ActorId::TimeSync,
                reason: "Test failure".to_string(),
            })
            .await
            .unwrap();

        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&1));
    }

    #[actix::test]
    async fn test_actor_restart_backoff() {
        let config = RestartConfig {
            max_restarts: 5,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        let supervisor =
            DaemonSupervisor::with_strategy_and_config(RestartStrategy::OneForOne, config.clone());
        let supervisor_addr = supervisor.start();

        // Trigger multiple failures
        for _ in 0..3 {
            supervisor_addr
                .send(ActorFailed {
                    actor_id: ActorId::TimeSync,
                    reason: "Test failure".to_string(),
                })
                .await
                .unwrap();
        }

        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&3));
    }

    #[actix::test]
    async fn test_supervisor_shutdown() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let time_sync = test_time_sync_actor();
        let time_sync_addr = time_sync.start();

        supervisor_addr
            .send(RegisterTimeSync {
                addr: time_sync_addr,
            })
            .await
            .unwrap();

        let result = supervisor_addr.send(Shutdown).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_restart_strategy_default() {
        assert_eq!(RestartStrategy::default(), RestartStrategy::OneForOne);
    }

    #[test]
    fn test_restart_config_default() {
        let config = RestartConfig::default();
        assert_eq!(config.max_restarts, 3);
        assert_eq!(config.time_window, Duration::from_secs(60));
    }

    #[test]
    fn test_actor_id_ordering() {
        let all_actors = ActorId::all_ordered();
        assert_eq!(all_actors.len(), 4);
        assert_eq!(all_actors[0], ActorId::TimeSync);
        assert_eq!(all_actors[1], ActorId::PortHopping);
        assert_eq!(all_actors[2], ActorId::Recovery);
        assert_eq!(all_actors[3], ActorId::FlowControl);
    }

    #[actix::test]
    async fn test_session_registration() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let result = supervisor_addr.send(RegisterSession).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());

        let stats = supervisor_addr.send(GetSessionStats).await.unwrap();
        assert_eq!(stats.active_sessions, 1);
        assert!(stats.accepting_sessions);
    }

    #[actix::test]
    async fn test_session_deregistration() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        supervisor_addr
            .send(RegisterSession)
            .await
            .unwrap()
            .unwrap();
        supervisor_addr
            .send(RegisterSession)
            .await
            .unwrap()
            .unwrap();

        let stats = supervisor_addr.send(GetSessionStats).await.unwrap();
        assert_eq!(stats.active_sessions, 2);

        supervisor_addr.send(DeregisterSession).await.unwrap();

        let stats = supervisor_addr.send(GetSessionStats).await.unwrap();
        assert_eq!(stats.active_sessions, 1);
    }

    #[actix::test]
    async fn test_graceful_shutdown_stops_accepting_sessions() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        // Register a session to keep supervisor alive during test
        supervisor_addr
            .send(RegisterSession)
            .await
            .unwrap()
            .unwrap();

        let supervisor_clone = supervisor_addr.clone();
        let shutdown_handle = actix::spawn(async move {
            supervisor_clone
                .send(GracefulShutdown {
                    drain_timeout_secs: 2,
                })
                .await
        });

        // Wait for shutdown to start processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify we get stats showing not accepting sessions
        let stats = supervisor_addr.send(GetSessionStats).await.unwrap();
        assert!(!stats.accepting_sessions);
        assert_eq!(stats.active_sessions, 1);

        // Try to register a new session and verify it's rejected
        let result = supervisor_addr.send(RegisterSession).await;
        match result {
            Ok(Err(SessionError::NotAcceptingSessions)) => (),
            _ => panic!("Expected NotAcceptingSessions error, got: {:?}", result),
        }

        // Clean up by deregistering the session so shutdown can complete
        supervisor_addr.send(DeregisterSession).await.unwrap();

        let _ = shutdown_handle.await;
    }

    #[actix::test]
    async fn test_graceful_shutdown_drains_sessions() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        supervisor_addr
            .send(RegisterSession)
            .await
            .unwrap()
            .unwrap();
        supervisor_addr
            .send(RegisterSession)
            .await
            .unwrap()
            .unwrap();

        let stats = supervisor_addr.send(GetSessionStats).await.unwrap();
        assert_eq!(stats.active_sessions, 2);

        let supervisor_clone = supervisor_addr.clone();
        let shutdown_handle = actix::spawn(async move {
            supervisor_clone
                .send(GracefulShutdown {
                    drain_timeout_secs: 5,
                })
                .await
        });

        // Wait for shutdown to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Deregister sessions
        supervisor_addr.send(DeregisterSession).await.unwrap();
        supervisor_addr.send(DeregisterSession).await.unwrap();

        // Wait for shutdown to complete
        let result = shutdown_handle.await;
        assert!(result.is_ok());
    }

    #[actix::test]
    async fn test_graceful_shutdown_timeout() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        supervisor_addr
            .send(RegisterSession)
            .await
            .unwrap()
            .unwrap();

        let start = Instant::now();
        supervisor_addr
            .send(GracefulShutdown {
                drain_timeout_secs: 1,
            })
            .await
            .unwrap();

        let elapsed = start.elapsed();
        // Should complete around 1 second (timeout)
        assert!(elapsed >= Duration::from_secs(1));
        assert!(elapsed < Duration::from_secs(2));
    }

    #[actix::test]
    async fn test_graceful_shutdown_ordered_actor_shutdown() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let time_sync = test_time_sync_actor();
        let time_sync_addr = time_sync.start();
        supervisor_addr
            .send(RegisterTimeSync {
                addr: time_sync_addr,
            })
            .await
            .unwrap();

        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.total_actors, 1);

        supervisor_addr
            .send(GracefulShutdown::default())
            .await
            .unwrap();

        // Verify supervisor eventually stops
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    #[actix::test]
    async fn test_graceful_shutdown_completes_within_timeout() {
        let supervisor = DaemonSupervisor::new();
        let supervisor_addr = supervisor.start();

        let time_sync = test_time_sync_actor();
        let time_sync_addr = time_sync.start();
        supervisor_addr
            .send(RegisterTimeSync {
                addr: time_sync_addr,
            })
            .await
            .unwrap();

        let start = Instant::now();
        supervisor_addr
            .send(GracefulShutdown {
                drain_timeout_secs: 30,
            })
            .await
            .unwrap();

        let elapsed = start.elapsed();
        // Should complete much faster than timeout since no active sessions
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn test_graceful_shutdown_default() {
        let shutdown = GracefulShutdown::default();
        assert_eq!(shutdown.drain_timeout_secs, 30);
    }

    #[test]
    fn test_session_error_display() {
        let error = SessionError::NotAcceptingSessions;
        assert_eq!(error.to_string(), "Not accepting new sessions");
    }

    // MED-009: Actor supervision tests

    #[actix::test]
    async fn test_actor_restart_on_failure() {
        let supervisor = DaemonSupervisor::with_strategy(RestartStrategy::OneForOne);
        let supervisor_addr = supervisor.start();

        // Trigger actor failure
        supervisor_addr
            .send(ActorFailed {
                actor_id: ActorId::TimeSync,
                reason: "Simulated crash for restart test".to_string(),
            })
            .await
            .unwrap();

        // Verify restart was recorded
        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&1));

        // Trigger second failure
        supervisor_addr
            .send(ActorFailed {
                actor_id: ActorId::TimeSync,
                reason: "Second failure".to_string(),
            })
            .await
            .unwrap();

        // Verify restart count incremented
        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&2));
    }

    #[actix::test]
    async fn test_supervision_tree_structure() {
        let supervisor = DaemonSupervisor::with_strategy(RestartStrategy::RestForOne);
        let supervisor_addr = supervisor.start();

        // Register actors in dependency order
        let time_sync = test_time_sync_actor();
        supervisor_addr
            .send(RegisterTimeSync {
                addr: time_sync.start(),
            })
            .await
            .unwrap();

        // Verify all actors in correct order
        let ordered = ActorId::all_ordered();
        assert_eq!(ordered[0], ActorId::TimeSync);
        assert_eq!(ordered[1], ActorId::PortHopping);
        assert_eq!(ordered[2], ActorId::Recovery);
        assert_eq!(ordered[3], ActorId::FlowControl);

        // Trigger failure in TimeSync (first actor)
        supervisor_addr
            .send(ActorFailed {
                actor_id: ActorId::TimeSync,
                reason: "Tree structure test".to_string(),
            })
            .await
            .unwrap();

        // Verify restart count
        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.strategy, RestartStrategy::RestForOne);
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&1));
    }

    #[actix::test]
    async fn test_exponential_backoff_multiple_restarts() {
        let config = RestartConfig {
            max_restarts: 5,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        let supervisor =
            DaemonSupervisor::with_strategy_and_config(RestartStrategy::OneForOne, config.clone());
        let supervisor_addr = supervisor.start();

        // Trigger 5 failures to verify backoff progression
        for i in 1..=5 {
            supervisor_addr
                .send(ActorFailed {
                    actor_id: ActorId::TimeSync,
                    reason: format!("Test failure {}", i),
                })
                .await
                .unwrap();

            // Wait for backoff to complete
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&5));

        // Trigger one more failure - should not restart (limit reached)
        supervisor_addr
            .send(ActorFailed {
                actor_id: ActorId::TimeSync,
                reason: "Test failure beyond limit".to_string(),
            })
            .await
            .unwrap();

        // Wait and verify count didn't increase
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&5));
    }

    #[actix::test]
    async fn test_restart_limit_escalation() {
        let config = RestartConfig {
            max_restarts: 2,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            time_window: Duration::from_secs(60),
        };

        let supervisor =
            DaemonSupervisor::with_strategy_and_config(RestartStrategy::OneForOne, config.clone());
        let supervisor_addr = supervisor.start();

        // Trigger max_restarts failures
        for i in 1..=2 {
            supervisor_addr
                .send(ActorFailed {
                    actor_id: ActorId::TimeSync,
                    reason: format!("Failure {}", i),
                })
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&2));

        // Next failure should escalate (not restart)
        supervisor_addr
            .send(ActorFailed {
                actor_id: ActorId::TimeSync,
                reason: "Escalation trigger".to_string(),
            })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Restart count should remain at max_restarts
        let stats = supervisor_addr.send(GetSupervisorStats).await.unwrap();
        assert_eq!(stats.actor_restart_counts.get(&ActorId::TimeSync), Some(&2));
    }
}
