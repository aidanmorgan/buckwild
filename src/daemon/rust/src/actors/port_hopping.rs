#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use actix::prelude::*;
use buckwild_common::engines::port_hopping::engine::PortHoppingEngine;
use buckwild_common::protocol::types::{ConnectionId, Port, SessionId};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

use super::base::{DaemonActor, HealthCheck, Shutdown};

/// Actor wrapping PortHoppingEngine for connection-specific port coordination
pub struct PortHoppingActor {
    engine: Arc<PortHoppingEngine>,
    connection_id: ConnectionId,
}

impl PortHoppingActor {
    /// Create new PortHoppingActor
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Self {
        let engine =
            PortHoppingEngine::new_for_connection(connection_id, local_endpoint, remote_endpoint);

        Self {
            engine: Arc::new(engine),
            connection_id,
        }
    }

    /// Get reference to underlying engine
    pub fn engine(&self) -> &Arc<PortHoppingEngine> {
        &self.engine
    }
}

impl Actor for PortHoppingActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!(
            connection_id = %self.connection_id,
            "PortHoppingActor started"
        );

        let engine = self.engine.clone();

        ctx.spawn(
            async move {
                if let Err(e) = engine.start().await {
                    tracing::error!(error = %e, "Failed to start port hopping engine");
                }
            }
            .into_actor(self)
            .map(|_, _, _| ()),
        );
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!(
            connection_id = %self.connection_id,
            "PortHoppingActor stopped"
        );
    }
}

impl DaemonActor for PortHoppingActor {
    fn name(&self) -> &'static str {
        "port-hopping"
    }

    fn is_healthy(&self) -> bool {
        true
    }
}

// Messages

/// Get current port for a session
#[derive(Message)]
#[rtype(result = "Option<Port>")]
pub struct GetCurrentPort {
    pub session_id: SessionId,
}

/// Advance to next port for a session
#[derive(Message)]
#[rtype(result = "Result<(), String>")]
pub struct AdvancePort {
    pub session_id: SessionId,
}

/// Get port schedule for a session
#[derive(Message)]
#[rtype(result = "Vec<Port>")]
pub struct GetSchedule {
    pub session_id: SessionId,
    pub count: usize,
}

/// Get session port state information
#[derive(Message)]
#[rtype(result = "Option<buckwild_common::engines::port_hopping::engine::SessionPortInfo>")]
pub struct GetSessionPortState {
    pub session_id: SessionId,
}

/// Get port hopping statistics
#[derive(Message)]
#[rtype(result = "buckwild_common::engines::port_hopping::engine::PortHoppingStats")]
pub struct GetStats;

// Message Handlers

impl Handler<GetCurrentPort> for PortHoppingActor {
    type Result = Option<Port>;

    fn handle(&mut self, msg: GetCurrentPort, _ctx: &mut Context<Self>) -> Self::Result {
        debug!(
            connection_id = %self.connection_id,
            session_id = %msg.session_id,
            "GetCurrentPort message received"
        );

        self.engine
            .get_current_port_for_session(&msg.session_id, true)
    }
}

impl Handler<AdvancePort> for PortHoppingActor {
    type Result = ResponseFuture<Result<(), String>>;

    fn handle(&mut self, msg: AdvancePort, _ctx: &mut Context<Self>) -> Self::Result {
        debug!(
            connection_id = %self.connection_id,
            session_id = %msg.session_id,
            "AdvancePort message received"
        );

        let engine = self.engine.clone();
        let session_id = msg.session_id;

        Box::pin(async move {
            engine
                .hop_port_for_session(&session_id)
                .await
                .map(|_| ())
                .map_err(|e| format!("Port hop failed: {}", e))
        })
    }
}

impl Handler<GetSchedule> for PortHoppingActor {
    type Result = Vec<Port>;

    fn handle(&mut self, msg: GetSchedule, _ctx: &mut Context<Self>) -> Self::Result {
        debug!(
            connection_id = %self.connection_id,
            session_id = %msg.session_id,
            count = msg.count,
            "GetSchedule message received"
        );

        // Generate port schedule for the session using engine's calculation
        self.engine
            .get_port_schedule_for_session(&msg.session_id, msg.count)
    }
}

impl Handler<GetSessionPortState> for PortHoppingActor {
    type Result = Option<buckwild_common::engines::port_hopping::engine::SessionPortInfo>;

    fn handle(&mut self, msg: GetSessionPortState, _ctx: &mut Context<Self>) -> Self::Result {
        debug!(
            connection_id = %self.connection_id,
            session_id = %msg.session_id,
            "GetSessionPortState message received"
        );

        self.engine.get_session_port_state(&msg.session_id)
    }
}

impl Handler<GetStats> for PortHoppingActor {
    type Result = ResponseFuture<buckwild_common::engines::port_hopping::engine::PortHoppingStats>;

    fn handle(&mut self, _msg: GetStats, _ctx: &mut Context<Self>) -> Self::Result {
        debug!(
            connection_id = %self.connection_id,
            "GetStats message received"
        );

        let engine = self.engine.clone();

        Box::pin(async move { engine.get_port_hopping_stats().await })
    }
}

impl Handler<HealthCheck> for PortHoppingActor {
    type Result = bool;

    fn handle(&mut self, _msg: HealthCheck, _ctx: &mut Context<Self>) -> Self::Result {
        self.is_healthy()
    }
}

impl Handler<Shutdown> for PortHoppingActor {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, _msg: Shutdown, _ctx: &mut Context<Self>) -> Self::Result {
        info!(
            connection_id = %self.connection_id,
            "PortHoppingActor shutting down"
        );

        let engine = self.engine.clone();

        Box::pin(async move {
            if let Err(e) = engine.shutdown().await {
                tracing::error!(error = %e, "Error during port hopping engine shutdown");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckwild_common::protocol::types::ConnectionId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_actor() -> PortHoppingActor {
        let connection_id = ConnectionId::new(12345678);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9090);

        PortHoppingActor::new(connection_id, local_endpoint, remote_endpoint)
    }

    #[actix::test]
    async fn test_port_hopping_actor_spawn() {
        let actor = create_test_actor();
        let addr = actor.start();
        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_port_hopping_actor_health_check() {
        let actor = create_test_actor();
        let addr = actor.start();

        let result = addr.send(HealthCheck).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[actix::test]
    async fn test_port_hopping_actor_get_current_port() {
        let actor = create_test_actor();
        let addr = actor.start();

        let session_id = SessionId::new(987654321);
        let msg = GetCurrentPort { session_id };

        let result = addr.send(msg).await;
        assert!(result.is_ok());
        // Session doesn't exist yet, should return None
        assert!(result.unwrap().is_none());
    }

    #[actix::test]
    async fn test_port_hopping_actor_advance_port() {
        let actor = create_test_actor();
        let addr = actor.start();

        let session_id = SessionId::new(987654321);
        let msg = AdvancePort { session_id };

        let result = addr.send(msg).await;
        assert!(result.is_ok());
        // Session doesn't exist, should return error
        assert!(result.unwrap().is_err());
    }

    #[actix::test]
    async fn test_port_hopping_actor_get_schedule() {
        let actor = create_test_actor();
        let addr = actor.start();

        let session_id = SessionId::new(987654321);
        let msg = GetSchedule {
            session_id,
            count: 5,
        };

        let result = addr.send(msg).await;
        assert!(result.is_ok());
        let schedule = result.unwrap();
        assert!(schedule.is_empty());
    }

    #[actix::test]
    async fn test_port_hopping_actor_get_session_port_state() {
        let actor = create_test_actor();
        let addr = actor.start();

        let session_id = SessionId::new(987654321);
        let msg = GetSessionPortState { session_id };

        let result = addr.send(msg).await;
        assert!(result.is_ok());
        // Session doesn't exist yet, should return None
        assert!(result.unwrap().is_none());
    }

    #[actix::test]
    async fn test_port_hopping_actor_get_stats() {
        let actor = create_test_actor();
        let addr = actor.start();

        let result = addr.send(GetStats).await;
        assert!(result.is_ok());
        // Stats should be available even with no sessions
        let _stats = result.unwrap();
    }

    #[actix::test]
    async fn test_port_hopping_actor_shutdown() {
        let actor = create_test_actor();
        let addr = actor.start();

        let result = addr.send(Shutdown).await;
        assert!(result.is_ok());
    }

    // MED-010: Port hopping tests

    #[test]
    fn test_port_schedule_generation() {
        use buckwild_common::network::ebpf::port_hopping::calculate_port;
        use buckwild_common::network::ebpf::types::TimeBucket;

        // 32-byte daily key
        let daily_key = vec![0x42; 32];

        // Calculate port for 1-hour schedule (7200 buckets at 500ms per bucket)
        let mut ports = Vec::new();
        let buckets_per_hour = 7200;

        for i in 0..buckets_per_hour {
            let bucket = TimeBucket::new(i);
            if let Some(port) = calculate_port(&daily_key, bucket) {
                ports.push(port);
            }
        }

        // Verify we generated entries for the full hour
        assert_eq!(ports.len(), buckets_per_hour as usize);

        // Verify ports are not all the same (randomization working)
        let first_port = ports[0];
        let different_ports = ports.iter().any(|&p| p != first_port);
        assert!(
            different_ports,
            "Port schedule should vary across time buckets"
        );
    }

    #[test]
    fn test_port_within_valid_range() {
        use buckwild_common::network::ebpf::port_hopping::calculate_port;
        use buckwild_common::network::ebpf::types::TimeBucket;

        let daily_key = vec![0x42; 32];

        // Test a variety of time buckets
        for i in 0..1000 {
            let bucket = TimeBucket::new(i);
            if let Some(port) = calculate_port(&daily_key, bucket) {
                assert!(
                    port >= 1024,
                    "Port {} below minimum valid port 1024 for bucket {}",
                    port,
                    i
                );
            }
        }
    }
}
