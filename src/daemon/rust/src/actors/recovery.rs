use actix::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

use buckwild_common::engines::recovery::engine::{
    RecoveryEngine, RecoveryStats, SessionRecoveryInfo,
};
use buckwild_common::error::EngineError;
use buckwild_common::protocol::types::{ConnectionId, SessionId};
use buckwild_common::security::crypto::ecdh::ThreadSafeEcdhManager;
use buckwild_common::security::crypto::hmac::HmacCalculator;
use buckwild_common::session::SessionState;

use super::base::{DaemonActor, HealthCheck, Shutdown};

pub struct RecoveryActor {
    engine: Arc<RecoveryEngine>,
    healthy: bool,
}

impl RecoveryActor {
    pub fn new(
        connection_id: ConnectionId,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
        ecdh_manager: Arc<ThreadSafeEcdhManager>,
        hmac_calculator: Arc<HmacCalculator>,
        session_manager: Arc<dyn buckwild_common::engines::recovery::engine::SessionManagerTrait>,
    ) -> Self {
        let engine = Arc::new(RecoveryEngine::new_for_connection(
            connection_id,
            local_endpoint,
            remote_endpoint,
            ecdh_manager,
            hmac_calculator,
            session_manager,
        ));

        Self {
            engine,
            healthy: true,
        }
    }
}

impl Actor for RecoveryActor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        info!("RecoveryActor started");
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("RecoveryActor stopped");
    }
}

impl DaemonActor for RecoveryActor {
    fn name(&self) -> &'static str {
        "recovery-actor"
    }

    fn is_healthy(&self) -> bool {
        self.healthy
    }
}

#[derive(Message)]
#[rtype(result = "Result<(), EngineError>")]
pub struct AddSession {
    pub session_id: SessionId,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct RemoveSession {
    pub session_id: SessionId,
}

#[derive(Message)]
#[rtype(result = "Result<buckwild_common::engines::recovery::engine::RecoveryResult, EngineError>")]
pub struct InitiateRecovery {
    pub session_id: SessionId,
    pub session_state: Arc<SessionState>,
    pub failure_reason: String,
}

#[derive(Message)]
#[rtype(result = "RecoveryStats")]
pub struct GetRecoveryStats;

#[derive(Message)]
#[rtype(result = "Option<SessionRecoveryInfo>")]
pub struct GetSessionRecoveryState {
    pub session_id: SessionId,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct CleanupExpiredData;

impl Handler<HealthCheck> for RecoveryActor {
    type Result = bool;

    fn handle(&mut self, _msg: HealthCheck, _ctx: &mut Self::Context) -> Self::Result {
        self.is_healthy()
    }
}

impl Handler<Shutdown> for RecoveryActor {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        debug!("RecoveryActor shutting down");
        ctx.stop();
        Box::pin(async move {}.into_actor(self))
    }
}

impl Handler<AddSession> for RecoveryActor {
    type Result = ResponseFuture<Result<(), EngineError>>;

    fn handle(&mut self, msg: AddSession, _ctx: &mut Self::Context) -> Self::Result {
        debug!(session_id = %msg.session_id, "AddSession message received");
        let engine = Arc::clone(&self.engine);
        let future = async move { engine.add_session(msg.session_id).await };
        Box::pin(future)
    }
}

impl Handler<RemoveSession> for RecoveryActor {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: RemoveSession, _ctx: &mut Self::Context) -> Self::Result {
        debug!(session_id = %msg.session_id, "RemoveSession message received");
        let engine = Arc::clone(&self.engine);
        let session_id = msg.session_id;
        let future = async move { engine.remove_session(&session_id).await };
        Box::pin(future)
    }
}

impl Handler<InitiateRecovery> for RecoveryActor {
    type Result = ResponseFuture<
        Result<buckwild_common::engines::recovery::engine::RecoveryResult, EngineError>,
    >;

    fn handle(&mut self, msg: InitiateRecovery, _ctx: &mut Self::Context) -> Self::Result {
        debug!(
            session_id = %msg.session_id,
            failure_reason = %msg.failure_reason,
            "InitiateRecovery message received"
        );
        let engine = Arc::clone(&self.engine);
        let future = async move {
            engine
                .initiate_recovery(msg.session_id, msg.session_state, msg.failure_reason)
                .await
        };
        Box::pin(future)
    }
}

impl Handler<GetRecoveryStats> for RecoveryActor {
    type Result = ResponseFuture<RecoveryStats>;

    fn handle(&mut self, _msg: GetRecoveryStats, _ctx: &mut Self::Context) -> Self::Result {
        let engine = Arc::clone(&self.engine);
        let future = async move { engine.get_recovery_stats().await };
        Box::pin(future)
    }
}

impl Handler<GetSessionRecoveryState> for RecoveryActor {
    type Result = ResponseFuture<Option<SessionRecoveryInfo>>;

    fn handle(&mut self, msg: GetSessionRecoveryState, _ctx: &mut Self::Context) -> Self::Result {
        debug!(session_id = %msg.session_id, "GetSessionRecoveryState message received");
        let engine = Arc::clone(&self.engine);
        let session_id = msg.session_id;
        let future = async move { engine.get_session_recovery_state(&session_id).await };
        Box::pin(future)
    }
}

impl Handler<CleanupExpiredData> for RecoveryActor {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, _msg: CleanupExpiredData, _ctx: &mut Self::Context) -> Self::Result {
        let engine = Arc::clone(&self.engine);
        let future = async move { engine.cleanup_expired_data().await };
        Box::pin(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckwild_common::engines::recovery::engine::SessionManagerTrait;
    use buckwild_common::protocol::types::{ConnectionId, SessionId, SessionKey};
    use buckwild_common::security::crypto::ecdh::ThreadSafeEcdhManager;
    use buckwild_common::security::crypto::hmac::HmacCalculator;
    use buckwild_common::session::SessionState;
    use std::net::SocketAddr;

    struct MockSessionManager;

    impl SessionManagerTrait for MockSessionManager {
        fn get_session_state(&self, _session_id: &SessionId) -> Option<Arc<SessionState>> {
            None
        }

        fn update_session_state(
            &self,
            _session_id: &SessionId,
            _state: Arc<SessionState>,
        ) -> Result<(), EngineError> {
            Ok(())
        }

        fn get_session_key(&self, _session_id: &SessionId) -> Option<SessionKey> {
            None
        }

        fn is_connection_established(&self) -> bool {
            true
        }
    }

    #[actix::test]
    async fn test_recovery_actor_spawn() {
        let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let connection_id = ConnectionId::new(1);

        let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(60));
        let hmac_calculator = Arc::new(HmacCalculator::new());
        let session_manager: Arc<dyn SessionManagerTrait> = Arc::new(MockSessionManager);

        let actor = RecoveryActor::new(
            connection_id,
            local_addr,
            remote_addr,
            ecdh_manager,
            hmac_calculator,
            session_manager,
        );

        let addr = actor.start();
        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_recovery_actor_level() {
        let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let connection_id = ConnectionId::new(1);

        let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(60));
        let hmac_calculator = Arc::new(HmacCalculator::new());
        let session_manager: Arc<dyn SessionManagerTrait> = Arc::new(MockSessionManager);

        let actor = RecoveryActor::new(
            connection_id,
            local_addr,
            remote_addr,
            ecdh_manager,
            hmac_calculator,
            session_manager,
        );

        let addr = actor.start();

        let session_id = SessionId::new(1);
        let add_result = addr
            .send(AddSession {
                session_id: session_id.clone(),
            })
            .await;
        assert!(add_result.is_ok());
        assert!(add_result.unwrap().is_ok());

        let state_result = addr
            .send(GetSessionRecoveryState {
                session_id: session_id.clone(),
            })
            .await;
        assert!(state_result.is_ok());
        let state = state_result.unwrap();
        assert!(state.is_some());
        assert_eq!(
            state.unwrap().current_level,
            buckwild_common::engines::recovery::engine::RecoveryLevel::None
        );
    }
}
