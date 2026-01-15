use actix::prelude::*;
use bytes::Bytes;
use std::sync::Arc;
use tracing::{debug, info, instrument};

use buckwild_common::engines::flow_control::engine::{FlowControlEngine, FlowControlStats};
use buckwild_common::error::EngineError;
use buckwild_common::protocol::types::{ConnectionId, SessionId, WindowSize};

use super::base::{DaemonActor, HealthCheck, Shutdown};

pub struct FlowControlActor {
    engine: Arc<FlowControlEngine>,
    healthy: bool,
}

impl FlowControlActor {
    pub fn new(
        connection_id: ConnectionId,
        session_id: SessionId,
        initial_send_seq: u32,
        initial_recv_seq: u32,
    ) -> Self {
        let engine = Arc::new(FlowControlEngine::new(
            connection_id,
            session_id,
            initial_send_seq,
            initial_recv_seq,
        ));

        Self {
            engine,
            healthy: true,
        }
    }
}

impl Actor for FlowControlActor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        info!("FlowControlActor started");
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("FlowControlActor stopped");
    }
}

impl DaemonActor for FlowControlActor {
    fn name(&self) -> &'static str {
        "flow-control-actor"
    }

    fn is_healthy(&self) -> bool {
        self.healthy
    }
}

#[derive(Message)]
#[rtype(result = "WindowSize")]
pub struct GetSendWindow;

#[derive(Message)]
#[rtype(result = "WindowSize")]
pub struct GetReceiveWindow;

#[derive(Message)]
#[rtype(result = "u32")]
pub struct GetCongestionWindow;

#[derive(Message, Debug)]
#[rtype(result = "bool")]
pub struct CanSendData {
    pub data_length: u32,
}

#[derive(Message)]
#[rtype(result = "Result<(), EngineError>")]
pub struct SendData {
    pub data: Bytes,
}

#[derive(Message)]
#[rtype(result = "FlowControlStats")]
pub struct GetFlowControlStats;

#[derive(Message)]
#[rtype(result = "u32")]
pub struct GetEffectiveWindow;

impl Handler<HealthCheck> for FlowControlActor {
    type Result = bool;

    fn handle(&mut self, _msg: HealthCheck, _ctx: &mut Self::Context) -> Self::Result {
        self.is_healthy()
    }
}

impl Handler<Shutdown> for FlowControlActor {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        debug!("FlowControlActor shutting down");
        ctx.stop();
        Box::pin(async move {}.into_actor(self))
    }
}

impl Handler<GetSendWindow> for FlowControlActor {
    type Result = MessageResult<GetSendWindow>;

    fn handle(&mut self, _msg: GetSendWindow, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.engine.get_send_window())
    }
}

impl Handler<GetReceiveWindow> for FlowControlActor {
    type Result = MessageResult<GetReceiveWindow>;

    fn handle(&mut self, _msg: GetReceiveWindow, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.engine.get_receive_window())
    }
}

impl Handler<GetCongestionWindow> for FlowControlActor {
    type Result = MessageResult<GetCongestionWindow>;

    fn handle(&mut self, _msg: GetCongestionWindow, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.engine.get_congestion_window())
    }
}

impl Handler<CanSendData> for FlowControlActor {
    type Result = MessageResult<CanSendData>;

    #[instrument(skip(self, _ctx), fields(data_length = msg.data_length))]
    fn handle(&mut self, msg: CanSendData, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.engine.can_send_data(msg.data_length))
    }
}

impl Handler<SendData> for FlowControlActor {
    type Result = ResponseFuture<Result<(), EngineError>>;

    fn handle(&mut self, msg: SendData, _ctx: &mut Self::Context) -> Self::Result {
        let data_len = msg.data.len();
        debug!(data_len, "SendData message received");

        let engine = Arc::clone(&self.engine);
        let future = async move { engine.send_data(msg.data).await };
        Box::pin(future)
    }
}

impl Handler<GetFlowControlStats> for FlowControlActor {
    type Result = ResponseFuture<FlowControlStats>;

    fn handle(&mut self, _msg: GetFlowControlStats, _ctx: &mut Self::Context) -> Self::Result {
        let engine = Arc::clone(&self.engine);
        let future = async move { engine.get_flow_control_stats().await };
        Box::pin(future)
    }
}

impl Handler<GetEffectiveWindow> for FlowControlActor {
    type Result = MessageResult<GetEffectiveWindow>;

    fn handle(&mut self, _msg: GetEffectiveWindow, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.engine.calculate_effective_window())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckwild_common::protocol::types::{ConnectionId, SessionId};

    #[actix::test]
    async fn test_flow_control_actor_spawn() {
        let connection_id = ConnectionId::new(1);
        let session_id = SessionId::new(2);

        let actor = FlowControlActor::new(connection_id, session_id, 0, 0);
        let addr = actor.start();
        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_flow_control_actor_window() {
        let connection_id = ConnectionId::new(1);
        let session_id = SessionId::new(2);

        let actor = FlowControlActor::new(connection_id, session_id, 0, 0);
        let addr = actor.start();

        let send_window_result = addr.send(GetSendWindow).await;
        assert!(send_window_result.is_ok());
        let send_window = send_window_result.unwrap();
        assert_eq!(send_window.as_u32(), 65535);

        let receive_window_result = addr.send(GetReceiveWindow).await;
        assert!(receive_window_result.is_ok());
        let receive_window = receive_window_result.unwrap();
        assert_eq!(receive_window.as_u32(), 65535);

        let congestion_window_result = addr.send(GetCongestionWindow).await;
        assert!(congestion_window_result.is_ok());
        let congestion_window = congestion_window_result.unwrap();
        assert_eq!(congestion_window, 1460);
    }
}
