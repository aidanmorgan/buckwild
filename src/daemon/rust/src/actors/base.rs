use actix::prelude::*;

pub trait DaemonActor: Actor {
    fn name(&self) -> &'static str;
    fn is_healthy(&self) -> bool;
}

#[derive(Message)]
#[rtype(result = "bool")]
pub struct HealthCheck;

#[derive(Message)]
#[rtype(result = "()")]
pub struct Shutdown;

pub struct ExampleActor {
    name: &'static str,
    healthy: bool,
}

impl ExampleActor {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            healthy: true,
        }
    }
}

impl Actor for ExampleActor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        tracing::info!("Actor {} started", self.name);
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        tracing::info!("Actor {} stopped", self.name);
    }
}

impl DaemonActor for ExampleActor {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_healthy(&self) -> bool {
        self.healthy
    }
}

impl Handler<HealthCheck> for ExampleActor {
    type Result = bool;

    fn handle(&mut self, _msg: HealthCheck, _ctx: &mut Self::Context) -> Self::Result {
        self.is_healthy()
    }
}

impl Handler<Shutdown> for ExampleActor {
    type Result = ();

    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        tracing::info!("Actor {} shutting down", self.name);
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix::test]
    async fn test_actor_spawn() {
        let actor = ExampleActor::new("test-actor");
        let addr = actor.start();
        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_actor_message() {
        let actor = ExampleActor::new("test-actor");
        let addr = actor.start();

        let result = addr.send(HealthCheck).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[actix::test]
    async fn test_actor_shutdown() {
        let actor = ExampleActor::new("test-actor");
        let addr = actor.start();

        let result = addr.send(Shutdown).await;
        assert!(result.is_ok());
    }
}
