use actix::prelude::*;
use buckwild_common::engines::time_sync::{SyncRequest, SyncResponse, TimeSyncEngine};
use buckwild_common::protocol::types::{ChallengeNonce, MicrosecondTimestamp, TimeOffset};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

use super::base::{DaemonActor, HealthCheck, Shutdown};

/// Configuration for time synchronization
#[derive(Debug, Clone)]
pub struct TimeSyncConfig {
    /// Interval between sync attempts (default: 60 seconds)
    pub sync_interval: Duration,
    /// Enable automatic periodic sync on startup
    pub auto_sync_on_startup: bool,
}

impl Default for TimeSyncConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(60),
            auto_sync_on_startup: true,
        }
    }
}

pub struct TimeSyncActor {
    engine: Arc<RwLock<TimeSyncEngine>>,
    config: TimeSyncConfig,
    /// Flag to track if periodic sync is running
    periodic_sync_active: bool,
}

impl TimeSyncActor {
    pub fn new() -> Self {
        Self::with_config(TimeSyncConfig::default())
    }

    pub fn with_config(config: TimeSyncConfig) -> Self {
        Self {
            engine: Arc::new(RwLock::new(TimeSyncEngine::new())),
            config,
            periodic_sync_active: false,
        }
    }

    pub fn with_engine(engine: TimeSyncEngine) -> Self {
        Self {
            engine: Arc::new(RwLock::new(engine)),
            config: TimeSyncConfig::default(),
            periodic_sync_active: false,
        }
    }

    /// Start periodic time synchronization
    fn start_periodic_sync(&mut self, ctx: &mut Context<Self>) {
        if self.periodic_sync_active {
            return;
        }

        let interval = self.config.sync_interval;
        info!(
            interval_secs = interval.as_secs(),
            "Starting periodic time synchronization"
        );

        ctx.run_interval(interval, |act, ctx| {
            if act.periodic_sync_active {
                ctx.address().do_send(PeriodicSync);
            }
        });

        self.periodic_sync_active = true;
    }

    /// Stop periodic time synchronization
    fn stop_periodic_sync(&mut self) {
        if self.periodic_sync_active {
            info!("Stopping periodic time synchronization");
            self.periodic_sync_active = false;
        }
    }
}

impl Default for TimeSyncActor {
    fn default() -> Self {
        Self::new()
    }
}

impl Actor for TimeSyncActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("TimeSyncActor started");

        // Start periodic sync if configured
        if self.config.auto_sync_on_startup {
            self.start_periodic_sync(ctx);

            // Trigger immediate sync on startup
            ctx.address().do_send(InitiateSync {
                host: None,
                reason: "startup".to_string(),
            });
        }
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.stop_periodic_sync();
        info!("TimeSyncActor stopped");
    }
}

/// Message: Get current time offset
#[derive(Message)]
#[rtype(result = "i64")]
pub struct GetOffset;

impl Handler<GetOffset> for TimeSyncActor {
    type Result = i64;

    fn handle(&mut self, _msg: GetOffset, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        engine.state().local_offset().as_i64()
    }
}

/// Message: Get offset for a specific host
#[derive(Message)]
#[rtype(result = "i64")]
pub struct GetOffsetForHost {
    pub host: IpAddr,
}

impl Handler<GetOffsetForHost> for TimeSyncActor {
    type Result = i64;

    fn handle(&mut self, msg: GetOffsetForHost, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        engine.state().local_offset_for_host(msg.host).as_i64()
    }
}

/// Message: Record a time sync sample
#[derive(Message)]
#[rtype(result = "()")]
pub struct RecordSample {
    pub offset_us: i64,
    pub rtt_us: u64,
}

impl Handler<RecordSample> for TimeSyncActor {
    type Result = ();

    fn handle(&mut self, msg: RecordSample, _ctx: &mut Self::Context) -> Self::Result {
        use buckwild_common::engines::time_sync::SyncSample;
        use buckwild_common::protocol::types::{RoundTripTime, Score};
        use std::time::Duration;

        let engine = self.engine.read();
        let sample = SyncSample {
            time_offset: TimeOffset::new(msg.offset_us),
            network_delay: Duration::from_micros(msg.rtt_us / 2),
            round_trip_time: RoundTripTime::from_nanos(msg.rtt_us * 1000),
            timestamp: MicrosecondTimestamp::now(),
            quality: Score::new(100.0),
            t1: MicrosecondTimestamp::new(0),
            t2: MicrosecondTimestamp::new(msg.offset_us as u64),
            t3: MicrosecondTimestamp::new(msg.offset_us as u64 + 10),
            t4: MicrosecondTimestamp::new(msg.rtt_us),
        };
        engine.state().add_sync_sample(sample);
    }
}

/// Message: Check if resync is needed
#[derive(Message)]
#[rtype(result = "bool")]
pub struct NeedsResync;

impl Handler<NeedsResync> for TimeSyncActor {
    type Result = bool;

    fn handle(&mut self, _msg: NeedsResync, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        !engine.is_sync_healthy()
    }
}

/// Message: Check if resync is needed for a specific host
#[derive(Message)]
#[rtype(result = "bool")]
pub struct NeedsResyncForHost {
    pub host: IpAddr,
}

impl Handler<NeedsResyncForHost> for TimeSyncActor {
    type Result = bool;

    fn handle(&mut self, msg: NeedsResyncForHost, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        !engine.is_sync_healthy_for_host(msg.host)
    }
}

/// Message: Periodic sync trigger
#[derive(Message)]
#[rtype(result = "()")]
pub struct PeriodicSync;

impl Handler<PeriodicSync> for TimeSyncActor {
    type Result = ();

    fn handle(&mut self, _msg: PeriodicSync, ctx: &mut Self::Context) -> Self::Result {
        debug!("Periodic time sync triggered");
        ctx.address().do_send(InitiateSync {
            host: None,
            reason: "periodic".to_string(),
        });
    }
}

/// Message: Initiate time synchronization
#[derive(Message)]
#[rtype(result = "Result<TimeOffset, String>")]
pub struct InitiateSync {
    /// Target host (None for default/global sync)
    pub host: Option<IpAddr>,
    /// Reason for sync (for logging)
    pub reason: String,
}

impl Handler<InitiateSync> for TimeSyncActor {
    type Result = ResponseActFuture<Self, Result<TimeOffset, String>>;

    fn handle(&mut self, msg: InitiateSync, _ctx: &mut Self::Context) -> Self::Result {
        let engine = Arc::clone(&self.engine);
        let host = msg.host;
        let reason = msg.reason;

        info!(
            host = ?host,
            reason = %reason,
            "Initiating time synchronization"
        );

        Box::pin(
            async move {
                // Placeholder: In a real implementation, these callbacks would send/receive
                // sync packets via the session manager. For now, we simulate successful sync.
                let send_request = |_req: SyncRequest| -> bool {
                    debug!("Sending time sync request (placeholder)");
                    true
                };

                let receive_response = |_nonce: ChallengeNonce| -> Option<SyncResponse> {
                    debug!("Receiving time sync response (placeholder)");
                    // Simulate a response for placeholder purposes
                    // Timestamps must be strictly ordered: t1 < t2 < t3 < t4
                    // The engine captures t1 before calling us, and t4 after we return.
                    // Strategy:
                    // - Capture now_us for t2 and t3 (now_us > t1 since time has passed)
                    // - t2 = now_us, t3 = now_us + 1 (ensures t2 < t3)
                    // - Sleep after capturing timestamps so t4 will be > t3
                    let now_us = MicrosecondTimestamp::now().as_u64();
                    let response = SyncResponse {
                        peer_timestamp: buckwild_common::protocol::types::Timestamp::now(),
                        // t2: peer receive time
                        peer_precision: MicrosecondTimestamp::new(now_us),
                        local_timestamp: buckwild_common::protocol::types::Timestamp::now(),
                        // t3: peer send time - +1us ensures t2 < t3
                        local_precision: MicrosecondTimestamp::new(now_us + 1),
                    };
                    // Sleep to ensure t4 (captured after return) > t3 (now_us + 1)
                    std::thread::sleep(std::time::Duration::from_micros(10));
                    Some(response)
                };

                let result = if let Some(host_addr) = host {
                    engine
                        .write()
                        .execute_precision_time_sync_for_host(
                            host_addr,
                            send_request,
                            receive_response,
                        )
                        .await
                } else {
                    engine
                        .write()
                        .execute_precision_time_sync(send_request, receive_response)
                        .await
                };

                match result {
                    Ok(offset) => {
                        info!(
                            offset_ns = offset.as_nanos(),
                            host = ?host,
                            reason = %reason,
                            "Time synchronization completed successfully"
                        );
                        Ok(offset)
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            host = ?host,
                            reason = %reason,
                            "Time synchronization failed"
                        );
                        Err(format!("Time sync failed: {}", e))
                    }
                }
            }
            .into_actor(self),
        )
    }
}

/// Message: Process incoming sync request
#[derive(Message)]
#[rtype(result = "Option<SyncResponse>")]
pub struct ProcessSyncRequest {
    pub request: SyncRequest,
}

impl Handler<ProcessSyncRequest> for TimeSyncActor {
    type Result = Option<SyncResponse>;

    fn handle(&mut self, msg: ProcessSyncRequest, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        engine.process_sync_request(&msg.request)
    }
}

/// Message: Monitor synchronization health
#[derive(Message)]
#[rtype(result = "bool")]
pub struct MonitorSync;

impl Handler<MonitorSync> for TimeSyncActor {
    type Result = bool;

    fn handle(&mut self, _msg: MonitorSync, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        engine.monitor_synchronization()
    }
}

/// Message: Monitor synchronization health for a specific host
#[derive(Message)]
#[rtype(result = "bool")]
pub struct MonitorSyncForHost {
    pub host: IpAddr,
}

impl Handler<MonitorSyncForHost> for TimeSyncActor {
    type Result = bool;

    fn handle(&mut self, msg: MonitorSyncForHost, _ctx: &mut Self::Context) -> Self::Result {
        let engine = self.engine.read();
        engine.monitor_synchronization_for_host(msg.host)
    }
}

impl DaemonActor for TimeSyncActor {
    fn name(&self) -> &'static str {
        "time-sync"
    }

    fn is_healthy(&self) -> bool {
        let engine = self.engine.read();
        engine.is_sync_healthy()
    }
}

impl Handler<HealthCheck> for TimeSyncActor {
    type Result = bool;

    fn handle(&mut self, _msg: HealthCheck, _ctx: &mut Self::Context) -> Self::Result {
        self.is_healthy()
    }
}

impl Handler<Shutdown> for TimeSyncActor {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, _msg: Shutdown, _ctx: &mut Self::Context) -> Self::Result {
        info!("TimeSyncActor shutting down");

        self.stop_periodic_sync();

        let engine = Arc::clone(&self.engine);
        Box::pin(
            async move {
                if let Err(e) = engine.read().shutdown().await {
                    error!(error = %e, "Error during time sync engine shutdown");
                }
            }
            .into_actor(self)
            .map(|_, _act, ctx| {
                ctx.stop();
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a TimeSyncActor for testing with auto_sync disabled
    /// This prevents the actor from blocking on InitiateSync during tests
    fn test_actor() -> TimeSyncActor {
        TimeSyncActor::with_config(TimeSyncConfig {
            auto_sync_on_startup: false,
            ..TimeSyncConfig::default()
        })
    }

    #[actix::test]
    async fn test_time_sync_actor_spawn() {
        let actor = test_actor();
        let addr = actor.start();
        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_time_sync_actor_offset() {
        let actor = test_actor();
        let addr = actor.start();

        let result = addr.send(GetOffset).await;
        assert!(
            result.is_ok(),
            "GetOffset message failed: {:?}",
            result.err()
        );

        let offset = result.ok().expect("Failed to get result");
        assert_eq!(offset, 0, "Initial offset should be 0");
    }

    #[actix::test]
    async fn test_time_sync_actor_sample() {
        let actor = test_actor();
        let addr = actor.start();

        let sample_msg = RecordSample {
            offset_us: 1000,
            rtt_us: 5000,
        };

        let result = addr.send(sample_msg).await;
        assert!(
            result.is_ok(),
            "RecordSample message failed: {:?}",
            result.err()
        );

        let offset_result = addr.send(GetOffset).await;
        assert!(
            offset_result.is_ok(),
            "GetOffset after sample failed: {:?}",
            offset_result.err()
        );
    }

    #[actix::test]
    async fn test_time_sync_needs_resync() {
        let actor = test_actor();
        let addr = actor.start();

        let result = addr.send(NeedsResync).await;
        assert!(result.is_ok(), "NeedsResync failed");
    }

    #[actix::test]
    async fn test_time_sync_health_check() {
        let actor = test_actor();
        let addr = actor.start();

        let result = addr.send(HealthCheck).await;
        assert!(result.is_ok(), "HealthCheck failed");
    }

    #[actix::test]
    async fn test_time_sync_custom_config() {
        let config = TimeSyncConfig {
            sync_interval: Duration::from_secs(30),
            auto_sync_on_startup: false,
        };
        let actor = TimeSyncActor::with_config(config);
        let addr = actor.start();

        assert!(addr.connected());
    }

    #[actix::test]
    async fn test_time_sync_offset_for_host() {
        let actor = test_actor();
        let addr = actor.start();

        let host = "127.0.0.1".parse::<IpAddr>().expect("Invalid IP");
        let result = addr.send(GetOffsetForHost { host }).await;
        assert!(result.is_ok(), "GetOffsetForHost failed");
        assert_eq!(result.ok().unwrap_or(0), 0, "Initial offset should be 0");
    }

    #[actix::test]
    async fn test_time_sync_monitor() {
        let actor = test_actor();
        let addr = actor.start();

        let result = addr.send(MonitorSync).await;
        assert!(result.is_ok(), "MonitorSync failed");
    }

    #[actix::test]
    async fn test_time_sync_shutdown() {
        let actor = test_actor();
        let addr = actor.start();

        let result = addr.send(Shutdown).await;
        assert!(result.is_ok(), "Shutdown failed");
    }
}
