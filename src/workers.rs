use crate::{App, time::now};
use std::time::{Duration, Instant};
/// How old a worker heartbeat may be for `/readyz` (the interval below plus slack).
pub const HEARTBEAT_STALE: i64 = 90;
/// Expired rows: (statement, seconds kept past expiry).
const CLEANUP: [(&str, i64); 4] = [
    ("DELETE FROM pairings WHERE expires_at<?", 86400),
    ("DELETE FROM recovery_challenges WHERE expires_at<?", 86400),
    ("DELETE FROM altcha_replay WHERE expires_at<?", 300),
    ("DELETE FROM rate_limits WHERE expires_at<?", 300),
];
/// One scanner per configured chain, plus webhook delivery and cleanup.
pub fn start(app: App) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles: Vec<_> = app
        .config
        .chains
        .iter()
        .map(|chain| tokio::spawn(scan(app.clone(), chain.clone())))
        .collect();
    handles.push(tokio::spawn(async move {
        let mut beat = Beat::new("delivery");
        let mut failing = false;
        loop {
            let result = crate::delivery::tick(&app).await;
            beat.beat(&app, result.is_ok()).await;
            match &result {
                Err(error) if !failing => tracing::error!(%error, "delivery worker unavailable"),
                Ok(()) if failing => tracing::info!("delivery worker recovered"),
                _ => {}
            }
            failing = result.is_err();
            for (sql, grace) in CLEANUP {
                if let Err(error) = sqlx::query(sql).bind(now() - grace).execute(&app.db).await {
                    tracing::error!(%error, "cleanup failed");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }));
    handles
}
/// Healthy workers rewrite their heartbeat at most this often; a change of health is
/// written at once. `/readyz` accepts heartbeats up to `HEARTBEAT_STALE` old.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
/// Pause between scan steps while blocks remain to catch up on.
const CATCH_UP_PAUSE: Duration = Duration::from_millis(50);
/// Pause after an error that is not an RPC outage.
const ERROR_PAUSE: Duration = Duration::from_secs(5);

/// A worker's throttled heartbeat: avoids a database write on every tick.
struct Beat {
    name: String,
    last: Option<(bool, Instant)>,
}
impl Beat {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            last: None,
        }
    }
    async fn beat(&mut self, app: &App, healthy: bool) {
        let due = match self.last {
            Some((was, at)) => was != healthy || at.elapsed() >= HEARTBEAT_INTERVAL,
            None => true,
        };
        if due {
            heartbeat(app, &self.name, healthy).await;
            self.last = Some((healthy, Instant::now()));
        }
    }
}
async fn scan(app: App, chain: crate::config::Chain) {
    let rpc = match crate::scanner::rpc::Rpc::new(&chain) {
        Ok(rpc) => rpc,
        Err(error) => {
            tracing::error!(chain=%chain.id, %error, "scanner initialization failed");
            return;
        }
    };
    let mut beat = Beat::new(format!("scanner:{}", chain.id));
    let mut last_error = String::new();
    // The starting height may need the RPC; keep trying until it answers.
    while let Err(error) = crate::scanner::init(&app, &chain, &rpc).await {
        beat.beat(&app, false).await;
        if last_error != error.to_string() {
            last_error = error.to_string();
            tracing::error!(chain=%chain.id, %error, "scanner start unavailable");
        }
        tokio::time::sleep(retry_pause(&rpc, &error)).await;
    }
    let mut state = crate::scanner::ScanState::default();
    // None until the first step; then whether the last step succeeded.
    let mut ok: Option<bool> = None;
    last_error.clear();
    loop {
        let result = crate::scanner::scan(
            &app,
            &chain,
            &rpc,
            &mut state,
            crate::scanner::MAX_BLOCKS_PER_STEP,
        )
        .await;
        let pause = match &result {
            Ok(outcome) => {
                beat.beat(&app, true).await;
                if ok == Some(false) {
                    tracing::info!(chain=%chain.id, "scanner recovered");
                }
                ok = Some(true);
                last_error.clear();
                if outcome.behind {
                    CATCH_UP_PAUSE
                } else {
                    chain.poll_interval()
                }
            }
            Err(error) => {
                // Log and mark the chain unhealthy once per state or error change.
                if ok != Some(false) || last_error != error.to_string() {
                    last_error = error.to_string();
                    let _ = sqlx::query("UPDATE chain_state SET healthy=0 WHERE chain=?")
                        .bind(&chain.id)
                        .execute(&app.db)
                        .await;
                    tracing::error!(chain=%chain.id, %error, "scanner unavailable or reorg requires review");
                }
                ok = Some(false);
                state.healthy_marked = false;
                beat.beat(&app, false).await;
                retry_pause(&rpc, error)
            }
        };
        tokio::time::sleep(pause).await;
    }
}
/// Waits for the earliest endpoint recovery when all are cooling down, else a fixed pause.
fn retry_pause(rpc: &crate::scanner::rpc::Rpc, error: &anyhow::Error) -> Duration {
    match error.downcast_ref::<crate::scanner::rpc::Unavailable>() {
        Some(unavailable) => unavailable
            .retry_in
            .max(rpc.retry_in().unwrap_or_default())
            .clamp(Duration::from_secs(1), Duration::from_secs(60)),
        None => ERROR_PAUSE,
    }
}
pub(crate) async fn heartbeat(app: &App, name: &str, healthy: bool) {
    let heartbeat = sqlx::query(
        "INSERT INTO worker_state(name,healthy,heartbeat) VALUES(?,?,?)
         ON CONFLICT(name) DO UPDATE
         SET healthy=excluded.healthy,heartbeat=excluded.heartbeat",
    )
    .bind(name)
    .bind(healthy)
    .bind(now())
    .execute(&app.db)
    .await;
    if heartbeat.is_err() {
        tracing::error!("worker heartbeat unavailable");
    }
}
