use crate::{App, time::now};
use std::time::Duration;
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
        loop {
            let result = crate::delivery::tick(&app).await;
            heartbeat(&app, "delivery", result.is_ok()).await;
            if let Err(error) = &result {
                tracing::error!(%error, "delivery worker unavailable");
            }
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
async fn scan(app: App, chain: crate::config::Chain) {
    let Ok(http) = crate::scanner::client() else {
        tracing::error!(chain=%chain.id, "scanner initialization failed");
        return;
    };
    // The starting height may need the RPC; keep trying until it answers.
    while let Err(error) = crate::scanner::init(&app, &chain, &http).await {
        heartbeat(&app, &format!("scanner:{}", chain.id), false).await;
        tracing::error!(chain=%chain.id, %error, "scanner start unavailable");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    loop {
        let result = crate::scanner::step(&app, &chain, &http).await;
        heartbeat(&app, &format!("scanner:{}", chain.id), result.is_ok()).await;
        if let Err(error) = &result {
            let _ = sqlx::query("UPDATE chain_state SET healthy=0 WHERE chain=?")
                .bind(&chain.id)
                .execute(&app.db)
                .await;
            tracing::error!(chain=%chain.id, %error, "scanner unavailable or reorg requires review");
        }
        let pause = if result.is_ok() { 500 } else { 5000 };
        tokio::time::sleep(Duration::from_millis(pause)).await;
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
