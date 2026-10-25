pub mod config;
pub mod crypto;
pub mod db;
pub mod delivery;
pub mod domain;
pub mod http;
pub mod scanner;
pub mod security;
pub mod time;
pub mod workers;
use sqlx::SqlitePool;
use std::sync::{Arc, atomic::AtomicBool};
use zeroize::Zeroizing;
pub struct State {
    pub db: SqlitePool,
    pub config: config::Config,
    pub cursor_key: Zeroizing<[u8; 32]>,
    pub master: Zeroizing<[u8; 32]>,
    pub altcha_key: Zeroizing<String>,
    /// Set on shutdown so /readyz fails while in-flight requests finish.
    pub draining: AtomicBool,
}
pub type App = Arc<State>;
pub async fn startup(config: config::Config) -> anyhow::Result<App> {
    let db = db::connect(&config.database).await?;
    let key = security::secret::env_key("PAYROOF_ALTCHA_KEY")?;
    let app = Arc::new(State {
        db,
        config,
        cursor_key: security::secret::env_key("PAYROOF_CURSOR_KEY")?,
        master: security::secret::env_key("PAYROOF_MASTER_KEY")?,
        altcha_key: Zeroizing::new(hex::encode(*key)),
        draining: AtomicBool::new(false),
    });
    anyhow::ensure!(
        *app.cursor_key != *app.master
            && hex::encode(*app.cursor_key) != *app.altcha_key
            && hex::encode(*app.master) != *app.altcha_key,
        "keys must be distinct"
    );
    Ok(app)
}
