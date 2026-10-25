use super::{
    CheckedJson, auth,
    error::{Error, Result},
};
use crate::{
    App,
    domain::{access::ALL, identifiers, watch_root::WatchRoot},
    time::{now, rfc},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKey {
    algorithm: String,
    public_key: String,
}
impl RecoveryKey {
    /// The raw Ed25519 public key.
    pub(super) fn bytes(&self) -> Result<[u8; 32]> {
        if self.algorithm != "ed25519" {
            return Err(Error::bad("invalid_recovery_key"));
        }
        URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| Error::bad("invalid_recovery_key"))
    }
}
/// A watch root as stored for a project; it was validated when the project was created.
pub(super) fn stored_root(json: &str) -> Result<WatchRoot> {
    let root: WatchRoot = serde_json::from_str(json)?;
    root.validate().map_err(|_| Error::corrupt())?;
    Ok(root)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    project: String,
    recovery_key: RecoveryKey,
    watch_roots: Vec<WatchRoot>,
    altcha: altcha::Payload,
}
pub async fn create(
    State(app): State<App>,
    CheckedJson(b): CheckedJson<Create>,
) -> Result<(StatusCode, Json<Value>)> {
    if !identifiers::project(&b.project) || b.watch_roots.len() != 1 {
        return Err(Error::bad("invalid_project"));
    }
    let key = b.recovery_key.bytes()?;
    let owner = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| Error::bad("invalid_recovery_key"))?;
    if owner.is_weak() {
        return Err(Error::bad("invalid_recovery_key"));
    }
    let root = &b.watch_roots[0];
    if root.family != "eip155" {
        return Err(Error::bad("unsupported_family"));
    }
    root.validate()
        .map_err(|_| Error::bad("invalid_watch_root"))?;
    super::altcha::consume(&app, &b.altcha, "project").await?;
    let mut tx = crate::db::write(&app.db).await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE recovery_public_key=?)")
            .bind(key.to_vec())
            .fetch_one(&mut *tx)
            .await?;
    if exists {
        return Err(Error::conflict("project_exists"));
    }
    let identity = root.identity()?;
    let used: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM watch_roots WHERE root_identity=?)")
            .bind(&identity)
            .fetch_one(&mut *tx)
            .await?;
    if used {
        return Err(Error::conflict("watch_root_in_use"));
    }
    let id =
        sqlx::query("INSERT INTO projects(project,recovery_public_key,created_at) VALUES(?,?,?)")
            .bind(&b.project)
            .bind(key.to_vec())
            .bind(now())
            .execute(&mut *tx)
            .await?
            .last_insert_rowid();
    sqlx::query(
        "INSERT INTO watch_roots(project_id,root_json,fingerprint,root_identity) VALUES(?,?,?,?)",
    )
    .bind(id)
    .bind(serde_json::to_string(root)?)
    .bind(root.fingerprint()?)
    .bind(identity)
    .execute(&mut *tx)
    .await?;
    let (_, token) = auth::issue(&mut tx, id, "First wallet", &ALL).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"project":b.project,"token":token,"permissions":ALL})),
    ))
}
pub async fn view(
    State(app): State<App>,
    axum::extract::Path(p): axum::extract::Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>> {
    let a = auth::auth(&app, &h, Some(&p), None).await?;
    let r = sqlx::query(
        "SELECT w.root_json,w.fingerprint,p.created_at
         FROM watch_roots w JOIN projects p ON p.id=w.project_id WHERE p.id=?",
    )
    .bind(a.project_id)
    .fetch_one(&app.db)
    .await?;
    let root = stored_root(r.get("root_json"))?;
    // The configured chains and assets: the only ones this server watches.
    let chains: Vec<Value> = app
        .config
        .chains
        .iter()
        .map(|c| {
            let assets: Vec<Value> = c
                .assets
                .iter()
                .map(|a| json!({"id": a.id, "symbol": a.symbol, "decimals": a.decimals}))
                .collect();
            json!({"id": c.id, "name": c.name, "confirmations": c.confirmations, "assets": assets})
        })
        .collect();
    Ok(Json(
        json!({"project":p,"watch_roots":[{"family":root.family,"path":root.path,"fingerprint":r.get::<String,_>("fingerprint")}],"chains":chains,"created_at":rfc(r.get("created_at"))}),
    ))
}
