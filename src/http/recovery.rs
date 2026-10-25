use super::{
    CheckedJson, auth,
    error::{Error, Result},
    projects::RecoveryKey,
};
use crate::{
    App,
    domain::access::ALL,
    security::secret::{hash, id, random},
    time::now,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    recovery_key: RecoveryKey,
    altcha: altcha::Payload,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Complete {
    signature: String,
    name: String,
}
/// Begins recovery for the project of a recovery key. A key owns at most one project,
/// so the key alone finds it; its name is returned only once the signature proves the
/// key (`complete`).
pub async fn challenge(
    State(app): State<App>,
    CheckedJson(b): CheckedJson<Challenge>,
) -> Result<Json<Value>> {
    super::altcha::consume(&app, &b.altcha, "recovery").await?;
    let pk = b.recovery_key.bytes()?;
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE recovery_public_key=?")
        .bind(pk.to_vec())
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(Error::not_found)?;
    let id = id("rcv_")?;
    let challenge = URL_SAFE_NO_PAD.encode(random::<32>()?);
    sqlx::query(
        "INSERT INTO recovery_challenges(id_hash,project_id,challenge,expires_at) VALUES(?,?,?,?)",
    )
    .bind(hash(&id))
    .bind(pid)
    .bind(&challenge)
    .bind(now() + 120)
    .execute(&app.db)
    .await?;
    Ok(Json(
        json!({"id":id,"challenge":challenge,"expires_in":120}),
    ))
}
pub async fn complete(
    State(app): State<App>,
    Path(id): Path<String>,
    CheckedJson(b): CheckedJson<Complete>,
) -> Result<Json<Value>> {
    auth::valid_name(&b.name)?;
    let mut tx = crate::db::write(&app.db).await?;
    let r = sqlx::query(
        "SELECT c.project_id,c.challenge,c.used_at,c.expires_at,p.project,p.recovery_public_key
         FROM recovery_challenges c JOIN projects p ON p.id=c.project_id WHERE c.id_hash=?",
    )
    .bind(hash(&id))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(Error::not_found)?;
    if r.get::<Option<i64>, _>("used_at").is_some() {
        return Err(Error::gone("recovery_consumed"));
    }
    if r.get::<i64, _>("expires_at") <= now() {
        return Err(Error::gone("recovery_challenge_expired"));
    }
    let invalid = || Error(StatusCode::UNAUTHORIZED, "invalid_signature");
    let bytes = URL_SAFE_NO_PAD
        .decode(&b.signature)
        .map_err(|_| invalid())?;
    let signature = ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| invalid())?;
    let key = r
        .get::<Vec<u8>, _>("recovery_public_key")
        .try_into()
        .ok()
        .and_then(|pk: [u8; 32]| ed25519_dalek::VerifyingKey::from_bytes(&pk).ok())
        .ok_or_else(Error::corrupt)?;
    let project: String = r.get("project");
    let challenge: String = r.get("challenge");
    // The wallet signs the origin it reached this server at: the configured origin or an alias.
    let signed = app.config.origins().any(|origin| {
        let message = crate::crypto::recovery::recovery_message(origin, &id, &challenge);
        key.verify_strict(message.as_bytes(), &signature).is_ok()
    });
    if !signed {
        return Err(invalid());
    }
    sqlx::query("UPDATE recovery_challenges SET used_at=? WHERE id_hash=?")
        .bind(now())
        .bind(hash(&id))
        .execute(&mut *tx)
        .await?;
    let (_, token) = auth::issue(&mut tx, r.get("project_id"), &b.name, &ALL).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"project":project,"token":token,"permissions":ALL}),
    ))
}
