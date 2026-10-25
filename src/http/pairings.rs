use super::{
    CheckedJson, auth,
    error::{Error, Result},
};
use crate::{
    App,
    domain::access::{Permission, validate},
    security::secret::{hash, id},
    time::{now, rfc},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    name: String,
    permissions: Vec<Permission>,
    altcha: altcha::Payload,
}
pub async fn create(
    State(app): State<App>,
    CheckedJson(b): CheckedJson<Create>,
) -> Result<(StatusCode, Json<Value>)> {
    validate(&b.permissions).map_err(|_| Error::bad("invalid_permissions"))?;
    auth::valid_name(&b.name)?;
    super::altcha::consume(&app, &b.altcha, "pairing").await?;
    let mut tx = crate::db::write(&app.db).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pairings WHERE expires_at>? AND status IN ('pending','approved')",
    )
    .bind(now())
    .fetch_one(&mut *tx)
    .await?;
    if count >= app.config.limits.pairing_capacity {
        return Err(Error::unavailable("pairing_capacity"));
    }
    let secret = id("pairsec_")?;
    let id = id("pair_")?;
    sqlx::query(
        "INSERT INTO pairings(id_hash,poll_hash,name,permissions_json,status,expires_at)
         VALUES(?,?,?,?,'pending',?)",
    )
    .bind(hash(&id))
    .bind(hash(&secret))
    .bind(&b.name)
    .bind(serde_json::to_string(&b.permissions)?)
    .bind(now() + 300)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"id":id,"poll_secret":secret,"url":format!("{}/v1/pairings/{id}",app.config.origin.trim_end_matches('/')),"expires_in":300,"interval":5}),
        ),
    ))
}
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>> {
    let r =
        sqlx::query("SELECT name,permissions_json,status,expires_at FROM pairings WHERE id_hash=?")
            .bind(hash(&id))
            .fetch_optional(&app.db)
            .await?
            .ok_or_else(Error::not_found)?;
    if r.get::<i64, _>("expires_at") <= now() {
        return Err(Error::gone("pairing_expired"));
    }
    let permissions = auth::stored_permissions(r.get("permissions_json"))?;
    Ok(Json(
        json!({"id":id,"name":r.get::<String,_>("name"),"permissions":permissions,"status":r.get::<String,_>("status"),"expires_at":rfc(r.get("expires_at"))}),
    ))
}
pub async fn approve(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode> {
    if !body.is_empty() {
        return Err(Error::bad("unexpected_body"));
    }
    let a = auth::auth(&app, &h, None, Some(Permission::Access)).await?;
    let mut tx = crate::db::write(&app.db).await?;
    let pairing = sqlx::query("SELECT status,expires_at FROM pairings WHERE id_hash=?")
        .bind(hash(&id))
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(Error::not_found)?;
    if pairing.get::<i64, _>("expires_at") <= now() {
        return Err(Error::gone("pairing_expired"));
    }
    if pairing.get::<String, _>("status") != "pending" {
        return Err(Error::conflict("pairing_unavailable"));
    }
    let n = sqlx::query(
        "UPDATE pairings SET status='approved',project_id=?,approver=?
         WHERE id_hash=? AND status='pending' AND expires_at>?",
    )
    .bind(a.project_id)
    .bind(a.access_id)
    .bind(hash(&id))
    .bind(now())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(Error::conflict("pairing_unavailable"));
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn token(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Response> {
    let secret = auth::bearer(&h)?;
    let mut tx = crate::db::write(&app.db).await?;
    let r = sqlx::query(
        "SELECT name,permissions_json,status,project_id,approver,expires_at,last_poll
         FROM pairings WHERE id_hash=? AND poll_hash=?",
    )
    .bind(hash(&id))
    .bind(hash(secret))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(Error::unauthorized)?;
    if r.get::<i64, _>("expires_at") <= now() {
        return Err(Error::gone("pairing_expired"));
    }
    let status: String = r.get("status");
    if status == "consumed" {
        return Err(Error::gone("pairing_consumed"));
    }
    if now() - r.get::<i64, _>("last_poll") < 5 {
        return Err(Error(StatusCode::TOO_MANY_REQUESTS, "slow_down"));
    }
    sqlx::query("UPDATE pairings SET last_poll=? WHERE id_hash=?")
        .bind(now())
        .bind(hash(&id))
        .execute(&mut *tx)
        .await?;
    match status.as_str() {
        "pending" => {
            tx.commit().await?;
            Ok((
                StatusCode::ACCEPTED,
                [("retry-after", "5")],
                Json(json!({"status":"pending","retry_after":5})),
            )
                .into_response())
        }
        "approved" => {
            let pid: i64 = r.get("project_id");
            let approver: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM access WHERE id=? AND revoked_at IS NULL)",
            )
            .bind(r.get::<String, _>("approver"))
            .fetch_one(&mut *tx)
            .await?;
            if !approver {
                return Err(Error::conflict("pairing_approver_revoked"));
            }
            let p = auth::stored_permissions(r.get("permissions_json"))?;
            let (_, token) = auth::issue(&mut tx, pid, r.get("name"), &p).await?;
            let project: String = sqlx::query_scalar("SELECT project FROM projects WHERE id=?")
                .bind(pid)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query("UPDATE pairings SET status='consumed' WHERE id_hash=?")
                .bind(hash(&id))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(
                Json(json!({"status":"approved","project":project,"token":token,"permissions":p}))
                    .into_response(),
            )
        }
        _ => Err(Error::corrupt()),
    }
}
