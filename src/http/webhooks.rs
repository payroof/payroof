use super::{
    CheckedJson, auth,
    error::{Error, Result},
};
use crate::{
    App,
    domain::access::Permission,
    security::secret::{id, seal},
    time::{now, rfc},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    url: String,
    events: Vec<String>,
}
const MAX_WEBHOOKS: i64 = 10;
fn validate(events: &[String]) -> Result<()> {
    if events.is_empty()
        || events.len() > 2
        || events.iter().any(|e| e != "seen" && e != "confirmed")
        || events.len() == 2 && events[0] == events[1]
    {
        return Err(Error::bad("invalid_events"));
    }
    Ok(())
}
pub fn aad(id: &str) -> String {
    format!("payroof:v1:webhook:{id}:secret")
}
pub async fn create(
    State(app): State<App>,
    Path(p): Path<String>,
    h: HeaderMap,
    CheckedJson(b): CheckedJson<Create>,
) -> Result<(StatusCode, Json<Value>)> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Webhooks)).await?;
    validate(&b.events)?;
    crate::delivery::ssrf::validate_webhook(&b.url, app.config.development)
        .await
        .map_err(|_| Error::bad("invalid_webhook_url"))?;
    let mut tx = crate::db::write(&app.db).await?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE project_id=?")
        .bind(a.project_id)
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_WEBHOOKS {
        return Err(Error::conflict("webhook_limit"));
    }
    let secret = id("whsec_")?;
    let id = id("wh_")?;
    sqlx::query(
        "INSERT INTO webhooks
         (id,project_id,url,events_json,secret_ciphertext,created_at)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(a.project_id)
    .bind(&b.url)
    .bind(serde_json::to_string(&b.events)?)
    .bind(seal(&app.master, aad(&id).as_bytes(), secret.as_bytes())?)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"url":b.url,"events":b.events,"secret":secret})),
    ))
}
pub async fn list(
    State(app): State<App>,
    Path(p): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Webhooks)).await?;
    let rows = sqlx::query("SELECT id,url,events_json,created_at FROM webhooks WHERE project_id=?")
        .bind(a.project_id)
        .fetch_all(&app.db)
        .await?;
    let webhooks = rows
        .iter()
        .map(|r| {
            let events: Vec<String> = serde_json::from_str(r.get("events_json"))?;
            validate(&events).map_err(|_| Error::corrupt())?;
            Ok(json!({
                "id": r.get::<String,_>("id"), "url": r.get::<String,_>("url"),
                "events": events,
                "created_at": rfc(r.get("created_at"))
            }))
        })
        .collect::<Result<Vec<Value>>>()?;
    Ok(Json(json!({"webhooks":webhooks})))
}
pub async fn delete(
    State(app): State<App>,
    Path((p, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Result<StatusCode> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Webhooks)).await?;
    let n = sqlx::query("DELETE FROM webhooks WHERE id=? AND project_id=?")
        .bind(id)
        .bind(a.project_id)
        .execute(&app.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}
