use super::{
    CheckedJson, auth,
    error::{Error, Result},
};
use crate::{
    App,
    domain::access::Permission,
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
pub async fn list(
    State(app): State<App>,
    Path(p): Path<String>,
    h: HeaderMap,
) -> Result<Json<Value>> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Access)).await?;
    let rows = sqlx::query(
        "SELECT id,name,permissions_json,created_at
         FROM access WHERE project_id=? AND revoked_at IS NULL ORDER BY created_at,id",
    )
    .bind(a.project_id)
    .fetch_all(&app.db)
    .await?;
    let access = rows
        .iter()
        .map(|r| {
            Ok(json!({
                "id": r.get::<String,_>("id"), "name": r.get::<String,_>("name"),
                "permissions": auth::stored_permissions(r.get("permissions_json"))?,
                "created_at": rfc(r.get("created_at"))
            }))
        })
        .collect::<Result<Vec<Value>>>()?;
    Ok(Json(json!({"access":access})))
}
pub async fn revoke(
    State(app): State<App>,
    Path((p, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Result<StatusCode> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Access)).await?;
    let n = sqlx::query(
        "UPDATE access SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND project_id=?",
    )
    .bind(now())
    .bind(&id)
    .bind(a.project_id)
    .execute(&app.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(Error::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    name: String,
    permissions: Vec<Permission>,
}
pub async fn create(
    State(app): State<App>,
    Path(p): Path<String>,
    h: HeaderMap,
    CheckedJson(b): CheckedJson<Create>,
) -> Result<(StatusCode, Json<Value>)> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Access)).await?;
    auth::valid_name(&b.name)?;
    crate::domain::access::validate(&b.permissions)
        .map_err(|_| Error::bad("invalid_permissions"))?;
    // A credential can never mint more authority than it holds itself.
    if b.permissions.iter().any(|x| !a.permissions.contains(x)) {
        return Err(Error::denied());
    }
    let mut tx = crate::db::write(&app.db).await?;
    let (id, token) = auth::issue(&mut tx, a.project_id, &b.name, &b.permissions).await?;
    let created_at: i64 = sqlx::query_scalar("SELECT created_at FROM access WHERE id=?")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id, "name": b.name, "permissions": b.permissions,
            "created_at": rfc(created_at), "token": token
        })),
    ))
}
