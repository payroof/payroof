use super::error::{Error, Result};
use crate::{App, domain::access::Permission, security::secret::hash};
use axum::http::HeaderMap;
use sqlx::Row;
pub fn bearer(h: &HeaderMap) -> Result<&str> {
    if h.get_all("authorization").iter().count() != 1 {
        return Err(Error::unauthorized());
    }
    let s = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(Error::unauthorized)?;
    if s.is_empty() || s.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(Error::unauthorized());
    }
    Ok(s)
}
pub struct Auth {
    pub project_id: i64,
    pub access_id: String,
    pub permissions: Vec<Permission>,
}
pub fn stored_permissions(raw: &str) -> Result<Vec<Permission>> {
    let p: Vec<Permission> = serde_json::from_str(raw)?;
    crate::domain::access::validate(&p).map_err(|_| Error::corrupt())?;
    Ok(p)
}
pub async fn auth(
    app: &App,
    h: &HeaderMap,
    project: Option<&str>,
    permission: Option<Permission>,
) -> Result<Auth> {
    let t = bearer(h)?;
    if !t.starts_with("prf_") || t.len() != 47 {
        return Err(Error::unauthorized());
    }
    let r = sqlx::query(
        "SELECT t.id,t.project_id,t.permissions_json,p.project
         FROM access t JOIN projects p ON p.id=t.project_id
         WHERE secret_hash=? AND revoked_at IS NULL",
    )
    .bind(hash(t))
    .fetch_optional(&app.db)
    .await?
    .ok_or_else(Error::unauthorized)?;
    if project.is_some_and(|p| p != r.get::<&str, _>("project")) {
        return Err(Error(axum::http::StatusCode::FORBIDDEN, "forbidden"));
    }
    let granted = stored_permissions(r.get("permissions_json"))?;
    if permission.is_some_and(|p| !granted.contains(&p)) {
        return Err(Error::denied());
    }
    Ok(Auth {
        project_id: r.get("project_id"),
        access_id: r.get("id"),
        permissions: granted,
    })
}
/// A token's display name, chosen by the wallet or app that holds it.
pub fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 100
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(Error::bad("invalid_name"));
    }
    Ok(())
}
pub async fn issue(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    project: i64,
    name: &str,
    p: &[Permission],
) -> Result<(String, String)> {
    crate::domain::access::validate(p).map_err(|_| Error::bad("invalid_permissions"))?;
    valid_name(name)?;
    let token = crate::security::secret::id("prf_")?;
    let id = crate::security::secret::id("acc_")?;
    sqlx::query(
        "INSERT INTO access(id,project_id,secret_hash,name,permissions_json,created_at)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(project)
    .bind(hash(&token))
    .bind(name)
    .bind(serde_json::to_string(p)?)
    .bind(crate::time::now())
    .execute(&mut **tx)
    .await?;
    Ok((id, token))
}
