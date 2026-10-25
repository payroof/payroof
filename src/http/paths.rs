use super::{
    auth,
    error::{Error, Result},
};
use crate::{App, crypto::cursor, domain::access::Permission};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::Row;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    scope: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}
pub async fn get(
    State(app): State<App>,
    Path(p): Path<String>,
    Query(q): Query<Page>,
    h: HeaderMap,
) -> Result<Response> {
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::Paths)).await?;
    crate::security::limits::allow(
        &app,
        &a.access_id,
        "paths",
        60,
        app.config.limits.paths_per_minute,
    )
    .await?;
    let scope = q.scope.as_deref().unwrap_or("confirmed");
    let limit = q.limit.unwrap_or(200.min(app.config.limits.path_page));
    if !["all", "confirmed"].contains(&scope) || !(1..=app.config.limits.path_page).contains(&limit)
    {
        return Err(Error::bad("invalid_page"));
    }
    let seq = if let Some(c) = q.cursor {
        cursor::decode(&*app.cursor_key, a.project_id, scope, &c)
            .map_err(|_| Error::bad("invalid_cursor"))?
    } else {
        0
    };
    let sql = if scope == "all" {
        "SELECT address_index,allocated_sequence AS seq FROM receive_mappings WHERE project_id=? AND allocated_sequence>? ORDER BY allocated_sequence LIMIT ?"
    } else {
        "SELECT address_index,confirmed_sequence AS seq FROM receive_mappings WHERE project_id=? AND confirmed_sequence>? ORDER BY confirmed_sequence LIMIT ?"
    };
    let rows = sqlx::query(sql)
        .bind(a.project_id)
        .bind(seq)
        .bind(limit + 1)
        .fetch_all(&app.db)
        .await?;
    let root: String = sqlx::query_scalar("SELECT root_json FROM watch_roots WHERE project_id=?")
        .bind(a.project_id)
        .fetch_one(&app.db)
        .await?;
    let root = super::projects::stored_root(&root)?;
    let page = &rows[..rows.len().min(limit as usize)];
    let last = page.last().map_or(seq, |r| r.get("seq"));
    let body: String = page
        .iter()
        .map(|r| format!("{}/{}\n", root.path, r.get::<i64, _>("address_index")))
        .collect();
    Ok((
        [
            ("content-type", "text/plain; charset=utf-8".to_string()),
            (
                "payroof-next-cursor",
                cursor::encode(&*app.cursor_key, a.project_id, scope, last),
            ),
            (
                "payroof-has-more",
                (rows.len() > limit as usize).to_string(),
            ),
        ],
        body,
    )
        .into_response())
}
