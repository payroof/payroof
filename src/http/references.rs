use super::{
    auth,
    error::{Error, Result},
};
use crate::{
    App,
    crypto::bip32::{DeriveError, derive_evm_address},
    domain::{access::Permission, identifiers},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use sqlx::Row;
pub async fn allocate(
    State(app): State<App>,
    Path((p, reference)): Path<(String, String)>,
    h: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    if !body.is_empty() {
        return Err(Error::bad("unexpected_body"));
    }
    if !identifiers::reference(&reference) {
        return Err(Error::bad("invalid_reference"));
    }
    let a = auth::auth(&app, &h, Some(&p), Some(Permission::References)).await?;
    crate::security::limits::allow(
        &app,
        &a.access_id,
        "allocate",
        60,
        app.config.limits.allocations_per_minute,
    )
    .await?;
    let mut tx = crate::db::write(&app.db).await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT address FROM receive_mappings WHERE project_id=? AND reference=?",
    )
    .bind(a.project_id)
    .bind(&reference)
    .fetch_optional(&mut *tx)
    .await?;
    let is_new = existing.is_none();
    let address = if let Some(address) = existing {
        address
    } else {
        let r = sqlx::query(
            "SELECT p.next_address_index,w.root_json FROM projects p
             JOIN watch_roots w ON w.project_id=p.id WHERE p.id=?",
        )
        .bind(a.project_id)
        .fetch_one(&mut *tx)
        .await?;
        let root = super::projects::stored_root(r.get("root_json"))?;
        let mut index: i64 = r.get("next_address_index");
        let address = loop {
            if index >= 1 << 31 {
                return Err(Error::conflict("derivation_exhausted"));
            }
            match derive_evm_address(&root.key, index as u32) {
                Ok(a) => break a,
                Err(DeriveError::InvalidChild) => index += 1,
                Err(_) => return Err(Error::corrupt()),
            }
        };
        sqlx::query(
            "INSERT INTO receive_mappings
             (project_id,reference,address_index,address,allocated_sequence,created_at)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(a.project_id)
        .bind(&reference)
        .bind(index)
        .bind(&address)
        .bind(index + 1)
        .bind(crate::time::now())
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE projects SET next_address_index=? WHERE id=?")
            .bind(index + 1)
            .bind(a.project_id)
            .execute(&mut *tx)
            .await?;
        address
    };
    tx.commit().await?;
    let destinations: Vec<Value> = app
        .config
        .chains
        .iter()
        .map(|c| json!({"chain":c.id,"address":address}))
        .collect();
    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(json!({"project":p,"reference":reference,"destinations":destinations})),
    ))
}
