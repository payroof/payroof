pub mod ssrf;
use crate::{App, security::secret::open, time::now};
use sqlx::Row;
use std::time::Duration;
pub async fn tick(app: &App) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "SELECT d.webhook_id,d.event_id,d.attempts,w.url,w.secret_ciphertext,e.payload_json
         FROM webhook_deliveries d JOIN webhooks w ON w.id=d.webhook_id
         JOIN transfer_events e ON e.id=d.event_id
         WHERE d.sent_at IS NULL AND d.failed_at IS NULL AND d.next_attempt_at<=?
         ORDER BY d.next_attempt_at LIMIT 20",
    )
    .bind(now())
    .fetch_all(&app.db)
    .await?;
    for r in rows {
        let wid: String = r.get("webhook_id");
        let eid: String = r.get("event_id");
        let body: String = r.get("payload_json");
        let url: String = r.get("url");
        let timestamp = now();
        // Persisted-state corruption is not a network outage. Fail the worker
        // visibly instead of silently retrying invalid JSON or a broken secret.
        let _: serde_json::Value = serde_json::from_str(&body)?;
        let secret = open(
            &app.master,
            crate::http::webhooks::aad(&wid).as_bytes(),
            r.get("secret_ciphertext"),
        )?;
        let secret = crate::crypto::webhook::decode_webhook_secret(std::str::from_utf8(&secret)?)?;
        let result = async {
            let http =
                ssrf::webhook_client(&url, app.config.development, Duration::from_secs(10)).await?;
            let response = http
                .post(&url)
                .header("content-type", "application/json")
                .header("payroof-id", &eid)
                .header("payroof-timestamp", timestamp)
                .header(
                    "payroof-signature",
                    crate::crypto::webhook::sign_webhook(&secret, timestamp, body.as_bytes()),
                )
                .body(body)
                .send()
                .await?;
            Ok::<_, anyhow::Error>(response.status().as_u16())
        }
        .await;
        let status = result.ok().map(i64::from);
        let attempts = r.get::<i64, _>("attempts") + 1;
        let success = status.is_some_and(|s| (200..300).contains(&s));
        let base = (5i64.saturating_mul(1i64 << attempts.min(12))).min(2880);
        let jitter =
            i64::from(u16::from_be_bytes(crate::security::secret::random::<2>()?)) % (base / 4 + 1);
        let delay = base + jitter;
        sqlx::query("UPDATE webhook_deliveries SET attempts=?,last_status=?,sent_at=?,failed_at=?,next_attempt_at=? WHERE webhook_id=? AND event_id=?")
   .bind(attempts).bind(status).bind(success.then_some(now())).bind((!success&&attempts>=20).then_some(now())).bind(now()+delay).bind(wid).bind(eid).execute(&app.db).await?;
        crate::workers::heartbeat(app, "delivery", true).await;
    }
    Ok(())
}
