pub mod access;
pub mod altcha;
pub mod auth;
pub mod error;
pub mod pairings;
pub mod paths;
pub mod projects;
pub mod recovery;
pub mod references;
pub mod webhooks;
use crate::App;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, FromRequest, Query, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
pub struct CheckedJson<T>(pub T);
impl<S, T> FromRequest<S> for CheckedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = error::Error;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(v) = Json::<T>::from_request(req, state)
            .await
            .map_err(|_| error::Error::bad("invalid_json"))?;
        Ok(Self(v))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Purpose {
    purpose: String,
}
async fn challenge(
    State(app): State<App>,
    Query(q): Query<Purpose>,
) -> error::Result<Json<::altcha::Challenge>> {
    if !["project", "pairing", "recovery"].contains(&q.purpose.as_str()) {
        return Err(error::Error::bad("invalid_purpose"));
    }
    Ok(Json(altcha::challenge(&app.altcha_key, &q.purpose)?))
}
/// Ready when not draining and every scanner and the delivery worker reported
/// healthy within the last minute.
async fn ready(State(app): State<App>) -> error::Result<Json<serde_json::Value>> {
    let unready = || error::Error::unavailable("worker_unready");
    if app.draining.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(unready());
    }
    let chains = app.config.chains.len() as i64;
    let (healthy_chains, live_workers): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM chain_state WHERE healthy=1),
                (SELECT COUNT(*) FROM worker_state
                 WHERE healthy=1 AND heartbeat>? AND (name='delivery' OR name LIKE 'scanner:%'))",
    )
    .bind(crate::time::now() - 60)
    .fetch_one(&app.db)
    .await?;
    if healthy_chains != chains || live_workers != chains + 1 {
        return Err(unready());
    }
    Ok(Json(json!({"ready":true})))
}
/// The (bucket, per-minute limit) a request counts against.
fn rate_bucket(
    l: &crate::config::Limits,
    method: &axum::http::Method,
    path: &str,
    public: bool,
) -> (String, i64) {
    use axum::http::Method;
    let max = match path {
        "/v1/projects" => l.project_per_minute,
        "/v1/altcha" => l.challenge_per_minute,
        "/v1/pairings" => l.pairing_per_minute,
        _ if public => l.recovery_per_minute,
        _ if *method == Method::GET && path.ends_with("/paths") => l.paths_per_minute,
        _ if *method == Method::GET => l.reads_per_minute,
        _ if *method == Method::PUT => l.allocations_per_minute,
        _ => l.mutations_per_minute,
    };
    let scope = if public {
        path
    } else if path.ends_with("/paths") {
        "paths"
    } else {
        "authenticated"
    };
    (format!("{method}:{scope}"), max)
}
async fn guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let request_id =
        crate::security::secret::id("req_").unwrap_or_else(|_| "req_unavailable".into());
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let mut response = async {
        let peer = req
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|p| {
                crate::security::trusted_proxy::client_ip(
                    p.0.ip(),
                    req.headers(),
                    &app.config.trusted_proxies,
                )
                .to_string()
            })
            .unwrap_or_else(|| "test".into());
        let public = path == "/v1/projects"
            || path == "/v1/pairings"
            || path.starts_with("/v1/recovery")
            || path == "/v1/altcha";
        let identity = if public {
            peer.clone()
        } else {
            req.headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or(&peer)
                .to_string()
        };
        let l = &app.config.limits;
        if path != "/healthz" && path != "/readyz" {
            let (bucket, max) = rate_bucket(l, &method, &path, public);
            crate::security::limits::allow(&app, &identity, &bucket, 60, max).await?;
        }
        if method == axum::http::Method::POST
            && matches!(path.as_str(), "/v1/projects" | "/v1/pairings")
        {
            crate::security::limits::allow(&app, &peer, &path, 86400, l.public_per_day).await?;
        }
        let max_body = if path == "/v1/projects" {
            l.project_body
        } else if path == "/v1/pairings" {
            l.pairing_body
        } else {
            l.general_body
        };
        let (parts, body) = req.into_parts();
        let b = to_bytes(body, max_body)
            .await
            .map_err(|_| error::Error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"))?;
        let req = Request::from_parts(parts, Body::from(b));
        tokio::time::timeout(std::time::Duration::from_secs(15), next.run(req))
            .await
            .map_err(|_| error::Error(StatusCode::REQUEST_TIMEOUT, "request_timeout"))
    }
    .await
    .unwrap_or_else(IntoResponse::into_response);
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        // Every error body is JSON with a request id; framework rejections get a generic one.
        let b = to_bytes(response.into_body(), 16384)
            .await
            .unwrap_or_default();
        let mut v: serde_json::Value = serde_json::from_slice(&b)
            .unwrap_or_else(|_| json!({"error":"invalid_request","message":"request rejected"}));
        let code = v["error"]
            .as_str()
            .filter(|s| s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .unwrap_or("internal");
        if status.is_server_error() {
            tracing::error!(request_id=%request_id,status=status.as_u16(),code,"request failed");
        } else {
            tracing::warn!(request_id=%request_id,status=status.as_u16(),code,"request rejected");
        }
        v["request_id"] = json!(request_id);
        response = (status, Json(v)).into_response();
    }
    let headers = response.headers_mut();
    if let Ok(id) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", id);
    }
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if status == StatusCode::TOO_MANY_REQUESTS {
        headers.insert("retry-after", HeaderValue::from_static("5"));
    }
    response
}
pub fn router(app: App) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"alive":true})) }))
        .route("/readyz", get(ready))
        .route("/v1/altcha", get(challenge))
        .route(
            "/v1/projects",
            post(projects::create).layer(tower::limit::ConcurrencyLimitLayer::new(
                app.config.limits.project_concurrency,
            )),
        )
        .route("/v1/projects/{project}", get(projects::view))
        .route(
            "/v1/projects/{project}/references/{reference}",
            put(references::allocate).layer(tower::limit::ConcurrencyLimitLayer::new(
                app.config.limits.allocation_concurrency,
            )),
        )
        .route("/v1/projects/{project}/paths", get(paths::get))
        .route(
            "/v1/projects/{project}/access",
            get(access::list).post(access::create),
        )
        .route("/v1/projects/{project}/access/{id}", delete(access::revoke))
        .route(
            "/v1/pairings",
            post(pairings::create).layer(tower::limit::ConcurrencyLimitLayer::new(
                app.config.limits.pairing_concurrency,
            )),
        )
        .route(
            "/v1/pairings/{id}",
            get(pairings::get).put(pairings::approve),
        )
        .route("/v1/pairings/{id}/token", post(pairings::token))
        .route("/v1/recovery", post(recovery::challenge))
        .route("/v1/recovery/{id}", put(recovery::complete))
        .route(
            "/v1/projects/{project}/webhooks",
            get(webhooks::list).post(webhooks::create),
        )
        .route(
            "/v1/projects/{project}/webhooks/{id}",
            delete(webhooks::delete),
        )
        .fallback(|| async { error::Error::not_found() })
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            app.config.limits.concurrency,
        ))
        .with_state(app)
}
