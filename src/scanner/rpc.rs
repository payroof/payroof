//! A chain's JSON-RPC endpoints: priority-ordered failover with per-endpoint cooldowns.
//!
//! Endpoint URLs usually embed API keys. They are therefore never logged, returned in
//! errors or shown by `Debug`: only `scheme://host[:port]` is ever printed.
use crate::config::Chain;
use serde_json::{Value, json};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_RESPONSE: usize = 8 * 1024 * 1024;
/// First cooldown after a failure, doubled per consecutive failure up to `MAX_COOLDOWN`.
const BASE_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_COOLDOWN: Duration = Duration::from_secs(120);
/// A server's `Retry-After` is honoured up to this long.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(600);

pub fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// `scheme://host[:port]` of a URL: no credentials, path or query.
pub fn redact(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(host), Some(port)) => format!("{}://{host}:{port}", u.scheme()),
            (Some(host), None) => format!("{}://{host}", u.scheme()),
            _ => "<rpc>".into(),
        },
        Err(_) => "<rpc>".into(),
    }
}

/// Every endpoint is cooling down; the caller should back off for `retry_in`.
#[derive(Debug)]
pub struct Unavailable {
    pub retry_in: Duration,
    pub detail: String,
}
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "all RPC endpoints unavailable (retry in {}s): {}",
            self.retry_in.as_secs().max(1),
            self.detail
        )
    }
}
impl std::error::Error for Unavailable {}

/// Why one attempt failed.
enum Fault {
    /// The endpoint is limiting, down or wrong: cool it down and try the next one.
    Endpoint {
        reason: String,
        retry_after: Option<Duration>,
        long: bool,
    },
    /// This request was refused (unknown method, bad params ...): try the next endpoint
    /// but do not penalise this one.
    Request(String),
}
impl Fault {
    fn endpoint(reason: impl Into<String>) -> Self {
        Self::Endpoint {
            reason: reason.into(),
            retry_after: None,
            long: false,
        }
    }
}

/// Whether a JSON-RPC error object means "slow down" rather than "bad request".
fn is_limit_error(code: i64, message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    matches!(code, -32005 | -32029 | -32097 | 429)
        || [
            "rate limit",
            "rate-limit",
            "ratelimit",
            "too many requests",
            "exceeded",
            "capacity",
            "throttl",
            "limit reached",
        ]
        .iter()
        .any(|needle| message.contains(needle))
}
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let seconds: u64 = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds).min(MAX_RETRY_AFTER))
}

struct Endpoint {
    url: url::Url,
    host: String,
}
#[derive(Default, Clone)]
struct Health {
    failures: u32,
    cooling_until: Option<Instant>,
    verified: bool,
}

pub struct Rpc {
    chain_id: String,
    http: reqwest::Client,
    endpoints: Vec<Endpoint>,
    health: Mutex<Vec<Health>>,
    base: Duration,
    max: Duration,
}
impl std::fmt::Debug for Rpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rpc")
            .field("chain", &self.chain_id)
            .field(
                "endpoints",
                &self.endpoints.iter().map(|e| &e.host).collect::<Vec<_>>(),
            )
            .finish()
    }
}
impl Rpc {
    pub fn new(chain: &Chain) -> anyhow::Result<Self> {
        Self::with_policy(
            chain.id.clone(),
            chain.rpc.urls(),
            BASE_COOLDOWN,
            MAX_COOLDOWN,
        )
    }
    pub fn with_policy(
        chain_id: String,
        urls: &[String],
        base: Duration,
        max: Duration,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!urls.is_empty(), "no RPC endpoint configured");
        let endpoints = urls
            .iter()
            .map(|raw| {
                let url = url::Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid RPC URL"))?;
                Ok(Endpoint {
                    host: redact(raw),
                    url,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            chain_id,
            http: client()?,
            health: Mutex::new(vec![Health::default(); endpoints.len()]),
            endpoints,
            base,
            max,
        })
    }
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
    fn health(&self) -> std::sync::MutexGuard<'_, Vec<Health>> {
        self.health.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// How long until some endpoint may be tried again; `None` when one is usable now.
    pub fn retry_in(&self) -> Option<Duration> {
        let now = Instant::now();
        let health = self.health();
        let mut soonest = None;
        for h in health.iter() {
            match h.cooling_until {
                Some(until) if until > now => {
                    let wait = until - now;
                    soonest = Some(soonest.map_or(wait, |s: Duration| s.min(wait)));
                }
                _ => return None,
            }
        }
        soonest
    }
    /// Usable endpoints, `prefer` first, otherwise in priority order.
    fn candidates(&self, prefer: Option<usize>) -> Vec<usize> {
        let now = Instant::now();
        let health = self.health();
        let usable = |i: usize| health[i].cooling_until.is_none_or(|until| until <= now);
        let mut order: Vec<usize> = prefer
            .filter(|&i| i < health.len() && usable(i))
            .into_iter()
            .collect();
        order.extend((0..health.len()).filter(|&i| usable(i) && Some(i) != prefer));
        order
    }
    fn succeed(&self, i: usize) {
        let mut health = self.health();
        if health[i].failures > 0 {
            tracing::info!(chain=%self.chain_id, endpoint=%self.endpoints[i].host, "RPC endpoint recovered");
        }
        health[i].failures = 0;
        health[i].cooling_until = None;
    }
    /// Starts or extends a cooldown: exponential, at least the server's `Retry-After`.
    pub fn penalize(&self, i: usize, reason: &str, retry_after: Option<Duration>, long: bool) {
        let mut health = self.health();
        let h = &mut health[i];
        h.failures = h.failures.saturating_add(1);
        h.verified = false;
        let exponent = (h.failures - 1).min(16);
        let mut delay = self.base.saturating_mul(1u32 << exponent).min(self.max);
        if long {
            delay = self.max;
        }
        if let Some(server) = retry_after {
            delay = delay.max(server);
        }
        h.cooling_until = Some(Instant::now() + delay);
        let first = h.failures == 1;
        drop(health);
        // One warning per outage; repeated failures of an already-cooling endpoint are quiet.
        if first {
            tracing::warn!(chain=%self.chain_id, endpoint=%self.endpoints[i].host, reason,
                cooldown_secs = delay.as_secs(), "RPC endpoint cooling down");
        } else {
            tracing::debug!(chain=%self.chain_id, endpoint=%self.endpoints[i].host, reason,
                cooldown_secs = delay.as_secs(), "RPC endpoint still failing");
        }
    }
    /// Calls `method` on the preferred (then first healthy) endpoint, failing over on
    /// limits and outages. `prefer` is updated to the endpoint that answered, so one scan
    /// step keeps talking to one node unless it fails.
    pub async fn call(
        &self,
        prefer: &mut Option<usize>,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        let order = self.candidates(*prefer);
        if order.is_empty() {
            return Err(Unavailable {
                retry_in: self.retry_in().unwrap_or_default(),
                detail: "every endpoint is cooling down".into(),
            }
            .into());
        }
        let mut last = String::from("no endpoint answered");
        for i in order {
            match self.attempt(i, method, &params).await {
                Ok(value) => {
                    self.succeed(i);
                    *prefer = Some(i);
                    return Ok(value);
                }
                Err(Fault::Endpoint {
                    reason,
                    retry_after,
                    long,
                }) => {
                    self.penalize(i, &reason, retry_after, long);
                    if *prefer == Some(i) {
                        *prefer = None;
                    }
                    last = reason;
                }
                Err(Fault::Request(reason)) => last = reason,
            }
        }
        match self.retry_in() {
            Some(retry_in) => Err(Unavailable {
                retry_in,
                detail: last,
            }
            .into()),
            None => Err(anyhow::anyhow!(last)),
        }
    }
    async fn attempt(&self, i: usize, method: &str, params: &Value) -> Result<Value, Fault> {
        if !self.health()[i].verified {
            let actual = self.send(i, "eth_chainId", &json!([])).await?;
            let actual = actual
                .as_str()
                .and_then(|s| s.strip_prefix("0x"))
                .and_then(|s| u64::from_str_radix(s, 16).ok());
            if actual.map(|id| format!("eip155:{id}")).as_deref() != Some(self.chain_id.as_str()) {
                return Err(Fault::Endpoint {
                    reason: "RPC chain mismatch".into(),
                    retry_after: None,
                    long: true,
                });
            }
            self.health()[i].verified = true;
        }
        self.send(i, method, params).await
    }
    async fn send(&self, i: usize, method: &str, params: &Value) -> Result<Value, Fault> {
        // Error texts below are fixed strings: reqwest's own errors embed the URL.
        let mut response = self
            .http
            .post(self.endpoints[i].url.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|e| {
                Fault::endpoint(if e.is_timeout() {
                    "RPC timeout"
                } else if e.is_connect() {
                    "RPC connection failed"
                } else {
                    "RPC transport error"
                })
            })?;
        let status = response.status();
        if !status.is_success() {
            let wait = retry_after(response.headers());
            return Err(match status.as_u16() {
                401 | 403 | 408 | 429 | 500..=599 => Fault::Endpoint {
                    reason: format!("RPC HTTP {}", status.as_u16()),
                    retry_after: wait,
                    long: false,
                },
                code => Fault::Request(format!("RPC HTTP {code}")),
            });
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > MAX_RESPONSE {
                        return Err(Fault::endpoint("RPC response too large"));
                    }
                    body.extend(chunk);
                }
                Ok(None) => break,
                Err(_) => return Err(Fault::endpoint("RPC response interrupted")),
            }
        }
        let value: Value =
            serde_json::from_slice(&body).map_err(|_| Fault::endpoint("RPC response invalid"))?;
        if let Some(error) = value.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error.get("message").and_then(Value::as_str).unwrap_or("");
            return Err(if is_limit_error(code, message) {
                Fault::endpoint(format!("RPC rate limited (code {code})"))
            } else {
                Fault::Request(format!("RPC rejected request (code {code})"))
            });
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| Fault::endpoint("RPC response invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    /// A scripted node: `mode` picks the reply, `hits` counts non-chainId requests.
    #[derive(Clone)]
    struct Node {
        mode: Arc<Mutex<&'static str>>,
        hits: Arc<AtomicUsize>,
        chain: &'static str,
    }
    async fn reply(
        State(node): State<Node>,
        axum::Json(req): axum::Json<Value>,
    ) -> axum::response::Response {
        if req["method"] == "eth_chainId" {
            return axum::Json(json!({"jsonrpc":"2.0","id":1,"result":node.chain})).into_response();
        }
        node.hits.fetch_add(1, Ordering::SeqCst);
        let mode = *node.mode.lock().unwrap();
        match mode {
            "429" => (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                "slow down",
            )
                .into_response(),
            "403" => StatusCode::FORBIDDEN.into_response(),
            "500" => StatusCode::BAD_GATEWAY.into_response(),
            "limit" => axum::Json(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"limit exceeded"}}),
            )
            .into_response(),
            "bad" => axum::Json(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}),
            )
            .into_response(),
            _ => axum::Json(json!({"jsonrpc":"2.0","id":1,"result":"0x10"})).into_response(),
        }
    }
    async fn node(mode: &'static str, chain: &'static str) -> (Node, String) {
        let node = Node {
            mode: Arc::new(Mutex::new(mode)),
            hits: Arc::new(AtomicUsize::new(0)),
            chain,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        // The path stands in for an API key.
        let url = format!(
            "http://{}/v2/TOPSECRETKEY?token=TOPSECRET",
            listener.local_addr().unwrap()
        );
        let app = Router::new()
            .route("/v2/{key}", post(reply))
            .with_state(node.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (node, url)
    }
    fn pool(urls: &[String], base_ms: u64) -> Rpc {
        Rpc::with_policy(
            "eip155:1".into(),
            urls,
            Duration::from_millis(base_ms),
            Duration::from_millis(base_ms * 8),
        )
        .unwrap()
    }
    async fn call(rpc: &Rpc) -> anyhow::Result<Value> {
        rpc.call(&mut None, "eth_blockNumber", json!([])).await
    }

    #[test]
    fn redaction_keeps_only_scheme_host_and_port() {
        assert_eq!(
            redact("https://user:pw@eth.example:8443/v2/KEY?a=b#f"),
            "https://eth.example:8443"
        );
        assert_eq!(redact("https://eth.example/KEY"), "https://eth.example");
        assert_eq!(redact("not a url with KEY"), "<rpc>");
        assert!(
            is_limit_error(-32005, "")
                && is_limit_error(-32029, "")
                && is_limit_error(1, "Rate limit hit")
        );
        assert!(
            is_limit_error(1, "daily request count exceeded") && is_limit_error(1, "at capacity")
        );
        assert!(!is_limit_error(-32602, "invalid params"));
    }

    #[tokio::test]
    async fn fails_over_on_429_403_5xx_and_json_rpc_limits_then_prefers_the_primary_again() {
        for mode in ["429", "403", "500", "limit"] {
            let (primary, a) = node(mode, "0x1").await;
            let (secondary, b) = node("ok", "0x1").await;
            let rpc = pool(&[a, b], 400);
            assert_eq!(call(&rpc).await.unwrap(), "0x10", "{mode}");
            assert_eq!(primary.hits.load(Ordering::SeqCst), 1);
            // Cooling: the primary is not retried while the secondary answers.
            call(&rpc).await.unwrap();
            assert_eq!(primary.hits.load(Ordering::SeqCst), 1, "{mode}");
            assert_eq!(secondary.hits.load(Ordering::SeqCst), 2);
            // After the cooldown the recovered primary is preferred again.
            *primary.mode.lock().unwrap() = "ok";
            tokio::time::sleep(Duration::from_millis(1300)).await; // covers Retry-After: 1
            call(&rpc).await.unwrap();
            assert_eq!(primary.hits.load(Ordering::SeqCst), 2, "{mode}");
            assert_eq!(secondary.hits.load(Ordering::SeqCst), 2);
            assert!(rpc.retry_in().is_none());
        }
    }

    #[tokio::test]
    async fn all_endpoints_cooling_reports_unavailable_without_sending_requests() {
        let (a_node, a) = node("429", "0x1").await;
        let (b_node, b) = node("500", "0x1").await;
        let rpc = pool(&[a, b], 10_000);
        let error = call(&rpc).await.unwrap_err();
        let unavailable = error.downcast_ref::<Unavailable>().expect("typed error");
        assert!(unavailable.retry_in > Duration::from_secs(1));
        let hits = (
            a_node.hits.load(Ordering::SeqCst),
            b_node.hits.load(Ordering::SeqCst),
        );
        assert_eq!(hits, (1, 1));
        assert!(
            call(&rpc)
                .await
                .unwrap_err()
                .downcast_ref::<Unavailable>()
                .is_some()
        );
        assert_eq!(
            (
                a_node.hits.load(Ordering::SeqCst),
                b_node.hits.load(Ordering::SeqCst)
            ),
            hits
        );
        assert!(rpc.retry_in().is_some());
    }

    #[tokio::test]
    async fn cooldown_grows_exponentially_and_honours_retry_after() {
        let (_, a) = node("500", "0x1").await;
        let rpc = pool(&[a], 100);
        let _ = call(&rpc).await;
        let first = rpc.retry_in().unwrap();
        assert!(first <= Duration::from_millis(100));
        rpc.penalize(0, "test", None, false);
        assert!(rpc.retry_in().unwrap() > first);
        rpc.penalize(0, "test", Some(Duration::from_secs(30)), false);
        assert!(rpc.retry_in().unwrap() > Duration::from_secs(20));
        // An absurd Retry-After is capped when parsed.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "999999".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(MAX_RETRY_AFTER));
    }

    #[tokio::test]
    async fn request_errors_do_not_cool_an_endpoint_and_wrong_chains_are_rejected() {
        let (a_node, a) = node("bad", "0x1").await;
        let rpc = pool(&[a], 100);
        let error = call(&rpc).await.unwrap_err();
        assert!(error.to_string().contains("RPC rejected request"));
        assert!(rpc.retry_in().is_none());
        *a_node.mode.lock().unwrap() = "ok";
        assert_eq!(call(&rpc).await.unwrap(), "0x10");

        let (wrong, w) = node("ok", "0x2").await;
        let (_, good) = node("ok", "0x1").await;
        let rpc = pool(&[w, good], 100);
        assert_eq!(call(&rpc).await.unwrap(), "0x10");
        assert_eq!(wrong.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn errors_and_debug_output_never_contain_the_url_path_or_query() {
        let (_, a) = node("429", "0x1").await;
        let (_, b) = node("500", "0x1").await;
        let rpc = pool(&[a.clone(), b.clone()], 100);
        let error = format!(
            "{:?} / {}",
            call(&rpc).await.unwrap_err(),
            call(&rpc).await.unwrap_err()
        );
        let debug = format!("{rpc:?}");
        for text in [error, debug] {
            assert!(
                !text.contains("TOPSECRET") && !text.contains("/v2/"),
                "{text}"
            );
        }
        // A connection failure must not leak the URL through reqwest's error text either.
        let dead = "http://127.0.0.1:1/v2/TOPSECRETKEY?token=TOPSECRET".to_string();
        let rpc = pool(&[dead], 100);
        let text = format!("{:?}", call(&rpc).await.unwrap_err());
        assert!(
            !text.contains("TOPSECRET") && text.contains("connection failed"),
            "{text}"
        );
    }
}
