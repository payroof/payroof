use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use payroof::{
    App, State,
    config::Config,
    domain::{
        access::ALL,
        watch_root::{WatchKey, WatchRoot},
    },
    http,
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;
async fn app() -> App {
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config: Config = toml::from_str(include_str!("../config/payroof.local.toml")).unwrap();
    Arc::new(State {
        db,
        config,
        cursor_key: Zeroizing::new([1; 32]),
        master: Zeroizing::new([2; 32]),
        altcha_key: Zeroizing::new("3".repeat(64)),
        draining: Default::default(),
    })
}
async fn concurrent_app() -> (App, std::path::PathBuf) {
    let mut app = app().await;
    let path = std::env::temp_dir().join(format!(
        "payroof-{}.sqlite",
        payroof::security::secret::id("test_").unwrap()
    ));
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5));
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    Arc::get_mut(&mut app).unwrap().db = db;
    (app, path)
}
async fn seeded(app: &App, project: &str, owner: u8) -> String {
    let root = WatchRoot {
        family: "eip155".into(),
        path: "m/44'/60'/0'/1".into(),
        key: WatchKey {
            algorithm: "bip32-secp256k1".into(),
            public_key: URL_SAFE_NO_PAD.encode(
                hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .unwrap(),
            ),
            chain_code: URL_SAFE_NO_PAD.encode([owner; 32]),
        },
    };
    let mut tx = payroof::db::write(&app.db).await.unwrap();
    let id =
        sqlx::query("INSERT INTO projects(project,recovery_public_key,created_at) VALUES(?,?,0)")
            .bind(project)
            .bind(vec![owner; 32])
            .execute(&mut *tx)
            .await
            .unwrap()
            .last_insert_rowid();
    sqlx::query(
        "INSERT INTO watch_roots(project_id,root_json,fingerprint,root_identity) VALUES(?,?,?,?)",
    )
    .bind(id)
    .bind(serde_json::to_string(&root).unwrap())
    .bind(root.fingerprint().unwrap())
    .bind(root.identity().unwrap())
    .execute(&mut *tx)
    .await
    .unwrap();
    let (_, token) = http::auth::issue(&mut tx, id, "test", &ALL).await.unwrap();
    tx.commit().await.unwrap();
    token
}
async fn request(app: &App, method: &str, path: &str, token: &str) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let r = http::router(app.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = r.status();
    let bytes = to_bytes(r.into_body(), 32768).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn access_path(app: &App, token: &str) -> String {
    let id: String = sqlx::query_scalar("SELECT id FROM access WHERE secret_hash=?")
        .bind(payroof::security::secret::hash(token))
        .fetch_one(&app.db)
        .await
        .unwrap();
    format!("/v1/projects/main/access/{id}")
}
#[tokio::test]
async fn authentication_and_access_listing_are_read_only() {
    use axum::{extract::Path, extract::State, http::HeaderMap};

    let app = app().await;
    let token = seeded(&app, "main", 1).await;
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    sqlx::query("PRAGMA query_only=ON")
        .execute(&app.db)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE access SET name='changed'")
            .execute(&app.db)
            .await
            .is_err()
    );
    // app() uses a single connection, so total_changes() is comparable across
    // these pool acquisitions, in addition to the query_only write guard.
    let changes_before: i64 = sqlx::query_scalar("SELECT total_changes()")
        .fetch_one(&app.db)
        .await
        .unwrap();

    let project_id: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE project='main'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    for permission in ALL {
        let authenticated = http::auth::auth(&app, &headers, Some("main"), Some(permission))
            .await
            .unwrap();
        assert_eq!(authenticated.project_id, project_id);
    }
    let axum::Json(listed) = http::access::list(State(app.clone()), Path("main".into()), headers)
        .await
        .unwrap();
    let changes_after: i64 = sqlx::query_scalar("SELECT total_changes()")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(changes_after, changes_before);
    let listed = listed["access"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["created_at", "id", "name", "permissions"]
    );
    assert!(listed[0]["id"].as_str().unwrap().starts_with("acc_"));
    assert_eq!(listed[0]["name"], "test");
    assert_eq!(listed[0]["permissions"], serde_json::json!(ALL));
}

#[tokio::test]
async fn allocation_idempotency_project_isolation_and_revocation() {
    let app = app().await;
    let a = seeded(&app, "main", 1).await;
    let b = seeded(&app, "main", 2).await;
    let (status, first) = request(&app, "PUT", "/v1/projects/main/references/ORDER-42", &a).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(first.get("address_index").is_none());
    let (status, again) = request(&app, "PUT", "/v1/projects/main/references/ORDER-42", &a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, again);
    assert_eq!(
        request(&app, "PUT", "/v1/projects/main/references/ORDER-42", &b)
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        request(&app, "PUT", "/v1/projects/other/references/ORDER-42", &a)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "DELETE", &access_path(&app, &a).await, &a)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "PUT", "/v1/projects/main/references/ORDER-43", &a)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn altcha_replay_is_durable() {
    let app = app().await;
    let challenge = test_challenge(&app, "pairing");
    let solution = altcha::solve_challenge(altcha::SolveChallengeOptions::new(&challenge))
        .unwrap()
        .unwrap();
    let p = altcha::Payload {
        challenge,
        solution,
    };
    http::altcha::consume(&app, &p, "pairing").await.unwrap();
    assert!(http::altcha::consume(&app, &p, "pairing").await.is_err());
    assert!(http::altcha::consume(&app, &p, "recovery").await.is_err());
}
#[test]
fn raw_body_mac() {
    use payroof::crypto::webhook::*;
    let body = br#"{ "amount": "42" }"#;
    let s = sign_webhook(&[1; 32], 1000, body);
    assert!(verify_webhook(&[1; 32], 1000, body, &s, 1001).is_ok());
    assert!(verify_webhook(&[1; 32], 1000, br#"{"amount":"42"}"#, &s, 1001).is_err());
    assert!(verify_webhook(&[1; 32], 1000, body, &s, 1301).is_err());
}
async fn json_request(app: &App, path: &str, body: Value) -> (StatusCode, Value) {
    json_method(app, "POST", path, body).await
}
async fn json_method(app: &App, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    json_auth_method(app, method, path, body, "").await
}
async fn json_auth_method(
    app: &App,
    method: &str,
    path: &str,
    body: Value,
    token: &str,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = req.body(Body::from(body.to_string())).unwrap();
    let r = http::router(app.clone()).oneshot(req).await.unwrap();
    let status = r.status();
    let bytes = to_bytes(r.into_body(), 32768).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn recovery_accepts_a_configured_origin_alias_only() {
    use ed25519_dalek::Signer;
    let base = app().await;
    let mut config = base.config.clone();
    config.origin_aliases = vec!["http://192.168.1.20:8080".into()];
    let app: App = Arc::new(State {
        db: base.db.clone(),
        config,
        cursor_key: Zeroizing::new([1; 32]),
        master: Zeroizing::new([2; 32]),
        altcha_key: Zeroizing::new("3".repeat(64)),
        draining: Default::default(),
    });
    let (status, _) = json_request(
        &app,
        "/v1/projects",
        project_body(&app, 76, "m/44'/60'/6'/1"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let owner = ed25519_dalek::SigningKey::from_bytes(&[76; 32]);
    let public = URL_SAFE_NO_PAD.encode(owner.verifying_key().as_bytes());
    let begin = || {
        json_request(
            &app,
            "/v1/recovery",
            serde_json::json!({"recovery_key":{"algorithm":"ed25519","public_key":public},"altcha":proof(&app,"recovery")}),
        )
    };
    let sign = |origin: &str, challenge: &Value| {
        let message = payroof::crypto::recovery::recovery_message(
            origin,
            challenge["id"].as_str().unwrap(),
            challenge["challenge"].as_str().unwrap(),
        );
        serde_json::json!({"signature":URL_SAFE_NO_PAD.encode(owner.sign(message.as_bytes()).to_bytes()),"name":"Recovered"})
    };
    let (_, unlisted) = begin().await;
    let path = format!("/v1/recovery/{}", unlisted["id"].as_str().unwrap());
    let body = sign("http://10.0.0.9:8080", &unlisted);
    assert_eq!(
        json_method(&app, "PUT", &path, body).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, aliased) = begin().await;
    let path = format!("/v1/recovery/{}", aliased["id"].as_str().unwrap());
    let (status, recovered) = json_method(
        &app,
        "PUT",
        &path,
        sign("http://192.168.1.20:8080", &aliased),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recovered["project"], "main");
}
#[tokio::test]
async fn recovery_is_origin_bound_one_use_and_expiring() {
    use ed25519_dalek::Signer;
    let app = app().await;
    let (status, created) = json_request(
        &app,
        "/v1/projects",
        project_body(&app, 77, "m/44'/60'/7'/1"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let owner = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    assert_eq!(
        created["permissions"],
        serde_json::json!(["references", "paths", "webhooks", "access"])
    );
    let public = URL_SAFE_NO_PAD.encode(owner.verifying_key().as_bytes());
    let (_, challenge) = json_request(
        &app,
        "/v1/recovery",
        serde_json::json!({"recovery_key":{"algorithm":"ed25519","public_key":public},"altcha":proof(&app,"recovery")}),
    )
    .await;
    let id = challenge["id"].as_str().unwrap();
    let nonce = challenge["challenge"].as_str().unwrap();
    let message = payroof::crypto::recovery::recovery_message(&app.config.origin, id, nonce);
    let signature = URL_SAFE_NO_PAD.encode(owner.sign(message.as_bytes()).to_bytes());
    let body = serde_json::json!({"signature":signature,"name":"Recovered Wallet"});
    let recovery_path = format!("/v1/recovery/{id}");
    let wrong = payroof::crypto::recovery::recovery_message("https://other.example", id, nonce);
    let mut wrong_body = body.clone();
    wrong_body["signature"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(owner.sign(wrong.as_bytes()).to_bytes()));
    assert_eq!(
        json_method(&app, "PUT", &recovery_path, wrong_body).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Another key's signature over the same challenge doesn't recover this project.
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[78; 32]);
    let mut wrong_body = body.clone();
    wrong_body["signature"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(stranger.sign(message.as_bytes()).to_bytes()));
    assert_eq!(
        json_method(&app, "PUT", &recovery_path, wrong_body).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (first, second) = tokio::join!(
        json_method(&app, "PUT", &recovery_path, body.clone()),
        json_method(&app, "PUT", &recovery_path, body)
    );
    let mut statuses = [first.0.as_u16(), second.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 410]);
    let recovered = if first.0 == StatusCode::OK {
        first.1
    } else {
        second.1
    };
    assert_eq!(recovered["permissions"], serde_json::json!(ALL));
    // The key alone found the project; its name comes back only with the proof.
    assert_eq!(recovered["project"], "main");
    assert!(challenge.get("project").is_none());
    let unknown = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[79; 32])
            .verifying_key()
            .as_bytes(),
    );
    assert_eq!(
        json_request(
            &app,
            "/v1/recovery",
            serde_json::json!({"recovery_key":{"algorithm":"ed25519","public_key":unknown},"altcha":proof(&app,"recovery")}),
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/v1/projects/main",
            recovered["token"].as_str().unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &access_path(&app, created["token"].as_str().unwrap()).await,
            created["token"].as_str().unwrap()
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/v1/projects/main",
            created["token"].as_str().unwrap()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );

    let (_, expired) = json_request(
        &app,
        "/v1/recovery",
        serde_json::json!({"recovery_key":{"algorithm":"ed25519","public_key":public},"altcha":proof(&app,"recovery")}),
    ).await;
    sqlx::query("UPDATE recovery_challenges SET expires_at=0 WHERE id_hash=?")
        .bind(payroof::security::secret::hash(
            expired["id"].as_str().unwrap(),
        ))
        .execute(&app.db)
        .await
        .unwrap();
    let expired_body = serde_json::json!({"signature":signature,"name":"Expired"});
    let (status, error) = json_method(
        &app,
        "PUT",
        &format!("/v1/recovery/{}", expired["id"].as_str().unwrap()),
        expired_body,
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(error["error"], "recovery_challenge_expired");
    assert!(error["request_id"].as_str().unwrap().starts_with("req_"));
}
fn proof(app: &App, purpose: &str) -> Value {
    let challenge = test_challenge(app, purpose);
    let solution = altcha::solve_challenge(altcha::SolveChallengeOptions::new(&challenge))
        .unwrap()
        .unwrap();
    serde_json::json!({"challenge":challenge,"solution":solution})
}
fn test_challenge(app: &App, purpose: &str) -> altcha::Challenge {
    // The real challenge shape with a known counter of zero, not a weakened KDF or a
    // bypassed verifier: tests stay fast and within the real challenge TTL.
    altcha::create_challenge(altcha::CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".into(),
        cost: 5000,
        counter: Some(0),
        key_prefix_length: Some(4),
        hmac_signature_secret: Some(app.altcha_key.to_string()),
        expires_at: Some(payroof::time::now() + 120),
        data: Some(std::collections::BTreeMap::from([(
            "purpose".into(),
            serde_json::json!(purpose),
        )])),
        ..Default::default()
    })
    .unwrap()
}
fn project_body(app: &App, owner: u8, path: &str) -> Value {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[owner; 32]).verifying_key();
    serde_json::json!({"project":"main","recovery_key":{"algorithm":"ed25519","public_key":URL_SAFE_NO_PAD.encode(owner.as_bytes())},"watch_roots":[{"family":"eip155","path":path,"key":{"algorithm":"bip32-secp256k1","public_key":URL_SAFE_NO_PAD.encode(hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()),"chain_code":URL_SAFE_NO_PAD.encode([42;32])}}],"altcha":proof(app,"project")})
}
#[tokio::test]
async fn concurrent_root_registration_is_private_and_unique() {
    let (app, path) = concurrent_app().await;
    let a = project_body(&app, 1, "m/44'/60'/0'/1");
    let b = project_body(&app, 2, "m/44'/60'/1'/1");
    let (a, b) = tokio::join!(
        json_request(&app, "/v1/projects", a),
        json_request(&app, "/v1/projects", b)
    );
    let (winner, loser) = if a.0 == StatusCode::CREATED {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(winner.0, StatusCode::CREATED);
    assert_eq!(loser.0, StatusCode::CONFLICT);
    assert_eq!(loser.1["error"], "watch_root_in_use");
    assert!(loser.1.get("owner").is_none());
    assert!(loser.1.get("project").is_none());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    app.db.close().await;
    std::fs::remove_file(path).unwrap();
}
#[tokio::test]
async fn concurrent_allocations_are_idempotent() {
    let (app, path) = concurrent_app().await;
    let token = seeded(&app, "main", 1).await;
    let (a, b) = tokio::join!(
        request(&app, "PUT", "/v1/projects/main/references/race", &token),
        request(&app, "PUT", "/v1/projects/main/references/race", &token)
    );
    assert_eq!(a.1, b.1);
    assert!([a.0, b.0].contains(&StatusCode::CREATED));
    assert!([a.0, b.0].contains(&StatusCode::OK));
    let count: i64 = sqlx::query_scalar("SELECT next_address_index FROM projects")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    app.db.close().await;
    std::fs::remove_file(path).unwrap();
}
#[tokio::test]
async fn concurrent_recovery_registration_cannot_rename_identity() {
    let (app, path) = concurrent_app().await;
    let a = project_body(&app, 1, "m/44'/60'/0'/1");
    let mut b = project_body(&app, 1, "m/44'/60'/1'/1");
    b["project"] = serde_json::json!("renamed");
    b["watch_roots"][0]["key"]["chain_code"] = serde_json::json!(URL_SAFE_NO_PAD.encode([43; 32]));
    let (a, b) = tokio::join!(
        json_request(&app, "/v1/projects", a),
        json_request(&app, "/v1/projects", b)
    );
    let (winner, loser) = if a.0 == StatusCode::CREATED {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(winner.0, StatusCode::CREATED);
    assert_eq!(loser.0, StatusCode::CONFLICT);
    assert_eq!(loser.1["error"], "project_exists");
    assert!(loser.1.get("project").is_none());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    app.db.close().await;
    std::fs::remove_file(path).unwrap();
}
#[tokio::test]
async fn pairing_metadata_and_poll_consumes_once() {
    let app = app().await;
    let owner = seeded(&app, "main", 1).await;
    let (_,pair)=json_request(&app,"/v1/pairings",serde_json::json!({"name":"<script>alert('x')</script>","permissions":["references"],"altcha":proof(&app,"pairing")})).await;
    let id = pair["id"].as_str().unwrap();
    let secret = pair["poll_secret"].as_str().unwrap();
    let stored: Vec<u8> = sqlx::query_scalar("SELECT poll_hash FROM pairings")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(stored, payroof::security::secret::hash(secret));
    assert_ne!(stored, secret.as_bytes());
    let r = http::router(app.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/pairings/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["content-type"], "application/json");
    let body = String::from_utf8(to_bytes(r.into_body(), 32768).await.unwrap().to_vec()).unwrap();
    let metadata: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(metadata["name"], "<script>alert('x')</script>");
    assert_eq!(metadata["permissions"], serde_json::json!(["references"]));
    assert_eq!(
        pair["url"],
        format!("{}/v1/pairings/{id}", app.config.origin)
    );
    assert!(!body.contains(secret));
    assert!(!body.contains(&owner));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        request(&app, "PUT", &format!("/v1/pairings/{id}"), &owner)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let token_path = format!("/v1/pairings/{id}/token");
    let (a, b) = tokio::join!(
        request(&app, "POST", &token_path, secret),
        request(&app, "POST", &token_path, secret)
    );
    assert_eq!(
        usize::from(a.1.get("token").is_some()) + usize::from(b.1.get("token").is_some()),
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let retrieved = if a.1.get("token").is_some() {
        &a.1
    } else {
        &b.1
    };
    assert_eq!(retrieved["permissions"], serde_json::json!(["references"]));
    assert_eq!(retrieved["project"], "main");
    sqlx::query("UPDATE pairings SET last_poll=0")
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "POST", &token_path, secret).await.0,
        StatusCode::GONE
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
async fn pairing_requires_access_permission_and_live_approver() {
    use payroof::domain::access::Permission;
    let app = app().await;
    let owner = seeded(&app, "main", 1).await;
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects")
        .fetch_one(&app.db)
        .await
        .unwrap();
    let mut tx = payroof::db::write(&app.db).await.unwrap();
    let (_, restricted) = http::auth::issue(&mut tx, pid, "restricted", &[Permission::References])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (_, pair) = json_request(
        &app,
        "/v1/pairings",
        serde_json::json!({
            "name":"app", "permissions":["paths"], "altcha":proof(&app,"pairing")
        }),
    )
    .await;
    let path = format!("/v1/pairings/{}", pair["id"].as_str().unwrap());
    let secret = pair["poll_secret"].as_str().unwrap();
    let poll_path = format!("{path}/token");
    assert_eq!(
        request(&app, "PUT", &path, &restricted).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "POST", &poll_path, "wrong-secret").await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, pending) = request(&app, "POST", &poll_path, secret).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(pending["status"], "pending");
    assert_eq!(
        request(&app, "POST", &poll_path, secret).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        request(&app, "PUT", &path, &owner).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "PUT", &path, &owner).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "DELETE", &access_path(&app, &owner).await, &owner)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    sqlx::query("UPDATE pairings SET last_poll=0")
        .execute(&app.db)
        .await
        .unwrap();
    let (status, error) = request(&app, "POST", &poll_path, secret).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"], "pairing_approver_revoked");
    for resource in ["paths", "access", "webhooks"] {
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("/v1/projects/main/{resource}"),
                &restricted
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        request(
            &app,
            "DELETE",
            &access_path(&app, &restricted).await,
            &restricted
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn final_route_surface_and_pairing_body_are_strict() {
    let app = app().await;
    let token = seeded(&app, "main", 1).await;
    for (method, path, status) in [
        ("GET", "/v1/main", StatusCode::NOT_FOUND),
        ("GET", "/v1/main/_/paths", StatusCode::NOT_FOUND),
        ("GET", "/v1/projects/main/settings", StatusCode::NOT_FOUND),
        ("GET", "/pair/missing", StatusCode::NOT_FOUND),
        (
            "POST",
            "/v1/pairings/missing/approve",
            StatusCode::NOT_FOUND,
        ),
        ("POST", "/v1/pairings/missing/deny", StatusCode::NOT_FOUND),
        (
            "POST",
            "/v1/pairings/missing/token",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PUT",
            "/v1/projects/main/access",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "PATCH",
            "/v1/projects/main/webhooks/missing",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        assert_eq!(
            request(&app, method, path, &token).await.0,
            status,
            "{method} {path}"
        );
    }
    assert_eq!(
        request(&app, "GET", "/v1/altcha?purpose=project_create", "")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&app, "GET", "/v1/altcha?purpose=project", "")
            .await
            .0,
        StatusCode::OK
    );
    for permissions in [
        serde_json::json!(["activity"]),
        serde_json::json!(["settings"]),
        serde_json::json!(["tokens"]),
        serde_json::json!(["access", "access"]),
        serde_json::json!([]),
    ] {
        assert_eq!(json_request(&app, "/v1/pairings", serde_json::json!({"name":"app","permissions":permissions,"altcha":proof(&app,"pairing")})).await.0, StatusCode::BAD_REQUEST);
    }
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/pairings/missing")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from("{}"))
        .unwrap();
    let r = http::router(app.clone()).oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let error: Value =
        serde_json::from_slice(&to_bytes(r.into_body(), 32768).await.unwrap()).unwrap();
    assert_eq!(error["error"], "unexpected_body");
}
#[tokio::test]
async fn configured_multichain_destinations_have_no_project_switches() {
    let mut app = app().await;
    let mut chain = app.config.chains[0].clone();
    chain.id = "eip155:1".into();
    chain.name = "Ethereum".into();
    chain.assets[0].id = "eip155:1/slip44:60".into();
    Arc::get_mut(&mut app).unwrap().config.chains.push(chain);
    let token = seeded(&app, "main", 1).await;
    let (status, view) = request(&app, "GET", "/v1/projects/main", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["chains"].as_array().unwrap().len(), 2);
    assert_eq!(
        view["chains"][0]["name"],
        app.config.chains[0].name.as_str()
    );
    assert_eq!(view["chains"][1]["name"], "Ethereum");
    assert!(view.get("settings").is_none());
    assert!(view["chains"][0].get("enabled").is_none());
    assert!(view["chains"][0]["assets"][0].get("enabled").is_none());
    let (status, mapping) =
        request(&app, "PUT", "/v1/projects/main/references/order", &token).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(mapping["destinations"].as_array().unwrap().len(), 2);
    assert_eq!(
        mapping["destinations"][0]["address"],
        mapping["destinations"][1]["address"]
    );
}
#[tokio::test]
async fn webhook_create_list_delete_and_production_ssrf() {
    let mut app = app().await;
    let token = seeded(&app, "main", 1).await;
    let path = "/v1/projects/main/webhooks";
    let body =
        serde_json::json!({"url":"http://127.0.0.1:9000/events","events":["seen","confirmed"]});
    let (status, created) = json_auth_method(&app, "POST", path, body.clone(), &token).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(created["secret"].as_str().unwrap().starts_with("whsec_"));
    let (status, listed) = request(&app, "GET", path, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["webhooks"][0]["id"], created["id"]);
    assert!(listed["webhooks"][0].get("secret").is_none());
    let id_path = format!("{path}/{}", created["id"].as_str().unwrap());
    assert_eq!(
        request(&app, "DELETE", &id_path, &token).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "DELETE", &id_path, &token).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", path, &token).await.1["webhooks"],
        serde_json::json!([])
    );
    Arc::get_mut(&mut app).unwrap().config.development = false;
    assert_eq!(
        json_auth_method(&app, "POST", path, body, &token).await.1["error"],
        "invalid_webhook_url"
    );
    let private = serde_json::json!({"url":"https://127.0.0.1/events","events":["seen"]});
    assert_eq!(
        json_auth_method(&app, "POST", path, private, &token)
            .await
            .1["error"],
        "invalid_webhook_url"
    );
}
#[tokio::test]
async fn unavailable_pairing_is_safe_json() {
    let app = app().await;
    let (_,pair)=json_request(&app,"/v1/pairings",serde_json::json!({"name":"expired","permissions":["references"],"altcha":proof(&app,"pairing")})).await;
    let id = pair["id"].as_str().unwrap();
    sqlx::query("UPDATE pairings SET expires_at=0")
        .execute(&app.db)
        .await
        .unwrap();
    for (id, status) in [
        (id, StatusCode::GONE),
        ("pair_missing", StatusCode::NOT_FOUND),
    ] {
        let r = http::router(app.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/pairings/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), status);
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(r.headers()["content-type"], "application/json");
        assert!(r.headers().contains_key("x-request-id"));
        let body =
            String::from_utf8(to_bytes(r.into_body(), 32768).await.unwrap().to_vec()).unwrap();
        let error: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            error["error"],
            if status == StatusCode::GONE {
                "pairing_expired"
            } else {
                "not_found"
            }
        );
        assert!(!body.contains("poll_secret"));
        assert!(!body.contains("project"));
    }
}
#[tokio::test]
async fn path_feed_has_its_own_configured_rate_bucket() {
    let mut app = app().await;
    Arc::get_mut(&mut app)
        .unwrap()
        .config
        .limits
        .paths_per_minute = 1;
    let token = seeded(&app, "main", 1).await;
    assert_eq!(
        request(&app, "GET", "/v1/projects/main", &token).await.0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "GET", "/v1/projects/main/paths", &token)
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = request(&app, "GET", "/v1/projects/main/paths", &token).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(
        request(&app, "GET", "/v1/projects/main", &token).await.0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn corrupted_persisted_permissions_fail_closed() {
    let app = app().await;
    let token = seeded(&app, "main", 1).await;
    sqlx::query("DROP TRIGGER immutable_permissions")
        .execute(&app.db)
        .await
        .unwrap();
    for raw in ["not json", "[]", "[\"unknown\"]", "[\"access\",\"access\"]"] {
        sqlx::query("UPDATE access SET permissions_json=?")
            .bind(raw)
            .execute(&app.db)
            .await
            .unwrap();
        let (status, body) = request(&app, "GET", "/v1/projects/main", &token).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "persisted_data_invalid");
    }
}
#[tokio::test]
async fn rate_limit_capacity_is_atomic_and_existing_keys_work() {
    let (mut app, path) = concurrent_app().await;
    Arc::get_mut(&mut app)
        .unwrap()
        .config
        .limits
        .rate_limit_entries = 1;
    let (a, b) = tokio::join!(
        payroof::security::limits::allow(&app, "random-a", "test", 60, 10),
        payroof::security::limits::allow(&app, "random-b", "test", 60, 10)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let existing = if a.is_ok() { "random-a" } else { "random-b" };
    assert!(
        payroof::security::limits::allow(&app, existing, "test", 60, 10)
            .await
            .is_ok()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rate_limits")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    app.db.close().await;
    std::fs::remove_file(path).unwrap();
}
#[tokio::test]
async fn configured_body_limit_and_worker_readiness() {
    let mut app = app().await;
    Arc::get_mut(&mut app).unwrap().config.limits.pairing_body = 10;
    let (status, _) = json_request(
        &app,
        "/v1/pairings",
        serde_json::json!({"name":"too long for configured body"}),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        request(&app, "GET", "/readyz", "").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for c in &app.config.chains {
        sqlx::query("INSERT INTO chain_state(chain,next_height,healthy) VALUES(?,0,1)")
            .bind(&c.id)
            .execute(&app.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO worker_state(name,healthy,heartbeat) VALUES(?,1,?)")
            .bind(format!("scanner:{}", c.id))
            .bind(payroof::time::now())
            .execute(&app.db)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO worker_state(name,healthy,heartbeat) VALUES('delivery',1,?)")
        .bind(payroof::time::now())
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(request(&app, "GET", "/readyz", "").await.0, StatusCode::OK);
    sqlx::query("UPDATE worker_state SET heartbeat=0 WHERE name='delivery'")
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/readyz", "").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn assets_are_configuration_only_and_transfers_route_is_gone() {
    let app = app().await;
    let token = seeded(&app, "main", 1).await;
    // Watched assets come from the configuration alone: there is no route to add one.
    let (status, _) = json_auth_method(
        &app,
        "PUT",
        "/v1/projects/main/assets",
        serde_json::json!({"assets":[]}),
        &token,
    )
    .await;
    assert!(matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ));
    let (_, view) = request(&app, "GET", "/v1/projects/main", &token).await;
    let configured: Vec<&str> = view["chains"][0]["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    let expected: Vec<&str> = app.config.chains[0]
        .assets
        .iter()
        .map(|a| a.id.as_str())
        .collect();
    assert_eq!(configured, expected);
    assert_eq!(
        request(&app, "GET", "/v1/projects/main/transfers", &token)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn access_list_hides_revoked_and_revocation_is_idempotent_and_scoped() {
    let app = app().await;
    let a = seeded(&app, "main", 1).await;
    let mut tx = payroof::db::write(&app.db).await.unwrap();
    let (_, b) = http::auth::issue(&mut tx, 1, "second", &ALL).await.unwrap();
    tx.commit().await.unwrap();
    let other = seeded(&app, "other", 3).await;
    let (status, list) = request(&app, "GET", "/v1/projects/main/access", &a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["access"].as_array().unwrap().len(), 2);
    let revoked = access_path(&app, &b).await;
    for _ in 0..2 {
        assert_eq!(
            request(&app, "DELETE", &revoked, &a).await.0,
            StatusCode::NO_CONTENT
        );
    }
    let (_, list) = request(&app, "GET", "/v1/projects/main/access", &a).await;
    assert_eq!(list["access"].as_array().unwrap().len(), 1);
    assert!(
        !list
            .to_string()
            .contains(&revoked[revoked.rfind('/').unwrap() + 1..])
    );
    assert_eq!(
        request(&app, "GET", "/v1/projects/main/access", &b).await.0,
        StatusCode::UNAUTHORIZED
    );
    let foreign = access_path(&app, &other).await;
    assert_eq!(
        request(&app, "DELETE", &foreign, &a).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "DELETE", "/v1/projects/main/access/acc_missing", &a)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (_, list) = request(&app, "GET", "/v1/projects/other/access", &other).await;
    assert_eq!(list["access"].as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn access_creation_is_subset_only_listed_without_token_and_revocable() {
    let app = app().await;
    let a = seeded(&app, "main", 1).await;
    let path = "/v1/projects/main/access";
    let (status, c) = json_auth_method(
        &app,
        "POST",
        path,
        serde_json::json!({"name":"Reader","permissions":["paths","access"]}),
        &a,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (id, token) = (c["id"].as_str().unwrap(), c["token"].as_str().unwrap());
    assert!(id.starts_with("acc_") && token.starts_with("prf_"));
    assert_eq!(c["name"], "Reader");
    assert_eq!(c["permissions"], serde_json::json!(["paths", "access"]));
    assert!(c["created_at"].as_str().unwrap().ends_with('Z'));
    // Works only for its own permissions.
    assert_eq!(
        request(&app, "GET", "/v1/projects/main/paths", token)
            .await
            .0,
        StatusCode::OK
    );
    let (status, e) = request(&app, "GET", "/v1/projects/main/webhooks", token).await;
    assert_eq!(
        (status, e["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("permission_denied"))
    );
    // No escalation beyond the caller's own permissions.
    let (status, e) = json_auth_method(
        &app,
        "POST",
        path,
        serde_json::json!({"name":"Bad","permissions":["paths","webhooks"]}),
        token,
    )
    .await;
    assert_eq!(
        (status, e["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("permission_denied"))
    );
    // A subset is fine.
    let (status, _) = json_auth_method(
        &app,
        "POST",
        path,
        serde_json::json!({"name":"Narrow","permissions":["paths"]}),
        token,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    // Invalid input.
    let long = "x".repeat(101);
    for body in [
        serde_json::json!({"name":"","permissions":["paths"]}),
        serde_json::json!({"name":" padded ","permissions":["paths"]}),
        serde_json::json!({"name":"bad\nname","permissions":["paths"]}),
        serde_json::json!({"name":long,"permissions":["paths"]}),
        serde_json::json!({"name":"n","permissions":[]}),
        serde_json::json!({"name":"n","permissions":["paths","paths"]}),
    ] {
        let (status, e) = json_auth_method(&app, "POST", path, body, &a).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{e}");
    }
    for body in [
        serde_json::json!({"name":"n","permissions":["root"]}),
        serde_json::json!({"name":"n","permissions":["paths"],"extra":1}),
        serde_json::json!({"permissions":["paths"]}),
    ] {
        let (status, e) = json_auth_method(&app, "POST", path, body, &a).await;
        assert_eq!(
            (status, e["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_json"))
        );
    }
    // Wrong project and unauthenticated.
    let other = seeded(&app, "other", 3).await;
    let body = serde_json::json!({"name":"n","permissions":["paths"]});
    assert_eq!(
        json_auth_method(&app, "POST", path, body.clone(), &other)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        json_auth_method(&app, "POST", path, body, "").await.0,
        StatusCode::UNAUTHORIZED
    );
    // Listing never carries tokens; revocation works.
    let (_, list) = request(&app, "GET", path, &a).await;
    assert_eq!(list["access"].as_array().unwrap().len(), 3);
    assert!(!list.to_string().contains(token) && !list.to_string().contains("\"token\""));
    assert_eq!(
        request(&app, "DELETE", &format!("{path}/{id}"), &a).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "GET", "/v1/projects/main/paths", token)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
