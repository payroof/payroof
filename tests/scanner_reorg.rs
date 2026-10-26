//! Deterministic RPC-backed scanner tests: no Anvil or external network required.
use axum::{Json, Router, extract::State as RpcState, routing::post};
use payroof::{App, State, config::Config, scanner};
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;
use zeroize::Zeroizing;

const CHAIN: &str = "eip155:31337";
const NATIVE: &str = "eip155:31337/slip44:60";
const TOKEN: &str = "0x1111111111111111111111111111111111111111";
const OTHER_TOKEN: &str = "0x2222222222222222222222222222222222222222";
const ADDRESS: &str = "0x3333333333333333333333333333333333333333";
const TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// Larger than both u64 and JavaScript's exact integer range.
const AMOUNT_HEX: &str = "0x10000000000000001";
const AMOUNT: &str = "18446744073709551617";
fn token_asset() -> String {
    format!("{CHAIN}/erc20:{TOKEN}")
}
fn hash(n: u64) -> String {
    format!("0x{n:064x}")
}
fn block(n: u64, hash_id: u64, parent: u64, transactions: Vec<Value>) -> Value {
    json!({"number":format!("0x{n:x}"),"hash":hash(hash_id),"parentHash":hash(parent),"transactions":transactions})
}
fn native(tx: u64) -> Value {
    json!({"hash":hash(tx),"from":"0x00000000000000000000000000000000000000aa","to":ADDRESS,"value":AMOUNT_HEX})
}
fn log(tx: u64, block_id: u64, contract: &str) -> Value {
    json!({"address":contract,"blockHash":hash(block_id),"transactionHash":hash(tx),"logIndex":"0x0","removed":false,"topics":[TOPIC,hash(0),format!("0x{}{}", "0".repeat(24), &ADDRESS[2..])],"data":format!("0x{:0>64}",&AMOUNT_HEX[2..])})
}
struct RpcData {
    chain_id: u64,
    head: u64,
    blocks: BTreeMap<u64, Value>,
    receipts: BTreeMap<String, Value>,
    logs: Vec<Value>,
    calls: Vec<Value>,
    canonical_override: Option<String>,
    ignore_log_filters: bool,
}
struct FakeRpc {
    data: Arc<Mutex<RpcData>>,
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for FakeRpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl FakeRpc {
    async fn start() -> Self {
        let data = Arc::new(Mutex::new(RpcData {
            chain_id: 31337,
            head: 1,
            blocks: BTreeMap::from([
                (1, block(1, 1, 0, vec![native(100)])),
                (2, block(2, 2, 1, vec![])),
            ]),
            receipts: BTreeMap::from([(hash(100), json!({"status":"0x1","blockHash":hash(1)}))]),
            logs: vec![log(200, 1, TOKEN)],
            calls: vec![],
            canonical_override: None,
            ignore_log_filters: false,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/", post(reply))
            .with_state(data.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { data, url, task }
    }
}
async fn reply(
    RpcState(data): RpcState<Arc<Mutex<RpcData>>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let mut data = data.lock().unwrap();
    data.calls.push(request.clone());
    let result = match request["method"].as_str().unwrap() {
        "eth_chainId" => json!(format!("0x{:x}", data.chain_id)),
        "eth_blockNumber" => json!(format!("0x{:x}", data.head)),
        "eth_getBlockByNumber" => {
            let height = u64::from_str_radix(
                request["params"][0]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let mut b = data.blocks.get(&height).cloned().unwrap_or(Value::Null);
            if request["params"][1] == false
                && let Some(h) = &data.canonical_override
            {
                b["hash"] = json!(h);
            }
            b
        }
        "eth_getTransactionReceipt" => data
            .receipts
            .get(request["params"][0].as_str().unwrap())
            .cloned()
            .unwrap_or(Value::Null),
        "eth_getLogs" => {
            let filter = &request["params"][0];
            // Model node-side contract/topic filtering, including unrelated token logs.
            json!(
                data.logs
                    .iter()
                    .filter(|l| data.ignore_log_filters
                        || (l["address"] == filter["address"]
                            && l["blockHash"] == filter["blockHash"]
                            && l["topics"][0] == filter["topics"][0]))
                    .collect::<Vec<_>>()
            )
        }
        method => panic!("unexpected RPC method: {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
}
async fn app(rpc: &FakeRpc, database: Option<&std::path::Path>) -> App {
    let options = match database {
        Some(path) => sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true),
        None => "sqlite::memory:".parse().unwrap(),
    }
    .foreign_keys(true);
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let mut config: Config = toml::from_str(include_str!("../config/payroof.local.toml")).unwrap();
    config.chains = vec![
        serde_json::from_value(
            json!({"id":CHAIN,"name":"Test chain","rpc":rpc.url,"confirmations":2,"start_height":1,"assets":[
                {"id":NATIVE,"kind":"native","symbol":"ETH","decimals":18},
                {"id":token_asset(),"kind":"erc20","symbol":"TEST","decimals":18}
            ]}),
        )
        .unwrap(),
    ];
    Arc::new(State {
        db,
        config,
        cursor_key: Zeroizing::new([1; 32]),
        master: Zeroizing::new([2; 32]),
        altcha_key: Zeroizing::new("3".repeat(64)),
        draining: Default::default(),
    })
}
async fn seed(app: &App) {
    sqlx::query(
        "INSERT INTO projects(id,project,recovery_public_key,created_at) VALUES(1,'main',?,0)",
    )
    .bind(vec![1u8; 32])
    .execute(&app.db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO receive_mappings(id,project_id,reference,address_index,address,allocated_sequence,created_at) VALUES(1,1,'order',0,?,1,0)").bind(ADDRESS).execute(&app.db).await.unwrap();
    sqlx::query("INSERT INTO chain_state(chain,next_height) VALUES(?,1)")
        .bind(CHAIN)
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO webhooks(id,project_id,url,events_json,secret_ciphertext,created_at) VALUES('wh_test',1,'http://127.0.0.1:1','[\"seen\",\"confirmed\"]','unused',0)").execute(&app.db).await.unwrap();
}
async fn step(app: &App) -> anyhow::Result<()> {
    // A fresh state and a one-block batch: every call re-verifies and scans one block.
    let rpc = scanner::rpc::Rpc::new(&app.config.chains[0])?;
    scanner::scan(
        app,
        &app.config.chains[0],
        &rpc,
        &mut scanner::ScanState::default(),
        1,
    )
    .await
    .map(|_| ())
}
async fn count(app: &App, table: &str) -> i64 {
    let query = match table {
        "transfers" => "SELECT COUNT(*) FROM transfers",
        "transfer_events" => "SELECT COUNT(*) FROM transfer_events",
        "webhook_deliveries" => "SELECT COUNT(*) FROM webhook_deliveries",
        "chain_blocks" => "SELECT COUNT(*) FROM chain_blocks",
        _ => panic!("unsupported test table"),
    };
    sqlx::query_scalar(query).fetch_one(&app.db).await.unwrap()
}
async fn next(app: &App) -> i64 {
    sqlx::query_scalar("SELECT next_height FROM chain_state")
        .fetch_one(&app.db)
        .await
        .unwrap()
}
async fn states(app: &App) -> Vec<String> {
    sqlx::query_scalar("SELECT state FROM transfers ORDER BY asset")
        .fetch_all(&app.db)
        .await
        .unwrap()
}
async fn sequence(app: &App) -> Option<i64> {
    sqlx::query_scalar("SELECT confirmed_sequence FROM receive_mappings WHERE id=1")
        .fetch_one(&app.db)
        .await
        .unwrap()
}
async fn ready(app: &App) -> axum::http::StatusCode {
    payroof::http::router(app.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri("/readyz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}
struct Workers(Vec<tokio::task::JoinHandle<()>>);
impl Drop for Workers {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
async fn assert_worker_unready(app: &App) {
    // Exercise the real worker error-to-health path, not fabricated health rows.
    let _workers = Workers(payroof::workers::start(app.clone()));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let failed: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM worker_state WHERE name=? AND healthy=0)",
            )
            .bind(format!("scanner:{CHAIN}"))
            .fetch_one(&app.db)
            .await
            .unwrap();
            if failed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scanner must report failure promptly");
    assert_eq!(
        ready(app).await,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT healthy FROM chain_state")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn native_and_erc20_seen_confirmed_exact_strings_and_duplicate_observations() {
    let rpc = FakeRpc::start().await;
    // Repeated RPC entries must not duplicate transfers, events, or outbox records.
    {
        let mut data = rpc.data.lock().unwrap();
        data.blocks.get_mut(&1).unwrap()["transactions"] = json!([native(100), native(100)]);
        data.logs.push(log(200, 1, TOKEN));
        data.head = 100; // Unscanned head must not confer finality.
    }
    let app = app(&rpc, None).await;
    seed(&app).await;
    assert_eq!(
        ready(&app).await,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    step(&app).await.unwrap();
    assert_eq!(states(&app).await, vec!["seen", "seen"]);
    assert_eq!(count(&app, "transfers").await, 2);
    assert_eq!(count(&app, "transfer_events").await, 2);
    assert_eq!(count(&app, "webhook_deliveries").await, 2);
    assert_eq!(sequence(&app).await, None);
    step(&app).await.unwrap();
    assert_eq!(states(&app).await, vec!["confirmed", "confirmed"]);
    assert_eq!(sequence(&app).await, Some(1));
    rpc.data.lock().unwrap().head = 2;
    step(&app).await.unwrap();
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 2);
    assert_eq!(count(&app, "transfer_events").await, 4);
    assert_eq!(count(&app, "webhook_deliveries").await, 4);
    for row in sqlx::query("SELECT amount,event_index,asset FROM transfers")
        .fetch_all(&app.db)
        .await
        .unwrap()
    {
        assert_eq!(row.get::<String, _>("amount"), AMOUNT);
        assert_eq!(
            row.get::<i64, _>("event_index"),
            if row.get::<String, _>("asset") == NATIVE {
                -1
            } else {
                0
            }
        );
    }
    for payload in sqlx::query_scalar::<_, String>("SELECT payload_json FROM transfer_events")
        .fetch_all(&app.db)
        .await
        .unwrap()
    {
        let payload: Value = serde_json::from_str(&payload).unwrap();
        assert!(payload["transfer"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(payload["amount"], json!(AMOUNT));
        assert_eq!(payload["block"]["height"], json!("1"));
        assert_eq!(payload["block"]["hash"], hash(1));
    }
}

#[tokio::test]
async fn unconfigured_tokens_removed_logs_and_failed_receipts_do_not_match() {
    let rpc = FakeRpc::start().await;
    {
        let mut data = rpc.data.lock().unwrap();
        data.receipts.get_mut(&hash(100)).unwrap()["status"] = json!("0x0");
        data.logs = vec![
            log(201, 1, OTHER_TOKEN),
            log(202, 1, TOKEN),
            log(203, 99, TOKEN),
        ];
        data.logs[1]["removed"] = json!(true);
    }
    let app = app(&rpc, None).await;
    seed(&app).await;
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 0);
    assert_eq!(count(&app, "transfer_events").await, 0);
    assert_eq!(count(&app, "webhook_deliveries").await, 0);
    let calls = rpc.data.lock().unwrap().calls.clone();
    let filter = &calls.iter().find(|c| c["method"] == "eth_getLogs").unwrap()["params"][0];
    assert_eq!(filter["address"], TOKEN);
    assert_eq!(filter["topics"][0], TOPIC);
    assert_eq!(filter["blockHash"], hash(1));
    {
        let mut data = rpc.data.lock().unwrap();
        data.head = 2;
        data.blocks.insert(2, block(2, 2, 1, vec![native(101)]));
        data.receipts
            .insert(hash(101), json!({"status":"0x1","blockHash":hash(2)}));
        data.logs = vec![log(204, 2, TOKEN)];
    }
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 2);
    {
        let mut data = rpc.data.lock().unwrap();
        data.head = 3;
        data.blocks.insert(3, block(3, 3, 2, vec![native(102)]));
        data.receipts
            .insert(hash(102), json!({"status":"0x1","blockHash":hash(3)}));
        data.logs = vec![log(205, 3, TOKEN)];
    }
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 4);
}

#[tokio::test]
async fn scanner_enforces_contract_and_topic_even_when_rpc_ignores_filters() {
    let rpc = FakeRpc::start().await;
    {
        let mut data = rpc.data.lock().unwrap();
        data.ignore_log_filters = true;
        data.receipts.get_mut(&hash(100)).unwrap()["status"] = json!("0x0");
        let mut wrong_topic = log(202, 1, TOKEN);
        wrong_topic["topics"][0] = json!(hash(999));
        data.logs = vec![log(201, 1, OTHER_TOKEN), wrong_topic];
    }
    let app = app(&rpc, None).await;
    seed(&app).await;
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 0);
    assert_eq!(count(&app, "transfer_events").await, 0);
}

#[tokio::test]
async fn chain_id_mismatch_leaves_checkpoint_untouched_and_worker_unready() {
    let rpc = FakeRpc::start().await;
    rpc.data.lock().unwrap().chain_id = 1;
    let app = app(&rpc, None).await;
    seed(&app).await;
    assert!(
        step(&app)
            .await
            .unwrap_err()
            .to_string()
            .contains("RPC chain mismatch")
    );
    assert_eq!(next(&app).await, 1);
    assert_eq!(count(&app, "chain_blocks").await, 0);
    assert_eq!(count(&app, "transfers").await, 0);
    assert!(
        rpc.data
            .lock()
            .unwrap()
            .calls
            .iter()
            .all(|c| c["method"] == "eth_chainId")
    );
    assert_worker_unready(&app).await;
}

#[tokio::test]
async fn unconfirmed_reorg_orphans_and_removes_pending_seen_deliveries_then_rescans() {
    let rpc = FakeRpc::start().await;
    let app = app(&rpc, None).await;
    seed(&app).await;
    step(&app).await.unwrap();
    // Keep one delivered event as history; only unsent seen deliveries may be removed.
    sqlx::query("UPDATE webhook_deliveries SET sent_at=1 WHERE event_id=(SELECT id FROM transfer_events ORDER BY id LIMIT 1)").execute(&app.db).await.unwrap();
    {
        let mut data = rpc.data.lock().unwrap();
        data.blocks.insert(1, block(1, 11, 0, vec![]));
        data.logs.clear();
    }
    step(&app).await.unwrap();
    assert_eq!(states(&app).await, vec!["orphaned", "orphaned"]);
    assert_eq!(next(&app).await, 1);
    assert_eq!(count(&app, "chain_blocks").await, 0);
    assert_eq!(count(&app, "transfer_events").await, 2);
    assert_eq!(count(&app, "webhook_deliveries").await, 1);
    assert_eq!(sequence(&app).await, None);
    step(&app).await.unwrap();
    assert_eq!(next(&app).await, 2);
    assert_eq!(states(&app).await, vec!["orphaned", "orphaned"]);
    {
        let mut data = rpc.data.lock().unwrap();
        data.head = 2;
        data.blocks.insert(2, block(2, 12, 11, vec![native(101)]));
        data.receipts
            .insert(hash(101), json!({"status":"0x1","blockHash":hash(12)}));
        data.logs = vec![log(201, 12, TOKEN)];
    }
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 4);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transfers WHERE state='seen'")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        2
    );
    assert_eq!(sequence(&app).await, None);
    {
        let mut data = rpc.data.lock().unwrap();
        data.head = 3;
        data.blocks.insert(3, block(3, 13, 12, vec![]));
    }
    step(&app).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transfers WHERE state='orphaned'")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transfers WHERE state='confirmed'")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        2
    );
    assert_eq!(sequence(&app).await, Some(1));
}

#[tokio::test]
async fn confirmed_reorg_fails_closed_without_changing_events_or_checkpoint() {
    let rpc = FakeRpc::start().await;
    let mut app = app(&rpc, None).await;
    Arc::get_mut(&mut app).unwrap().config.chains[0].confirmations = 1;
    seed(&app).await;
    step(&app).await.unwrap();
    assert_eq!(states(&app).await, vec!["confirmed", "confirmed"]);
    rpc.data
        .lock()
        .unwrap()
        .blocks
        .insert(1, block(1, 11, 0, vec![]));
    assert!(
        step(&app)
            .await
            .unwrap_err()
            .to_string()
            .contains("reorg crosses confirmed transfer")
    );
    assert_eq!(states(&app).await, vec!["confirmed", "confirmed"]);
    assert_eq!(next(&app).await, 2);
    assert_eq!(count(&app, "chain_blocks").await, 1);
    assert_eq!(count(&app, "transfer_events").await, 4);
    assert_eq!(count(&app, "webhook_deliveries").await, 4);
    assert_eq!(sequence(&app).await, Some(1));
    // Keep the delivery worker from attempting fixture-only encrypted secrets.
    sqlx::query("UPDATE webhook_deliveries SET next_attempt_at=?")
        .bind(payroof::time::now() + 3600)
        .execute(&app.db)
        .await
        .unwrap();
    assert_worker_unready(&app).await;
    assert_eq!(next(&app).await, 2);
    assert_eq!(states(&app).await, vec!["confirmed", "confirmed"]);
}

#[tokio::test]
async fn canonical_change_and_database_error_are_atomic() {
    let rpc = FakeRpc::start().await;
    let mut app = app(&rpc, None).await;
    Arc::get_mut(&mut app).unwrap().config.chains[0].confirmations = 1;
    seed(&app).await;
    rpc.data.lock().unwrap().canonical_override = Some(hash(99));
    assert!(
        step(&app)
            .await
            .unwrap_err()
            .to_string()
            .contains("block changed during scan")
    );
    assert_eq!(next(&app).await, 1);
    assert_eq!(count(&app, "transfers").await, 0);
    assert_eq!(count(&app, "chain_blocks").await, 0);
    rpc.data.lock().unwrap().canonical_override = None;
    // Failure late in the transaction must roll back transfers, events and deliveries.
    sqlx::query("CREATE TRIGGER reject_checkpoint BEFORE UPDATE OF next_height ON chain_state BEGIN SELECT RAISE(ABORT,'test checkpoint failure'); END").execute(&app.db).await.unwrap();
    assert!(step(&app).await.is_err());
    assert_eq!(next(&app).await, 1);
    for table in [
        "transfers",
        "transfer_events",
        "webhook_deliveries",
        "chain_blocks",
    ] {
        assert_eq!(count(&app, table).await, 0, "{table} must roll back");
    }
    assert_eq!(sequence(&app).await, None);
    sqlx::query("DROP TRIGGER reject_checkpoint")
        .execute(&app.db)
        .await
        .unwrap();
    step(&app).await.unwrap();
    assert_eq!(count(&app, "transfers").await, 2);
}

#[tokio::test]
async fn healthy_scanner_and_delivery_workers_make_readiness_available() {
    let rpc = FakeRpc::start().await;
    let app = app(&rpc, None).await;
    seed(&app).await;
    // No external webhook I/O: readiness still exercises both real worker loops.
    sqlx::query("DELETE FROM webhooks")
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        ready(&app).await,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    let _workers = Workers(payroof::workers::start(app.clone()));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if ready(&app).await == axum::http::StatusCode::OK {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("healthy workers must become ready promptly");
    assert_eq!(next(&app).await, 2);
    assert_eq!(states(&app).await, vec!["seen", "seen"]);
}

struct DatabaseFile(std::path::PathBuf);
impl Drop for DatabaseFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[tokio::test]
async fn restart_reopens_durable_checkpoint_without_duplicate_events() {
    let rpc = FakeRpc::start().await;
    let file = DatabaseFile(std::env::temp_dir().join(format!(
        "payroof-scanner-{}.sqlite",
        payroof::security::secret::id("test_").unwrap()
    )));
    let first = app(&rpc, Some(&file.0)).await;
    seed(&first).await;
    step(&first).await.unwrap();
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM transfers ORDER BY id")
        .fetch_all(&first.db)
        .await
        .unwrap();
    first.db.close().await;
    drop(first);
    let restarted = app(&rpc, Some(&file.0)).await;
    assert_eq!(next(&restarted).await, 2);
    assert_eq!(states(&restarted).await, vec!["seen", "seen"]);
    step(&restarted).await.unwrap(); // Already caught up: no replay.
    assert_eq!(count(&restarted, "transfer_events").await, 2);
    rpc.data.lock().unwrap().head = 2;
    step(&restarted).await.unwrap();
    step(&restarted).await.unwrap();
    assert_eq!(states(&restarted).await, vec!["confirmed", "confirmed"]);
    assert_eq!(count(&restarted, "transfer_events").await, 4);
    assert_eq!(count(&restarted, "webhook_deliveries").await, 4);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT id FROM transfers ORDER BY id")
            .fetch_all(&restarted.db)
            .await
            .unwrap(),
        ids
    );
    assert_eq!(sequence(&restarted).await, Some(1));
    restarted.db.close().await;
}

#[tokio::test]
async fn unconfigured_tokens_are_never_recorded() {
    let rpc = FakeRpc::start().await;
    {
        // The node returns every log, including a token nobody configured.
        let mut data = rpc.data.lock().unwrap();
        data.ignore_log_filters = true;
        data.logs.push(log(200, 1, TOKEN));
        data.logs.push(log(201, 1, OTHER_TOKEN));
    }
    let app = app(&rpc, None).await;
    seed(&app).await;
    step(&app).await.unwrap();
    let assets: Vec<String> = sqlx::query_scalar("SELECT asset FROM transfers ORDER BY asset")
        .fetch_all(&app.db)
        .await
        .unwrap();
    assert_eq!(assets, vec![token_asset(), NATIVE.to_string()]);
}

#[tokio::test]
async fn a_chain_without_a_start_height_begins_at_its_head_once() {
    let rpc = FakeRpc::start().await;
    rpc.data.lock().unwrap().head = 42;
    let first = app(&rpc, None).await;
    let mut chain = first.config.chains[0].clone();
    chain.start_height = None;
    let http = scanner::rpc::Rpc::new(&chain).unwrap();
    scanner::init(&first, &chain, &http).await.unwrap();
    assert_eq!(next(&first).await, 42);
    // Later starts keep the recorded position.
    rpc.data.lock().unwrap().head = 50;
    scanner::init(&first, &chain, &http).await.unwrap();
    assert_eq!(next(&first).await, 42);
    // A configured height is used as given.
    let other = app(&rpc, None).await;
    scanner::init(&other, &other.config.chains[0], &http)
        .await
        .unwrap();
    assert_eq!(next(&other).await, 1);
}

fn methods(rpc: &FakeRpc) -> Vec<String> {
    let mut data = rpc.data.lock().unwrap();
    data.calls
        .drain(..)
        .map(|c| c["method"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn unchanged_head_costs_one_request_and_a_batch_catches_up_in_one_step() {
    let rpc = FakeRpc::start().await;
    rpc.data.lock().unwrap().head = 2;
    let app = app(&rpc, None).await;
    seed(&app).await;
    let chain = &app.config.chains[0];
    let client = scanner::rpc::Rpc::new(chain).unwrap();
    let mut state = scanner::ScanState::default();
    // Both blocks in one step; the second is chained by parentHash, not re-fetched.
    let outcome = scanner::scan(&app, chain, &client, &mut state, 20)
        .await
        .unwrap();
    assert!(!outcome.behind);
    assert_eq!(next(&app).await, 3);
    // Idle: the first idle step re-verifies the tip, later ones only ask for the head.
    scanner::scan(&app, chain, &client, &mut state, 20)
        .await
        .unwrap();
    methods(&rpc);
    for _ in 0..3 {
        scanner::scan(&app, chain, &client, &mut state, 20)
            .await
            .unwrap();
    }
    assert_eq!(methods(&rpc), vec!["eth_blockNumber"; 3]);
    // A new block resumes full work.
    {
        let mut data = rpc.data.lock().unwrap();
        data.head = 3;
        data.blocks.insert(3, block(3, 3, 2, vec![]));
    }
    scanner::scan(&app, chain, &client, &mut state, 20)
        .await
        .unwrap();
    assert_eq!(next(&app).await, 4);
}

#[tokio::test]
async fn full_transactions_are_requested_only_when_a_native_asset_is_watched() {
    let rpc = FakeRpc::start().await;
    let app = app(&rpc, None).await;
    seed(&app).await;
    let mut chain = app.config.chains[0].clone();
    chain.assets.retain(|a| a.kind != "native");
    let client = scanner::rpc::Rpc::new(&chain).unwrap();
    scanner::scan(&app, &chain, &client, &mut Default::default(), 1)
        .await
        .unwrap();
    let flags: Vec<Value> = rpc
        .data
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| c["method"] == "eth_getBlockByNumber")
        .map(|c| c["params"][1].clone())
        .collect();
    assert!(!flags.is_empty() && flags.iter().all(|f| f == false));
    assert_eq!(count(&app, "transfers").await, 1); // the token transfer only
}

#[tokio::test]
async fn a_lagging_node_is_ignored_and_a_dead_primary_fails_over() {
    let rpc = FakeRpc::start().await;
    let app = app(&rpc, None).await;
    seed(&app).await;
    let mut chain = app.config.chains[0].clone();
    chain.rpc = serde_json::from_value(json!(["http://127.0.0.1:1/KEY", rpc.url])).unwrap();
    let client = scanner::rpc::Rpc::new(&chain).unwrap();
    let mut state = scanner::ScanState::default();
    rpc.data.lock().unwrap().head = 500;
    scanner::scan(&app, &chain, &client, &mut state, 1)
        .await
        .unwrap();
    assert_eq!(next(&app).await, 2); // served by the second endpoint
    // The only node now reports a head far below the one seen: treated as no new block.
    rpc.data.lock().unwrap().head = 3;
    methods(&rpc);
    let outcome = scanner::scan(&app, &chain, &client, &mut state, 20)
        .await
        .unwrap();
    assert!(!outcome.behind);
    assert_eq!(next(&app).await, 2);
    assert_eq!(methods(&rpc), vec!["eth_blockNumber"]);
}

#[tokio::test]
async fn idle_workers_poll_at_the_configured_interval_without_rewriting_heartbeats() {
    let rpc = FakeRpc::start().await;
    let mut app = app(&rpc, None).await;
    Arc::get_mut(&mut app).unwrap().config.chains[0].poll_interval_ms = Some(200);
    seed(&app).await;
    sqlx::query("DELETE FROM webhooks")
        .execute(&app.db)
        .await
        .unwrap();
    let _workers = Workers(payroof::workers::start(app.clone()));
    tokio::time::timeout(Duration::from_secs(3), async {
        while ready(&app).await != axum::http::StatusCode::OK {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("workers become ready");
    let beats = || async {
        sqlx::query_as::<_, (String, i64)>("SELECT name,heartbeat FROM worker_state ORDER BY name")
            .fetch_all(&app.db)
            .await
            .unwrap()
    };
    // Let the scanner reach the idle state (block 1 and 2 scanned, then head only).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (before, calls_before) = (beats().await, rpc.data.lock().unwrap().calls.len());
    assert_eq!(before.len(), 2);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let polls = rpc.data.lock().unwrap().calls.len() - calls_before;
    // ~10 polls of eth_blockNumber at 200 ms, and no heartbeat write in between.
    assert!((5..=14).contains(&polls), "{polls} idle requests");
    assert_eq!(beats().await, before);
    assert_eq!(ready(&app).await, axum::http::StatusCode::OK);
}
