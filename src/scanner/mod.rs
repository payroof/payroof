//! Canonical block observation, fetched in concurrent windows and applied in order. Native transfers are top-level EVM
//! transactions; value moved by internal calls is not observed.
pub mod rpc;
use crate::{App, config::Chain, security::secret::id, time::now};
use futures_util::{StreamExt, stream};
use num_bigint::BigUint;
use rpc::Rpc;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    future::Future,
    time::{Duration, Instant},
};
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
/// Most blocks one scan step observes before yielding to the poll loop.
pub const MAX_BLOCKS_PER_STEP: usize = 100;
/// Blocks recorded per database transaction while catching up.
const COMMIT_CHUNK: usize = 25;
/// The newest blocks (within this many of the head) get their logs by block hash.
const LIVE_MARGIN: i64 = 4;
/// A head this many blocks below the highest one seen comes from a lagging node (a real
/// reorg is far shallower) and is not used.
const HEAD_REGRESSION_TOLERANCE: i64 = 32;
/// While the head is unchanged, the last scanned block is re-verified at this interval.
const IDLE_RECHECK: Duration = Duration::from_secs(30);
/// How long a block below the reported head may stay unavailable before the scanner reports
/// it. Load-balanced providers announce a head before every backend has the block; that is
/// retried on the next poll instead of marking the chain unhealthy.
const MISSING_BLOCK_GRACE: Duration = Duration::from_secs(60);

/// What a scanner remembers between steps (in memory only; nothing here is authoritative).
#[derive(Default)]
pub struct ScanState {
    last_head: Option<i64>,
    last_check: Option<Instant>,
    /// `chain_state.healthy` is known to be 1, so idle polls need not write it again.
    pub healthy_marked: bool,
    /// A block the node reported but could not return yet, and since when.
    missing: Option<(i64, Instant)>,
    /// Requests in flight at once (0: not set yet): halves when endpoints push back and
    /// grows by one after every clean window, up to the chain's `max_concurrency`.
    in_flight: usize,
    /// Blocks per `eth_getLogs` range (0: not set yet); halves when a node refuses a range.
    log_blocks: i64,
}
impl ScanState {
    fn concurrency(&self, chain: &Chain) -> usize {
        match self.in_flight {
            0 => chain.max_concurrency(),
            n => n.min(chain.max_concurrency()),
        }
    }
    fn adapt(&mut self, pushed_back: bool, chain: &Chain) {
        let now = self.concurrency(chain);
        self.in_flight = if pushed_back {
            (now / 2).max(1)
        } else {
            (now + 1).min(chain.max_concurrency())
        };
    }
    fn log_span(&self) -> i64 {
        match self.log_blocks {
            0 => MAX_BLOCKS_PER_STEP as i64,
            n => n,
        }
    }
    fn adapt_span(&mut self, split: bool, used: i64) {
        self.log_blocks = if split {
            (used / 2).max(1)
        } else {
            (used * 2).min(MAX_BLOCKS_PER_STEP as i64)
        };
    }
}
/// Progress of one `scan` call.
pub struct Outcome {
    /// Blocks remain between the scan height and the head.
    pub behind: bool,
}
enum Block {
    Idle,
    Rewound,
    Scanned { next: i64 },
}
fn quantity(v: &Value) -> anyhow::Result<BigUint> {
    let s = v
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(|| anyhow::anyhow!("invalid quantity"))?;
    anyhow::ensure!(!s.is_empty() && s.len() <= 64, "invalid quantity");
    BigUint::parse_bytes(s.as_bytes(), 16).ok_or_else(|| anyhow::anyhow!("invalid quantity"))
}
fn height(v: &Value) -> anyhow::Result<i64> {
    i64::try_from(quantity(v)?).map_err(|_| anyhow::anyhow!("quantity overflow"))
}
fn text(v: &Value, key: &str) -> anyhow::Result<String> {
    Ok(v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing RPC field"))?
        .to_ascii_lowercase())
}
async fn emit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    transfer: &str,
    event: &str,
) -> anyhow::Result<()> {
    let r = sqlx::query(
        "SELECT t.*,p.project,m.reference FROM transfers t
         JOIN projects p ON p.id=t.project_id
         JOIN receive_mappings m ON m.id=t.mapping_id WHERE t.id=?",
    )
    .bind(transfer)
    .fetch_one(&mut **tx)
    .await?;
    let eid = id("evt_")?;
    let payload = json!({
        "id": eid, "event": event, "transfer": transfer,
        "project": r.get::<String,_>("project"),
        "reference": r.get::<String,_>("reference"),
        "chain": r.get::<String,_>("chain"),
        "asset": r.get::<String,_>("asset"),
        "address": r.get::<String,_>("address"),
        "transaction": r.get::<String,_>("transaction_id"),
        "amount": r.get::<String,_>("amount"),
        "block": {
            "height": r.get::<i64,_>("block_height").to_string(),
            "hash": r.get::<String,_>("block_hash")
        }
    });
    let n = sqlx::query(
        "INSERT INTO transfer_events(id,transfer_id,event,payload_json,created_at)
         VALUES(?,?,?,?,?) ON CONFLICT(transfer_id,event) DO NOTHING",
    )
    .bind(&eid)
    .bind(transfer)
    .bind(event)
    .bind(payload.to_string())
    .bind(now())
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if n == 1 {
        let rows = sqlx::query("SELECT id,events_json FROM webhooks WHERE project_id=?")
            .bind(r.get::<i64, _>("project_id"))
            .fetch_all(&mut **tx)
            .await?;
        for wh in rows {
            let events: Vec<String> = serde_json::from_str(wh.get("events_json"))?;
            if events.iter().any(|e| e == event) {
                sqlx::query("INSERT INTO webhook_deliveries(webhook_id,event_id,next_attempt_at) VALUES(?,?,?)").bind(wh.get::<String,_>("id")).bind(&eid).bind(now()).execute(&mut **tx).await?;
            }
        }
    }
    Ok(())
}
struct Incoming {
    address: String,
    asset: String,
    transaction: String,
    index: i64,
    amount: String,
}
/// The chain's current block height, from the endpoint recorded in `pin` when usable.
async fn head(rpc: &Rpc, pin: &mut Option<usize>) -> anyhow::Result<i64> {
    height(&rpc.call(pin, "eth_blockNumber", json!([])).await?)
}
/// Records where scanning starts, on a chain's first run only: the configured
/// `start_height`, or the chain's current head when none is configured.
pub async fn init(app: &App, chain: &Chain, rpc: &Rpc) -> anyhow::Result<()> {
    let known: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chain_state WHERE chain=?)")
        .bind(&chain.id)
        .fetch_one(&app.db)
        .await?;
    if known {
        return Ok(());
    }
    let start = match chain.start_height {
        Some(height) => i64::try_from(height)?,
        None => head(rpc, &mut None).await?,
    };
    sqlx::query("INSERT INTO chain_state(chain,next_height) VALUES(?,?) ON CONFLICT DO NOTHING")
        .bind(&chain.id)
        .bind(start)
        .execute(&app.db)
        .await?;
    Ok(())
}
/// The current head, or `None` when the answering node lags far behind what was seen
/// (treated as "no new block"; the node is cooled down so another one is asked next).
async fn observe_head(
    rpc: &Rpc,
    pin: &mut Option<usize>,
    state: &ScanState,
) -> anyhow::Result<Option<i64>> {
    let mut lagged = false;
    for _ in 0..rpc.len() {
        let head = match head(rpc, pin).await {
            Ok(head) => head,
            // Only a lagging node answered; no other node is available right now.
            Err(_) if lagged => return Ok(None),
            Err(error) => return Err(error),
        };
        match (state.last_head, *pin) {
            (Some(seen), Some(i)) if head + HEAD_REGRESSION_TOLERANCE < seen => {
                rpc.penalize(i, "RPC endpoint lagging", None, false);
                *pin = None;
                lagged = true;
            }
            _ => return Ok(Some(head)),
        }
    }
    Ok(None)
}
/// Observes up to `max_blocks` new blocks. Cheap when nothing changed: with an unchanged
/// head only `eth_blockNumber` is requested (the last block is re-verified every 30 s).
/// When behind, the blocks of one step are fetched concurrently (see the module notes in
/// `docs/operations.md`), checked against each other by `parentHash`, and committed in
/// order in a few database transactions.
pub async fn scan(
    app: &App,
    chain: &Chain,
    rpc: &Rpc,
    state: &mut ScanState,
    max_blocks: usize,
) -> anyhow::Result<Outcome> {
    let mut pin = None;
    let Some(head) = observe_head(rpc, &mut pin, state).await? else {
        return Ok(Outcome { behind: false });
    };
    let unchanged = state.last_head == Some(head)
        && state
            .last_check
            .is_some_and(|checked| checked.elapsed() < IDLE_RECHECK);
    state.last_head = Some(head);
    if unchanged {
        let next: i64 = sqlx::query_scalar("SELECT next_height FROM chain_state WHERE chain=?")
            .bind(&chain.id)
            .fetch_one(&app.db)
            .await?;
        if next > head {
            return Ok(Outcome { behind: false });
        }
    }
    let behind =
        match scan_window(app, chain, rpc, &mut pin, state, head, max_blocks.max(1)).await? {
            Block::Idle => false,
            Block::Rewound => true,
            Block::Scanned { next } => next <= head,
        };
    Ok(Outcome { behind })
}

/// A block of the window, fully observed but not yet committed.
struct Observed {
    height: i64,
    hash: String,
    parent: String,
    incoming: Vec<Incoming>,
}

/// Watched assets: exactly the ones configured for this chain, nothing else.
struct Watched {
    natives: Vec<String>,
    /// contract -> asset id
    tokens: BTreeMap<String, String>,
}
impl Watched {
    fn new(chain: &Chain) -> anyhow::Result<Self> {
        let mut natives = Vec::new();
        let mut tokens = BTreeMap::new();
        for a in &chain.assets {
            if a.kind == "native" {
                natives.push(a.id.clone());
            } else {
                let contract =
                    a.id.split_once("/erc20:")
                        .ok_or_else(|| anyhow::anyhow!("invalid token"))?
                        .1;
                tokens.insert(contract.to_owned(), a.id.clone());
            }
        }
        Ok(Self { natives, tokens })
    }
    /// The `address` member of an `eth_getLogs` filter covering every watched token.
    fn address_filter(&self) -> Value {
        match self.tokens.keys().collect::<Vec<_>>().as_slice() {
            [one] => json!(one),
            many => json!(many),
        }
    }
}

/// Runs `calls` with at most `limit` in flight, results in input order.
async fn concurrently<T, F>(limit: usize, calls: Vec<F>) -> Vec<T>
where
    F: Future<Output = T>,
{
    stream::iter(calls).buffered(limit.max(1)).collect().await
}

async fn fetch_blocks(
    rpc: &Rpc,
    pin: Option<usize>,
    heights: &[i64],
    full: bool,
    limit: usize,
) -> Vec<anyhow::Result<Value>> {
    concurrently(
        limit,
        heights
            .iter()
            .map(|height| async move {
                let mut pin = pin;
                rpc.call(
                    &mut pin,
                    "eth_getBlockByNumber",
                    json!([format!("0x{height:x}"), full]),
                )
                .await
            })
            .collect(),
    )
    .await
}

/// Logs of one range, as returned by the node.
#[derive(Default)]
struct RangeLogs {
    logs: Vec<Value>,
    /// Heights the node refused even one block of; they are asked for by block hash.
    unresolved: Vec<i64>,
    /// A range had to be split.
    split: bool,
}
/// Token logs of `from..=to` in ranges of at most `span` blocks, splitting a range the node
/// refuses (result or range limits) until it is accepted.
async fn range_logs(
    rpc: &Rpc,
    pin: Option<usize>,
    (from, to): (i64, i64),
    span: i64,
    address: &Value,
    limit: usize,
) -> anyhow::Result<RangeLogs> {
    let mut out = RangeLogs::default();
    let mut ranges = Vec::new();
    let mut start = from;
    while start <= to {
        let end = (start + span.max(1) - 1).min(to);
        ranges.push((start, end));
        start = end + 1;
    }
    while !ranges.is_empty() {
        let answers = concurrently(
            limit,
            ranges
                .iter()
                .map(|&(a, b)| async move {
                    let mut pin = pin;
                    rpc.call(
                        &mut pin,
                        "eth_getLogs",
                        json!([{"fromBlock":format!("0x{a:x}"),"toBlock":format!("0x{b:x}"),
                            "address":address,"topics":[TRANSFER_TOPIC]}]),
                    )
                    .await
                })
                .collect(),
        )
        .await;
        let mut again = Vec::new();
        for (&(a, b), answer) in ranges.iter().zip(answers) {
            match answer {
                Ok(logs) => out.logs.extend(match logs {
                    Value::Array(logs) => logs,
                    _ => anyhow::bail!("invalid logs"),
                }),
                Err(error) if error.is::<rpc::RangeLimit>() => {
                    out.split = true;
                    if a < b {
                        let mid = a + (b - a) / 2;
                        again.push((a, mid));
                        again.push((mid + 1, b));
                    } else {
                        out.unresolved.push(a);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        ranges = again;
    }
    Ok(out)
}

/// Raw `eth_getLogs` entries of one block, asked for by its hash.
async fn block_logs(
    rpc: &Rpc,
    pin: Option<usize>,
    hash: &str,
    address: &Value,
) -> anyhow::Result<Vec<Value>> {
    let mut pin = pin;
    match rpc
        .call(
            &mut pin,
            "eth_getLogs",
            json!([{"blockHash":hash,"address":address,"topics":[TRANSFER_TOPIC]}]),
        )
        .await?
    {
        Value::Array(logs) => Ok(logs),
        _ => anyhow::bail!("invalid logs"),
    }
}

/// The transfer a log records, if it is a watched token's well-formed `Transfer`.
fn parse_log(
    log: &Value,
    block_hash: &str,
    tokens: &BTreeMap<String, String>,
) -> anyhow::Result<Option<Incoming>> {
    if log["removed"] == true || log["blockHash"] != block_hash {
        return Ok(None);
    }
    // Reviewed RPCs still must not be allowed to bypass our configured
    // contract/event allowlist by ignoring eth_getLogs filter arguments.
    let Some(asset) = tokens.get(&text(log, "address")?) else {
        return Ok(None);
    };
    let topics = log["topics"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid topics"))?;
    if topics.first().and_then(Value::as_str) != Some(TRANSFER_TOPIC) {
        return Ok(None);
    }
    anyhow::ensure!(topics.len() == 3, "invalid ERC20 topics");
    for topic in &topics[1..] {
        let topic = topic
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid address topic"))?;
        anyhow::ensure!(
            topic.len() == 66
                && topic.starts_with("0x")
                && topic[2..].bytes().all(|b| b.is_ascii_hexdigit())
                && topic[2..26].bytes().all(|b| b == b'0'),
            "invalid address topic"
        );
    }
    let topic = |i: usize| {
        topics[i]
            .as_str()
            .map(|t| format!("0x{}", &t[26..]).to_ascii_lowercase())
            .ok_or_else(|| anyhow::anyhow!("invalid topic"))
    };
    let data = log["data"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid ERC20 data"))?;
    anyhow::ensure!(
        data.len() == 66 && data.starts_with("0x"),
        "invalid ERC20 data"
    );
    let amount = quantity(&log["data"])?;
    if amount == BigUint::default() {
        return Ok(None);
    }
    Ok(Some(Incoming {
        address: topic(2)?,
        asset: asset.clone(),
        transaction: text(log, "transactionHash")?,
        index: height(&log["logIndex"])?,
        amount: amount.to_string(),
    }))
}

/// Reverts to the block before the last scanned one when that block is no longer canonical.
/// Fails closed when a confirmed transfer would be affected.
async fn rewind(app: &App, chain: &Chain, next: i64) -> anyhow::Result<()> {
    let confirmed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM transfers
         WHERE chain=? AND block_height>=? AND state='confirmed')",
    )
    .bind(&chain.id)
    .bind(next - 1)
    .fetch_one(&app.db)
    .await?;
    anyhow::ensure!(
        !confirmed,
        "reorg crosses confirmed transfer; operator review required"
    );
    let mut tx = crate::db::write(&app.db).await?;
    sqlx::query(
        "UPDATE transfers SET state='orphaned' WHERE chain=? AND block_height>=? AND state='seen'",
    )
    .bind(&chain.id)
    .bind(next - 1)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM webhook_deliveries WHERE sent_at IS NULL AND event_id IN
         (SELECT e.id FROM transfer_events e JOIN transfers t ON t.id=e.transfer_id
          WHERE t.chain=? AND t.state='orphaned' AND e.event='seen')",
    )
    .bind(&chain.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM chain_blocks WHERE chain=? AND height>=?")
        .bind(&chain.id)
        .bind(next - 1)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE chain_state SET next_height=? WHERE chain=?")
        .bind(next - 1)
        .bind(&chain.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn scan_window(
    app: &App,
    chain: &Chain,
    rpc: &Rpc,
    pin: &mut Option<usize>,
    state: &mut ScanState,
    head: i64,
    max_blocks: usize,
) -> anyhow::Result<Block> {
    let next: i64 = sqlx::query_scalar("SELECT next_height FROM chain_state WHERE chain=?")
        .bind(&chain.id)
        .fetch_one(&app.db)
        .await?;
    let previous: Option<String> =
        sqlx::query_scalar("SELECT hash FROM chain_blocks WHERE chain=? AND height=?")
            .bind(&chain.id)
            .bind(next - 1)
            .fetch_optional(&app.db)
            .await?;
    // The window is chained to the last committed block by `parentHash` below; that block
    // itself is re-verified against the node once per step.
    if let Some(previous) = previous.as_ref() {
        let actual = rpc
            .call(
                pin,
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", next - 1), false]),
            )
            .await?;
        state.last_check = Some(Instant::now());
        // A node that does not know a block at or below the head it reported is behind
        // (e.g. after failover); that is not evidence of a reorg.
        anyhow::ensure!(
            !actual.is_null() || next - 1 > head,
            "RPC endpoint does not have the last scanned block yet"
        );
        if actual.is_null() || text(&actual, "hash")? != *previous {
            rewind(app, chain, next).await?;
            return Ok(Block::Rewound);
        }
    }
    if next > head {
        if !state.healthy_marked {
            sqlx::query("UPDATE chain_state SET healthy=1 WHERE chain=?")
                .bind(&chain.id)
                .execute(&app.db)
                .await?;
            state.healthy_marked = true;
        }
        return Ok(Block::Idle);
    }
    let watched = Watched::new(chain)?;
    // Transactions are only needed to see native transfers.
    let watches_native = !watched.natives.is_empty();
    let count = usize::try_from(head - next + 1)
        .unwrap_or(usize::MAX)
        .min(max_blocks);
    let heights: Vec<i64> = (next..).take(count).collect();
    let last = *heights.last().expect("window is not empty");
    let limit = state.concurrency(chain);
    // Blocks within LIVE_MARGIN of the head are asked for by hash: load-balanced nodes
    // may not index the newest logs on every backend yet.
    let range_to = last.min(head - LIVE_MARGIN);
    let range = (!watched.tokens.is_empty() && range_to > next).then_some((next, range_to));
    let address = watched.address_filter();
    let pressure = rpc.pressure();
    let span = state.log_span();
    let (blocks, ranged) = tokio::join!(
        fetch_blocks(rpc, *pin, &heights, watches_native, limit),
        async {
            match range {
                Some(range) => {
                    Some(range_logs(rpc, *pin, range, span, &address, (limit / 4).max(1)).await)
                }
                None => None,
            }
        }
    );
    state.adapt(rpc.pressure() > pressure, chain);
    let ranged = ranged.transpose()?;
    if let Some(ranged) = &ranged {
        state.adapt_span(ranged.split, span);
    }

    // The longest run of consecutive blocks that chain to each other and to our last block.
    let mut window: Vec<(i64, Value, String, String)> = Vec::new();
    let mut unavailable = None;
    for (height, block) in heights.iter().zip(blocks) {
        let first = window.is_empty();
        let block = match block {
            Ok(block) => block,
            Err(error) if first => return Err(error),
            Err(error) => {
                tracing::debug!(chain=%chain.id, height, %error, "block fetch failed; window cut short");
                break;
            }
        };
        if block.is_null() {
            if !first {
                // The node announced this block before it can serve it: commit what we
                // have and look again on the next poll, on another backend.
                *pin = None;
                unavailable = Some(*height);
                break;
            }
            let since = match state.missing {
                Some((missing, since)) if missing == next => since,
                _ => Instant::now(),
            };
            anyhow::ensure!(
                since.elapsed() < MISSING_BLOCK_GRACE,
                "RPC endpoint does not have block {next} below head {head}"
            );
            state.missing = Some((next, since));
            tracing::debug!(chain=%chain.id, height = next, "block not available yet; retrying");
            // Ask a different backend next time rather than the one that just lagged.
            *pin = None;
            return Ok(Block::Idle);
        }
        let hash = text(&block, "hash")?;
        let parent = text(&block, "parentHash")?;
        let expected = match window.last() {
            Some((_, _, hash, _)) => Some(hash.as_str()),
            None => previous.as_deref(),
        };
        if expected.is_some_and(|h| h != parent) {
            anyhow::ensure!(!first, "inconsistent parent; retry canonical head");
            // The node answered from two different chains while we fetched; keep the
            // blocks that chain and fetch the rest again next step.
            break;
        }
        anyhow::ensure!(block["transactions"].is_array(), "invalid block");
        window.push((*height, block, hash, parent));
    }
    state.missing = unavailable.map(|height| match state.missing {
        Some((missing, since)) if missing == height => (height, since),
        _ => (height, Instant::now()),
    });
    let last = window.last().expect("first block is present").0;
    let cut = window.len();

    // Token logs per block: from the range query where the block's hash matches, otherwise
    // (live blocks, unresolved or mismatching heights) asked for by block hash.
    let mut raw: BTreeMap<i64, Vec<Value>> = BTreeMap::new();
    let mut by_hash: Vec<usize> = Vec::new();
    if !watched.tokens.is_empty() {
        let mut dirty = std::collections::BTreeSet::new();
        let covered = |h: i64| range.is_some_and(|(a, b)| (a..=b).contains(&h));
        if let Some(ranged) = &ranged {
            dirty.extend(ranged.unresolved.iter().copied());
            for log in &ranged.logs {
                if log["removed"] == true {
                    continue;
                }
                let h = height(&log["blockNumber"])?;
                let Some(slot) = h.checked_sub(next).and_then(|i| usize::try_from(i).ok()) else {
                    continue;
                };
                let Some((_, _, hash, _)) = window.get(slot).filter(|_| covered(h)) else {
                    continue;
                };
                if log["blockHash"] == hash.as_str() {
                    raw.entry(h).or_default().push(log.clone());
                } else {
                    dirty.insert(h);
                }
            }
        }
        for (i, (h, ..)) in window.iter().enumerate() {
            if !covered(*h) || dirty.contains(h) {
                raw.remove(h);
                by_hash.push(i);
            }
        }
    }
    let fetched = concurrently(
        limit,
        by_hash
            .iter()
            .map(|&i| {
                let (pin, hash, address) = (*pin, window[i].2.as_str(), &address);
                async move { block_logs(rpc, pin, hash, address).await }
            })
            .collect(),
    )
    .await;
    for (&i, logs) in by_hash.iter().zip(fetched) {
        raw.insert(window[i].0, logs?);
    }

    // Native transfers: top-level transactions to a watched address, confirmed by receipt.
    let mut pending = Vec::new(); // (window index, address, transaction hash, amount)
    if watches_native {
        for (i, (_, block, ..)) in window.iter().enumerate() {
            for transaction in block["transactions"].as_array().into_iter().flatten() {
                if transaction["to"].is_null() {
                    continue;
                }
                let amount = quantity(&transaction["value"])?;
                if amount == BigUint::default() {
                    continue;
                }
                let address = text(transaction, "to")?;
                let known: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM receive_mappings WHERE address=?)",
                )
                .bind(&address)
                .fetch_one(&app.db)
                .await?;
                if known {
                    pending.push((i, address, text(transaction, "hash")?, amount));
                }
            }
        }
    }
    let preferred = *pin;
    let receipts = concurrently(
        limit,
        pending
            .iter()
            .map(|(_, _, hash, _)| async move {
                let mut pin = preferred;
                rpc.call(&mut pin, "eth_getTransactionReceipt", json!([hash]))
                    .await
            })
            .collect(),
    )
    .await;
    let mut observed: Vec<Observed> = window
        .iter()
        .map(|(height, _, hash, parent)| Observed {
            height: *height,
            hash: hash.clone(),
            parent: parent.clone(),
            incoming: Vec::new(),
        })
        .collect();
    for ((i, address, hash, amount), receipt) in pending.into_iter().zip(receipts) {
        let receipt = receipt?;
        if receipt["status"] != "0x1" || receipt["blockHash"] != observed[i].hash.as_str() {
            continue;
        }
        for asset in &watched.natives {
            observed[i].incoming.push(Incoming {
                address: address.clone(),
                asset: asset.clone(),
                transaction: hash.clone(),
                index: -1,
                amount: amount.to_string(),
            });
        }
    }
    for block in &mut observed {
        for log in raw.get(&block.height).into_iter().flatten() {
            if let Some(incoming) = parse_log(log, &block.hash, &watched.tokens)? {
                block.incoming.push(incoming);
            }
        }
    }

    // Verify the window still belongs to the current canonical chain before committing. The
    // blocks are chained by parentHash, so the newest being canonical implies all are.
    let current = rpc
        .call(
            pin,
            "eth_getBlockByNumber",
            json!([format!("0x{last:x}"), false]),
        )
        .await?;
    anyhow::ensure!(
        text(&current, "hash")? == observed[cut - 1].hash,
        "block changed during scan"
    );
    for chunk in observed.chunks(COMMIT_CHUNK) {
        commit(app, chain, chunk).await?;
    }
    state.healthy_marked = true;
    if unavailable.is_some() {
        return Ok(Block::Idle);
    }
    Ok(Block::Scanned { next: last + 1 })
}

/// Records consecutive observed blocks in one database transaction.
async fn commit(app: &App, chain: &Chain, blocks: &[Observed]) -> anyhow::Result<()> {
    let mut tx = crate::db::write(&app.db).await?;
    for block in blocks {
        let next = block.height;
        for item in &block.incoming {
            let rows =
                sqlx::query("SELECT m.id,m.project_id FROM receive_mappings m WHERE m.address=?")
                    .bind(&item.address)
                    .fetch_all(&mut *tx)
                    .await?;
            for r in rows {
                let tid = id("tr_")?;
                sqlx::query(
                    "INSERT INTO transfers
                     (id,project_id,mapping_id,chain,asset,address,transaction_id,
                      event_index,amount,state,block_height,block_hash)
                     VALUES(?,?,?,?,?,?,?,?,?,'seen',?,?)
                     ON CONFLICT(project_id,chain,transaction_id,event_index,asset,address)
                     DO UPDATE SET state='seen',block_height=excluded.block_height,
                                   block_hash=excluded.block_hash
                     WHERE transfers.state='orphaned'",
                )
                .bind(&tid)
                .bind(r.get::<i64, _>("project_id"))
                .bind(r.get::<i64, _>("id"))
                .bind(&chain.id)
                .bind(&item.asset)
                .bind(&item.address)
                .bind(&item.transaction)
                .bind(item.index)
                .bind(&item.amount)
                .bind(next)
                .bind(&block.hash)
                .execute(&mut *tx)
                .await?;
                let stored: String = sqlx::query_scalar(
                    "SELECT id FROM transfers WHERE project_id=? AND chain=?
                     AND transaction_id=? AND event_index=? AND asset=? AND address=?",
                )
                .bind(r.get::<i64, _>("project_id"))
                .bind(&chain.id)
                .bind(&item.transaction)
                .bind(item.index)
                .bind(&item.asset)
                .bind(&item.address)
                .fetch_one(&mut *tx)
                .await?;
                emit(&mut tx, &stored, "seen").await?;
            }
        }
        sqlx::query("INSERT INTO chain_blocks(chain,height,hash,parent_hash) VALUES(?,?,?,?)")
            .bind(&chain.id)
            .bind(next)
            .bind(&block.hash)
            .bind(&block.parent)
            .execute(&mut *tx)
            .await?;
        // Finality is measured against the committed canonical scan height, never the unscanned RPC head.
        let final_height = next - i64::from(chain.confirmations) + 1;
        let confirm=sqlx::query("SELECT id,mapping_id,project_id FROM transfers WHERE chain=? AND state='seen' AND block_height<=?").bind(&chain.id).bind(final_height).fetch_all(&mut *tx).await?;
        for r in confirm {
            sqlx::query("UPDATE transfers SET state='confirmed' WHERE id=?")
                .bind(r.get::<String, _>("id"))
                .execute(&mut *tx)
                .await?;
            let seq: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(confirmed_sequence),0)+1 FROM receive_mappings WHERE project_id=?",
            )
            .bind(r.get::<i64, _>("project_id"))
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query("UPDATE receive_mappings SET confirmed_sequence=? WHERE id=? AND confirmed_sequence IS NULL").bind(seq).bind(r.get::<i64,_>("mapping_id")).execute(&mut *tx).await?;
            emit(&mut tx, r.get("id"), "confirmed").await?;
        }
    }
    let newest = blocks.last().map_or(0, |b| b.height);
    sqlx::query("UPDATE chain_state SET next_height=?,healthy=1 WHERE chain=?")
        .bind(newest + 1)
        .bind(&chain.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
