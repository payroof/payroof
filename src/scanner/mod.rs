//! Sequential canonical block observation. Native transfers are top-level EVM
//! transactions; value moved by internal calls is not observed.
pub mod rpc;
use crate::{App, config::Chain, security::secret::id, time::now};
use num_bigint::BigUint;
use rpc::Rpc;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
/// Most blocks one scan step observes before yielding to the poll loop.
pub const MAX_BLOCKS_PER_STEP: usize = 20;
/// A head this many blocks below the highest one seen comes from a lagging node (a real
/// reorg is far shallower) and is not used.
const HEAD_REGRESSION_TOLERANCE: i64 = 32;
/// While the head is unchanged, the last scanned block is re-verified at this interval.
const IDLE_RECHECK: Duration = Duration::from_secs(30);

/// What a scanner remembers between steps (in memory only; nothing here is authoritative).
#[derive(Default)]
pub struct ScanState {
    last_head: Option<i64>,
    last_check: Option<Instant>,
    /// `chain_state.healthy` is known to be 1, so idle polls need not write it again.
    pub healthy_marked: bool,
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
    let mut behind = false;
    for i in 0..max_blocks.max(1) {
        match scan_block(app, chain, rpc, &mut pin, state, head, i == 0).await? {
            Block::Idle => {
                behind = false;
                break;
            }
            Block::Rewound => {
                behind = true;
                break;
            }
            Block::Scanned { next } => behind = next <= head,
        }
        if !behind {
            break;
        }
    }
    Ok(Outcome { behind })
}
async fn scan_block(
    app: &App,
    chain: &Chain,
    rpc: &Rpc,
    pin: &mut Option<usize>,
    state: &mut ScanState,
    head: i64,
    check_previous: bool,
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
    // Later blocks of a batch are chained to the previous one by `parentHash` below.
    if let Some(previous) = previous.as_ref().filter(|_| check_previous) {
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
            sqlx::query("UPDATE transfers SET state='orphaned' WHERE chain=? AND block_height>=? AND state='seen'").bind(&chain.id).bind(next-1).execute(&mut *tx).await?;
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
    // Transactions are only needed to see native transfers.
    let watches_native = chain.assets.iter().any(|a| a.kind == "native");
    let block = rpc
        .call(
            pin,
            "eth_getBlockByNumber",
            json!([format!("0x{next:x}"), watches_native]),
        )
        .await?;
    anyhow::ensure!(!block.is_null(), "RPC endpoint does not have the block yet");
    let block_hash = text(&block, "hash")?;
    let parent = text(&block, "parentHash")?;
    anyhow::ensure!(
        previous.is_none_or(|h| h == parent),
        "inconsistent parent; retry canonical head"
    );
    // Watched assets: exactly the ones configured for this chain, nothing else.
    let mut natives = Vec::new();
    let mut tokens: BTreeMap<String, String> = BTreeMap::new(); // contract -> asset id
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
    let mut incoming = Vec::new();
    for transaction in block["transactions"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid block"))?
    {
        if transaction["to"].is_null() {
            continue;
        }
        let amount = quantity(&transaction["value"])?;
        if amount == BigUint::default() {
            continue;
        }
        let address = text(transaction, "to")?;
        let known: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM receive_mappings WHERE address=?)")
                .bind(&address)
                .fetch_one(&app.db)
                .await?;
        if !known {
            continue;
        }
        let hash = text(transaction, "hash")?;
        let receipt = rpc
            .call(pin, "eth_getTransactionReceipt", json!([hash]))
            .await?;
        if receipt["status"] != "0x1" || receipt["blockHash"] != block_hash {
            continue;
        }
        for asset in &natives {
            incoming.push(Incoming {
                address: address.clone(),
                asset: asset.clone(),
                transaction: hash.clone(),
                index: -1,
                amount: amount.to_string(),
            });
        }
    }
    if !tokens.is_empty() {
        // One request per block for every watched token, pinned to this block's hash.
        let address = match tokens.keys().collect::<Vec<_>>().as_slice() {
            [one] => json!(one),
            many => json!(many),
        };
        let logs = rpc
            .call(
                pin,
                "eth_getLogs",
                json!([{"blockHash":block_hash,"address":address,"topics":[TRANSFER_TOPIC]}]),
            )
            .await?;
        for log in logs
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid logs"))?
        {
            if log["removed"] == true || log["blockHash"] != block_hash {
                continue;
            }
            // Reviewed RPCs still must not be allowed to bypass our configured
            // contract/event allowlist by ignoring eth_getLogs filter arguments.
            let Some(asset) = tokens.get(&text(log, "address")?) else {
                continue;
            };
            let topics = log["topics"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid topics"))?;
            if topics.first().and_then(Value::as_str) != Some(TRANSFER_TOPIC) {
                continue;
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
                continue;
            }
            let index = height(&log["logIndex"])?;
            incoming.push(Incoming {
                address: topic(2)?,
                asset: asset.clone(),
                transaction: text(log, "transactionHash")?,
                index,
                amount: amount.to_string(),
            });
        }
    }
    // Verify the observed block still belongs to the current canonical chain before committing.
    let current = rpc
        .call(
            pin,
            "eth_getBlockByNumber",
            json!([format!("0x{next:x}"), false]),
        )
        .await?;
    anyhow::ensure!(
        text(&current, "hash")? == block_hash,
        "block changed during scan"
    );
    let mut tx = crate::db::write(&app.db).await?;
    for item in incoming {
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
            .bind(&block_hash)
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
        .bind(&block_hash)
        .bind(parent)
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
    sqlx::query("UPDATE chain_state SET next_height=?,healthy=1 WHERE chain=?")
        .bind(next + 1)
        .bind(&chain.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.healthy_marked = true;
    Ok(Block::Scanned { next: next + 1 })
}
