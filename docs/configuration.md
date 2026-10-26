# Configuration

Payroof reads one TOML file, passed as the only argument.
[`config/payroof.example.toml`](../config/payroof.example.toml) is a deployment that watches the
same networks, coins and tokens Payroof Wallet starts with (Ethereum, Base, Polygon,
Arbitrum, BNB Smart Chain: native coins, USDC, USDT, WETH). **Payroof watches exactly
the assets listed**; nothing can be added at runtime.
[`config/payroof.local.toml`](../config/payroof.local.toml) targets a local Anvil chain
(`http://127.0.0.1:8545`) in development mode.

## File keys

| Key | Purpose |
|---|---|
| `bind`, `origin` | Listen address and the public origin clients use |
| `origin_aliases` | Other origins this server is reached at; recovery signatures may name them |
| `database` | SQLite URL; its directory must be writable |
| `development` | Allows HTTP origins/RPCs and private webhook targets. **Never in production** |
| `trusted_proxies` | CIDRs whose forwarding headers set the client IP |
| `[[chains]]` | `id` (`eip155:<n>`), `name` (display, 1-40 chars), `rpc` (a URL or a list of URLs, see [RPC endpoints](#rpc-endpoints)), `confirmations`, optional `poll_interval_ms`, optional `max_concurrency`, optional `start_height` (default: the head at first run) |
| `[[chains.assets]]` | `id` (`eip155:<n>/slip44:<coin>` or `eip155:<n>/erc20:<contract>`), `kind`, `symbol`, `decimals` |
| `[limits]` | Rate, body, concurrency and capacity limits; omitted keys keep the defaults below |

## RPC endpoints

`rpc` is a single URL (as before) or a list in priority order, at most 8, all HTTPS
outside development:

```toml
[[chains]]
id = "eip155:1"
name = "Ethereum"
rpc = ["https://eth-provider.example/v2/YOUR_KEY", "https://ethereum.publicnode.com", "https://eth.drpc.org"]
poll_interval_ms = 6000   # optional
max_concurrency = 8       # optional
confirmations = 12
```

- Payroof uses the first healthy endpoint. A rate limit (HTTP 429, 403, 401, JSON-RPC
  `-32005`/`-32029` or an error mentioning "rate limit", "exceeded" or "capacity"), a 5xx
  response, a timeout or an invalid response puts that endpoint into a cooldown (5 s,
  doubling per consecutive failure up to 2 minutes, or longer if the server sends
  `Retry-After`) and the request is retried on the next endpoint. After the cooldown the
  earlier endpoint is preferred again. An endpoint that serves another chain id is rejected.
- Requests of one scan step stay on one endpoint unless it fails. A head more than 32
  blocks below the highest one seen is treated as a lagging node and ignored.
- When all endpoints are cooling down the chain waits for the first one to recover and
  `/readyz` reports not ready; the log shows one line per state change.
- Put a provider URL with an API key first and public endpoints after it. URLs are
  secrets: logs and errors show only `scheme://host`. Keep keys out of version control.
- `poll_interval_ms` (100-300000) is the pause between checks for a new block. Default by
  chain id: Ethereum (`eip155:1`) 6000, BNB Smart Chain (`eip155:56`) 1500, Arbitrum One
  (`eip155:42161`) 1000, anything else (including Base and Polygon) 2000. While the head is
  unchanged a poll is a single `eth_blockNumber`. A block near the head costs about four requests
  (parent check, block, one `eth_getLogs` for all tokens, canonical re-check) plus one
  receipt per transaction paying a watched address.
- `max_concurrency` (1-32, default 8) is the most requests in flight at once while catching
  up. A step then observes up to 100 blocks: they are fetched concurrently, token logs of
  the older blocks come from one `eth_getLogs` per block range, and the result is checked
  and committed in order. The scanner halves the concurrency itself while endpoints answer
  with rate limits or errors and raises it again afterwards, so the value is a ceiling.
  Lower it for a provider with a tight per-second quota; raise it (and list several
  endpoints) for a fast node. Expect roughly `max_concurrency / latency` blocks per second
  (about 30-50 per second on remote endpoints at the default).

## Limits

Defaults (all validated at startup; a zero, negative or excessive value is rejected):

| Key | Default | Meaning |
|---|---|---|
| `project_per_minute`, `pairing_per_minute`, `recovery_per_minute`, `challenge_per_minute` | 3, 5, 5, 10 | Per client IP: project creation, pairing creation, recovery routes, ALTCHA challenges |
| `public_per_day` | 30 | Per client IP: project and pairing creations per day |
| `reads_per_minute`, `mutations_per_minute`, `allocations_per_minute`, `paths_per_minute` | 300, 30, 120, 30 | Per credential (or client IP without one): GET requests, POST/DELETE requests, PUT requests (reference allocation, pairing approval), path listings |
| `general_body`, `pairing_body`, `project_body` | 16384, 2048, 32768 | Maximum request body in bytes |
| `concurrency`, `project_concurrency`, `pairing_concurrency`, `allocation_concurrency` | 64, 8, 8, 32 | In-flight requests overall and for project creation, pairing creation and reference allocation |
| `pairing_capacity` | 10000 | Live pairing requests |
| `path_page` | 1000 | Maximum `limit` for the paths listing (1-1000) |
| `rate_limit_entries` | 100000 | Rate-limit counters kept at once |

## Environment

| Variable | Purpose |
|---|---|
| `PAYROOF_MASTER_KEY` | Encrypts webhook secrets at rest |
| `PAYROOF_CURSOR_KEY` | Authenticates pagination cursors |
| `PAYROOF_ALTCHA_KEY` | Signs proof-of-work challenges |
| `RUST_LOG` | Log filter, e.g. `info` (JSON logs on stdout) |

Each key is 32 random bytes in hex (`openssl rand -hex 32`). Keep them, and the
database, backed up together: losing a key makes encrypted webhook secrets
unrecoverable.
