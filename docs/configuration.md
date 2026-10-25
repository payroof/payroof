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
| `[[chains]]` | `id` (`eip155:<n>`), `name` (display, 1-40 chars), `rpc`, `confirmations`, optional `start_height` (default: the head at first run) |
| `[[chains.assets]]` | `id` (`eip155:<n>/slip44:<coin>` or `eip155:<n>/erc20:<contract>`), `kind`, `symbol`, `decimals` |
| `[limits]` | Rate, body, concurrency and capacity limits; omitted keys keep the defaults below |

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
