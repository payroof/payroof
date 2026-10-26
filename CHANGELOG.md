# Changelog

All notable changes to this project are documented in this file. The format is based
on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.2.1] - 2026-10-26

- A block below the reported head that the node cannot return yet (load-balanced providers announce a head before every backend has it) is retried on the next poll, preferably on another endpoint, instead of marking the chain unhealthy and briefly failing `/readyz` with 503. It is reported as an error only if it stays unavailable for 60 s.

## [0.2.0] - 2026-10-26

- Several RPC endpoints per chain: `rpc` accepts a URL or a priority-ordered list. Rate limits (HTTP 429/403/401, JSON-RPC -32005/-32029 and "rate limit"/"exceeded"/"capacity" errors), 5xx and timeouts cool an endpoint down with exponential backoff (honouring `Retry-After`) and the request moves to the next endpoint; recovered endpoints are preferred again. Existing single-URL configs keep working.
- RPC URLs are redacted to scheme and host in logs, errors and `Debug` output, since they usually embed API keys.
- Far fewer RPC requests: per-chain `poll_interval_ms` (defaults near half the block time: Ethereum 6 s, BNB Smart Chain 1.5 s, Polygon and Base 2 s, Arbitrum 1 s, other chains 2 s) instead of polling every 500 ms; an unchanged head costs one `eth_blockNumber`; the chain id is verified once per endpoint; blocks are fetched with full transactions only when a native asset is watched; one `eth_getLogs` per block covers all watched tokens; catch-up observes up to 20 blocks per step.
- A head far below the highest one seen (a lagging node) is ignored instead of triggering reorg handling.
- When every endpoint is cooling down the chain loop waits for the first recovery; failures are logged once per state change instead of on every retry.
- Worker heartbeats are written at most every 20 seconds (immediately on a health change), cutting idle SQLite writes; `/readyz` accepts heartbeats up to 90 seconds old (was 60). The database now uses `PRAGMA synchronous=NORMAL` with WAL.

## [0.1.0] - 2026-10-25

- First public release.
- Watch-only payment addresses derived from public BIP-32 watch roots, one per reference.
- Multichain scanning of configured native coins and ERC-20 tokens on EVM chains, with confirmations and reorg handling.
- HMAC-signed `seen` and `confirmed` webhooks with retries and SSRF protection.
- Per-project scoped access credentials, Wallet pairing and Ed25519 recovery.
- ALTCHA proof of work, rate limits and request bounds.
- Single static binary with SQLite; Docker image, Homebrew tap and prebuilt binaries.
