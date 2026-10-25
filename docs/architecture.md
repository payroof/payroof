# Architecture and security

Payroof holds **public derivation material only**: it can derive and watch a
merchant's addresses, but it never sees a key that can spend from them.

```text
Wallet  -- project + recovery public key + watch root --> Payroof
App     -- pairing request --> Wallet approves explicitly --> one-time access credential
App     -- reference (e.g. an order) --> Payroof --> one derived address on every chain
Payroof -- seen / confirmed (HMAC-signed) --> app webhook
Wallet  <-- new payment addresses and received payments -- Payroof
```

## Design

- **Watch-only**: BIP-32 public watch roots; every reference maps to a deterministic
  address the merchant's Wallet can verify and spend from.
- **Multichain scanning**: exactly the native coins and ERC-20 tokens configured for
  each `eip155` chain, with confirmation depths, reorg handling and durable state.
- **Signed webhooks**: `seen` and `confirmed` events with the transfer, address and
  amount; HMAC-signed, retried, SSRF-safe (HTTPS, public DNS, pinned). See the
  [webhook section](http-api.md#webhooks).
- **Scoped access**: per-project revocable credentials with four permissions
  (`references`, `paths`, `webhooks`, `access`), delegated only through an explicit
  Wallet pairing.
- **Recovery**: an Ed25519 recovery key, derived in the Wallet, restores access.
- **Abuse resistance**: ALTCHA proof of work, rate and concurrency limits, bounded
  bodies and request deadlines.
- **Small footprint**: one static binary and SQLite.

## Security notes

See also [Public errors and security](http-api.md#public-errors-and-security).

- Bearer tokens are opaque, hashed at rest, revocable and Project-scoped.
- Webhook secrets are encrypted at rest with per-webhook authenticated context.
- Production requires HTTPS origin and RPCs. Webhook targets require HTTPS on port 443
  and public DNS addresses; every attempt re-validates DNS and pins the connection.
- Only explicitly configured trusted proxy CIDRs can supply the client IP.

## Source layout

`src/domain` (identifiers, assets, watch roots, access), `src/crypto` (BIP-32,
cursors, recovery, webhook signing), `src/security` (limits, proxies, secrets),
`src/http` (routes), `src/scanner` (chain scanning), `src/delivery` (webhooks, SSRF
guard), `src/workers.rs`, `migrations/` (SQLite schema).
