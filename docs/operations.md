# Operations

## Docker

```sh
cp config/payroof.example.toml payroof.toml   # then set origin; review RPCs and assets
export PAYROOF_ALTCHA_KEY=$(openssl rand -hex 32) \
       PAYROOF_CURSOR_KEY=$(openssl rand -hex 32) \
       PAYROOF_MASTER_KEY=$(openssl rand -hex 32)
docker compose up -d        # pulls ghcr.io/payroof/payroof:<version>, or add --build
curl -fsS http://127.0.0.1:8080/readyz
```

[`compose.yaml`](../compose.yaml) runs the image read-only, without capabilities or
privilege escalation, as UID 10001, with the database on a named volume. The image is
a `scratch` image holding only the static binary and CA certificates. The config is
mounted at `/etc/payroof/payroof.toml`.

## Health and shutdown

- `GET /healthz` reports liveness; `GET /readyz` reports readiness, which requires
  the database, every chain scanner and the delivery worker to be current: healthy
  with a heartbeat younger than 90 seconds. Workers write heartbeats about every 20
  seconds (immediately when health changes), not on every poll.
- The binary's `healthcheck [URL]` command probes readiness; the image uses it.
- `SIGTERM` turns readiness off, drains HTTP requests, then stops the workers.
- The schema is applied at startup from [`migrations/`](../migrations).

## RPC providers and rate limits

Public RPCs rate limit shared clients. List several endpoints per chain (see
[RPC endpoints](configuration.md#rpc-endpoints)), preferably your own provider first.
Log lines to expect: `RPC endpoint cooling down` (warning, once per outage, with the
host only), `RPC endpoint recovered`, and one `scanner unavailable` error per state or
error change while a chain is unready. Persistent `all RPC endpoints unavailable` means
every listed endpoint is limiting or down: add endpoints, raise `poll_interval_ms`, or
use a paid plan. The SQLite database runs in WAL mode with `synchronous=NORMAL`; after a
power loss the newest commits may be lost, in which case the scanner re-observes those
blocks (webhooks are at-least-once).

## Backups

Back up the SQLite database together with the three keys (see
[configuration](configuration.md#environment)).

## Releases

Versions follow [SemVer](https://semver.org); changes are listed in
[CHANGELOG.md](../CHANGELOG.md). Pushing a tag `vX.Y.Z` that matches `Cargo.toml` runs
the release workflow: checks, crates.io [`payroof`](https://crates.io/crates/payroof),
`ghcr.io/payroof/payroof:X.Y.Z`, then a GitHub release with the changelog section.
Nothing is deployed automatically.
