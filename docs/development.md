# Development

Requires the Rust toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml).

```sh
export PAYROOF_ALTCHA_KEY=$(openssl rand -hex 32) \
       PAYROOF_CURSOR_KEY=$(openssl rand -hex 32) \
       PAYROOF_MASTER_KEY=$(openssl rand -hex 32)
RUST_LOG=info cargo run --locked --release -- config/payroof.local.toml
```

The local config targets an Anvil chain at `http://127.0.0.1:8545` in development mode.

## Checks

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
docker build -t payroof:dev .
```

Tests cover the protocol, tenant isolation, replay, concurrent allocation, access
revocation, limits, readiness, configured assets and reorgs.
