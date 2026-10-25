# Changelog

All notable changes to this project are documented in this file. The format is based
on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.0] - 2026-10-25

- First public release.
- Watch-only payment addresses derived from public BIP-32 watch roots, one per reference.
- Multichain scanning of configured native coins and ERC-20 tokens on EVM chains, with confirmations and reorg handling.
- HMAC-signed `seen` and `confirmed` webhooks with retries and SSRF protection.
- Per-project scoped access credentials, Wallet pairing and Ed25519 recovery.
- ALTCHA proof of work, rate limits and request bounds.
- Single static binary with SQLite; Docker image, Homebrew tap and prebuilt binaries.
