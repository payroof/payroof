use super::error::{Error, Result};
use crate::{App, security::secret::hash, time::now};
use altcha::{CreateChallengeOptions, Payload, VerifySolutionOptions};
use serde_json::json;
use std::collections::BTreeMap;
/// PBKDF2-SHA-256 iterations per attempt. A server verifies with one derivation.
const COST: u32 = 5000;
/// The secret counter a client must reach, trying each one from zero: 1,500 to 2,100
/// attempts, about 1.1 to 1.5 s on a current Mac (in a browser or a native solver) and
/// longer on slower devices. A proof is never found early by luck, so each one costs at
/// least that much work.
const COUNTER: std::ops::RangeInclusive<u32> = 1500..=2100;
/// Bytes of the derived key the client must match: a wrong counter matches by
/// chance once in 2^32 attempts.
const PREFIX_BYTES: usize = 4;
pub fn challenge(secret: &str, purpose: &str) -> anyhow::Result<altcha::Challenge> {
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    let span = COUNTER.end() - COUNTER.start() + 1;
    Ok(altcha::create_challenge(CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".into(),
        cost: COST,
        counter: Some(COUNTER.start() + u32::from_le_bytes(random) % span),
        key_prefix_length: Some(PREFIX_BYTES),
        hmac_signature_secret: Some(secret.into()),
        expires_at: Some(now() + 120),
        data: Some(BTreeMap::from([("purpose".into(), json!(purpose))])),
        ..Default::default()
    })?)
}
pub async fn consume(app: &App, payload: &Payload, purpose: &str) -> Result<()> {
    let p = &payload.challenge.parameters;
    // Bound expensive verification before evaluating attacker supplied KDF inputs.
    if p.algorithm != "PBKDF2/SHA-256"
        || p.cost != COST
        || p.key_length != 32
        || p.key_prefix.len() != PREFIX_BYTES * 2
        || p.memory_cost.is_some()
        || p.parallelism.is_some()
        || p.expires_at.is_none_or(|e| e <= now() || e > now() + 150)
        || p.data
            .as_ref()
            .and_then(|d| d.get("purpose"))
            .and_then(|v| v.as_str())
            != Some(purpose)
    {
        return Err(Error::bad("invalid_altcha"));
    }
    let verified = altcha::verify_solution(VerifySolutionOptions::new(
        &payload.challenge,
        &payload.solution,
        &*app.altcha_key,
    ))
    .map_err(|_| Error::bad("invalid_altcha"))?;
    if !verified.verified {
        return Err(Error::bad("invalid_altcha"));
    }
    let signature = payload
        .challenge
        .signature
        .as_deref()
        .ok_or_else(|| Error::bad("invalid_altcha"))?;
    let n = sqlx::query(
        "INSERT INTO altcha_replay(fingerprint,purpose,expires_at)
         VALUES(?,?,?) ON CONFLICT DO NOTHING",
    )
    .bind(hash(signature))
    .bind(purpose)
    .bind(p.expires_at.unwrap_or(0))
    .execute(&app.db)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(Error::conflict("altcha_replayed"));
    }
    Ok(())
}
