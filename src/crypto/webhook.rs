use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub fn decode_webhook_secret(s: &str) -> anyhow::Result<[u8; 32]> {
    let raw = s
        .strip_prefix("whsec_")
        .ok_or_else(|| anyhow::anyhow!("bad webhook secret"))?;
    let b = URL_SAFE_NO_PAD.decode(raw)?;
    anyhow::ensure!(b.len() == 32, "bad webhook secret length");
    Ok(b.try_into().unwrap())
}

pub fn sign_webhook(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("v1={}", hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_webhook(
    secret: &[u8],
    timestamp: i64,
    body: &[u8],
    signature: &str,
    now: i64,
) -> anyhow::Result<()> {
    anyhow::ensure!(now.abs_diff(timestamp) <= 300, "stale webhook");
    let tag = hex::decode(
        signature
            .strip_prefix("v1=")
            .ok_or_else(|| anyhow::anyhow!("invalid signature"))?,
    )?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| anyhow::anyhow!("invalid key"))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&tag)
        .map_err(|_| anyhow::anyhow!("invalid signature"))
}
