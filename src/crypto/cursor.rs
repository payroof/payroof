use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
pub fn encode(key: &[u8], project: i64, scope: &str, seq: i64) -> String {
    let data = format!("v1:{project}:{scope}:{seq}");
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
    m.update(data.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(data),
        URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
    )
}
pub fn decode(key: &[u8], project: i64, scope: &str, cursor: &str) -> anyhow::Result<i64> {
    anyhow::ensure!(cursor.len() <= 256, "invalid cursor");
    let (d, t) = cursor
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid cursor"))?;
    let d = URL_SAFE_NO_PAD.decode(d)?;
    let t = URL_SAFE_NO_PAD.decode(t)?;
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("fixed key");
    m.update(&d);
    m.verify_slice(&t)
        .map_err(|_| anyhow::anyhow!("invalid cursor"))?;
    let d = String::from_utf8(d)?;
    let prefix = format!("v1:{project}:{scope}:");
    let seq: i64 = d
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("wrong cursor stream"))?
        .parse()?;
    anyhow::ensure!(seq >= 0, "invalid cursor");
    Ok(seq)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bound() {
        let c = encode(&[1; 32], 7, "all", 20);
        assert_eq!(decode(&[1; 32], 7, "all", &c).unwrap(), 20);
        assert!(decode(&[1; 32], 8, "all", &c).is_err());
        assert!(decode(&[1; 32], 7, "confirmed", &c).is_err());
    }
}
