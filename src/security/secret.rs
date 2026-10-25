use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
pub fn random<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::fill(&mut b).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    Ok(b)
}
pub fn id(prefix: &str) -> anyhow::Result<String> {
    Ok(format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(random::<32>()?)
    ))
}
pub fn hash(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}
/// A 32-byte key from a hex environment variable.
pub fn env_key(name: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let invalid = || anyhow::anyhow!("{name} must be 64 hex characters");
    let s = Zeroizing::new(std::env::var(name).map_err(|_| invalid())?);
    let b = Zeroizing::new(hex::decode(s.as_bytes()).map_err(|_| invalid())?);
    Ok(Zeroizing::new(
        b.as_slice().try_into().map_err(|_| invalid())?,
    ))
}
pub fn seal(key: &[u8; 32], aad: &[u8], data: &[u8]) -> anyhow::Result<String> {
    let n = random::<24>()?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    let nonce = XNonce::try_from(n.as_slice()).map_err(|_| anyhow::anyhow!("invalid nonce"))?;
    let c = cipher
        .encrypt(&nonce, Payload { msg: data, aad })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut b = n.to_vec();
    b.extend(c);
    Ok(URL_SAFE_NO_PAD.encode(b))
}
pub fn open(key: &[u8; 32], aad: &[u8], envelope: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let b = URL_SAFE_NO_PAD.decode(envelope)?;
    anyhow::ensure!(
        b.len() >= 40 && b.len() <= 4 * 1024 * 1024,
        "invalid envelope"
    );
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    let nonce = XNonce::try_from(&b[..24]).map_err(|_| anyhow::anyhow!("invalid nonce"))?;
    Ok(Zeroizing::new(
        cipher
            .decrypt(&nonce, Payload { msg: &b[24..], aad })
            .map_err(|_| anyhow::anyhow!("authentication failed"))?,
    ))
}
