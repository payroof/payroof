use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchKey {
    pub algorithm: String,
    pub public_key: String,
    pub chain_code: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchRoot {
    pub family: String,
    pub path: String,
    pub key: WatchKey,
}
impl WatchRoot {
    pub fn identity(&self) -> anyhow::Result<String> {
        let (pk, cc) = crate::crypto::bip32::decode_watch_key(&self.key)?;
        let mut h = Sha256::new();
        h.update(b"payroof-watch-material-v1\0");
        h.update(self.family.as_bytes());
        h.update([0]);
        h.update(pk);
        h.update(cc);
        Ok(hex::encode(h.finalize()))
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.family == "eip155" && self.key.algorithm == "bip32-secp256k1",
            "unsupported watch root"
        );
        let slot = self
            .path
            .strip_prefix("m/44'/60'/")
            .and_then(|s| s.strip_suffix("'/1"))
            .ok_or_else(|| anyhow::anyhow!("invalid root"))?;
        let n: u32 = slot.parse()?;
        anyhow::ensure!(n < 1 << 31 && n.to_string() == slot, "invalid slot");
        crate::crypto::bip32::decode_watch_key(&self.key)?;
        Ok(())
    }
    /// Canonical fingerprint: SHA256("payroof-watch-v1\0" || family || 0 || path || 0 || SEC1 || chain code).
    pub fn fingerprint(&self) -> anyhow::Result<String> {
        let (pk, cc) = crate::crypto::bip32::decode_watch_key(&self.key)?;
        let mut h = Sha256::new();
        h.update(b"payroof-watch-v1\0");
        h.update(self.family.as_bytes());
        h.update([0]);
        h.update(self.path.as_bytes());
        h.update([0]);
        h.update(pk);
        h.update(cc);
        Ok(format!("sha256:{}", hex::encode(h.finalize())))
    }
}
