use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use k256::{
    FieldBytes, ProjectivePoint, PublicKey, Scalar,
    elliptic_curve::{ff::PrimeField, group::Group, sec1::ToSec1Point},
};
use sha2::Sha512;
use sha3::{Digest, Keccak256};

use crate::domain::watch_root::WatchKey;

#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("invalid watch key")]
    InvalidWatchKey,
    #[error("hardened child index")]
    Hardened,
    #[error("invalid bip32 child")]
    InvalidChild,
}

pub fn decode_watch_key(w: &WatchKey) -> Result<([u8; 33], [u8; 32]), DeriveError> {
    let pk = URL_SAFE_NO_PAD
        .decode(&w.public_key)
        .map_err(|_| DeriveError::InvalidWatchKey)?;
    let cc = URL_SAFE_NO_PAD
        .decode(&w.chain_code)
        .map_err(|_| DeriveError::InvalidWatchKey)?;
    if pk.len() != 33 || cc.len() != 32 {
        return Err(DeriveError::InvalidWatchKey);
    }
    PublicKey::from_sec1_bytes(&pk).map_err(|_| DeriveError::InvalidWatchKey)?;
    Ok((pk.try_into().unwrap(), cc.try_into().unwrap()))
}

fn derive_public_child(watch: &WatchKey, index: u32) -> Result<PublicKey, DeriveError> {
    if index >= (1 << 31) {
        return Err(DeriveError::Hardened);
    }
    let (pk_bytes, chain_code) = decode_watch_key(watch)?;
    let parent = PublicKey::from_sec1_bytes(&pk_bytes).map_err(|_| DeriveError::InvalidWatchKey)?;
    let mut mac = Hmac::<Sha512>::new_from_slice(&chain_code).expect("HMAC key size");
    mac.update(&pk_bytes);
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();
    let il: [u8; 32] = i[..32].try_into().unwrap();
    let scalar = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(il)))
        .ok_or(DeriveError::InvalidChild)?;
    if bool::from(scalar.is_zero()) {
        return Err(DeriveError::InvalidChild);
    }
    let point = ProjectivePoint::GENERATOR * scalar + ProjectivePoint::from(*parent.as_affine());
    if bool::from(point.is_identity()) {
        return Err(DeriveError::InvalidChild);
    }
    PublicKey::from_affine(point.to_affine()).map_err(|_| DeriveError::InvalidChild)
}

fn evm_address(pubkey: &PublicKey) -> String {
    let p = pubkey.to_sec1_point(false);
    let hash = Keccak256::digest(&p.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn derive_evm_address(watch: &WatchKey, index: u32) -> Result<String, DeriveError> {
    Ok(evm_address(&derive_public_child(watch, index)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_hardened() {
        let w = WatchKey {
            algorithm: "bip32-secp256k1".into(),
            public_key: "x".into(),
            chain_code: "y".into(),
        };
        assert!(matches!(
            derive_public_child(&w, 1 << 31),
            Err(DeriveError::Hardened)
        ));
    }
}
