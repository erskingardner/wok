use secp256k1::{XOnlyPublicKey, SECP256K1};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::EventError;

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

/// NIP-01 event id: SHA-256 of compact JSON `[0, pubkey, created_at, kind, tags, content]`.
pub fn event_id_hash(orig: &Value) -> Result<[u8; 32], EventError> {
    let arr = Value::Array(vec![
        Value::from(0u64),
        orig.get("pubkey")
            .cloned()
            .ok_or_else(|| EventError::msg("missing pubkey"))?,
        orig.get("created_at")
            .cloned()
            .ok_or_else(|| EventError::msg("missing created_at"))?,
        orig.get("kind")
            .cloned()
            .ok_or_else(|| EventError::msg("missing kind"))?,
        orig.get("tags")
            .cloned()
            .ok_or_else(|| EventError::msg("missing tags"))?,
        orig.get("content")
            .cloned()
            .ok_or_else(|| EventError::msg("missing content"))?,
    ]);
    let encoded = serde_json::to_string(&arr).map_err(|e| EventError::msg(e.to_string()))?;
    Ok(sha256(encoded.as_bytes()))
}

pub fn verify_id(orig: &Value, packed_id: &[u8]) -> Result<(), EventError> {
    let hash = event_id_hash(orig)?;
    if hash.as_slice() != packed_id {
        return Err(EventError::msg("bad event id"));
    }
    Ok(())
}

pub fn verify_sig(sig: &[u8], hash: &[u8], pubkey: &[u8]) -> Result<bool, EventError> {
    if sig.len() != 64 || hash.len() != 32 || pubkey.len() != 32 {
        return Err(EventError::msg("verify sig: bad input size"));
    }
    let pk = XOnlyPublicKey::from_slice(pubkey)
        .map_err(|_| EventError::msg("verify sig: bad pubkey"))?;
    let signature = secp256k1::schnorr::Signature::from_slice(sig)
        .map_err(|_| EventError::msg("verify sig: bad signature"))?;
    Ok(SECP256K1.verify_schnorr(&signature, hash, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;

    #[test]
    fn hash_matches_known_vector() {
        // NIP-01 style serialization: no extra whitespace, UTF-8, no unicode escaping.
        let ev = json!({
            "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "created_at": 0,
            "kind": 1,
            "tags": [],
            "content": "hello"
        });
        let h = event_id_hash(&ev).unwrap();
        let encoded = serde_json::to_string(&json!([
            0,
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            0,
            1,
            [],
            "hello"
        ]))
        .unwrap();
        assert_eq!(h, sha256(encoded.as_bytes()));
    }

    #[test]
    fn schnorr_roundtrip() {
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);
        let (xonly, _) = kp.x_only_public_key();
        let sig = SECP256K1.sign_schnorr(&sha256(b"test-msg"), &kp);
        assert!(verify_sig(sig.as_ref(), &sha256(b"test-msg"), &xonly.serialize()).unwrap());
        assert!(!verify_sig(sig.as_ref(), &sha256(b"other"), &xonly.serialize()).unwrap());
    }
}
