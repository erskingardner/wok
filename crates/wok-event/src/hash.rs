use secp256k1::{XOnlyPublicKey, SECP256K1};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::EventError;

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

/// NIP-01 event id: SHA-256 of compact JSON `[0,pubkey,created_at,kind,tags,content]`,
/// escaping only what NIP-01 lists (plus `\u00xx` for other control
/// characters) and writing every other character, U+007F included, verbatim.
pub fn event_id_hash(orig: &Value) -> Result<[u8; 32], EventError> {
    Ok(sha256(
        id_preimage(orig, crate::json::write_nip01)?.as_bytes(),
    ))
}

/// The id preimage strfry and earlier Wok releases hashed: tao escaping, which
/// also writes U+007F as `\u007f`. It differs from NIP-01 only for events
/// containing U+007F. Accept it only for events a relay has already stored.
pub fn legacy_event_id_hash(orig: &Value) -> Result<[u8; 32], EventError> {
    Ok(sha256(
        id_preimage(orig, crate::json::write_tao)?.as_bytes(),
    ))
}

fn id_preimage(orig: &Value, write: fn(&Value, &mut String)) -> Result<String, EventError> {
    let mut encoded = String::with_capacity(256);
    encoded.push_str("[0");
    for (key, error) in [
        ("pubkey", "missing pubkey"),
        ("created_at", "missing created_at"),
        ("kind", "missing kind"),
        ("tags", "missing tags"),
        ("content", "missing content"),
    ] {
        encoded.push(',');
        write(
            orig.get(key).ok_or_else(|| EventError::msg(error))?,
            &mut encoded,
        );
    }
    encoded.push(']');
    Ok(encoded)
}

/// Check `packed_id` against the NIP-01 preimage.
pub fn verify_id(orig: &Value, packed_id: &[u8]) -> Result<(), EventError> {
    let preimage = id_preimage(orig, crate::json::write_nip01)?;
    if sha256(preimage.as_bytes()).as_slice() != packed_id {
        return Err(EventError::msg("bad event id"));
    }
    Ok(())
}

/// Check `packed_id` against the NIP-01 preimage, or else the legacy tao
/// preimage, for stored events from strfry or earlier Wok releases. The two
/// preimages differ only where U+007F occurs, so other events hash once.
pub fn verify_id_allowing_legacy(orig: &Value, packed_id: &[u8]) -> Result<(), EventError> {
    let preimage = id_preimage(orig, crate::json::write_nip01)?;
    if sha256(preimage.as_bytes()).as_slice() == packed_id
        || (preimage.contains('\u{7f}') && legacy_event_id_hash(orig)?.as_slice() == packed_id)
    {
        return Ok(());
    }
    Err(EventError::msg("bad event id"))
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
    fn id_preimage_writes_del_verbatim_and_legacy_escapes_it() {
        // NIP-01 lists seven escapes; "all other characters must be included
        // verbatim". serde_json writes U+007F raw, like go-nostr and
        // nostr-tools; tao escaped it.
        let ev = json!({
            "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "created_at": 1,
            "kind": 1,
            "tags": [["t", "a\u{7f}"]],
            "content": "line\nquote\" back\\ tab\t cr\r bs\u{8} ff\u{c} nul\u{0} us\u{1f} del\u{7f} é",
        });
        let fields = json!([0, ev["pubkey"], 1, 1, ev["tags"], ev["content"]]);
        let spec = serde_json::to_string(&fields).unwrap();
        assert!(spec.contains('\u{7f}'));
        assert_eq!(event_id_hash(&ev).unwrap(), sha256(spec.as_bytes()));
        let legacy = spec.replace('\u{7f}', "\\u007f");
        assert_eq!(
            legacy_event_id_hash(&ev).unwrap(),
            sha256(legacy.as_bytes())
        );

        let spec_id = sha256(spec.as_bytes());
        let legacy_id = sha256(legacy.as_bytes());
        assert!(verify_id(&ev, &spec_id).is_ok());
        assert!(verify_id(&ev, &legacy_id).is_err());
        assert!(verify_id_allowing_legacy(&ev, &spec_id).is_ok());
        assert!(verify_id_allowing_legacy(&ev, &legacy_id).is_ok());
        assert!(verify_id_allowing_legacy(&ev, &[0u8; 32]).is_err());
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
