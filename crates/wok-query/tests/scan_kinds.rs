use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::{foreach_by_filter, NostrFilterGroup};

fn sign(kind: u64, content: &str, created: u64) -> (Vec<u8>, String, String) {
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "created_at": created,
        "kind": kind,
        "tags": [],
        "content": content,
        "pubkey": hex::encode(xonly.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, &kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    (parsed.packed.into_bytes(), parsed.json, hex::encode(id))
}

#[test]
fn scan_kinds_and_limit() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut evs = Vec::new();
    let mut ids = Vec::new();
    for i in 0..10 {
        let (p, j, id) = sign(1, &format!("n{i}"), 1_700_000_000 + i);
        ids.push(id);
        evs.push(EventToWrite::new(p, j));
    }
    let (p, j, _) = sign(0, "meta", 1_700_000_050);
    evs.push(EventToWrite::new(p, j));
    {
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    let mut got = Vec::new();
    foreach_by_filter(&txn, &json!({"kinds":[1], "limit": 5}), 500, 3, |lev| {
        got.push(lev);
    })
    .unwrap();
    assert_eq!(got.len(), 5);
    let fg = NostrFilterGroup::from_value(&json!({"kinds":[0]}), 500, 3).unwrap();
    assert_eq!(fg.size(), 1);
}
