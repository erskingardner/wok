use serde_json::json;
use tempfile::TempDir;
use wok_db::{check_integrity, write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};

fn sign(kind: u64, content: &str, created: u64, tags: serde_json::Value) -> (Vec<u8>, String) {
    use secp256k1::{Keypair, SECP256K1};
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "created_at": created,
        "kind": kind,
        "tags": tags,
        "content": content,
        "pubkey": hex::encode(xonly.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, &kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    (parsed.packed.into_bytes(), parsed.json)
}

#[test]
fn write_delete_replace_no_index_drift() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut evs = Vec::new();
    for i in 0..20 {
        let (p, j) = sign(1, &format!("n{i}"), 1_700_000_000 + i, json!([]));
        evs.push(EventToWrite::new(p, j));
    }
    let (p, j) = sign(0, "profile-1", 1_700_000_050, json!([]));
    evs.push(EventToWrite::new(p, j));
    {
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
        txn.commit().unwrap();
    }
    {
        let txn = env.begin_ro().unwrap();
        let report = check_integrity(&txn).unwrap();
        assert!(report.ok(), "{report:?}");
        assert_eq!(report.events, 21);
    }
    let mut levs = Vec::new();
    {
        let txn = env.begin_ro().unwrap();
        wok_db::foreach_created_at(&txn, 0, 0, false, |_, lev| {
            if levs.len() < 5 {
                levs.push(lev);
            }
            true
        })
        .unwrap();
    }
    {
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut NoopNegentropy, levs).unwrap();
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(report.ok(), "index drift after delete: {report:?}");
}

#[test]
fn integrity_detects_semantic_index_drift_even_when_counts_match() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let (packed, json) = sign(1, "indexed", 1_700_000_100, json!([["t", "rust"]]));
    let view = PackedEventView::new(&packed).unwrap();
    let expected_key = wok_db::comparators::make_key_string_u64(view.id(), view.created_at());
    let mut wrong_id = [0u8; 32];
    wrong_id[0] = 1;
    let wrong_key = wok_db::comparators::make_key_string_u64(&wrong_id, view.created_at());
    let mut events = vec![EventToWrite::new(packed, json)];
    {
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
    }
    let lev = events[0].lev_id.to_ne_bytes();
    {
        let mut txn = env.begin_rw().unwrap();
        assert!(txn
            .del(env.dbis().event_id, &expected_key, Some(&lev))
            .unwrap());
        assert!(txn.put(env.dbis().event_id, &wrong_key, &lev, 0).unwrap());
        txn.commit().unwrap();
    }

    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(!report.ok());
    assert_eq!(report.events, 1);
    assert_eq!(report.missing_index_entries, 1, "{report:#?}");
    assert_eq!(report.extra_index_entries, 1, "{report:#?}");
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "missing-index" && issue.table == "event_id"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "unexpected-index" && issue.table == "event_id"));
}

#[test]
fn integrity_handles_malformed_custom_index_keys_without_panicking() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    {
        let mut txn = env.begin_rw().unwrap();
        txn.put(env.dbis().event_id, b"bad", &999u64.to_ne_bytes(), 0)
            .unwrap();
        txn.commit().unwrap();
    }

    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(!report.ok());
    assert_eq!(report.extra_index_entries, 1, "{report:#?}");
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "dangling-index"));
}
