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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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

#[test]
fn integrity_detects_search_index_drift() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let (packed, json) = sign(1, "searchable", 1_700_000_100, json!([]));
    let mut events = vec![EventToWrite::new(packed, json)];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();

    let lev = events[0].lev_id.to_ne_bytes();
    let mut txn = env.begin_rw().unwrap();
    assert!(txn
        .del(
            env.dbis().event_search.unwrap(),
            b"\x01searchable",
            Some(&lev),
        )
        .unwrap());
    txn.put(
        env.dbis().event_search.unwrap(),
        b"\x01not-in-content",
        &lev,
        0,
    )
    .unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(!report.ok());
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "missing-index" && issue.table == "event_search"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "unexpected-index" && issue.table == "event_search"));
}

/// Write `contents` as kind-1 notes and return their local ids.
fn write_notes(env: &Env, contents: &[&str]) -> Vec<u64> {
    let mut events = contents
        .iter()
        .enumerate()
        .map(|(i, content)| {
            let (packed, json) = sign(1, content, 1_700_000_100 + i as u64, json!([]));
            EventToWrite::new(packed, json)
        })
        .collect::<Vec<_>>();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    events.iter().map(|event| event.lev_id).collect()
}

/// The `event_search` issues, as `(category, detail)`, sorted.
fn search_issues(report: &wok_db::IntegrityReport) -> Vec<(&'static str, String)> {
    let mut issues = report
        .issues
        .iter()
        .filter(|issue| issue.table == "event_search")
        .map(|issue| (issue.category, issue.detail.clone()))
        .collect::<Vec<_>>();
    issues.sort();
    issues
}

#[test]
fn integrity_counts_every_kind_of_search_drift() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let levs = write_notes(&env, &["alpha beta", "gamma"]);
    let dbi = env.dbis().event_search.unwrap();
    let lev = levs[0].to_ne_bytes();
    let mut txn = env.begin_rw().unwrap();
    assert!(txn.del(dbi, b"\x01alpha", Some(&lev)).unwrap());
    txn.put(dbi, b"\x01bogus", &lev, 0).unwrap();
    txn.put(dbi, b"\x01gamma", &999u64.to_ne_bytes(), 0)
        .unwrap();
    txn.put(dbi, b"\x03alpha", &lev, 0).unwrap();
    txn.put(dbi, b"\x01short", &7u32.to_ne_bytes(), 0).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(!report.ok());
    assert_eq!(report.missing_index_entries, 1, "{report:#?}");
    assert_eq!(report.extra_index_entries, 4, "{report:#?}");
    assert_eq!(report.malformed_records, 2, "{report:#?}");
    let a = levs[0];
    assert_eq!(
        search_issues(&report),
        [
            ("dangling-index", "levId 999".to_string()),
            ("malformed-key", "invalid term key".to_string()),
            (
                "malformed-value",
                "value has 4 bytes, expected 8".to_string()
            ),
            ("missing-index", format!("levId {a}")),
            ("unexpected-index", format!("term \"bogus\", levId {a}")),
        ]
    );
}

#[test]
fn integrity_checks_search_postings_of_events_it_cannot_read() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let levs = write_notes(&env, &["alpha", "beta", "gamma"]);
    let dbis = env.dbis();
    let search = dbis.event_search.unwrap();
    let (a, b, c) = (levs[0], levs[1], levs[2]);
    let mut txn = env.begin_rw().unwrap();
    // A payload that does not decode derives no postings.
    txn.put(dbis.event_payload, &a.to_ne_bytes(), b"\x07", 0)
        .unwrap();
    // A PackedEvent too short to read, and a payload with no PackedEvent,
    // still derive postings from their payloads.
    txn.put(dbis.event, &b.to_ne_bytes(), b"short", 0).unwrap();
    txn.put(search, b"\x01bogusb", &b.to_ne_bytes(), 0).unwrap();
    assert!(txn.del(dbis.event, &c.to_ne_bytes(), None).unwrap());
    txn.put(search, b"\x01bogusc", &c.to_ne_bytes(), 0).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(!report.ok());
    assert!(report.issues.len() < 100, "{report:#?}");
    let unexpected = search_issues(&report)
        .into_iter()
        .filter(|(category, _)| *category == "unexpected-index")
        .map(|(_, detail)| detail)
        .collect::<Vec<_>>();
    assert_eq!(
        unexpected,
        [
            format!("term \"alpha\", levId {a}"),
            format!("term \"bogusb\", levId {b}"),
            format!("term \"bogusc\", levId {c}"),
        ]
    );
}

#[test]
fn integrity_counts_search_drift_beyond_the_reported_issues() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let levs = write_notes(&env, &["alpha"]);
    let dbi = env.dbis().event_search.unwrap();
    let mut txn = env.begin_rw().unwrap();
    for i in 0..150 {
        txn.put(
            dbi,
            format!("\x01bogus{i}").as_bytes(),
            &levs[0].to_ne_bytes(),
            0,
        )
        .unwrap();
    }
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert_eq!(report.extra_index_entries, 150, "{report:#?}");
    assert_eq!(report.missing_index_entries, 0, "{report:#?}");
    assert_eq!(report.issues.len(), 100);
    assert!(report
        .issues
        .iter()
        .all(|issue| issue.category == "unexpected-index" && issue.table == "event_search"));
}
