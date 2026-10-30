use lmdb_sys::MDB_dbi;
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::json;
use std::collections::BTreeMap;
use tempfile::TempDir;
use wok_db::comparators::make_key_string_u64;
use wok_db::{check_integrity, write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};

fn sign(kind: u64, content: &str, created: u64, tags: serde_json::Value) -> (Vec<u8>, String) {
    let kp = Keypair::new(SECP256K1, &mut rand::thread_rng());
    sign_by(&kp, kind, content, created, tags)
}

fn sign_by(
    kp: &Keypair,
    kind: u64,
    content: &str,
    created: u64,
    tags: serde_json::Value,
) -> (Vec<u8>, String) {
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
    let sig = SECP256K1.sign_schnorr(&id, kp);
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
    wok_db::finish_search_index(&env).unwrap();

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

/// Write `contents` as kind-1 notes, index them for search, and return their
/// local ids.
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
    wok_db::finish_search_index(env).unwrap();
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

fn fixed_key() -> Keypair {
    let secret = SecretKey::from_byte_array(&[7; 32]).unwrap();
    Keypair::from_secret_key(SECP256K1, &secret)
}

/// The indexes in strfry's layout, by the names integrity reports.
fn strfry_indexes(env: &Env) -> [(&'static str, MDB_dbi); 10] {
    let dbis = env.dbis();
    [
        ("event_id", dbis.event_id),
        ("event_pubkey_kind", dbis.event_pubkey_kind),
        ("event_tag", dbis.event_tag),
        ("event_deletion", dbis.event_deletion),
        ("event_replace", dbis.event_replace),
        ("event_created_at", dbis.event_created_at),
        ("event_pubkey", dbis.event_pubkey),
        ("event_replace_deletion", dbis.event_replace_deletion),
        ("event_kind", dbis.event_kind),
        ("event_expiration", dbis.event_expiration),
    ]
}

/// The issues of `table`, as `(category, detail)`, sorted.
fn table_issues(report: &wok_db::IntegrityReport, table: &str) -> Vec<(&'static str, String)> {
    let mut issues = report
        .issues
        .iter()
        .filter(|issue| issue.table == table)
        .map(|issue| (issue.category, issue.detail.clone()))
        .collect::<Vec<_>>();
    issues.sort();
    issues
}

#[test]
fn integrity_counts_every_kind_of_drift_in_each_strfry_index() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let key = fixed_key();
    let pubkey = hex::encode(key.x_only_public_key().0.serialize());
    // Between them, these events have postings in every index.
    let specs = [
        (
            1,
            "tagged",
            json!([
                ["t", "rust"],
                ["p", "11".repeat(32)],
                ["expiration", "2000000000"]
            ]),
        ),
        (
            5,
            "",
            json!([
                ["e", "22".repeat(32)],
                ["a", format!("30000:{pubkey}:gone")]
            ]),
        ),
        (0, "{}", json!([])),
        (30000, "", json!([["d", "list"]])),
        (1, "victim", json!([])),
    ];
    let mut events = specs
        .iter()
        .enumerate()
        .map(|(i, (kind, content, tags))| {
            let (packed, json) =
                sign_by(&key, *kind, content, 1_700_000_001 + i as u64, tags.clone());
            EventToWrite::new(packed, json)
        })
        .collect::<Vec<_>>();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
    let levs = events.iter().map(|event| event.lev_id).collect::<Vec<_>>();
    // An event whose PackedEvent will be too short to read. A note without
    // tags, it has postings of its own in these indexes.
    let victim = levs[4];
    let victim_tables = [
        "event_id",
        "event_pubkey_kind",
        "event_created_at",
        "event_pubkey",
        "event_kind",
    ];

    let mut expected = BTreeMap::new();
    let mut txn = env.begin_rw().unwrap();
    for (table, dbi) in strfry_indexes(&env) {
        // A posting of an event, and another event, which does not derive it:
        // each event has a created_at of its own.
        let mut first = None;
        txn.foreach_full(dbi, &[], &[], false, |key, value| {
            let lev = u64::from_ne_bytes(value.try_into().unwrap());
            if lev == victim {
                return true;
            }
            first = Some((key.to_vec(), lev));
            false
        })
        .unwrap();
        let (posting, owner) = first.unwrap();
        let other = *levs
            .iter()
            .find(|&&lev| lev != owner && lev != victim)
            .unwrap();
        assert!(txn.del(dbi, &posting, Some(&owner.to_ne_bytes())).unwrap());
        for lev in [other, 999, victim] {
            txn.put(dbi, &posting, &lev.to_ne_bytes(), 0).unwrap();
        }
        let mut malformed = posting.clone();
        *malformed.last_mut().unwrap() ^= 0xff;
        txn.put(dbi, &malformed, &7u32.to_ne_bytes(), 0).unwrap();
        let mut issues = vec![
            ("dangling-index", "levId 999".to_string()),
            (
                "malformed-value",
                "value has 4 bytes, expected 8".to_string(),
            ),
            ("missing-index", format!("levId {owner}")),
            ("unexpected-index", format!("levId {other}")),
            ("unverifiable-index", format!("levId {victim}")),
        ];
        if victim_tables.contains(&table) {
            issues.push(("unverifiable-index", format!("levId {victim}")));
        }
        expected.insert(table, issues);
    }
    txn.put(env.dbis().event, &victim.to_ne_bytes(), b"short", 0)
        .unwrap();
    txn.commit().unwrap();

    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(!report.ok());
    assert!(report.issues.len() < 100, "{report:#?}");
    assert_eq!(report.missing_index_entries, 10, "{report:#?}");
    assert_eq!(report.extra_index_entries, 45, "{report:#?}");
    assert_eq!(report.malformed_records, 10, "{report:#?}");
    assert_eq!(report.packed_parse_errors, 1, "{report:#?}");
    for (table, issues) in expected {
        assert_eq!(table_issues(&report, table), issues, "{table}");
    }
}

/// Index `records` as stored at local ids from 1, keeping every version of
/// an address, as a database migrated from strfry may.
fn indexed_records(dir: &TempDir, records: &[(Vec<u8>, String)]) -> Env {
    let source_dir = TempDir::new().unwrap();
    let source = Env::open(source_dir.path(), EnvOptions::for_tests()).unwrap();
    source.ensure_initialized().unwrap();
    let mut txn = source.begin_rw().unwrap();
    for (i, (packed, json)) in records.iter().enumerate() {
        let lev = i as u64 + 1;
        txn.put_u64(source.dbis().event, lev, packed, 0).unwrap();
        txn.put_u64(
            source.dbis().event_payload,
            lev,
            &wok_db::encode_raw_payload(json),
            0,
        )
        .unwrap();
    }
    txn.commit().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    wok_db::rebuild_primary_and_event_indices(
        &source.begin_ro().unwrap(),
        &mut txn,
        wok_db::PackedEventRebuild::Copy,
    )
    .unwrap();
    txn.commit().unwrap();
    env
}

#[test]
fn integrity_counts_replacement_history_from_valid_postings_only() {
    let tmp = TempDir::new().unwrap();
    let key = fixed_key();
    let pubkey = key.x_only_public_key().0.serialize();
    let specs = [
        (0, json!([])),
        (1, json!([])),
        (0, json!([])),
        (0, json!([])),
        (30000, json!([["d", "x"]])),
        (30000, json!([["d", "x"]])),
        (30000, json!([["d", "y"]])),
        (1, json!([["d", "x"]])),
        (1, json!([["d", "x"]])),
    ];
    let records = specs
        .iter()
        .enumerate()
        .map(|(i, (kind, tags))| {
            sign_by(
                &key,
                *kind,
                &format!("v{i}"),
                1_000 + i as u64,
                tags.clone(),
            )
        })
        .collect::<Vec<_>>();
    let env = indexed_records(&tmp, &records);
    let address =
        |kind: u64, d: &str| make_key_string_u64(&[&pubkey[..], d.as_bytes()].concat(), kind);
    // Three versions of a replaceable event (local ids 1, 3 and 4) and two of
    // an addressable one (5 and 6) are history. One version of another
    // address (7) is not, nor are notes that share a `d` (8 and 9).
    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(report.ok(), "{report:#?}");
    assert_eq!((report.superseded_groups, report.superseded_events), (2, 3));
    assert_eq!(wok_db::state::superseded_events_ro(&txn).unwrap(), Some(3));
    drop(txn);

    // A count that drifted from intact postings is reported.
    let mut txn = env.begin_rw().unwrap();
    txn.put(
        env.dbis().state.unwrap(),
        b"superseded-versions",
        &7u64.to_le_bytes(),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert_eq!(report.metadata_errors, 1, "{report:#?}");
    assert_eq!(
        table_issues(&report, "state"),
        [(
            "counter-drift",
            "superseded event count is 7, expected 3".to_string()
        )]
    );

    // Postings that no version derives join no group: the note between the
    // replaceable versions, a dangling one, a replaceable version under
    // another address, and an addressable version under the notes' key.
    let dbi = env.dbis().event_replace;
    let mut txn = env.begin_rw().unwrap();
    for (posting, lev) in [
        (address(0, ""), 2u64),
        (address(0, ""), 999),
        (address(30000, "y"), 3),
        (address(1, "x"), 5),
    ] {
        txn.put(dbi, &posting, &lev.to_ne_bytes(), 0).unwrap();
    }
    txn.commit().unwrap();
    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(!report.ok());
    assert_eq!((report.superseded_groups, report.superseded_events), (2, 3));
    assert_eq!(report.extra_index_entries, 4, "{report:#?}");
    assert_eq!(
        table_issues(&report, "event_replace"),
        [
            ("dangling-index", "levId 999".to_string()),
            ("unexpected-index", "levId 2".to_string()),
            ("unexpected-index", "levId 3".to_string()),
            ("unexpected-index", "levId 5".to_string()),
        ]
    );
    // A broken index cannot establish drift in the stored count.
    assert_eq!(report.metadata_errors, 0, "{report:#?}");
}
