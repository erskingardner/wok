//! `verify_events`: each stored event against its payload.
use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{
    check_integrity, verify_events, write_events, Env, EnvOptions, EventToWrite, NoopNegentropy,
};
use wok_event::{EventLimits, PackedEventBuilder, PackedEventTagBuilder, PackedEventView};

fn signed(content: &str, created_at: u64) -> Value {
    signed_with(1, json!([["t", "verify"]]), content, created_at)
}

fn signed_with(kind: u64, tags: Value, content: &str, created_at: u64) -> Value {
    use secp256k1::{Keypair, SECP256K1};
    let kp = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let mut ev = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "pubkey": hex::encode(kp.x_only_public_key().0.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    ev["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &kp).as_ref()));
    ev
}

fn packed(ev: &Value) -> Vec<u8> {
    wok_event::nostr_json_to_packed_event(ev, &EventLimits::default())
        .unwrap()
        .into_bytes()
}

/// `ev`'s record with this kind, expiration and tags in place of its own.
fn forged(ev: &Value, kind: u64, expiration: u64, tags: &[(char, &[u8])]) -> Vec<u8> {
    let original = packed(ev);
    let view = PackedEventView::new(&original).unwrap();
    let mut builder = PackedEventTagBuilder::default();
    for (name, value) in tags {
        builder.add(*name, value).unwrap();
    }
    PackedEventBuilder::build(
        view.id(),
        view.pubkey(),
        view.created_at(),
        kind,
        expiration,
        &builder,
    )
    .unwrap()
    .into_bytes()
}

/// Store each PackedEvent with its payload as given, as a crafted source
/// would hold them. Returns their local ids, in order.
fn store(env: &Env, records: Vec<(Vec<u8>, String)>) -> Vec<u64> {
    let mut events: Vec<_> = records
        .into_iter()
        .map(|(packed, json)| EventToWrite::new(packed, json))
        .collect();
    let ids: Vec<_> = events
        .iter()
        .map(|event| event.packed[..32].to_vec())
        .collect();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    // The writer stores a batch in its own order.
    ids.iter()
        .map(|id| {
            events
                .iter()
                .find(|event| event.packed[..32] == id[..])
                .unwrap()
                .lev_id
        })
        .collect()
}

fn open() -> (TempDir, Env) {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    (tmp, env)
}

#[test]
fn crafted_records_pass_integrity_but_not_verification() {
    let (_tmp, env) = open();
    let good = signed("good", 1_700_000_000);
    let other = signed("other", 1_700_000_001);
    let mut bad_sig = signed("bad sig", 1_700_000_002);
    let sig = bad_sig["sig"].as_str().unwrap();
    bad_sig["sig"] = json!(format!(
        "{}{}",
        if sig.starts_with('0') { "1" } else { "0" },
        &sig[1..]
    ));
    let edited = signed("edited", 1_700_000_003);
    let mut edited_json = edited.clone();
    edited_json["content"] = json!("edited later");
    let kind = signed("kind", 1_700_000_004);
    // Records whose indexes put the payload where it does not belong: under
    // kind 7, another recipient, another address, another expiry.
    let recipient = [0x22; 32];
    let dm = signed_with(
        4,
        json!([["p", hex::encode(recipient)]]),
        "dm",
        1_700_000_006,
    );
    let article = signed_with(30023, json!([["d", "post"]]), "article", 1_700_000_007);
    let kept = signed_with(1, json!([]), "kept", 1_700_000_008);
    let tao = wok_event::json::to_tao_string;
    let lev_ids = store(
        &env,
        vec![
            (packed(&good), tao(&good)),
            // Another event's payload under this record.
            (packed(&signed("swapped", 1_700_000_005)), tao(&other)),
            (packed(&bad_sig), tao(&bad_sig)),
            (packed(&edited), tao(&edited_json)),
            (forged(&kind, 7, 0, &[('t', b"verify")]), tao(&kind)),
            (forged(&dm, 4, 0, &[('p', &[0x33; 32])]), tao(&dm)),
            (
                forged(&article, 30023, 0, &[('d', b""), ('d', b"post")]),
                tao(&article),
            ),
            (forged(&kept, 1, 1_700_000_100, &[]), tao(&kept)),
        ],
    );

    let integrity = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(integrity.ok(), "{integrity:?}");

    for threads in [1, 3] {
        let report = verify_events(&env, threads).unwrap();
        assert_eq!(report.events, 8);
        assert_eq!(report.failed, 7);
        assert!(!report.ok());
        let failures: Vec<_> = report
            .failures
            .iter()
            .map(|failure| (failure.lev_id, failure.reason.as_str()))
            .collect();
        let forged_p = format!("packed p tag {} is not in the payload", "33".repeat(32));
        let mut expected = vec![
            (lev_ids[1], "payload id differs from the packed record"),
            (lev_ids[2], "bad signature"),
            (lev_ids[3], "bad event id"),
            (lev_ids[4], "payload kind differs from the packed record"),
            (lev_ids[5], forged_p.as_str()),
            (
                lev_ids[6],
                r#"packed address "" differs from the payload's "post""#,
            ),
            (
                lev_ids[7],
                "packed expiration 1700000100 differs from the payload's none",
            ),
        ];
        expected.sort();
        assert_eq!(failures, expected);
        // Failures name the id the indexes hold.
        let named = |lev_id| {
            let failure = report.failures.iter().find(|f| f.lev_id == lev_id);
            failure.unwrap().id.clone()
        };
        assert_eq!(named(lev_ids[2]), bad_sig["id"].as_str().unwrap());
    }
}

#[test]
fn compressed_payloads_are_verified() {
    let (_tmp, env) = open();
    let good = signed("compressed", 1_700_000_000);
    let mut forged = signed("forged", 1_700_000_001);
    let lev_ids = store(
        &env,
        vec![
            (packed(&good), wok_event::json::to_tao_string(&good)),
            (packed(&forged), wok_event::json::to_tao_string(&forged)),
        ],
    );
    forged["content"] = json!("forged later");
    let mut txn = env.begin_rw().unwrap();
    let dict = br#"{"content":"xxxxxxxxxxxxxxxx","kind":1,"tags":[]}"#.repeat(32);
    let dict_id = wok_db::insert_compression_dictionary(&mut txn, &dict).unwrap();
    for (lev_id, event) in lev_ids.iter().zip([&good, &forged]) {
        let compressed = zstd::bulk::Compressor::with_dictionary(3, &dict)
            .unwrap()
            .compress(wok_event::json::to_tao_string(event).as_bytes())
            .unwrap();
        let payload = wok_db::encode_zstd_payload(u32::try_from(dict_id).unwrap(), &compressed);
        txn.put_u64(env.dbis().event_payload, *lev_id, &payload, 0)
            .unwrap();
    }
    txn.commit().unwrap();

    let report = verify_events(&env, 2).unwrap();
    assert_eq!(report.events, 2);
    assert_eq!(report.failed, 1);
    assert_eq!(report.failures[0].lev_id, lev_ids[1]);
    assert_eq!(report.failures[0].reason, "bad event id");
}

/// `n` records that do not verify, cheaply: their ids hash nothing.
fn unverifiable(n: u64) -> Vec<(Vec<u8>, String)> {
    (0..n)
        .map(|n| {
            let ev = json!({
                "id": hex::encode(wok_event::sha256(&n.to_be_bytes())),
                "pubkey": "22".repeat(32),
                "created_at": n,
                "kind": 1,
                "tags": [],
                "content": "",
                "sig": "00".repeat(64),
            });
            (packed(&ev), wok_event::json::to_tao_string(&ev))
        })
        .collect()
}

#[test]
fn workers_report_the_lowest_failures_across_runs() {
    // More events than one run of local ids.
    let (_tmp, env) = open();
    let lev_ids = store(&env, unverifiable(10_000));
    for threads in [1, 4] {
        let report = verify_events(&env, threads).unwrap();
        assert_eq!(report.events, 10_000);
        assert_eq!(report.failed, 10_000);
        let reported: Vec<_> = report.failures.iter().map(|f| f.lev_id).collect();
        assert_eq!(reported, lev_ids[..100]);
    }
}

#[test]
fn empty_database_verifies() {
    let (_tmp, env) = open();
    let report = verify_events(&env, 4).unwrap();
    assert_eq!((report.events, report.failed), (0, 0));
    assert!(report.ok());
}

#[test]
fn sparse_local_ids_cost_their_events_not_the_id_space() {
    // A source may store events at any local ids. Taking every run of 4,096
    // ids in turn would need about 2^52 runs to reach the last of these.
    let (_tmp, env) = open();
    let lev_ids = [1, 2, 1 << 40, 1 << 60, u64::MAX];
    let mut txn = env.begin_rw().unwrap();
    for (n, lev_id) in lev_ids.into_iter().enumerate() {
        let ev = signed(&format!("sparse {n}"), 1_700_000_000 + n as u64);
        let mut json = ev.clone();
        if lev_id == u64::MAX {
            json["content"] = json!("edited");
        }
        txn.put_u64(env.dbis().event, lev_id, &packed(&ev), 0)
            .unwrap();
        let payload = wok_db::encode_raw_payload(&wok_event::json::to_tao_string(&json));
        txn.put_u64(env.dbis().event_payload, lev_id, &payload, 0)
            .unwrap();
    }
    txn.commit().unwrap();
    for threads in [1, 4] {
        let report = verify_events(&env, threads).unwrap();
        assert_eq!((report.events, report.failed), (5, 1));
        assert_eq!(report.failures[0].lev_id, u64::MAX);
    }
}

#[test]
fn verification_fits_the_reader_slots_left() {
    // Each worker holds a reader slot. With every slot but the caller's
    // taken, the caller verifies alone.
    let (_tmp, env) = open();
    store(&env, unverifiable(5_000));
    // The calling thread keeps its slot after the transaction ends.
    drop(env.begin_ro().unwrap());
    let max_readers = env.stats().unwrap().max_readers as usize;
    let gate = std::sync::RwLock::new(());
    let held = gate.write().unwrap();
    std::thread::scope(|scope| {
        let (began, results) = std::sync::mpsc::channel();
        for _ in 0..max_readers {
            let began = began.clone();
            let (env, gate) = (&env, &gate);
            scope.spawn(move || {
                let txn = env.begin_ro();
                began.send(txn.is_ok()).unwrap();
                if txn.is_ok() {
                    drop(gate.read().unwrap());
                }
            });
        }
        let holding = results.iter().take(max_readers).filter(|ok| *ok).count();
        assert_eq!(holding, max_readers - 1);

        let report = verify_events(&env, 8).unwrap();
        assert_eq!((report.events, report.failed), (5_000, 5_000));
        drop(held);
    });
}
