//! Reindex keeps every table that events don't derive (#241).
use lmdb_sys::MDB_dbi;
use std::collections::BTreeSet;
use wok_db::env::Dbis;
use wok_db::schema::*;
use wok_db::{dbi_specs, Env, EnvOptions, EventToWrite, NoopNegentropy, PackedEventRebuild, Role};

/// The table's handle when reindex keeps its records unchanged, or None when
/// it derives the table from the events again. Events and payloads change
/// only when reindex repacks or deletes them, which this fixture never asks
/// for. A table this test does not name fails it until it is classified here.
fn kept_table(dbis: Dbis, name: &str) -> Option<MDB_dbi> {
    match name {
        DBI_META => Some(dbis.meta),
        DBI_NEGENTROPY_FILTER => Some(dbis.negentropy_filter),
        DBI_EVENT => Some(dbis.event),
        DBI_COMPRESSION_DICTIONARY => Some(dbis.compression_dictionary),
        DBI_EVENT_PAYLOAD => Some(dbis.event_payload),
        DBI_VANISH_PUBKEY => Some(dbis.vanish_pubkey.unwrap()),
        DBI_MODERATION => Some(dbis.moderation.unwrap()),
        // Reindex keeps the sequence and pending recipient deletion cutoffs
        // (`deletion_protection`), recounting derived state and restarting
        // sweeps. The visibility generation only signals a running relay.
        DBI_EVENT_ID
        | DBI_EVENT_PUBKEY_KIND
        | DBI_EVENT_TAG
        | DBI_EVENT_DELETION
        | DBI_EVENT_REPLACE
        | DBI_EVENT_CREATED_AT
        | DBI_EVENT_PUBKEY
        | DBI_EVENT_REPLACE_DELETION
        | DBI_EVENT_KIND
        | DBI_EVENT_EXPIRATION
        | DBI_NEGENTROPY
        | DBI_EVENT_SEARCH
        | DBI_STATE
        | DBI_EVENT_TAG_KIND
        | DBI_EVENT_TAG_KIND_BUILD => None,
        _ => panic!("say whether reindex keeps or derives {name}"),
    }
}

fn records(env: &Env, dbi: MDB_dbi) -> Vec<(Vec<u8>, Vec<u8>)> {
    let txn = env.begin_ro().unwrap();
    let mut records = Vec::new();
    txn.foreach_full(dbi, &[], &[], false, |key, value| {
        records.push((key.to_vec(), value.to_vec()));
        true
    })
    .unwrap();
    records
}

fn stored_event(id: u8, pubkey: u8) -> EventToWrite {
    let mut tags = wok_event::PackedEventTagBuilder::default();
    tags.add('t', b"kept").unwrap();
    let packed =
        wok_event::PackedEventBuilder::build(&[id; 32], &[pubkey; 32], 1_000, 1, 0, &tags).unwrap();
    let json = serde_json::json!({
        "id": hex::encode([id; 32]),
        "pubkey": hex::encode([pubkey; 32]),
        "created_at": 1_000,
        "kind": 1,
        "tags": [["t", "kept"]],
        "content": "kept tables",
        "sig": "00".repeat(64),
    });
    EventToWrite::new(packed.into_bytes(), json.to_string())
}

#[test]
fn reindex_keeps_every_table_events_do_not_derive() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = Env::open(source_dir.path(), EnvOptions::for_tests()).unwrap();
    source.ensure_initialized().unwrap();
    let mut txn = source.begin_rw().unwrap();
    let mut events = [stored_event(1, 7), stored_event(2, 8)];
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    wok_db::insert_negentropy_filter(&mut txn, r#"{"kinds":[1]}"#).unwrap();
    wok_db::insert_compression_dictionary(&mut txn, b"dictionary").unwrap();
    wok_db::mark_vanished(&mut txn, &[9; 32], 2_000).unwrap();
    // Every kind of NIP-86 record.
    wok_db::ban_pubkey(&mut txn, &[7; 32], "spam").unwrap();
    wok_db::allow_pubkey(&mut txn, &[8; 32], "member").unwrap();
    wok_db::ban_event(&mut txn, &[2; 32], "abuse").unwrap();
    wok_db::allow_event(&mut txn, &[3; 32], "reviewed").unwrap();
    wok_db::block_ip(&mut txn, "192.0.2.1", "flood").unwrap();
    wok_db::report_event(&mut txn, &[4; 32], "reported", &mut 1).unwrap();
    let role = Role {
        id: "editor".into(),
        label: "Editor".into(),
        description: "Edits".into(),
        color: "#00ff00".into(),
        order: 1,
    };
    wok_db::put_role(&mut txn, &role).unwrap();
    wok_db::assign_role(&mut txn, &[8; 32], "editor").unwrap();
    wok_db::disallow_kind(&mut txn, 4).unwrap();
    wok_db::allow_kind(&mut txn, 7).unwrap();
    txn.commit().unwrap();
    let moderation = records(&source, source.dbis().moderation.unwrap());
    let record_types: BTreeSet<u8> = moderation.iter().map(|(key, _)| key[0]).collect();
    assert_eq!(record_types, b"ABEGIKLPRV".iter().copied().collect());

    let target_dir = tempfile::tempdir().unwrap();
    let target = Env::open(target_dir.path(), EnvOptions::for_tests()).unwrap();
    let mut txn = target.begin_rw().unwrap();
    wok_db::rebuild_primary_and_event_indices(
        &source.begin_ro().unwrap(),
        &mut txn,
        PackedEventRebuild::RepackLongTags,
    )
    .unwrap();
    txn.commit().unwrap();

    for spec in dbi_specs() {
        let (Some(source_dbi), Some(target_dbi)) = (
            kept_table(source.dbis(), spec.name),
            kept_table(target.dbis(), spec.name),
        ) else {
            continue;
        };
        let kept = records(&source, source_dbi);
        assert!(!kept.is_empty(), "store a record in {} first", spec.name);
        assert_eq!(
            records(&target, target_dbi),
            kept,
            "reindex changed {}",
            spec.name
        );
    }
    let txn = target.begin_ro().unwrap();
    let banned = wok_db::get_packed_ro(&txn, events[1].lev_id)
        .unwrap()
        .unwrap();
    assert!(
        wok_db::is_event_moderated_ro(&txn, wok_event::PackedEventView::new(&banned).unwrap())
            .unwrap()
    );
}
