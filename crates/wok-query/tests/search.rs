use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{
    delete_events, encode_zstd_payload, event_json_owned, insert_compression_dictionary,
    write_events, Decompressor, Env, EnvOptions, EventToWrite, NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::{
    foreach_by_filter, DbQuery, NostrFilterGroup, QueryScheduler, SubId, Subscription,
};

fn sign(kind: u64, content: &str, created_at: u64) -> EventToWrite {
    let mut rng = rand::thread_rng();
    let keypair = Keypair::new(SECP256K1, &mut rng);
    let (public_key, _) = keypair.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": [],
        "content": content,
        "pubkey": hex::encode(public_key.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr(&id, &keypair);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn contents(env: &Env, lev_ids: &[u64]) -> Vec<String> {
    let txn = env.begin_ro().unwrap();
    let mut decompressor = Decompressor::new();
    lev_ids
        .iter()
        .map(|lev_id| {
            let json = event_json_owned(&txn, &mut decompressor, *lev_id, 1_000_000).unwrap();
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["content"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn search_is_ranked_then_limited_and_honors_structured_filters() {
    let temp = TempDir::new().unwrap();
    let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = vec![
        sign(1, "Nostr search makes relays useful", 100),
        sign(1, "Search tools for every Nostr relay", 300),
        sign(0, "Nostr search profile", 400),
        sign(1, "unrelated content", 500),
    ];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let mut hits = Vec::new();
    foreach_by_filter(
        &txn,
        &json!({"search":"nostr search", "kinds":[1], "limit":1}),
        100,
        3,
        16,
        |lev_id| hits.push(lev_id),
    )
    .unwrap();
    drop(txn);
    assert_eq!(
        contents(&env, &hits),
        vec!["Nostr search makes relays useful"]
    );
}

#[test]
fn search_ignores_extensions_and_is_unicode_case_insensitive() {
    let temp = TempDir::new().unwrap();
    let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = vec![sign(1, "A CAFÉ for Nostr users", 100)];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let mut hits = Vec::new();
    foreach_by_filter(
        &txn,
        &json!({"search":"café domain:example.com include:spam"}),
        100,
        3,
        16,
        |lev_id| hits.push(lev_id),
    )
    .unwrap();
    assert_eq!(hits.len(), 1);
}

#[test]
fn delete_removes_search_postings_and_missing_index_is_backfilled() {
    let temp = TempDir::new().unwrap();
    let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = vec![sign(1, "backfill sentinel", 100)];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    let lev_id = events[0].lev_id;
    txn.commit().unwrap();

    let mut txn = env.begin_rw().unwrap();
    txn.clear(env.dbis().event_search.unwrap()).unwrap();
    txn.commit().unwrap();
    env.ensure_initialized().unwrap();

    let txn = env.begin_ro().unwrap();
    let mut hits = Vec::new();
    foreach_by_filter(
        &txn,
        &json!({"search":"backfill sentinel"}),
        100,
        3,
        16,
        |hit| hits.push(hit),
    )
    .unwrap();
    assert_eq!(hits, vec![lev_id]);
    drop(txn);

    let mut txn = env.begin_rw().unwrap();
    delete_events(&mut txn, &mut NoopNegentropy, [lev_id]).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    hits.clear();
    foreach_by_filter(
        &txn,
        &json!({"search":"backfill sentinel"}),
        100,
        3,
        16,
        |hit| hits.push(hit),
    )
    .unwrap();
    assert!(hits.is_empty());
}

#[test]
fn multiple_search_filters_are_merged_by_quality() {
    let temp = TempDir::new().unwrap();
    let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = vec![
        sign(1, "common first", 100),
        sign(1, "common second", 200),
        sign(1, "rarest result", 50),
    ];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let mut hits = Vec::new();
    foreach_by_filter(
        &txn,
        &json!([
            {"search":"common", "limit":1},
            {"search":"rarest", "limit":1}
        ]),
        100,
        3,
        16,
        |lev_id| hits.push(lev_id),
    )
    .unwrap();
    drop(txn);
    assert_eq!(
        contents(&env, &hits),
        vec!["rarest result", "common second"]
    );

    let group = NostrFilterGroup::from_value(
        &json!([
            {"search":"common", "limit":2},
            {"search":"rarest", "limit":1}
        ]),
        100,
        3,
        16,
    )
    .unwrap();
    let txn = env.begin_ro().unwrap();
    let mut capped = DbQuery::new(
        Subscription::new(1, SubId::new("search-cap").unwrap(), group, false),
        1,
        0,
    );
    let mut capped_hits = Vec::new();
    assert!(capped
        .process(&txn, |_, lev| capped_hits.push(lev), u64::MAX)
        .unwrap());
    assert_eq!(capped_hits.len(), 1);
}

/// Store every payload zstd-compressed with a dictionary, as `wok dict` does.
fn compress_payloads(env: &Env) {
    let txn = env.begin_ro().unwrap();
    let mut lev_ids = Vec::new();
    foreach_by_filter(&txn, &json!({}), 100, 3, 16, |lev_id| lev_ids.push(lev_id)).unwrap();
    let mut decompressor = Decompressor::new();
    let stored: Vec<_> = lev_ids
        .into_iter()
        .map(|lev_id| {
            let json = event_json_owned(&txn, &mut decompressor, lev_id, 1_000_000).unwrap();
            (lev_id, json)
        })
        .collect();
    drop(txn);
    let dict = br#"{"content":"alpha beta gamma","kind":1,"tags":[]}"#.repeat(32);
    let mut txn = env.begin_rw().unwrap();
    let dict_id = u32::try_from(insert_compression_dictionary(&mut txn, &dict).unwrap()).unwrap();
    for (lev_id, json) in stored {
        let compressed = zstd::bulk::Compressor::with_dictionary(3, &dict)
            .unwrap()
            .compress(json.as_bytes())
            .unwrap();
        let payload = encode_zstd_payload(dict_id, &compressed);
        txn.put_u64(env.dbis().event_payload, lev_id, &payload, 0)
            .unwrap();
    }
    txn.commit().unwrap();
}

#[test]
fn compressed_matches_get_the_phrase_boost_through_the_scheduler() {
    let temp = TempDir::new().unwrap();
    let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    // Without the phrase boost, the newer note ranks first.
    let mut events = vec![sign(1, "alpha beta", 100), sign(1, "alpha gamma beta", 200)];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    compress_payloads(&env);

    // Every filter's phrase check reads a compressed payload through the
    // scheduler's one decompressor.
    let filter = json!({"search": "alpha beta", "limit": 1});
    let group = NostrFilterGroup::from_value(&json!([filter, filter, filter]), 100, 3, 16).unwrap();
    let txn = env.begin_ro().unwrap();
    let mut scheduler = QueryScheduler::new(1, 0, 0);
    scheduler
        .add_sub(
            &txn,
            Subscription::new(1, SubId::new("phrase").unwrap(), group, false),
        )
        .unwrap();
    let mut hits = Vec::new();
    while scheduler.has_running() {
        scheduler
            .process(
                &txn,
                u64::MAX,
                |_, lev_id, _| {
                    hits.push(lev_id);
                    true
                },
                |_, _, _, _, _| {},
            )
            .unwrap();
    }
    drop(txn);
    assert_eq!(contents(&env, &hits), vec!["alpha beta"]);
}
