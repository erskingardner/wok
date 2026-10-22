//! The TagKind plan returns exactly what the Tag plan does: the same events
//! in the same order, for random corpora and filters with one tag and
//! `kinds`, including entries an earlier release left when it deleted their
//! events.

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{
    delete_events, reset_tag_kind_index, tag_kind_key, write_events, Env, EnvOptions, EventToWrite,
    NoopNegentropy,
};
use wok_event::{to_hex, PackedEventBuilder, PackedEventTagBuilder, PackedEventView};
use wok_query::visibility::ReadVisibility;
use wok_query::{foreach_visible_by_filter, DbScan, NostrFilterGroup};

const KINDS: [u64; 9] = [0, 1, 3, 4, 6, 7, 1059, 9735, 30023];
const BASE: u64 = 1_700_000_000;
const TOPICS: [&str; 4] = ["nostr", "rust", "wok", "zap"];
const D_TAGS: [&str; 2] = ["post", "note"];

fn key(n: u8) -> [u8; 32] {
    [0x10 + n; 32]
}

fn ref_id(n: u8) -> [u8; 32] {
    [0xe0 + n; 32]
}

fn address(n: u8) -> String {
    format!("30023:{}:{}", to_hex(&key(n % 4)), D_TAGS[n as usize % 2])
}

/// One tag of an event, as the filter names it and as JSON lists it.
fn tag(rng: &mut StdRng) -> (char, Vec<u8>, String) {
    match rng.gen_range(0..5) {
        0 => {
            let pk = key(rng.gen_range(0..6));
            ('p', pk.to_vec(), to_hex(&pk))
        }
        1 => {
            let id = ref_id(rng.gen_range(0..4));
            ('e', id.to_vec(), to_hex(&id))
        }
        2 => {
            let topic = TOPICS[rng.gen_range(0..TOPICS.len())];
            ('t', topic.as_bytes().to_vec(), topic.to_owned())
        }
        3 => {
            let a = address(rng.gen_range(0..4));
            ('a', a.as_bytes().to_vec(), a)
        }
        _ => {
            let pk = key(rng.gen_range(0..6));
            ('P', pk.to_vec(), to_hex(&pk))
        }
    }
}

/// An unsigned event; the write path does not check signatures.
fn event(rng: &mut StdRng, n: u64) -> EventToWrite {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    id[8..16].copy_from_slice(&rng.gen::<u64>().to_be_bytes());
    let author = key(rng.gen_range(0..6));
    let kind = KINDS[rng.gen_range(0..KINDS.len())];
    // A narrow window makes ties on created_at common.
    let created_at = BASE + rng.gen_range(0..40);
    let mut tags = PackedEventTagBuilder::default();
    let mut json_tags = Vec::new();
    if kind == 30023 {
        let d = D_TAGS[rng.gen_range(0..2)];
        tags.add('d', d.as_bytes()).unwrap();
        json_tags.push(json!(["d", d]));
    }
    for _ in 0..rng.gen_range(0..4) {
        let (name, packed, text) = tag(rng);
        tags.add(name, &packed).unwrap();
        json_tags.push(json!([name.to_string(), text]));
        if rng.gen_bool(0.1) {
            // The same value twice gives one index entry.
            tags.add(name, &packed).unwrap();
            json_tags.push(json!([name.to_string(), text]));
        }
    }
    let packed = PackedEventBuilder::build(&id, &author, created_at, kind, 0, &tags).unwrap();
    let json = json!({
        "id": to_hex(&id),
        "pubkey": to_hex(&author),
        "created_at": created_at,
        "kind": kind,
        "tags": json_tags,
        "content": "",
        "sig": "00".repeat(64),
    })
    .to_string();
    EventToWrite::new(packed.into_bytes(), json)
}

/// The same corpus in two databases: `indexed` keeps the TagKind index,
/// where an earlier release deleted some events and left their entries;
/// `unindexed` has it reset, so its queries plan on the Tag index.
fn corpus(seed: u64) -> (TempDir, Env, TempDir, Env) {
    let mut rng = StdRng::seed_from_u64(seed);
    let count = rng.gen_range(30..90);
    let events: Vec<_> = (0..count).map(|n| event(&mut rng, n)).collect();
    let deleted: Vec<usize> = (0..count as usize).filter(|_| rng.gen_bool(0.1)).collect();
    let open = || {
        let dir = TempDir::new().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        (dir, env)
    };
    let (indexed_dir, indexed) = open();
    let (unindexed_dir, unindexed) = open();
    for env in [&indexed, &unindexed] {
        let mut batch = events.clone();
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut batch, false).unwrap();
        let gone: Vec<_> = deleted
            .iter()
            .map(|&i| batch[i].lev_id)
            .filter(|&lev| lev != 0)
            .collect();
        delete_events(&mut txn, &mut NoopNegentropy, gone.iter().copied()).unwrap();
        if std::ptr::eq(env, &indexed) {
            let dbi = env.dbis().event_tag_kind.unwrap();
            for &i in &deleted {
                let lev = batch[i].lev_id;
                let view = PackedEventView::new(&batch[i].packed).unwrap();
                view.foreach_tag(|name, value| {
                    let key = tag_kind_key(name as u8, value, view.kind(), view.created_at());
                    txn.put(dbi, &key, &lev.to_ne_bytes(), 0).unwrap();
                    true
                });
            }
        } else {
            reset_tag_kind_index(&mut txn).unwrap();
        }
        txn.commit().unwrap();
    }
    let complete = |env: &Env| wok_db::tag_kind_index_complete_ro(&env.begin_ro().unwrap());
    assert!(complete(&indexed).unwrap());
    assert!(!complete(&unindexed).unwrap());
    (indexed_dir, indexed, unindexed_dir, unindexed)
}

fn filter_strategy() -> impl Strategy<Value = Value> {
    let values = prop_oneof![
        prop::collection::vec(0u8..7, 1..4).prop_map(|ns| (
            "#p",
            ns.into_iter()
                .map(|n| Value::from(to_hex(&key(n))))
                .collect::<Vec<_>>()
        )),
        prop::collection::vec(0u8..5, 1..3).prop_map(|ns| (
            "#e",
            ns.into_iter()
                .map(|n| Value::from(to_hex(&ref_id(n))))
                .collect::<Vec<_>>()
        )),
        prop::collection::vec(0usize..5, 1..3).prop_map(|ns| (
            "#t",
            ns.into_iter()
                .map(|n| Value::from(TOPICS.get(n).copied().unwrap_or("absent")))
                .collect::<Vec<_>>()
        )),
        prop::collection::vec(0u8..5, 1..3).prop_map(|ns| (
            "#a",
            ns.into_iter()
                .map(|n| Value::from(address(n)))
                .collect::<Vec<_>>()
        )),
        prop::collection::vec(0u8..7, 1..3).prop_map(|ns| (
            "#P",
            ns.into_iter()
                .map(|n| Value::from(to_hex(&key(n))))
                .collect::<Vec<_>>()
        )),
        prop::collection::vec(0usize..2, 1..2).prop_map(|ns| (
            "#d",
            ns.into_iter()
                .map(|n| Value::from(D_TAGS[n]))
                .collect::<Vec<_>>()
        )),
    ];
    (
        values,
        prop::collection::vec(prop::sample::select(KINDS.to_vec()), 1..5),
        prop::option::of(prop::collection::vec(0u8..7, 1..3)),
        prop::option::of(0u64..40),
        prop::option::of(0u64..40),
        prop::option::of(1u64..40),
    )
        .prop_map(|((tag, values), kinds, authors, since, until, limit)| {
            let mut filter = json!({ "kinds": kinds });
            filter[tag] = json!(values);
            if let Some(authors) = authors {
                filter["authors"] = json!(authors
                    .into_iter()
                    .map(|n| to_hex(&key(n)))
                    .collect::<Vec<_>>());
            }
            if let Some(since) = since {
                filter["since"] = json!(BASE + since);
            }
            if let Some(until) = until {
                filter["until"] = json!(BASE + until);
            }
            if let Some(limit) = limit {
                filter["limit"] = json!(limit);
            }
            filter
        })
}

fn results(env: &Env, filter: &Value) -> Vec<u64> {
    let txn = env.begin_ro().unwrap();
    let mut levs = Vec::new();
    foreach_visible_by_filter(&txn, filter, 500, 3, 16, ReadVisibility::default(), |lev| {
        levs.push(lev)
    })
    .unwrap();
    levs
}

fn plan(env: &Env, filter: &Value) -> &'static str {
    let txn = env.begin_ro().unwrap();
    let group = NostrFilterGroup::from_value(filter, 500, 3, 16).unwrap();
    DbScan::new(&group.filters[0], &txn).desc
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn the_tag_kind_plan_returns_what_the_tag_plan_does(
        seed in any::<u64>(),
        filters in prop::collection::vec(filter_strategy(), 1..12),
    ) {
        let (_a, indexed, _b, unindexed) = corpus(seed);
        for filter in &filters {
            prop_assert_eq!(plan(&unindexed, filter), "Tag");
            // The author probe may still prefer the Pubkey index.
            prop_assert!(["TagKind", "Pubkey", "PubkeyKind"].contains(&plan(&indexed, filter)));
            prop_assert_eq!(results(&indexed, filter), results(&unindexed, filter), "{}", filter);
        }
    }
}

#[test]
fn a_filter_list_mixing_plans_returns_what_the_tag_plan_does() {
    let (_a, indexed, _b, unindexed) = corpus(7);
    let filters = json!([
        {"#p": [to_hex(&key(1)), to_hex(&key(2))], "kinds": [1, 7, 9735], "limit": 10},
        {"#t": ["nostr"], "kinds": [1]},
        {"#e": [to_hex(&ref_id(0))], "kinds": [7], "authors": [to_hex(&key(3))]},
        {"#t": ["rust"]},
    ]);
    assert_eq!(results(&indexed, &filters), results(&unindexed, &filters));
}
