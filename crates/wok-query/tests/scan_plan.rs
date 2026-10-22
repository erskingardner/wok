//! The query-cost gate prices the plan `DbScan` runs: for any filter,
//! `ScanPlan` names the scan's plan and counts the cursors it opens, whether
//! or not the (tag, kind, created_at) index is complete.

use serde_json::{json, Map, Value};
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{to_hex, PackedEventBuilder, PackedEventTagBuilder};
use wok_query::{DbScan, NostrFilterGroup, ScanPlan};

fn keys(n: usize, salt: u8) -> Vec<String> {
    (0..n).map(|i| format!("{salt:02x}{i:062x}")).collect()
}

/// A database holding one event, whose (tag, kind, created_at) index is
/// complete or, as while the writer builds it, not.
fn open(tag_kind_index: bool) -> (TempDir, Env) {
    let dir = TempDir::new().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut tags = PackedEventTagBuilder::default();
    tags.add('p', &[3; 32]).unwrap();
    // An unsigned event; the write path does not check signatures.
    let packed = PackedEventBuilder::build(&[1; 32], &[2; 32], 1_700_000_000, 1, 0, &tags).unwrap();
    let json = json!({
        "id": to_hex(&[1; 32]),
        "pubkey": to_hex(&[2; 32]),
        "created_at": 1_700_000_000,
        "kind": 1,
        "tags": [["p", to_hex(&[3; 32])]],
        "content": "",
        "sig": "00".repeat(64),
    });
    let mut events = [EventToWrite::new(packed.into_bytes(), json.to_string())];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    if !tag_kind_index {
        wok_db::reset_tag_kind_index(&mut txn).unwrap();
    }
    txn.commit().unwrap();
    let complete = wok_db::tag_kind_index_complete_ro(&env.begin_ro().unwrap()).unwrap();
    assert_eq!(complete, tag_kind_index);
    (dir, env)
}

/// Every combination of the fields the planner looks at, at sizes on both
/// sides of the PubkeyKind and TagKind pair bounds.
fn filters() -> Vec<Value> {
    let ids = [None, Some(2)];
    let authors = [None, Some(1), Some(334), Some(2047)];
    let kinds: [Option<Vec<u64>>; 5] = [
        None,
        Some(vec![1]),
        Some(vec![1, 6, 7]),
        Some(vec![0, 3, 10002]),
        Some((1..=10).collect()),
    ];
    let tags: [&[(&str, usize)]; 5] = [
        &[],
        &[("#p", 1)],
        &[("#p", 100)],
        &[("#e", 99)],
        &[("#p", 3), ("#t", 2)],
    ];
    let and_tags = [false, true];
    let limits = [None, Some(0), Some(50), Some(900)];
    let mut out = Vec::new();
    for ids in ids {
        for authors in authors {
            for kinds in &kinds {
                for tags in tags {
                    for and_tag in and_tags {
                        for limit in limits {
                            let mut f = Map::new();
                            if let Some(n) = ids {
                                f.insert("ids".into(), json!(keys(n, 1)));
                            }
                            if let Some(n) = authors {
                                f.insert("authors".into(), json!(keys(n, 2)));
                            }
                            if let Some(kinds) = kinds {
                                f.insert("kinds".into(), json!(kinds));
                            }
                            for &(tag, n) in tags {
                                f.insert(tag.into(), json!(keys(n, 3)));
                            }
                            if and_tag {
                                f.insert("&t".into(), json!(["a", "b"]));
                            }
                            if let Some(limit) = limit {
                                f.insert("limit".into(), json!(limit));
                            }
                            out.push(Value::Object(f));
                        }
                    }
                }
            }
        }
    }
    out
}

#[test]
fn scan_plans_name_the_plan_and_count_the_cursors_the_scan_opens() {
    let envs = [open(false), open(true)];
    let mut seen = std::collections::BTreeSet::new();
    for filter in filters() {
        let group = NostrFilterGroup::from_value(&filter, u64::MAX, 8, 16).unwrap();
        let f = &group.filters[0];
        for (tag_kind_index, (_, env)) in [false, true].into_iter().zip(&envs) {
            // One event never triggers the author probe, so the scan keeps
            // the plan it was given.
            let scan = DbScan::new(f, &env.begin_ro().unwrap());
            let plan = ScanPlan::choose(f, || tag_kind_index);
            assert_eq!(plan.name(), scan.desc, "{filter}, {tag_kind_index}");
            assert_eq!(plan.cursors(f), scan.cursor_count(), "{filter}");
            if f.limit != 0 {
                seen.insert(plan.name());
            }
        }
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "CreatedAt",
            "ID",
            "Kind",
            "Pubkey",
            "PubkeyKind",
            "Tag",
            "TagKind"
        ]
    );
}
