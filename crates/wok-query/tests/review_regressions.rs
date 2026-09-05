use serde_json::json;
use wok_db::{Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};
use wok_query::{DbQuery, NostrFilterGroup, SubId, Subscription};

#[test]
fn review_nonmatching_search_respects_timeslice() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = Vec::new();
    for i in 1u64..=4096 {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&i.to_be_bytes());
        let packed =
            PackedEventBuilder::build(&id, &[7; 32], i, 1, 0, &PackedEventTagBuilder::default())
                .unwrap();
        events.push(EventToWrite::new(
            packed.into_bytes(),
            json!({"content":"common"}).to_string(),
        ));
    }
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    for (kind, expected_complete) in [(1, false), (2, false)] {
        let group = NostrFilterGroup::from_value(
            &json!({"search":"common", "kinds":[kind], "limit":1}),
            500,
            3,
            16,
        )
        .unwrap();
        let sub = Subscription::new(1, SubId::new("slice").unwrap(), group, false);
        let mut query = DbQuery::new(sub, 2000, 0);
        let complete = query.process(&txn, |_, _| {}, 0).unwrap();
        assert_eq!(
            complete, expected_complete,
            "kind {kind}: a zero-budget scan should yield before exhausting 4096 postings"
        );
    }
}

/// Work-count regression for the bounded author/tag planner.
#[test]
fn broad_tag_uses_selective_author_without_skipping_filter_checks() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = Vec::new();
    for i in 1u64..=10_000 {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&i.to_be_bytes());
        let mut author = [0; 32];
        author[..8].copy_from_slice(&(i % 1000).to_be_bytes());
        let mut tags = PackedEventTagBuilder::default();
        tags.add('t', if i == 1000 { b"other" } else { b"common" })
            .unwrap();
        let packed = PackedEventBuilder::build(&id, &author, i, 1, 0, &tags).unwrap();
        events.push(EventToWrite::new(
            packed.into_bytes(),
            json!({"content":""}).to_string(),
        ));
    }
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    let full = NostrFilterGroup::from_value(
        &json!({"authors":[hex::encode([0;32])],"#t":["common"]}),
        20_000,
        3,
        16,
    )
    .unwrap();
    let mut author =
        NostrFilterGroup::from_value(&json!({"authors":[hex::encode([0;32])]}), 20_000, 3, 16)
            .unwrap();
    author.filters[0].index_only_scans = false;
    let mut expected = None;
    for (label, plan) in [
        ("current tag seed", &full.filters[0]),
        ("author seed control", &author.filters[0]),
    ] {
        let start = std::time::Instant::now();
        let mut scan = wok_query::DbScan::new(plan, &txn);
        let mut ids = Vec::new();
        assert!(scan
            .scan(
                &txn,
                &full.filters[0],
                |id| {
                    ids.push(id);
                    false
                },
                |_| false
            )
            .unwrap());
        ids.sort_unstable();
        eprintln!(
            "{label}: {} work units, {} us, {} results",
            scan.approx_work,
            start.elapsed().as_micros(),
            ids.len()
        );
        assert_eq!(ids.len(), 9);
        assert!(scan.approx_work < 500);
        if let Some(want) = &expected {
            assert_eq!(&ids, want);
        } else {
            expected = Some(ids);
        }
    }
}
