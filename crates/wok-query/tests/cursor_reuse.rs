//! Physical cursor reuse must preserve logical range initialization and refill
//! positions when a multi-author scan yields between candidates and slices.
use serde_json::json;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder, PackedEventView};
use wok_query::{DbScan, NostrFilterGroup};

fn author(n: u64) -> [u8; 32] {
    let mut author = [0; 32];
    author[..8].copy_from_slice(&n.to_be_bytes());
    author
}

fn event(n: u64, who: u64, created: u64) -> EventToWrite {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let packed = PackedEventBuilder::build(
        &id,
        &author(who),
        created,
        1,
        0,
        &PackedEventTagBuilder::default(),
    )
    .unwrap();
    EventToWrite::new(packed.into_bytes(), json!({"content": ""}).to_string())
}

#[test]
fn feed_resumes_across_empty_authors_ties_refills_and_a_later_commit() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let base = 1_700_000_000;
    let mut events = Vec::new();
    for who in 0..500 {
        if who != 0 && who % 5 == 0 {
            continue;
        }
        for depth in 0..if who == 0 { 80 } else { 3 } {
            let created = base
                + if who == 0 {
                    1000 + depth
                } else {
                    100 + who % 7 + depth / 2
                };
            events.push(event(who * 1000 + depth + 1, who, created));
        }
    }
    let mut tx = env.begin_rw().unwrap();
    write_events(&mut tx, &mut NoopNegentropy, &mut events, false).unwrap();
    tx.commit().unwrap();
    let mut expected: Vec<_> = events
        .iter()
        .filter_map(|e| {
            let created = PackedEventView::new(&e.packed).unwrap().created_at();
            (created >= base + 102 && created <= base + 1059).then_some((created, e.lev_id))
        })
        .collect();
    expected.sort_unstable_by(|a, b| b.cmp(a));
    let expected: Vec<_> = expected.into_iter().take(100).map(|(_, id)| id).collect();
    let group = NostrFilterGroup::from_value(
        &json!({"authors": (0..500).map(|n| hex::encode(author(n))).collect::<Vec<_>>(),
            "since": base + 102, "until": base + 1059, "limit": 50}),
        1000,
        8,
        16,
    )
    .unwrap();
    let filter = &group.filters[0];
    let old = env.begin_ro().unwrap();
    let mut scan = DbScan::new(filter, &old);
    assert_eq!(scan.cursor_count(), 500);
    let mut seen = Vec::new();
    let mut calls = 0;
    // Each handler stop leaves a candidate unsettled. Small work slices also
    // interrupt initialization before all 500 logical cursors have been read.
    while seen.len() < 100 {
        let start_work = scan.approx_work;
        scan.scan(
            &old,
            filter,
            |id| {
                seen.push(id);
                true
            },
            |work| work.saturating_sub(start_work) >= 17,
        )
        .unwrap();
        calls += 1;
        if calls == 1 {
            // New physical iterators in later slices must still use the old
            // snapshot, including for an event at the query's upper boundary.
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut new = [event(999_999, 0, base + 1059)];
                        let mut tx = env.begin_rw().unwrap();
                        write_events(&mut tx, &mut NoopNegentropy, &mut new, false).unwrap();
                        tx.commit().unwrap();
                    })
                    .join()
                    .unwrap();
            });
        }
        assert!(calls < 10_000, "scan stopped making progress");
    }
    assert!(calls > seen.len(), "initialization never yielded");
    assert_eq!(seen, expected);
}
