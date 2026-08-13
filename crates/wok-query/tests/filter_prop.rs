use proptest::prelude::*;
use serde_json::json;
use wok_event::{PackedEventBuilder, PackedEventTagBuilder, PackedEventView};
use wok_query::{dumb_match, NostrFilter};

fn packed(
    id: u8,
    pk: u8,
    created: u64,
    kind: u64,
    tag: Option<(char, Vec<u8>)>,
) -> wok_event::PackedEvent {
    let mut tags = PackedEventTagBuilder::default();
    if let Some((n, v)) = tag {
        tags.add(n, &v).unwrap();
    }
    PackedEventBuilder::build(&[id; 32], &[pk; 32], created, kind, 0, &tags).unwrap()
}

/// Independent matcher used only by this property test.
fn naive_match(filter: &NostrFilter, ev: PackedEventView<'_>) -> bool {
    if ev.created_at() < filter.since || ev.created_at() > filter.until {
        return false;
    }
    if let Some(ids) = &filter.ids {
        if !(0..ids.size()).any(|i| ids.at(i) == ev.id()) {
            return false;
        }
    }
    if let Some(authors) = &filter.authors {
        if !(0..authors.size()).any(|i| authors.at(i) == ev.pubkey()) {
            return false;
        }
    }
    if let Some(kinds) = &filter.kinds {
        if !(0..kinds.size()).any(|i| kinds.at(i) == ev.kind()) {
            return false;
        }
    }
    for (name, set) in &filter.tags {
        let mut ok = false;
        ev.foreach_tag(|n, v| {
            if n == *name && (0..set.size()).any(|i| set.at(i) == v) {
                ok = true;
                return false;
            }
            true
        });
        if !ok {
            return false;
        }
    }
    true
}

proptest! {
    #[test]
    fn matcher_agrees_with_naive(
        id in 0u8..8,
        pk in 0u8..8,
        created in 0u64..100,
        kind in 0u64..8,
        since in 0u64..50,
        until in 50u64..100,
        filter_kind in 0u64..8,
    ) {
        let ev = packed(id, pk, created, kind, None);
        let f = NostrFilter::parse(&json!({
            "kinds": [filter_kind],
            "since": since,
            "until": until,
        }), 500, 3).unwrap();
        let a = f.does_match(ev.view());
        let b = naive_match(&f, ev.view());
        let c = dumb_match(&f, ev.view());
        prop_assert_eq!(a, b);
        prop_assert_eq!(a, c);
    }
}
