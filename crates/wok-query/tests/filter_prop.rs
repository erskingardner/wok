use proptest::prelude::*;
use serde_json::json;
use wok_event::{PackedEventBuilder, PackedEventTagBuilder, PackedEventView};
use wok_query::{dumb_match, NostrFilter};

fn tag_value(value: u8) -> String {
    format!("v{value}")
}

fn packed_tags(values: &[u8]) -> wok_event::PackedEvent {
    let mut tags = PackedEventTagBuilder::default();
    for value in values {
        tags.add('t', tag_value(*value).as_bytes()).unwrap();
    }
    PackedEventBuilder::build(&[1; 32], &[2; 32], 50, 1, 0, &tags).unwrap()
}

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
        }), 500, 3, 16).unwrap();
        let a = f.does_match(ev.view());
        let b = naive_match(&f, ev.view());
        let c = dumb_match(&f, ev.view());
        prop_assert_eq!(a, b);
        prop_assert_eq!(a, c);
    }


    #[test]
    fn nip91_matcher_agrees_with_wire_semantics(
        event_values in prop::collection::vec(0u8..6, 0..8),
        and_values in prop::collection::vec(0u8..6, 1..6),
        or_values in prop::collection::vec(0u8..6, 0..6),
    ) {
        let event = packed_tags(&event_values);
        let and_json: Vec<_> = and_values.iter().copied().map(tag_value).collect();
        let or_json: Vec<_> = and_values
            .iter()
            .chain(or_values.iter())
            .copied()
            .map(tag_value)
            .collect();
        let filter = NostrFilter::parse(
            &json!({"&t":and_json, "#t":or_json}),
            500,
            3,
            16,
        )
        .unwrap();

        let required: std::collections::HashSet<_> = and_values.iter().copied().collect();
        let alternatives: std::collections::HashSet<_> = or_values
            .iter()
            .copied()
            .filter(|value| !required.contains(value))
            .collect();
        let present: std::collections::HashSet<_> = event_values.iter().copied().collect();
        let expected = required.iter().all(|value| present.contains(value))
            && (alternatives.is_empty()
                || alternatives.iter().any(|value| present.contains(value)));
        prop_assert_eq!(filter.does_match(event.view()), expected);
    }
}
