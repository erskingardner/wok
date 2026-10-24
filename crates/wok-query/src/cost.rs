//! The query-cost gate's estimate, made before any cursor opens.
//!
//! The unit is index entries touched. A filter costs the cursors its plan
//! opens (the plan [`DbScan`](crate::DbScan) picks, see [`ScanPlan`]), plus,
//! for a REQ, the rows its `limit` lets it return. Selectivity depends on
//! the database and is not seen: a filter whose plan reads many entries per
//! match, such as `#t` with `authors`, costs what its cursors and `limit`
//! say. Tracking issue #97 §3.4 sets out the model.

use crate::filter::{FilterSetBytes, NostrFilter, NostrFilterGroup};
use crate::scan::ScanPlan;

/// Flat price of a NIP-50 search filter, which reads term postings rather
/// than a chronological index.
const SEARCH_COST: u64 = 1_000;

/// The kind of request [`NostrFilterGroup::estimated_cost`] prices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostedRequest {
    /// A REQ. Its rows are bounded before the scan: each filter's `limit`
    /// is clamped to `max_filter_limit` when it is parsed, and the
    /// request's are capped at `max_total_events` (zero is unlimited).
    Req { max_total_events: u64 },
    /// A COUNT, priced at twice its seeks. Its rows are bounded only while
    /// it runs, by `max_filter_limit_count` and the COUNT budget.
    Count,
    /// A NEG-OPEN, priced at its seeks. It is refused before its scan is
    /// scheduled when its view would not fit the sync memory budgets, and
    /// its scan stops past `max_sync_events`. Not priced by rows on purpose:
    /// a sync is meant to move many events, up to all a relay holds (#173).
    NegOpen,
}

impl NostrFilterGroup {
    /// The index entries `request` would touch with these filters.
    /// `tag_kind_index` says whether the (tag, kind, created_at) index is
    /// complete, so one tag with `kinds` plans on it.
    pub fn estimated_cost(&self, request: CostedRequest, tag_kind_index: bool) -> u64 {
        let mut seeks = 0u64;
        let mut rows = 0u64;
        let mut and_checks = 0u64;
        for filter in &self.filters {
            seeks = seeks.saturating_add(filter_seeks(filter, tag_kind_index));
            let filter_rows = match &filter.ids {
                Some(ids) => filter.limit.min(ids.size() as u64),
                None => filter.limit,
            };
            rows = rows.saturating_add(filter_rows);
            // Each candidate is checked for every NIP-91 `&` value.
            let and_values: usize = filter.and_tags.values().map(FilterSetBytes::size).sum();
            and_checks = and_checks.saturating_add(filter_rows.saturating_mul(and_values as u64));
        }
        match request {
            CostedRequest::Req { max_total_events } => {
                if max_total_events != 0 {
                    rows = rows.min(max_total_events);
                }
                seeks.saturating_add(rows).saturating_add(and_checks)
            }
            CostedRequest::Count => seeks.saturating_mul(2),
            CostedRequest::NegOpen => seeks,
        }
    }
}

/// The cursors a filter's scan opens, or [`SEARCH_COST`] for a search.
fn filter_seeks(filter: &NostrFilter, tag_kind_index: bool) -> u64 {
    if filter.search.is_some() {
        return SEARCH_COST;
    }
    let plan = ScanPlan::choose(filter, || tag_kind_index);
    let cursors = plan.cursors(filter) as u64;
    match (plan, &filter.authors, &filter.kinds) {
        // Past the PubkeyKind cap of pairs the Pubkey plan reads the authors'
        // events until it finds the kinds, so it costs at least the
        // (author, kind) pairs it declined to seek, and their whole history
        // for kinds they rarely publish (C6).
        (ScanPlan::Pubkey, Some(authors), Some(kinds)) if cursors != 0 => {
            (authors.size() as u64).saturating_mul(kinds.size() as u64)
        }
        _ => cursors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// The public preset's `max_filter_limit`, `max_total_events_per_req`
    /// and `max_query_work`.
    const MAX_FILTER_LIMIT: u64 = 2_000;
    const MAX_TOTAL_EVENTS: u64 = 10_000;
    const MAX_QUERY_COST: u64 = 20_000;
    /// The limits COUNT and NEG-OPEN filters are parsed with: one past
    /// `max_filter_limit_count` and `max_sync_events`.
    const COUNT_LIMIT: u64 = 1_000_001;
    const SYNC_LIMIT: u64 = 1_000_001;

    const REQ: CostedRequest = CostedRequest::Req {
        max_total_events: MAX_TOTAL_EVENTS,
    };

    fn keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{i:064x}")).collect()
    }

    fn group(filters: &[Value], max_filter_limit: u64) -> NostrFilterGroup {
        NostrFilterGroup::from_value(&json!(filters), max_filter_limit, 8, 16).unwrap()
    }

    /// Tracking issue #97 §3.4's table. Every filter in it costs the same
    /// whether or not the (tag, kind, created_at) index is complete.
    #[test]
    fn the_cost_table_prices_planner_work_and_limit() {
        let eleven_kinds = [1, 6, 7, 9735, 30023, 1063, 20, 21, 22, 1111, 9802];
        let fifty_kinds: Vec<u64> = (1..=50).collect();
        let gid = "ab".repeat(32);
        let reactions: Vec<Value> = keys(45)
            .into_iter()
            .map(|id| json!({"#e": [id], "kinds": [7]}))
            .collect();
        let fan_out = json!({"authors": keys(2000), "kinds": fifty_kinds});
        let since = 1_700_000_000;
        let table: Vec<(&str, CostedRequest, Vec<Value>, u64)> = vec![
            (
                "authors[150], limit 20",
                REQ,
                vec![json!({"authors": keys(150), "limit": 20})],
                170,
            ),
            (
                "11-kind global feed, limit 50",
                REQ,
                vec![json!({"kinds": eleven_kinds, "limit": 50})],
                61,
            ),
            ("45 reaction filters, no limit", REQ, reactions, 10_045),
            (
                "outbox metadata: authors[1000] x kinds[0,3,10002,10050]",
                REQ,
                vec![json!({"authors": keys(1000), "kinds": [0, 3, 10002, 10050]})],
                6_000,
            ),
            (
                "MDK directory: authors[200] x 6 kinds, limit 1200",
                REQ,
                vec![json!({
                    "authors": keys(200),
                    "kinds": [0, 3, 10002, 10050, 10051, 30443],
                    "limit": 1200,
                })],
                2_400,
            ),
            (
                "MDK group: kinds[445], #h, since",
                REQ,
                vec![json!({"kinds": [445], "#h": [gid], "since": since})],
                2_001,
            ),
            ("{}, no limit", REQ, vec![json!({})], 2_001),
            (
                "authors[2000] x 50 kinds",
                REQ,
                vec![fan_out.clone()],
                102_000,
            ),
            (
                "#t with one author",
                REQ,
                vec![json!({"#t": ["nostr"], "authors": keys(1)})],
                2_001,
            ),
            (
                "COUNT follower count",
                CostedRequest::Count,
                vec![json!({"kinds": [3], "#p": keys(1)})],
                2,
            ),
            (
                "COUNT kinds[1]",
                CostedRequest::Count,
                vec![json!({"kinds": [1]})],
                2,
            ),
            (
                "COUNT authors[2000] x 50 kinds",
                CostedRequest::Count,
                vec![fan_out],
                200_000,
            ),
            (
                "NEG-OPEN kinds[445], #h",
                CostedRequest::NegOpen,
                vec![json!({"kinds": [445], "#h": [gid]})],
                1,
            ),
        ];
        for (shape, request, filters, want) in table {
            let max_filter_limit = match request {
                CostedRequest::Req { .. } => MAX_FILTER_LIMIT,
                CostedRequest::Count => COUNT_LIMIT,
                CostedRequest::NegOpen => SYNC_LIMIT,
            };
            let fg = group(&filters, max_filter_limit);
            for tag_kind_index in [false, true] {
                assert_eq!(
                    fg.estimated_cost(request, tag_kind_index),
                    want,
                    "{shape}, tag_kind_index {tag_kind_index}"
                );
            }
            let refused = want > MAX_QUERY_COST;
            assert_eq!(refused, shape.contains("x 50 kinds"), "{shape}");
        }
    }

    #[test]
    fn a_plan_on_the_tag_kind_index_costs_its_pairs() {
        let notifications = group(
            &[json!({"#p": keys(1), "kinds": [1, 6, 7, 9735, 1111], "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(notifications.estimated_cost(REQ, false), 1 + 50);
        assert_eq!(notifications.estimated_cost(REQ, true), 5 + 50);
        assert_eq!(
            notifications.estimated_cost(CostedRequest::NegOpen, true),
            5
        );
        // Past 1000 pairs under a small limit, as up to it.
        let pictures = group(
            &[json!({"#p": keys(600), "kinds": [20, 21], "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(pictures.estimated_cost(REQ, false), 600 + 50);
        assert_eq!(pictures.estimated_cost(REQ, true), 1_200 + 50);
        // A second tag keeps the Tag plan, seeded from the smaller value set.
        let two_tags = group(
            &[json!({"#p": keys(3), "#t": ["a", "b"], "kinds": [1], "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(two_tags.estimated_cost(REQ, true), 2 + 50);
    }

    #[test]
    fn author_kind_pairs_cost_the_same_on_either_plan() {
        // PubkeyKind: a home feed and a picture feed of 600 follows.
        let feed = group(
            &[json!({"authors": keys(600), "kinds": [1, 6], "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(feed.estimated_cost(REQ, false), 1_200 + 50);
        let pictures = group(
            &[json!({"authors": keys(600), "kinds": [20, 21], "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(pictures.estimated_cost(REQ, false), 1_200 + 50);
        assert_eq!(pictures.estimated_cost(CostedRequest::Count, false), 2_400);
        // Pubkey: past the cap of pairs.
        let nine_kinds: Vec<u64> = (1..=9).collect();
        let fallback = group(
            &[json!({"authors": keys(2000), "kinds": nine_kinds, "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(fallback.estimated_cost(REQ, false), 18_000 + 50);
        let authors = group(
            &[json!({"authors": keys(334), "limit": 50})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(authors.estimated_cost(REQ, false), 334 + 50);
    }

    #[test]
    fn rows_count_limit_ids_and_the_request_cap() {
        let ids = group(&[json!({"ids": keys(64)})], MAX_FILTER_LIMIT);
        assert_eq!(ids.estimated_cost(REQ, false), 64 + 64);
        let fewer = group(&[json!({"ids": keys(64), "limit": 10})], MAX_FILTER_LIMIT);
        assert_eq!(fewer.estimated_cost(REQ, false), 64 + 10);
        // `max_filter_limit` clamps a larger limit when the filter is parsed.
        let clamped = group(
            &[json!({"kinds": [1], "limit": 1_000_000})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(clamped.estimated_cost(REQ, false), 1 + 2_000);
        // Rows across filters stop at the request-wide cap; zero is no cap.
        let feeds = group(&vec![json!({"kinds": [1]}); 6], MAX_FILTER_LIMIT);
        assert_eq!(feeds.estimated_cost(REQ, false), 6 + 10_000);
        let uncapped = CostedRequest::Req {
            max_total_events: 0,
        };
        assert_eq!(feeds.estimated_cost(uncapped, false), 6 + 12_000);
        // `limit: 0` reads no history.
        let none = group(
            &[json!({"authors": keys(2000), "limit": 0})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(none.estimated_cost(REQ, false), 0);
        assert_eq!(none.estimated_cost(CostedRequest::Count, false), 0);
    }

    /// A sync is meant to move many events, up to all a relay holds, so a
    /// broad NEG-OPEN costs only its seeks and is never refused for its rows
    /// (#173). `max_sync_events` and the sync memory budgets bound it.
    #[test]
    fn a_broad_sync_costs_only_its_seeks() {
        for filter in [
            json!({}),
            json!({"kinds": [1]}),
            json!({"since": 0, "limit": SYNC_LIMIT}),
        ] {
            let fg = group(std::slice::from_ref(&filter), SYNC_LIMIT);
            let cost = fg.estimated_cost(CostedRequest::NegOpen, false);
            assert_eq!(cost, 1, "{filter}");
        }
    }

    #[test]
    fn search_and_nip91_filters_add_their_checks() {
        let search = group(&[json!({"search": "nostr", "limit": 20})], MAX_FILTER_LIMIT);
        assert_eq!(search.estimated_cost(REQ, false), 1_000 + 20);
        assert_eq!(search.estimated_cost(CostedRequest::Count, false), 2_000);
        assert_eq!(search.estimated_cost(CostedRequest::NegOpen, false), 1_000);

        // A required tag seeds one cursor, and each candidate is checked for
        // every `&` value; only a REQ's rows are priced.
        let and = group(&[json!({"&t": ["a", "b"], "limit": 100})], MAX_FILTER_LIMIT);
        assert_eq!(and.estimated_cost(REQ, false), 1 + 100 + 2 * 100);
        assert_eq!(and.estimated_cost(CostedRequest::Count, false), 2);
        let id_and = group(
            &[json!({"ids": keys(1), "&t": ["a", "b"]})],
            MAX_FILTER_LIMIT,
        );
        assert_eq!(id_and.estimated_cost(REQ, false), 1 + 1 + 2);
        // The `&` checks are not capped with the rows.
        let ands = group(&vec![json!({"&t": ["a"]}); 6], MAX_FILTER_LIMIT);
        assert_eq!(ands.estimated_cost(REQ, false), 6 + 10_000 + 12_000);
    }
}
