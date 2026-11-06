//! Equal completed delivery does not imply equal bounded completeness evidence.

use super::*;

const GAP_ROWS: u64 = 512;
const DELIVERED: u64 = 50;
const TOP_TIME: u64 = BASE + 20_000;
const WITNESS_TIME: u64 = BASE + 18_000;

fn completeness_gap_fixture() -> Fixture {
    // Author zero is the first selected key; every other selected author is
    // absent. Chronology, rather than allocation/local-ID order, defines the
    // fifty delivered rows and the older fifty-first selected witness.
    let mut events = (0..DELIVERED)
        .map(|n| event(n + 1, 0, TOP_TIME, 1, 0))
        .collect::<Vec<_>>();
    events.extend((0..GAP_ROWS).map(|n| event(1_000 + n, 10_000 + n, BASE + 19_000, 1, 0)));
    events.push(event(100_000, 0, WITNESS_TIME, 1, 0));
    store(events)
}

fn assert_truthful_control(
    fixture: &Fixture,
    author_count: u64,
    options: &QueryOptions,
    control: &Sample,
) {
    let with_witness = group(&feed(0..author_count, DELIVERED + 1));
    let all_selected = expected(fixture, &with_witness, options);
    assert_eq!(all_selected.len(), 51);
    assert_eq!(control.delivery.ids, all_selected[..50]);
    assert!(!control.delivery.ids.contains(&all_selected[50]));
    assert_eq!(control.delivery.sent_count, DELIVERED);
    assert!(control.completed && !control.delivery.payload_failed);
    assert!(control.completeness.more);
    assert!(!control.completeness.finish && !control.completeness.restricted);
}

fn assert_unknown(candidate: &Sample) {
    assert!(candidate.completed && !candidate.delivery.payload_failed);
    assert_eq!(candidate.completeness, Completeness::default());
    // The ordinary peek budget remains unchanged and is entirely consumed.
    assert_eq!(candidate.peek_work, PEEK_WORK);
}

fn assert_author_suffix_starts_after_delivery(candidate: &Sample) {
    let stats = candidate.bounded.unwrap();
    assert!(stats.configured && stats.author_suffix && !stats.exhausted);
    assert_eq!(stats.raw_visits, DELIVERED);
    assert_eq!(stats.handled_rows, DELIVERED);
    assert_eq!(stats.primary_reads, DELIVERED);
    assert_eq!(stats.matched_rows, DELIVERED);
    assert_eq!(
        stats.suffix_fence,
        Some(Fence {
            time: TOP_TIME,
            id: *candidate.delivery.ids.last().unwrap(),
        })
    );
}

fn global_gap_counterexample(author_count: u64) {
    let fixture = completeness_gap_fixture();
    let filters = group(&feed(0..author_count, DELIVERED));
    for time_budget_us in [u64::MAX, 0] {
        let options = QueryOptions {
            time_budget_us,
            ..QueryOptions::default()
        };
        let (control, candidate) =
            bounded_pair(&fixture, &filters, &options, Arm::BoundedGlobalPeek);
        assert_truthful_control(&fixture, author_count, &options, &control);
        assert_unknown(&candidate);
        assert!(!strict_equal(&control, &candidate));
        let stats = candidate.bounded.unwrap();
        assert!(stats.configured && !stats.author_suffix && !stats.exhausted);
        assert!(stats.raw_visits > DELIVERED && stats.raw_visits < RAW_CAP);
        assert!(stats.handled_rows > DELIVERED);
        assert_eq!(stats.primary_reads, stats.handled_rows);
        assert_eq!(stats.matched_rows, DELIVERED);
        evidence(
            &format!("global_gap_{author_count}_authors_budget_{time_budget_us}"),
            "global_until_cap",
            &control,
            &candidate,
        );
    }
}

#[test]
fn global_gap_500_authors_preserves_delivery_but_loses_more_hint() {
    global_gap_counterexample(500);
}

#[test]
fn global_gap_2047_authors_preserves_delivery_but_loses_more_hint() {
    global_gap_counterexample(2047);
}

#[test]
fn author_peek_500_can_recover_the_same_more_witness_within_ordinary_budget() {
    let fixture = completeness_gap_fixture();
    let filters = group(&feed(0..500, DELIVERED));
    for time_budget_us in [u64::MAX, 0] {
        let options = QueryOptions {
            time_budget_us,
            ..QueryOptions::default()
        };
        let (control, candidate) =
            bounded_pair(&fixture, &filters, &options, Arm::BoundedAuthorPeek);
        assert_truthful_control(&fixture, 500, &options, &control);
        assert_author_suffix_starts_after_delivery(&candidate);
        assert_eq!(candidate.completeness, control.completeness);
        assert!(strict_equal(&control, &candidate));
        assert!(candidate.peek_work > 0 && candidate.peek_work < PEEK_WORK);
        evidence(
            &format!("author_peek_gap_500_authors_budget_{time_budget_us}"),
            "author_on_peek",
            &control,
            &candidate,
        );
    }
}

#[test]
fn author_peek_2047_reinitialization_loses_hint_despite_equal_completed_delivery() {
    let fixture = completeness_gap_fixture();
    let filters = group(&feed(0..2047, DELIVERED));
    for time_budget_us in [u64::MAX, 0] {
        let options = QueryOptions {
            time_budget_us,
            ..QueryOptions::default()
        };
        let (control, candidate) =
            bounded_pair(&fixture, &filters, &options, Arm::BoundedAuthorPeek);
        assert_truthful_control(&fixture, 2047, &options, &control);
        assert_author_suffix_starts_after_delivery(&candidate);
        assert_unknown(&candidate);
        assert!(!strict_equal(&control, &candidate));
        evidence(
            &format!("author_peek_gap_2047_authors_budget_{time_budget_us}"),
            "author_on_peek",
            &control,
            &candidate,
        );
    }
}
