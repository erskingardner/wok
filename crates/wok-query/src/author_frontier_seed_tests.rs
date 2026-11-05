//! Focused guards for the distinct same-v3 external consumer.

use super::*;
use crate::scan::author_head_scan::InitializationStats;
use wok_db::{AuthorHead, AuthorPosition};

fn metadata(feeds: &[Value]) -> Vec<u8> {
    let mut rows = vec![json!({"shape":"tag","filter":{"#t":["red"],"limit":50,"until":BASE+127}})];
    for value in feeds {
        rows.push(json!({"shape":"feed500","filter":value}));
        rows.push(json!({"shape":"author","filter":{"authors":[hex::encode(author(0))],"limit":50,"until":BASE+127}}));
    }
    wok_event::json::to_tao_string(&json!(rows)).into_bytes()
}

fn reopen_for_writes(path: &Path) -> Env {
    Env::open(
        path,
        EnvOptions {
            create_dir: false,
            create_dbis: false,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap()
}

#[test]
fn separate_parser_pairing_schema_and_readonly_closure_preserve_original_entry() {
    let Fixture {
        dir,
        env,
        events: _,
    } = store(dense_events(512, 4, false));
    drop(env);
    let filters = dir.path().join("same-v3-inputs.json");
    let bytes = metadata(&[feed(0..500, 50), feed(12..512, 50)]);
    std::fs::write(&filters, &bytes).unwrap();
    assert!(diagnose_author_frontiers(dir.path(), &filters, 0).is_err());
    assert!(diagnose_author_frontiers(dir.path(), &filters, 5).is_err());
    let report = diagnose_author_frontiers(dir.path(), &filters, 2).unwrap();
    assert_eq!(report["format"], "wok-author-frontier-query-diagnostic-v1");
    assert_eq!(report["status"], "passed");
    assert_eq!(report["database_closed"], true);
    assert_eq!(report["env_read_only"], true);
    assert_eq!(report["env_create_dir"], false);
    assert_eq!(report["env_create_dbis"], false);
    assert_eq!(report["filters_sha256"], digest(&bytes));
    assert_eq!(report["input_records"], 5);
    assert_eq!(report["selected_feed_records"], 2);
    assert_eq!(report["selected_original_input_indexes"], json!([1, 3]));
    assert_eq!(report["planned_pairs"], 4);
    assert_eq!(report["arm_query_attempts"], 8);
    assert_eq!(report["recorded_arm_results"], 8);
    assert_eq!(report["recorded_pairs"], 4);
    assert_eq!(report["completed_pairs"], 4);
    assert_eq!(report["strict_eligible_pairs"], 4);
    assert_eq!(report["experiment"]["batch_keys"], 32);
    assert_eq!(report["measurement_schema"]["wrapper_count"], 30);
    assert_eq!(report["measurement_schema"]["native_count"], 13);
    assert_eq!(report["execution_limits"]["time_budget_us"], 0);
    assert_eq!(report["execution_limits"]["max_slices"], 64);
    let rows = report["records"].as_array().unwrap();
    for pair in rows.chunks_exact(2) {
        let pass = pair[0]["pass"].as_u64().unwrap();
        assert_eq!(
            pair[0]["arm"],
            if pass % 2 == 1 {
                "author_frontier_reader"
            } else {
                "pubkey_control"
            }
        );
        assert_eq!(pair[0]["arm_ordinal"], 0);
        assert_eq!(pair[1]["arm_ordinal"], 1);
        assert_eq!(pair[0]["input_index"], pair[1]["input_index"]);
        assert_eq!(pair[0]["filter_sha256"], pair[1]["filter_sha256"]);
        assert_eq!(pair[0]["ordered_local_ids"], pair[1]["ordered_local_ids"]);
        for row in pair {
            assert_eq!(row["pair_equivalent"], true);
            assert_eq!(row["logical_work_equal"], true);
            assert_eq!(row["plan"]["desc"], "Pubkey");
            assert_eq!(row["plan"]["index_only"], true);
            assert_eq!(row["plan"]["cursors"], 500);
            assert_eq!(row["plan"]["initial_depth"], 1);
            assert_eq!(
                row["plan"]["initial_refill_depths_summary"],
                json!({"count":500,"min":2,"max":2})
            );
            assert!(row["plan"].get("refill_depths").is_none());
            assert!(row.get("diagnostic_closure_elapsed_us").is_none());
            assert_eq!(
                row["measurements"]["wrapper"].as_object().unwrap().len(),
                30
            );
            assert_eq!(row["measurements"]["native"].as_object().unwrap().len(), 13);
            let init = &row["author_frontier_initialization"];
            assert_eq!(init["header_keys_during_peek"], 0);
            assert_eq!(init["unclassified_issued_keys"], 0);
            if row["arm"] == "author_frontier_reader" {
                assert_eq!(init["issued_keys"], 500);
                assert_eq!(init["seeded_heads"], 500);
                assert_eq!(
                    row["measurements"]["wrapper"]["author_head_multiget_calls"],
                    16
                );
            } else {
                assert_eq!(init["issued_keys"], 0);
                assert_eq!(init["reader_enabled"], false);
            }
        }
    }
    // Opening a writer after the returned report exercises actual Env closure.
    drop(reopen_for_writes(dir.path()));
    let legacy = diagnose(dir.path(), &filters, 1).unwrap();
    assert_eq!(legacy["format"], "wok-feed-query-diagnostic-v1");
    assert!(legacy.get("measurement_schema").is_none());
    assert!(legacy["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["arm"] == "created_at_membership"));
    assert!(legacy["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r.get("author_frontier_initialization").is_none()
            && r.get("diagnostic_closure_elapsed_us").is_some()));
    // Metadata validation precedes any native open and does not silently select
    // malformed or absent feed cases. The original parser remains unchanged.
    std::fs::write(&filters, b"[]").unwrap();
    assert!(
        diagnose_author_frontiers(&dir.path().join("absent"), &filters, 1)
            .unwrap_err()
            .contains("records")
    );
    std::fs::write(
        &filters,
        wok_event::json::to_tao_string(&json!([{"shape":"feed500","filter":feed(0..499,50)}])),
    )
    .unwrap();
    assert!(diagnose_author_frontiers(dir.path(), &filters, 1)
        .unwrap_err()
        .contains("cardinality"));
}

#[test]
fn actual_initialization_outcomes_partition_issued_keys_across_process_slices() {
    let fixture = store(dense_events(128, 4, false));
    for (since, until, issued, seeds, missing, older, newer) in [
        (0, BASE + 127, 500, 128, 372, 0, 0),
        // A historical first batch switches the remaining ranges to ordinary
        // seeks; classify only the32 keys that were actually requested.
        (0, 0, 32, 0, 0, 0, 32),
        (BASE + 128, BASE + 20000, 500, 0, 372, 128, 0),
    ] {
        let mut value = feed(0..500, 50);
        value["since"] = json!(since);
        value["until"] = json!(until);
        let group = group(&value);
        let sample = read_arm(
            &fixture.env,
            &group,
            Arm::AuthorHeads,
            &QueryOptions {
                time_budget_us: 0,
                ..QueryOptions::default()
            },
        )
        .unwrap();
        let s = sample.author_frontier_initialization;
        assert!(sample.completed);
        assert_eq!(s.issued_keys, issued);
        assert_eq!(s.seeded_heads, seeds);
        assert_eq!(s.fallback_missing, missing);
        assert_eq!(s.fallback_below_since, older);
        assert_eq!(s.fallback_above_until, newer);
        assert_eq!(s.fallback_unsupported_timestamp, 0);
        assert_eq!(s.classified_keys(), issued);
        assert_eq!(s.header_keys_during_peek, 0);
        assert_eq!(s.issued_keys, sample.measurements.wrapper.author_head_keys);
    }
    // This real normal-query run spans several process slices. Summing the
    // whole scanner counter on every slice instead of its delta overcounts.
    let wide = store(dense_events(2048, 3, false));
    let sample = read_arm(
        &wide.env,
        &group(&feed(0..2047, 50)),
        Arm::AuthorHeads,
        &QueryOptions {
            time_budget_us: 0,
            ..QueryOptions::default()
        },
    )
    .unwrap();
    assert!(sample.completed && sample.slice_work.len() > 1);
    assert_eq!(sample.author_frontier_initialization.issued_keys, 2047);
    assert_eq!(
        sample.author_frontier_initialization.classified_keys(),
        2047
    );
    assert_eq!(sample.measurements.wrapper.author_head_keys, 2047);
    assert_eq!(
        sample
            .author_frontier_initialization
            .header_keys_during_peek,
        0
    );
    // Classify the inherited packed-time limitation independently. MAX/absent
    // until itself is not an unsupported timestamp; a supported head still seeds.
    let head = |time| {
        Some(AuthorHead {
            first: AuthorPosition {
                created_at: time,
                local_id: 1,
            },
            next: None,
        })
    };
    let mut stats = InitializationStats::default();
    stats.observe(None, 0, u64::MAX);
    stats.observe(head(0x100_00000000), 0, u64::MAX);
    stats.observe(head(9), 10, u64::MAX);
    stats.observe(head(11), 0, 10);
    stats.observe(head(11), 0, u64::MAX);
    assert_eq!(stats.classified_keys(), 5);
    assert_eq!(
        (
            stats.fallback_missing,
            stats.fallback_unsupported_timestamp,
            stats.fallback_below_since,
            stats.fallback_above_until,
            stats.seeded_heads
        ),
        (1, 1, 1, 1, 1)
    );
    let before = InitializationStats {
        issued_keys: 32,
        seeded_heads: 32,
        ..InitializationStats::default()
    };
    let after = InitializationStats {
        issued_keys: 64,
        seeded_heads: 63,
        fallback_missing: 1,
        ..InitializationStats::default()
    };
    let mut total = InitializationStats::default();
    total.add_delta(before, InitializationStats::default(), false);
    total.add_delta(after, before, false);
    assert_eq!(total, after);
    let peek_after = InitializationStats {
        issued_keys: 65,
        fallback_missing: 2,
        ..after
    };
    total.add_delta(peek_after, after, true);
    assert_eq!(total.header_keys_during_peek, 1); // proves the guard would observe an accidental future peek lookup
}

#[test]
fn limited_samples_are_retained_and_never_strictly_eligible() {
    let Fixture {
        dir,
        env,
        events: _,
    } = store(
        (0..3000)
            .map(|n| event(n + 1, n % 500, BASE + n / 500, 22242, 0))
            .collect(),
    );
    drop(env);
    let filters = dir.path().join("limited.json");
    std::fs::write(&filters, metadata(&[feed(0..500, 50)])).unwrap();
    let report = diagnose_comparison(
        dir.path(),
        &filters,
        1,
        &QueryOptions {
            time_budget_us: 0,
            max_slices: 1,
            ..QueryOptions::default()
        },
        DiagnosticComparison::AuthorFrontiers,
    )
    .unwrap();
    assert_eq!(report["status"], "processing_limit");
    assert_eq!(report["all_pairs_equivalent"], false);
    assert_eq!(report["recorded_arm_results"], 2);
    assert_eq!(report["recorded_pairs"], 1);
    assert_eq!(report["completed_pairs"], 0);
    assert_eq!(report["strict_eligible_pairs"], 0);
    assert_eq!(
        report["processing_limited_pairs"].as_array().unwrap().len(),
        1
    );
    for row in report["records"].as_array().unwrap() {
        assert_eq!(row["completed"], false);
        assert_eq!(row["completeness_final"], false);
        assert_eq!(row["pair_equivalent"], false);
        assert_eq!(row["slice_work"].as_array().unwrap().len(), 1);
        assert!(row["chronological_work"].as_u64().unwrap() > 2000);
        assert!(row["ordered_local_ids"].is_array());
        assert!(row["measurements"]["wrapper"].is_object());
    }
    drop(reopen_for_writes(dir.path()));
}

#[test]
fn failed_payload_equal_components_still_retain_both_ineligible_samples() {
    let Fixture {
        dir,
        env,
        events: _,
    } = store((0..50).map(|n| event(n + 1, n, BASE + n, 1, 0)).collect());
    let group = group(&feed(0..500, 50));
    let id = read_arm(&env, &group, Arm::Pubkey, &QueryOptions::default())
        .unwrap()
        .delivery
        .ids[0];
    let mut tx = env.begin_rw().unwrap();
    tx.put_u64(env.dbis().event_payload, id, &[0xFF], 0)
        .unwrap();
    tx.commit().unwrap();
    drop(env);
    let filters = dir.path().join("payload-error.json");
    std::fs::write(&filters, metadata(&[feed(0..500, 50)])).unwrap();
    let report = diagnose_author_frontiers(dir.path(), &filters, 1).unwrap();
    assert_eq!(report["status"], "payload_error");
    assert_eq!(report["all_pairs_equivalent"], false);
    assert_eq!(report["recorded_arm_results"], 2);
    assert_eq!(report["completed_pairs"], 1);
    assert_eq!(report["strict_eligible_pairs"], 0);
    assert_eq!(report["different_pairs"].as_array().unwrap().len(), 1);
    let rows = report["records"].as_array().unwrap();
    assert_eq!(rows[0]["ordered_local_ids"], rows[1]["ordered_local_ids"]);
    for row in rows {
        assert_eq!(row["completed"], true);
        assert_eq!(row["payload_failed"], true);
        assert_eq!(row["delivery_equal"], true);
        assert_eq!(row["completeness_equal"], true);
        assert_eq!(row["pair_equivalent"], false);
        assert_eq!(row["completeness"]["finish"], false);
        assert_eq!(row["completeness"]["more"], false);
        assert!(row["packed_sha256"].is_string());
        assert!(row["payload_sha256"].is_string());
        assert!(row["body_sha256"].is_string());
    }
    drop(reopen_for_writes(dir.path()));
}
