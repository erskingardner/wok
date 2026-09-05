//! Regression fixtures for publication ownership through sorting and aborts.
use super::*;
use wok_db::EnvOptions;
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

#[test]
fn review_writer_acknowledges_each_event_to_its_publisher() {
    check_routing(0, 0, true, true);
}
#[test]
fn mixed_outcomes_remain_with_their_publishers() {
    check_routing(1, 0, false, true);
}
#[test]
fn transaction_abort_receipts_remain_with_their_publishers() {
    check_routing(0, 1, false, false);
}
fn check_routing(author_quota: u64, global_quota: u64, first_ok: bool, second_ok: bool) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut cfg = Config::default();
    cfg.db_min_free_disk_bytes = 0;
    cfg.relay.abuse.max_stored_events_per_pubkey = author_quota;
    cfg.relay.abuse.max_stored_events = global_quota;
    let conns = Arc::new(ConnTable::new());
    let metrics = Arc::new(Metrics::default());
    let moderation = Arc::new(parking_lot::RwLock::new(
        load_moderation_snapshot_ro(&env.begin_ro().unwrap()).unwrap(),
    ));
    let (out1, mut rx1) = tokio::sync::mpsc::unbounded_channel();
    let (out2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
    conns.insert(1, Outbound::new(out1, 0));
    conns.insert(2, Outbound::new(out2, 0));
    let (tx, rx) = bounded(4);
    for (conn_id, timestamp) in [(1, 200), (2, 100)] {
        let id = [conn_id as u8; 32];
        let packed = PackedEventBuilder::build(
            &id,
            &[7; 32],
            timestamp,
            1,
            0,
            &PackedEventTagBuilder::default(),
        )
        .unwrap();
        tx.send(WriterMsg::AddEvent {
            conn_id,
            source: TransportSource::Unix,
            packed: packed.into_bytes(),
            json: json!({"id":hex::encode(id),"pubkey":hex::encode([7;32]),"created_at":timestamp,"kind":1,"tags":[],"content":"batch","sig":"00".repeat(64)}).to_string(),
            authed: None,
        }).unwrap();
    }
    drop(tx);
    run_writer(
        env,
        Arc::new(parking_lot::RwLock::new(cfg)),
        conns,
        metrics,
        rx,
        vec![],
        moderation,
    );
    let first: Value = serde_json::from_str(&rx1.try_recv().unwrap().into_text()).unwrap();
    let second: Value = serde_json::from_str(&rx2.try_recv().unwrap().into_text()).unwrap();
    assert_eq!(first[2], first_ok);
    assert_eq!(second[2], second_ok);
    assert_eq!(
        (first[1].clone(), second[1].clone()),
        (json!(hex::encode([1; 32])), json!(hex::encode([2; 32]))),
        "ACKs sent to the wrong publishers"
    );
}
