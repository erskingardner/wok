//! Copies of one event in one write batch, as two connections or a retrying
//! client send them. A later copy has the event only when the first copy was
//! stored or found stored; otherwise it shares the first copy's refusal.
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{
    lookup_event_by_id_ro, write::write_events_with_quota, Env, EnvOptions, EventToWrite,
    EventWriteStatus, NoopNegentropy, VanishPolicy,
};
use wok_event::{parse_and_verify_event, EventLimits};
use EventWriteStatus::{Deleted, Duplicate, QuotaExceeded, Replaced, Written};

struct Signed {
    id: [u8; 32],
    pubkey: [u8; 32],
    packed: Vec<u8>,
    json: String,
}

fn signed(key: &Keypair, kind: u64, created_at: u64, tags: Value) -> Signed {
    let (pubkey, _) = key.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": "batch-copies",
        "pubkey": hex::encode(pubkey.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr(&id, key);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    Signed {
        id,
        pubkey: pubkey.serialize(),
        packed: parsed.packed.into_bytes(),
        json: parsed.json,
    }
}

fn database() -> (TempDir, Env) {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    (directory, env)
}

fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

/// Writes `batch` in one transaction and returns each event's status in
/// the order given; the writer sorts the batch.
fn write(
    env: &Env,
    policy: &VanishPolicy,
    author_quota: u64,
    batch: &[&Signed],
) -> Vec<EventWriteStatus> {
    let mut events: Vec<_> = batch
        .iter()
        .enumerate()
        .map(|(order, event)| {
            EventToWrite::new(event.packed.clone(), event.json.clone()).with_context(order)
        })
        .collect();
    let mut txn = env.begin_rw().unwrap();
    write_events_with_quota(
        &mut txn,
        &mut NoopNegentropy,
        &mut events,
        policy,
        author_quota,
    )
    .unwrap();
    txn.commit().unwrap();
    events.sort_by_key(|event| event.context);
    events.iter().map(|event| event.status).collect()
}

fn stored(env: &Env, event: &Signed) -> bool {
    lookup_event_by_id_ro(&env.begin_ro().unwrap(), &event.id)
        .unwrap()
        .is_some()
}

fn author_count(env: &Env, pubkey: &[u8; 32]) -> u64 {
    let mut txn = env.begin_rw().unwrap();
    let count = wok_db::state::author_count(&mut txn, pubkey).unwrap();
    txn.abort();
    count
}

#[test]
fn copies_of_one_event_store_it_once() {
    let (_directory, env) = database();
    let none = VanishPolicy::disabled();
    let author = key();
    let note = signed(&author, 1, 100, json!([]));
    assert_eq!(
        write(&env, &none, 0, &[&note, &note, &note]),
        [Written, Duplicate, Duplicate]
    );
    // Copies of an event stored by an earlier batch.
    assert_eq!(write(&env, &none, 0, &[&note, &note]), [Duplicate; 2]);
    assert!(stored(&env, &note));
    assert_eq!(author_count(&env, &note.pubkey), 1);
}

#[test]
fn copies_of_a_superseded_replaceable_event_are_all_refused_and_use_no_quota() {
    let (_directory, env) = database();
    let none = VanishPolicy::disabled();
    let author = key();
    let newer = signed(&author, 10002, 200, json!([]));
    let stale = signed(&author, 10002, 100, json!([]));
    let note = signed(&author, 1, 300, json!([]));
    assert_eq!(write(&env, &none, 0, &[&newer]), [Written]);
    // Room for one more event: the refused copies take none of it.
    assert_eq!(
        write(&env, &none, 2, &[&stale, &stale, &note]),
        [Replaced, Replaced, Written]
    );
    assert!(!stored(&env, &stale));
    assert!(stored(&env, &newer));
    assert_eq!(author_count(&env, &newer.pubkey), 2);
}

#[test]
fn copies_from_an_author_at_quota_are_all_refused() {
    let (_directory, env) = database();
    let none = VanishPolicy::disabled();
    let author = key();
    let first = signed(&author, 1, 100, json!([]));
    let over = signed(&author, 1, 200, json!([]));
    assert_eq!(write(&env, &none, 1, &[&first]), [Written]);
    assert_eq!(write(&env, &none, 1, &[&over, &over]), [QuotaExceeded; 2]);
    assert!(!stored(&env, &over));
    assert_eq!(author_count(&env, &first.pubkey), 1);
}

#[test]
fn copies_of_a_deleted_event_are_all_refused() {
    let (_directory, env) = database();
    let none = VanishPolicy::disabled();
    let author = key();

    // A tombstone stored by an earlier batch.
    let gone = signed(&author, 1, 100, json!([]));
    let tombstone = signed(&author, 5, 150, json!([["e", hex::encode(gone.id)]]));
    assert_eq!(write(&env, &none, 0, &[&tombstone]), [Written]);
    assert_eq!(write(&env, &none, 0, &[&gone, &gone]), [Deleted; 2]);
    assert!(!stored(&env, &gone));

    // A tombstone written earlier in the same batch.
    let target = signed(&author, 1, 300, json!([]));
    let deletion = signed(&author, 5, 250, json!([["e", hex::encode(target.id)]]));
    assert_eq!(
        write(&env, &none, 0, &[&target, &deletion, &target]),
        [Deleted, Written, Deleted]
    );
    assert!(!stored(&env, &target));

    // A deletion later in the batch removes an event its first copy stored:
    // the later copy is answered like that copy, as separate batches would.
    let removed = signed(&author, 1, 400, json!([]));
    let deletion = signed(&author, 5, 450, json!([["e", hex::encode(removed.id)]]));
    assert_eq!(
        write(&env, &none, 0, &[&removed, &deletion, &removed]),
        [Written, Written, Duplicate]
    );
    assert!(!stored(&env, &removed));
}

#[test]
fn copies_from_a_vanished_author_are_all_refused() {
    let (_directory, env) = database();
    let policy = VanishPolicy {
        enabled: true,
        service_url: "wss://relay.example.com/".into(),
    };
    let author = key();
    let vanish = signed(&author, 62, 200, json!([["relay", "ALL_RELAYS"]]));
    assert_eq!(
        write(&env, &policy, 0, &[&vanish, &vanish]),
        [Written, Duplicate]
    );
    let old = signed(&author, 1, 100, json!([]));
    assert_eq!(write(&env, &policy, 0, &[&old, &old]), [Deleted; 2]);
    assert!(!stored(&env, &old));

    // A request for another relay is refused, every copy of it.
    let elsewhere = signed(
        &key(),
        62,
        200,
        json!([["relay", "wss://somewhere.example/"]]),
    );
    assert_eq!(
        write(&env, &policy, 0, &[&elsewhere, &elsewhere]),
        [Deleted; 2]
    );
    assert!(!stored(&env, &elsewhere));
}
