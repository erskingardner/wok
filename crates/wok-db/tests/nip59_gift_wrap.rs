use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{
    lookup_event_by_id_ro, write_events, Env, EnvOptions, EventToWrite, EventWriteStatus,
    NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits};

fn signed(
    key: &Keypair,
    kind: u64,
    created_at: u64,
    tags: serde_json::Value,
) -> ([u8; 32], EventToWrite) {
    let (pubkey, _) = key.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": "gift",
        "pubkey": hex::encode(pubkey.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr(&id, key);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    (
        id,
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json),
    )
}

fn write(env: &Env, event: &mut EventToWrite) {
    let mut txn = env.begin_rw().unwrap();
    write_events(
        &mut txn,
        &mut NoopNegentropy,
        std::slice::from_mut(event),
        false,
    )
    .unwrap();
    txn.commit().unwrap();
}

#[test]
fn recipient_can_delete_gift_wrap_and_prevent_rebroadcast() {
    let dir = TempDir::new().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut rng = rand::thread_rng();
    let sender = Keypair::new(SECP256K1, &mut rng);
    let recipient = Keypair::new(SECP256K1, &mut rng);
    let (recipient_pubkey, _) = recipient.x_only_public_key();

    let (gift_id, mut gift) = signed(
        &sender,
        1059,
        1_700_000_000,
        json!([["p", hex::encode(recipient_pubkey.serialize())]]),
    );
    write(&env, &mut gift);
    assert_eq!(gift.status, EventWriteStatus::Written);

    let (_, mut deletion) = signed(
        &recipient,
        5,
        1_700_000_001,
        json!([["e", hex::encode(gift_id)]]),
    );
    write(&env, &mut deletion);
    assert_eq!(deletion.status, EventWriteStatus::Written);
    assert!(lookup_event_by_id_ro(&env.begin_ro().unwrap(), &gift_id)
        .unwrap()
        .is_none());

    let (_, mut rebroadcast) = signed(
        &sender,
        1059,
        1_700_000_000,
        json!([["p", hex::encode(recipient_pubkey.serialize())]]),
    );
    write(&env, &mut rebroadcast);
    assert_eq!(rebroadcast.status, EventWriteStatus::Deleted);
}
