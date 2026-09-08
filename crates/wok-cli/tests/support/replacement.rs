use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::path::Path;
use wok_db::{Env, EnvOptions};

pub fn events(kind: u64) -> Vec<Value> {
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (0..3).map(|i| {
        let mut event = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),"kind":kind,"created_at":now-30+i,"tags":[["d","history"]],"content":format!("version {i}")});
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id,&key).as_ref()));
        event
    }).collect()
}

fn open(path: &Path) -> Env {
    let env = Env::open(
        path,
        EnvOptions {
            map_size: 67108864,
            ..Default::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    env
}

/// Coherent retained history, including search indexes and the physical tree.
pub fn seed(path: &Path, events: &[Value], version: u64) -> Env {
    let temp = tempfile::tempdir().unwrap();
    let source = open(temp.path());
    {
        let mut txn = source.begin_rw().unwrap();
        for (i, event) in events.iter().enumerate() {
            let parsed = wok_event::parse_and_verify_event(
                event,
                &wok_event::EventLimits::default(),
                None,
                true,
                false,
            )
            .unwrap();
            txn.put_u64(
                source.dbis().event,
                i as u64 + 1,
                &parsed.packed.into_bytes(),
                0,
            )
            .unwrap();
            txn.put_u64(
                source.dbis().event_payload,
                i as u64 + 1,
                &wok_db::encode_raw_payload(&parsed.json),
                0,
            )
            .unwrap();
        }
        txn.commit().unwrap();
    }
    let env = open(path);
    {
        let mut txn = env.begin_rw().unwrap();
        wok_db::rebuild_primary_and_event_indices(&source.begin_ro().unwrap(), &mut txn).unwrap();
        let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
        for event in events {
            tree.insert(
                event["created_at"].as_u64().unwrap(),
                &hex::decode(event["id"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        tree.backend.flush().unwrap();
        drop(tree);
        let mut meta =
            wok_db::decode_meta(txn.get_u64(env.dbis().meta, 1).unwrap().unwrap()).unwrap();
        meta.db_version = version;
        txn.put_u64(env.dbis().meta, 1, &wok_db::encode_meta(&meta), 0)
            .unwrap();
        txn.commit().unwrap();
    }
    env
}
