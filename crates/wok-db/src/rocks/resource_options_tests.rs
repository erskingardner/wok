use super::*;
use crate::{Decompressor, EventToWrite, NoopNegentropy};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::json;

fn small() -> RocksDbOptions {
    RocksDbOptions {
        block_cache_bytes: 16 << 20,
        row_cache_bytes: 0,
        total_memtable_bytes: 16 << 20,
        max_total_wal_bytes: 32 << 20,
    }
}

fn signed(offset: u64) -> EventToWrite {
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[29; 32]).unwrap());
    let mut event = json!({
        "pubkey":hex::encode(key.x_only_public_key().0.serialize()),
        "kind":1,"created_at":1_700_000_000+offset,
        "tags":[["t","resource-sizing"]],"content":"unchanged primary and payload",
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    let parsed = wok_event::parse_and_verify_event(
        &event,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

#[test]
fn invalid_resource_targets_cannot_create_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let bad = [
        RocksDbOptions {
            block_cache_bytes: 0,
            ..small()
        },
        RocksDbOptions {
            total_memtable_bytes: 0,
            ..small()
        },
        RocksDbOptions {
            max_total_wal_bytes: 0,
            ..small()
        },
        RocksDbOptions {
            row_cache_bytes: usize::MAX,
            ..small()
        },
    ];
    for (index, rocksdb) in bad.into_iter().enumerate() {
        let destination = dir.path().join(index.to_string());
        assert!(Env::open(
            &destination,
            EnvOptions {
                rocksdb,
                ..EnvOptions::for_tests()
            }
        )
        .is_err());
        assert!(!destination.exists());
    }
}

#[test]
fn sized_caches_preserve_snapshot_primary_bytes_and_reopen_audit() {
    let fixtures = [signed(0), signed(1)];
    let mut fingerprints = Vec::new();
    for rocksdb in [RocksDbOptions::default(), small()] {
        let dir = tempfile::tempdir().unwrap();
        let options = EnvOptions {
            rocksdb,
            ..EnvOptions::for_tests()
        };
        let env = Env::open(dir.path(), options.clone()).unwrap();
        env.ensure_initialized().unwrap();
        assert_eq!(
            env.inner
                .db
                .property_int_value("rocksdb.block-cache-capacity")
                .unwrap(),
            Some(rocksdb.block_cache_bytes as u64)
        );
        #[cfg(feature = "rocksdb-memory-diagnostics")]
        {
            let row = &env.inner.memory_sample("test")["row_cache"];
            assert_eq!(row["available"], true);
            assert_eq!(row["capacity_bytes"], rocksdb.row_cache_bytes);
            assert_eq!(row["enabled"], rocksdb.row_cache_bytes != 0);
            if rocksdb.row_cache_bytes == 0 {
                assert_eq!(row["usage_bytes"], 0);
                assert_eq!(row["pinned_usage_bytes"], 0);
            }
        }
        let mut events = fixtures
            .iter()
            .map(|event| EventToWrite::new(event.packed.clone(), event.json.clone()))
            .collect::<Vec<_>>();
        let mut write = env.begin_rw().unwrap();
        crate::write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
        write.commit().unwrap();
        let old = env.begin_ro().unwrap();
        assert_eq!(
            old.get_u64(env.dbis().event, events[0].lev_id)
                .unwrap()
                .unwrap(),
            fixtures[0].packed
        );
        let mut write = env.begin_rw().unwrap();
        crate::delete_events(&mut write, &mut NoopNegentropy, [events[0].lev_id]).unwrap();
        write.commit().unwrap();
        assert_eq!(
            crate::event_json_owned(&old, &mut Decompressor::new(), events[0].lev_id, 1 << 20)
                .unwrap(),
            fixtures[0].json
        );
        assert!(env
            .begin_ro()
            .unwrap()
            .get_u64(env.dbis().event, events[0].lev_id)
            .unwrap()
            .is_none());
        drop(old);
        drop(env);
        let reopened = Env::open(dir.path(), options).unwrap();
        let tx = reopened.begin_ro().unwrap();
        assert_eq!(
            tx.get_u64(reopened.dbis().event, events[1].lev_id)
                .unwrap()
                .unwrap(),
            fixtures[1].packed
        );
        assert_eq!(
            crate::event_json_owned(&tx, &mut Decompressor::new(), events[1].lev_id, 1 << 20)
                .unwrap(),
            fixtures[1].json
        );
        let audit = reopened.audit_rocksdb_layout().unwrap();
        assert_eq!(audit["ok"], true);
        assert_eq!(audit["verified_signatures_and_bodies"], 1);
        fingerprints.push(audit["primary_fingerprint_sha256"].clone());
    }
    assert_eq!(fingerprints[0], fingerprints[1]);
}

#[test]
fn aggregate_target_flushes_below_the_unchanged_per_cf_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let options = EnvOptions {
        rocksdb: RocksDbOptions {
            total_memtable_bytes: 1 << 20,
            max_total_wal_bytes: 64 << 20,
            ..small()
        },
        ..EnvOptions::for_tests()
    };
    let env = Env::open(dir.path(), options.clone()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().moderation.unwrap();
    let value = vec![43; 8192];
    for batch in 0u64..8 {
        let mut write = env.begin_rw().unwrap();
        for record in 0u64..64 {
            write
                .put(dbi, &(batch * 64 + record).to_be_bytes(), &value, 0)
                .unwrap();
        }
        write.commit().unwrap();
    }
    drop(env);
    let log = std::fs::read_to_string(dir.path().join("LOG")).unwrap();
    assert!(log.contains("Flushing triggered to alleviate write buffer memory usage"));
    // No test or production call forces settlement. This ordinary reopen must
    // recover exact bytes under the same small target and unchanged sync WAL.
    let env = Env::open(dir.path(), options).unwrap();
    let tx = env.begin_ro().unwrap();
    for record in 0u64..512 {
        assert_eq!(tx.get(dbi, &record.to_be_bytes()).unwrap().unwrap(), value);
    }
}
