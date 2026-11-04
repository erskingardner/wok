//! Offline, bounded-memory verification of the optimized physical schema.
use super::*;
use crate::{Decompressor, Env};
use sha2::{Digest, Sha256};

impl Env {
    /// Run only on a closed seed/copy: the read-only open must not race a writer.
    /// Scans authoritative components and verifies every covering/thin posting,
    /// then independently counts every logical table against transactional counters.
    pub fn audit_rocksdb_layout(&self) -> Result<serde_json::Value, DbError> {
        self.check_background_errors()?;
        let snapshot = self.inner.db.snapshot();
        let cf = |name: &str| {
            self.inner
                .db
                .cf_handle(name)
                .ok_or_else(|| err("missing audit column family"))
        };
        let mut it = snapshot.raw_iterator_cf(cf(COMBINED)?);
        it.seek_to_first();
        let mut count = 0u64;
        let mut digest = Sha256::new();
        let mut decompressor = Decompressor::new();
        // Only compression dictionaries are read through this transaction; primary
        // bytes stream directly from the iterator, never accumulating in an arena.
        let txn = self.begin_ro()?;
        while let Some((key, value)) = it.item() {
            let (k, _) = decode(3, key, &[])?;
            let id = u64::from_ne_bytes(
                k.as_slice()
                    .try_into()
                    .map_err(|_| err("bad audit local ID"))?,
            );
            let (packed, payload) = parts(value)?;
            let packed = packed.ok_or_else(|| err("orphan payload"))?;
            let payload = payload.ok_or_else(|| err("missing event payload"))?;
            let event = wok_event::PackedEventView::new(packed)?;
            let json = decompressor.decode(&txn, payload, 16 * 1024 * 1024)?;
            let parsed = wok_event::json::parse_strict(json)?;
            wok_event::verify_strfry_event(event, &parsed)?;
            let posting = encode(
                10,
                &crate::keys::make_key_string_u64(event.pubkey(), event.created_at()),
                Some(&k),
            );
            let thin = snapshot
                .get_cf(cf(cf_name(10))?, &posting)
                .map_err(err)?
                .ok_or_else(|| err("missing thin author posting"))?;
            if !thin.is_empty() {
                return Err(err("thin author posting contains payload"));
            }
            let cover = snapshot
                .get_cf(cf(COVERING)?, &posting)
                .map_err(err)?
                .ok_or_else(|| err("missing author cover"))?;
            if cover != value {
                return Err(err("author cover differs from combined primary"));
            }
            digest.update(id.to_le_bytes());
            digest.update((packed.len() as u64).to_le_bytes());
            digest.update(packed);
            digest.update((payload.len() as u64).to_le_bytes());
            digest.update(payload);
            count += 1;
            if count % 100000 == 0 {
                tracing::info!(events = count, "RocksDB physical audit progress");
            }
            it.next();
        }
        it.status().map_err(err)?;
        let mut counts = serde_json::Map::new();
        for dbi in 1..=COVER_DBI {
            let mut it = snapshot.raw_iterator_cf(cf(cf_name(dbi))?);
            it.seek_to_first();
            let mut found = 0u64;
            while let Some((key, value)) = it.item() {
                let (_, dup) = decode(dbi, key, value)?;
                if spec(dbi).flags & lmdb_sys::MDB_DUPSORT != 0 && dup.len() != 8 {
                    return Err(err("malformed physical duplicate"));
                }
                if combined(dbi) {
                    let (a, b) = parts(value)?;
                    if (if dbi == 3 { a } else { b }).is_some() {
                        found += 1;
                    }
                } else {
                    found += 1;
                }
                it.next();
            }
            it.status().map_err(err)?;
            let expected = txn.entries(dbi)? as u64;
            if found != expected {
                return Err(err(format!(
                    "physical count {found} != transactional count {expected} in {}",
                    cf_name(dbi)
                )));
            }
            counts.insert(
                if dbi == COVER_DBI {
                    COVERING.to_string()
                } else {
                    spec(dbi).name.to_string()
                },
                serde_json::json!(found),
            );
        }
        if counts
            .get(crate::schema::DBI_EVENT_PUBKEY)
            .and_then(|v| v.as_u64())
            != Some(count)
            || counts.get(COVERING).and_then(|v| v.as_u64()) != Some(count)
        {
            return Err(err(
                "author indexes do not contain exactly one posting per primary",
            ));
        }
        self.check_background_errors()?;
        let hash = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Ok(
            serde_json::json!({"ok":true,"events":count,"verified_signatures_and_bodies":count,"covering_records_verified":count,"primary_fingerprint_sha256":hash,"table_counts":counts,"layout":String::from_utf8_lossy(FORMAT),"durability":"one atomic cross-CF WriteBatch with sync WAL before ACK; no power-loss proof implied"}),
        )
    }
}
