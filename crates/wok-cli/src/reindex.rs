use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wok_db::{
    check_integrity, event_fingerprint, event_fingerprint_excluding,
    event_fingerprint_without_hashed_tag_values, foreach_negentropy_filter,
    rebuild_primary_and_event_indices, Env, EnvOptions, PackedEventRebuild,
};

/// Primary records scanned per batch when rebuilding a negentropy tree.
const NEGENTROPY_BUILD_BATCH: usize = 10_000;
use wok_relay::Config;

#[derive(Debug, Serialize)]
pub struct ReindexOutcome {
    pub database: PathBuf,
    pub backup: PathBuf,
    pub events: u64,
    pub payloads: u64,
    pub index_entries: u64,
    pub negentropy_trees: u64,
    pub negentropy_items: u64,
    pub repacked_long_tag_records: u64,
    pub skipped_long_tag_records: u64,
    /// Versions deleted because a repaired `a` tag of a deletion request
    /// names their address: one longer than 255 bytes, a replaceable event's,
    /// or one whose kind has leading zeros. The backup keeps them.
    pub deleted_under_repaired_deletions: u64,
    /// Fingerprint of the original database, which is kept as the backup.
    pub source_event_fingerprint_sha256: String,
    pub event_fingerprint_sha256: String,
}

#[derive(Debug, Serialize)]
struct ReindexManifest {
    format_version: u64,
    database: PathBuf,
    backup: PathBuf,
    created_at_unix_seconds: u64,
    events: u64,
    payloads: u64,
    index_entries: u64,
    negentropy_trees: u64,
    negentropy_items: u64,
    repacked_long_tag_records: u64,
    skipped_long_tag_records: u64,
    deleted_under_repaired_deletions: u64,
    source_event_fingerprint_sha256: String,
    event_fingerprint_sha256: String,
}

pub fn run(cfg: &Config, backup: Option<&Path>, confirmed_stopped: bool) -> Result<ReindexOutcome> {
    if !confirmed_stopped {
        bail!("refusing to reindex without --confirm-relay-stopped");
    }
    let database = cfg
        .db
        .canonicalize()
        .with_context(|| format!("resolve database {}", cfg.db.display()))?;
    let parent = database.parent().context("database path has no parent")?;
    let backup = match backup {
        Some(path) => absolute_new_path(path).context("resolve backup path")?,
        None => default_backup_path(&database)?,
    };
    if backup.exists() {
        bail!("backup path {} already exists", backup.display());
    }
    if backup.parent() != Some(parent) {
        bail!("backup must be a sibling of the database for atomic promotion");
    }

    let options = EnvOptions {
        max_readers: cfg.db_maxreaders,
        map_size: cfg.db_mapsize,
        no_read_ahead: cfg.db_no_read_ahead,
        create_dir: false,
        create_dbis: false,
        ..EnvOptions::default()
    };
    let source = Env::open(&database, options.clone()).context("open source database")?;
    if source.db_version()? != wok_event::WOK_DB_VERSION {
        bail!(
            "reindex requires a Wok-owned version {} database",
            wok_event::WOK_DB_VERSION
        );
    }
    let source_integrity = check_integrity(&source.begin_ro()?)?;
    ensure_reindexable(&source_integrity)?;
    validate_primary_payloads(&source, cfg.events.max_event_size)?;
    let before = event_fingerprint(&source)?;
    let before_unhashed = event_fingerprint_without_hashed_tag_values(&source)?;

    let staging = tempfile::Builder::new()
        .prefix(".wok-reindex-")
        .tempdir_in(parent)
        .context("create reindex staging directory")?;
    let target = Env::open(
        staging.path(),
        EnvOptions {
            max_readers: cfg.db_maxreaders,
            map_size: cfg.db_mapsize,
            no_read_ahead: cfg.db_no_read_ahead,
            ..EnvOptions::default()
        },
    )
    .context("create staged database")?;
    target.ensure_initialized()?;
    let stats = {
        let source_txn = source.begin_ro()?;
        let mut target_txn = target.begin_rw()?;
        let stats = rebuild_primary_and_event_indices(
            &source_txn,
            &mut target_txn,
            PackedEventRebuild::RepackLongTags,
        )?;
        target_txn.commit()?;
        stats
    };
    let (negentropy_trees, negentropy_items) = rebuild_negentropy(&target)?;

    let target_integrity = check_integrity(&target.begin_ro()?)?;
    if !target_integrity.ok() {
        bail!("staged database failed integrity verification: {target_integrity:#?}");
    }
    // Repacking only adds hashed tag values to records that dropped them, and
    // only the versions the rebuild reports deleting may be missing.
    let deleted = &stats.deleted_versions;
    let kept = |without_hashed_tag_values: bool| {
        if !deleted.is_empty() {
            event_fingerprint_excluding(&source, deleted, without_hashed_tag_values)
        } else if without_hashed_tag_values {
            Ok(before_unhashed.clone())
        } else {
            Ok(before.clone())
        }
    };
    let after = event_fingerprint(&target)?;
    if event_fingerprint_without_hashed_tag_values(&target)? != kept(true)?
        || (stats.repacked_long_tag_records == 0 && kept(false)? != after)
    {
        bail!("event fingerprint changed while rebuilding indexes");
    }

    let source_fingerprint = hex::encode(before.sha256);
    let fingerprint = hex::encode(after.sha256);
    let manifest = ReindexManifest {
        format_version: 1,
        database: database.clone(),
        backup: backup.clone(),
        created_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs(),
        events: stats.events,
        payloads: stats.payloads,
        index_entries: stats.index_entries,
        negentropy_trees,
        negentropy_items,
        repacked_long_tag_records: stats.repacked_long_tag_records,
        skipped_long_tag_records: stats.skipped_long_tag_records,
        deleted_under_repaired_deletions: deleted.len() as u64,
        source_event_fingerprint_sha256: source_fingerprint.clone(),
        event_fingerprint_sha256: fingerprint.clone(),
    };
    std::fs::write(
        staging.path().join("reindex-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .context("write reindex manifest")?;

    drop(target);
    drop(source);
    let staging_path = staging.keep();
    std::fs::rename(&database, &backup).with_context(|| {
        format!(
            "move original database {} to {}",
            database.display(),
            backup.display()
        )
    })?;
    if let Err(promote_error) = std::fs::rename(&staging_path, &database) {
        let rollback = std::fs::rename(&backup, &database);
        if let Err(rollback_error) = rollback {
            bail!(
                "promotion failed ({promote_error}); rollback also failed ({rollback_error}); original remains at {} and staging at {}",
                backup.display(),
                staging_path.display()
            );
        }
        bail!("promotion failed and original database was restored: {promote_error}");
    }

    let promoted = Env::open(&database, options).context("open promoted database")?;
    let promoted_integrity = check_integrity(&promoted.begin_ro()?)?;
    if !promoted_integrity.ok() || event_fingerprint(&promoted)? != after {
        bail!(
            "promoted database verification failed; original database is preserved at {}",
            backup.display()
        );
    }

    Ok(ReindexOutcome {
        database,
        backup,
        events: stats.events,
        payloads: stats.payloads,
        index_entries: stats.index_entries,
        negentropy_trees,
        negentropy_items,
        repacked_long_tag_records: stats.repacked_long_tag_records,
        skipped_long_tag_records: stats.skipped_long_tag_records,
        deleted_under_repaired_deletions: stats.deleted_versions.len() as u64,
        source_event_fingerprint_sha256: source_fingerprint,
        event_fingerprint_sha256: fingerprint,
    })
}

fn ensure_reindexable(report: &wok_db::IntegrityReport) -> Result<()> {
    if !report.missing_payloads.is_empty()
        || !report.orphan_payloads.is_empty()
        || report.packed_parse_errors != 0
        || report.payload_parse_errors != 0
        || report.metadata_errors != 0
        || report.lookup_errors != 0
    {
        bail!(
            "database has primary, payload, or metadata corruption that reindex cannot repair: {report:#?}"
        );
    }
    let rebuildable_tables = [
        "author_counts",
        "event_id",
        "event_pubkey_kind",
        "event_tag",
        "event_deletion",
        "event_replace",
        "event_created_at",
        "event_pubkey",
        "event_replace_deletion",
        "event_kind",
        "event_expiration",
        "negentropy",
    ];
    if report
        .issues
        .iter()
        .any(|issue| !rebuildable_tables.contains(&issue.table))
    {
        bail!("database contains corruption outside rebuildable indexes: {report:#?}");
    }
    Ok(())
}

fn validate_primary_payloads(env: &Env, max_event_size: usize) -> Result<()> {
    let txn = env.begin_ro()?;
    let mut decompressor = wok_db::Decompressor::new();
    let mut error = None;
    txn.foreach_full(txn.env().dbis().event, &[], &[], false, |key, packed| {
        let Ok(key): Result<[u8; 8], _> = key.try_into() else {
            error = Some(anyhow::anyhow!("Event key is not 8 bytes"));
            return false;
        };
        let lev_id = u64::from_ne_bytes(key);
        let packed = match wok_event::PackedEventView::new(packed) {
            Ok(packed) => packed,
            Err(err) => {
                error = Some(anyhow::anyhow!("levId {lev_id}: {err}"));
                return false;
            }
        };
        let result = wok_db::event_json_owned(&txn, &mut decompressor, lev_id, max_event_size)
            .map_err(anyhow::Error::from)
            .and_then(|json| {
                let event: serde_json::Value = serde_json::from_str(&json)?;
                let id = event
                    .get("id")
                    .and_then(|id| id.as_str())
                    .context("payload has no string id")?;
                if id != hex::encode(packed.id()) {
                    bail!("payload id differs from PackedEvent id");
                }
                Ok(())
            });
        if let Err(err) = result {
            error = Some(err.context(format!("levId {lev_id}")));
            return false;
        }
        true
    })?;
    if let Some(error) = error {
        bail!("database has payload corruption that reindex cannot repair: {error}");
    }
    Ok(())
}

fn rebuild_negentropy(env: &Env) -> Result<(u64, u64)> {
    let tree_ids = {
        let txn = env.begin_ro()?;
        let mut tree_ids = Vec::new();
        foreach_negentropy_filter(&txn, |id, _| {
            tree_ids.push(id);
            true
        })?;
        tree_ids
    };
    // A tree holds every stored record its filter matches, as the writer and
    // `wok negentropy build` keep it; reads apply visibility (superseded,
    // expired, vanished or moderated records) on top. Building one tree at a
    // time in bounded batches keeps memory independent of the database size.
    let mut total_items = 0u64;
    for tree_id in &tree_ids {
        let items = crate::build_negentropy_tree(env, *tree_id, NEGENTROPY_BUILD_BATCH)?;
        total_items = total_items.saturating_add(items);
    }
    Ok((tree_ids.len() as u64, total_items))
}

fn default_backup_path(database: &Path) -> Result<PathBuf> {
    let parent = database.parent().context("database path has no parent")?;
    let name = database
        .file_name()
        .context("database path has no final component")?
        .to_string_lossy();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    Ok(parent.join(format!("{name}.pre-reindex-{timestamp}")))
}

fn absolute_new_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .context("path has no parent")?
        .canonicalize()?;
    let name = absolute
        .file_name()
        .context("path has no final component")?;
    Ok(parent.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wok_db::{write_events, EventToWrite, NoopNegentropy};
    use wok_event::{parse_and_verify_event, EventLimits};

    fn signed(tags: serde_json::Value, content: &str) -> (Vec<u8>, String) {
        let keypair = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
        signed_by(&keypair, 1, 1_700_000_000, tags, content)
    }

    fn signed_by(
        keypair: &secp256k1::Keypair,
        kind: u64,
        created_at: u64,
        tags: serde_json::Value,
        content: &str,
    ) -> (Vec<u8>, String) {
        use secp256k1::SECP256K1;
        let (pubkey, _) = keypair.x_only_public_key();
        let mut event = json!({
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "pubkey": hex::encode(pubkey.serialize()),
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, keypair).as_ref()));
        let parsed =
            parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
        (parsed.packed.into_bytes(), parsed.json)
    }

    fn signed_event() -> (Vec<u8>, String) {
        signed(json!([["t", "reindex"]]), "repair me")
    }

    fn open_existing(path: &Path) -> Env {
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
    fn repacks_records_that_dropped_long_tag_values() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("db");
        let backup = root.path().join("backup");
        let url = format!("https://example.com/{}", "r".repeat(300));
        let (current, current_json) = signed(json!([["r", &url]]), "current");
        let (repacked, legacy_json) = signed(json!([["r", &url], ["t", "short"]]), "legacy");
        // Versions of a long address keyed by the empty d, a newer one stored
        // at its own address, and a deletion of the address after the oldest.
        // Repacked, the deletion removes the oldest; the middle one stays as
        // superseded history.
        let author = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
        let d = "x".repeat(300);
        let address = format!(
            "30000:{}:{d}",
            hex::encode(author.x_only_public_key().0.serialize())
        );
        let (older, older_json) =
            signed_by(&author, 30000, 1_700_000_000, json!([["d", &d]]), "older");
        let (newer, newer_json) =
            signed_by(&author, 30000, 1_700_000_100, json!([["d", &d]]), "newer");
        let (middle, middle_json) =
            signed_by(&author, 30000, 1_700_000_050, json!([["d", &d]]), "middle");
        let (deletion, deletion_json) =
            signed_by(&author, 5, 1_700_000_030, json!([["a", &address]]), "");
        // What strfry and earlier Wok releases stored: the long values dropped.
        let legacy_packing = |packed: &[u8]| {
            let view = wok_event::PackedEventView::new(packed).unwrap();
            let mut tags = wok_event::PackedEventTagBuilder::default();
            for tag in view.tags() {
                if wok_event::hashed_tag_value_digest(&tag.value).is_none() {
                    tags.add(tag.name, &tag.value).unwrap();
                }
            }
            wok_event::PackedEventBuilder::build(
                view.id(),
                view.pubkey(),
                view.created_at(),
                view.kind(),
                view.expiration(),
                &tags,
            )
            .unwrap()
            .into_bytes()
        };
        let legacy = legacy_packing(&repacked);
        let legacy_older = legacy_packing(&older);
        let legacy_middle = legacy_packing(&middle);
        let legacy_deletion = legacy_packing(&deletion);
        let filter = json!({"#r": [&url]}).to_string();
        {
            let staging = tempfile::tempdir().unwrap();
            let source = Env::open(staging.path(), EnvOptions::for_tests()).unwrap();
            source.ensure_initialized().unwrap();
            let mut txn = source.begin_rw().unwrap();
            // The newest local ID is a version the deletion removes.
            for (lev, (packed, json)) in [
                (&legacy, &legacy_json),
                (&current, &current_json),
                (&legacy_middle, &middle_json),
                (&newer, &newer_json),
                (&legacy_deletion, &deletion_json),
                (&legacy_older, &older_json),
            ]
            .into_iter()
            .enumerate()
            {
                let lev = lev as u64 + 1;
                txn.put_u64(source.dbis().event, lev, packed, 0).unwrap();
                txn.put_u64(
                    source.dbis().event_payload,
                    lev,
                    &wok_db::encode_raw_payload(json),
                    0,
                )
                .unwrap();
            }
            txn.commit().unwrap();
            let env = Env::open(&database, EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut txn = env.begin_rw().unwrap();
            rebuild_primary_and_event_indices(
                &source.begin_ro().unwrap(),
                &mut txn,
                PackedEventRebuild::Copy,
            )
            .unwrap();
            // Only the current record's packing matches the filtered tree.
            assert_eq!(
                wok_db::insert_negentropy_filter(&mut txn, &filter).unwrap(),
                2
            );
            wok_db::bump_negentropy_mod_counter(&mut txn).unwrap();
            let all = vec![
                &legacy,
                &current,
                &legacy_middle,
                &newer,
                &legacy_deletion,
                &legacy_older,
            ];
            for (tree_id, records) in [(1, all), (2, vec![&current])] {
                let mut tree = wok_negentropy::open_rw(&mut txn, tree_id).unwrap();
                for packed in records {
                    let packed = wok_event::PackedEventView::new(packed).unwrap();
                    tree.insert(packed.created_at(), packed.id()).unwrap();
                }
                tree.backend.flush().unwrap();
            }
            txn.commit().unwrap();
            let txn = env.begin_ro().unwrap();
            let report = check_integrity(&txn).unwrap();
            assert!(report.ok(), "{:?}", report.issues);
            assert_eq!(report.legacy_long_tag_records, 4);
            assert_eq!(report.superseded_events, 1);
            assert_eq!(wok_negentropy::verify_tree(&txn, 2, &filter).unwrap(), 1);
            assert_eq!(wok_db::state::high_water_ro(&txn).unwrap(), Some(6));
        }

        let cfg = Config {
            db: database.clone(),
            ..Config::default()
        };
        let outcome = run(&cfg, Some(&backup), true).unwrap();
        assert_eq!(outcome.events, 5);
        assert_eq!(outcome.payloads, 5);
        assert_eq!(outcome.repacked_long_tag_records, 4);
        assert_eq!(outcome.skipped_long_tag_records, 0);
        assert_eq!(outcome.deleted_under_repaired_deletions, 1);
        assert_eq!((outcome.negentropy_trees, outcome.negentropy_items), (2, 7));
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(database.join("reindex-manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["deleted_under_repaired_deletions"], 1);
        assert_eq!(manifest["events"], 5);

        // The backup is the original, the deleted version included.
        let original = open_existing(&backup);
        assert_eq!(
            outcome.source_event_fingerprint_sha256,
            hex::encode(event_fingerprint(&original).unwrap().sha256)
        );
        assert_eq!(
            wok_db::get_packed_ro(&original.begin_ro().unwrap(), 6)
                .unwrap()
                .unwrap(),
            legacy_older
        );
        let repaired = open_existing(&database);
        assert_eq!(
            outcome.event_fingerprint_sha256,
            hex::encode(event_fingerprint(&repaired).unwrap().sha256)
        );
        assert_eq!(
            event_fingerprint_without_hashed_tag_values(&repaired).unwrap(),
            event_fingerprint_excluding(&original, &[6].into(), true).unwrap()
        );
        let txn = repaired.begin_ro().unwrap();
        assert_eq!(wok_db::get_packed_ro(&txn, 1).unwrap().unwrap(), repacked);
        assert_eq!(wok_db::get_packed_ro(&txn, 2).unwrap().unwrap(), current);
        assert_eq!(wok_db::get_packed_ro(&txn, 3).unwrap().unwrap(), middle);
        assert_eq!(wok_db::get_packed_ro(&txn, 4).unwrap().unwrap(), newer);
        assert_eq!(wok_db::get_packed_ro(&txn, 5).unwrap().unwrap(), deletion);
        assert!(wok_db::get_packed_ro(&txn, 6).unwrap().is_none());
        assert!(wok_db::get_payload_ro(&txn, 6).unwrap().is_none());
        // Deleting the newest record leaves the sequence where it was.
        assert_eq!(wok_db::state::high_water_ro(&txn).unwrap(), Some(6));
        let report = check_integrity(&txn).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
        assert_eq!(report.legacy_long_tag_records, 0);
        assert_eq!(report.superseded_events, 1);
        assert_eq!(wok_db::state::superseded_events_ro(&txn).unwrap(), Some(1));
        // Trees keep superseded history, as the writer and verification do:
        // the match-all tree holds the middle version reads hide.
        assert_eq!(wok_negentropy::verify_tree(&txn, 1, "{}").unwrap(), 5);
        assert_eq!(wok_negentropy::verify_tree(&txn, 2, &filter).unwrap(), 2);
        let mut hits = Vec::new();
        wok_query::foreach_by_filter(&txn, &json!({"#r": [&url]}), 100, 3, 16, |lev_id| {
            hits.push(lev_id)
        })
        .unwrap();
        hits.sort();
        assert_eq!(hits, [1, 2]);
        let mut hits = Vec::new();
        wok_query::foreach_by_filter(&txn, &json!({"kinds": [30000]}), 100, 3, 16, |lev_id| {
            hits.push(lev_id)
        })
        .unwrap();
        assert_eq!(hits, [4]);
        drop(txn);
        drop((original, repaired));
        let doctor = crate::doctor::run(&cfg, Path::new("missing-test-config.toml"));
        assert!(doctor.ok, "{}", doctor.render_human());

        // A second reindex finds nothing more to repair.
        let again = run(&cfg, Some(&root.path().join("backup-again")), true).unwrap();
        assert_eq!(
            (
                again.events,
                again.repacked_long_tag_records,
                again.deleted_under_repaired_deletions
            ),
            (5, 0, 0)
        );
        assert_eq!(
            again.event_fingerprint_sha256,
            outcome.event_fingerprint_sha256
        );
        assert_eq!(
            again.source_event_fingerprint_sha256,
            outcome.event_fingerprint_sha256
        );
    }

    #[test]
    fn rebuilds_indexes_and_preserves_original_as_backup() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("db");
        let backup = root.path().join("backup");
        let env = Env::open(&database, EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let (packed, json) = signed_event();
        let mut events = vec![EventToWrite::new(packed.clone(), json)];
        {
            let mut txn = env.begin_rw().unwrap();
            write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
            txn.commit().unwrap();
        }
        let view = wok_event::PackedEventView::new(&packed).unwrap();
        let key = wok_db::comparators::make_key_string_u64(view.id(), view.created_at());
        {
            let mut txn = env.begin_rw().unwrap();
            txn.del(
                env.dbis().event_id,
                &key,
                Some(&events[0].lev_id.to_ne_bytes()),
            )
            .unwrap();
            let mut author_key = vec![b'a'];
            author_key.extend_from_slice(view.pubkey());
            txn.put(
                env.dbis().state.unwrap(),
                &author_key,
                &999u64.to_le_bytes(),
                0,
            )
            .unwrap();
            // Retain a historical high-water mark above the surviving tail.
            txn.put(
                env.dbis().state.unwrap(),
                b"sequence",
                &41u64.to_le_bytes(),
                0,
            )
            .unwrap();
            txn.commit().unwrap();
        }
        drop(env);

        let cfg = Config {
            db: database.clone(),
            ..Config::default()
        };
        let outcome = run(&cfg, Some(&backup), true).unwrap();
        assert_eq!(outcome.events, 1);
        assert_eq!(outcome.backup, backup.canonicalize().unwrap());

        let repaired = Env::open(
            &database,
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::for_tests()
            },
        )
        .unwrap();
        assert!(check_integrity(&repaired.begin_ro().unwrap()).unwrap().ok());
        let txn = repaired.begin_ro().unwrap();
        assert_eq!(wok_db::state::high_water_ro(&txn).unwrap(), Some(41));
        let mut author_key = vec![b'a'];
        author_key.extend_from_slice(view.pubkey());
        assert!(txn
            .get(repaired.dbis().state.unwrap(), &author_key)
            .unwrap()
            .is_none());
        let mut search_hits = Vec::new();
        wok_query::foreach_by_filter(&txn, &json!({"search":"repair me"}), 100, 3, 16, |lev_id| {
            search_hits.push(lev_id)
        })
        .unwrap();
        assert_eq!(search_hits.len(), 1, "reindexed event was not searchable");
        drop(txn);
        let mut txn = repaired.begin_rw().unwrap();
        assert_eq!(
            wok_db::state::author_count(&mut txn, view.pubkey()).unwrap(),
            1
        );
        txn.commit().unwrap();
        assert!(check_integrity(&repaired.begin_ro().unwrap()).unwrap().ok());
        let original = Env::open(
            &backup,
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::for_tests()
            },
        )
        .unwrap();
        assert!(!check_integrity(&original.begin_ro().unwrap()).unwrap().ok());
    }

    #[test]
    fn refuses_sequence_corruption_even_when_issue_details_are_truncated() {
        for sequence in [0u64.to_le_bytes().to_vec(), vec![1]] {
            let root = tempfile::tempdir().unwrap();
            let database = root.path().join("db");
            let backup = root.path().join("backup");
            let env = Env::open(&database, EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let (packed, json) = signed_event();
            let mut events = [EventToWrite::new(packed, json)];
            let mut txn = env.begin_rw().unwrap();
            write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
            txn.commit().unwrap();
            let mut txn = env.begin_rw().unwrap();
            let state = env.dbis().state.unwrap();
            for i in 0u16..101 {
                let mut key = vec![b'a'];
                key.extend_from_slice(&i.to_be_bytes());
                txn.put(state, &key, &0u64.to_le_bytes(), 0).unwrap();
            }
            txn.put(state, b"sequence", &sequence, 0).unwrap();
            txn.commit().unwrap();
            let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
            assert_eq!(report.issues.len(), 100);
            assert!(report
                .issues
                .iter()
                .all(|issue| issue.table == "author_counts"));
            assert_eq!(report.metadata_errors, 1);
            let fingerprint = event_fingerprint(&env).unwrap();
            drop(env);
            let cfg = Config {
                db: database.clone(),
                ..Config::default()
            };
            let error = run(&cfg, Some(&backup), true).unwrap_err();
            assert!(
                error.to_string().contains("metadata corruption"),
                "{error:#}"
            );
            assert!(!backup.exists());
            let env = Env::open(
                &database,
                EnvOptions {
                    read_only: true,
                    create_dbis: false,
                    create_dir: false,
                    ..EnvOptions::for_tests()
                },
            )
            .unwrap();
            assert_eq!(event_fingerprint(&env).unwrap(), fingerprint);
            assert_eq!(
                env.begin_ro()
                    .unwrap()
                    .get(env.dbis().state.unwrap(), b"sequence")
                    .unwrap()
                    .unwrap(),
                sequence
            );
        }
    }
}
