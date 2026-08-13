use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wok_db::{
    bump_negentropy_mod_counter, check_integrity, event_fingerprint, foreach_negentropy_filter,
    rebuild_primary_and_event_indices, Env, EnvOptions,
};
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
        bail!("reindex requires a Wok-owned version 4 database");
    }
    let source_integrity = check_integrity(&source.begin_ro()?)?;
    ensure_reindexable(&source_integrity)?;
    validate_primary_payloads(&source, cfg.events.max_event_size)?;
    let before = event_fingerprint(&source)?;

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
        let stats = rebuild_primary_and_event_indices(&source_txn, &mut target_txn)?;
        target_txn.commit()?;
        stats
    };
    let (negentropy_trees, negentropy_items) = rebuild_negentropy(&target)?;

    let target_integrity = check_integrity(&target.begin_ro()?)?;
    if !target_integrity.ok() {
        bail!("staged database failed integrity verification: {target_integrity:#?}");
    }
    let after = event_fingerprint(&target)?;
    if before != after {
        bail!("event fingerprint changed while rebuilding indexes");
    }

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
    if !promoted_integrity.ok() || event_fingerprint(&promoted)? != before {
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
    let filters = {
        let txn = env.begin_ro()?;
        let mut filters = Vec::new();
        foreach_negentropy_filter(&txn, |id, filter| {
            filters.push((id, filter.to_string()));
            true
        })?;
        filters
    };
    let mut total_items = 0u64;
    for (tree_id, filter) in &filters {
        let records = {
            let txn = env.begin_ro()?;
            let filter: serde_json::Value = serde_json::from_str(filter)?;
            let mut records = Vec::new();
            wok_query::foreach_by_filter(&txn, &filter, u64::MAX, 64, |lev_id| {
                if let Ok(Some(packed)) = wok_db::get_packed_ro(&txn, lev_id) {
                    if let Ok(packed) = wok_event::PackedEventView::new(&packed) {
                        records.push((packed.created_at(), packed.id().to_vec()));
                    }
                }
            })?;
            records
        };
        let mut txn = env.begin_rw()?;
        {
            let mut tree = wok_negentropy::open_rw(&mut txn, *tree_id)?;
            for (timestamp, id) in &records {
                tree.insert(*timestamp, id)?;
            }
            tree.backend.flush()?;
        }
        txn.commit()?;
        total_items = total_items.saturating_add(records.len() as u64);
    }
    if !filters.is_empty() {
        let mut txn = env.begin_rw()?;
        bump_negentropy_mod_counter(&mut txn)?;
        txn.commit()?;
    }
    Ok((filters.len() as u64, total_items))
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

    fn signed_event() -> (Vec<u8>, String) {
        use secp256k1::{Keypair, SECP256K1};
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = keypair.x_only_public_key();
        let mut event = json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [["t", "reindex"]],
            "content": "repair me",
            "pubkey": hex::encode(pubkey.serialize()),
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &keypair).as_ref()));
        let parsed =
            parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
        (parsed.packed.into_bytes(), parsed.json)
    }

    #[test]
    fn rebuilds_indexes_and_preserves_original_as_backup() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("db");
        let backup = root.path().join("backup");
        let env = Env::open(&database, EnvOptions::default()).unwrap();
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
                ..EnvOptions::default()
            },
        )
        .unwrap();
        assert!(check_integrity(&repaired.begin_ro().unwrap()).unwrap().ok());
        let original = Env::open(
            &backup,
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::default()
            },
        )
        .unwrap();
        assert!(!check_integrity(&original.begin_ro().unwrap()).unwrap().ok());
    }
}
