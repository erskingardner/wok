use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wok_db::{check_integrity, event_fingerprint, snapshot_lmdb_readonly, Env, EnvOptions};
use wok_relay::Config;

const MANIFEST_NAME: &str = "migration-manifest.json";

#[derive(Serialize)]
struct MigrationManifest {
    format_version: u64,
    source_type: &'static str,
    source_db: String,
    source_config: String,
    source_db_version: u64,
    target_db: String,
    target_config: String,
    target_db_version: u64,
    wok_version: &'static str,
    migrated_at_unix_seconds: u64,
    event_count: u64,
    event_fingerprint_sha256: String,
    target_data_sha256: String,
    source_config_sha256: String,
    output_config_sha256: String,
    verification: Verification,
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct Verification {
    source_integrity_ok: bool,
    event_records_unchanged: bool,
    target_opens_as_wok: bool,
}

pub fn migrate_strfry(source_db: &Path, source_config: &Path, output: &Path) -> Result<()> {
    let source_db = absolute_existing(source_db, "source database")?;
    let source_config = absolute_existing(source_config, "source config")?;
    if !source_db.is_dir() {
        bail!(
            "source database '{}' is not a directory",
            source_db.display()
        );
    }
    let output = std::path::absolute(output).context("resolve output path")?;
    if output.exists() {
        bail!(
            "output '{}' already exists; refusing to overwrite it",
            output.display()
        );
    }
    let output_parent = output
        .parent()
        .context("output path has no parent directory")?;
    std::fs::create_dir_all(output_parent).with_context(|| {
        format!(
            "create output parent directory '{}'",
            output_parent.display()
        )
    })?;

    let source_config_bytes = std::fs::read(&source_config)
        .with_context(|| format!("read source config '{}'", source_config.display()))?;
    let source_config_text =
        std::str::from_utf8(&source_config_bytes).context("strfry config is not valid UTF-8")?;
    let source_cfg = Config::parse_strfry(source_config_text).map_err(anyhow::Error::msg)?;

    let staging = tempfile::Builder::new()
        .prefix(".wok-migrate-")
        .tempdir_in(output_parent)
        .context("create migration staging directory")?;
    let staging_db = staging.path().join("db");
    snapshot_lmdb_readonly(&source_db, &staging_db, source_cfg.db_no_read_ahead)
        .context("take read-only LMDB snapshot")?;

    let options = EnvOptions {
        max_readers: source_cfg.db_maxreaders,
        map_size: source_cfg.db_mapsize,
        no_read_ahead: source_cfg.db_no_read_ahead,
        create_dir: false,
        create_dbis: false,
        ..EnvOptions::default()
    };
    let snapshot = Env::open(&staging_db, options.clone()).context("open strfry snapshot")?;
    let source_version = snapshot.db_version()?;
    if source_version != wok_event::STRFRY_DB_VERSION {
        bail!(
            "source database version is {source_version}; expected strfry version {}",
            wok_event::STRFRY_DB_VERSION
        );
    }
    let source_integrity = check_integrity(&snapshot.begin_ro()?)?;
    if !source_integrity.ok() {
        bail!("source database failed integrity checks: {source_integrity:?}");
    }
    let before = event_fingerprint(&snapshot)?;
    snapshot.upgrade_strfry_v3_to_wok()?;
    drop(snapshot);

    let target = Env::open(&staging_db, options).context("reopen migrated Wok database")?;
    target.ensure_initialized()?;
    let after = event_fingerprint(&target)?;
    if before != after {
        bail!("event verification failed after assigning Wok database ownership");
    }
    drop(target);

    let final_db = output.join("db");
    let final_config = output.join("wok.toml");
    let translated_config = translated_config(&source_cfg, &final_db)?;
    let parsed_target = Config::parse_toml(&translated_config).map_err(anyhow::Error::msg)?;
    if parsed_target.db != final_db {
        bail!("translated config does not select the migrated database");
    }
    std::fs::write(
        staging.path().join("wok.toml"),
        translated_config.as_bytes(),
    )
    .context("write translated Wok config")?;

    let manifest = MigrationManifest {
        format_version: 1,
        source_type: "strfry-lmdb-v3",
        source_db: source_db.display().to_string(),
        source_config: source_config.display().to_string(),
        source_db_version: source_version,
        target_db: final_db.display().to_string(),
        target_config: final_config.display().to_string(),
        target_db_version: wok_event::WOK_DB_VERSION,
        wok_version: env!("CARGO_PKG_VERSION"),
        migrated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs(),
        event_count: before.count,
        event_fingerprint_sha256: hex::encode(before.sha256),
        target_data_sha256: sha256_file(&staging_db.join("data.mdb"))?,
        source_config_sha256: sha256_bytes(&source_config_bytes),
        output_config_sha256: sha256_bytes(translated_config.as_bytes()),
        verification: Verification {
            source_integrity_ok: true,
            event_records_unchanged: true,
            target_opens_as_wok: true,
        },
        warnings: vec![
            "The source database and config were not modified.",
            "The copied database is Wok-owned and must not be opened by strfry.",
            "Review plugin, write-policy, and socket paths before cutover.",
            "Only supported strfry settings were translated into Wok TOML.",
        ],
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(staging.path().join(MANIFEST_NAME), manifest_json)
        .context("write migration manifest")?;

    let staging_path = staging.keep();
    if let Err(error) = std::fs::rename(&staging_path, &output) {
        let _ = std::fs::remove_dir_all(&staging_path);
        return Err(error).with_context(|| {
            format!(
                "atomically promote migration output to '{}'",
                output.display()
            )
        });
    }

    println!("Migrated {} events from strfry.", before.count);
    println!("Wok config: {}", final_config.display());
    println!("Manifest: {}", output.join(MANIFEST_NAME).display());
    println!("Source files were not modified.");
    Ok(())
}

fn absolute_existing(path: &Path, label: &str) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("resolve {label} '{}'", path.display()))?;
    if !path.exists() {
        bail!("{label} '{}' does not exist", path.display());
    }
    Ok(path)
}

fn translated_config(source: &Config, final_db: &Path) -> Result<String> {
    let mut target = source.clone();
    target.db = final_db.to_path_buf();
    target.to_toml().map_err(anyhow::Error::msg)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open '{}'", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read '{}'", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wok_db::{
        encode_meta, encode_negentropy_filter, write_events, EventToWrite, Meta, NoopNegentropy,
    };
    use wok_event::{parse_and_verify_event, EventLimits};

    #[test]
    fn translated_config_converts_supported_values_to_toml() {
        let source = Config::parse_strfry("db = \"old-db\"\nrelay { port = 7777 }\n").unwrap();
        let output = Path::new("/srv/wok/db");
        let translated = translated_config(&source, output).unwrap();
        let parsed = Config::parse_toml(&translated).unwrap();
        assert_eq!(parsed.db, output);
        assert_eq!(parsed.relay.port, 7777);
        assert!(translated.contains("[database]"));
        assert!(translated.contains("[relay]"));
    }

    #[test]
    fn migrates_verified_v3_snapshot_without_touching_source() {
        let temp = tempfile::tempdir().unwrap();
        let source_db = temp.path().join("strfry-db");
        let source_config = temp.path().join("strfry.conf");
        let output = temp.path().join("wok-output");

        let source = Env::open(&source_db, EnvOptions::default()).unwrap();
        {
            let mut txn = source.begin_rw().unwrap();
            txn.put_u64(
                source.dbis().meta,
                1,
                &encode_meta(&Meta {
                    db_version: wok_event::STRFRY_DB_VERSION,
                    endianness: 1,
                    negentropy_modification_counter: 1,
                }),
                lmdb_sys::MDB_NOOVERWRITE | lmdb_sys::MDB_APPEND,
            )
            .unwrap();
            txn.put_u64(
                source.dbis().negentropy_filter,
                1,
                &encode_negentropy_filter("{}"),
                lmdb_sys::MDB_NOOVERWRITE | lmdb_sys::MDB_APPEND,
            )
            .unwrap();
            let parsed = signed_event();
            let mut events = [EventToWrite::new(parsed.packed.into_bytes(), parsed.json)];
            write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
            txn.commit().unwrap();
        }
        let source_fingerprint = event_fingerprint(&source).unwrap();
        drop(source);
        std::fs::write(
            &source_config,
            format!(
                "db = \"{}\"\nrelay {{ port = 7777 }}\n",
                source_db.display()
            ),
        )
        .unwrap();
        let source_data_before = sha256_file(&source_db.join("data.mdb")).unwrap();

        migrate_strfry(&source_db, &source_config, &output).unwrap();

        assert_eq!(
            sha256_file(&source_db.join("data.mdb")).unwrap(),
            source_data_before,
            "migration modified the source data.mdb"
        );
        let source = Env::open(&source_db, EnvOptions::default()).unwrap();
        assert_eq!(source.db_version().unwrap(), wok_event::STRFRY_DB_VERSION);
        let target = Env::open(output.join("db"), EnvOptions::default()).unwrap();
        target.ensure_initialized().unwrap();
        assert_eq!(target.db_version().unwrap(), wok_event::WOK_DB_VERSION);
        assert_eq!(event_fingerprint(&target).unwrap(), source_fingerprint);

        let output_cfg = Config::load(output.join("wok.toml")).unwrap();
        assert_eq!(output_cfg.db, output.join("db"));
        assert_eq!(output_cfg.relay.port, 7777);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join(MANIFEST_NAME)).unwrap()).unwrap();
        assert_eq!(manifest["event_count"], 1);
        assert_eq!(manifest["source_db_version"], 3);
        assert_eq!(manifest["target_db_version"], 4);
        assert_eq!(manifest["verification"]["event_records_unchanged"], true);
    }

    fn signed_event() -> wok_event::ParsedEvent {
        use secp256k1::{Keypair, SECP256K1};
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = keypair.x_only_public_key();
        let mut event = json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "migration fixture",
            "pubkey": hex::encode(pubkey.serialize()),
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        let sig = SECP256K1.sign_schnorr(&id, &keypair);
        event["sig"] = json!(hex::encode(sig.as_ref()));
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap()
    }
}
