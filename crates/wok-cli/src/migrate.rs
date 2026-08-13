use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use wok_db::{
    check_integrity, event_fingerprint, snapshot_lmdb_readonly, Env, EnvOptions, EnvironmentStats,
    IntegrityReport,
};
use wok_relay::{Config, StrfryConfigTranslation};

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
    translated_config_keys: Vec<String>,
    ignored_config_keys: Vec<String>,
    verification: Verification,
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct Verification {
    source_integrity_ok: bool,
    event_records_unchanged: bool,
    target_opens_as_wok: bool,
}

#[derive(Debug, Serialize)]
pub struct MigrationPreflight {
    pub ok: bool,
    pub source_db: String,
    pub source_config: String,
    pub output: String,
    pub output_available: bool,
    pub source_db_version: u64,
    pub expected_source_db_version: u64,
    pub event_count: u64,
    pub source_data_bytes: u64,
    pub estimated_output_bytes: u64,
    pub available_output_bytes: Option<u64>,
    pub lmdb: EnvironmentStats,
    pub source_integrity: IntegrityReport,
    pub translated_keys: Vec<String>,
    pub ignored_keys: Vec<String>,
    pub external_paths: Vec<ExternalPathCheck>,
    pub source_use_probe: String,
    pub active_source_processes: Vec<SourceProcess>,
    pub generated_toml: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ExternalPathCheck {
    pub name: &'static str,
    pub ok: bool,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct SourceProcess {
    pub pid: u32,
    pub command: String,
}

struct PreparedMigration {
    report: MigrationPreflight,
    source_db: PathBuf,
    source_config: PathBuf,
    output: PathBuf,
    source_config_bytes: Vec<u8>,
    source_cfg: Config,
}

impl MigrationPreflight {
    fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Migration preflight: {}\n",
            if self.ok { "PASS" } else { "FAIL" }
        ));
        out.push_str(&format!(
            "Source: {} (LMDB v{}, {} events, {} bytes)\n",
            self.source_db, self.source_db_version, self.event_count, self.source_data_bytes
        ));
        out.push_str(&format!(
            "Integrity: {}\n",
            if self.source_integrity.ok() {
                "PASS"
            } else {
                "FAIL"
            }
        ));
        match self.available_output_bytes {
            Some(available) => out.push_str(&format!(
                "Capacity: {} bytes estimated, {} bytes available\n",
                self.estimated_output_bytes, available
            )),
            None => out.push_str("Capacity: unavailable\n"),
        }
        out.push_str(&format!(
            "Config keys: {} translated, {} ignored\n",
            self.translated_keys.len(),
            self.ignored_keys.len()
        ));
        for key in &self.translated_keys {
            out.push_str(&format!("  translated: {key}\n"));
        }
        for key in &self.ignored_keys {
            out.push_str(&format!("  ignored: {key}\n"));
        }
        for check in &self.external_paths {
            out.push_str(&format!(
                "  {} {}: {}\n",
                if check.ok { "PASS" } else { "FAIL" },
                check.name,
                check.detail
            ));
        }
        out.push_str(&format!("Source-use probe: {}\n", self.source_use_probe));
        for process in &self.active_source_processes {
            out.push_str(&format!(
                "  active: pid {} {}\n",
                process.pid, process.command
            ));
        }
        for warning in &self.warnings {
            out.push_str(&format!("WARN: {warning}\n"));
        }
        out.push_str("\nGenerated wok.toml:\n");
        out.push_str(&self.generated_toml);
        out
    }
}

pub fn check_strfry(
    source_db: &Path,
    source_config: &Path,
    output: &Path,
    json: bool,
) -> Result<()> {
    let prepared = prepare_strfry(source_db, source_config, output)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&prepared.report)?);
    } else {
        print!("{}", prepared.report.render_human());
    }
    if !prepared.report.ok {
        bail!("migration preflight failed");
    }
    Ok(())
}

pub fn migrate_strfry(source_db: &Path, source_config: &Path, output: &Path) -> Result<()> {
    let prepared = prepare_strfry(source_db, source_config, output)?;
    if !prepared.report.ok {
        bail!(
            "migration preflight failed; run `wok migrate strfry --check` for the complete report"
        );
    }
    let PreparedMigration {
        report,
        source_db,
        source_config,
        output,
        source_config_bytes,
        source_cfg,
    } = prepared;
    let output_parent = output
        .parent()
        .context("output path has no parent directory")?;
    std::fs::create_dir_all(output_parent).with_context(|| {
        format!(
            "create output parent directory '{}'",
            output_parent.display()
        )
    })?;

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
        translated_config_keys: report.translated_keys,
        ignored_config_keys: report.ignored_keys,
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
            "New ephemeral events are live-only by default; set events.ephemeral_persistence = \"ttl\" for strfry-compatible retention.",
            "Wok native abuse controls are enabled by default; review relay.abuse budgets and quotas before cutover.",
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

fn prepare_strfry(
    source_db: &Path,
    source_config: &Path,
    output: &Path,
) -> Result<PreparedMigration> {
    let source_db = absolute_existing(source_db, "source database")?;
    let source_config = absolute_existing(source_config, "source config")?;
    if !source_db.is_dir() {
        bail!(
            "source database '{}' is not a directory",
            source_db.display()
        );
    }
    let output = std::path::absolute(output).context("resolve output path")?;
    let source_config_bytes = std::fs::read(&source_config)
        .with_context(|| format!("read source config '{}'", source_config.display()))?;
    let source_config_text =
        std::str::from_utf8(&source_config_bytes).context("strfry config is not valid UTF-8")?;
    let StrfryConfigTranslation {
        config: source_cfg,
        translated_keys,
        ignored_keys,
    } = Config::translate_strfry(source_config_text).map_err(anyhow::Error::msg)?;

    let final_db = output.join("db");
    let generated_toml = translated_config(&source_cfg, &final_db)?;
    Config::parse_toml(&generated_toml).map_err(anyhow::Error::msg)?;

    let (source_use_probe, active_source_processes) = probe_source_processes(&source_db);
    let env = Env::open(
        &source_db,
        EnvOptions {
            max_readers: source_cfg.db_maxreaders,
            map_size: source_cfg.db_mapsize,
            no_read_ahead: source_cfg.db_no_read_ahead,
            create_dir: false,
            create_dbis: false,
            read_only: true,
            ..EnvOptions::default()
        },
    )
    .context("open strfry source read-only")?;
    let source_db_version = env.db_version()?;
    let lmdb = env.stats()?;
    let source_integrity = check_integrity(&env.begin_ro()?)?;
    drop(env);

    let source_data_bytes = std::fs::metadata(source_db.join("data.mdb"))
        .context("inspect source data.mdb")?
        .len();
    // The compact LMDB snapshot is normally smaller than data.mdb. Use the
    // existing file size plus fixed metadata/config headroom as a conservative
    // capacity estimate rather than promising compaction savings.
    let estimated_output_bytes = source_data_bytes.saturating_add(64 * 1024 * 1024);
    let available_output_bytes =
        nearest_existing_parent(&output).and_then(|path| crate::doctor::available_bytes(path).ok());
    let external_paths = external_path_checks(&source_cfg);
    let output_available = !output.exists();
    let mut warnings = Vec::new();
    if !output_available {
        warnings.push(format!(
            "output {} already exists and will not be overwritten",
            output.display()
        ));
    }
    if !ignored_keys.is_empty() {
        warnings.push(format!(
            "{} unsupported config keys will be ignored",
            ignored_keys.len()
        ));
    }
    if !active_source_processes.is_empty() {
        warnings.push(
            "the source database is open by another process; stop strfry before cutover".into(),
        );
    }
    if source_use_probe.starts_with("unavailable") {
        warnings.push("could not determine whether strfry is using the source database".into());
    }
    if lmdb.map_size > 0 {
        let utilization = lmdb.used_bytes as f64 / lmdb.map_size as f64;
        if utilization >= 0.75 {
            warnings.push(format!(
                "LMDB map is {:.1}% full; increase database.map_size before growth",
                utilization * 100.0
            ));
        }
    }
    if let Some(available) = available_output_bytes {
        if available < estimated_output_bytes {
            warnings.push(format!(
                "only {available} bytes are available for an estimated {estimated_output_bytes}-byte output"
            ));
        }
    } else {
        warnings.push("could not determine free space for the output filesystem".into());
    }
    let ok = output_available
        && source_db_version == wok_event::STRFRY_DB_VERSION
        && source_integrity.ok()
        && external_paths.iter().all(|check| check.ok)
        && available_output_bytes
            .map(|available| available >= estimated_output_bytes)
            .unwrap_or(false);
    let report = MigrationPreflight {
        ok,
        source_db: source_db.display().to_string(),
        source_config: source_config.display().to_string(),
        output: output.display().to_string(),
        output_available,
        source_db_version,
        expected_source_db_version: wok_event::STRFRY_DB_VERSION,
        event_count: source_integrity.events,
        source_data_bytes,
        estimated_output_bytes,
        available_output_bytes,
        lmdb,
        source_integrity,
        translated_keys,
        ignored_keys,
        external_paths,
        source_use_probe,
        active_source_processes,
        generated_toml,
        warnings,
    };
    Ok(PreparedMigration {
        report,
        source_db,
        source_config,
        output,
        source_config_bytes,
        source_cfg,
    })
}

fn nearest_existing_parent(path: &Path) -> Option<&Path> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if candidate.exists() {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn external_path_checks(cfg: &Config) -> Vec<ExternalPathCheck> {
    let mut checks = Vec::new();
    if !cfg.relay.write_policy_plugin.is_empty() {
        let executable = cfg
            .relay
            .write_policy_plugin
            .split_whitespace()
            .next()
            .unwrap_or_default();
        let found = crate::doctor::find_executable(executable);
        checks.push(ExternalPathCheck {
            name: "write-policy",
            ok: found.is_some(),
            path: executable.into(),
            detail: found
                .map(|path| format!("executable {}", path.display()))
                .unwrap_or_else(|| format!("cannot find executable {executable:?}")),
        });
    }
    if cfg.relay.unix.enabled {
        let path = &cfg.relay.unix.path;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let exists = parent.is_dir();
        let writable = exists
            && unsafe {
                let Ok(cpath) = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
                else {
                    return checks;
                };
                libc::access(cpath.as_ptr(), libc::W_OK) == 0
            };
        checks.push(ExternalPathCheck {
            name: "unix-socket",
            ok: exists && writable,
            path: path.display().to_string(),
            detail: if !exists {
                format!("parent {} does not exist", parent.display())
            } else if !writable {
                format!("parent {} is not writable", parent.display())
            } else {
                format!("parent {} is writable", parent.display())
            },
        });
    }
    checks
}

fn probe_source_processes(source_db: &Path) -> (String, Vec<SourceProcess>) {
    let data = source_db.join("data.mdb");
    let output = match Command::new("lsof")
        .args(["-F", "pc", "--"])
        .arg(&data)
        .output()
    {
        Ok(output) => output,
        Err(error) => return (format!("unavailable: {error}"), Vec::new()),
    };
    // lsof exits 1 when no files match, which is a successful empty probe.
    if !output.status.success() && output.status.code() != Some(1) {
        return (
            format!(
                "unavailable: lsof exited {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "by signal".into())
            ),
            Vec::new(),
        );
    }
    let mut processes = Vec::new();
    let mut pid = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(value) = line.strip_prefix('p') {
            pid = value.parse::<u32>().ok();
        } else if let (Some(value), Some(pid)) = (line.strip_prefix('c'), pid.take()) {
            if pid != std::process::id() {
                processes.push(SourceProcess {
                    pid,
                    command: value.to_string(),
                });
            }
        }
    }
    ("available (lsof)".into(), processes)
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
                "db = \"{}\"\nrelay {{ port = 7777\n info {{ nips = \"1,2,3\" }} }}\n",
                source_db.display()
            ),
        )
        .unwrap();
        let source_data_before = sha256_file(&source_db.join("data.mdb")).unwrap();

        let preflight = prepare_strfry(&source_db, &source_config, &output).unwrap();
        assert!(preflight.report.ok, "{:#?}", preflight.report);
        assert_eq!(preflight.report.event_count, 1);
        assert!(preflight
            .report
            .translated_keys
            .contains(&"relay.port".to_string()));
        assert_eq!(preflight.report.ignored_keys, ["relay.info.nips"]);
        assert!(preflight.report.generated_toml.contains("[database]"));
        assert!(!output.exists(), "preflight created its output directory");
        assert_eq!(
            sha256_file(&source_db.join("data.mdb")).unwrap(),
            source_data_before,
            "preflight modified the source data.mdb"
        );

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
        let txn = target.begin_ro().unwrap();
        let mut search_hits = Vec::new();
        wok_query::foreach_by_filter(
            &txn,
            &json!({"search":"migration fixture"}),
            100,
            3,
            |lev_id| search_hits.push(lev_id),
        )
        .unwrap();
        assert_eq!(search_hits.len(), 1, "migrated event was not searchable");
        drop(txn);

        let output_cfg = Config::load(output.join("wok.toml")).unwrap();
        assert_eq!(output_cfg.db, output.join("db"));
        assert_eq!(output_cfg.relay.port, 7777);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join(MANIFEST_NAME)).unwrap()).unwrap();
        assert_eq!(manifest["event_count"], 1);
        assert_eq!(manifest["source_db_version"], 3);
        assert_eq!(manifest["target_db_version"], 4);
        assert_eq!(manifest["verification"]["event_records_unchanged"], true);
        assert_eq!(manifest["ignored_config_keys"], json!(["relay.info.nips"]));
        assert!(manifest["translated_config_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "relay.port"));
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
