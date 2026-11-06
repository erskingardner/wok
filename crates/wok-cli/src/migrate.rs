#![allow(unsafe_code)]

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use wok_db::{
    audit_strfry_source, migrate_strfry_to_rocksdb, Env, EnvOptions, EnvironmentStats,
    EventVerificationReport, IntegrityReport, LmdbSourceReport, LmdbToRocksOptions,
    LmdbToRocksReport,
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
    superseded_groups: u64,
    superseded_events: u64,
    legacy_long_tag_records: u64,
    event_fingerprint_sha256: String,
    source_data_sha256: String,
    target_files: Vec<NativeFile>,
    native_migration: LmdbToRocksReport,
    /// Native table hashes above describe the raw copy, before new Wok-only derived tables were initialized.
    destination_derived_tables_initialized: bool,
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
    source_events_verified: bool,
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
    pub source_logical_state: LmdbSourceReport,
    pub event_fingerprint_sha256: String,
    pub estimated_output_bytes: u64,
    pub available_output_bytes: Option<u64>,
    pub lmdb: EnvironmentStats,
    pub source_integrity: IntegrityReport,
    /// Each event against its payload when full verification was requested.
    pub event_verification: Option<EventVerificationReport>,
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
    source_audit: wok_db::StrfrySourceAudit,
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
        if let Some(verification) = &self.event_verification {
            if verification.ok() {
                out.push_str(&format!(
                    "Event verification: PASS ({} events)\n",
                    verification.events
                ));
            } else {
                out.push_str(&format!(
                    "Event verification: FAIL ({} of {} events)\n",
                    verification.failed, verification.events
                ));
                out.push_str(&failure_lines(verification));
            }
        }
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
    let prepared = prepare_strfry(source_db, source_config, output, true)?;
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

/// Caller must acknowledge that all source users are stopped before copying.
pub fn migrate_strfry(source_db: &Path, source_config: &Path, output: &Path) -> Result<()> {
    let prepared = prepare_strfry(source_db, source_config, output, true)?;
    if let Some(verification) = &prepared.report.event_verification {
        if !verification.ok() {
            bail!(
                "{} of {} source events do not verify against their stored payloads:\n{}\
                Restore or repair the source before migrating.",
                verification.failed,
                verification.events,
                failure_lines(verification)
            );
        }
    }
    if !prepared.report.ok {
        bail!(
            "migration preflight failed; run `wok migrate strfry --check` for the complete report"
        );
    }
    if !prepared.report.active_source_processes.is_empty() {
        bail!("source database is in use; stop every source relay and utility");
    }
    let PreparedMigration {
        report,
        source_db,
        source_config,
        output,
        source_config_bytes,
        source_cfg,
        source_audit,
    } = prepared;
    let parent = output.parent().context("output path has no parent")?;
    let source_identity = source_file_identity(&source_db.join("data.mdb"))?;
    let source_data_sha256 = sha256_file(&source_db.join("data.mdb"))?;
    // Keep immediately: every failed copy/manifest/promotion remains private
    // and available for diagnosis. Nothing is automatically deleted or reused.
    let staging = tempfile::Builder::new()
        .prefix(".wok-migrate-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .context("create private migration staging")?
        .keep();
    let result = (|| -> Result<()> {
        let staging_db = staging.join("db");
        let copied =
            migrate_strfry_to_rocksdb(&source_db, &staging_db, &LmdbToRocksOptions::default())
                .context("direct read-only strfry v3 to RocksDB conversion")?;
        if !copied.verified
            || !copied.sealed
            || !copied.source_unchanged
            || copied.source.transaction_id != report.source_logical_state.transaction_id
            || copied.primary_fingerprint_sha256 != report.event_fingerprint_sha256
        {
            bail!("source state changed since preflight or conversion was not fully verified");
        }
        // The sixteen imported tables stay byte-identical except Meta version.
        // Only new, derived Wok indexes/bookkeeping are initialized here.
        let target = Env::open(
            &staging_db,
            EnvOptions {
                create_dir: false,
                ..EnvOptions::default()
            },
        )
        .context("open verified RocksDB destination")?;
        wok_db::backend_migration::initialize_strfry_derived_state(&target, &copied, &source_audit)
            .context("initialize verified replacement-history bookkeeping without a legacy scan")?;
        target.ensure_initialized()?;
        wok_db::finish_search_index(&target).context("build destination search index")?;
        let after = wok_db::backend_migration::verify_rocksdb_events_bounded(&target)?;
        if after.count != report.event_count
            || hex::encode(after.sha256) != copied.primary_fingerprint_sha256
        {
            bail!("stored event bytes changed during destination initialization");
        }
        target.check_background_errors()?;
        drop(target);
        if source_file_identity(&source_db.join("data.mdb"))? != source_identity
            || sha256_file(&source_db.join("data.mdb"))? != source_data_sha256
            || wok_db::inspect_strfry_source(&source_db)?.transaction_id
                != copied.source.transaction_id
            || std::fs::read(&source_config)? != source_config_bytes
        {
            bail!("source database/config changed during migration");
        }
        let final_db = output.join("db");
        let final_config = output.join("wok.toml");
        let config = translated_config(&source_cfg, &final_db)?;
        if Config::parse_toml(&config).map_err(anyhow::Error::msg)?.db != final_db {
            bail!("translated config does not select the migrated database");
        }
        write_new(&staging.join("wok.toml"), config.as_bytes())?;
        let manifest=MigrationManifest {
            format_version:2,source_type:"strfry-lmdb-v3",source_db:source_db.display().to_string(),
            source_config:source_config.display().to_string(),source_db_version:3,
            target_db:final_db.display().to_string(),target_config:final_config.display().to_string(),
            target_db_version:wok_event::WOK_DB_VERSION,wok_version:env!("CARGO_PKG_VERSION"),
            migrated_at_unix_seconds:SystemTime::now().duration_since(UNIX_EPOCH)
                .context("system clock is before Unix epoch")?.as_secs(),
            event_count:after.count,superseded_groups:report.source_integrity.superseded_groups,
            superseded_events:report.source_integrity.superseded_events,
            legacy_long_tag_records:report.source_integrity.legacy_long_tag_records,
            event_fingerprint_sha256:hex::encode(after.sha256),source_data_sha256,
            target_files:native_inventory(&staging_db)?,native_migration:copied,
            destination_derived_tables_initialized:true,
            source_config_sha256:sha256_bytes(&source_config_bytes),
            output_config_sha256:sha256_bytes(config.as_bytes()),
            translated_config_keys:report.translated_keys.clone(),ignored_config_keys:report.ignored_keys.clone(),
            verification:Verification {source_integrity_ok:true,source_events_verified:true,
                event_records_unchanged:true,target_opens_as_wok:true},
            warnings:vec!["Source data.mdb and config retained unchanged; LMDB reader coordination can update lock.mdb.",
                "The destination is RocksDB and must never be opened by strfry.",
                "Only supported config settings were translated; review plugin, AUTH, abuse and socket policies.",
                "New ephemeral events are live-only by default; review events.ephemeral_persistence before cutover."]
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        write_new(&staging.join(MANIFEST_NAME), &bytes)?;
        write_new(
            &staging.join("migration-manifest.sha256"),
            format!("{}  {MANIFEST_NAME}\n", sha256_bytes(&bytes)).as_bytes(),
        )?;
        File::open(&staging)?.sync_all()?;
        wok_db::backup::promote_directory_noreplace(&staging, &output)
            .context("publish verified migration without replacing any existing output")?;
        File::open(parent)?.sync_all()?;
        println!(
            "Migrated {} events directly from strfry to RocksDB.",
            after.count
        );
        if report.source_integrity.superseded_events != 0 {
            println!("Retained {} superseded events in {} replacement groups; relay reads serve only the winners.",
                report.source_integrity.superseded_events,report.source_integrity.superseded_groups);
        }
        if report.source_integrity.legacy_long_tag_records != 0 {
            println!("Kept {} records as strfry packed them; `wok reindex --confirm-relay-stopped` indexes omitted long tag values.",report.source_integrity.legacy_long_tag_records);
        }
        if report.source_integrity.legacy_untombstoned_deletions != 0 {
            println!("{} deletion requests name replaceable events or kinds with leading zeros, which strfry did not tombstone; `wok reindex --confirm-relay-stopped` repairs those tombstones.",report.source_integrity.legacy_untombstoned_deletions);
        }
        println!(
            "Wok config: {}\nManifest: {}\nSource data and config were not modified.",
            final_config.display(),
            output.join(MANIFEST_NAME).display()
        );
        Ok(())
    })();
    result.with_context(|| {
        format!(
            "migration staging retained at {} (unless already published at {})",
            staging.display(),
            output.display()
        )
    })
}

#[derive(Serialize)]
struct NativeFile {
    path: String,
    bytes: u64,
    sha256: String,
}
fn source_file_identity(path: &Path) -> Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() {
        bail!("source data.mdb must remain a regular file");
    }
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}
fn native_inventory(path: &Path) -> Result<Vec<NativeFile>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            bail!("unexpected nonregular destination database entry");
        }
        files.push(NativeFile {
            path: entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 database filename"))?,
            bytes: entry.metadata()?.len(),
            sha256: sha256_file(&entry.path())?,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn failure_lines(verification: &EventVerificationReport) -> String {
    let mut out = String::new();
    for failure in &verification.failures {
        out.push_str(&format!(
            "  levId {} (id {}): {}\n",
            failure.lev_id, failure.id, failure.reason
        ));
    }
    let unnamed = verification.failed - verification.failures.len() as u64;
    if unnamed != 0 {
        out.push_str(&format!("  and {unnamed} more\n"));
    }
    out
}

/// With `verify`, also check each source event against its payload in one
/// registered snapshot. All source users must remain stopped during copying.
fn prepare_strfry(
    source_db: &Path,
    source_config: &Path,
    output: &Path,
    verify: bool,
) -> Result<PreparedMigration> {
    let source_db = absolute_existing(source_db, "source database")?;
    let source_config = absolute_existing(source_config, "source config")?;
    if !source_db.is_dir() {
        bail!(
            "source database '{}' is not a directory",
            source_db.display()
        );
    }
    if output
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("output must not contain parent traversal");
    }
    let output = std::path::absolute(output).context("resolve output path")?;
    let parent = output
        .parent()
        .context("output needs a parent")?
        .canonicalize()
        .context("output parent must already exist")?;
    let output = parent.join(
        output
            .file_name()
            .context("output needs a new directory name")?,
    );
    if output.starts_with(&source_db) || source_db.starts_with(&output) {
        bail!("source/output paths must not overlap");
    }
    if source_db.to_str().is_none() || source_config.to_str().is_none() || output.to_str().is_none()
    {
        bail!("migration paths must be valid UTF8");
    }
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
    let audit =
        audit_strfry_source(&source_db, verify).context("inspect strfry source read-only")?;
    let source_db_version = audit.source.db_version;
    let lmdb = audit.lmdb;
    let source_integrity = audit.integrity.clone();
    let event_verification = audit.event_verification.clone();
    let source_data_bytes = audit.source.data_file_bytes;
    // Planning floor, not an upper bound on WAL/compaction growth.
    let estimated_output_bytes = source_data_bytes.saturating_mul(2).saturating_add(2 << 30);
    let available_output_bytes =
        nearest_existing_parent(&output).and_then(|path| crate::doctor::available_bytes(path).ok());
    let external_paths = external_path_checks(&source_cfg);
    let output_available =
        std::fs::symlink_metadata(&output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    let mut warnings = Vec::new();
    if source_integrity.superseded_events != 0 {
        warnings.push(format!(
            "{} superseded events in {} replacement groups will be preserved by this lossless migration; relay reads serve only the winners",
            source_integrity.superseded_events, source_integrity.superseded_groups,
        ));
    }
    if let Some(warning) = source_cfg.auth_configuration_warning() {
        warnings.push(format!("{warning}; review AUTH before cutover"));
    }
    warnings.extend(source_cfg.deprecations.iter().cloned());
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
    if ignored_keys
        .iter()
        .any(|key| key.split('.').next() == Some("plugins") && key.ends_with(".cmd"))
    {
        warnings.push(
            "plugins.* arrays are not translated; set relay.write_policy_plugin to the plugin command"
                .into(),
        );
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
                "source LMDB map is {:.1}% full; the RocksDB destination does not use database.map_size",
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
        && event_verification
            .as_ref()
            .is_none_or(EventVerificationReport::ok)
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
        source_logical_state: audit.source.clone(),
        event_fingerprint_sha256: hex::encode(audit.fingerprint.sha256),
        estimated_output_bytes,
        available_output_bytes,
        lmdb,
        source_integrity,
        event_verification,
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
        source_audit: audit,
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
    // Migration is the highest-trust operation wok performs: resolve lsof at
    // a well-known absolute path first so a hijacked PATH can't substitute
    // arbitrary code; fall back to PATH lookup only if none exist.
    let lsof = ["/usr/bin/lsof", "/bin/lsof", "/usr/sbin/lsof", "/sbin/lsof"]
        .iter()
        .find(|candidate| Path::new(candidate).exists())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "lsof".to_string());
    let output = match Command::new(lsof)
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
    use wok_db::{encode_meta, EventToWrite, Meta};
    use wok_event::{parse_and_verify_event, EventLimits};

    fn fixture_dir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }

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
        assert!(translated.lines().any(|line| line == "preset = \"public\""));
    }

    #[test]
    fn migrates_verified_v3_snapshot_without_touching_source() {
        let temp = fixture_dir();
        let source_db = temp.path().join("strfry-db");
        let source_config = temp.path().join("strfry.conf");
        let output = temp.path().join("wok-output");

        let parsed = signed_event();
        strfry_source(
            &source_db,
            vec![EventToWrite::new(parsed.packed.into_bytes(), parsed.json)],
        );
        let source_fingerprint = audit_strfry_source(&source_db, true).unwrap().fingerprint;
        std::fs::write(
            &source_config,
            format!(
                "db = \"{}\"\nrelay {{ port = 7777\n info {{ nips = \"1,2,3\" }} }}\n",
                source_db.display()
            ),
        )
        .unwrap();
        let source_data_before = sha256_file(&source_db.join("data.mdb")).unwrap();

        let preflight = prepare_strfry(&source_db, &source_config, &output, true).unwrap();
        assert!(preflight.report.ok, "{:#?}", preflight.report);
        assert_eq!(preflight.report.event_count, 1);
        let verification = preflight.report.event_verification.as_ref().unwrap();
        assert_eq!((verification.events, verification.failed), (1, 0));
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

        let manifest_bytes = std::fs::read(output.join(MANIFEST_NAME)).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(
            std::fs::read_to_string(output.join("migration-manifest.sha256")).unwrap(),
            format!("{}  {MANIFEST_NAME}\n", sha256_bytes(&manifest_bytes))
        );
        assert_eq!(
            saved["target_files"],
            serde_json::to_value(native_inventory(&output.join("db")).unwrap()).unwrap()
        );
        assert!(saved["native_migration"]["verified"].as_bool().unwrap());
        assert!(saved["native_migration"]["source_unchanged"]
            .as_bool()
            .unwrap());
        assert_eq!(saved["format_version"], 2);
        assert!(
            !output.join("db/data.mdb").exists(),
            "destination must be native RocksDB"
        );

        assert_eq!(
            sha256_file(&source_db.join("data.mdb")).unwrap(),
            source_data_before,
            "migration modified the source data.mdb"
        );
        assert_eq!(
            wok_db::inspect_strfry_source(&source_db)
                .unwrap()
                .db_version,
            3
        );
        assert!(Env::open(&source_db, EnvOptions::for_tests()).is_err());
        let target = Env::open(output.join("db"), EnvOptions::for_tests()).unwrap();
        target.ensure_initialized().unwrap();
        assert_eq!(target.db_version().unwrap(), wok_event::WOK_DB_VERSION);
        assert_eq!(
            wok_db::event_fingerprint(&target).unwrap(),
            source_fingerprint
        );
        let txn = target.begin_ro().unwrap();
        let mut search_hits = Vec::new();
        wok_query::foreach_by_filter(
            &txn,
            &json!({"search":"migration fixture"}),
            100,
            3,
            16,
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
        assert_eq!(manifest["target_db_version"], wok_event::WOK_DB_VERSION);
        assert_eq!(manifest["verification"]["source_events_verified"], true);
        assert_eq!(manifest["verification"]["event_records_unchanged"], true);
        assert_eq!(manifest["ignored_config_keys"], json!(["relay.info.nips"]));
        assert!(manifest["translated_config_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "relay.port"));
    }

    #[test]
    fn refuses_sources_whose_events_do_not_verify() {
        let temp = fixture_dir();
        let source_db = temp.path().join("strfry-db");
        let source_config = temp.path().join("strfry.conf");
        let output = temp.path().join("wok-output");

        let packed = |event: &serde_json::Value| {
            wok_event::nostr_json_to_packed_event(event, &EventLimits::default())
                .unwrap()
                .into_bytes()
        };
        let tao = wok_event::json::to_tao_string;
        let good = signed("good", 1_700_000_000);
        // Another signed event's payload under this record.
        let swapped = signed("swapped", 1_700_000_001);
        let mut bad_sig = signed("bad signature", 1_700_000_002);
        let sig = bad_sig["sig"].as_str().unwrap().to_owned();
        bad_sig["sig"] = json!(format!("{}{}", &sig[64..], &sig[..64]));
        // The packed record moves the event a day later than it was signed.
        let moved = signed("moved", 1_700_000_003);
        let mut moved_packed = moved.clone();
        moved_packed["created_at"] = json!(1_700_086_403u64);
        strfry_source(
            &source_db,
            vec![
                EventToWrite::new(packed(&good), tao(&good)),
                EventToWrite::new(packed(&swapped), tao(&good)),
                EventToWrite::new(packed(&bad_sig), tao(&bad_sig)),
                EventToWrite::new(packed(&moved_packed), tao(&moved)),
            ],
        );
        std::fs::write(
            &source_config,
            format!("db = \"{}\"\n", source_db.display()),
        )
        .unwrap();

        let preflight = prepare_strfry(&source_db, &source_config, &output, true).unwrap();
        let report = &preflight.report;
        assert!(
            report.source_integrity.ok(),
            "{:#?}",
            report.source_integrity
        );
        assert!(!report.ok);
        let verification = report.event_verification.as_ref().unwrap();
        assert_eq!((verification.events, verification.failed), (4, 3));
        let mut reasons: Vec<_> = verification
            .failures
            .iter()
            .map(|failure| (failure.id.as_str(), failure.reason.as_str()))
            .collect();
        reasons.sort();
        let mut expected = vec![
            (
                swapped["id"].as_str().unwrap(),
                "payload id differs from the packed record",
            ),
            (bad_sig["id"].as_str().unwrap(), "bad signature"),
            (
                moved["id"].as_str().unwrap(),
                "payload created_at differs from the packed record",
            ),
        ];
        expected.sort();
        assert_eq!(reasons, expected);
        let human = report.render_human();
        assert!(
            human.contains("Event verification: FAIL (3 of 4 events)"),
            "{human}"
        );
        assert!(human.contains(bad_sig["id"].as_str().unwrap()), "{human}");

        // The migration itself verifies its snapshot, whatever the preflight
        // it repeats found.
        let error = migrate_strfry(&source_db, &source_config, &output)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("3 of 4 source events do not verify against their stored payloads"),
            "{error}"
        );
        for (id, reason) in expected {
            assert!(error.contains(&format!("(id {id}): {reason}")), "{error}");
        }
        assert!(!output.exists());
        let leftovers: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".wok-migrate-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// Synthetic v3 native fixture. It is never opened by the runtime Env.
    fn strfry_source(path: &Path, events: Vec<EventToWrite>) {
        use lmdb_sys::*;
        use std::os::unix::ffi::OsStrExt;
        use std::{ffi::CString, ptr};
        let root = fixture_dir();
        let fixture = Env::open(root.path().join("db"), EnvOptions::for_tests()).unwrap();
        fixture.ensure_initialized().unwrap();
        {
            let mut tx = fixture.begin_rw().unwrap();
            let mut events = events;
            wok_db::write_events(&mut tx, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
            assert!(events
                .iter()
                .all(|e| e.status == wok_db::EventWriteStatus::Written));
            tx.commit().unwrap();
        }
        std::fs::create_dir(path).unwrap();
        struct Native {
            env: *mut MDB_env,
            txn: *mut MDB_txn,
        }
        impl Drop for Native {
            fn drop(&mut self) {
                unsafe {
                    if !self.txn.is_null() {
                        mdb_txn_abort(self.txn);
                    }
                    if !self.env.is_null() {
                        mdb_env_close(self.env);
                    }
                }
            }
        }
        let mut owner = Native {
            env: ptr::null_mut(),
            txn: ptr::null_mut(),
        };
        // SAFETY: test-only handles exclusively own a new temporary native DB;
        // all borrowed row buffers and comparator callbacks outlive each call.
        unsafe {
            assert_eq!(mdb_env_create(&mut owner.env), 0);
            assert_eq!(mdb_env_set_maxdbs(owner.env, 64), 0);
            assert_eq!(mdb_env_set_mapsize(owner.env, 32 << 20), 0);
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(mdb_env_open(owner.env, name.as_ptr(), 0, 0o640), 0);
            assert_eq!(
                mdb_txn_begin(owner.env, ptr::null_mut(), 0, &mut owner.txn),
                0
            );
            let ro = fixture.begin_ro().unwrap();
            for (n, spec) in wok_db::schema::dbi_specs().iter().take(16).enumerate() {
                let name = CString::new(spec.name).unwrap();
                let mut dbi = 0;
                assert_eq!(
                    mdb_dbi_open(owner.txn, name.as_ptr(), spec.flags, &mut dbi),
                    0
                );
                let cmp = match spec.comparator {
                    wok_db::schema::ComparatorKind::Default => None,
                    wok_db::schema::ComparatorKind::StringUint64 => {
                        Some(wok_db::comparators::lmdb_comparator_string_u64 as *mut MDB_cmp_func)
                    }
                    wok_db::schema::ComparatorKind::Uint64Uint64 => {
                        Some(wok_db::comparators::lmdb_comparator_u64_u64 as *mut MDB_cmp_func)
                    }
                    wok_db::schema::ComparatorKind::StringUint64Uint64 => Some(
                        wok_db::comparators::lmdb_comparator_string_u64_u64 as *mut MDB_cmp_func,
                    ),
                };
                if let Some(cmp) = cmp {
                    assert_eq!(mdb_set_compare(owner.txn, dbi, cmp), 0);
                }
                ro.foreach_full(n as u32 + 1, &[], &[], false, |key, value| {
                    let normalized;
                    let value = if n == 0 && key == 1u64.to_ne_bytes() {
                        normalized = encode_meta(&Meta {
                            db_version: 3,
                            endianness: 1,
                            negentropy_modification_counter: 1,
                        });
                        normalized.as_slice()
                    } else {
                        value
                    };
                    let mut key = MDB_val {
                        mv_size: key.len(),
                        mv_data: key.as_ptr().cast_mut().cast(),
                    };
                    let mut value = MDB_val {
                        mv_size: value.len(),
                        mv_data: value.as_ptr().cast_mut().cast(),
                    };
                    assert_eq!(mdb_put(owner.txn, dbi, &mut key, &mut value, 0), 0);
                    true
                })
                .unwrap();
            }
            let tx = std::mem::replace(&mut owner.txn, ptr::null_mut());
            assert_eq!(mdb_txn_commit(tx), 0);
        }
    }

    fn signed(content: &str, created_at: u64) -> serde_json::Value {
        use secp256k1::{Keypair, SECP256K1};
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = keypair.x_only_public_key();
        let mut event = json!({
            "created_at": created_at,
            "kind": 1,
            "tags": [],
            "content": content,
            "pubkey": hex::encode(pubkey.serialize()),
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        let sig = SECP256K1.sign_schnorr(&id, &keypair);
        event["sig"] = json!(hex::encode(sig.as_ref()));
        event
    }

    fn signed_event() -> wok_event::ParsedEvent {
        let event = signed("migration fixture", 1_700_000_000);
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap()
    }
}
