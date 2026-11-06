//! Offline operator boundary for verified, full-state LMDB conversion.
//!
//! The storage crate owns copying and validation. This module owns explicit
//! paths, disk preflight, retained staging, the manifest, and publication.

use anyhow::Result;
use anyhow::{bail, Context};
use clap::Args;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct Options {
    /// Stopped Wok LMDB v4/v5 database directory (not a strfry database)
    #[arg(long)]
    pub source: PathBuf,
    /// New RocksDB directory; its parent must already exist
    #[arg(long)]
    pub output: PathBuf,
    /// Acknowledge that every relay and utility using the source is stopped
    #[arg(long)]
    pub confirm_relay_stopped: bool,
    /// Inspect source and capacity without creating a destination
    #[arg(long)]
    pub check: bool,
    /// Emit one machine-readable outcome, including on failure
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct Execution {
    phase: &'static str,
    staging_directory: Option<PathBuf>,
    verified_copy: bool,
    output_published: bool,
}
impl Default for Execution {
    fn default() -> Self {
        Self {
            phase: "preflight",
            staging_directory: None,
            verified_copy: false,
            output_published: false,
        }
    }
}

pub fn run(options: Options) -> Result<()> {
    let mut execution = Execution::default();
    let result = enabled::execute(&options, &mut execution);
    match result {
        Ok(report) => emit(&report, options.json),
        Err(error) => {
            let report = json!({
                "format":"wok-lmdb-to-rocksdb-outcome-v1", "ok":false,
                "source":options.source.to_string_lossy(), "output":options.output.to_string_lossy(),
                "check_only":options.check, "execution":execution,
                "error":format!("{error:#}")
            });
            // A retained failure report is useful even when stdout is lost.
            if let Some(staging) = &execution.staging_directory {
                if let Err(save_error) =
                    enabled::write_json_new(&staging.join("failure.json"), &report)
                {
                    tracing::warn!("could not save migration failure report: {save_error:#}");
                }
            }
            if options.json {
                emit(&report, true)?;
            }
            let retained = execution
                .staging_directory
                .as_ref()
                .map(|path| format!("; staging retained at {}", path.display()))
                .unwrap_or_default();
            Err(error.context(format!(
                "migration stopped during {} (output published: {}, verified copy: {}){retained}",
                execution.phase, execution.output_published, execution.verified_copy
            )))
        }
    }
}

fn emit(report: &Value, as_json: bool) -> Result<()> {
    let text = if as_json {
        serde_json::to_string_pretty(report)?
    } else {
        report["message"]
            .as_str()
            .unwrap_or("Migration checked")
            .to_owned()
    };
    match writeln!(io::stdout().lock(), "{text}") {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

mod enabled {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Component, Path};
    use std::time::{SystemTime, UNIX_EPOCH};
    use wok_db::{
        inspect_lmdb_source, migrate_lmdb_to_rocksdb, Env, EnvOptions, LmdbSourceReport,
        LmdbToRocksOptions,
    };

    const MANIFEST: &str = "wok-migration-manifest.json";
    const MANIFEST_SHA: &str = "wok-migration-manifest.sha256";
    const RESERVE_BYTES: u64 = 2 << 30;

    fn sync_directory(path: &Path) -> Result<()> {
        File::open(path)?
            .sync_all()
            .with_context(|| format!("sync {}", path.display()))
    }

    pub(super) fn write_json_new(path: &Path, value: &Value) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        write_new(path, &bytes)?;
        sync_directory(path.parent().context("report path has no parent")?)?;
        Ok(bytes)
    }

    fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn paths(options: &Options) -> Result<(PathBuf, PathBuf)> {
        if options.source.to_str().is_none() || options.output.to_str().is_none() {
            bail!("source and output paths must be valid UTF-8 for the migration manifest");
        }
        let source = options
            .source
            .canonicalize()
            .context("resolve source database")?;
        if !source.is_dir() {
            bail!("source must be an LMDB database directory");
        }
        // Reject ambiguous traversal rather than resolving a missing path
        // through a symlink or creating parents during a check-only command.
        if options
            .output
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            bail!("output path must not contain '..'");
        }
        let name = options
            .output
            .file_name()
            .context("output needs a new directory name")?;
        let parent = options
            .output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()
            .context("destination parent must already exist")?;
        if !parent.is_dir() {
            bail!("destination parent is not a directory");
        }
        let output = parent.join(name);
        if source.to_str().is_none() || output.to_str().is_none() {
            bail!("source and output paths must be valid UTF-8 for the migration manifest");
        }
        if output.starts_with(&source) || source.starts_with(&output) {
            bail!("source and output must not overlap");
        }
        match fs::symlink_metadata(&output) {
            Ok(_) => bail!(
                "output {} already exists; refusing to replace it",
                output.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok((source, output))
    }

    fn disk_preflight(source: &LmdbSourceReport, parent: &Path) -> Result<Value> {
        let required = source
            .data_file_bytes
            .checked_mul(3)
            .and_then(|n| n.checked_add(RESERVE_BYTES))
            .context("disk estimate overflow")?;
        let available = crate::doctor::available_bytes(parent).map_err(anyhow::Error::msg)?;
        Ok(
            json!({"available_bytes":available,"required_free_bytes":required,
            "sufficient":available >= required,
            "estimate":"three times source data.mdb size plus 2 GiB; not a bound on native compaction peaks"}),
        )
    }

    pub(super) fn execute(options: &Options, execution: &mut Execution) -> Result<Value> {
        if !options.check && !options.confirm_relay_stopped {
            bail!("stop every source relay/utility, then pass --confirm-relay-stopped");
        }
        let (source, output) = paths(options)?;
        let parent = output.parent().context("output has no parent")?;
        let inspected = inspect_lmdb_source(&source).context("inspect Wok LMDB source")?;
        let disk = disk_preflight(&inspected, parent)?;
        if !disk["sufficient"].as_bool().unwrap_or(false) {
            bail!("insufficient destination space: {} bytes available, {} bytes required by the conservative estimate",
                disk["available_bytes"], disk["required_free_bytes"]);
        }
        if options.check {
            return Ok(
                json!({"format":"wok-lmdb-to-rocksdb-preflight-v1","ok":true,
                "check_only":true,"source":inspected,"output":output,"disk":disk,
                "relay_stopped_acknowledged":options.confirm_relay_stopped,
                "message":format!("Preflight passed: Wok LMDB v{} → RocksDB v{} at {}. No output created. Stop all source users before migration; copying requires --confirm-relay-stopped. Estimated free-space floor: {} bytes.",
                    inspected.db_version,inspected.target_db_version,output.display(),disk["required_free_bytes"])}),
            );
        }
        execution.phase = "copy";
        let staging = tempfile::Builder::new()
            .prefix(".wok-rocksdb-migrate-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .context("create migration staging directory")?
            .keep();
        execution.staging_directory = Some(staging.clone());
        sync_directory(parent)?;
        write_json_new(
            &staging.join("owner.json"),
            &json!({
                "format":"wok-lmdb-to-rocksdb-staging-v1","source":source,"output":output,
                "wok_version":env!("CARGO_PKG_VERSION")
            }),
        )?;
        let database = staging.join("db");
        let copied = migrate_lmdb_to_rocksdb(&source, &database, &LmdbToRocksOptions::default())
            .context("copy and verify full logical state")?;
        execution.phase = "manifest";
        if !copied.verified
            || !copied.sealed
            || !copied.source_unchanged
            || copied
                .tables
                .iter()
                .any(|t| t.expected_target_sha256 != t.target_sha256)
        {
            bail!("storage migration did not return a sealed, unchanged-source, verified copy");
        }
        execution.verified_copy = true;
        let manifest = json!({"format":"wok-lmdb-to-rocksdb-migration-v1",
            "wok_version":env!("CARGO_PKG_VERSION"),"source":source,"output":output,
            "created_at_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "relay_stopped_acknowledged":true,"disk_preflight":disk,"migration":copied});
        let bytes = write_json_new(&database.join(MANIFEST), &manifest)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        write_new(
            &database.join(MANIFEST_SHA),
            format!("{digest}  {MANIFEST}\n").as_bytes(),
        )?;
        if fs::read(database.join(MANIFEST))? != bytes
            || fs::read_to_string(database.join(MANIFEST_SHA))? != format!("{digest}  {MANIFEST}\n")
        {
            bail!("migration manifest verification failed");
        }
        execution.phase = "reopen";
        let reopened = Env::open(
            &database,
            EnvOptions {
                read_only: true,
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::default()
            },
        )
        .context("reopen verified RocksDB read-only")?;
        if reopened.db_version()? != inspected.target_db_version {
            bail!("reopened database has an unexpected logical version");
        }
        drop(reopened);
        fs::set_permissions(&database, fs::Permissions::from_mode(0o700))?;
        sync_directory(&database)?;
        execution.phase = "publish";
        wok_db::backup::promote_directory_noreplace(&database, &output)?;
        execution.output_published = true;
        sync_directory(&staging)?;
        sync_directory(parent)?;
        // The database is now published. Keep the small staging receipt rather
        // than risk confusing metadata cleanup with failure of the conversion.
        execution.phase = "complete";
        Ok(json!({"format":"wok-lmdb-to-rocksdb-outcome-v1","ok":true,
            "check_only":false,"output":output,"manifest":output.join(MANIFEST),
            "manifest_sha256":digest,"migration":copied,"execution":execution,
            "message":format!("Verified {} events and {} logical tables; RocksDB published at {}. Source LMDB retained at {}. Manifest: {}. Point the RocksDB relay configuration at the new directory when ready.",
                copied.verified_events,copied.tables.len(),output.display(),source.display(),output.join(MANIFEST).display())}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn explicit_paths_parse_independently_of_service_configuration() {
        let cli = crate::Cli::try_parse_from([
            "wok",
            "--config",
            "/missing/service.toml",
            "migrate",
            "rocksdb",
            "--source",
            "/source",
            "--output",
            "/new",
            "--check",
            "--json",
        ])
        .unwrap();
        let crate::Command::Migrate {
            cmd: crate::MigrateCmd::Rocksdb(options),
        } = cli.cmd
        else {
            panic!("wrong command");
        };
        assert!(options.check && options.json && !options.confirm_relay_stopped);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_paths_fail_without_panicking_or_creating_output() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = tempfile::tempdir().unwrap();
        let invalid = root
            .path()
            .join(OsString::from_vec(b"source-\xff".to_vec()));
        let valid = root.path().join("source");
        // APFS rejects invalid UTF-8 names itself; argument rejection must work
        // before filesystem access on every platform.
        std::fs::create_dir(&valid).unwrap();
        for (source, output) in [
            (invalid.clone(), root.path().join("output")),
            (
                valid,
                root.path()
                    .join(OsString::from_vec(b"output-\xff".to_vec())),
            ),
        ] {
            let error = run(Options {
                source,
                output: output.clone(),
                confirm_relay_stopped: true,
                check: true,
                json: false,
            })
            .unwrap_err();
            assert!(format!("{error:#}").contains("valid UTF-8"));
            assert!(!output.exists());
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[allow(unsafe_code)]
    mod native {
        use super::*;
        use lmdb_sys::*;
        use sha2::{Digest, Sha256};
        use std::ffi::CString;
        use std::fs;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::path::Path;
        use std::ptr;
        use wok_db::{Env, EnvOptions};

        // Test-only LMDB handles let the RocksDB CLI exercise its actual
        // cross-backend operator boundary without a public fixture API.
        struct Fixture {
            env: *mut MDB_env,
            txn: *mut MDB_txn,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                // SAFETY: fixture exclusively owns these native handles;
                // commit clears txn and every borrowed value is already gone.
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
        fn fixture(path: &Path, corrupt: bool) {
            fs::create_dir(path).unwrap();
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let mut owner = Fixture {
                env: ptr::null_mut(),
                txn: ptr::null_mut(),
            };
            // SAFETY: out-pointers/byte slices live for each synchronous call;
            // this one-thread fixture writes only its own temporary directory.
            unsafe {
                assert_eq!(mdb_env_create(&mut owner.env), 0);
                assert_eq!(mdb_env_set_maxdbs(owner.env, 64), 0);
                assert_eq!(mdb_env_set_mapsize(owner.env, 16 << 20), 0);
                assert_eq!(mdb_env_open(owner.env, path.as_ptr(), MDB_NOTLS, 0o640), 0);
                assert_eq!(
                    mdb_txn_begin(owner.env, ptr::null_mut(), 0, &mut owner.txn),
                    0
                );
                for (index, spec) in wok_db::schema::dbi_specs().iter().enumerate() {
                    let name = CString::new(spec.name).unwrap();
                    let mut dbi = 0;
                    assert_eq!(
                        mdb_dbi_open(owner.txn, name.as_ptr(), spec.flags, &mut dbi),
                        0
                    );
                    let row = match index + 1 {
                        1 => Some((
                            1u64.to_ne_bytes().to_vec(),
                            wok_db::encode_meta(&wok_db::Meta {
                                db_version: 5,
                                endianness: 1,
                                negentropy_modification_counter: 7,
                            }),
                        )),
                        3 if corrupt => Some((
                            1u64.to_ne_bytes().to_vec(),
                            b"invalid packed event".to_vec(),
                        )),
                        15 if corrupt => {
                            Some((1u64.to_ne_bytes().to_vec(), b"invalid payload".to_vec()))
                        }
                        20 => Some((b"opaque-operator-state".to_vec(), b"\0\xffkept".to_vec())),
                        _ => None,
                    };
                    if let Some((key, value)) = row {
                        let mut key = MDB_val {
                            mv_size: key.len(),
                            mv_data: key.as_ptr().cast_mut().cast(),
                        };
                        let mut value = MDB_val {
                            mv_size: value.len(),
                            mv_data: value.as_ptr().cast_mut().cast(),
                        };
                        assert_eq!(mdb_put(owner.txn, dbi, &mut key, &mut value, 0), 0);
                    }
                }
                let txn = std::mem::replace(&mut owner.txn, ptr::null_mut());
                assert_eq!(mdb_txn_commit(txn), 0);
            }
        }
        fn options(source: &Path, output: &Path) -> Options {
            Options {
                source: source.into(),
                output: output.into(),
                confirm_relay_stopped: true,
                check: false,
                json: false,
            }
        }
        fn readonly(path: &Path) -> Result<Env, wok_db::DbError> {
            Env::open(
                path,
                EnvOptions {
                    read_only: true,
                    create_dir: false,
                    create_dbis: false,
                    ..EnvOptions::for_tests()
                },
            )
        }

        #[test]
        fn preflight_then_full_state_publication_preserves_source_and_manifest() {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("lmdb");
            fixture(&source, false);
            let before = Sha256::digest(fs::read(source.join("data.mdb")).unwrap());
            let output = root.path().join("rocks");
            let mut options = options(&source, &output);
            options.check = true;
            options.confirm_relay_stopped = false;
            let mut execution = Execution::default();
            let check = enabled::execute(&options, &mut execution).unwrap();
            assert_eq!(check["ok"], true);
            assert!(!output.exists());
            assert!(execution.staging_directory.is_none());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);

            options.check = false;
            assert!(enabled::execute(&options, &mut execution)
                .unwrap_err()
                .to_string()
                .contains("--confirm-relay-stopped"));
            options.confirm_relay_stopped = true;
            let report = enabled::execute(&options, &mut execution).unwrap();
            assert_eq!(report["ok"], true);
            assert!(execution.output_published && execution.verified_copy);
            assert_eq!(
                fs::metadata(execution.staging_directory.as_ref().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                Sha256::digest(fs::read(source.join("data.mdb")).unwrap()),
                before
            );
            let manifest = fs::read(output.join("wok-migration-manifest.json")).unwrap();
            let hash = hex::encode(Sha256::digest(&manifest));
            assert_eq!(report["manifest_sha256"], hash);
            assert_eq!(
                fs::read_to_string(output.join("wok-migration-manifest.sha256")).unwrap(),
                format!("{hash}  wok-migration-manifest.json\n")
            );
            let manifest: Value = serde_json::from_slice(&manifest).unwrap();
            assert_eq!(manifest["migration"]["verified"], true);
            assert_eq!(manifest["migration"]["source_unchanged"], true);
            assert_eq!(manifest["migration"]["sealed"], true);
            let env = readonly(&output).unwrap();
            assert_eq!(env.db_version().unwrap(), 5);
            assert_eq!(
                env.begin_ro()
                    .unwrap()
                    .get(env.dbis().state.unwrap(), b"opaque-operator-state")
                    .unwrap(),
                Some(b"\0\xffkept".as_slice())
            );
            drop(env);
            assert!(enabled::execute(&options, &mut Execution::default()).is_err());
        }

        #[test]
        fn refused_paths_never_create_a_staging_directory() {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            let exists = root.path().join("exists");
            fs::create_dir(&exists).unwrap();
            let dangling = root.path().join("dangling");
            symlink("not-present", &dangling).unwrap();
            for output in [
                source.join("nested"),
                exists,
                dangling,
                root.path().join("../escape"),
            ] {
                let mut state = Execution::default();
                let err = enabled::execute(&options(&source, &output), &mut state).unwrap_err();
                assert!(!format!("{err:#}").contains("inspect Wok LMDB"));
                assert!(state.staging_directory.is_none());
                assert!(!state.output_published);
            }
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
        }

        #[test]
        fn invalid_source_retains_incomplete_staging_without_publishing() {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            fixture(&source, true);
            let before = Sha256::digest(fs::read(source.join("data.mdb")).unwrap());
            let output = root.path().join("output");
            let mut state = Execution::default();
            assert!(enabled::execute(&options(&source, &output), &mut state).is_err());
            assert!(!output.exists() && !state.output_published && !state.verified_copy);
            let stage = state.staging_directory.unwrap();
            assert_eq!(
                fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert!(stage.join("owner.json").is_file());
            assert!(stage.join("db").is_dir());
            assert!(readonly(&stage.join("db")).is_err());
            assert_eq!(
                Sha256::digest(fs::read(source.join("data.mdb")).unwrap()),
                before
            );
        }
    }
}
