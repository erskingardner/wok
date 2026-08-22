#![allow(unsafe_code)]

use serde::Serialize;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use wok_db::{
    check_integrity, event_json_owned, foreach_negentropy_filter, Decompressor, Env, EnvOptions,
    EnvironmentStats, IntegrityReport,
};
use wok_event::PackedEventView;
use wok_relay::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
    pub database: Option<EnvironmentStats>,
    pub integrity: Option<IntegrityReport>,
}

impl DoctorReport {
    fn new() -> Self {
        Self {
            ok: true,
            checks: Vec::new(),
            database: None,
            integrity: None,
        }
    }

    fn add(&mut self, name: impl Into<String>, status: CheckStatus, detail: impl Into<String>) {
        if status == CheckStatus::Fail {
            self.ok = false;
        }
        self.checks.push(DoctorCheck {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }

    pub fn render_human(&self) -> String {
        let mut output = String::new();
        for check in &self.checks {
            let status = match check.status {
                CheckStatus::Pass => "PASS",
                CheckStatus::Warn => "WARN",
                CheckStatus::Fail => "FAIL",
            };
            output.push_str(&format!("{status:4} {:24} {}\n", check.name, check.detail));
        }
        output.push_str(if self.ok {
            "Doctor result: healthy\n"
        } else {
            "Doctor result: failures found\n"
        });
        output
    }
}

pub fn run(cfg: &Config, config_path: &Path) -> DoctorReport {
    let mut report = DoctorReport::new();
    if config_path.is_file() {
        report.add(
            "config",
            CheckStatus::Pass,
            format!("loaded {}", config_path.display()),
        );
    } else {
        report.add(
            "config",
            CheckStatus::Warn,
            format!("{} is absent; defaults are in use", config_path.display()),
        );
    }

    match cfg.auth_configuration_warning() {
        Some(detail) => report.add("relay-auth", CheckStatus::Warn, detail),
        None => report.add(
            "relay-auth",
            CheckStatus::Pass,
            "restricted reads have usable NIP-42 authentication or are disabled",
        ),
    }

    // Hot-reload merges the file over factory defaults, so a truncated or
    // partially-provisioned file silently weakens these scopes; surface
    // their current state so operators can spot the reversion.
    report.add(
        "write-policy-plugin",
        if cfg.relay.write_policy_plugin.is_empty() {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        },
        if cfg.relay.write_policy_plugin.is_empty() {
            "no write-policy plugin configured".to_string()
        } else {
            format!("write-policy plugin: {}", cfg.relay.write_policy_plugin)
        },
    );
    report.add(
        "filter-validation",
        if cfg.relay.filter_validation.enabled {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        if cfg.relay.filter_validation.enabled {
            "ingress filter validation is enabled".to_string()
        } else {
            "ingress filter validation is disabled".to_string()
        },
    );
    report.add(
        "abuse-limits",
        if cfg.relay.abuse.enabled {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        if cfg.relay.abuse.enabled {
            "abuse rate limits and quotas are enabled".to_string()
        } else {
            "abuse rate limits and quotas are disabled".to_string()
        },
    );

    if !cfg.db.is_dir() {
        report.add(
            "database-path",
            CheckStatus::Fail,
            format!("{} is not a directory", cfg.db.display()),
        );
        return report;
    }
    for filename in ["data.mdb", "lock.mdb"] {
        let path = cfg.db.join(filename);
        report.add(
            format!("database-{filename}"),
            if path.is_file() {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            path.display().to_string(),
        );
    }

    check_external_paths(cfg, &mut report);

    let env = match Env::open(
        &cfg.db,
        EnvOptions {
            max_readers: cfg.db_maxreaders,
            map_size: cfg.db_mapsize,
            no_read_ahead: cfg.db_no_read_ahead,
            create_dir: false,
            create_dbis: false,
            read_only: true,
            ..EnvOptions::default()
        },
    ) {
        Ok(env) => env,
        Err(error) => {
            report.add("database-open", CheckStatus::Fail, error.to_string());
            return report;
        }
    };
    report.add(
        "database-open",
        CheckStatus::Pass,
        "all authoritative DBIs opened",
    );
    report.add(
        "search-index",
        if env.dbis().event_search.is_some() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        if env.dbis().event_search.is_some() {
            "NIP-50 derived index is present"
        } else {
            "NIP-50 derived index is absent and will be backfilled on the next writable open"
        },
    );

    match env.db_meta() {
        Ok(Some(meta)) => {
            report.add(
                "database-version",
                if meta.db_version == wok_event::WOK_DB_VERSION {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                format!(
                    "found {}, expected {}",
                    meta.db_version,
                    wok_event::WOK_DB_VERSION
                ),
            );
            report.add(
                "database-endianness",
                if meta.endianness == 1 && cfg!(target_endian = "little") {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                format!(
                    "marker={}, host={}",
                    meta.endianness,
                    if cfg!(target_endian = "little") {
                        "little"
                    } else {
                        "big"
                    }
                ),
            );
        }
        Ok(None) => report.add(
            "database-meta",
            CheckStatus::Fail,
            "Meta record 1 is missing",
        ),
        Err(error) => report.add("database-meta", CheckStatus::Fail, error.to_string()),
    }

    match env.stats() {
        Ok(stats) => {
            let utilization = if stats.map_size == 0 {
                100.0
            } else {
                stats.used_bytes as f64 * 100.0 / stats.map_size as f64
            };
            let status = if utilization >= 90.0 {
                CheckStatus::Fail
            } else if utilization >= 75.0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            };
            report.add(
                "lmdb-map",
                status,
                format!(
                    "{} of {} bytes used ({utilization:.1}%)",
                    stats.used_bytes, stats.map_size
                ),
            );
            report.database = Some(stats);
        }
        Err(error) => report.add("lmdb-map", CheckStatus::Fail, error.to_string()),
    }

    match available_bytes(&cfg.db) {
        Ok(bytes) => report.add(
            "free-space",
            if bytes < 1_073_741_824 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            format!("{bytes} bytes available"),
        ),
        Err(error) => report.add("free-space", CheckStatus::Warn, error),
    }

    match env.begin_ro() {
        Ok(txn) => {
            match check_integrity(&txn) {
                Ok(integrity) => {
                    report.add(
                        "integrity",
                        if integrity.ok() {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        format!(
                            "{} events, {} payloads, {} expected / {} actual index entries",
                            integrity.events,
                            integrity.payloads,
                            integrity.expected_index_entries,
                            integrity.actual_index_entries
                        ),
                    );
                    report.integrity = Some(integrity);
                }
                Err(error) => report.add("integrity", CheckStatus::Fail, error.to_string()),
            }
            check_payload_identity(&txn, cfg.events.max_event_size, &mut report);
            check_negentropy(&txn, &mut report);
        }
        Err(error) => report.add("read-transaction", CheckStatus::Fail, error.to_string()),
    }

    report
}

fn check_payload_identity(txn: &wok_db::RoTxn<'_>, max_size: usize, report: &mut DoctorReport) {
    let mut checked = 0u64;
    let mut failures = Vec::new();
    let mut decompressor = Decompressor::new();
    let result = txn.foreach_full(txn.env().dbis().event, &[], &[], false, |key, packed| {
        let Ok(key): Result<[u8; 8], _> = key.try_into() else {
            return true;
        };
        let lev_id = u64::from_ne_bytes(key);
        let Ok(packed) = PackedEventView::new(packed) else {
            return true;
        };
        checked += 1;
        let failure = event_json_owned(txn, &mut decompressor, lev_id, max_size)
            .and_then(|json| {
                let value: serde_json::Value = serde_json::from_str(&json)
                    .map_err(|error| wok_db::DbError::msg(error.to_string()))?;
                let id = value
                    .get("id")
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| wok_db::DbError::msg("payload has no string id"))?;
                if id != hex::encode(packed.id()) {
                    return Err(wok_db::DbError::msg(
                        "payload id differs from PackedEvent id",
                    ));
                }
                Ok(())
            })
            .err();
        if let Some(error) = failure {
            if failures.len() < 20 {
                failures.push(format!("levId {lev_id}: {error}"));
            }
        }
        true
    });
    match result {
        Err(error) => report.add("payload-identity", CheckStatus::Fail, error.to_string()),
        Ok(_) if failures.is_empty() => report.add(
            "payload-identity",
            CheckStatus::Pass,
            format!("decoded and matched {checked} event payloads"),
        ),
        Ok(_) => report.add("payload-identity", CheckStatus::Fail, failures.join("; ")),
    }
}

fn check_negentropy(txn: &wok_db::RoTxn<'_>, report: &mut DoctorReport) {
    let mut tree_ids = Vec::new();
    if let Err(error) = foreach_negentropy_filter(txn, |id, _| {
        tree_ids.push(id);
        true
    }) {
        report.add("negentropy", CheckStatus::Fail, error.to_string());
        return;
    }
    let mut total = 0u64;
    for id in &tree_ids {
        let result = wok_negentropy::open_ro(txn, *id).and_then(|mut tree| tree.size_mut());
        match result {
            Ok(size) => total = total.saturating_add(size),
            Err(error) => {
                report.add(
                    "negentropy",
                    CheckStatus::Fail,
                    format!("tree {id}: {error}"),
                );
                return;
            }
        }
    }
    report.add(
        "negentropy",
        CheckStatus::Pass,
        format!("{} trees, {total} items", tree_ids.len()),
    );
}

fn check_external_paths(cfg: &Config, report: &mut DoctorReport) {
    if cfg.relay.write_policy_plugin.is_empty() {
        report.add("write-policy", CheckStatus::Pass, "disabled");
    } else {
        let executable = cfg
            .relay
            .write_policy_plugin
            .split_whitespace()
            .next()
            .unwrap_or_default();
        match find_executable(executable) {
            Some(path) => report.add(
                "write-policy",
                CheckStatus::Pass,
                format!("executable {}", path.display()),
            ),
            None => report.add(
                "write-policy",
                CheckStatus::Fail,
                format!("cannot find executable {executable:?}"),
            ),
        }
    }

    if !cfg.relay.fips.enabled {
        report.add("fips-native-api", CheckStatus::Pass, "disabled");
    } else if !cfg!(feature = "native-fips") {
        report.add(
            "fips-native-api",
            CheckStatus::Fail,
            "binary was built without the native-fips feature",
        );
    } else if !cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos"
    )) {
        report.add(
            "fips-native-api",
            CheckStatus::Fail,
            "native FIPS is supported only on Linux, FreeBSD, and macOS",
        );
    } else {
        let path = &cfg.relay.fips.socket_path;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            match path.metadata() {
                Ok(metadata) if metadata.file_type().is_socket() => report.add(
                    "fips-native-api",
                    CheckStatus::Pass,
                    format!("native API socket {}", path.display()),
                ),
                Ok(_) => report.add(
                    "fips-native-api",
                    CheckStatus::Fail,
                    format!("{} exists and is not a socket", path.display()),
                ),
                Err(error) => report.add(
                    "fips-native-api",
                    CheckStatus::Fail,
                    format!("cannot access {}: {error}", path.display()),
                ),
            }
        }
        #[cfg(not(unix))]
        report.add(
            "fips-native-api",
            CheckStatus::Fail,
            "native FIPS requires a Unix socket",
        );
    }

    if !cfg.relay.unix.enabled {
        report.add("unix-socket", CheckStatus::Pass, "disabled");
        return;
    }
    let path = &cfg.relay.unix.path;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        report.add(
            "unix-socket",
            CheckStatus::Fail,
            format!("parent {} does not exist", parent.display()),
        );
        return;
    }
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            match path.metadata() {
                Ok(metadata) if metadata.file_type().is_socket() => report.add(
                    "unix-socket",
                    CheckStatus::Pass,
                    format!("existing socket {}", path.display()),
                ),
                Ok(_) => report.add(
                    "unix-socket",
                    CheckStatus::Fail,
                    format!("{} exists and is not a socket", path.display()),
                ),
                Err(error) => report.add("unix-socket", CheckStatus::Fail, error.to_string()),
            }
        }
        #[cfg(not(unix))]
        report.add(
            "unix-socket",
            CheckStatus::Fail,
            "Unix sockets are unsupported on this platform",
        );
    } else {
        report.add(
            "unix-socket",
            CheckStatus::Pass,
            format!("{} will be created", path.display()),
        );
    }
}

pub(crate) fn find_executable(command: &str) -> Option<PathBuf> {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return is_executable(path).then(|| path.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(command))
            .find(|candidate| is_executable(candidate))
    })
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

pub(crate) fn available_bytes(path: &Path) -> Result<u64, String> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "database path contains NUL".to_string())?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok((stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_empty_database_passes() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        drop(env);
        let cfg = Config {
            db: temp.path().to_path_buf(),
            ..Config::default()
        };
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert!(report.ok, "{}", report.render_human());
        assert!(report.integrity.unwrap().ok());
    }

    #[test]
    fn missing_plugin_is_a_failure() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        drop(env);
        let mut cfg = Config {
            db: temp.path().to_path_buf(),
            ..Config::default()
        };
        cfg.relay.write_policy_plugin = "/definitely/missing/wok-plugin".into();
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert!(!report.ok);
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "write-policy" && check.status == CheckStatus::Fail));
    }

    #[cfg(not(feature = "native-fips"))]
    #[test]
    fn enabled_fips_reports_a_missing_build_feature() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        drop(env);
        let mut cfg = Config {
            db: temp.path().to_path_buf(),
            ..Config::default()
        };
        cfg.relay.fips.enabled = true;
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert!(!report.ok);
        assert!(report.checks.iter().any(|check| {
            check.name == "fips-native-api"
                && check.status == CheckStatus::Fail
                && check.detail.contains("without the native-fips feature")
        }));
    }
}
