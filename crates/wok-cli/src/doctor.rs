#![allow(unsafe_code)]

use serde::Serialize;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use wok_db::{
    check_integrity, event_json_owned, foreach_negentropy_filter, Decompressor, Env, EnvOptions,
    EnvironmentStats, IntegrityReport, TagKindIndexReport, TAG_KIND_SCHEMA_VERSION,
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
        check_config_defaults(config_path, &mut report);
    } else {
        report.add(
            "config",
            CheckStatus::Warn,
            format!("{} is absent; defaults are in use", config_path.display()),
        );
    }

    // The relay refuses to start, or to reload, with this configuration.
    if let Some(error) = cfg.serving_error() {
        report.add("preset", CheckStatus::Fail, error);
    }
    match cfg.auth_configuration_warning() {
        Some(detail) => report.add("relay-auth", CheckStatus::Warn, detail),
        None => report.add(
            "relay-auth",
            CheckStatus::Pass,
            "NIP-42 authentication is usable, or nothing needs it",
        ),
    }
    check_read_classes(cfg, &mut report);

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
    let (status, detail) = filter_rules_check(&cfg.relay.filter_validation);
    report.add("filter-validation", status, detail);
    let caps = cfg.message_cap_warnings();
    report.add(
        "message-caps",
        if caps.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        if caps.is_empty() {
            "each message cap holds the largest EVENT, REQ and COUNT its limits accept".to_string()
        } else {
            caps.join(" ")
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
                    let history_status = if integrity.superseded_events == 0 {
                        CheckStatus::Pass
                    } else {
                        CheckStatus::Warn
                    };
                    report.add(
                        "replacement-history",
                        history_status,
                        format!(
                            "{} superseded events in {} replacement groups; retained history is hidden from relay reads and `wok purge-superseded` deletes it",
                            integrity.superseded_events, integrity.superseded_groups,
                        ),
                    );
                    report.add(
                        "long-tag-packing",
                        if integrity.legacy_long_tag_records == 0 {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Warn
                        },
                        format!(
                            "{} records lack single-letter tag values longer than 255 bytes in their indexes (packed by strfry or an earlier Wok); `wok reindex --confirm-relay-stopped` repacks them",
                            integrity.legacy_long_tag_records,
                        ),
                    );
                    report.add(
                        "deletion-tombstones",
                        if integrity.legacy_untombstoned_deletions == 0 {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Warn
                        },
                        format!(
                            "{} deletion requests lack the tombstone of an address their `a` tag names (a replaceable event, or a kind with leading zeros; stored by strfry or an earlier Wok), so the versions they name were not deleted or can be published again; `wok reindex --confirm-relay-stopped` deletes them and adds the tombstones",
                            integrity.legacy_untombstoned_deletions,
                        ),
                    );
                    check_tag_kind_index(integrity.tag_kind_index.as_ref(), &mut report);
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

/// Report how far `wok_Event__tagKind` indexes the stored events, and the
/// entries that do not match them.
fn check_tag_kind_index(tag_kind: Option<&TagKindIndexReport>, report: &mut DoctorReport) {
    const NAME: &str = "tag-kind-index";
    const REINDEX: &str = "`wok reindex --confirm-relay-stopped`";
    let Some(tag_kind) = tag_kind else {
        report.add(
            NAME,
            CheckStatus::Warn,
            format!("the (tag, kind, created_at) index is absent; the relay creates it on its next start and builds it in the background, or {REINDEX} builds it now"),
        );
        return;
    };
    let state = tag_kind.state;
    match state.schema {
        Some(TAG_KIND_SCHEMA_VERSION) => {}
        Some(schema) => {
            report.add(
                NAME,
                CheckStatus::Warn,
                format!("the (tag, kind, created_at) index has layout {schema}, not {TAG_KIND_SCHEMA_VERSION}; the next writable open empties it"),
            );
            return;
        }
        None => {
            report.add(
                NAME,
                CheckStatus::Warn,
                "the (tag, kind, created_at) index is not initialized; the next writable open initializes it",
            );
            return;
        }
    }
    let counted =
        |n: u64, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut status = CheckStatus::Pass;
    let mut details = Vec::new();
    if tag_kind.missing_entries != 0 || tag_kind.unexpected_entries != 0 {
        status = CheckStatus::Fail;
        let (missing, unexpected) = (tag_kind.missing_entries, tag_kind.unexpected_entries);
        details.push(format!(
            "{missing} missing and {unexpected} mismatched {}; {REINDEX} rebuilds the index",
            if missing + unexpected == 1 {
                "entry"
            } else {
                "entries"
            },
        ));
    }
    if !tag_kind.complete {
        if status == CheckStatus::Pass {
            status = CheckStatus::Warn;
        }
        details.push(match state.bulk_pass {
            Some(pass) => format!(
                "being built in key order: {} of {} tag entries visited; the relay continues in the background, or {REINDEX} builds it now",
                pass.visited, tag_kind.tag_entries
            ),
            None => format!(
                "indexed through local ID {} of {}; the relay indexes the rest in the background, or {REINDEX} does now",
                state.indexed_through, state.high_water
            ),
        });
    }
    if tag_kind.stale_entries != 0 {
        if status == CheckStatus::Pass {
            status = CheckStatus::Warn;
        }
        details.push(format!(
            "{} events that an earlier Wok release deleted; reads skip them, and {REINDEX} rebuilds the index without them",
            counted(tag_kind.stale_entries, "entry names", "entries name")
        ));
    }
    if details.is_empty() {
        details.push(format!(
            "{} every stored event",
            counted(tag_kind.actual_entries, "entry indexes", "entries index")
        ));
    }
    report.add(NAME, status, details.join("; "));
}

/// Warn about keys the file pins to a built-in default that an earlier
/// release used and the preset has since replaced: the relay keeps the old
/// value. Keys that repeat the preset's current values would go stale the
/// same way when a default changes, so point to `wok config minimize`.
fn check_config_defaults(path: &Path, report: &mut DoctorReport) {
    let explanation = match std::fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|text| Config::explain_toml(&text))
    {
        Ok(explanation) => explanation,
        Err(error) => {
            report.add("config-defaults", CheckStatus::Warn, error);
            return;
        }
    };
    let deprecations = &explanation.config.deprecations;
    report.add(
        "config-deprecations",
        if deprecations.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        if deprecations.is_empty() {
            "no deprecated key is set".to_string()
        } else {
            deprecations.join(" ")
        },
    );
    let preset = explanation.config.preset;
    let minimize = match explanation.repeated_preset_values().count() {
        0 => String::new(),
        1 => format!(
            " 1 key repeats preset {preset}'s value and will not follow it if it changes; \
             `wok config minimize` removes it."
        ),
        repeated => format!(
            " {repeated} keys repeat preset {preset}'s values and will not follow them if \
             they change; `wok config minimize` removes them."
        ),
    };
    let stale = explanation.stale_defaults();
    if stale.is_empty() {
        report.add(
            "config-defaults",
            CheckStatus::Pass,
            format!("no key pins a replaced default.{minimize}"),
        );
        return;
    }
    let pinned: Vec<String> = stale
        .iter()
        .map(|stale| {
            let line = stale
                .line
                .map_or_else(String::new, |line| format!("line {line}, "));
            format!(
                "{} = {} ({line}the default through {}; preset {preset}: {})",
                stale.key, stale.value, stale.last_release, stale.preset_value
            )
        })
        .collect();
    report.add(
        "config-defaults",
        CheckStatus::Warn,
        format!(
            "{} {} a default that has since changed: {}. Delete a line to use the \
             preset's value, or keep it if you chose that value.{minimize}",
            stale.len(),
            if stale.len() == 1 {
                "key pins"
            } else {
                "keys pin"
            },
            pinned.join("; "),
        ),
    );
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
    if let Err(error) = foreach_negentropy_filter(txn, |id, filter| {
        tree_ids.push((id, filter.to_string()));
        true
    }) {
        report.add("negentropy", CheckStatus::Fail, error.to_string());
        return;
    }
    let mut total = 0u64;
    for (id, filter) in &tree_ids {
        let result = wok_negentropy::verify_tree(txn, *id, filter);
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
        format!(
            "{} trees, {total} items verified against primary events",
            tree_ids.len()
        ),
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

/// Who may read each kind, against the preset and the inbox kinds. The
/// relay logs both warnings at startup; a reload logs what it widens.
fn check_read_classes(cfg: &Config, report: &mut DoctorReport) {
    match cfg.read_class_warning() {
        Some(detail) => report.add("read-classes", CheckStatus::Warn, detail),
        None => report.add(
            "read-classes",
            CheckStatus::Pass,
            format!(
                "no kind has more readers than preset {} gives it",
                cfg.preset
            ),
        ),
    }
    match cfg.inbox_kinds_warning() {
        Some(detail) => report.add("inbox-kinds", CheckStatus::Warn, detail),
        None => report.add(
            "inbox-kinds",
            CheckStatus::Pass,
            if cfg.relay.auth.write_policy == wok_relay::AccessPolicy::Members {
                "every inbox kind is recipient-only or stricter"
            } else {
                "inbox kinds admit writes only under write_policy = \"members\""
            },
        ),
    }
}

/// Which `[relay.filter_validation]` rules are set, so a reload that drops
/// one shows.
fn filter_rules_check(rules: &wok_relay::config::FilterValidationConfig) -> (CheckStatus, String) {
    let active: Vec<&str> = [
        (rules.max_kinds_per_filter != 0, "max_kinds_per_filter"),
        (!rules.allowed_kinds.is_empty(), "allowed_kinds"),
        (rules.require_author_or_tag, "require_author_or_tag"),
        (rules.require_scoped_filters, "require_scoped_filters"),
    ]
    .into_iter()
    .filter_map(|(set, rule)| set.then_some(rule))
    .collect();
    if active.is_empty() {
        (CheckStatus::Warn, "no ingress filter rule is set".into())
    } else {
        (
            CheckStatus::Pass,
            format!("ingress filter rules: {}", active.join(", ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_empty_database_passes() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
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
    fn a_message_cap_too_small_for_its_limits_is_a_warning() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        drop(env);
        let mut cfg = Config {
            db: temp.path().to_path_buf(),
            ..Config::default()
        };
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert_eq!(check(&report, "message-caps").status, CheckStatus::Pass);
        cfg.events.max_event_size = 4 * 1024 * 1024;
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        let caps = check(&report, "message-caps");
        assert_eq!(caps.status, CheckStatus::Warn);
        assert!(
            caps.detail.starts_with(
                "relay.max_websocket_payload_size = 2097152 is too small for \
                 events.max_event_size = 4194304"
            ),
            "{}",
            caps.detail
        );
    }

    #[test]
    fn missing_plugin_is_a_failure() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
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

    fn check<'a>(report: &'a DoctorReport, name: &str) -> &'a DoctorCheck {
        report
            .checks
            .iter()
            .find(|check| check.name == name)
            .unwrap()
    }

    #[test]
    fn tag_kind_index_drift_is_reported() {
        use secp256k1::SECP256K1;
        use serde_json::json;
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let keypair = secp256k1::Keypair::new(SECP256K1, &mut rand::thread_rng());
        let mut events = Vec::new();
        for created_at in [1_700_000_000, 1_700_000_001] {
            let mut event = json!({
                "created_at": created_at,
                "kind": 1059,
                "tags": [["p", "33".repeat(32)]],
                "content": "",
                "pubkey": hex::encode(keypair.x_only_public_key().0.serialize()),
            });
            let id = wok_event::event_id_hash(&event).unwrap();
            event["id"] = json!(hex::encode(id));
            event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &keypair).as_ref()));
            let parsed =
                wok_event::parse_and_verify_event(&event, &Default::default(), None, true, false)
                    .unwrap();
            events.push(wok_db::EventToWrite::new(
                parsed.packed.into_bytes(),
                parsed.json,
            ));
        }
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
        let key = |event: &wok_db::EventToWrite| {
            let view = PackedEventView::new(&event.packed).unwrap();
            wok_db::tag_kind_key(b'p', &[0x33; 32], view.kind(), view.created_at())
        };
        let dbi = env.dbis().event_tag_kind.unwrap();
        drop(env);
        // One process opens an environment once, so doctor needs it closed.
        let reopen = || Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
        let cfg = Config {
            db: temp.path().to_path_buf(),
            ..Config::default()
        };
        // These writes skip negentropy trees; only the index checks matter.
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert_eq!(check(&report, "integrity").status, CheckStatus::Pass);
        let tag_kind = check(&report, "tag-kind-index");
        assert_eq!(tag_kind.status, CheckStatus::Pass, "{}", tag_kind.detail);
        assert_eq!(tag_kind.detail, "2 entries index every stored event");

        // An earlier release deleted the first event and left its entry.
        let env = reopen();
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [events[0].lev_id]).unwrap();
        txn.put(dbi, &key(&events[0]), &events[0].lev_id.to_ne_bytes(), 0)
            .unwrap();
        txn.commit().unwrap();
        drop(env);
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert_eq!(check(&report, "integrity").status, CheckStatus::Pass);
        let tag_kind = check(&report, "tag-kind-index");
        assert_eq!(tag_kind.status, CheckStatus::Warn);
        assert!(
            tag_kind
                .detail
                .starts_with("1 entry names events that an earlier Wok release deleted"),
            "{}",
            tag_kind.detail
        );

        // The second event, still stored, lost its entry.
        let env = reopen();
        let mut txn = env.begin_rw().unwrap();
        assert!(txn
            .del(dbi, &key(&events[1]), Some(&events[1].lev_id.to_ne_bytes()))
            .unwrap());
        txn.commit().unwrap();
        drop(env);
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert_eq!(check(&report, "integrity").status, CheckStatus::Fail);
        let tag_kind = check(&report, "tag-kind-index");
        assert_eq!(tag_kind.status, CheckStatus::Fail);
        assert!(
            tag_kind
                .detail
                .starts_with("1 missing and 0 mismatched entry"),
            "{}",
            tag_kind.detail
        );

        // The relay starts over: a key-ordered pass, one entry in.
        let env = reopen();
        let mut txn = env.begin_rw().unwrap();
        wok_db::reset_tag_kind_index(&mut txn).unwrap();
        wok_db::backfill_tag_kind_index(&mut txn, 1, std::time::Duration::MAX).unwrap();
        txn.commit().unwrap();
        drop(env);
        let report = run(&cfg, Path::new("missing-test-config.toml"));
        assert_eq!(check(&report, "integrity").status, CheckStatus::Pass);
        let tag_kind = check(&report, "tag-kind-index");
        assert_eq!(tag_kind.status, CheckStatus::Warn);
        assert!(
            tag_kind
                .detail
                .starts_with("being built in key order: 1 of 1 tag entries visited"),
            "{}",
            tag_kind.detail
        );
    }

    #[test]
    fn read_classes_wider_than_the_presets_are_warnings() {
        let report = |text: &str| {
            let cfg = Config::parse_toml(text).unwrap();
            run(&cfg, Path::new("missing-test-config.toml"))
        };
        let defaults = report("");
        assert_eq!(check(&defaults, "read-classes").status, CheckStatus::Pass);
        assert_eq!(check(&defaults, "inbox-kinds").status, CheckStatus::Pass);

        let widened =
            report("[relay.auth]\nrecipient_only_kinds = [4]\nwrite_policy = \"members\"\n");
        let reads = check(&widened, "read-classes");
        assert_eq!(reads.status, CheckStatus::Warn);
        assert!(
            reads.detail.contains(
                "than preset public does: 1059 (recipient-only -> anyone), \
                 21059 (recipient-only -> anyone)."
            ),
            "{}",
            reads.detail
        );
        let inbox = check(&widened, "inbox-kinds");
        assert_eq!(inbox.status, CheckStatus::Warn);
        assert!(
            inbox.detail.contains("kinds [1059, 21059]"),
            "{}",
            inbox.detail
        );

        // The marmot preset refuses to serve gift wraps to anyone.
        let marmot = report(
            "preset = \"marmot\"\n[relay.auth]\nservice_url = \"wss://relay.example.com\"\n\
             recipient_only_kinds = []\n",
        );
        assert!(!marmot.ok);
        let preset = check(&marmot, "preset");
        assert_eq!(preset.status, CheckStatus::Fail);
        assert!(
            preset.detail.contains("kinds [1059, 21059]"),
            "{}",
            preset.detail
        );
        assert_eq!(check(&marmot, "read-classes").status, CheckStatus::Warn);
    }

    /// The checks `check_config_defaults` reports for a file: deprecated
    /// keys, then replaced defaults.
    fn config_checks(text: &str) -> (DoctorCheck, DoctorCheck) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wok.toml");
        std::fs::write(&path, text).unwrap();
        let mut report = DoctorReport::new();
        check_config_defaults(&path, &mut report);
        let names: Vec<&str> = report
            .checks
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        assert_eq!(names, ["config-deprecations", "config-defaults"]);
        let defaults = report.checks.pop().unwrap();
        (report.checks.pop().unwrap(), defaults)
    }

    #[test]
    fn filter_rules_check_lists_every_rule_set() {
        let mut rules = Config::default().relay.filter_validation;
        assert_eq!(filter_rules_check(&rules).0, CheckStatus::Warn);
        // The marmot preset's only rule.
        rules.require_scoped_filters = true;
        assert_eq!(
            filter_rules_check(&rules),
            (
                CheckStatus::Pass,
                "ingress filter rules: require_scoped_filters".into()
            )
        );
        rules.max_kinds_per_filter = 6;
        rules.allowed_kinds = "1".into();
        rules.require_author_or_tag = true;
        assert_eq!(
            filter_rules_check(&rules).1,
            "ingress filter rules: max_kinds_per_filter, allowed_kinds, require_author_or_tag, \
             require_scoped_filters"
        );
    }

    fn config_defaults_check(text: &str) -> DoctorCheck {
        config_checks(text).1
    }

    #[test]
    fn pinned_old_default_is_a_warning() {
        let check = config_defaults_check(
            "preset = \"public\"\n\
             [events]\n\
             reject_older_than_secs = 94608000\n\
             max_num_tags = 5000\n",
        );
        assert_eq!(check.name, "config-defaults");
        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(
            check.detail,
            "1 key pins a default that has since changed: \
             events.reject_older_than_secs = 94608000 \
             (line 3, the default through 0.7.0; preset public: 0). \
             Delete a line to use the preset's value, or keep it if you chose that value. \
             1 key repeats preset public's value and will not follow it if it changes; \
             `wok config minimize` removes it."
        );

        // The complete 0.7.0 sample pins 13 replaced defaults.
        let check = config_defaults_check(include_str!(
            "../../wok-relay/src/config/testdata/wok-0.7.0.toml"
        ));
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.starts_with("13 keys pin"), "{}", check.detail);
        assert!(check
            .detail
            .contains("relay.abuse.req_burst = 40 (line 142,"));
        assert!(check
            .detail
            .contains("relay.auth.recipient_only_kinds = [4, 1059] (line 101,"));
        assert!(check
            .detail
            .contains("relay.max_req_filter_size = 65536 (line 54,"));
        assert!(check
            .detail
            .ends_with("`wok config minimize` removes them."));
    }

    #[test]
    fn config_without_old_defaults_passes() {
        let check = config_defaults_check(
            "[events]\nreject_older_than_secs = 31536000\n[relay]\nport = 7777\n",
        );
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check
            .detail
            .starts_with("no key pins a replaced default. 1 key repeats"));
        let check = config_defaults_check(include_str!("../../../docs/wok.toml"));
        assert_eq!(check.status, CheckStatus::Pass);
        assert_eq!(check.detail, "no key pins a replaced default.");
    }

    #[test]
    fn deprecated_keys_are_a_warning() {
        let (check, _) = config_checks(include_str!(
            "../../wok-relay/src/config/testdata/wok-0.7.0.toml"
        ));
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check
                .detail
                .starts_with("relay.filter_validation.enabled = false is deprecated"),
            "{}",
            check.detail
        );
        // Its old query cost ceiling is ignored, in favor of the new key.
        assert!(
            check
                .detail
                .contains("relay.abuse.max_query_cost is deprecated and ignored")
                && check.detail.contains("relay.abuse.max_query_work"),
            "{}",
            check.detail
        );
        // An enabled zero kind cap gets its own entry: it no longer refuses
        // filters that list kinds.
        let (check, _) =
            config_checks("[relay.filter_validation]\nenabled = true\nmax_kinds_per_filter = 0\n");
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check
                .detail
                .contains("relay.filter_validation.max_kinds_per_filter = 0 in an enabled section")
                && check.detail.contains("allowed_kinds"),
            "{}",
            check.detail
        );
        let (check, _) = config_checks(include_str!("../../../docs/wok.toml"));
        assert_eq!(check.status, CheckStatus::Pass);
        assert_eq!(check.detail, "no deprecated key is set");
    }
}
