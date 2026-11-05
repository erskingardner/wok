//! Private, offline physical-copy experiment. Compiled only into heads-layout
//! unit tests; there is no runtime converter or CLI/config switch.
//!
//! Only a separately authorized host route may invoke the ignored entry point.
//! It requires an independently copied disposable source and creates a fresh
//! owned run directory. A failed directory is retained and never resumed.
#![forbid(unsafe_code)]

use super::*;
use crate::env::native_options;
use crate::{AuthorHead, AuthorPosition, Env, EnvOptions};
use rocksdb::{ColumnFamily, ReadOptions, Snapshot, WriteBatch, WriteOptions, DB};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const DUAL: &[u8] = b"wok-rocks-v1:combined:dual-author:reverse-order:sync-wal";
const PENDING: &[u8] = b"wok-rocksdb-build-incomplete:v1-dual-to-v3-frontiers";
const MAX_JSON: u64 = 2 << 20;
const MAX_FILES: usize = 100_000;
// Errors are deliberately fixed labels. Never export an underlying native,
// codec, signature or JSON error: it could include private stored row bytes.
type BResult<T> = Result<T, &'static str>;

#[derive(Clone, Copy, Serialize)]
struct Limits {
    batch_bytes: usize,
    batch_rows: usize,
    row_bytes: usize,
    dictionary_bytes: u64,
    dictionary_records: u64,
    reserve_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            batch_bytes: 8 << 20,
            batch_rows: 10_000,
            row_bytes: 64 << 20,
            dictionary_bytes: 256 << 20,
            dictionary_records: 4096,
            reserve_bytes: 12 << 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileHash {
    bytes: u64,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Inventory {
    directories: BTreeSet<String>,
    files: BTreeMap<String, FileHash>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    format: String,
    source: PathBuf,
    disposable_copy: bool,
    retained_inventory: PathBuf,
    retained_inventory_sha256: String,
    retained_audit: PathBuf,
    retained_audit_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyFile {
    path: String,
    size: u64,
    mtime_ns: u64,
    sha256: String,
}
fn normalize_inventory(rows: Vec<LegacyFile>) -> BResult<Inventory> {
    if rows.len() > MAX_FILES {
        return Err("inventory file limit exceeded");
    }
    let mut out = Inventory {
        directories: BTreeSet::new(),
        files: BTreeMap::new(),
    };
    for row in rows {
        let path = Path::new(&row.path);
        if row.path.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || !valid_sha(&row.sha256)
        {
            return Err("legacy inventory path or digest invalid");
        }
        // mtime is preserved in the original bound report, but it is not part
        // of byte identity of an independently allocated disposable copy.
        let _retained_timestamp = row.mtime_ns;
        for parent in path.ancestors().skip(1) {
            if parent.as_os_str().is_empty() {
                break;
            }
            out.directories
                .insert(parent.to_str().ok_or("inventory path invalid")?.to_owned());
        }
        if out
            .files
            .insert(
                row.path,
                FileHash {
                    bytes: row.size,
                    sha256: row.sha256,
                },
            )
            .is_some()
        {
            return Err("duplicate legacy inventory path");
        }
    }
    Ok(out)
}
fn retained_audit(audit: &Value) -> BResult<(u64, String)> {
    let events = audit["events"]
        .as_u64()
        .ok_or("retained audit count missing")?;
    if audit["ok"] != true
        || audit["layout"].as_str() != std::str::from_utf8(DUAL).ok()
        || [
            "verified_signatures_and_bodies",
            "covering_records_verified",
        ]
        .iter()
        .any(|key| audit[*key].as_u64() != Some(events))
        || audit["table_counts"][crate::schema::DBI_EVENT_PUBKEY].as_u64() != Some(events)
        || audit["table_counts"][COVERING].as_u64() != Some(events)
        || audit
            .get("thin_author_records_verified")
            .is_some_and(|n| n.as_u64() != Some(events))
    {
        return Err("retained full v1 audit contract failed");
    }
    let primary = audit["primary_fingerprint_sha256"]
        .as_str()
        .filter(|s| valid_sha(s))
        .ok_or("retained primary digest invalid")?
        .to_owned();
    Ok((events, primary))
}
struct Input {
    source: PathBuf,
    before: Inventory,
    provenance_sha256: String,
    retained_inventory_sha256: String,
    retained_audit_sha256: String,
    events: u64,
    primary_sha256: String,
    normalized: Inventory,
    original_inventory_rows: usize,
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn checked_add(a: u64, b: usize) -> BResult<u64> {
    a.checked_add(u64::try_from(b).map_err(|_| "length overflow")?)
        .ok_or("length overflow")
}
fn hash_file(path: &Path) -> BResult<FileHash> {
    let meta = fs::symlink_metadata(path).map_err(|_| "file metadata failed")?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err("nonregular or multiply linked file refused");
    }
    let mut f = File::open(path).map_err(|_| "file open failed")?;
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 64 << 10];
    loop {
        let n = f.read(&mut buffer).map_err(|_| "file read failed")?;
        if n == 0 {
            break;
        }
        bytes = checked_add(bytes, n)?;
        hash.update(&buffer[..n]);
    }
    let after = f.metadata().map_err(|_| "file metadata failed")?;
    if bytes != meta.len()
        || meta.len() != after.len()
        || meta.dev() != after.dev()
        || meta.ino() != after.ino()
        || meta.mtime() != after.mtime()
        || meta.mtime_nsec() != after.mtime_nsec()
        || meta.ctime() != after.ctime()
        || meta.ctime_nsec() != after.ctime_nsec()
    {
        return Err("file changed while hashing");
    }
    Ok(FileHash {
        bytes,
        sha256: hex_digest(hash.finalize()),
    })
}
fn inventory(root: &Path) -> BResult<Inventory> {
    fn visit(root: &Path, path: &Path, out: &mut Inventory, count: &mut usize) -> BResult<()> {
        for entry in fs::read_dir(path).map_err(|_| "directory read failed")? {
            let entry = entry.map_err(|_| "directory entry failed")?;
            *count = count.checked_add(1).ok_or("inventory overflow")?;
            if *count > MAX_FILES {
                return Err("inventory file limit exceeded");
            }
            let path = entry.path();
            let name = path
                .strip_prefix(root)
                .map_err(|_| "inventory path failed")?
                .to_str()
                .ok_or("non-UTF8 inventory path refused")?
                .to_owned();
            let meta = fs::symlink_metadata(&path).map_err(|_| "file metadata failed")?;
            if meta.is_dir() {
                out.directories.insert(name);
                visit(root, &path, out, count)?;
            } else if meta.is_file() {
                out.files.insert(name, hash_file(&path)?);
            } else {
                return Err("nonregular inventory member refused");
            }
        }
        Ok(())
    }
    let mut out = Inventory {
        directories: BTreeSet::new(),
        files: BTreeMap::new(),
    };
    visit(root, root, &mut out, &mut 0)?;
    Ok(out)
}
fn canonical_directory(path: &Path) -> BResult<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err("absolute canonical directory required");
    }
    let canonical = fs::canonicalize(path).map_err(|_| "directory canonicalization failed")?;
    if canonical != path
        || !fs::symlink_metadata(path)
            .map_err(|_| "directory metadata failed")?
            .is_dir()
    {
        return Err("symlink or noncanonical directory refused");
    }
    Ok(canonical)
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> BResult<(T, String)> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| "proof path failed")? != path {
        return Err("absolute canonical proof path required");
    }
    let identity = hash_file(path)?;
    if identity.bytes > MAX_JSON {
        return Err("proof JSON exceeds limit");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "proof open failed")?
        .take(MAX_JSON + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "proof read failed")?;
    if bytes.len() as u64 != identity.bytes || hex_digest(Sha256::digest(&bytes)) != identity.sha256
    {
        return Err("proof changed while reading");
    }
    Ok((
        serde_json::from_slice(&bytes).map_err(|_| "proof JSON schema failed")?,
        identity.sha256,
    ))
}
fn write_json_new(path: &Path, value: &impl Serialize) -> BResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)
        .map_err(|_| "proof creation refused or failed")?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|_| "proof serialization failed")?;
    file.write_all(b"\n").map_err(|_| "proof write failed")?;
    file.sync_all().map_err(|_| "proof sync failed")?;
    File::open(path.parent().ok_or("proof parent missing")?)
        .map_err(|_| "proof directory open failed")?
        .sync_all()
        .map_err(|_| "proof directory sync failed")
}
fn input(source: &Path, proof: &Path) -> BResult<Input> {
    let source = canonical_directory(source)?;
    let (p, provenance_sha256): (Provenance, _) = read_json(proof)?;
    if p.format != "wok-physical-builder-source-v1" || !p.disposable_copy || p.source != source {
        return Err("disposable source provenance mismatch");
    }
    let (rows, inventory_sha): (Vec<LegacyFile>, _) = read_json(&p.retained_inventory)?;
    let original_inventory_rows = rows.len();
    let expected = normalize_inventory(rows)?;
    if inventory_sha != p.retained_inventory_sha256 || !valid_sha(&inventory_sha) {
        return Err("retained inventory hash mismatch");
    }
    let (audit, audit_sha): (Value, _) = read_json(&p.retained_audit)?;
    if audit_sha != p.retained_audit_sha256 || !valid_sha(&audit_sha) {
        return Err("retained audit hash mismatch");
    }
    let (events, primary_sha256) = retained_audit(&audit)?;
    let before = inventory(&source)?;
    if before.files != expected.files {
        return Err("copied source differs from retained closed inventory");
    }
    Ok(Input {
        source,
        before,
        provenance_sha256,
        retained_inventory_sha256: inventory_sha,
        retained_audit_sha256: audit_sha,
        events,
        primary_sha256,
        normalized: expected,
        original_inventory_rows,
    })
}

fn dual_cfs() -> Vec<&'static str> {
    let mut names = physical_cf_names();
    names.retain(|name| *name != HEAD_CF);
    names.push(COVERING);
    names.sort_unstable();
    names
}
fn check_names(path: &Path, names: &[&str]) -> BResult<()> {
    let mut actual =
        DB::list_cf(&rocksdb::Options::default(), path).map_err(|_| "CF inspection failed")?;
    let mut expected = names.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual != expected {
        return Err("physical CF set mismatch");
    }
    Ok(())
}
fn cf<'a>(db: &'a DB, name: &str) -> BResult<&'a ColumnFamily> {
    db.cf_handle(name).ok_or("required CF missing")
}
fn read_only_db(path: &Path, names: Vec<&'static str>, marker: &[u8]) -> BResult<DB> {
    check_names(path, &names)?;
    let (mut options, cfs) = native_options(false, names);
    options.set_info_logger(rocksdb::InfoLogger::new_callback_logger(
        rocksdb::LogLevel::Error,
        |_, _| {},
    ));
    options.set_skip_stats_update_on_db_open(true);
    let db = DB::open_cf_descriptors_read_only(&options, path, cfs, false)
        .map_err(|_| "read-only native open failed")?;
    if db
        .get(FORMAT_KEY)
        .map_err(|_| "format read failed")?
        .as_deref()
        != Some(marker)
    {
        return Err("physical format mismatch");
    }
    Ok(db)
}
// This private adapter cannot create CFs, write, or accept an arbitrary marker.
// Ordinary Env::open retains its exact marker check before any writable open.
fn pending_audit_env(path: &Path) -> BResult<Env> {
    let db = read_only_db(path, physical_cf_names(), PENDING)?;
    Env::from_native_db(db, path, true).map_err(|_| "pending audit Env construction failed")
}
fn background_errors(db: &DB, names: &[&str]) -> BResult<()> {
    for name in names {
        if db
            .property_int_value_cf(cf(db, name)?, "rocksdb.background-errors")
            .map_err(|_| "background status read failed")?
            .unwrap_or(0)
            != 0
        {
            return Err("native background error");
        }
    }
    Ok(())
}
fn space(path: &Path, reserve: u64) -> BResult<()> {
    if fs2::available_space(path).map_err(|_| "free-space read failed")? < reserve {
        return Err("construction reserve breached");
    }
    Ok(())
}
fn ro() -> ReadOptions {
    let mut options = ReadOptions::default();
    options.fill_cache(false);
    options
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct CfHash {
    rows: u64,
    key_bytes: u64,
    value_bytes: u64,
    sha256: String,
}
struct Framed {
    hash: Sha256,
    rows: u64,
    key_bytes: u64,
    value_bytes: u64,
}
impl Framed {
    fn new(name: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"WOK-PHYSICAL-CF-V1\0");
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        Self {
            hash,
            rows: 0,
            key_bytes: 0,
            value_bytes: 0,
        }
    }
    fn row(&mut self, key: &[u8], value: &[u8]) -> BResult<()> {
        self.rows = self.rows.checked_add(1).ok_or("row count overflow")?;
        self.key_bytes = checked_add(self.key_bytes, key.len())?;
        self.value_bytes = checked_add(self.value_bytes, value.len())?;
        self.hash.update([1]);
        self.hash.update((key.len() as u64).to_le_bytes());
        self.hash.update(key);
        self.hash.update((value.len() as u64).to_le_bytes());
        self.hash.update(value);
        Ok(())
    }
    fn finish(mut self) -> CfHash {
        self.hash.update([0]);
        for n in [self.rows, self.key_bytes, self.value_bytes] {
            self.hash.update(n.to_le_bytes());
        }
        CfHash {
            rows: self.rows,
            key_bytes: self.key_bytes,
            value_bytes: self.value_bytes,
            sha256: hex_digest(self.hash.finalize()),
        }
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ColumnHash {
    full: CfHash,
    without_format: Option<CfHash>,
}
fn scan(
    db: &DB,
    snapshot: &Snapshot<'_>,
    name: &str,
    mut visit: impl FnMut(&[u8], &[u8]) -> BResult<()>,
) -> BResult<ColumnHash> {
    let mut full = Framed::new(name);
    let mut normalized = (name == "default").then(|| Framed::new(name));
    let mut it = snapshot.raw_iterator_cf_opt(cf(db, name)?, ro());
    it.seek_to_first();
    while let Some((key, value)) = it.item() {
        visit(key, value)?;
        full.row(key, value)?;
        if let Some(hash) = &mut normalized {
            if key != FORMAT_KEY {
                hash.row(key, value)?;
            }
        }
        it.next();
    }
    it.status().map_err(|_| "native iterator failed")?;
    Ok(ColumnHash {
        full: full.finish(),
        without_format: normalized.map(Framed::finish),
    })
}
fn all_hashes(db: &DB) -> BResult<BTreeMap<String, ColumnHash>> {
    let snapshot = db.snapshot();
    let mut out = BTreeMap::new();
    for name in physical_cf_names() {
        out.insert(name.to_owned(), scan(db, &snapshot, name, |_, _| Ok(()))?);
    }
    Ok(out)
}
fn equal_kept(
    source: &BTreeMap<String, ColumnHash>,
    target: &BTreeMap<String, ColumnHash>,
) -> BResult<()> {
    for (name, before) in source {
        if name == COVERING {
            continue;
        }
        let after = target.get(name).ok_or("kept CF hash missing")?;
        let equal = if name == "default" {
            before.without_format == after.without_format && before.without_format.is_some()
        } else {
            before == after
        };
        if !equal {
            return Err("kept CF byte hash mismatch");
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    AfterPending,
    AfterBatch,
    AfterCopy,
    CorruptHead,
    AfterAudit,
    AfterSeal,
}
fn injected(fault: Fault, point: Fault) -> BResult<()> {
    if fault == point {
        Err("injected fixture fault")
    } else {
        Ok(())
    }
}
struct Batches<'a> {
    db: &'a DB,
    path: &'a Path,
    limits: Limits,
    fault: Fault,
    batch: WriteBatch,
    commits: u64,
    rows: u64,
    options: WriteOptions,
}
impl<'a> Batches<'a> {
    fn new(db: &'a DB, path: &'a Path, limits: Limits, fault: Fault) -> Self {
        let mut options = WriteOptions::default();
        options.set_sync(true);
        options.disable_wal(false);
        Self {
            db,
            path,
            limits,
            fault,
            batch: WriteBatch::default(),
            commits: 0,
            rows: 0,
            options,
        }
    }
    fn put(&mut self, name: &str, key: &[u8], value: &[u8]) -> BResult<()> {
        let row = key
            .len()
            .checked_add(value.len())
            .ok_or("row length overflow")?;
        if row > self.limits.row_bytes {
            return Err("single row budget exceeded");
        }
        // Conservatively allow for CF tag/varint framing before owning a row.
        let predicted = self
            .batch
            .size_in_bytes()
            .checked_add(row)
            .and_then(|n| n.checked_add(64))
            .ok_or("batch length overflow")?;
        if !self.batch.is_empty()
            && (self.batch.len() >= self.limits.batch_rows || predicted > self.limits.batch_bytes)
        {
            self.flush()?;
        }
        self.batch.put_cf(cf(self.db, name)?, key, value);
        if self.batch.len() > 1 && self.batch.size_in_bytes() > self.limits.batch_bytes {
            return Err("serialized batch budget exceeded");
        }
        self.rows = self.rows.checked_add(1).ok_or("row count overflow")?;
        if self.batch.len() >= self.limits.batch_rows
            || self.batch.size_in_bytes() > self.limits.batch_bytes
        {
            self.flush()?;
        }
        Ok(())
    }
    fn flush(&mut self) -> BResult<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        space(self.path, self.limits.reserve_bytes)?;
        background_errors(self.db, &physical_cf_names())?;
        self.db
            .write_opt(std::mem::take(&mut self.batch), &self.options)
            .map_err(|_| "synchronous batch write failed")?;
        self.commits = self.commits.checked_add(1).ok_or("batch count overflow")?;
        if self.commits == 1 {
            injected(self.fault, Fault::AfterBatch)?;
        }
        Ok(())
    }
}

struct PrimaryFingerprint {
    hash: Sha256,
    count: u64,
}
impl PrimaryFingerprint {
    fn new() -> Self {
        Self {
            hash: Sha256::new(),
            count: 0,
        }
    }
    fn row(&mut self, key: &[u8], value: &[u8]) -> BResult<()> {
        let (local, _) = decode(3, key, &[]).map_err(|_| "primary key decoding failed")?;
        let id = u64::from_ne_bytes(
            local
                .as_slice()
                .try_into()
                .map_err(|_| "primary local ID malformed")?,
        );
        if encode(3, &local, None) != key {
            return Err("noncanonical primary key refused");
        }
        let (packed, payload) = parts(value).map_err(|_| "combined component framing failed")?;
        let packed = packed.ok_or("packed component absent")?;
        let payload = payload.ok_or("payload component absent")?;
        self.hash.update(id.to_le_bytes());
        self.hash.update((packed.len() as u64).to_le_bytes());
        self.hash.update(packed);
        self.hash.update((payload.len() as u64).to_le_bytes());
        self.hash.update(payload);
        self.count = self.count.checked_add(1).ok_or("primary count overflow")?;
        Ok(())
    }
    fn finish(self) -> (u64, String) {
        (self.count, hex_digest(self.hash.finalize()))
    }
}

// Reverse physical traversal yields authors in raw ascending order, and each
// author's positions oldest first. Keeping the latest two as rows arrive gives
// the exact frontier and an independently ascending-key derived-CF hash without
// an author map, spool file or event-body materialization.
fn frontiers(
    db: &DB,
    snapshot: &Snapshot<'_>,
    mut emit: impl FnMut(&[u8; 32], AuthorHead) -> BResult<()>,
) -> BResult<(CfHash, u64)> {
    let mut it = snapshot.raw_iterator_cf_opt(cf(db, cf_name(10))?, ro());
    it.seek_to_last();
    let mut current: Option<([u8; 32], AuthorHead)> = None;
    let mut digest = Framed::new(HEAD_CF);
    let mut positions = 0u64;
    let mut finish = |author: &[u8; 32], head: AuthorHead| -> BResult<()> {
        let value = head.encode();
        emit(author, head)?;
        digest.row(author, &value)?;
        positions = positions
            .checked_add(if head.next.is_some() { 2 } else { 1 })
            .ok_or("frontier count overflow")?;
        Ok(())
    };
    while let Some((raw, value)) = it.item() {
        let (key, dup) = decode(10, raw, value).map_err(|_| "thin posting decoding failed")?;
        if key.len() != 40
            || dup.len() != 8
            || !value.is_empty()
            || encode(10, &key, Some(&dup)) != raw
        {
            return Err("noncanonical thin posting refused");
        }
        let author: [u8; 32] = key[..32].try_into().map_err(|_| "thin author malformed")?;
        let position = AuthorPosition {
            created_at: u64::from_ne_bytes(
                key[32..]
                    .try_into()
                    .map_err(|_| "thin timestamp malformed")?,
            ),
            local_id: u64::from_ne_bytes(
                dup.as_slice()
                    .try_into()
                    .map_err(|_| "thin local ID malformed")?,
            ),
        };
        match current.take() {
            Some((previous, head)) if previous == author => {
                if position <= head.first {
                    return Err("thin position order invalid");
                }
                current = Some((
                    author,
                    AuthorHead {
                        first: position,
                        next: Some(head.first),
                    },
                ));
            }
            Some((previous, head)) => {
                if author <= previous {
                    return Err("thin author order invalid");
                }
                finish(&previous, head)?;
                current = Some((
                    author,
                    AuthorHead {
                        first: position,
                        next: None,
                    },
                ));
            }
            None => {
                current = Some((
                    author,
                    AuthorHead {
                        first: position,
                        next: None,
                    },
                ))
            }
        }
        it.prev();
    }
    it.status().map_err(|_| "native frontier iterator failed")?;
    if let Some((author, head)) = current {
        finish(&author, head)?;
    }
    Ok((digest.finish(), positions))
}

#[derive(Serialize)]
struct CopyProof {
    source_native_sequence: u64,
    target_native_sequence_after_copy: u64,
    source_cf_hashes: BTreeMap<String, ColumnHash>,
    frontier_hash: CfHash,
    frontier_positions: u64,
    primary_count: u64,
    primary_sha256: String,
    synchronized_batches: u64,
    written_rows: u64,
}
fn dictionary_budget(db: &DB, snapshot: &Snapshot<'_>, limits: Limits) -> BResult<()> {
    let hash = scan(db, snapshot, cf_name(14), |key, value| {
        if key
            .len()
            .checked_add(value.len())
            .ok_or("dictionary length overflow")?
            > limits.row_bytes
        {
            return Err("dictionary row budget exceeded");
        }
        Ok(())
    })?
    .full;
    if hash.rows > limits.dictionary_records || hash.value_bytes > limits.dictionary_bytes {
        return Err("dictionary cache budget exceeded");
    }
    Ok(())
}
fn check_meta(db: &DB, snapshot: &Snapshot<'_>) -> BResult<()> {
    if !cfg!(target_endian = "little") {
        return Err("builder host endianness unsupported");
    }
    let raw = snapshot
        .get_cf(cf(db, cf_name(1))?, encode(1, &1u64.to_ne_bytes(), None))
        .map_err(|_| "source Meta read failed")?
        .ok_or("source Meta absent")?;
    let meta = crate::decode_meta(&raw).map_err(|_| "source Meta decoding failed")?;
    if meta.db_version != wok_event::WOK_DB_VERSION || meta.endianness != 1 {
        return Err("source logical version or endianness incompatible");
    }
    Ok(())
}
fn copy_rows(
    source: &DB,
    snapshot: &Snapshot<'_>,
    target: &DB,
    target_path: &Path,
    limits: Limits,
    fault: Fault,
) -> BResult<CopyProof> {
    let mut batches = Batches::new(target, target_path, limits, fault);
    let mut source_cf_hashes = BTreeMap::new();
    let mut primary = PrimaryFingerprint::new();
    for name in dual_cfs() {
        let hash = scan(source, snapshot, name, |key, value| {
            if key
                .len()
                .checked_add(value.len())
                .ok_or("row length overflow")?
                > limits.row_bytes
            {
                return Err("single source row budget exceeded");
            }
            if name == COMBINED {
                primary.row(key, value)?;
            }
            if name != COVERING && !(name == "default" && key == FORMAT_KEY) {
                batches.put(name, key, value)?;
            }
            Ok(())
        })?;
        source_cf_hashes.insert(name.to_owned(), hash);
    }
    let (frontier_hash, frontier_positions) = frontiers(source, snapshot, |author, head| {
        batches.put(HEAD_CF, author, &head.encode())
    })?;
    batches.flush()?;
    background_errors(source, &dual_cfs())?;
    background_errors(target, &physical_cf_names())?;
    let (primary_count, primary_sha256) = primary.finish();
    Ok(CopyProof {
        source_native_sequence: source.latest_sequence_number(),
        target_native_sequence_after_copy: target.latest_sequence_number(),
        source_cf_hashes,
        frontier_hash,
        frontier_positions,
        primary_count,
        primary_sha256,
        synchronized_batches: batches.commits,
        written_rows: batches.rows,
    })
}
fn verify_hashes(copy: &CopyProof, hashes: &BTreeMap<String, ColumnHash>) -> BResult<()> {
    equal_kept(&copy.source_cf_hashes, hashes)?;
    if hashes.get(HEAD_CF).map(|h| &h.full) != Some(&copy.frontier_hash) {
        return Err("derived frontier byte hash mismatch");
    }
    Ok(())
}
fn verify_audit(copy: &CopyProof, audit: &Value) -> BResult<()> {
    if audit["ok"] != true
        || [
            "events",
            "verified_signatures_and_bodies",
            "thin_author_records_verified",
        ]
        .iter()
        .any(|key| audit[key].as_u64() != Some(copy.primary_count))
        || audit["primary_fingerprint_sha256"].as_str() != Some(copy.primary_sha256.as_str())
        || audit["covering_records_verified"].as_u64() != Some(0)
        || audit["author_head_records_verified"].as_u64() != Some(copy.frontier_hash.rows)
        || audit["author_frontier_positions_verified"].as_u64() != Some(copy.frontier_positions)
    {
        return Err("full target audit totals or fingerprint mismatch");
    }
    Ok(())
}
fn json_sha(value: &impl Serialize) -> BResult<String> {
    let mut value = serde_json::to_value(value).map_err(|_| "proof hash serialization failed")?;
    // Match the emitted logical JSON object regardless of Rust struct field
    // declaration order or serde_json's preserve_order feature unification.
    value.sort_all_objects();
    Ok(hex_digest(Sha256::digest(
        serde_json::to_vec(&value).map_err(|_| "proof hash serialization failed")?,
    )))
}
fn target_parent(destination: &Path, source: &Path) -> BResult<()> {
    if !destination.is_absolute()
        || destination
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err("absolute canonical destination required");
    }
    let parent = destination.parent().ok_or("destination parent missing")?;
    canonical_directory(parent)?;
    if destination.file_name().is_none()
        || fs::symlink_metadata(destination).is_ok()
        || destination.starts_with(source)
        || source.starts_with(destination)
    {
        return Err("existing or overlapping destination refused");
    }
    Ok(())
}
fn seal(path: &Path) -> BResult<()> {
    // A read-only exact-marker check precedes this private writable open, too.
    drop(read_only_db(path, physical_cf_names(), PENDING)?);
    let (options, descriptors) = native_options(false, physical_cf_names());
    let db = DB::open_cf_descriptors(&options, path, descriptors)
        .map_err(|_| "seal writer open failed")?;
    if db
        .get(FORMAT_KEY)
        .map_err(|_| "seal marker read failed")?
        .as_deref()
        != Some(PENDING)
    {
        return Err("seal marker changed");
    }
    let mut options = WriteOptions::default();
    options.set_sync(true);
    options.disable_wal(false);
    db.put_opt(FORMAT_KEY, FORMAT, &options)
        .map_err(|_| "synchronous seal failed")?;
    background_errors(&db, &physical_cf_names())?;
    Ok(())
}

// The retained15M audit takes minutes. Accept only its existing numeric count
// events on this synchronous thread. Debug/message values are never formatted.
struct AuditProgress;
impl tracing::Subscriber for AuditProgress {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "wok_db::rocks::audit" && *metadata.level() == tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        struct Events(Option<u64>);
        impl tracing::field::Visit for Events {
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                if field.name() == "events" {
                    self.0 = Some(value);
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut events = Events(None);
        event.record(&mut events);
        if let Some(events) = events.0.filter(|n| *n > 0 && *n % 100_000 == 0) {
            eprintln!("WOK_PHYSICAL_BUILDER_AUDIT_PROGRESS events={events}");
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn build_inner(
    input: &Input,
    destination: &Path,
    limits: Limits,
    fault: Fault,
    stage: &mut &'static str,
    owned: &mut bool,
) -> BResult<Value> {
    if limits.batch_bytes == 0 || limits.batch_rows == 0 || limits.row_bytes == 0 {
        return Err("zero build budget refused");
    }
    target_parent(destination, &input.source)?;
    space(
        destination.parent().ok_or("destination parent missing")?,
        limits.reserve_bytes,
    )?;
    // No target directory exists until the v1 layout, snapshot, Meta and bounded
    // dictionary-cache requirements have passed these read-only checks.
    let copy = {
        let source = read_only_db(&input.source, dual_cfs(), DUAL)?;
        let sequence = source.latest_sequence_number();
        let snapshot = source.snapshot();
        if source.latest_sequence_number() != sequence {
            return Err("source sequence changed");
        }
        check_meta(&source, &snapshot)?;
        dictionary_budget(&source, &snapshot, limits)?;
        *stage = "creating_owned_target";
        fs::DirBuilder::new()
            .mode(0o700)
            .create(destination)
            .map_err(|_| "owned run directory creation refused")?;
        *owned = true;
        write_json_new(
            &destination.join("source-inventory.normalized.json"),
            &input.normalized,
        )?;
        write_json_new(
            &destination.join("normalization.json"),
            &json!({
                "format":"wok-legacy-file-inventory-normalization-v1",
                "original_inventory_sha256":input.retained_inventory_sha256,
                "original_rows":input.original_inventory_rows,
                "normalized_inventory_sha256":hash_file(&destination.join("source-inventory.normalized.json"))?.sha256,
                "policy":"Exact legacy path,size,mtime_ns,sha256 array. Safe unique relative path and size/content SHA retained; mtime_ns excluded from independent-copy byte identity. Parent directories inferred; extra empty directories not claimed by old file list are recorded in before/after inventory.",
                "source_files_match":true
            }),
        )?;
        write_json_new(
            &destination.join("owner.json"),
            &json!({
                "format":"wok-physical-builder-owner-v1", "status":"incomplete_owned_disposable_target",
                "source":input.source,"destination":destination,"provenance_sha256":input.provenance_sha256,
                "retained_inventory_sha256":input.retained_inventory_sha256,"retained_audit_sha256":input.retained_audit_sha256,
                "limits":limits,"host_os":std::env::consts::OS,"host_arch":std::env::consts::ARCH,
                "claim_scope":"No network latency, capacity, storage-savings or cross-layout performance claim. Host authorization and pristine-copy guard are external prerequisites."
            }),
        )?;
        let path = destination.join("pending-db");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "pending directory creation failed")?;
        let (options, descriptors) = native_options(true, physical_cf_names());
        let target = DB::open_cf_descriptors(&options, &path, descriptors)
            .map_err(|_| "fresh native target open failed")?;
        let mut write = WriteOptions::default();
        write.set_sync(true);
        write.disable_wal(false);
        target
            .put_opt(FORMAT_KEY, PENDING, &write)
            .map_err(|_| "incomplete marker sync failed")?;
        *stage = "incomplete_copy";
        injected(fault, Fault::AfterPending)?;
        let copy = copy_rows(&source, &snapshot, &target, &path, limits, fault)?;
        if source.latest_sequence_number() != sequence || copy.source_native_sequence != sequence {
            return Err("source sequence changed");
        }
        if copy.primary_count != input.events || copy.primary_sha256 != input.primary_sha256 {
            return Err("retained source primary fingerprint mismatch");
        }
        copy
        // Iterator/batch/snapshot/source/target handles all drop at this boundary.
    };
    *stage = "closed_copy";
    if inventory(&input.source)? != input.before {
        return Err("source closed inventory changed");
    }
    let pending = destination.join("pending-db");
    space(&pending, limits.reserve_bytes)?;
    write_json_new(
        &destination.join("copy.json"),
        &json!({
            "format":"wok-physical-builder-copy-v1","status":"copied_pending_audit",
            "source_inventory_unchanged":true,"copy":copy,
            "source_closed_inventory":input.before,"target_closed_inventory":inventory(&pending)?
        }),
    )?;
    injected(fault, Fault::AfterCopy)?;
    if fault == Fault::CorruptHead {
        // Deliberate synthetic-fixture corruption; never selectable by env/input.
        let (options, descriptors) = native_options(false, physical_cf_names());
        let db = DB::open_cf_descriptors(&options, &pending, descriptors)
            .map_err(|_| "fixture open failed")?;
        let author = {
            let mut it = db.raw_iterator_cf(cf(&db, HEAD_CF)?);
            it.seek_to_first();
            let author = it.key().ok_or("fixture head missing")?.to_vec();
            it.status().map_err(|_| "fixture iterator failed")?;
            author
        };
        db.put_cf(cf(&db, HEAD_CF)?, author, [0; 15])
            .map_err(|_| "fixture corruption failed")?;
    }
    *stage = "incomplete_audit";
    let pending_hashes = {
        let env = pending_audit_env(&pending)?;
        let hashes = all_hashes(&env.inner.db)?;
        verify_hashes(&copy, &hashes)?;
        // Map the error rather than displaying it: parser/signature errors may
        // include event fields. Audit output itself contains only hashes/counts.
        let audit = tracing::subscriber::with_default(AuditProgress, || env.audit_rocksdb_layout())
            .map_err(|_| "full target signature/body/layout audit failed")?;
        verify_audit(&copy, &audit)?;
        if env
            .inner
            .db
            .get(FORMAT_KEY)
            .map_err(|_| "pending marker read failed")?
            .as_deref()
            != Some(PENDING)
        {
            return Err("pending audit marker changed");
        }
        write_json_new(
            &destination.join("audit.json"),
            &json!({
                "format":"wok-physical-builder-audit-v1","status":"audited_pending_not_ready",
                "actual_physical_marker":String::from_utf8_lossy(PENDING),
                "intended_final_marker":String::from_utf8_lossy(FORMAT),
                "audit":audit,"pending_cf_hashes":hashes,"read_only":true
            }),
        )?;
        hashes
    };
    *stage = "audited_pending";
    injected(fault, Fault::AfterAudit)?;
    space(&pending, limits.reserve_bytes)?;
    if inventory(&input.source)? != input.before {
        return Err("source closed inventory changed");
    }
    seal(&pending)?;
    *stage = "sealed_unpublished";
    injected(fault, Fault::AfterSeal)?;
    space(&pending, limits.reserve_bytes)?;
    let final_hashes = {
        let env = Env::open(
            &pending,
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                read_only: true,
                ..EnvOptions::for_tests()
            },
        )
        .map_err(|_| "ordinary sealed read-only reopen failed")?;
        let hashes = all_hashes(&env.inner.db)?;
        verify_hashes(&copy, &hashes)?;
        // Native marker mirror must be bootstrapped from the final copied keys,
        // paired with the target sequence, not a source/pre-copy sequence.
        let txn = env
            .begin_ro()
            .map_err(|_| "sealed snapshot construction failed")?;
        for key in [b"\0schema".as_slice(), b"\0through".as_slice()] {
            txn.get(env.dbis().event_tag_kind.ok_or("tag-kind CF missing")?, key)
                .map_err(|_| "sealed marker mirror read failed")?;
        }
        env.check_background_errors()
            .map_err(|_| "sealed background errors")?;
        hashes
    };
    // Between the successful pending full audit and this reopen, the one format
    // value is the only changed user record. Raw equality makes a second15M
    // signature/body pass unnecessary; native SST/WAL files may be rewritten.
    for (name, before) in &pending_hashes {
        let after = final_hashes.get(name).ok_or("sealed CF missing")?;
        if name == "default" {
            if before.without_format != after.without_format {
                return Err("post-audit metadata changed");
            }
        } else if before != after {
            return Err("post-audit user data changed");
        }
    }
    if inventory(&input.source)? != input.before {
        return Err("source closed inventory changed");
    }
    let files = inventory(&pending)?;
    let final_path = destination.join("db");
    if fs::symlink_metadata(&final_path).is_ok() {
        return Err("publication path exists");
    }
    // Both names are inside our freshly exclusive0700 directory. As with native
    // Env opens, an external actor must not replace this owned directory.
    fs::rename(&pending, &final_path).map_err(|_| "owned target publication failed")?;
    File::open(destination)
        .map_err(|_| "run directory open failed")?
        .sync_all()
        .map_err(|_| "run directory sync failed")?;
    if inventory(&final_path)? != files {
        return Err("published closed inventory changed");
    }
    let ready = json!({
        "format":"wok-physical-builder-ready-v1","status":"passed","role":"owned_disposable_diagnostic_target",
        "db":final_path,"provenance_sha256":input.provenance_sha256,
        "owner_sha256":hash_file(&destination.join("owner.json"))?.sha256,
        "normalization_sha256":hash_file(&destination.join("normalization.json"))?.sha256,
        "copy_sha256":hash_file(&destination.join("copy.json"))?.sha256,
        "audit_sha256":hash_file(&destination.join("audit.json"))?.sha256,
        "source_inventory_unchanged":true,"closed_inventory":files,
        "closed_inventory_sha256":json_sha(&files)?,
        "cf_hashes":final_hashes,"cf_manifest_sha256":json_sha(&final_hashes)?,
        "primary_count":copy.primary_count,"primary_sha256":copy.primary_sha256,
        "omitted_cf":COVERING,"derived_cf":HEAD_CF,"format_marker":String::from_utf8_lossy(FORMAT),
        "second_source_signature_audit":false,"full_target_signature_body_audit":true,
        "scope":"Within this generated v3 layout only. Original pristine remains closed; no immutable new seed or later archival is established."
    });
    write_json_new(&destination.join("ready.json"), &ready)?;
    *stage = "diagnostic_ready";
    Ok(ready)
}
fn build(
    source: &Path,
    destination: &Path,
    proof: &Path,
    limits: Limits,
    fault: Fault,
) -> BResult<Value> {
    let input = input(source, proof)?;
    let mut stage = "preflight";
    let mut owned = false;
    let result = build_inner(&input, destination, limits, fault, &mut stage, &mut owned);
    if let Err(label) = result {
        // RAII has closed every native handle before this failure proof. If disk
        // exhaustion prevents this small file, keep the original static error.
        if owned {
            let unchanged = inventory(&input.source)
                .map(|after| after == input.before)
                .unwrap_or(false);
            let _ = write_json_new(
                &destination.join("failure.json"),
                &json!({
                    "format":"wok-physical-builder-failure-v1","status":"failed_retained",
                    "stage":stage,"error_label":label,"source_inventory_unchanged":unchanged,
                    "provenance_sha256":input.provenance_sha256,"owned_destination":destination,
                    "automatic_retry_or_cleanup":false,"ready_present":destination.join("ready.json").exists(),
                "publication_requires":"successful process exit plus validated ready proof and no failure proof"
                }),
            );
        }
        return Err(label);
    }
    result
}

#[test]
#[ignore = "requires explicit owned disposable v1 copy, provenance and absent output; never opens a default/pristine path"]
fn build_disposable_v3_target() {
    // Resolve every required env before touching a path. No input/content/keys
    // are printed on error, including through an underlying native DbError.
    let paths = [
        "WOK_PHYSICAL_BUILDER_SOURCE",
        "WOK_PHYSICAL_BUILDER_DESTINATION",
        "WOK_PHYSICAL_BUILDER_PROVENANCE",
    ]
    .map(std::env::var_os);
    let [Some(source), Some(destination), Some(proof)] = paths else {
        panic!("all three WOK_PHYSICAL_BUILDER path variables are required");
    };
    match build(
        Path::new(&source),
        Path::new(&destination),
        Path::new(&proof),
        Limits::default(),
        Fault::None,
    ) {
        Ok(ready) => println!(
            "WOK_PHYSICAL_BUILDER_RESULT {}",
            json!({
                "status":"passed","db":ready["db"],"primary_count":ready["primary_count"],
                "primary_sha256":ready["primary_sha256"],"cf_manifest_sha256":ready["cf_manifest_sha256"]
            })
        ),
        Err(label) => {
            eprintln!("WOK_PHYSICAL_BUILDER_FAILED {label}");
            panic!("physical builder failed; owned output retained if created");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decompressor, EventToWrite, NoopNegentropy};
    use secp256k1::{Keypair, SecretKey, SECP256K1};
    use wok_event::PackedEventView;

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        source: PathBuf,
        proof: PathBuf,
        expected_heads: BTreeMap<[u8; 32], AuthorHead>,
    }
    fn signed(n: u64, who: u8, created: u64) -> EventToWrite {
        let key =
            Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[who; 32]).unwrap());
        let mut value = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
            "kind":1,"created_at":created,"tags":[["t","physical-copy"]],
            "content":format!("private synthetic fixture {n}: 🥘\u{7f}")});
        let id = wok_event::event_id_hash(&value).unwrap();
        value["id"] = json!(hex::encode(id));
        value["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
        let parsed = wok_event::parse_and_verify_event(
            &value,
            &wok_event::EventLimits::default(),
            None,
            true,
            false,
        )
        .unwrap();
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
    }
    fn limits() -> Limits {
        Limits {
            reserve_bytes: 0,
            batch_rows: 2,
            batch_bytes: 256,
            ..Limits::default()
        }
    }
    fn replace_json(path: &Path, value: &impl Serialize) {
        // Synthetic fixture metadata only, never the real builder output path.
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
    fn legacy_inventory(path: &Path) -> Vec<LegacyFile> {
        inventory(path)
            .unwrap()
            .files
            .into_iter()
            .map(|(name, file)| {
                let meta = fs::metadata(path.join(&name)).unwrap();
                LegacyFile {
                    path: name,
                    size: file.bytes,
                    mtime_ns: u64::try_from(
                        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
                    )
                    .unwrap(),
                    sha256: file.sha256,
                }
            })
            .collect()
    }
    // Fixture-only verification deliberately emits the historical9aa audit
    // schema: there is NO thin_author_records_verified field. This tiny signed
    // source is fully checked here; the real ignored builder reuses a retained
    // audit instead of performing another15M source signature/body audit.
    fn fixture_v1_audit(path: &Path) -> Value {
        let db = read_only_db(path, dual_cfs(), DUAL).unwrap();
        let env = Env::from_native_db(db, path, true).unwrap();
        let txn = env.begin_ro().unwrap();
        let snapshot = env.inner.db.snapshot();
        let mut primary = PrimaryFingerprint::new();
        let mut decompressor = Decompressor::new();
        scan(&env.inner.db, &snapshot, COMBINED, |key, value| {
            primary.row(key, value)?;
            let (local, _) = decode(3, key, &[]).unwrap();
            let (packed, payload) = parts(value).unwrap();
            let event = PackedEventView::new(packed.unwrap()).unwrap();
            let json = decompressor
                .decode(&txn, payload.unwrap(), 16 << 20)
                .unwrap();
            let parsed = wok_event::json::parse_strict(json).unwrap();
            wok_event::verify_strfry_event(event, &parsed).unwrap();
            let posting = encode(
                10,
                &crate::keys::make_key_string_u64(event.pubkey(), event.created_at()),
                Some(&local),
            );
            assert_eq!(
                snapshot
                    .get_cf(cf(&env.inner.db, cf_name(10))?, &posting)
                    .unwrap()
                    .as_deref(),
                Some(&[][..])
            );
            assert_eq!(
                snapshot
                    .get_cf(cf(&env.inner.db, COVERING)?, &posting)
                    .unwrap()
                    .as_deref(),
                Some(value)
            );
            Ok(())
        })
        .unwrap();
        let (events, primary_sha256) = primary.finish();
        let mut counts = serde_json::Map::new();
        for dbi in 1..=COVER_DBI {
            let mut count = 0;
            scan(&env.inner.db, &snapshot, cf_name(dbi), |_, value| {
                let present = if combined(dbi) {
                    let (a, b) = parts(value).unwrap();
                    if dbi == 3 {
                        a.is_some()
                    } else {
                        b.is_some()
                    }
                } else {
                    true
                };
                count += u64::from(present);
                Ok(())
            })
            .unwrap();
            let key = format!("entries/{dbi}");
            let expected = env
                .inner
                .db
                .get(key.as_bytes())
                .unwrap()
                .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
                .unwrap_or(0);
            assert_eq!(count, expected);
            counts.insert(
                if dbi == COVER_DBI {
                    COVERING
                } else {
                    spec(dbi).name
                }
                .to_owned(),
                json!(count),
            );
        }
        assert_eq!(counts[crate::schema::DBI_EVENT_PUBKEY], events);
        assert_eq!(counts[COVERING], events);
        json!({"ok":true,"events":events,"verified_signatures_and_bodies":events,
            "covering_records_verified":events,"primary_fingerprint_sha256":primary_sha256,
            "table_counts":counts,"layout":String::from_utf8_lossy(DUAL),
            "durability":"one atomic cross-CF WriteBatch with sync WAL before ACK; no power-loss proof implied"})
    }
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let source = root.join("disposable-v1");
        let mut positions: BTreeMap<[u8; 32], Vec<AuthorPosition>> = BTreeMap::new();
        {
            let env = Env::open(root.join("fixture-v3"), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut events = vec![
                signed(1, 7, 10),
                signed(2, 8, 20),
                signed(3, 7, 30),
                signed(4, 9, 0),
                signed(5, 7, 30),
                signed(6, 8, 50),
            ];
            let mut txn = env.begin_rw().unwrap();
            crate::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
            let dictionary = b"synthetic physical-copy dictionary \0\xff payload payload payload";
            let dict_id = crate::insert_compression_dictionary(&mut txn, dictionary).unwrap();
            let compressed = zstd::bulk::Compressor::with_dictionary(3, dictionary)
                .unwrap()
                .compress(events[0].json.as_bytes())
                .unwrap();
            txn.put_u64(
                env.dbis().event_payload,
                events[0].lev_id,
                &crate::encode_zstd_payload(u32::try_from(dict_id).unwrap(), &compressed),
                0,
            )
            .unwrap();
            txn.put(
                env.dbis().state.unwrap(),
                b"opaque\0state",
                b"\0\xffkept",
                0,
            )
            .unwrap();
            txn.commit().unwrap();
            env.inner
                .db
                .put(b"opaque\0default", b"\xff\0metadata")
                .unwrap();
            env.inner
                .db
                .put(b"entries/23", (events.len() as u64).to_le_bytes())
                .unwrap();
            for event in &events {
                let packed = PackedEventView::new(&event.packed).unwrap();
                positions
                    .entry(packed.pubkey().try_into().unwrap())
                    .or_default()
                    .push(AuthorPosition {
                        created_at: packed.created_at(),
                        local_id: event.lev_id,
                    });
            }
            let (options, descriptors) = native_options(true, dual_cfs());
            let db = DB::open_cf_descriptors(&options, &source, descriptors).unwrap();
            let snapshot = env.inner.db.snapshot();
            let mut batch = WriteBatch::default();
            for name in dual_cfs().into_iter().filter(|name| *name != COVERING) {
                scan(&env.inner.db, &snapshot, name, |key, value| {
                    batch.put_cf(
                        cf(&db, name)?,
                        key,
                        if name == "default" && key == FORMAT_KEY {
                            DUAL
                        } else {
                            value
                        },
                    );
                    if name == COMBINED {
                        let (local, _) = decode(3, key, &[]).unwrap();
                        let event = PackedEventView::new(parts(value).unwrap().0.unwrap()).unwrap();
                        let posting = encode(
                            10,
                            &crate::keys::make_key_string_u64(event.pubkey(), event.created_at()),
                            Some(&local),
                        );
                        batch.put_cf(cf(&db, COVERING)?, posting, value);
                    }
                    Ok(())
                })
                .unwrap();
            }
            let mut options = WriteOptions::default();
            options.set_sync(true);
            db.write_opt(batch, &options).unwrap();
        }
        let expected_heads = positions
            .into_iter()
            .map(|(author, mut rows)| {
                rows.sort_unstable_by(|a, b| b.cmp(a));
                (
                    author,
                    AuthorHead {
                        first: rows[0],
                        next: rows.get(1).copied(),
                    },
                )
            })
            .collect();
        let before = inventory(&source).unwrap();
        let audit = fixture_v1_audit(&source);
        assert!(audit.get("thin_author_records_verified").is_none());
        assert_eq!(inventory(&source).unwrap(), before);
        let inventory_path = root.join("original-inventory.json");
        write_json_new(&inventory_path, &legacy_inventory(&source)).unwrap();
        let audit_path = root.join("original-audit.json");
        write_json_new(&audit_path, &audit).unwrap();
        let proof = root.join("source-provenance.json");
        write_json_new(&proof, &json!({
            "format":"wok-physical-builder-source-v1","source":source,"disposable_copy":true,
            "retained_inventory":inventory_path,"retained_inventory_sha256":hash_file(&inventory_path).unwrap().sha256,
            "retained_audit":audit_path,"retained_audit_sha256":hash_file(&audit_path).unwrap().sha256
        })).unwrap();
        Fixture {
            _dir: dir,
            root,
            source,
            proof,
            expected_heads,
        }
    }
    fn rebind_synthetic_inventory(fixture: &Fixture) {
        let mut p: Value = read_json(&fixture.proof).unwrap().0;
        let path = Path::new(p["retained_inventory"].as_str().unwrap());
        replace_json(path, &legacy_inventory(&fixture.source));
        p["retained_inventory_sha256"] = json!(hash_file(path).unwrap().sha256);
        replace_json(&fixture.proof, &p);
    }
    fn mutate_source(f: &Fixture, mutate: impl FnOnce(&DB)) {
        let (options, descriptors) = native_options(false, dual_cfs());
        {
            let db = DB::open_cf_descriptors(&options, &f.source, descriptors).unwrap();
            mutate(&db);
        }
        rebind_synthetic_inventory(f);
    }
    fn ready(f: &Fixture, name: &str, budget: Limits) -> Value {
        let destination = f.root.join(name);
        let before = inventory(&f.source).unwrap();
        let ready = build(&f.source, &destination, &f.proof, budget, Fault::None).unwrap();
        assert_eq!(inventory(&f.source).unwrap(), before);
        assert_eq!(ready["status"], "passed");
        ready
    }

    #[test]
    fn legacy_signed_source_preserves_all_kept_bytes_and_frontiers_across_batch_boundaries() {
        let f = fixture();
        let one = ready(
            &f,
            "one-row-batches",
            Limits {
                batch_rows: 1,
                ..limits()
            },
        );
        let many = ready(
            &f,
            "larger-batches",
            Limits {
                batch_rows: 10_000,
                batch_bytes: 8 << 20,
                ..limits()
            },
        );
        assert_eq!(one["cf_hashes"], many["cf_hashes"]);
        assert_eq!(one["primary_sha256"], many["primary_sha256"]);
        let path = Path::new(one["db"].as_str().unwrap());
        let env = Env::open(
            path,
            EnvOptions {
                read_only: true,
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::for_tests()
            },
        )
        .unwrap();
        assert!(env.inner.db.cf_handle(COVERING).is_none());
        assert_eq!(
            env.inner.db.get(b"opaque\0default").unwrap().as_deref(),
            Some(&b"\xff\0metadata"[..])
        );
        assert_eq!(
            env.inner.db.get(b"entries/23").unwrap().unwrap(),
            6u64.to_le_bytes()
        );
        let txn = env.begin_ro().unwrap();
        let authors: Vec<_> = f.expected_heads.keys().collect();
        assert_eq!(
            txn.author_heads(authors).unwrap(),
            f.expected_heads
                .values()
                .copied()
                .map(Some)
                .collect::<Vec<_>>()
        );
        let normalization: Value = read_json(&f.root.join("one-row-batches/normalization.json"))
            .unwrap()
            .0;
        let original: Value = read_json(&f.proof).unwrap().0;
        assert_eq!(
            normalization["original_inventory_sha256"],
            original["retained_inventory_sha256"]
        );
        assert_eq!(
            normalization["original_rows"].as_u64(),
            Some(inventory(&f.source).unwrap().files.len() as u64)
        );
    }
    #[test]
    fn retained_legacy_audit_requires_both_author_counts_and_checks_optional_new_field() {
        let mut audit = json!({"ok":true,"events":15_000_000,"verified_signatures_and_bodies":15_000_000,
            "covering_records_verified":15_000_000,"primary_fingerprint_sha256":"4d220f614c2b01ccfba317129f15a196fb20173f3acea29ca6e1da735ab95db0",
            "layout":String::from_utf8_lossy(DUAL),"table_counts":{
                (crate::schema::DBI_EVENT_PUBKEY):15_000_000,(COVERING):15_000_000}});
        assert!(retained_audit(&audit).is_ok());
        audit["thin_author_records_verified"] = json!(15_000_000);
        assert!(retained_audit(&audit).is_ok());
        audit["thin_author_records_verified"] = json!(14_999_999);
        assert!(retained_audit(&audit).is_err());
        audit
            .as_object_mut()
            .unwrap()
            .remove("thin_author_records_verified");
        audit["table_counts"][crate::schema::DBI_EVENT_PUBKEY] = json!(14_999_999);
        assert!(retained_audit(&audit).is_err());
    }
    #[test]
    fn rejects_existing_destination_and_wrong_layout_without_mutating_unowned_paths() {
        let f = fixture();
        let destination = f.root.join("existing");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("owner.json"), b"unrelated existing file").unwrap();
        let before = inventory(&destination).unwrap();
        assert!(build(&f.source, &destination, &f.proof, limits(), Fault::None).is_err());
        assert_eq!(inventory(&destination).unwrap(), before);
        mutate_source(&f, |db| db.put(FORMAT_KEY, FORMAT).unwrap());
        let source_before = inventory(&f.source).unwrap();
        let absent = f.root.join("wrong-layout-output");
        assert!(build(&f.source, &absent, &f.proof, limits(), Fault::None).is_err());
        assert!(!absent.exists());
        assert_eq!(inventory(&f.source).unwrap(), source_before);
        {
            let (options, descriptors) = native_options(false, dual_cfs());
            let mut db = DB::open_cf_descriptors(&options, &f.source, descriptors).unwrap();
            db.put(FORMAT_KEY, DUAL).unwrap();
            db.create_cf("unexpected_fixture_cf", &rocksdb::Options::default())
                .unwrap();
        }
        rebind_synthetic_inventory(&f);
        let before = inventory(&f.source).unwrap();
        let absent = f.root.join("wrong-CF-output");
        assert_eq!(
            build(&f.source, &absent, &f.proof, limits(), Fault::None).unwrap_err(),
            "physical CF set mismatch"
        );
        assert!(!absent.exists());
        assert_eq!(inventory(&f.source).unwrap(), before);
    }
    #[test]
    fn pending_faults_refuse_normal_opens_and_do_not_resume_or_publish() {
        for fault in [
            Fault::AfterPending,
            Fault::AfterBatch,
            Fault::AfterCopy,
            Fault::AfterAudit,
            Fault::AfterSeal,
        ] {
            let f = fixture();
            let destination = f.root.join("failed-owned");
            let before = inventory(&f.source).unwrap();
            assert!(build(&f.source, &destination, &f.proof, limits(), fault).is_err());
            assert!(!destination.join("ready.json").exists());
            assert!(!destination.join("db").exists());
            assert_eq!(inventory(&f.source).unwrap(), before);
            let pending = destination.join("pending-db");
            let closed = inventory(&pending).unwrap();
            if fault != Fault::AfterSeal {
                for read_only in [false, true] {
                    for create_dbis in [false, true] {
                        assert!(Env::open(
                            &pending,
                            EnvOptions {
                                read_only,
                                create_dbis,
                                create_dir: false,
                                ..EnvOptions::for_tests()
                            }
                        )
                        .is_err());
                        assert_eq!(inventory(&pending).unwrap(), closed);
                    }
                }
            } else {
                assert!(destination.join("audit.json").is_file());
                drop(read_only_db(&pending, physical_cf_names(), FORMAT).unwrap());
            }
            let retained = inventory(&destination).unwrap();
            assert!(build(&f.source, &destination, &f.proof, limits(), Fault::None).is_err());
            assert_eq!(inventory(&destination).unwrap(), retained);
        }
    }
    #[test]
    fn pending_audit_adapter_is_exact_layout_marker_and_read_only() {
        let f = fixture();
        let destination = f.root.join("pending-adapter");
        assert!(build(
            &f.source,
            &destination,
            &f.proof,
            limits(),
            Fault::AfterCopy
        )
        .is_err());
        let path = destination.join("pending-db");
        let before = inventory(&path).unwrap();
        {
            let env = pending_audit_env(&path).unwrap();
            assert!(env.begin_rw().is_err());
            let audit = env.audit_rocksdb_layout().unwrap();
            assert_eq!(audit["verified_signatures_and_bodies"], 6);
        }
        assert_eq!(inventory(&path).unwrap(), before);
        let (options, descriptors) = native_options(false, physical_cf_names());
        {
            let db = DB::open_cf_descriptors(&options, &path, descriptors).unwrap();
            db.put(FORMAT_KEY, FORMAT).unwrap();
        }
        let before = inventory(&path).unwrap();
        assert!(pending_audit_env(&path).is_err());
        assert_eq!(inventory(&path).unwrap(), before);
        assert!(pending_audit_env(&f.source).is_err());
    }
    #[test]
    fn missing_empty_components_malformed_thin_and_corrupt_derived_bytes_never_publish() {
        for packed in [None, Some(Vec::new())] {
            let f = fixture();
            mutate_source(&f, |db| {
                let key = encode(3, &1u64.to_ne_bytes(), None);
                let old = db.get_cf(cf(db, COMBINED).unwrap(), &key).unwrap().unwrap();
                let payload = parts(&old).unwrap().1.unwrap().to_vec();
                let raw = Record {
                    packed,
                    payload: Some(payload),
                }
                .encode();
                db.put_cf(cf(db, COMBINED).unwrap(), key, &raw).unwrap();
            });
            let destination = f.root.join("invalid-components");
            assert!(build(&f.source, &destination, &f.proof, limits(), Fault::None).is_err());
            assert!(!destination.join("ready.json").exists());
        }
        let f = fixture();
        mutate_source(&f, |db| {
            let posting = encode(
                10,
                &crate::keys::make_key_string_u64(&[3; 32], 1),
                Some(b"bad"),
            );
            db.put_cf(cf(db, cf_name(10)).unwrap(), posting, [])
                .unwrap();
        });
        let destination = f.root.join("bad-thin");
        assert!(build(&f.source, &destination, &f.proof, limits(), Fault::None).is_err());
        assert!(!destination.join("ready.json").exists());
        let f = fixture();
        let destination = f.root.join("bad-derived");
        assert!(build(
            &f.source,
            &destination,
            &f.proof,
            limits(),
            Fault::CorruptHead
        )
        .is_err());
        assert!(!destination.join("ready.json").exists());
    }
    #[test]
    fn full_output_body_audit_is_required_even_if_input_claims_a_matching_fingerprint() {
        let f = fixture();
        mutate_source(&f, |db| {
            let key = encode(3, &1u64.to_ne_bytes(), None);
            let old = db.get_cf(cf(db, COMBINED).unwrap(), &key).unwrap().unwrap();
            let packed = parts(&old).unwrap().0.unwrap().to_vec();
            let raw = Record {
                packed: Some(packed),
                payload: Some(crate::encode_raw_payload("invalid synthetic JSON body")),
            }
            .encode();
            db.put_cf(cf(db, COMBINED).unwrap(), key, raw).unwrap();
        });
        // Deliberately forge only this synthetic retained report's fingerprint.
        // A caller's claimed prior audit must never bypass the real target audit.
        let (db, primary) = {
            let db = read_only_db(&f.source, dual_cfs(), DUAL).unwrap();
            let mut fp = PrimaryFingerprint::new();
            scan(&db, &db.snapshot(), COMBINED, |key, value| {
                fp.row(key, value)
            })
            .unwrap();
            let fp = fp.finish().1;
            (db, fp)
        };
        drop(db);
        let mut p: Value = read_json(&f.proof).unwrap().0;
        let audit_path = PathBuf::from(p["retained_audit"].as_str().unwrap());
        let mut audit: Value = read_json(&audit_path).unwrap().0;
        audit["primary_fingerprint_sha256"] = json!(primary);
        replace_json(&audit_path, &audit);
        p["retained_audit_sha256"] = json!(hash_file(&audit_path).unwrap().sha256);
        replace_json(&f.proof, &p);
        let destination = f.root.join("forged-input-proof");
        assert_eq!(
            build(&f.source, &destination, &f.proof, limits(), Fault::None).unwrap_err(),
            "full target signature/body/layout audit failed"
        );
        let failure = fs::read_to_string(destination.join("failure.json")).unwrap();
        assert!(!failure.contains("invalid synthetic JSON body"));
        assert!(!destination.join("ready.json").exists());
    }
    #[test]
    fn frontier_pass_handles_full_width_ties_id_zero_and_empty_authors() {
        let dir = tempfile::tempdir().unwrap();
        let (options, descriptors) = native_options(true, dual_cfs());
        let db = DB::open_cf_descriptors(&options, dir.path(), descriptors).unwrap();
        let a = [0; 32];
        let b = [255; 32];
        let rows = [
            (a, 0, 0),
            (a, u64::MAX, 0),
            (a, u64::MAX, u64::MAX),
            (b, 0, u64::MAX),
        ];
        for (author, time, id) in rows {
            db.put_cf(
                cf(&db, cf_name(10)).unwrap(),
                encode(
                    10,
                    &crate::keys::make_key_string_u64(&author, time),
                    Some(&id.to_ne_bytes()),
                ),
                [],
            )
            .unwrap();
        }
        let mut found = BTreeMap::new();
        let (hash, positions) = frontiers(&db, &db.snapshot(), |author, head| {
            found.insert(*author, head);
            Ok(())
        })
        .unwrap();
        assert_eq!(hash.rows, 2);
        assert_eq!(positions, 3);
        assert_eq!(
            found[&a],
            AuthorHead {
                first: AuthorPosition {
                    created_at: u64::MAX,
                    local_id: u64::MAX
                },
                next: Some(AuthorPosition {
                    created_at: u64::MAX,
                    local_id: 0
                })
            }
        );
        assert_eq!(
            found[&b],
            AuthorHead {
                first: AuthorPosition {
                    created_at: 0,
                    local_id: u64::MAX
                },
                next: None
            }
        );
        for (author, time, id) in rows {
            db.delete_cf(
                cf(&db, cf_name(10)).unwrap(),
                encode(
                    10,
                    &crate::keys::make_key_string_u64(&author, time),
                    Some(&id.to_ne_bytes()),
                ),
            )
            .unwrap();
        }
        // An empty native CF emits no synthetic default head.
        let (hash, positions) = frontiers(&db, &db.snapshot(), |_, _| {
            panic!("empty CF emitted a head")
        })
        .unwrap();
        assert_eq!(hash.rows, 0);
        assert_eq!(positions, 0);
    }
    #[test]
    fn length_framing_normalization_and_resource_refusals_are_not_ambiguous() {
        let typed = CfHash {
            rows: 1,
            key_bytes: 2,
            value_bytes: 3,
            sha256: "fixture".into(),
        };
        let reordered = json!({"value_bytes":3,"sha256":"fixture","rows":1,"key_bytes":2});
        assert_eq!(json_sha(&typed).unwrap(), json_sha(&reordered).unwrap());
        let mut a = Framed::new("cf");
        a.row(b"a", b"bc").unwrap();
        let mut b = Framed::new("cf");
        b.row(b"ab", b"c").unwrap();
        assert_ne!(a.finish().sha256, b.finish().sha256);
        let row = LegacyFile {
            path: "../escape".into(),
            size: 0,
            mtime_ns: 0,
            sha256: hex_digest(Sha256::digest([])),
        };
        assert!(normalize_inventory(vec![row]).is_err());
        let f = fixture();
        let source_before = inventory(&f.source).unwrap();
        let destination = f.root.join("reserve-refusal");
        assert!(build(
            &f.source,
            &destination,
            &f.proof,
            Limits {
                reserve_bytes: u64::MAX,
                ..limits()
            },
            Fault::None
        )
        .is_err());
        assert!(!destination.exists());
        assert_eq!(inventory(&f.source).unwrap(), source_before);
        let destination = f.root.join("dictionary-budget-refusal");
        assert!(build(
            &f.source,
            &destination,
            &f.proof,
            Limits {
                dictionary_records: 0,
                ..limits()
            },
            Fault::None
        )
        .is_err());
        assert!(!destination.exists());
        mutate_source(&f, |db| db.put(b"oversize-opaque", vec![0; 2048]).unwrap());
        let destination = f.root.join("row-budget-refusal");
        assert!(build(
            &f.source,
            &destination,
            &f.proof,
            Limits {
                row_bytes: 512,
                ..limits()
            },
            Fault::None
        )
        .is_err());
        assert!(!destination.join("ready.json").exists());
        let alias = f.root.join("source-alias");
        std::os::unix::fs::symlink(&f.source, &alias).unwrap();
        let destination = f.root.join("symlink-refusal");
        assert!(build(&alias, &destination, &f.proof, limits(), Fault::None).is_err());
        assert!(!destination.exists());
        let hardlink = f.root.join("linked-copy");
        let original = f.source.join("CURRENT");
        fs::hard_link(&original, &hardlink).unwrap();
        let destination = f.root.join("hardlink-refusal");
        assert!(build(&f.source, &destination, &f.proof, limits(), Fault::None).is_err());
        assert!(!destination.exists());
    }
}
