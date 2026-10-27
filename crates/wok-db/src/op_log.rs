//! Bench-only record of every committed write, so the writer's storage work
//! can be replayed on other engines (#257 item 12). Built only with the
//! `op-log` feature; nothing calls it in a relay.
//!
//! The log is a zstd stream. A header names each table with its DBI number,
//! open flags and comparator. Then come records, all integers little-endian:
//!
//! - `P dbi:u32 flags:u32 klen:u32 key vlen:u32 val`: a put that changed the
//!   table, with its `mdb_put` flags.
//! - `D dbi:u32 klen:u32 key has_val:u8 [vlen:u32 val]`: a delete that
//!   removed something. Deleting every duplicate of a key is logged as one
//!   record per duplicate, so a replay needs no reads.
//! - `X dbi:u32`: a table was cleared.
//! - `C`: the transaction holding the records since the last `C` committed.
//!   Aborted transactions leave no records.
//! - `H len:u16 label`: a phase marker from the caller.
//! - `E`: end of log.
//!
//! Puts that changed nothing (`MDB_KEYEXIST`) and deletes that found nothing
//! are not logged. Reads are not logged.

use crate::env::{Dbis, Env};
use crate::schema::{dbi_specs, ComparatorKind};
use lmdb_sys::MDB_dbi;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

pub const MAGIC: &[u8; 8] = b"WOKOPS1\n";

static ACTIVE: AtomicBool = AtomicBool::new(false);
static LOG: Mutex<Option<zstd::Encoder<'static, BufWriter<File>>>> = Mutex::new(None);

pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Every table `env` opened, by name, with its DBI number.
pub fn table_dbis(env: &Env) -> Vec<(&'static str, MDB_dbi)> {
    tables(&env.dbis())
        .into_iter()
        .filter_map(|(name, dbi)| dbi.map(|dbi| (name, dbi)))
        .collect()
}

fn tables(d: &Dbis) -> Vec<(&'static str, Option<MDB_dbi>)> {
    use crate::schema::*;
    vec![
        (DBI_META, Some(d.meta)),
        (DBI_NEGENTROPY_FILTER, Some(d.negentropy_filter)),
        (DBI_EVENT, Some(d.event)),
        (DBI_EVENT_ID, Some(d.event_id)),
        (DBI_EVENT_PUBKEY_KIND, Some(d.event_pubkey_kind)),
        (DBI_EVENT_TAG, Some(d.event_tag)),
        (DBI_EVENT_DELETION, Some(d.event_deletion)),
        (DBI_EVENT_REPLACE, Some(d.event_replace)),
        (DBI_EVENT_CREATED_AT, Some(d.event_created_at)),
        (DBI_EVENT_PUBKEY, Some(d.event_pubkey)),
        (DBI_EVENT_REPLACE_DELETION, Some(d.event_replace_deletion)),
        (DBI_EVENT_KIND, Some(d.event_kind)),
        (DBI_EVENT_EXPIRATION, Some(d.event_expiration)),
        (DBI_COMPRESSION_DICTIONARY, Some(d.compression_dictionary)),
        (DBI_EVENT_PAYLOAD, Some(d.event_payload)),
        (DBI_NEGENTROPY, Some(d.negentropy)),
        (DBI_EVENT_SEARCH, d.event_search),
        (DBI_VANISH_PUBKEY, d.vanish_pubkey),
        (DBI_MODERATION, d.moderation),
        (DBI_STATE, d.state),
        (DBI_EVENT_TAG_KIND, d.event_tag_kind),
        (DBI_EVENT_TAG_KIND_BUILD, d.event_tag_kind_build),
    ]
}

fn comparator_code(kind: ComparatorKind) -> u8 {
    match kind {
        ComparatorKind::Default => 0,
        ComparatorKind::StringUint64 => 1,
        ComparatorKind::Uint64Uint64 => 2,
        ComparatorKind::StringUint64Uint64 => 3,
    }
}

/// Start logging every write transaction `env` commits to `path`.
pub fn start(path: &Path, env: &Env) -> io::Result<()> {
    let mut out = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, File::create(path)?), 1)?;
    out.write_all(MAGIC)?;
    let tables = table_dbis(env);
    out.write_all(&(tables.len() as u32).to_le_bytes())?;
    for (name, dbi) in tables {
        let spec = dbi_specs()
            .iter()
            .find(|spec| spec.name == name)
            .expect("every table has a spec");
        out.write_all(&dbi.to_le_bytes())?;
        out.write_all(&spec.flags.to_le_bytes())?;
        out.write_all(&[comparator_code(spec.comparator)])?;
        out.write_all(&(name.len() as u16).to_le_bytes())?;
        out.write_all(name.as_bytes())?;
    }
    *LOG.lock().unwrap() = Some(out);
    ACTIVE.store(true, Ordering::Relaxed);
    Ok(())
}

/// Mark the start of a phase, between transactions.
pub fn phase(label: &str) -> io::Result<()> {
    let mut log = LOG.lock().unwrap();
    let Some(out) = log.as_mut() else {
        return Ok(());
    };
    out.write_all(b"H")?;
    out.write_all(&(label.len() as u16).to_le_bytes())?;
    out.write_all(label.as_bytes())
}

/// End the log and flush it to disk.
pub fn finish() -> io::Result<()> {
    ACTIVE.store(false, Ordering::Relaxed);
    let Some(mut out) = LOG.lock().unwrap().take() else {
        return Ok(());
    };
    out.write_all(b"E")?;
    let mut file = out.finish()?;
    file.flush()?;
    file.into_inner().map_err(|e| e.into_error())?.sync_all()
}

pub(crate) fn committed(ops: &[u8]) {
    let mut log = LOG.lock().unwrap();
    if let Some(out) = log.as_mut() {
        out.write_all(ops)
            .and_then(|()| out.write_all(b"C"))
            .expect("write the op log");
    }
}

fn bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

pub(crate) fn put(buf: &mut Vec<u8>, dbi: MDB_dbi, flags: u32, key: &[u8], val: &[u8]) {
    buf.push(b'P');
    buf.extend_from_slice(&dbi.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    bytes(buf, key);
    bytes(buf, val);
}

pub(crate) fn del(buf: &mut Vec<u8>, dbi: MDB_dbi, key: &[u8], val: Option<&[u8]>) {
    buf.push(b'D');
    buf.extend_from_slice(&dbi.to_le_bytes());
    bytes(buf, key);
    match val {
        Some(val) => {
            buf.push(1);
            bytes(buf, val);
        }
        None => buf.push(0),
    }
}

pub(crate) fn clear(buf: &mut Vec<u8>, dbi: MDB_dbi) {
    buf.push(b'X');
    buf.extend_from_slice(&dbi.to_le_bytes());
}
