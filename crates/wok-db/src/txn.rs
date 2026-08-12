//! Transactions and cursors. mmap slices are valid only for `&self` of the txn.

use crate::env::Env;
use crate::error::check;
use crate::keys::u64_from_ne;
use crate::DbError;
use lmdb_sys::*;
use std::marker::PhantomData;
use std::ptr;

type Kv<'a> = (&'a [u8], &'a [u8]);

pub struct RoTxn<'env> {
    pub(crate) txn: *mut MDB_txn,
    pub(crate) env: &'env Env,
    committed: bool,
}

pub struct RwTxn<'env> {
    pub(crate) txn: *mut MDB_txn,
    pub(crate) env: &'env Env,
    committed: bool,
}

impl<'env> RoTxn<'env> {
    pub fn begin(env: &'env Env) -> Result<Self, DbError> {
        let mut txn = ptr::null_mut();
        unsafe {
            check(mdb_txn_begin(
                env.inner.env,
                ptr::null_mut(),
                MDB_RDONLY,
                &mut txn,
            ))?;
        }
        Ok(Self {
            txn,
            env,
            committed: false,
        })
    }

    pub fn get<'a>(&'a self, dbi: MDB_dbi, key: &[u8]) -> Result<Option<&'a [u8]>, DbError> {
        get_raw(self.txn, dbi, key)
    }

    pub fn get_u64(&self, dbi: MDB_dbi, key: u64) -> Result<Option<&[u8]>, DbError> {
        self.get(dbi, &key.to_ne_bytes())
    }

    pub fn cursor(&self, dbi: MDB_dbi) -> Result<Cursor<'_>, DbError> {
        Cursor::open(self.txn, dbi)
    }

    pub fn env(&self) -> &'env Env {
        self.env
    }

    pub fn raw(&self) -> *mut MDB_txn {
        self.txn
    }

    pub fn foreach_full<F>(
        &self,
        dbi: MDB_dbi,
        start_key: &[u8],
        start_dup: &[u8],
        reverse: bool,
        cb: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        foreach_full(self.txn, dbi, start_key, start_dup, reverse, cb)
    }

    pub fn abort(mut self) {
        self.committed = true;
        unsafe { mdb_txn_abort(self.txn) }
    }
}

impl Drop for RoTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe { mdb_txn_abort(self.txn) }
        }
    }
}

impl<'env> RwTxn<'env> {
    pub fn begin(env: &'env Env) -> Result<Self, DbError> {
        let mut txn = ptr::null_mut();
        unsafe {
            check(mdb_txn_begin(env.inner.env, ptr::null_mut(), 0, &mut txn))?;
        }
        Ok(Self {
            txn,
            env,
            committed: false,
        })
    }

    pub fn get<'a>(&'a self, dbi: MDB_dbi, key: &[u8]) -> Result<Option<&'a [u8]>, DbError> {
        get_raw(self.txn, dbi, key)
    }

    pub fn get_u64(&self, dbi: MDB_dbi, key: u64) -> Result<Option<&[u8]>, DbError> {
        self.get(dbi, &key.to_ne_bytes())
    }

    pub fn put(
        &mut self,
        dbi: MDB_dbi,
        key: &[u8],
        val: &[u8],
        flags: u32,
    ) -> Result<bool, DbError> {
        put_raw(self.txn, dbi, key, val, flags)
    }

    pub fn put_u64(
        &mut self,
        dbi: MDB_dbi,
        key: u64,
        val: &[u8],
        flags: u32,
    ) -> Result<bool, DbError> {
        self.put(dbi, &key.to_ne_bytes(), val, flags)
    }

    pub fn del(&mut self, dbi: MDB_dbi, key: &[u8], val: Option<&[u8]>) -> Result<bool, DbError> {
        del_raw(self.txn, dbi, key, val)
    }

    pub fn del_u64(&mut self, dbi: MDB_dbi, key: u64, val: Option<&[u8]>) -> Result<bool, DbError> {
        self.del(dbi, &key.to_ne_bytes(), val)
    }

    pub fn cursor(&self, dbi: MDB_dbi) -> Result<Cursor<'_>, DbError> {
        Cursor::open(self.txn, dbi)
    }

    pub fn env(&self) -> &'env Env {
        self.env
    }

    pub fn raw(&self) -> *mut MDB_txn {
        self.txn
    }

    pub fn foreach_full<F>(
        &self,
        dbi: MDB_dbi,
        start_key: &[u8],
        start_dup: &[u8],
        reverse: bool,
        cb: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        foreach_full(self.txn, dbi, start_key, start_dup, reverse, cb)
    }

    pub fn next_integer_key(&self, dbi: MDB_dbi) -> Result<u64, DbError> {
        Ok(largest_integer_key(self.txn, dbi)? + 1)
    }

    pub fn commit(mut self) -> Result<(), DbError> {
        self.committed = true;
        check(unsafe { mdb_txn_commit(self.txn) })
    }

    pub fn abort(mut self) {
        self.committed = true;
        unsafe { mdb_txn_abort(self.txn) }
    }
}

impl Drop for RwTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe { mdb_txn_abort(self.txn) }
        }
    }
}

fn mdb_val(bytes: &[u8]) -> MDB_val {
    MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr() as *mut _,
    }
}

fn slice_from_val<'a>(v: &MDB_val) -> &'a [u8] {
    if v.mv_size == 0 || v.mv_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }
    }
}

fn get_raw<'a>(txn: *mut MDB_txn, dbi: MDB_dbi, key: &[u8]) -> Result<Option<&'a [u8]>, DbError> {
    let mut k = mdb_val(key);
    let mut v = MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    };
    let rc = unsafe { mdb_get(txn, dbi, &mut k, &mut v) };
    if rc == MDB_NOTFOUND {
        return Ok(None);
    }
    check(rc)?;
    Ok(Some(slice_from_val(&v)))
}

fn put_raw(
    txn: *mut MDB_txn,
    dbi: MDB_dbi,
    key: &[u8],
    val: &[u8],
    flags: u32,
) -> Result<bool, DbError> {
    let mut k = mdb_val(key);
    let mut v = mdb_val(val);
    let rc = unsafe { mdb_put(txn, dbi, &mut k, &mut v, flags) };
    if rc == MDB_KEYEXIST {
        return Ok(false);
    }
    check(rc)?;
    Ok(true)
}

fn del_raw(
    txn: *mut MDB_txn,
    dbi: MDB_dbi,
    key: &[u8],
    val: Option<&[u8]>,
) -> Result<bool, DbError> {
    let mut k = mdb_val(key);
    let rc = if let Some(val) = val {
        let mut v = mdb_val(val);
        unsafe { mdb_del(txn, dbi, &mut k, &mut v) }
    } else {
        unsafe { mdb_del(txn, dbi, &mut k, ptr::null_mut()) }
    };
    if rc == MDB_NOTFOUND {
        return Ok(false);
    }
    check(rc)?;
    Ok(true)
}

fn largest_integer_key(txn: *mut MDB_txn, dbi: MDB_dbi) -> Result<u64, DbError> {
    let mut cursor = ptr::null_mut();
    unsafe { check(mdb_cursor_open(txn, dbi, &mut cursor))? };
    let mut k = MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    };
    let mut v = MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    };
    let rc = unsafe { mdb_cursor_get(cursor, &mut k, &mut v, MDB_LAST) };
    unsafe { mdb_cursor_close(cursor) };
    if rc == MDB_NOTFOUND {
        return Ok(0);
    }
    check(rc)?;
    if k.mv_size != 8 {
        return Err(DbError::msg("integer key size != 8"));
    }
    Ok(u64_from_ne(slice_from_val(&k)))
}

pub struct Cursor<'txn> {
    cursor: *mut MDB_cursor,
    _marker: PhantomData<&'txn ()>,
}

impl<'txn> Cursor<'txn> {
    fn open(txn: *mut MDB_txn, dbi: MDB_dbi) -> Result<Self, DbError> {
        let mut cursor = ptr::null_mut();
        unsafe { check(mdb_cursor_open(txn, dbi, &mut cursor))? };
        Ok(Self {
            cursor,
            _marker: PhantomData,
        })
    }

    pub fn get(
        &mut self,
        key: Option<&[u8]>,
        val: Option<&[u8]>,
        op: u32,
    ) -> Result<Option<Kv<'txn>>, DbError> {
        let mut k = match key {
            Some(b) => mdb_val(b),
            None => MDB_val {
                mv_size: 0,
                mv_data: ptr::null_mut(),
            },
        };
        let mut v = match val {
            Some(b) => mdb_val(b),
            None => MDB_val {
                mv_size: 0,
                mv_data: ptr::null_mut(),
            },
        };
        let rc = unsafe { mdb_cursor_get(self.cursor, &mut k, &mut v, op) };
        if rc == MDB_NOTFOUND {
            return Ok(None);
        }
        check(rc)?;
        Ok(Some((slice_from_val(&k), slice_from_val(&v))))
    }

    pub fn count(&mut self) -> Result<usize, DbError> {
        let mut n: usize = 0;
        check(unsafe { mdb_cursor_count(self.cursor, &mut n) })?;
        Ok(n)
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        unsafe { mdb_cursor_close(self.cursor) }
    }
}

fn dbi_flags(txn: *mut MDB_txn, dbi: MDB_dbi) -> Result<u32, DbError> {
    let mut flags = 0u32;
    check(unsafe { mdb_dbi_flags(txn, dbi, &mut flags) })?;
    Ok(flags)
}

/// Iterate a DBI from a starting key/dup, matching C++ `generic_foreachFull`.
///
/// `MDB_GET_BOTH_RANGE` / `MDB_FIRST_DUP` are only valid on `MDB_DUPSORT`
/// databases. Integer-key tables (Event, Meta, payloads, NegentropyFilter)
/// must use `MDB_SET_RANGE` or they return `MDB_INCOMPATIBLE`.
///
/// Returns `Ok(true)` if the scan finished, `Ok(false)` if the callback stopped it.
pub fn foreach_full<F>(
    txn: *mut MDB_txn,
    dbi: MDB_dbi,
    start_key: &[u8],
    start_dup: &[u8],
    reverse: bool,
    mut cb: F,
) -> Result<bool, DbError>
where
    F: FnMut(&[u8], &[u8]) -> bool,
{
    let dups = dbi_flags(txn, dbi)? & MDB_DUPSORT != 0;
    let mut cursor = Cursor::open(txn, dbi)?;
    let first = if reverse {
        if dups {
            position_reverse_dup(&mut cursor, start_key, start_dup)?
        } else {
            position_reverse_nodup(&mut cursor, start_key)?
        }
    } else if dups {
        position_forward_dup(&mut cursor, start_key, start_dup)?
    } else {
        position_forward_nodup(&mut cursor, start_key)?
    };
    let Some((mut k, mut v)) = first else {
        return Ok(true);
    };
    let traversal = if reverse { MDB_PREV } else { MDB_NEXT };
    loop {
        if !cb(k, v) {
            return Ok(false);
        }
        match cursor.get(None, None, traversal)? {
            None => break,
            Some((nk, nv)) => {
                k = nk;
                v = nv;
            }
        }
    }
    Ok(true)
}

fn position_forward_nodup<'txn>(
    cursor: &mut Cursor<'txn>,
    start_key: &[u8],
) -> Result<Option<Kv<'txn>>, DbError> {
    if start_key.is_empty() {
        return cursor.get(None, None, MDB_FIRST);
    }
    cursor.get(Some(start_key), None, MDB_SET_RANGE)
}

fn position_reverse_nodup<'txn>(
    cursor: &mut Cursor<'txn>,
    start_key: &[u8],
) -> Result<Option<Kv<'txn>>, DbError> {
    if start_key.is_empty() {
        return cursor.get(None, None, MDB_LAST);
    }
    if let Some((k, v)) = cursor.get(Some(start_key), None, MDB_SET_RANGE)? {
        if k == start_key {
            return Ok(Some((k, v)));
        }
        return cursor.get(None, None, MDB_PREV);
    }
    cursor.get(None, None, MDB_LAST)
}

fn position_forward_dup<'txn>(
    cursor: &mut Cursor<'txn>,
    start_key: &[u8],
    start_dup: &[u8],
) -> Result<Option<Kv<'txn>>, DbError> {
    if start_key.is_empty() {
        return cursor.get(None, None, MDB_FIRST);
    }
    if !start_dup.is_empty() {
        if let Some(kv) = cursor.get(Some(start_key), Some(start_dup), MDB_GET_BOTH_RANGE)? {
            return Ok(Some(kv));
        }
    }
    if cursor.get(Some(start_key), None, MDB_SET)?.is_some() {
        if let Some(dup) = cursor.get(None, None, MDB_FIRST_DUP)? {
            return Ok(Some(dup));
        }
        return cursor.get(Some(start_key), None, MDB_SET);
    }
    if let Some(kv) = cursor.get(Some(start_key), None, MDB_SET_RANGE)? {
        if let Some(dup) = cursor.get(None, None, MDB_FIRST_DUP)? {
            return Ok(Some(dup));
        }
        return Ok(Some(kv));
    }
    Ok(None)
}

fn position_reverse_dup<'txn>(
    cursor: &mut Cursor<'txn>,
    start_key: &[u8],
    start_dup: &[u8],
) -> Result<Option<Kv<'txn>>, DbError> {
    if start_key.is_empty() {
        return cursor.get(None, None, MDB_LAST);
    }
    if !start_dup.is_empty() {
        if let Some((k, v)) = cursor.get(Some(start_key), Some(start_dup), MDB_GET_BOTH_RANGE)? {
            if v != start_dup {
                return cursor.get(None, None, MDB_PREV);
            }
            return Ok(Some((k, v)));
        }
    }
    if cursor.get(Some(start_key), None, MDB_SET)?.is_some() {
        return cursor.get(None, None, MDB_LAST_DUP);
    }
    if cursor.get(Some(start_key), None, MDB_SET_RANGE)?.is_some() {
        return cursor.get(None, None, MDB_PREV);
    }
    cursor.get(None, None, MDB_LAST)
}
