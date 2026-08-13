//! Composite key encoding and C++-compatible LMDB comparators.
//!
//! `StringUint64`: memcmp on the string prefix (length-aware, like LMDB `mdb_cmp_memn`),
//! then native-endian u64 numeric compare on the last 8 bytes.
//!
//! `Uint64Uint64`: two native-endian u64s.
//!
//! `StringUint64Uint64`: memcmp on the string prefix, then two native-endian u64s.

use lmdb_sys::MDB_val;
use std::cmp::Ordering;
use std::os::raw::c_int;

pub fn u64_ne_bytes(n: u64) -> [u8; 8] {
    n.to_ne_bytes()
}

pub fn u64_from_ne(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_ne_bytes(buf)
}

pub fn make_key_string_u64(s: &[u8], n: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(s.len() + 8);
    k.extend_from_slice(s);
    k.extend_from_slice(&n.to_ne_bytes());
    k
}

pub fn parse_key_string_u64(k: &[u8]) -> Result<(&[u8], u64), super::DbError> {
    if k.len() < 8 {
        return Err(super::DbError::msg("StringUint64 key too short to parse"));
    }
    let (s, n) = k.split_at(k.len() - 8);
    Ok((s, u64_from_ne(n)))
}

pub fn make_key_u64_u64(n1: u64, n2: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(16);
    k.extend_from_slice(&n1.to_ne_bytes());
    k.extend_from_slice(&n2.to_ne_bytes());
    k
}

pub fn parse_key_u64_u64(k: &[u8]) -> Result<(u64, u64), super::DbError> {
    if k.len() != 16 {
        return Err(super::DbError::msg(
            "Uint64Uint64 key too short/long to parse",
        ));
    }
    Ok((u64_from_ne(&k[0..8]), u64_from_ne(&k[8..16])))
}

pub fn make_key_string_u64_u64(s: &[u8], n1: u64, n2: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(s.len() + 16);
    k.extend_from_slice(s);
    k.extend_from_slice(&n1.to_ne_bytes());
    k.extend_from_slice(&n2.to_ne_bytes());
    k
}

pub fn parse_key_string_u64_u64(k: &[u8]) -> Result<(&[u8], u64, u64), super::DbError> {
    if k.len() < 16 {
        return Err(super::DbError::msg(
            "StringUint64Uint64 key too short to parse",
        ));
    }
    let (s, rest) = k.split_at(k.len() - 16);
    Ok((s, u64_from_ne(&rest[0..8]), u64_from_ne(&rest[8..16])))
}

/// LMDB `mdb_cmp_memn`: memcmp common prefix, then shorter first.
pub fn cmp_memn(a: &[u8], b: &[u8]) -> Ordering {
    let len = a.len().min(b.len());
    match a[..len].cmp(&b[..len]) {
        Ordering::Equal => a.len().cmp(&b.len()),
        o => o,
    }
}

pub fn cmp_string_u64(a: &[u8], b: &[u8]) -> Ordering {
    match (a.len() >= 8, b.len() >= 8) {
        (false, false) => return cmp_memn(a, b),
        (false, true) => return Ordering::Less,
        (true, false) => return Ordering::Greater,
        (true, true) => {}
    }
    let a_s = &a[..a.len() - 8];
    let b_s = &b[..b.len() - 8];
    match cmp_memn(a_s, b_s) {
        Ordering::Equal => u64_from_ne(&a[a.len() - 8..]).cmp(&u64_from_ne(&b[b.len() - 8..])),
        o => o,
    }
}

pub fn cmp_u64_u64(a: &[u8], b: &[u8]) -> Ordering {
    match (a.len() == 16, b.len() == 16) {
        (false, false) => return cmp_memn(a, b),
        (false, true) => return Ordering::Less,
        (true, false) => return Ordering::Greater,
        (true, true) => {}
    }
    match u64_from_ne(&a[0..8]).cmp(&u64_from_ne(&b[0..8])) {
        Ordering::Equal => u64_from_ne(&a[8..16]).cmp(&u64_from_ne(&b[8..16])),
        o => o,
    }
}

pub fn cmp_string_u64_u64(a: &[u8], b: &[u8]) -> Ordering {
    match (a.len() >= 16, b.len() >= 16) {
        (false, false) => return cmp_memn(a, b),
        (false, true) => return Ordering::Less,
        (true, false) => return Ordering::Greater,
        (true, true) => {}
    }
    let a_s = &a[..a.len() - 16];
    let b_s = &b[..b.len() - 16];
    match cmp_memn(a_s, b_s) {
        Ordering::Equal => match u64_from_ne(&a[a.len() - 16..a.len() - 8])
            .cmp(&u64_from_ne(&b[b.len() - 16..b.len() - 8]))
        {
            Ordering::Equal => u64_from_ne(&a[a.len() - 8..]).cmp(&u64_from_ne(&b[b.len() - 8..])),
            o => o,
        },
        o => o,
    }
}

fn val_slice<'a>(v: *const MDB_val) -> &'a [u8] {
    unsafe {
        let v = &*v;
        if v.mv_size == 0 || v.mv_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size)
        }
    }
}

fn ord_to_c(o: Ordering) -> c_int {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// # Safety
/// `a` and `b` must be valid pointers to `MDB_val` values provided by LMDB
/// for the duration of this call.
pub unsafe extern "C" fn lmdb_comparator_string_u64(a: *const MDB_val, b: *const MDB_val) -> c_int {
    ord_to_c(cmp_string_u64(val_slice(a), val_slice(b)))
}

/// # Safety
/// `a` and `b` must be valid pointers to `MDB_val` values provided by LMDB
/// for the duration of this call.
pub unsafe extern "C" fn lmdb_comparator_u64_u64(a: *const MDB_val, b: *const MDB_val) -> c_int {
    ord_to_c(cmp_u64_u64(val_slice(a), val_slice(b)))
}

/// # Safety
/// `a` and `b` must be valid pointers to `MDB_val` values provided by LMDB
/// for the duration of this call.
pub unsafe extern "C" fn lmdb_comparator_string_u64_u64(
    a: *const MDB_val,
    b: *const MDB_val,
) -> c_int {
    ord_to_c(cmp_string_u64_u64(val_slice(a), val_slice(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_u64_orders_by_string_then_time() {
        let a = make_key_string_u64(b"abc", 10);
        let b = make_key_string_u64(b"abc", 20);
        let c = make_key_string_u64(b"abd", 1);
        assert_eq!(cmp_string_u64(&a, &b), Ordering::Less);
        assert_eq!(cmp_string_u64(&c, &a), Ordering::Greater);
        // shorter string is less when prefix-equal (memcmp_memn)
        let d = make_key_string_u64(b"ab", 99);
        assert_eq!(cmp_string_u64(&d, &a), Ordering::Less);
    }

    #[test]
    fn u64_u64_numeric() {
        let a = make_key_u64_u64(1, 100);
        let b = make_key_u64_u64(1, 200);
        let c = make_key_u64_u64(2, 0);
        assert_eq!(cmp_u64_u64(&a, &b), Ordering::Less);
        assert_eq!(cmp_u64_u64(&c, &a), Ordering::Greater);
    }

    #[test]
    fn malformed_keys_sort_before_valid_keys_without_panicking() {
        let short = [1, 2, 3];
        let valid_string = make_key_string_u64(b"x", 1);
        let valid_pair = make_key_u64_u64(1, 2);
        let valid_triple = make_key_string_u64_u64(b"x", 1, 2);

        assert_eq!(cmp_string_u64(&short, &valid_string), Ordering::Less);
        assert_eq!(cmp_u64_u64(&short, &valid_pair), Ordering::Less);
        assert_eq!(cmp_string_u64_u64(&short, &valid_triple), Ordering::Less);
        assert_eq!(cmp_string_u64(&short, &short), Ordering::Equal);
        assert_eq!(cmp_u64_u64(&short, &short), Ordering::Equal);
        assert_eq!(cmp_string_u64_u64(&short, &short), Ordering::Equal);
    }
}
