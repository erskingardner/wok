# lmdb-sys with LMDB 0.9.37

Wok's copy of [lmdb-sys 0.8.0](https://github.com/danburkert/lmdb-rs)
(Apache-2.0), patched in for the crates.io one by the root and `fuzz`
`Cargo.toml`. It differs from upstream in three ways:

- `lmdb/libraries/liblmdb` holds LMDB 0.9.37 (OpenLDAP Public License 2.8; see
  `LICENSE` and `COPYRIGHT` there) instead of 0.9.21. Only the files the build
  needs, plus `CHANGES`, are kept.
- `build.rs` always compiles that copy. Upstream linked a system `liblmdb`
  whenever pkg-config found one, whatever its version; LMDB 1.0 cannot read a
  0.9 database.
- `src/lib.rs` no longer denies warnings.

`src/ffi.rs` and `src/constants.rs` are upstream's, unchanged: LMDB's API is
the same across 0.9.x. 0.9.37 keeps the data and lock formats of 0.9.21
(`MDB_DATA_VERSION` and `MDB_LOCK_VERSION` 1), so it opens databases older
Wok and strfry wrote, and can share one with them.

To update, take the files from the `LMDB_0.9.x` tag of
<https://git.openldap.org/openldap/openldap> (`libraries/liblmdb`), check that
both format versions are unchanged and the API in `lmdb.h` is the same, and
update the version here, in `build.rs` and in `wok-db`'s version test.
