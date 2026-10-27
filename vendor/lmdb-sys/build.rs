// Always builds the LMDB in this crate. Upstream lmdb-sys 0.8.0 linked a
// system liblmdb instead whenever pkg-config found one, of whatever version.

extern crate cc;

use std::env;
use std::path::PathBuf;

fn main() {
    let lmdb = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("lmdb")
        .join("libraries")
        .join("liblmdb");
    for file in ["mdb.c", "midl.c", "lmdb.h", "midl.h"] {
        println!("cargo:rerun-if-changed={}", lmdb.join(file).display());
    }
    cc::Build::new()
        .file(lmdb.join("mdb.c"))
        .file(lmdb.join("midl.c"))
        // https://github.com/LMDB/lmdb/blob/LMDB_0.9.37/libraries/liblmdb/Makefile#L25
        .opt_level(2)
        // LMDB's own code: a path dependency would print its warnings in
        // every build.
        .warnings(false)
        .compile("lmdb");
}
