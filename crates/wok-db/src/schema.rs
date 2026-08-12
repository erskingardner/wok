//! Named DBIs and open flags matching generated `defaultDb.h`.

use lmdb_sys::*;

pub const DBI_META: &str = "rasgueadb_defaultDb__Meta";
pub const DBI_NEGENTROPY_FILTER: &str = "rasgueadb_defaultDb__NegentropyFilter";
pub const DBI_EVENT: &str = "rasgueadb_defaultDb__Event";
pub const DBI_EVENT_ID: &str = "rasgueadb_defaultDb__Event__id";
pub const DBI_EVENT_PUBKEY_KIND: &str = "rasgueadb_defaultDb__Event__pubkeyKind";
pub const DBI_EVENT_TAG: &str = "rasgueadb_defaultDb__Event__tag";
pub const DBI_EVENT_DELETION: &str = "rasgueadb_defaultDb__Event__deletion";
pub const DBI_EVENT_REPLACE: &str = "rasgueadb_defaultDb__Event__replace";
pub const DBI_EVENT_CREATED_AT: &str = "rasgueadb_defaultDb__Event__created_at";
pub const DBI_EVENT_PUBKEY: &str = "rasgueadb_defaultDb__Event__pubkey";
pub const DBI_EVENT_REPLACE_DELETION: &str = "rasgueadb_defaultDb__Event__replaceDeletion";
pub const DBI_EVENT_KIND: &str = "rasgueadb_defaultDb__Event__kind";
pub const DBI_EVENT_EXPIRATION: &str = "rasgueadb_defaultDb__Event__expiration";
pub const DBI_COMPRESSION_DICTIONARY: &str = "rasgueadb_defaultDb__CompressionDictionary";
pub const DBI_EVENT_PAYLOAD: &str = "rasgueadb_defaultDb__EventPayload";
pub const DBI_NEGENTROPY: &str = "negentropy";

pub const DBI_NAMES: &[&str] = &[
    DBI_META,
    DBI_NEGENTROPY_FILTER,
    DBI_EVENT,
    DBI_EVENT_ID,
    DBI_EVENT_PUBKEY_KIND,
    DBI_EVENT_TAG,
    DBI_EVENT_DELETION,
    DBI_EVENT_REPLACE,
    DBI_EVENT_CREATED_AT,
    DBI_EVENT_PUBKEY,
    DBI_EVENT_REPLACE_DELETION,
    DBI_EVENT_KIND,
    DBI_EVENT_EXPIRATION,
    DBI_COMPRESSION_DICTIONARY,
    DBI_EVENT_PAYLOAD,
    DBI_NEGENTROPY,
];

#[derive(Clone, Copy, Debug)]
pub struct DbiSpec {
    pub name: &'static str,
    pub flags: u32,
    pub comparator: ComparatorKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComparatorKind {
    Default,
    StringUint64,
    Uint64Uint64,
    StringUint64Uint64,
}

const DUP: u32 = MDB_CREATE | MDB_DUPSORT | MDB_INTEGERDUP | MDB_DUPFIXED;
const INT: u32 = MDB_CREATE | MDB_INTEGERKEY;
const DUP_INTKEY: u32 = DUP | MDB_INTEGERKEY;

pub fn dbi_specs() -> &'static [DbiSpec] {
    &[
        DbiSpec {
            name: DBI_META,
            flags: INT,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_NEGENTROPY_FILTER,
            flags: INT,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT,
            flags: INT,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT_ID,
            flags: DUP,
            comparator: ComparatorKind::StringUint64,
        },
        DbiSpec {
            name: DBI_EVENT_PUBKEY_KIND,
            flags: DUP,
            comparator: ComparatorKind::StringUint64Uint64,
        },
        DbiSpec {
            name: DBI_EVENT_TAG,
            flags: DUP,
            comparator: ComparatorKind::StringUint64,
        },
        DbiSpec {
            name: DBI_EVENT_DELETION,
            flags: DUP,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT_REPLACE,
            flags: DUP,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT_CREATED_AT,
            flags: DUP_INTKEY,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT_PUBKEY,
            flags: DUP,
            comparator: ComparatorKind::StringUint64,
        },
        DbiSpec {
            name: DBI_EVENT_REPLACE_DELETION,
            flags: DUP,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT_KIND,
            flags: DUP,
            comparator: ComparatorKind::Uint64Uint64,
        },
        DbiSpec {
            name: DBI_EVENT_EXPIRATION,
            flags: DUP_INTKEY,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_COMPRESSION_DICTIONARY,
            flags: INT,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_EVENT_PAYLOAD,
            flags: INT,
            comparator: ComparatorKind::Default,
        },
        DbiSpec {
            name: DBI_NEGENTROPY,
            flags: MDB_CREATE | MDB_REVERSEKEY,
            comparator: ComparatorKind::Default,
        },
    ]
}

#[derive(Clone, Copy, Debug)]
pub struct DbiName;
