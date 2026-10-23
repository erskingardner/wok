#![forbid(unsafe_code)]

pub mod cost;
pub mod filter;
pub mod hll;
pub mod monitor;
pub mod pending;
pub mod scan;
pub mod scheduler;
pub mod subid;

pub use cost::CostedRequest;
pub use filter::{
    dumb_match, FilterValidator, NostrFilter, NostrFilterGroup, DEFAULT_MAX_AND_ENTRIES,
};
pub use hll::{offset_for_filter as nip45_hll_offset, HyperLogLog};
pub use monitor::{ActiveMonitors, Recipient};
pub use pending::{HeldEvent, PendingBuffer, PendingEvent};
pub use scan::{
    foreach_by_filter, foreach_visible_by_filter, Completeness, DbQuery, DbScan, ScanPlan,
};
pub use scheduler::{QueryFailure, QueryScheduler, Scheduled};
pub use subid::{FilterLimit, QueryError, SubId, Subscription};

pub mod visibility;
