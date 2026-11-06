//! Opt-in measurements for a synchronous read on one OS thread.
//!
//! Use a fresh read transaction inside [`measure`] to count its cache population;
//! an already populated transaction will report its existing cache hits instead.
//! The scope counts every instrumented Wok operation on the calling thread, so
//! keep writes, environment opening and unrelated reads outside it. It never
//! follows work onto another thread and must not span an async suspension.
//!
//! Wrapper invocations, explicitly owned byte copies and native PerfContext
//! metrics are separate. A returned primary pin may use native owned storage;
//! its returned byte count is not proof of a zero-copy native operation. Native
//! block reads can hit the OS cache and do not establish physical disk I/O.
//! This API exclusively resets/enables count-level RocksDB PerfContext for its
//! thread and disables it on return or unwind. The binding exposes no previous
//! perf-level getter, so an unknown previous native perf level is not restored.
//! Ordinary builds omit this module and every recording hook.

use rocksdb::perf::{set_perf_stats, PerfContext, PerfMetric, PerfStatsLevel};
use serde::Serialize;
use std::cell::RefCell;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

/// Exact Wok wrapper calls and selected byte materializations in this scope.
///
/// Byte fields measure the named copies/materializations, not total allocator
/// traffic, live memory, decompressed bytes or native RocksDB allocations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WrapperCounters {
    /// Nonempty author-head native batched MultiGet invocations, not internal seeks.
    pub author_head_multiget_calls: u64,
    /// Requested head keys, including repeated keys, before native execution.
    pub author_head_keys: u64,
    pub iterator_creations: u64,
    pub seek: u64,
    pub seek_for_prev: u64,
    pub seek_to_first: u64,
    pub seek_to_last: u64,
    pub next: u64,
    pub prev: u64,
    pub typed_index_entries: u64,
    pub fallback_index_entries: u64,
    pub logical_decode_calls: u64,
    pub ordered_key_encodes: u64,
    pub ordered_key_bytes: u64,
    pub resume_key_copies: u64,
    pub resume_key_bytes: u64,
    /// Physical iterator rows copied into owned key/value vectors by the
    /// generic cursor. Temporary decoder and cursor-position clones are not
    /// included; these fields do not count all generic-path allocations.
    pub generic_row_materializations: u64,
    pub generic_key_copy_bytes: u64,
    pub generic_value_copy_bytes: u64,
    pub arena_copy_bytes: u64,
    pub primary_pin_lookups: u64,
    pub primary_pins_found: u64,
    pub primary_pins_missing: u64,
    pub primary_pin_returned_bytes: u64,
    pub primary_cached_pinned_hits: u64,
    pub primary_cached_owned_hits: u64,
    pub cover_records_copied: u64,
    pub cover_record_bytes_copied: u64,
    pub cover_cached_pinned_hits: u64,
    pub cover_cached_owned_hits: u64,
}

/// RocksDB's thread-local internal counters at `EnableCount` level.
/// Internal seeks can fan out across memtables/SST children; they are not
/// interchangeable with [`WrapperCounters::seek`] or other wrapper calls.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NativeCounters {
    pub user_key_comparison_count: u64,
    pub seek_on_memtable_count: u64,
    pub seek_child_seek_count: u64,
    pub next_on_memtable_count: u64,
    pub prev_on_memtable_count: u64,
    pub block_cache_hit_count: u64,
    pub block_read_count: u64,
    pub block_read_bytes: u64,
    pub get_read_bytes: u64,
    pub iter_read_bytes: u64,
    pub internal_key_skipped_count: u64,
    pub internal_delete_skipped_count: u64,
    pub get_from_memtable_count: u64,
}

impl NativeCounters {
    fn read(perf: &PerfContext) -> Self {
        Self {
            user_key_comparison_count: perf.metric(PerfMetric::UserKeyComparisonCount),
            seek_on_memtable_count: perf.metric(PerfMetric::SeekOnMemtableCount),
            seek_child_seek_count: perf.metric(PerfMetric::SeekChildSeekCount),
            next_on_memtable_count: perf.metric(PerfMetric::NextOnMemtableCount),
            prev_on_memtable_count: perf.metric(PerfMetric::PrevOnMemtableCount),
            block_cache_hit_count: perf.metric(PerfMetric::BlockCacheHitCount),
            block_read_count: perf.metric(PerfMetric::BlockReadCount),
            block_read_bytes: perf.metric(PerfMetric::BlockReadByte),
            get_read_bytes: perf.metric(PerfMetric::GetReadBytes),
            iter_read_bytes: perf.metric(PerfMetric::IterReadBytes),
            internal_key_skipped_count: perf.metric(PerfMetric::InternalKeySkippedCount),
            internal_delete_skipped_count: perf.metric(PerfMetric::InternalDeleteSkippedCount),
            get_from_memtable_count: perf.metric(PerfMetric::GetFromMemtableCount),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReadMeasurements {
    pub wrapper: WrapperCounters,
    pub native: NativeCounters,
}

/// Nested measurement would reset the enclosing native context, so reject it
/// before changing either the wrapper counters or RocksDB's perf settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeAlreadyActive;

impl fmt::Display for ScopeAlreadyActive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a read diagnostic scope is already active on this thread")
    }
}
impl std::error::Error for ScopeAlreadyActive {}

thread_local! {
    static COUNTERS: RefCell<Option<WrapperCounters>> = const { RefCell::new(None) };
}

pub(crate) fn record(update: impl FnOnce(&mut WrapperCounters)) {
    COUNTERS.with_borrow_mut(|slot| {
        if let Some(counters) = slot {
            update(counters);
        }
    });
}

struct ScopeGuard(PhantomData<Rc<()>>);
impl Drop for ScopeGuard {
    fn drop(&mut self) {
        set_perf_stats(PerfStatsLevel::Disable);
        COUNTERS.with_borrow_mut(|slot| *slot = None);
    }
}

/// Measure exactly one synchronous closure on the calling thread.
///
/// A closure returning `Result::Err` still returns its measurements. A panic
/// propagates after clearing the scope and disabling native perf counters.
/// The measurement layer does not retain callbacks or transactions; a returned
/// value's ownership and transaction lifetime remain controlled by the caller.
pub fn measure<T>(read: impl FnOnce() -> T) -> Result<(T, ReadMeasurements), ScopeAlreadyActive> {
    COUNTERS.with_borrow_mut(|slot| {
        if slot.is_some() {
            return Err(ScopeAlreadyActive);
        }
        *slot = Some(WrapperCounters::default());
        Ok(())
    })?;
    let _guard = ScopeGuard(PhantomData);
    set_perf_stats(PerfStatsLevel::EnableCount);
    let mut perf = PerfContext::default();
    perf.reset();
    let result = read();
    let wrapper = COUNTERS.with_borrow(|slot| slot.expect("active read diagnostic scope"));
    let native = NativeCounters::read(&perf);
    Ok((result, ReadMeasurements { wrapper, native }))
}

#[cfg(test)]
#[path = "read_diagnostics_tests.rs"]
mod tests;
