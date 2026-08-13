//! NegentropyFilterCache matching `src/NegentropyFilterCache.h`.

use crate::error::NegError;
use crate::lmdb_store;
use wok_db::{lookup, RoTxn, RwTxn};
use wok_event::PackedEventView;
use wok_query::NostrFilter;

struct FilterInfo {
    filter: NostrFilter,
    tree_id: u64,
}

pub struct NegentropyFilterCache {
    filters: Vec<FilterInfo>,
    modification_counter: u64,
    max_tags_per_filter: usize,
}

impl Default for NegentropyFilterCache {
    fn default() -> Self {
        // C++ uses cfg().relay__maxTagsPerFilter (default 3).
        Self::new(3)
    }
}

impl NegentropyFilterCache {
    pub fn new(max_tags_per_filter: usize) -> Self {
        Self {
            filters: Vec::new(),
            modification_counter: 0,
            max_tags_per_filter,
        }
    }

    fn freshen(&mut self, txn: &RoTxn<'_>) -> Result<(), NegError> {
        let raw = txn
            .get_u64(txn.env().dbis().meta, 1)?
            .ok_or_else(|| NegError::msg("no Meta entry"))?;
        let meta = wok_db::decode_meta(raw)?;
        if meta.negentropy_modification_counter == self.modification_counter {
            return Ok(());
        }
        self.filters.clear();
        let mut parse_err: Option<NegError> = None;
        let max_tags = self.max_tags_per_filter;
        lookup::foreach_negentropy_filter(txn, |id, filter_str| {
            // C++ tao::json::from_string throws on a corrupt filter row;
            // propagate instead of silently substituting a match-all {}.
            match wok_event::json::parse_strict(filter_str)
                .map_err(|e| NegError::msg(e.to_string()))
                .and_then(|v| {
                    NostrFilter::parse(&v, u64::MAX, max_tags)
                        .map_err(|e| NegError::msg(e.to_string()))
                }) {
                Ok(f) => self.filters.push(FilterInfo {
                    filter: f,
                    tree_id: id,
                }),
                Err(e) => {
                    parse_err = Some(e);
                    return false;
                }
            }
            true
        })?;
        if let Some(e) = parse_err {
            return Err(e);
        }
        self.modification_counter = meta.negentropy_modification_counter;
        Ok(())
    }

    fn freshen_rw(&mut self, txn: &RwTxn<'_>) -> Result<(), NegError> {
        let raw = txn
            .get_u64(txn.env().dbis().meta, 1)?
            .ok_or_else(|| NegError::msg("no Meta entry"))?;
        let meta = wok_db::decode_meta(raw)?;
        if meta.negentropy_modification_counter == self.modification_counter {
            return Ok(());
        }
        self.filters.clear();
        let mut parse_err: Option<NegError> = None;
        let max_tags = self.max_tags_per_filter;
        lookup::foreach_negentropy_filter_rw(txn, |id, filter_str| {
            match wok_event::json::parse_strict(filter_str)
                .map_err(|e| NegError::msg(e.to_string()))
                .and_then(|v| {
                    NostrFilter::parse(&v, u64::MAX, max_tags)
                        .map_err(|e| NegError::msg(e.to_string()))
                }) {
                Ok(f) => self.filters.push(FilterInfo {
                    filter: f,
                    tree_id: id,
                }),
                Err(e) => {
                    parse_err = Some(e);
                    return false;
                }
            }
            true
        })?;
        if let Some(e) = parse_err {
            return Err(e);
        }
        self.modification_counter = meta.negentropy_modification_counter;
        Ok(())
    }
}

impl NegentropyFilterCache {
    /// Apply insert/erase against matching trees inside an already-open write txn.
    pub fn apply(
        &mut self,
        txn: &mut RwTxn<'_>,
        packed: PackedEventView<'_>,
        insert: bool,
    ) -> Result<(), NegError> {
        self.freshen_rw(txn)?;
        let matches: Vec<u64> = self
            .filters
            .iter()
            .filter(|f| f.filter.does_match(packed))
            .map(|f| f.tree_id)
            .collect();
        for tree_id in matches {
            let mut tree = lmdb_store::open_rw(txn, tree_id)?;
            if insert {
                let _ = tree.insert(packed.created_at(), packed.id())?;
            } else {
                let _ = tree.erase(packed.created_at(), packed.id())?;
            }
            tree.backend.flush()?;
        }
        Ok(())
    }

    pub fn freshen_ro(&mut self, txn: &RoTxn<'_>) -> Result<(), NegError> {
        self.freshen(txn)
    }
}

/// Collect packed events then apply after write_events returns, because
/// `write_events` does not give us the txn inside NegentropySink.
#[derive(Default)]
pub struct DeferredSink {
    ops: Vec<(Vec<u8>, bool)>,
}

impl wok_db::NegentropySink for DeferredSink {
    fn update(&mut self, packed: PackedEventView<'_>, insert: bool) -> Result<(), wok_db::DbError> {
        self.ops.push((packed.as_bytes().to_vec(), insert));
        Ok(())
    }
}

impl DeferredSink {
    pub fn apply(
        self,
        cache: &mut NegentropyFilterCache,
        txn: &mut RwTxn<'_>,
    ) -> Result<(), NegError> {
        cache.freshen_rw(txn)?;
        for (buf, insert) in self.ops {
            let packed = PackedEventView::new(&buf).map_err(|e| NegError::msg(e.to_string()))?;
            cache.apply(txn, packed, insert)?;
        }
        Ok(())
    }
}
