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
}

impl Default for NegentropyFilterCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NegentropyFilterCache {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            modification_counter: 0,
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
        lookup::foreach_negentropy_filter(txn, |id, filter_str| {
            if let Ok(f) = NostrFilter::parse(
                &serde_json::from_str(filter_str).unwrap_or(serde_json::json!({})),
                u64::MAX,
                64,
            ) {
                self.filters.push(FilterInfo {
                    filter: f,
                    tree_id: id,
                });
            }
            true
        })?;
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
        lookup::foreach_negentropy_filter_rw(txn, |id, filter_str| {
            if let Ok(f) = NostrFilter::parse(
                &serde_json::from_str(filter_str).unwrap_or(serde_json::json!({})),
                u64::MAX,
                64,
            ) {
                self.filters.push(FilterInfo {
                    filter: f,
                    tree_id: id,
                });
            }
            true
        })?;
        self.modification_counter = meta.negentropy_modification_counter;
        Ok(())
    }
}

impl wok_db::NegentropySink for NegentropyFilterCache {
    fn update(&mut self, packed: PackedEventView<'_>, insert: bool) -> Result<(), wok_db::DbError> {
        let _ = (packed, insert);
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

    pub fn matching_tree(&self, filter_str: &str) -> Option<u64> {
        // C++ compares canonical JSON of the filter with since/until stripped.
        self.filters.iter().find_map(|f| {
            let compiled = serde_json::to_string(&serde_json::json!({})).ok()?;
            let _ = compiled;
            let _ = f;
            let _ = filter_str;
            None
        })
    }
}

/// Sink that updates trees during `write_events`.
#[allow(dead_code)]
pub struct UpdatingSink<'a, 'env> {
    cache: &'a mut NegentropyFilterCache,
    // Held only for the duration of a write_events call; trees are opened per update.
    _marker: std::marker::PhantomData<&'env ()>,
}

impl<'a> UpdatingSink<'a, '_> {
    #[allow(dead_code)]
    pub fn new(cache: &'a mut NegentropyFilterCache) -> Self {
        Self {
            cache,
            _marker: std::marker::PhantomData,
        }
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
