//! NegentropyFilterCache matching `src/NegentropyFilterCache.h`.

use crate::error::NegError;
use crate::lmdb_store;
use wok_db::{lookup, RoTxn, RwTxn};
use wok_event::PackedEventView;
use wok_query::NostrFilter;

/// Parse a stored tree filter. Every tree writer, `verify_tree` and
/// `wok negentropy add` use this, so a filter the CLI accepts is one every
/// write can parse. Tree membership is matched once per stored event, so
/// the client-filter cost limits (`relay.max_tags_per_filter`,
/// `relay.max_and_entries`) do not apply: a reload that lowers them must not
/// make a stored tree unparseable and every write fail (#243).
pub fn parse_negentropy_filter(filter_str: &str) -> Result<NostrFilter, NegError> {
    let value = wok_event::json::parse_strict(filter_str)
        .map_err(|error| NegError::msg(error.to_string()))?;
    let filter = NostrFilter::parse(&value, u64::MAX, usize::MAX, usize::MAX)
        .map_err(|error| NegError::msg(error.to_string()))?;
    if filter.search.is_some() {
        return Err(NegError::msg(
            "negentropy filters do not support content search",
        ));
    }
    Ok(filter)
}

struct FilterInfo {
    filter: NostrFilter,
    tree_id: u64,
}

/// Stored tree filters, parsed without client-filter limits (C++ applies
/// `relay__maxTagsPerFilter` here; see [`parse_negentropy_filter`]).
#[derive(Default)]
pub struct NegentropyFilterCache {
    filters: Vec<FilterInfo>,
    modification_counter: Option<u64>,
}

impl NegentropyFilterCache {
    fn freshen(&mut self, txn: &RoTxn<'_>) -> Result<(), NegError> {
        let raw = txn
            .get_u64(txn.env().dbis().meta, 1)?
            .ok_or_else(|| NegError::msg("no Meta entry"))?;
        let meta = wok_db::decode_meta(raw)?;
        if Some(meta.negentropy_modification_counter) == self.modification_counter {
            return Ok(());
        }
        self.filters.clear();
        let mut parse_err: Option<NegError> = None;
        lookup::foreach_negentropy_filter(txn, |id, filter_str| {
            // C++ tao::json::from_string throws on a corrupt filter row;
            // propagate instead of silently substituting a match-all {}.
            match parse_negentropy_filter(filter_str) {
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
        self.modification_counter = Some(meta.negentropy_modification_counter);
        Ok(())
    }

    fn freshen_rw(&mut self, txn: &RwTxn<'_>) -> Result<(), NegError> {
        let raw = txn
            .get_u64(txn.env().dbis().meta, 1)?
            .ok_or_else(|| NegError::msg("no Meta entry"))?;
        let meta = wok_db::decode_meta(raw)?;
        if Some(meta.negentropy_modification_counter) == self.modification_counter {
            return Ok(());
        }
        self.filters.clear();
        let mut parse_err: Option<NegError> = None;
        lookup::foreach_negentropy_filter_rw(txn, |id, filter_str| {
            match parse_negentropy_filter(filter_str) {
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
        self.modification_counter = Some(meta.negentropy_modification_counter);
        Ok(())
    }
}

impl wok_db::NegentropySink for NegentropyFilterCache {
    fn update(
        &mut self,
        txn: &mut RwTxn<'_>,
        packed: PackedEventView<'_>,
        insert: bool,
    ) -> Result<(), wok_db::DbError> {
        self.apply(txn, packed, insert)
            .map_err(|error| wok_db::DbError::msg(error.to_string()))
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

/// One publication transaction's tree deltas. Only timestamp/id pairs are
/// retained; large event payloads and tag arrays are never copied.
pub struct BatchSink<'a> {
    cache: &'a mut NegentropyFilterCache,
    prepared: bool,
    ops: std::collections::BTreeMap<u64, Vec<(u64, [u8; 32], bool)>>,
}
impl NegentropyFilterCache {
    pub fn batch(&mut self) -> BatchSink<'_> {
        BatchSink {
            cache: self,
            prepared: false,
            ops: Default::default(),
        }
    }
}
impl wok_db::NegentropySink for BatchSink<'_> {
    fn update(
        &mut self,
        txn: &mut RwTxn<'_>,
        packed: PackedEventView<'_>,
        insert: bool,
    ) -> Result<(), wok_db::DbError> {
        if !self.prepared {
            self.cache
                .freshen_rw(txn)
                .map_err(|e| wok_db::DbError::msg(e.to_string()))?;
            self.prepared = true;
        }
        for f in &self.cache.filters {
            if f.filter.does_match(packed) {
                self.ops.entry(f.tree_id).or_default().push((
                    packed.created_at(),
                    packed.id().try_into().unwrap(),
                    insert,
                ));
            }
        }
        Ok(())
    }
}
impl BatchSink<'_> {
    pub fn flush(self, txn: &mut RwTxn<'_>) -> Result<(), NegError> {
        for (tree_id, ops) in self.ops {
            let mut tree = lmdb_store::open_rw(txn, tree_id)?;
            for (timestamp, id, insert) in ops {
                if insert {
                    tree.insert(timestamp, &id)?;
                } else {
                    tree.erase(timestamp, &id)?;
                }
            }
            tree.backend.flush()?;
        }
        Ok(())
    }
}

/// Optional compatibility sink for callers that need to defer tree updates
/// until after their event-write loop.
#[derive(Default)]
pub struct DeferredSink {
    ops: Vec<(Vec<u8>, bool)>,
}

impl wok_db::NegentropySink for DeferredSink {
    fn update(
        &mut self,
        _txn: &mut RwTxn<'_>,
        packed: PackedEventView<'_>,
        insert: bool,
    ) -> Result<(), wok_db::DbError> {
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
        let mut batch = cache.batch();
        for (buf, insert) in self.ops {
            let packed = PackedEventView::new(&buf).map_err(|e| NegError::msg(e.to_string()))?;
            wok_db::NegentropySink::update(&mut batch, txn, packed, insert)?;
        }
        batch.flush(txn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_search_filters_without_event_content() {
        let error = parse_negentropy_filter(r#"{"search":"nostr"}"#).unwrap_err();
        assert!(error
            .to_string()
            .contains("negentropy filters do not support content search"));
    }

    #[test]
    fn accepts_nip91_filters_with_overlap_normalization() {
        let filter =
            parse_negentropy_filter(r##"{"&t":["meme","cat"],"#t":["meme","cat","black"]}"##)
                .unwrap();
        assert_eq!(filter.and_tags[&'t'].size(), 2);
        assert_eq!(filter.tags[&'t'].size(), 1);
    }
}
