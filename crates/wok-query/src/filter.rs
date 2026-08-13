//! Filter compilation and matching matching `src/filters.h`.

use crate::subid::QueryError;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use wok_event::{from_hex_exact, PackedEventView, MAX_INDEXED_TAG_VAL_SIZE};

#[derive(Debug, Clone)]
pub struct FilterSetBytes {
    items: Vec<Vec<u8>>,
}

impl FilterSetBytes {
    pub fn parse(
        arr: &Value,
        hex_decode: bool,
        min_size: usize,
        max_size: usize,
    ) -> Result<Self, QueryError> {
        if max_size > MAX_INDEXED_TAG_VAL_SIZE {
            return Err(QueryError::msg("maxSize bigger than max indexed tag size"));
        }
        let arr = arr
            .as_array()
            .ok_or_else(|| QueryError::msg("not an array"))?;
        let mut items = Vec::new();
        for i in arr {
            let s = i
                .as_str()
                .ok_or_else(|| QueryError::msg("filter item not a string"))?;
            let bytes = if hex_decode {
                // C++ FilterSetBytes uses from_hex(..., false).
                from_hex_exact(s).map_err(|e| QueryError::msg(e.to_string()))?
            } else {
                s.as_bytes().to_vec()
            };
            if bytes.len() < min_size {
                return Err(QueryError::msg("filter item too small"));
            }
            if bytes.len() > max_size {
                return Err(QueryError::msg("filter item too large"));
            }
            items.push(bytes);
        }
        items.sort();
        items.dedup();
        let total: usize = items.iter().map(|i| i.len()).sum();
        if total > 65535 {
            return Err(QueryError::msg("total filter items too large"));
        }
        Ok(Self { items })
    }

    pub fn at(&self, n: usize) -> &[u8] {
        &self.items[n]
    }

    pub fn size(&self) -> usize {
        self.items.len()
    }

    pub fn does_match(&self, candidate: &[u8]) -> bool {
        self.items
            .binary_search_by(|item| item.as_slice().cmp(candidate))
            .is_ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.items.iter().map(|v| v.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct FilterSetUint {
    items: Vec<u64>,
}

impl FilterSetUint {
    pub fn parse(arr: &Value) -> Result<Self, QueryError> {
        let arr = arr
            .as_array()
            .ok_or_else(|| QueryError::msg("not an array"))?;
        let mut items = Vec::new();
        for i in arr {
            let n = i
                .as_u64()
                .ok_or_else(|| QueryError::msg("kind not an unsigned integer"))?;
            items.push(n);
        }
        items.sort_unstable();
        items.dedup();
        Ok(Self { items })
    }

    pub fn at(&self, n: usize) -> u64 {
        self.items[n]
    }

    pub fn size(&self) -> usize {
        self.items.len()
    }

    pub fn does_match(&self, candidate: u64) -> bool {
        self.items.binary_search(&candidate).is_ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.items.iter().copied()
    }
}

#[derive(Debug, Clone)]
pub struct NostrFilter {
    pub ids: Option<FilterSetBytes>,
    pub authors: Option<FilterSetBytes>,
    pub kinds: Option<FilterSetUint>,
    pub tags: BTreeMap<char, FilterSetBytes>,
    pub since: u64,
    pub until: u64,
    pub limit: u64,
    pub never_match: bool,
    pub index_only_scans: bool,
}

impl NostrFilter {
    pub fn parse(
        filter_obj: &Value,
        max_filter_limit: u64,
        max_tags_per_filter: usize,
    ) -> Result<Self, QueryError> {
        if !filter_obj.is_object() {
            return Err(QueryError::msg("provided filter is not an object"));
        }
        let mut f = Self {
            ids: None,
            authors: None,
            kinds: None,
            tags: BTreeMap::new(),
            since: 0,
            until: u64::MAX,
            limit: u64::MAX,
            never_match: false,
            index_only_scans: false,
        };
        let mut num_major = 0u64;
        let obj = filter_obj.as_object().unwrap();
        for (k, v) in obj {
            if k == "ids" {
                if !v.is_array() {
                    return Err(QueryError::msg("ids not an array"));
                }
                if v.as_array().unwrap().is_empty() {
                    f.never_match = true;
                    continue;
                }
                num_major += 1;
                f.ids = Some(
                    FilterSetBytes::parse(v, true, 32, 32)
                        .map_err(|e| QueryError::msg(format!("error parsing ids: {e}")))?,
                );
            } else if k == "authors" {
                if !v.is_array() {
                    return Err(QueryError::msg("authors not an array"));
                }
                if v.as_array().unwrap().is_empty() {
                    f.never_match = true;
                    continue;
                }
                num_major += 1;
                f.authors = Some(
                    FilterSetBytes::parse(v, true, 32, 32)
                        .map_err(|e| QueryError::msg(format!("error parsing authors: {e}")))?,
                );
            } else if k == "kinds" {
                if !v.is_array() {
                    return Err(QueryError::msg("kinds not an array"));
                }
                if v.as_array().unwrap().is_empty() {
                    f.never_match = true;
                    continue;
                }
                num_major += 1;
                f.kinds = Some(
                    FilterSetUint::parse(v)
                        .map_err(|e| QueryError::msg(format!("error parsing kinds: {e}")))?,
                );
            } else if k.starts_with('#') {
                if !v.is_array() {
                    return Err(QueryError::msg(format!("{k} not an array")));
                }
                if v.as_array().unwrap().is_empty() {
                    f.never_match = true;
                    continue;
                }
                num_major += 1;
                if k.len() == 2 {
                    let tag = k.chars().nth(1).unwrap();
                    let set = if tag == 'p' || tag == 'e' {
                        FilterSetBytes::parse(v, true, 32, 32)
                    } else {
                        FilterSetBytes::parse(v, false, 0, MAX_INDEXED_TAG_VAL_SIZE)
                    }
                    .map_err(|e| QueryError::msg(format!("error parsing {k}: {e}")))?;
                    f.tags.insert(tag, set);
                } else {
                    return Err(QueryError::msg("unindexed tag filter"));
                }
            } else if k == "since" {
                f.since = v
                    .as_u64()
                    .ok_or_else(|| QueryError::msg("error parsing since"))?;
            } else if k == "until" {
                f.until = v
                    .as_u64()
                    .ok_or_else(|| QueryError::msg("error parsing until"))?;
            } else if k == "limit" {
                f.limit = v
                    .as_u64()
                    .ok_or_else(|| QueryError::msg("error parsing limit"))?;
            } else {
                return Err(QueryError::msg(format!("unrecognised filter item: {k}")));
            }
        }
        if f.tags.len() > max_tags_per_filter {
            return Err(QueryError::msg("too many tags in filter"));
        }
        if f.limit > max_filter_limit {
            f.limit = max_filter_limit;
        }
        f.index_only_scans =
            num_major <= 1 || (num_major == 2 && f.authors.is_some() && f.kinds.is_some());
        Ok(f)
    }

    pub fn does_match_times(&self, created: u64) -> bool {
        created >= self.since && created <= self.until
    }

    pub fn does_match(&self, ev: PackedEventView<'_>) -> bool {
        if self.never_match {
            return false;
        }
        if !self.does_match_times(ev.created_at()) {
            return false;
        }
        if let Some(ids) = &self.ids {
            if !ids.does_match(ev.id()) {
                return false;
            }
        }
        if let Some(authors) = &self.authors {
            if !authors.does_match(ev.pubkey()) {
                return false;
            }
        }
        if let Some(kinds) = &self.kinds {
            if !kinds.does_match(ev.kind()) {
                return false;
            }
        }
        for (tag, filt) in &self.tags {
            let mut found = false;
            ev.foreach_tag(|name, val| {
                if name == *tag && filt.does_match(val) {
                    found = true;
                    return false;
                }
                true
            });
            if !found {
                return false;
            }
        }
        true
    }

    pub fn is_full_db_query(&self) -> bool {
        self.ids.is_none() && self.authors.is_none() && self.kinds.is_none() && self.tags.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NostrFilterGroup {
    pub filters: Vec<NostrFilter>,
}

impl NostrFilterGroup {
    pub fn from_req(
        arr: &[Value],
        max_filter_limit: u64,
        max_tags: usize,
    ) -> Result<Self, QueryError> {
        if arr.len() < 3 {
            return Err(QueryError::msg("too small"));
        }
        let mut fg = Self::default();
        for item in arr.iter().skip(2) {
            fg.add_filter(item, max_filter_limit, max_tags)?;
        }
        Ok(fg)
    }

    pub fn from_value(
        filter: &Value,
        max_filter_limit: u64,
        max_tags: usize,
    ) -> Result<Self, QueryError> {
        let mut fg = Self::default();
        if filter.is_array() {
            for e in filter.as_array().unwrap() {
                fg.add_filter(e, max_filter_limit, max_tags)?;
            }
        } else {
            fg.add_filter(filter, max_filter_limit, max_tags)?;
        }
        Ok(fg)
    }

    pub fn add_filter(
        &mut self,
        item: &Value,
        max_filter_limit: u64,
        max_tags: usize,
    ) -> Result<(), QueryError> {
        let f = NostrFilter::parse(item, max_filter_limit, max_tags)?;
        if !f.never_match {
            self.filters.push(f);
        }
        Ok(())
    }

    pub fn does_match(&self, ev: PackedEventView<'_>) -> bool {
        self.filters.iter().any(|f| f.does_match(ev))
    }

    pub fn size(&self) -> usize {
        self.filters.len()
    }

    pub fn is_full_db_query(&self) -> bool {
        self.size() == 1 && self.filters[0].is_full_db_query()
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterValidator {
    pub enabled: bool,
    pub min_filters_per_req: u64,
    pub max_filters_per_req: u64,
    pub max_kinds_per_filter: u64,
    pub allowed_kinds: HashSet<u64>,
    pub require_author_or_tag: bool,
}

impl FilterValidator {
    pub fn validate(&self, fg: &NostrFilterGroup) -> Result<(), QueryError> {
        if !self.enabled {
            return Ok(());
        }
        let n = fg.filters.len() as u64;
        if n < self.min_filters_per_req || n > self.max_filters_per_req {
            return Err(QueryError::msg(format!("invalid number of filters: {n}")));
        }
        for filter in &fg.filters {
            if let Some(kinds) = &filter.kinds {
                if kinds.size() as u64 > self.max_kinds_per_filter {
                    return Err(QueryError::msg(format!(
                        "too many kinds in filter: {}",
                        kinds.size()
                    )));
                }
                if !self.allowed_kinds.is_empty() {
                    for k in kinds.iter() {
                        if !self.allowed_kinds.contains(&k) {
                            return Err(QueryError::msg(format!("kind not allowed: {k}")));
                        }
                    }
                }
            }
            if self.require_author_or_tag {
                let has_author = filter
                    .authors
                    .as_ref()
                    .map(|a| a.size() == 1)
                    .unwrap_or(false);
                let has_p = filter
                    .tags
                    .get(&'p')
                    .map(|t| t.size() == 1)
                    .unwrap_or(false);
                let has_e = filter
                    .tags
                    .get(&'e')
                    .map(|t| t.size() == 1)
                    .unwrap_or(false);
                if !has_author && !has_p && !has_e {
                    return Err(QueryError::msg(
                        "filter must have exactly one author, p tag, or e tag",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Simple reference matcher used by property tests.
pub fn dumb_match(filter: &NostrFilter, ev: PackedEventView<'_>) -> bool {
    filter.does_match(ev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    fn packed_note(
        id: u8,
        pk: u8,
        created: u64,
        kind: u64,
        tags: &[(&str, &[u8])],
    ) -> wok_event::PackedEvent {
        let mut b = PackedEventTagBuilder::default();
        for (n, v) in tags {
            b.add(n.chars().next().unwrap(), v).unwrap();
        }
        PackedEventBuilder::build(&[id; 32], &[pk; 32], created, kind, 0, &b).unwrap()
    }

    #[test]
    fn empty_ids_never_match_dropped() {
        let fg = NostrFilterGroup::from_value(&json!({"ids": []}), 500, 3).unwrap();
        assert_eq!(fg.size(), 0);
    }

    #[test]
    fn kind_and_time_match() {
        let f =
            NostrFilter::parse(&json!({"kinds":[1], "since": 10, "until": 20}), 500, 3).unwrap();
        let ev = packed_note(1, 2, 15, 1, &[]);
        assert!(f.does_match(ev.view()));
        let ev = packed_note(1, 2, 9, 1, &[]);
        assert!(!f.does_match(ev.view()));
        let ev = packed_note(1, 2, 15, 2, &[]);
        assert!(!f.does_match(ev.view()));
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(NostrFilter::parse(&json!({"foo": 1}), 500, 3).is_err());
    }

    #[test]
    fn ids_must_be_32_bytes() {
        assert!(NostrFilter::parse(&json!({"ids":["aa"]}), 500, 3).is_err());
    }

    #[test]
    fn index_only_heuristic() {
        let f = NostrFilter::parse(&json!({"kinds":[1]}), 500, 3).unwrap();
        assert!(f.index_only_scans);
        let f =
            NostrFilter::parse(&json!({"authors":["11".repeat(32)], "kinds":[1]}), 500, 3).unwrap();
        assert!(f.index_only_scans);
        let f = NostrFilter::parse(&json!({"ids":["11".repeat(32)], "kinds":[1]}), 500, 3).unwrap();
        assert!(!f.index_only_scans);
    }
}
