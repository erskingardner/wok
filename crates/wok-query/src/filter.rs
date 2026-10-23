//! Filter compilation and matching matching `src/filters.h`.

use crate::subid::{FilterLimit, QueryError};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use wok_db::{parse_search_query, search_term_set, SearchQuery, SearchTermSet};
use wok_event::{
    from_lower_hex_exact, indexed_tag_value, PackedEventView, MAX_INDEXED_TAG_VAL_SIZE,
};

pub const DEFAULT_MAX_AND_ENTRIES: usize = 16;

#[derive(Debug, Clone)]
pub struct FilterSetBytes {
    /// Sorted values in the form PackedEvent and the indexes hold them: tag
    /// values longer than `MAX_INDEXED_TAG_VAL_SIZE` are hashed.
    items: Vec<Vec<u8>>,
    /// The original value of each hashed item.
    originals: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl FilterSetBytes {
    pub fn parse(
        arr: &Value,
        hex_decode: bool,
        min_size: usize,
        max_size: usize,
    ) -> Result<Self, QueryError> {
        let arr = arr
            .as_array()
            .ok_or_else(|| QueryError::msg("not an array"))?;
        let mut items = Vec::new();
        let mut originals = BTreeMap::new();
        for i in arr {
            let s = i
                .as_str()
                .ok_or_else(|| QueryError::msg("filter item not a string"))?;
            let bytes = if hex_decode {
                from_lower_hex_exact(s).map_err(|e| QueryError::msg(e.to_string()))?
            } else {
                s.as_bytes().to_vec()
            };
            if bytes.len() < min_size {
                return Err(QueryError::msg("filter item too small"));
            }
            if bytes.len() > max_size {
                return Err(QueryError::msg("filter item too large"));
            }
            if bytes.len() > MAX_INDEXED_TAG_VAL_SIZE {
                let hashed = indexed_tag_value(&bytes).into_owned();
                originals.insert(hashed.clone(), bytes);
                items.push(hashed);
            } else {
                items.push(bytes);
            }
        }
        items.sort();
        items.dedup();
        let total: usize = items
            .iter()
            .map(|item| originals.get(item).unwrap_or(item).len())
            .sum();
        if total > 65535 {
            return Err(QueryError::msg("total filter items too large"));
        }
        Ok(Self { items, originals })
    }

    /// Tag values of any length. A value can match only an event that packed
    /// the same value, so the 65535-byte total is the only bound.
    pub fn parse_tag_values(arr: &Value) -> Result<Self, QueryError> {
        Self::parse(arr, false, 0, usize::MAX)
    }

    /// The `n`th value as PackedEvent holds it.
    pub fn at(&self, n: usize) -> &[u8] {
        &self.items[n]
    }

    /// The `n`th value as the filter gave it.
    pub fn original(&self, n: usize) -> &[u8] {
        let item = &self.items[n];
        self.originals.get(item).unwrap_or(item)
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

    fn remove_all(&mut self, excluded: &Self) {
        self.items.retain(|item| !excluded.does_match(item));
        self.originals.retain(|item, _| !excluded.does_match(item));
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
            if n > u16::MAX as u64 {
                return Err(QueryError::msg("kind must be between 0 and 65535"));
            }
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
    pub and_tags: BTreeMap<char, FilterSetBytes>,
    pub search: Option<SearchQuery>,
    pub since: u64,
    pub until: u64,
    pub limit: u64,
    /// An `ids`, `authors`, `kinds` or `#x` list was empty, so no event can
    /// match (NIP-01). [`NostrFilterGroup`] drops such filters.
    pub never_match: bool,
    pub index_only_scans: bool,
}

impl NostrFilter {
    pub fn parse(
        filter_obj: &Value,
        max_filter_limit: u64,
        max_tags_per_filter: usize,
        max_and_entries: usize,
    ) -> Result<Self, QueryError> {
        if !filter_obj.is_object() {
            return Err(QueryError::msg("provided filter is not an object"));
        }
        let mut f = Self {
            ids: None,
            authors: None,
            kinds: None,
            tags: BTreeMap::new(),
            and_tags: BTreeMap::new(),
            search: None,
            since: 0,
            until: u64::MAX,
            limit: u64::MAX,
            never_match: false,
            index_only_scans: false,
        };
        let mut num_major_non_tag = 0u64;
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
                num_major_non_tag += 1;
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
                num_major_non_tag += 1;
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
                num_major_non_tag += 1;
                f.kinds = Some(
                    FilterSetUint::parse(v)
                        .map_err(|e| QueryError::msg(format!("error parsing kinds: {e}")))?,
                );
            } else if k.starts_with('#') {
                // A key NIP-01 does not define is unsupported, whatever its value.
                if k.len() != 2 || !k.as_bytes()[1].is_ascii_alphabetic() {
                    return Err(QueryError::unsupported("unindexed tag filter"));
                }
                if !v.is_array() {
                    return Err(QueryError::msg(format!("{k} not an array")));
                }
                if v.as_array().unwrap().is_empty() {
                    f.never_match = true;
                    continue;
                }
                let tag = k.as_bytes()[1] as char;
                let set = if tag == 'p' || tag == 'e' {
                    FilterSetBytes::parse(v, true, 32, 32)
                } else {
                    FilterSetBytes::parse_tag_values(v)
                }
                .map_err(|e| QueryError::msg(format!("error parsing {k}: {e}")))?;
                f.tags.insert(tag, set);
            } else if k.starts_with('&') {
                if k.len() != 2 || !k.as_bytes()[1].is_ascii_alphabetic() {
                    return Err(QueryError::unsupported("unindexed AND tag filter"));
                }
                if !v.is_array() {
                    return Err(QueryError::msg(format!("{k} not an array")));
                }
                if v.as_array().unwrap().is_empty() {
                    return Err(QueryError::msg(format!("{k} array must not be empty")));
                }
                let tag = k.as_bytes()[1] as char;
                let set = if tag == 'p' || tag == 'e' {
                    FilterSetBytes::parse(v, true, 32, 32)
                } else {
                    FilterSetBytes::parse_tag_values(v)
                }
                .map_err(|e| QueryError::msg(format!("error parsing {k}: {e}")))?;
                f.and_tags.insert(tag, set);
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
            } else if k == "search" {
                let query = v
                    .as_str()
                    .ok_or_else(|| QueryError::msg("search not a string"))?;
                f.search =
                    Some(parse_search_query(query).map_err(|error| {
                        QueryError::msg(format!("error parsing search: {error}"))
                    })?);
                num_major_non_tag += 1;
            } else {
                return Err(QueryError::unsupported(format!(
                    "unrecognised filter item: {k}"
                )));
            }
        }
        for (tag, required) in &f.and_tags {
            if let Some(alternatives) = f.tags.get_mut(tag) {
                alternatives.remove_all(required);
            }
        }
        f.tags.retain(|_, alternatives| alternatives.size() > 0);

        let tag_key_count = f
            .tags
            .keys()
            .chain(f.and_tags.keys())
            .copied()
            .collect::<HashSet<_>>()
            .len();
        if tag_key_count > max_tags_per_filter {
            return Err(QueryError::limit(
                FilterLimit::TagsPerFilter,
                "too many tags in filter",
            ));
        }
        let and_entry_count: usize = f.and_tags.values().map(FilterSetBytes::size).sum();
        if and_entry_count > max_and_entries {
            return Err(QueryError::limit(
                FilterLimit::AndEntries,
                "too many AND entries in filter",
            ));
        }
        if f.limit > max_filter_limit {
            f.limit = max_filter_limit;
        }
        let num_major = num_major_non_tag + tag_key_count as u64;
        f.index_only_scans = f.and_tags.is_empty()
            && (num_major <= 1 || (num_major == 2 && f.authors.is_some() && f.kinds.is_some()));
        Ok(f)
    }

    pub fn does_match_times(&self, created: u64) -> bool {
        created >= self.since && created <= self.until
    }

    pub fn does_match(&self, ev: PackedEventView<'_>) -> bool {
        if self.search.is_some() {
            return false;
        }
        self.does_match_without_search(ev)
    }

    pub fn does_match_without_search(&self, ev: PackedEventView<'_>) -> bool {
        if self.never_match || !self.does_match_times(ev.created_at()) {
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
        for (tag, required) in &self.and_tags {
            for value in required.iter() {
                let mut found = false;
                ev.foreach_tag(|name, candidate| {
                    if name == *tag && candidate == value {
                        found = true;
                        return false;
                    }
                    true
                });
                if !found {
                    return false;
                }
            }
        }
        true
    }

    pub fn does_match_with_content(&self, ev: PackedEventView<'_>, content: &str) -> bool {
        let terms = search_term_set(content);
        self.does_match_with_search_terms(ev, Some(&terms))
    }

    pub fn does_match_with_search_terms(
        &self,
        ev: PackedEventView<'_>,
        search_terms: Option<&SearchTermSet>,
    ) -> bool {
        if !self.does_match_without_search(ev) {
            return false;
        }
        let Some(query) = &self.search else {
            return true;
        };
        let Some(search_terms) = search_terms else {
            return false;
        };
        query.terms.iter().all(|term| search_terms.contains(term))
    }

    pub fn is_full_db_query(&self) -> bool {
        !self.never_match
            && self.ids.is_none()
            && self.authors.is_none()
            && self.kinds.is_none()
            && self.tags.is_empty()
            && self.and_tags.is_empty()
            && self.search.is_none()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NostrFilterGroup {
    pub filters: Vec<NostrFilter>,
    /// Filters dropped because they can never match (an empty list). They
    /// need no scan and no live monitor entry, but count toward limits on
    /// the number of filters a request sends.
    pub never_matching: usize,
}

impl NostrFilterGroup {
    pub fn from_req(
        arr: &[Value],
        max_filter_limit: u64,
        max_tags: usize,
        max_and_entries: usize,
    ) -> Result<Self, QueryError> {
        if arr.len() < 3 {
            return Err(QueryError::msg("too small"));
        }
        let mut fg = Self::default();
        for item in arr.iter().skip(2) {
            fg.add_filter(item, max_filter_limit, max_tags, max_and_entries)?;
        }
        Ok(fg)
    }

    pub fn from_value(
        filter: &Value,
        max_filter_limit: u64,
        max_tags: usize,
        max_and_entries: usize,
    ) -> Result<Self, QueryError> {
        let mut fg = Self::default();
        if filter.is_array() {
            for e in filter.as_array().unwrap() {
                fg.add_filter(e, max_filter_limit, max_tags, max_and_entries)?;
            }
        } else {
            fg.add_filter(filter, max_filter_limit, max_tags, max_and_entries)?;
        }
        Ok(fg)
    }

    pub fn add_filter(
        &mut self,
        item: &Value,
        max_filter_limit: u64,
        max_tags: usize,
        max_and_entries: usize,
    ) -> Result<(), QueryError> {
        let f = NostrFilter::parse(item, max_filter_limit, max_tags, max_and_entries)?;
        if f.never_match {
            self.never_matching += 1;
        } else {
            self.filters.push(f);
        }
        Ok(())
    }

    pub fn does_match(&self, ev: PackedEventView<'_>) -> bool {
        self.filters.iter().any(|f| f.does_match(ev))
    }

    pub fn does_match_with_content(&self, ev: PackedEventView<'_>, content: &str) -> bool {
        let terms = search_term_set(content);
        self.does_match_with_search_terms(ev, Some(&terms))
    }

    pub fn does_match_with_search_terms(
        &self,
        ev: PackedEventView<'_>,
        search_terms: Option<&SearchTermSet>,
    ) -> bool {
        self.filters
            .iter()
            .any(|filter| filter.does_match_with_search_terms(ev, search_terms))
    }

    pub fn requires_content(&self) -> bool {
        self.filters.iter().any(|filter| filter.search.is_some())
    }

    pub fn size(&self) -> usize {
        self.filters.len()
    }

    pub fn is_full_db_query(&self) -> bool {
        self.size() == 1 && self.filters[0].is_full_db_query()
    }
}

/// Optional rules for a REQ's filters. Each is off at its zero or empty
/// value, so the default validator accepts every filter.
#[derive(Debug, Clone, Default)]
pub struct FilterValidator {
    pub max_kinds_per_filter: u64,
    pub allowed_kinds: HashSet<u64>,
    pub require_author_or_tag: bool,
    /// Every filter must name what it wants: `ids`, `authors` or a tag
    /// filter, with any number of values. This refuses enumeration such as
    /// `{"kinds":[445]}` and keeps group, inbox, `ids` and directory
    /// filters (#97 F13).
    pub require_scoped_filters: bool,
}

impl FilterValidator {
    pub fn validate(&self, fg: &NostrFilterGroup) -> Result<(), QueryError> {
        for filter in &fg.filters {
            if let Some(kinds) = &filter.kinds {
                if self.max_kinds_per_filter != 0 && kinds.size() as u64 > self.max_kinds_per_filter
                {
                    return Err(QueryError::limit(
                        FilterLimit::KindsPerFilter,
                        format!("too many kinds in filter: {}", kinds.size()),
                    ));
                }
                if !self.allowed_kinds.is_empty() {
                    for k in kinds.iter() {
                        if !self.allowed_kinds.contains(&k) {
                            return Err(QueryError::limit(
                                FilterLimit::AllowedKinds,
                                format!("kind not allowed: {k}"),
                            ));
                        }
                    }
                }
            }
            if self.require_scoped_filters
                && filter.ids.is_none()
                && filter.authors.is_none()
                && filter.tags.is_empty()
                && filter.and_tags.is_empty()
            {
                return Err(QueryError::limit(
                    FilterLimit::ScopedFilters,
                    "filter must name ids, authors or a tag",
                ));
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
                let has_and_p = filter
                    .and_tags
                    .get(&'p')
                    .map(|t| t.size() == 1)
                    .unwrap_or(false);
                let has_e = filter
                    .tags
                    .get(&'e')
                    .map(|t| t.size() == 1)
                    .unwrap_or(false);
                let has_and_e = filter
                    .and_tags
                    .get(&'e')
                    .map(|t| t.size() == 1)
                    .unwrap_or(false);
                if !has_author && !has_p && !has_e && !has_and_p && !has_and_e {
                    return Err(QueryError::limit(
                        FilterLimit::AuthorOrTag,
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
    fn empty_filter_lists_match_nothing() {
        // NIP-01: an empty list matches no event and is not an absent field.
        let ev = packed_note(1, 2, 15, 1, &[("p", &[3; 32])]);
        for empty in [
            json!({"ids": []}),
            json!({"authors": []}),
            json!({"kinds": []}),
            json!({"#p": []}),
            json!({"#t": [], "kinds": [1]}),
        ] {
            let f = NostrFilter::parse(&empty, 500, 3, 16).unwrap();
            assert!(f.never_match, "{empty}");
            assert!(!f.does_match(ev.view()), "{empty}");
            assert!(!f.is_full_db_query(), "{empty}");
            let fg = NostrFilterGroup::from_value(&empty, 500, 3, 16).unwrap();
            assert_eq!((fg.size(), fg.never_matching), (0, 1), "{empty}");
            assert!(!fg.does_match(ev.view()), "{empty}");
        }

        // The other filters of the request still apply.
        let fg = NostrFilterGroup::from_value(&json!([{"kinds": []}, {"kinds": [1]}]), 500, 3, 16)
            .unwrap();
        assert_eq!((fg.size(), fg.never_matching), (1, 1));
        assert!(fg.does_match(ev.view()));

        // The rest of the filter is still validated.
        assert!(NostrFilter::parse(&json!({"kinds": [], "ids": ["aa"]}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"#1": []}), 500, 3, 16).is_err());
    }

    #[test]
    fn each_validation_rule_applies_when_set() {
        let group = |filters: Value| NostrFilterGroup::from_value(&filters, 500, 3, 16).unwrap();
        // Each refusal names the rule that made it.
        let broken = |validator: &FilterValidator, fg: &NostrFilterGroup| {
            validator.validate(fg).unwrap_err().broken_limit()
        };
        // MDK's directory batch names six kinds.
        let six_kinds = group(json!([{"kinds": [0, 1, 3, 10002, 10050, 30443]}]));
        assert!(FilterValidator::default().validate(&six_kinds).is_ok());
        let capped = FilterValidator {
            max_kinds_per_filter: 3,
            ..Default::default()
        };
        assert_eq!(
            broken(&capped, &six_kinds),
            Some(FilterLimit::KindsPerFilter)
        );
        let allowed = FilterValidator {
            allowed_kinds: [0, 3].into(),
            ..Default::default()
        };
        assert_eq!(
            broken(&allowed, &six_kinds),
            Some(FilterLimit::AllowedKinds)
        );
        assert!(allowed.validate(&group(json!([{"kinds": [3]}]))).is_ok());
        let scoped = FilterValidator {
            require_author_or_tag: true,
            ..Default::default()
        };
        assert_eq!(broken(&scoped, &six_kinds), Some(FilterLimit::AuthorOrTag));
        assert!(scoped
            .validate(&group(json!([{"authors": ["11".repeat(32)]}])))
            .is_ok());
        // A filter that matches nothing is not checked.
        assert!(scoped.validate(&group(json!([{"authors": []}]))).is_ok());

        // Scoped filters accept any scope, with any number of values: what
        // Marmot clients send.
        let scoped = FilterValidator {
            require_scoped_filters: true,
            ..Default::default()
        };
        let (id, pk) = ("11".repeat(32), "22".repeat(32));
        for filter in [
            json!({"kinds": [445], "#h": ["g1", "g2"], "since": 1}),
            json!({"kinds": [1059], "#p": [pk]}),
            json!({"kinds": [1], "&p": [pk]}),
            json!({"ids": [id]}),
            json!({"authors": [pk, id], "kinds": [0, 3, 10002, 10050, 30443]}),
            json!({"#d": ["x"]}),
        ] {
            assert!(scoped.validate(&group(json!([filter]))).is_ok(), "{filter}");
        }
        for filter in [
            json!({"kinds": [445]}),
            json!({"since": 1}),
            json!({}),
            json!({"search": "nostr"}),
        ] {
            assert_eq!(
                scoped
                    .validate(&group(json!([filter])))
                    .unwrap_err()
                    .to_string(),
                "filter must name ids, authors or a tag",
                "{filter}"
            );
            assert_eq!(
                broken(&scoped, &group(json!([filter]))),
                Some(FilterLimit::ScopedFilters),
                "{filter}"
            );
        }
        // Every filter of the request.
        assert!(scoped
            .validate(&group(json!([{"ids": [id]}, {"kinds": [445]}])))
            .is_err());
    }

    #[test]
    fn parse_limits_name_the_limit_they_broke() {
        let pk = "22".repeat(32);
        let limit = |filter: Value| {
            NostrFilter::parse(&filter, 500, 2, 1)
                .unwrap_err()
                .broken_limit()
        };
        assert_eq!(
            limit(json!({"#t": ["a"], "#e": [pk], "#p": [pk]})),
            Some(FilterLimit::TagsPerFilter)
        );
        assert_eq!(
            limit(json!({"&t": ["a", "b"]})),
            Some(FilterLimit::AndEntries)
        );
        assert_eq!(limit(json!({"ids": ["aa"]})), None);
    }

    #[test]
    fn kind_and_time_match() {
        let f = NostrFilter::parse(&json!({"kinds":[1], "since": 10, "until": 20}), 500, 3, 16)
            .unwrap();
        let ev = packed_note(1, 2, 15, 1, &[]);
        assert!(f.does_match(ev.view()));
        let ev = packed_note(1, 2, 9, 1, &[]);
        assert!(!f.does_match(ev.view()));
        let ev = packed_note(1, 2, 15, 2, &[]);
        assert!(!f.does_match(ev.view()));
    }

    #[test]
    fn long_tag_values_match_their_hashed_packed_form() {
        let longest = "z".repeat(wok_event::MAX_INDEXED_TAG_VAL_SIZE);
        let long = "z".repeat(300);
        let longer = "z".repeat(301);
        let packed = |value: &str| {
            let indexed = indexed_tag_value(value.as_bytes());
            packed_note(1, 2, 15, 30000, &[("d", &indexed)])
        };
        for (value, other) in [(&longest, &long), (&long, &longer), (&longer, &long)] {
            for key in ["#d", "&d"] {
                let f = NostrFilter::parse(&json!({ key: [value] }), 500, 3, 16).unwrap();
                assert!(f.does_match(packed(value).view()), "{key} {}", value.len());
                assert!(!f.does_match(packed(other).view()), "{key} {}", value.len());
            }
        }

        let f = NostrFilter::parse(&json!({"#d": [&long, "short", &long]}), 500, 3, 16).unwrap();
        let values = &f.tags[&'d'];
        assert_eq!(values.size(), 2);
        let originals: HashSet<_> = (0..2).map(|n| values.original(n)).collect();
        assert_eq!(originals, HashSet::from([long.as_bytes(), &b"short"[..]]));

        // A required long value leaves only the other OR alternative.
        let f = NostrFilter::parse(&json!({"&d": [&long], "#d": [&long, &longer]}), 500, 3, 16)
            .unwrap();
        assert_eq!(f.tags[&'d'].size(), 1);
        assert_eq!(f.tags[&'d'].original(0), longer.as_bytes());

        // The total bound counts the values as sent, not their hashes.
        let many: Vec<_> = (0..70)
            .map(|n| format!("{n:02}{}", "z".repeat(998)))
            .collect();
        assert!(NostrFilter::parse(&json!({"#r": many}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"#r": &many[..65]}), 500, 3, 16).is_ok());
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(NostrFilter::parse(&json!({"foo": 1}), 500, 3, 16).is_err());
    }

    #[test]
    fn ids_must_be_32_bytes() {
        assert!(NostrFilter::parse(&json!({"ids":["aa"]}), 500, 3, 16).is_err());
    }

    #[test]
    fn index_only_heuristic() {
        let f = NostrFilter::parse(&json!({"kinds":[1]}), 500, 3, 16).unwrap();
        assert!(f.index_only_scans);
        let f = NostrFilter::parse(
            &json!({"authors":["11".repeat(32)], "kinds":[1]}),
            500,
            3,
            16,
        )
        .unwrap();
        assert!(f.index_only_scans);
        let f =
            NostrFilter::parse(&json!({"ids":["11".repeat(32)], "kinds":[1]}), 500, 3, 16).unwrap();
        assert!(!f.index_only_scans);
    }

    #[test]
    fn search_matching_accepts_precomputed_event_terms() {
        let filter = NostrFilter::parse(&json!({"search":"café nostr"}), 500, 3, 16).unwrap();
        let event = packed_note(1, 2, 15, 1, &[]);
        let terms = search_term_set("A NOSTR relay with Café support");

        assert!(!filter.does_match(event.view()));
        assert!(!filter.does_match_with_search_terms(event.view(), None));
        assert!(filter.does_match_with_search_terms(event.view(), Some(&terms)));
    }

    #[test]
    fn nip91_requires_every_and_value_and_preserves_residual_or() {
        let filter = NostrFilter::parse(
            &json!({
                "&t":["meme", "cat"],
                "#t":["meme", "cat", "black", "white"]
            }),
            500,
            3,
            16,
        )
        .unwrap();
        assert!(!filter.index_only_scans);
        assert_eq!(filter.and_tags[&'t'].size(), 2);
        assert_eq!(filter.tags[&'t'].size(), 2);

        let matching = packed_note(
            1,
            2,
            15,
            1,
            &[("t", b"meme"), ("t", b"cat"), ("t", b"black")],
        );
        let missing_and = packed_note(2, 2, 15, 1, &[("t", b"meme"), ("t", b"black")]);
        let missing_or = packed_note(3, 2, 15, 1, &[("t", b"meme"), ("t", b"cat")]);
        assert!(filter.does_match(matching.view()));
        assert!(!filter.does_match(missing_and.view()));
        assert!(!filter.does_match(missing_or.view()));
    }

    #[test]
    fn nip91_complete_overlap_removes_the_or_clause() {
        let filter = NostrFilter::parse(
            &json!({"&t":["meme", "cat"], "#t":["cat", "meme"]}),
            500,
            3,
            16,
        )
        .unwrap();
        assert!(filter.tags.is_empty());
        let event = packed_note(1, 2, 15, 1, &[("t", b"meme"), ("t", b"cat")]);
        assert!(filter.does_match(event.view()));
        assert!(!filter.is_full_db_query());
    }

    #[test]
    fn nip91_validates_shape_hex_and_limits() {
        assert!(NostrFilter::parse(&json!({"&t":[]}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"&t":"meme"}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"&1":["x"]}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"&tag":["x"]}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"&p":["AA".repeat(32)]}), 500, 3, 16).is_err());
        assert!(NostrFilter::parse(&json!({"&e":["aa"]}), 500, 3, 16).is_err());

        let duplicate =
            NostrFilter::parse(&json!({"&t":["a", "a", "b"], "#t":["a", "b"]}), 500, 1, 2).unwrap();
        assert_eq!(duplicate.and_tags[&'t'].size(), 2);
        assert!(NostrFilter::parse(&json!({"&t":["a", "b", "c"]}), 500, 1, 2,).is_err());
        assert!(
            NostrFilter::parse(&json!({"&t":["a"], "#p":["11".repeat(32)]}), 500, 1, 2,).is_err()
        );
    }
}
