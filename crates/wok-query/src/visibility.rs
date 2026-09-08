//! Shared per-event read visibility for history, counts, live delivery and sync.

use crate::{NostrFilter, NostrFilterGroup};
use wok_event::PackedEventView;

/// Conservative, constant-seek proof that a physical tree needs no global
/// visibility filtering. Callers separately enforce identity-scoped access.
pub fn physical_tree_is_globally_visible(
    txn: &wok_db::RoTxn<'_>,
    filter: &NostrFilter,
) -> Result<bool, wok_db::DbError> {
    let db = txn.env().dbis();
    for dbi in [db.moderation, db.vanish_pubkey].into_iter().flatten() {
        if txn.entries(dbi)? != 0 {
            return Ok(false);
        }
    }
    // Expiring/TTL records need per-event checks even between cleanup ticks.
    if txn.entries(db.event_expiration)? != 0 {
        return Ok(false);
    }
    // Physical trees are safe for clean replacement groups, including profiles
    // and contacts. Retained history (or older, uninitialized bookkeeping)
    // requires per-event filtering unless the filter excludes replacement.
    let excludes_replaceable = filter.kinds.as_ref().is_some_and(|kinds| {
        kinds.iter().all(|kind| {
            !wok_event::is_replaceable_kind(kind) && !wok_event::is_param_replaceable_kind(kind)
        })
    });
    if !excludes_replaceable && wok_db::state::superseded_events_ro(txn)? != Some(0) {
        return Ok(false);
    }
    Ok(true)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadRestrictor {
    pub restricted_kinds: Vec<u64>,
    pub restrict_to_involved: bool,
}

impl ReadRestrictor {
    pub fn new(kinds: Vec<u64>, restrict_to_involved: bool) -> Self {
        Self {
            restricted_kinds: kinds,
            restrict_to_involved,
        }
    }

    pub fn is_restricted_kind(&self, kind: u64) -> bool {
        self.restricted_kinds.contains(&kind)
    }

    pub fn is_filter_fully_restricted(&self, filter: &NostrFilter) -> bool {
        let Some(kinds) = &filter.kinds else {
            return false;
        };
        if self.restricted_kinds.is_empty() {
            return false;
        }
        kinds.iter().all(|k| self.restricted_kinds.contains(&k))
    }

    pub fn is_filter_group_fully_restricted(&self, fg: &NostrFilterGroup) -> bool {
        if self.restricted_kinds.is_empty() || fg.filters.is_empty() {
            return false;
        }
        fg.filters
            .iter()
            .all(|f| self.is_filter_fully_restricted(f))
    }

    pub fn is_filter_allowed_to_count(&self, fg: &NostrFilterGroup, authed: Option<&[u8]>) -> bool {
        if self.restricted_kinds.is_empty() {
            return true;
        }
        for f in &fg.filters {
            // Admission requires a scoped filter. The shared per-event check
            // additionally enforces first-recipient semantics before counting.
            let has_restricted = f
                .kinds
                .as_ref()
                .map(|kinds| kinds.iter().any(|k| self.restricted_kinds.contains(&k)))
                .unwrap_or(true);
            if !has_restricted {
                continue;
            }
            let Some(pk) = authed else {
                return false;
            };
            let author_scoped = f
                .authors
                .as_ref()
                .map(|a| a.size() > 0 && (0..a.size()).all(|i| a.at(i) == pk))
                .unwrap_or(false);
            let p_scoped = f
                .tags
                .get(&'p')
                .map(|t| t.size() > 0 && (0..t.size()).all(|i| t.at(i) == pk))
                .unwrap_or(false);
            let and_p_scoped = f
                .and_tags
                .get(&'p')
                .map(|t| t.size() > 0 && (0..t.size()).all(|i| t.at(i) == pk))
                .unwrap_or(false);
            if !author_scoped && !p_scoped && !and_p_scoped {
                return false;
            }
        }
        true
    }

    pub fn should_send_to_subscriber(
        &self,
        packed: PackedEventView<'_>,
        authed: Option<&[u8]>,
    ) -> bool {
        if !(self.is_restricted_kind(packed.kind()) && self.restrict_to_involved) {
            return true;
        }
        let Some(pk) = authed else {
            return false;
        };
        let mut recipient = None;
        packed.foreach_tag(|name, val| {
            if name == 'p' && val.len() == 32 {
                recipient = Some(val == pk);
                return false;
            }
            true
        });
        let Some(recipient) = recipient else {
            return false;
        };
        recipient || pk == packed.pubkey()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadVisibility {
    pub restrictor: ReadRestrictor,
    pub identities: Vec<[u8; 32]>,
    pub ephemeral_lifetime_secs: Option<u64>,
}

impl ReadVisibility {
    pub fn allows(
        &self,
        txn: &wok_db::RoTxn<'_>,
        event: PackedEventView<'_>,
    ) -> Result<bool, wok_db::DbError> {
        if !self
            .restrictor
            .should_send_to_identities(event, &self.identities)
        {
            return Ok(false);
        }
        self.globally_visible(txn, event)
    }

    pub fn globally_visible(
        &self,
        txn: &wok_db::RoTxn<'_>,
        event: PackedEventView<'_>,
    ) -> Result<bool, wok_db::DbError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if (event.expiration() > 1 && event.expiration() <= now)
            || (event.expiration() == 1
                && self
                    .ephemeral_lifetime_secs
                    .is_some_and(|ttl| event.created_at().saturating_add(ttl) <= now))
        {
            return Ok(false);
        }
        Ok(!wok_db::is_event_vanished_ro(txn, event)?
            && !wok_db::is_event_moderated_ro(txn, event)?
            && !wok_db::is_event_superseded_ro(txn, event)?)
    }
}

impl ReadRestrictor {
    pub fn should_send_to_identities(
        &self,
        event: PackedEventView<'_>,
        identities: &[[u8; 32]],
    ) -> bool {
        if !self.is_restricted_kind(event.kind()) || !self.restrict_to_involved {
            return true;
        }
        identities
            .iter()
            .any(|pk| self.should_send_to_subscriber(event, Some(pk)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    #[test]
    fn fully_restricted_kinds() {
        let r = ReadRestrictor::new(vec![4, 1059], true);
        let fg = NostrFilterGroup::from_value(&json!({"kinds":[4]}), 500, 3, 16).unwrap();
        assert!(r.is_filter_group_fully_restricted(&fg));
        let fg = NostrFilterGroup::from_value(&json!({"kinds":[1,4]}), 500, 3, 16).unwrap();
        assert!(!r.is_filter_group_fully_restricted(&fg));
    }

    #[test]
    fn send_restricted_to_p_tag() {
        let r = ReadRestrictor::new(vec![4], true);
        let mut tags = PackedEventTagBuilder::default();
        tags.add('p', &[9u8; 32]).unwrap();
        let ev = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 1, 4, 0, &tags).unwrap();
        assert!(!r.should_send_to_subscriber(ev.view(), None));
        assert!(r.should_send_to_subscriber(ev.view(), Some(&[9u8; 32])));
        assert!(r.should_send_to_subscriber(ev.view(), Some(&[2u8; 32])));
        assert!(!r.should_send_to_subscriber(ev.view(), Some(&[3u8; 32])));
    }

    #[test]
    fn count_without_kinds_cannot_leak_restricted_population() {
        let r = ReadRestrictor::new(vec![4, 1059], true);
        let broad = NostrFilterGroup::from_value(&json!({}), 500, 3, 16).unwrap();
        assert!(!r.is_filter_allowed_to_count(&broad, None));
        assert!(!r.is_filter_allowed_to_count(&broad, Some(&[9u8; 32])));

        let scoped =
            NostrFilterGroup::from_value(&json!({"authors":[hex::encode([9u8; 32])]}), 500, 3, 16)
                .unwrap();
        assert!(r.is_filter_allowed_to_count(&scoped, Some(&[9u8; 32])));
    }

    #[test]
    fn nip91_required_p_tag_safely_scopes_restricted_count() {
        let r = ReadRestrictor::new(vec![4], true);
        let authed = [9u8; 32];
        let other = [8u8; 32];
        let scoped = NostrFilterGroup::from_value(
            &json!({
                "kinds":[4],
                "&p":[hex::encode(authed)],
                "#p":[hex::encode(authed)]
            }),
            500,
            3,
            16,
        )
        .unwrap();
        assert!(r.is_filter_allowed_to_count(&scoped, Some(&authed)));
        assert!(!r.is_filter_allowed_to_count(&scoped, Some(&[7u8; 32])));

        let ambiguous_and = NostrFilterGroup::from_value(
            &json!({
                "kinds":[4],
                "&p":[hex::encode(authed), hex::encode(other)],
                "#p":[hex::encode(authed), hex::encode(other)]
            }),
            500,
            3,
            16,
        )
        .unwrap();
        assert!(!r.is_filter_allowed_to_count(&ambiguous_and, Some(&authed)));

        let unsafe_or = NostrFilterGroup::from_value(
            &json!({"kinds":[4], "#p":[hex::encode(authed), hex::encode(other)]}),
            500,
            3,
            16,
        )
        .unwrap();
        assert!(!r.is_filter_allowed_to_count(&unsafe_or, Some(&authed)));
    }
}
