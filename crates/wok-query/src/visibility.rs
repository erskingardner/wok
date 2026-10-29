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
    if wok_db::has_deletion_markers_ro(txn)? {
        return Ok(false);
    }
    if let Some(dbi) = db.moderation {
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

/// Who may read events of a kind. Each class admits fewer readers than the
/// one before it, and a kind listed in several classes takes the strictest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadClass {
    /// Anyone.
    Open,
    /// Any reader that has authenticated, as any pubkey.
    Authenticated,
    /// The author and the event's first `p`-tag recipient.
    Recipient,
    /// The author only.
    Owner,
}

/// The kinds of each restricted [`ReadClass`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadRestrictor {
    /// Kinds only their author and first `p`-tag recipient may read, such as
    /// DMs and gift wraps.
    pub recipient_only: Vec<u64>,
    /// Kinds only their author may read, such as NIP-78 app data.
    pub owner_only: Vec<u64>,
    /// Kinds any authenticated reader may read.
    pub authenticated: Vec<u64>,
}

impl ReadRestrictor {
    pub fn class(&self, kind: u64) -> ReadClass {
        if self.owner_only.contains(&kind) {
            ReadClass::Owner
        } else if self.recipient_only.contains(&kind) {
            ReadClass::Recipient
        } else if self.authenticated.contains(&kind) {
            ReadClass::Authenticated
        } else {
            ReadClass::Open
        }
    }

    /// Every kind in a restricted class.
    pub fn restricted_kinds(&self) -> impl Iterator<Item = u64> + '_ {
        self.owner_only
            .iter()
            .chain(&self.recipient_only)
            .chain(&self.authenticated)
            .copied()
    }

    pub fn is_restricted_kind(&self, kind: u64) -> bool {
        self.class(kind) != ReadClass::Open
    }

    fn restricts_nothing(&self) -> bool {
        self.restricted_kinds().next().is_none()
    }

    /// The strictest class of the kinds `filter` can match. A filter that
    /// names no kinds matches every class in use.
    fn strictest_class(&self, filter: &NostrFilter) -> ReadClass {
        match &filter.kinds {
            Some(kinds) => kinds
                .iter()
                .map(|kind| self.class(kind))
                .max()
                .unwrap_or(ReadClass::Open),
            None if !self.owner_only.is_empty() => ReadClass::Owner,
            None if !self.recipient_only.is_empty() => ReadClass::Recipient,
            None if !self.authenticated.is_empty() => ReadClass::Authenticated,
            None => ReadClass::Open,
        }
    }

    pub fn is_filter_fully_restricted(&self, filter: &NostrFilter) -> bool {
        let Some(kinds) = &filter.kinds else {
            return false;
        };
        if self.restricts_nothing() {
            return false;
        }
        kinds.iter().all(|k| self.is_restricted_kind(k))
    }

    /// Whether this rule can hide any event `fg` matches from a reader that
    /// has not authenticated.
    pub fn may_hide_matches(&self, fg: &NostrFilterGroup) -> bool {
        self.strictest_group_class(fg) != ReadClass::Open
    }

    /// The strictest class of the kinds any filter in `fg` can match.
    pub fn strictest_group_class(&self, fg: &NostrFilterGroup) -> ReadClass {
        fg.filters
            .iter()
            .map(|f| self.strictest_class(f))
            .max()
            .unwrap_or(ReadClass::Open)
    }

    pub fn is_filter_group_fully_restricted(&self, fg: &NostrFilterGroup) -> bool {
        if self.restricts_nothing() || fg.filters.is_empty() {
            return false;
        }
        fg.filters
            .iter()
            .all(|f| self.is_filter_fully_restricted(f))
    }

    pub fn is_filter_allowed_to_count(&self, fg: &NostrFilterGroup, authed: Option<&[u8]>) -> bool {
        fg.filters
            .iter()
            .all(|f| self.count_refusal(f, authed).is_none())
    }

    /// The class that keeps `authed` from counting `f`, if one does.
    fn count_refusal(&self, f: &NostrFilter, authed: Option<&[u8]>) -> Option<ReadClass> {
        // Admission requires a filter scoped to what `authed` may read.
        // The shared per-event check additionally enforces first-recipient
        // semantics before counting.
        let class = self.strictest_class(f);
        if class == ReadClass::Open {
            return None;
        }
        let Some(pk) = authed else {
            return Some(class);
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
        let scoped = match class {
            ReadClass::Open | ReadClass::Authenticated => true,
            ReadClass::Recipient => author_scoped || p_scoped || and_p_scoped,
            ReadClass::Owner => author_scoped,
        };
        (!scoped).then_some(class)
    }

    /// The strictest class that keeps a reader authenticated as
    /// `identities` (none, for an anonymous one) from counting `fg`: of the
    /// filters no identity may count, else, when each is counted by one
    /// identity but none counts them all, of those the first may not.
    pub fn count_refusal_class(&self, fg: &NostrFilterGroup, identities: &[[u8; 32]]) -> ReadClass {
        let refused_to_all = fg
            .filters
            .iter()
            .filter_map(|f| {
                let classes = identities
                    .iter()
                    .map(|pk| self.count_refusal(f, Some(pk)))
                    .chain(identities.is_empty().then(|| self.count_refusal(f, None)));
                classes
                    .collect::<Option<Vec<_>>>()
                    .map(|_| self.strictest_class(f))
            })
            .max();
        refused_to_all
            .or_else(|| {
                let first = identities.first().map(|pk| &pk[..]);
                fg.filters
                    .iter()
                    .filter_map(|f| self.count_refusal(f, first))
                    .max()
            })
            .unwrap_or(ReadClass::Open)
    }

    pub fn should_send_to_subscriber(
        &self,
        packed: PackedEventView<'_>,
        authed: Option<&[u8]>,
    ) -> bool {
        let class = self.class(packed.kind());
        if class == ReadClass::Open {
            return true;
        }
        let Some(pk) = authed else {
            return false;
        };
        // Authors can always read their own events, including restricted
        // kinds that carry no `p` tag.
        if class == ReadClass::Authenticated || pk == packed.pubkey() {
            return true;
        }
        if class == ReadClass::Owner {
            return false;
        }
        let mut recipient = false;
        packed.foreach_tag(|name, val| {
            if name == 'p' && val.len() == 32 {
                recipient = val == pk;
                return false;
            }
            true
        });
        recipient
    }
}

/// A read transaction as visibility checks see it. The clock is read once,
/// and which policy tables can hide an event is found once, so checking each
/// event looks up only what is there. Build one per scan slice, live batch or
/// sync pass. A table whose state cannot be read is checked for every event,
/// as if it held records.
pub struct ReadSnapshot<'t> {
    txn: &'t wok_db::RoTxn<'t>,
    now: u64,
    /// An author-vanish or kind-5 recipient marker may hide an event.
    deletions: bool,
    moderation: wok_db::ModerationView<'t>,
    /// A replaceable or addressable event checked may lose replacement.
    superseded: bool,
}

impl<'t> ReadSnapshot<'t> {
    /// For any event, stored in `txn` or not.
    pub fn new(txn: &'t wok_db::RoTxn<'t>) -> Self {
        Self {
            txn,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            deletions: wok_db::has_deletion_markers_ro(txn).unwrap_or(true),
            moderation: wok_db::ModerationView::new(txn),
            superseded: true,
        }
    }

    /// For events read from `txn`, and live-only events, which are never
    /// replaceable. When `txn` holds no superseded version, no stored event
    /// loses NIP-01 replacement, so that lookup is skipped. A replaceable
    /// event not stored in `txn`, such as a copy of one since replaced, could
    /// still lose to one that is: check it with [`new`](Self::new).
    pub fn for_stored(txn: &'t wok_db::RoTxn<'t>) -> Self {
        Self {
            superseded: !matches!(wok_db::state::superseded_events_ro(txn), Ok(Some(0))),
            ..Self::new(txn)
        }
    }

    pub fn txn(&self) -> &'t wok_db::RoTxn<'t> {
        self.txn
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadVisibility {
    pub restrictor: ReadRestrictor,
    pub identities: Vec<[u8; 32]>,
    pub ephemeral_lifetime_secs: Option<u64>,
    /// Set only by operator tools that address stored records. Client reads
    /// never set it: NIP-42 forbids sending kind 22242 to any client.
    pub include_auth_events: bool,
}

impl ReadVisibility {
    pub fn allows(
        &self,
        snapshot: &ReadSnapshot<'_>,
        event: PackedEventView<'_>,
    ) -> Result<bool, wok_db::DbError> {
        if !self
            .restrictor
            .should_send_to_identities(event, &self.identities)
        {
            return Ok(false);
        }
        self.globally_visible(snapshot, event)
    }

    /// [`allows`](Self::allows), also setting `restricted` when the event is
    /// hidden by the restricted-read rule alone, which authenticating as an
    /// involved pubkey lifts. Moderation, vanish, expiry and replacement are
    /// not: AUTH changes none of them. Once `restricted` is set, hidden
    /// events cost no more than `allows`.
    pub fn allows_noting_restricted(
        &self,
        snapshot: &ReadSnapshot<'_>,
        event: PackedEventView<'_>,
        restricted: &mut bool,
    ) -> Result<bool, wok_db::DbError> {
        if self
            .restrictor
            .should_send_to_identities(event, &self.identities)
        {
            return self.globally_visible(snapshot, event);
        }
        if !*restricted && self.globally_visible(snapshot, event)? {
            *restricted = true;
        }
        Ok(false)
    }

    pub fn globally_visible(
        &self,
        snapshot: &ReadSnapshot<'_>,
        event: PackedEventView<'_>,
    ) -> Result<bool, wok_db::DbError> {
        // NIP-42: relays MUST exclude kind 22242 from broadcast. Wok's ingest
        // paths refuse one, but a record migrated from strfry or committed by
        // another writer is hidden from every client read. Being ephemeral,
        // it also has an expiration record, which keeps physical trees on
        // per-event checks.
        if event.kind() == wok_event::AUTH_KIND && !self.include_auth_events {
            return Ok(false);
        }
        let now = snapshot.now;
        // NIP-59 backdates gift wraps, so a kind 21059 may be published up to
        // GIFT_WRAP_BACKDATE_SECS after its created_at. Its lifetime counts
        // from that latest publication time; from created_at, a backdated
        // wrap accepted at publication would already have expired.
        let lifetime_start = if event.kind() == 21059 {
            event
                .created_at()
                .saturating_add(wok_event::GIFT_WRAP_BACKDATE_SECS)
        } else {
            event.created_at()
        };
        if (event.expiration() > 1 && event.expiration() <= now)
            || (event.expiration() == 1
                && self
                    .ephemeral_lifetime_secs
                    .is_some_and(|ttl| lifetime_start.saturating_add(ttl) <= now))
        {
            return Ok(false);
        }
        let txn = snapshot.txn;
        Ok(
            !(snapshot.deletions && wok_db::is_event_vanished_ro(txn, event)?)
                && !snapshot.moderation.hides(event)?
                && !(snapshot.superseded && wok_db::is_event_superseded_ro(txn, event)?),
        )
    }
}

impl ReadRestrictor {
    pub fn should_send_to_identities(
        &self,
        event: PackedEventView<'_>,
        identities: &[[u8; 32]],
    ) -> bool {
        if !self.is_restricted_kind(event.kind()) {
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
    use serde_json::{json, Value};
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    fn recipient_only(kinds: Vec<u64>) -> ReadRestrictor {
        ReadRestrictor {
            recipient_only: kinds,
            ..ReadRestrictor::default()
        }
    }

    #[test]
    fn fully_restricted_kinds() {
        let r = recipient_only(vec![4, 1059]);
        let fg = NostrFilterGroup::from_value(&json!({"kinds":[4]}), 500, 3, 16).unwrap();
        assert!(r.is_filter_group_fully_restricted(&fg));
        let fg = NostrFilterGroup::from_value(&json!({"kinds":[1,4]}), 500, 3, 16).unwrap();
        assert!(!r.is_filter_group_fully_restricted(&fg));
    }

    #[test]
    fn send_restricted_to_p_tag() {
        let r = recipient_only(vec![4]);
        let mut tags = PackedEventTagBuilder::default();
        tags.add('p', &[9u8; 32]).unwrap();
        let ev = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 1, 4, 0, &tags).unwrap();
        assert!(!r.should_send_to_subscriber(ev.view(), None));
        assert!(r.should_send_to_subscriber(ev.view(), Some(&[9u8; 32])));
        assert!(r.should_send_to_subscriber(ev.view(), Some(&[2u8; 32])));
        assert!(!r.should_send_to_subscriber(ev.view(), Some(&[3u8; 32])));
    }

    #[test]
    fn auth_events_are_hidden_from_every_reader() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let txn = env.begin_ro().unwrap();
        let snapshot = ReadSnapshot::new(&txn);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let author = [2u8; 32];
        let visibility = ReadVisibility {
            identities: vec![author],
            ephemeral_lifetime_secs: Some(3600),
            ..ReadVisibility::default()
        };
        let tags = PackedEventTagBuilder::default();
        for (kind, visible) in [(22241, true), (22242, false), (22243, true)] {
            let ev = PackedEventBuilder::build(&[1u8; 32], &author, now, kind, 1, &tags).unwrap();
            assert_eq!(
                visibility.allows(&snapshot, ev.view()).unwrap(),
                visible,
                "kind {kind}"
            );
        }
        let operator = ReadVisibility {
            include_auth_events: true,
            ..visibility
        };
        let auth = PackedEventBuilder::build(&[1u8; 32], &author, now, 22242, 1, &tags).unwrap();
        assert!(operator.allows(&snapshot, auth.view()).unwrap());
    }

    #[test]
    fn ephemeral_gift_wraps_live_as_long_as_they_may_be_backdated() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let txn = env.begin_ro().unwrap();
        let snapshot = ReadSnapshot::new(&txn);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let visibility = ReadVisibility {
            ephemeral_lifetime_secs: Some(300),
            ..ReadVisibility::default()
        };
        let backdate = wok_event::GIFT_WRAP_BACKDATE_SECS;
        let tags = PackedEventTagBuilder::default();
        for (kind, created_at, visible) in [
            (20_001, now - 60, true),
            (20_001, now - 3600, false),
            (21059, now - 3600, true),
            (21059, now - backdate, true),
            (21059, now - backdate - 400, false),
        ] {
            let ev = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], created_at, kind, 1, &tags)
                .unwrap();
            assert_eq!(
                visibility.globally_visible(&snapshot, ev.view()).unwrap(),
                visible,
                "kind {kind} dated {} s ago",
                now - created_at
            );
        }
    }

    #[test]
    fn author_reads_restricted_event_without_p_tag() {
        let r = recipient_only(vec![30078]);
        let tags = PackedEventTagBuilder::default();
        let ev = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 1, 30078, 0, &tags).unwrap();
        assert!(!r.should_send_to_subscriber(ev.view(), None));
        assert!(r.should_send_to_subscriber(ev.view(), Some(&[2u8; 32])));
        assert!(!r.should_send_to_subscriber(ev.view(), Some(&[3u8; 32])));
    }

    #[test]
    fn each_class_admits_its_readers() {
        let r = ReadRestrictor {
            recipient_only: vec![4, 30078],
            owner_only: vec![30078],
            authenticated: vec![7],
        };
        let (author, recipient, stranger) = ([2u8; 32], [9u8; 32], [3u8; 32]);
        let mut tags = PackedEventTagBuilder::default();
        tags.add('p', &recipient).unwrap();
        // (kind, anonymous, author, first p-tag recipient, anyone else)
        for (kind, readers) in [
            (1, [true, true, true, true]),
            (7, [false, true, true, true]),
            (4, [false, true, true, false]),
            // Listed as recipient-only too, but owner-only is stricter.
            (30078, [false, true, false, false]),
        ] {
            let ev = PackedEventBuilder::build(&[1u8; 32], &author, 1, kind, 0, &tags).unwrap();
            let read = [
                None,
                Some(&author[..]),
                Some(&recipient[..]),
                Some(&stranger[..]),
            ]
            .map(|pk| r.should_send_to_subscriber(ev.view(), pk));
            assert_eq!(read, readers, "kind {kind}");
            assert_eq!(
                r.should_send_to_identities(ev.view(), &[stranger, recipient]),
                readers[2],
                "kind {kind}"
            );
        }
        assert_eq!(r.class(30078), ReadClass::Owner);
        assert_eq!(r.class(1), ReadClass::Open);
    }

    #[test]
    fn counts_are_scoped_to_the_strictest_class() {
        let r = ReadRestrictor {
            recipient_only: vec![4],
            owner_only: vec![30078],
            authenticated: vec![7],
        };
        let me = [9u8; 32];
        let count = |filter: Value, authed: Option<&[u8]>| {
            let fg = NostrFilterGroup::from_value(&filter, 500, 3, 16).unwrap();
            r.is_filter_allowed_to_count(&fg, authed)
        };
        let mine = hex::encode(me);
        // Any authenticated reader may count kind 7.
        assert!(!count(json!({"kinds":[7]}), None));
        assert!(count(json!({"kinds":[7]}), Some(&me)));
        // A recipient may count the DMs tagging them, but not app data.
        assert!(count(json!({"kinds":[4],"#p":[mine]}), Some(&me)));
        assert!(!count(json!({"kinds":[30078],"#p":[mine]}), Some(&me)));
        assert!(count(json!({"kinds":[30078],"authors":[mine]}), Some(&me)));
        // Without kinds a filter can match the owner-only kinds.
        assert!(!count(json!({"#p":[mine]}), Some(&me)));
        assert!(count(json!({"authors":[mine]}), Some(&me)));
        // Nothing is restricted without a class.
        let open = ReadRestrictor::default();
        let fg = NostrFilterGroup::from_value(&json!({}), 500, 3, 16).unwrap();
        assert!(open.is_filter_allowed_to_count(&fg, None));
        assert!(!open.may_hide_matches(&fg));
        assert!(r.may_hide_matches(&fg));
    }

    #[test]
    fn count_without_kinds_cannot_leak_restricted_population() {
        let r = recipient_only(vec![4, 1059]);
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
        let r = recipient_only(vec![4]);
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
