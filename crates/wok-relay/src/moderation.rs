//! NIP-86 management commands, role-based management levels, and the
//! membership and write-policy decisions shared by the ingester, the writer
//! thread and the HTTP endpoint.

use crate::config::AccessPolicy;
use crate::Config;
use wok_db::{ModerationSnapshot, BUILTIN_ROLE_ADMIN, BUILTIN_ROLE_MODERATOR};
use wok_event::{to_hex, PackedEventView};

pub use wok_db::Role;

/// A management mutation applied by the single writer thread so LMDB and the
/// in-memory snapshot change atomically from the relay's point of view.
#[derive(Debug)]
pub enum ManagementCmd {
    BanPubkey { pubkey: [u8; 32], reason: String },
    UnbanPubkey { pubkey: [u8; 32] },
    AllowPubkey { pubkey: [u8; 32], reason: String },
    UnallowPubkey { pubkey: [u8; 32] },
    BanEvent { id: [u8; 32], reason: String },
    UnbanEvent { id: [u8; 32] },
    AllowEvent { id: [u8; 32], reason: String },
    UnallowEvent { id: [u8; 32] },
    BlockIp { ip: String, reason: String },
    UnblockIp { ip: String },
    PutRole { role: Role },
    DeleteRole { id: String },
    AssignRole { pubkey: [u8; 32], role: String },
    UnassignRole { pubkey: [u8; 32], role: String },
    AllowKind { kind: u64 },
    DisallowKind { kind: u64 },
}

impl ManagementCmd {
    /// Apply the mutation inside an open read-write transaction.
    pub fn apply(&self, txn: &mut wok_db::RwTxn<'_>) -> Result<(), wok_db::DbError> {
        match self {
            Self::BanPubkey { pubkey, reason } => wok_db::ban_pubkey(txn, pubkey, reason),
            Self::UnbanPubkey { pubkey } => wok_db::unban_pubkey(txn, pubkey),
            Self::AllowPubkey { pubkey, reason } => wok_db::allow_pubkey(txn, pubkey, reason),
            Self::UnallowPubkey { pubkey } => wok_db::unallow_pubkey(txn, pubkey),
            Self::BanEvent { id, reason } => wok_db::ban_event(txn, id, reason),
            Self::UnbanEvent { id } => wok_db::unban_event(txn, id),
            Self::AllowEvent { id, reason } => wok_db::allow_event(txn, id, reason),
            Self::UnallowEvent { id } => wok_db::unallow_event(txn, id),
            Self::BlockIp { ip, reason } => wok_db::block_ip(txn, ip, reason),
            Self::UnblockIp { ip } => wok_db::unblock_ip(txn, ip),
            Self::PutRole { role } => wok_db::put_role(txn, role),
            Self::DeleteRole { id } => wok_db::delete_role(txn, id),
            Self::AssignRole { pubkey, role } => wok_db::assign_role(txn, pubkey, role),
            Self::UnassignRole { pubkey, role } => wok_db::unassign_role(txn, pubkey, role),
            Self::AllowKind { kind } => wok_db::allow_kind(txn, *kind),
            Self::DisallowKind { kind } => wok_db::disallow_kind(txn, *kind),
        }
    }
}

/// Management access granted to a management-API signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementLevel {
    /// Config `admin.pubkeys` or the built-in `admin` role: every method.
    Admin,
    /// Built-in `moderator` role: moderation methods only, no relay config or
    /// role management.
    Moderator,
    None,
}

pub fn management_level(
    cfg: &Config,
    snap: &ModerationSnapshot,
    pubkey: &[u8; 32],
) -> ManagementLevel {
    let hex = to_hex(pubkey);
    if cfg.admin.pubkeys.iter().any(|allowed| allowed == &hex) {
        return ManagementLevel::Admin;
    }
    let roles = snap.roles_of(pubkey);
    if roles.iter().any(|role| role == BUILTIN_ROLE_ADMIN) {
        ManagementLevel::Admin
    } else if roles.iter().any(|role| role == BUILTIN_ROLE_MODERATOR) {
        ManagementLevel::Moderator
    } else {
        ManagementLevel::None
    }
}

fn is_admin_pubkey(cfg: &Config, pubkey: &[u8; 32]) -> bool {
    let hex = to_hex(pubkey);
    cfg.admin.pubkeys.iter().any(|allowed| allowed == &hex)
}

/// Whether `pubkey` is a member under `relay.auth`'s `members` policies: it
/// is not banned, and it is allowlisted, holds any role (built-in or
/// custom), or is one of `admin.pubkeys`.
pub fn is_member(cfg: &Config, snap: &ModerationSnapshot, pubkey: &[u8; 32]) -> bool {
    !snap.banned_pubkeys.contains_key(pubkey)
        && (snap.is_member(pubkey) || is_admin_pubkey(cfg, pubkey))
}

/// [`is_member`] by committed LMDB moderation state instead of the
/// in-memory snapshot. This closes the race where an allowlist or role
/// revocation commits after an event passed the ingester's snapshot check
/// but before the writer stores it.
pub fn stored_is_member(
    txn: &wok_db::RoTxn<'_>,
    cfg: &Config,
    pubkey: &[u8; 32],
) -> Result<bool, wok_db::DbError> {
    if wok_db::banned_pubkey_reason_ro(txn, pubkey)?.is_some() {
        return Ok(false);
    }
    Ok(wok_db::allowed_pubkey_reason_ro(txn, pubkey)?.is_some()
        || !wok_db::pubkey_roles_ro(txn, pubkey)?.is_empty()
        || is_admin_pubkey(cfg, pubkey))
}

/// What an event offers `relay.auth.write_policy`: whether its connection
/// had authenticated, and the member, if any, that admits it. Bans and the
/// kind policy are checked apart from it, and NIP-62 vanish requests skip it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteGrant {
    pub authenticated: bool,
    /// The connection had authenticated as the event's author, which NIP-70
    /// protected events and `owner_only_kinds` require whatever the policy.
    pub as_author: bool,
    pub member: Option<[u8; 32]>,
    /// The member is the recipient of one of `inbox_kinds`, which must
    /// still list the event's kind.
    pub inbox: bool,
}

impl WriteGrant {
    /// The grant for `event` sent on a connection authenticated as
    /// `identities`. Under `write_policy = "members"`, its member is the
    /// event's author, else one of `identities` (C7: a member's events from
    /// throwaway keys), else, for one of `inbox_kinds`, its first `p`-tag
    /// recipient.
    pub fn new(
        cfg: &Config,
        snap: &ModerationSnapshot,
        event: PackedEventView<'_>,
        identities: &[[u8; 32]],
    ) -> Self {
        let auth = &cfg.relay.auth;
        let author: Option<[u8; 32]> = event.pubkey().try_into().ok();
        let mut grant = Self {
            authenticated: !identities.is_empty(),
            as_author: author.is_some_and(|author| identities.contains(&author)),
            ..Self::default()
        };
        if auth.write_policy != AccessPolicy::Members {
            return grant;
        }
        grant.member = author
            .into_iter()
            .chain(identities.iter().copied())
            .find(|pubkey| is_member(cfg, snap, pubkey));
        if grant.member.is_none() && auth.inbox_kinds.contains(&event.kind()) {
            grant.member = first_p_tag(event).filter(|pubkey| is_member(cfg, snap, pubkey));
            grant.inbox = grant.member.is_some();
        }
        grant
    }

    /// Whether `relay.auth.write_policy` admits the event, by the
    /// moderation state the grant was made from.
    pub fn admits(&self, cfg: &Config) -> bool {
        match cfg.relay.auth.write_policy {
            AccessPolicy::Open => true,
            AccessPolicy::Authenticated => self.authenticated,
            AccessPolicy::Members => self.member.is_some(),
        }
    }

    /// [`admits`](Self::admits) for an event of `kind` by committed
    /// moderation state and the writer's configuration: the member must
    /// still be one, and an inbox recipient's kind still an inbox kind.
    pub fn stored_admits(
        &self,
        txn: &wok_db::RoTxn<'_>,
        cfg: &Config,
        kind: u64,
    ) -> Result<bool, wok_db::DbError> {
        match (cfg.relay.auth.write_policy, self.member) {
            (AccessPolicy::Members, Some(member)) => Ok((!self.inbox
                || cfg.relay.auth.inbox_kinds.contains(&kind))
                && stored_is_member(txn, cfg, &member)?),
            _ => Ok(self.admits(cfg)),
        }
    }

    /// The OK reason for an event the policy does not admit:
    /// `auth-required:` while authenticating could admit it.
    pub fn refusal(&self, cfg: &Config) -> String {
        let policy = cfg.relay.auth.write_policy;
        let who = match policy {
            AccessPolicy::Members => "members",
            _ => "authenticated users",
        };
        if !self.authenticated && cfg.auth_usable() {
            format!("auth-required: this relay accepts events only from {who}")
        } else if !self.authenticated && policy == AccessPolicy::Authenticated {
            "restricted: this relay accepts events only from authenticated users, and it does \
             not offer AUTH"
                .into()
        } else {
            format!("restricted: this relay accepts events only from {who}")
        }
    }
}

/// The pubkey an event's first `p` tag names, as NIP-17 and NIP-59 address
/// their recipient.
fn first_p_tag(event: PackedEventView<'_>) -> Option<[u8; 32]> {
    let mut recipient = None;
    event.foreach_tag(|name, value| {
        if name == 'p' && value.len() == 32 {
            recipient = value.try_into().ok();
            return false;
        }
        true
    });
    recipient
}

#[cfg(test)]
mod tests {
    use super::*;
    use wok_db::BUILTIN_ROLE_MEMBER;

    fn snap_with(assignments: &[(&[u8; 32], &str)]) -> ModerationSnapshot {
        let mut snap = ModerationSnapshot::default();
        for (pubkey, role) in assignments {
            snap.pubkey_roles
                .entry(**pubkey)
                .or_default()
                .push(role.to_string());
        }
        snap
    }

    #[test]
    fn management_levels_follow_config_and_roles() {
        let mut cfg = Config::default();
        let admin_pk = [1u8; 32];
        cfg.admin.pubkeys = vec![to_hex(&admin_pk)];
        let snap = snap_with(&[
            (&[2u8; 32], BUILTIN_ROLE_ADMIN),
            (&[3u8; 32], BUILTIN_ROLE_MODERATOR),
        ]);
        assert_eq!(
            management_level(&cfg, &snap, &admin_pk),
            ManagementLevel::Admin
        );
        assert_eq!(
            management_level(&cfg, &snap, &[2u8; 32]),
            ManagementLevel::Admin
        );
        assert_eq!(
            management_level(&cfg, &snap, &[3u8; 32]),
            ManagementLevel::Moderator
        );
        assert_eq!(
            management_level(&cfg, &snap, &[9u8; 32]),
            ManagementLevel::None
        );
    }

    #[test]
    fn membership_combines_bans_allowlist_roles_and_admins() {
        let mut cfg = Config::default();
        let admin_pk = [1u8; 32];
        cfg.admin.pubkeys = vec![to_hex(&admin_pk)];
        let mut snap = snap_with(&[(&[2u8; 32], BUILTIN_ROLE_MEMBER)]);
        snap.allowed_pubkeys.insert([3u8; 32], String::new());
        snap.banned_pubkeys.insert([4u8; 32], String::new());
        snap.allowed_pubkeys.insert([4u8; 32], String::new());

        assert!(is_member(&cfg, &snap, &[2u8; 32])); // member role
        assert!(is_member(&cfg, &snap, &[3u8; 32])); // allowlisted
        assert!(is_member(&cfg, &snap, &admin_pk)); // operator admin
        assert!(!is_member(&cfg, &snap, &[4u8; 32])); // ban wins
        assert!(!is_member(&cfg, &snap, &[9u8; 32]));
    }

    #[test]
    fn write_grants_follow_the_policy() {
        use wok_event::{PackedEventBuilder, PackedEventTagBuilder};
        let mut cfg = Config::default();
        cfg.relay.auth.service_url = "wss://relay.example.com".into();
        let (member, outsider, throwaway) = ([2u8; 32], [3u8; 32], [5u8; 32]);
        let mut snap = ModerationSnapshot::default();
        snap.allowed_pubkeys.insert(member, String::new());
        let event = |author: &[u8; 32], kind: u64, recipient: &[u8; 32]| {
            let mut tags = PackedEventTagBuilder::default();
            tags.add('p', recipient).unwrap();
            PackedEventBuilder::build(&[1u8; 32], author, 1, kind, 0, &tags).unwrap()
        };
        let grant = |author: &[u8; 32],
                     kind: u64,
                     recipient: &[u8; 32],
                     identities: &[[u8; 32]],
                     cfg: &Config| {
            WriteGrant::new(
                cfg,
                &snap,
                event(author, kind, recipient).view(),
                identities,
            )
        };

        // Open and authenticated policies need no member.
        let anonymous = grant(&throwaway, 445, &outsider, &[], &cfg);
        assert_eq!(anonymous, WriteGrant::default());
        assert!(anonymous.admits(&cfg));
        cfg.relay.auth.write_policy = AccessPolicy::Authenticated;
        assert!(!anonymous.admits(&cfg));
        assert!(anonymous.refusal(&cfg).starts_with("auth-required: "));
        let authed = grant(&throwaway, 445, &outsider, &[outsider], &cfg);
        assert_eq!(authed.member, None);
        assert!(authed.admits(&cfg));
        // Whether one of the identities is the author is recorded under
        // every policy, for NIP-70 and `owner_only_kinds`.
        assert!(!authed.as_author);
        assert!(grant(&throwaway, 445, &outsider, &[outsider, throwaway], &cfg).as_author);

        // Members: the author, an AUTHed identity (C7), or an inbox kind's
        // first recipient.
        cfg.relay.auth.write_policy = AccessPolicy::Members;
        // (author, kind, first p tag, AUTHed identities, admitting member,
        // whether it was admitted as an inbox recipient)
        for (author, kind, recipient, identities, admitted_by, inbox) in [
            (member, 1, outsider, vec![], Some(member), false),
            (
                throwaway,
                445,
                outsider,
                vec![outsider, member],
                Some(member),
                false,
            ),
            (throwaway, 1059, member, vec![], Some(member), true),
            (throwaway, 21059, member, vec![outsider], Some(member), true),
            (throwaway, 4, member, vec![], None, false),
            (throwaway, 445, outsider, vec![outsider], None, false),
            (throwaway, 445, outsider, vec![], None, false),
        ] {
            let grant = grant(&author, kind, &recipient, &identities, &cfg);
            assert_eq!(grant.member, admitted_by, "kind {kind} {identities:?}");
            assert_eq!(grant.inbox, inbox, "kind {kind} {identities:?}");
            assert_eq!(grant.admits(&cfg), admitted_by.is_some());
        }
        let anonymous = grant(&throwaway, 445, &outsider, &[], &cfg);
        assert_eq!(
            anonymous.refusal(&cfg),
            "auth-required: this relay accepts events only from members"
        );
        let outsider_conn = grant(&throwaway, 445, &outsider, &[outsider], &cfg);
        assert_eq!(
            outsider_conn.refusal(&cfg),
            "restricted: this relay accepts events only from members"
        );
        // Without usable AUTH, authenticating cannot help.
        cfg.relay.auth.service_url.clear();
        assert!(anonymous.refusal(&cfg).starts_with("restricted: "));
        cfg.relay.auth.inbox_kinds.clear();
        assert_eq!(grant(&throwaway, 1059, &member, &[], &cfg).member, None);
    }

    /// The writer-side recheck must observe committed revocations, closing
    /// the race where an event passed the ingester's snapshot check before
    /// `unallowpubkey`/`unassignrole`/`deleterole` committed.
    #[test]
    fn stored_membership_sees_committed_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        let mut cfg = Config::default();
        cfg.relay.auth.write_policy = AccessPolicy::Members;
        let admin_pk = [1u8; 32];
        cfg.admin.pubkeys = vec![to_hex(&admin_pk)];
        let alice = [7u8; 32];

        let permitted = |env: &wok_db::Env, cfg: &Config, pk: &[u8; 32]| {
            let txn = env.begin_ro().unwrap();
            stored_is_member(&txn, cfg, pk).unwrap()
        };

        // Nobody is allowed initially; admins always are.
        assert!(!permitted(&env, &cfg, &alice));
        assert!(permitted(&env, &cfg, &admin_pk));

        // Allow, then revoke: the committed state flips the decision.
        let mut txn = env.begin_rw().unwrap();
        wok_db::allow_pubkey(&mut txn, &alice, "").unwrap();
        txn.commit().unwrap();
        assert!(permitted(&env, &cfg, &alice));
        let mut txn = env.begin_rw().unwrap();
        wok_db::unallow_pubkey(&mut txn, &alice).unwrap();
        txn.commit().unwrap();
        assert!(!permitted(&env, &cfg, &alice));

        // Role assignment grants, role deletion revokes.
        let mut txn = env.begin_rw().unwrap();
        wok_db::put_role(
            &mut txn,
            &Role {
                id: "vip".into(),
                label: String::new(),
                description: String::new(),
                color: String::new(),
                order: 0,
            },
        )
        .unwrap();
        wok_db::assign_role(&mut txn, &alice, "vip").unwrap();
        txn.commit().unwrap();
        assert!(permitted(&env, &cfg, &alice));
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_role(&mut txn, "vip").unwrap();
        txn.commit().unwrap();
        assert!(!permitted(&env, &cfg, &alice));

        // A ban dominates even an explicit allow.
        let mut txn = env.begin_rw().unwrap();
        wok_db::allow_pubkey(&mut txn, &alice, "").unwrap();
        wok_db::ban_pubkey(&mut txn, &alice, "").unwrap();
        txn.commit().unwrap();
        assert!(!permitted(&env, &cfg, &alice));

        // A grant names the member it was made for, which must still be
        // one; the open policy needs none.
        let txn = env.begin_ro().unwrap();
        let grant = WriteGrant {
            authenticated: true,
            member: Some(alice),
            ..WriteGrant::default()
        };
        assert!(!grant.stored_admits(&txn, &cfg, 1).unwrap());
        cfg.relay.auth.write_policy = AccessPolicy::Open;
        assert!(grant.stored_admits(&txn, &cfg, 1).unwrap());
    }
}
