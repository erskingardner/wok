//! NIP-86 management commands, role-based management levels, and write
//! permission decisions shared by the writer thread and the HTTP endpoint.

use crate::Config;
use wok_db::{ModerationSnapshot, BUILTIN_ROLE_ADMIN, BUILTIN_ROLE_MODERATOR};
use wok_event::to_hex;

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
    AllowEvent { id: [u8; 32] },
    BlockIp { ip: String, reason: String },
    UnblockIp { ip: String },
    PutRole { role: Role },
    DeleteRole { id: String },
    AssignRole { pubkey: [u8; 32], role: String },
    UnassignRole { pubkey: [u8; 32], role: String },
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
            Self::AllowEvent { id } => wok_db::allow_event(txn, id),
            Self::BlockIp { ip, reason } => wok_db::block_ip(txn, ip, reason),
            Self::UnblockIp { ip } => wok_db::unblock_ip(txn, ip),
            Self::PutRole { role } => wok_db::put_role(txn, role),
            Self::DeleteRole { id } => wok_db::delete_role(txn, id),
            Self::AssignRole { pubkey, role } => wok_db::assign_role(txn, pubkey, role),
            Self::UnassignRole { pubkey, role } => wok_db::unassign_role(txn, pubkey, role),
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

/// Whether `pubkey` may write events under the current moderation state.
/// Bans always win; `relay.auth.restrict_writes` then gates everyone not on
/// the allowlist, not holding a role, and not an operator admin.
pub fn write_permitted(cfg: &Config, snap: &ModerationSnapshot, pubkey: &[u8; 32]) -> bool {
    if snap.banned_pubkeys.contains_key(pubkey) {
        return false;
    }
    if !cfg.relay.auth.restrict_writes {
        return true;
    }
    if snap.write_permitted(pubkey) {
        return true;
    }
    let hex = to_hex(pubkey);
    cfg.admin.pubkeys.iter().any(|allowed| allowed == &hex)
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
    fn write_permission_combines_bans_allowlist_roles_and_admins() {
        let mut cfg = Config::default();
        let admin_pk = [1u8; 32];
        cfg.admin.pubkeys = vec![to_hex(&admin_pk)];
        let mut snap = snap_with(&[(&[2u8; 32], BUILTIN_ROLE_MEMBER)]);
        snap.allowed_pubkeys.insert([3u8; 32], String::new());
        snap.banned_pubkeys.insert([4u8; 32], String::new());

        // Unrestricted writes: everyone except banned authors.
        assert!(write_permitted(&cfg, &snap, &[9u8; 32]));
        assert!(!write_permitted(&cfg, &snap, &[4u8; 32]));

        cfg.relay.auth.restrict_writes = true;
        assert!(!write_permitted(&cfg, &snap, &[9u8; 32]));
        assert!(write_permitted(&cfg, &snap, &[2u8; 32])); // member role
        assert!(write_permitted(&cfg, &snap, &[3u8; 32])); // allowlisted
        assert!(write_permitted(&cfg, &snap, &admin_pk)); // operator admin
        assert!(!write_permitted(&cfg, &snap, &[4u8; 32])); // ban wins
    }
}
