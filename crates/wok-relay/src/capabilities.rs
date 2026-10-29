//! Relay-owned NIP capabilities advertised through NIP-11.
//!
//! Event kinds that Wok can store are not capabilities by themselves. This
//! catalog only contains NIPs for which the relay implements observable
//! protocol or storage behavior.

use crate::restrict::ReadClass;
use crate::Config;
use crate::EphemeralPersistence;
use std::borrow::Cow;
use std::fmt;

/// A NIP-11 identifier. Numeric NIPs retain their integer representation;
/// lettered designations retain their literal spelling as strings. The two
/// forms are distinct: `"5A"` is not numeric NIP-90, nor is `"91"` NIP-91.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(untagged)]
pub enum NipId {
    Number(u64),
    Named(Cow<'static, str>),
}

impl NipId {
    pub const fn named(name: &'static str) -> Self {
        Self::Named(Cow::Borrowed(name))
    }
}

impl From<u64> for NipId {
    fn from(number: u64) -> Self {
        Self::Number(number)
    }
}

impl From<&'static str> for NipId {
    fn from(name: &'static str) -> Self {
        Self::named(name)
    }
}

impl fmt::Display for NipId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) => write!(f, "{number:02}"),
            Self::Named(name) => f.write_str(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCapability {
    pub nip: NipId,
    pub name: &'static str,
    pub enabled_when: CapabilityCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityCondition {
    Always,
    AdminEnabled,
    AuthConfigured,
    CountEnabled,
    NegentropyEnabled,
    Nip59Safe,
    Nip62Enabled,
    Nip78Safe,
    Nip91Enabled,
    PowRequired,
    SearchEnabled,
}

impl CapabilityCondition {
    fn is_enabled(self, cfg: &Config) -> bool {
        match self {
            Self::Always => true,
            Self::AdminEnabled => cfg.admin.enabled && !cfg.admin.pubkeys.is_empty(),
            Self::AuthConfigured => cfg.auth_usable(),
            Self::CountEnabled => cfg.relay.max_filter_limit_count > 0,
            Self::NegentropyEnabled => cfg.relay.negentropy_enabled,
            // Recipients read their gift wraps, and nobody else does.
            Self::Nip59Safe => {
                let reads = cfg.read_restrictor();
                cfg.events.ephemeral_persistence == EphemeralPersistence::LiveOnly
                    && cfg.auth_usable()
                    && wok_event::GIFT_WRAP_KINDS
                        .iter()
                        .all(|&kind| reads.class(kind) == ReadClass::Recipient)
            }
            Self::Nip62Enabled => cfg.relay.nip62.enabled,
            // NIP-78: app data is served only to, and accepted only from, a
            // connection authenticated as its author.
            Self::Nip78Safe => {
                let reads = cfg.read_restrictor();
                cfg.auth_usable()
                    && wok_event::APP_DATA_KINDS
                        .iter()
                        .all(|&kind| reads.class(kind) == ReadClass::Owner)
            }
            Self::Nip91Enabled => {
                cfg.relay.max_tags_per_filter > 0 && cfg.relay.max_and_entries > 0
            }
            Self::PowRequired => cfg.relay.abuse.enabled && cfg.relay.abuse.min_pow_difficulty > 0,
            Self::SearchEnabled => cfg.relay.search_enabled,
        }
    }
}

/// The authoritative capability catalog for NIP-11, documentation, and tests.
pub const RELAY_CAPABILITY_CATALOG: &[RelayCapability] = &[
    RelayCapability {
        nip: NipId::Number(1),
        name: "Basic protocol",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: NipId::Number(9),
        name: "Event deletion",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: NipId::Number(11),
        name: "Relay information",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: NipId::Number(13),
        name: "Proof of work",
        enabled_when: CapabilityCondition::PowRequired,
    },
    RelayCapability {
        nip: NipId::Number(40),
        name: "Expiration",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: NipId::Number(42),
        name: "Authentication of clients to relays",
        enabled_when: CapabilityCondition::AuthConfigured,
    },
    RelayCapability {
        nip: NipId::Number(45),
        name: "Event counts",
        enabled_when: CapabilityCondition::CountEnabled,
    },
    RelayCapability {
        nip: NipId::Number(50),
        name: "Search capability",
        enabled_when: CapabilityCondition::SearchEnabled,
    },
    RelayCapability {
        nip: NipId::Number(59),
        name: "Gift wrap",
        enabled_when: CapabilityCondition::Nip59Safe,
    },
    RelayCapability {
        nip: NipId::Number(62),
        name: "Request to Vanish",
        enabled_when: CapabilityCondition::Nip62Enabled,
    },
    RelayCapability {
        nip: NipId::Number(67),
        name: "EOSE completeness hint",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: NipId::Number(70),
        name: "Protected events",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: NipId::Number(77),
        name: "Negentropy syncing",
        enabled_when: CapabilityCondition::NegentropyEnabled,
    },
    RelayCapability {
        nip: NipId::Number(78),
        name: "Arbitrary custom app data",
        enabled_when: CapabilityCondition::Nip78Safe,
    },
    RelayCapability {
        nip: NipId::Number(86),
        name: "Relay management API",
        enabled_when: CapabilityCondition::AdminEnabled,
    },
    RelayCapability {
        nip: NipId::Number(91),
        name: "AND operator in filters",
        enabled_when: CapabilityCondition::Nip91Enabled,
    },
    RelayCapability {
        nip: NipId::named(wok_event::DELETION_PROTECTION_NIP),
        name: "Deletion Request Protection",
        enabled_when: CapabilityCondition::Always,
    },
];

pub fn relay_capabilities(cfg: &Config) -> Vec<RelayCapability> {
    RELAY_CAPABILITY_CATALOG
        .iter()
        .filter(|capability| capability.enabled_when.is_enabled(cfg))
        .cloned()
        .collect()
}

pub fn supported_nips(cfg: &Config) -> Vec<NipId> {
    relay_capabilities(cfg)
        .into_iter()
        .map(|capability| capability.nip)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nip_identifiers_preserve_integer_and_named_forms() {
        let document = json!([90, "5A", 217, "D9"]);
        let nips: Vec<NipId> = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(
            nips.iter()
                .cloned()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4
        );
        assert_eq!(serde_json::to_value(nips).unwrap(), document);
    }

    #[test]
    fn catalog_is_sorted_and_unique() {
        assert!(RELAY_CAPABILITY_CATALOG
            .windows(2)
            .all(|pair| pair[0].nip < pair[1].nip));
    }

    #[test]
    fn conditional_capabilities_follow_runtime_configuration() {
        let mut cfg = Config::default();
        assert_eq!(
            serde_json::to_value(supported_nips(&cfg)).unwrap(),
            json!([1, 9, 11, 40, 45, 50, 62, 67, 70, 77, 91, "D9"])
        );

        cfg.relay.auth.service_url = "wss://relay.example.com/".into();
        cfg.relay.max_filter_limit_count = 0;
        cfg.relay.negentropy_enabled = false;
        cfg.events.ephemeral_persistence = EphemeralPersistence::Ttl;
        assert_eq!(
            serde_json::to_value(supported_nips(&cfg)).unwrap(),
            json!([1, 9, 11, 40, 42, 50, 62, 67, 70, 78, 91, "D9"])
        );

        cfg.relay.abuse.min_pow_difficulty = 20;
        assert_eq!(
            serde_json::to_value(supported_nips(&cfg)).unwrap(),
            json!([1, 9, 11, 13, 40, 42, 50, 62, 67, 70, 78, 91, "D9"])
        );

        cfg.relay.max_and_entries = 0;
        assert!(!supported_nips(&cfg).contains(&NipId::Number(91)));

        cfg.relay.search_enabled = false;
        assert!(!supported_nips(&cfg).contains(&NipId::Number(50)));
    }

    #[test]
    fn nip86_requires_enabled_admin_with_pubkeys() {
        let mut cfg = Config::default();
        assert!(!supported_nips(&cfg).contains(&NipId::Number(86)));
        cfg.admin.enabled = true;
        assert!(!supported_nips(&cfg).contains(&NipId::Number(86)));
        cfg.admin.pubkeys = vec!["ab".repeat(32)];
        assert!(supported_nips(&cfg).contains(&NipId::Number(86)));
    }

    #[test]
    fn nip59_requires_every_private_gift_wrap_safeguard() {
        let mut cfg = Config::default();
        cfg.relay.auth.service_url = "wss://relay.example.com/".into();
        assert!(supported_nips(&cfg).contains(&NipId::Number(59)));

        for wrap in [1059, 21059] {
            let auth = &mut cfg.relay.auth;
            auth.recipient_only_kinds.retain(|kind| *kind != wrap);
            assert!(
                !supported_nips(&cfg).contains(&NipId::Number(59)),
                "kind {wrap}"
            );
            // Readable after any AUTH is not recipient-only.
            cfg.relay.auth.authenticated_kinds.push(wrap);
            assert!(
                !supported_nips(&cfg).contains(&NipId::Number(59)),
                "kind {wrap}"
            );
            // In both classes, the stricter recipient-only applies.
            cfg.relay.auth.recipient_only_kinds.push(wrap);
            assert!(
                supported_nips(&cfg).contains(&NipId::Number(59)),
                "kind {wrap}"
            );
            // Owner-only is stricter still, and hides wraps from recipients.
            cfg.relay.auth.owner_only_kinds.push(wrap);
            assert!(
                !supported_nips(&cfg).contains(&NipId::Number(59)),
                "kind {wrap}"
            );
            cfg.relay.auth.owner_only_kinds.retain(|kind| *kind != wrap);
            cfg.relay.auth.authenticated_kinds.clear();
            assert!(
                supported_nips(&cfg).contains(&NipId::Number(59)),
                "kind {wrap}"
            );
        }

        cfg.relay.auth.enabled = false;
        assert!(!supported_nips(&cfg).contains(&NipId::Number(59)));
    }

    #[test]
    fn nip78_requires_owner_only_app_data_and_usable_auth() {
        let mut cfg = Config::default();
        assert!(!supported_nips(&cfg).contains(&NipId::Number(78)));
        cfg.relay.auth.service_url = "wss://relay.example.com/".into();
        assert!(supported_nips(&cfg).contains(&NipId::Number(78)));
        for kind in wok_event::APP_DATA_KINDS {
            cfg.relay.auth.owner_only_kinds.retain(|k| *k != kind);
            cfg.relay.auth.recipient_only_kinds.push(kind);
            assert!(
                !supported_nips(&cfg).contains(&NipId::Number(78)),
                "kind {kind}"
            );
            cfg.relay.auth.owner_only_kinds.push(kind);
            assert!(
                supported_nips(&cfg).contains(&NipId::Number(78)),
                "kind {kind}"
            );
        }
        cfg.relay.auth.enabled = false;
        assert!(!supported_nips(&cfg).contains(&NipId::Number(78)));
    }
}
