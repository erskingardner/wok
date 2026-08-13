//! Relay-owned NIP capabilities advertised through NIP-11.
//!
//! Event kinds that Wok can store are not capabilities by themselves. This
//! catalog only contains NIPs for which the relay implements observable
//! protocol or storage behavior.

use crate::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayCapability {
    pub nip: u64,
    pub name: &'static str,
    pub enabled_when: CapabilityCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityCondition {
    Always,
    AuthConfigured,
    CountEnabled,
    NegentropyEnabled,
}

impl CapabilityCondition {
    fn is_enabled(self, cfg: &Config) -> bool {
        match self {
            Self::Always => true,
            Self::AuthConfigured => {
                cfg.relay.auth.enabled && !cfg.relay.auth.service_url.is_empty()
            }
            Self::CountEnabled => cfg.relay.max_filter_limit_count > 0,
            Self::NegentropyEnabled => cfg.relay.negentropy_enabled,
        }
    }
}

/// The authoritative capability catalog for NIP-11, documentation, and tests.
pub const RELAY_CAPABILITY_CATALOG: &[RelayCapability] = &[
    RelayCapability {
        nip: 1,
        name: "Basic protocol",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: 9,
        name: "Event deletion",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: 11,
        name: "Relay information",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: 40,
        name: "Expiration",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: 42,
        name: "Authentication of clients to relays",
        enabled_when: CapabilityCondition::AuthConfigured,
    },
    RelayCapability {
        nip: 45,
        name: "Event counts",
        enabled_when: CapabilityCondition::CountEnabled,
    },
    RelayCapability {
        nip: 59,
        name: "Gift wrap",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: 70,
        name: "Protected events",
        enabled_when: CapabilityCondition::Always,
    },
    RelayCapability {
        nip: 77,
        name: "Negentropy syncing",
        enabled_when: CapabilityCondition::NegentropyEnabled,
    },
];

pub fn relay_capabilities(cfg: &Config) -> Vec<RelayCapability> {
    RELAY_CAPABILITY_CATALOG
        .iter()
        .copied()
        .filter(|capability| capability.enabled_when.is_enabled(cfg))
        .collect()
}

pub fn supported_nips(cfg: &Config) -> Vec<u64> {
    relay_capabilities(cfg)
        .into_iter()
        .map(|capability| capability.nip)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_sorted_and_unique() {
        assert!(RELAY_CAPABILITY_CATALOG
            .windows(2)
            .all(|pair| pair[0].nip < pair[1].nip));
    }

    #[test]
    fn conditional_capabilities_follow_runtime_configuration() {
        let mut cfg = Config::default();
        assert_eq!(supported_nips(&cfg), vec![1, 9, 11, 40, 45, 59, 70, 77]);

        cfg.relay.auth.service_url = "wss://relay.example.com/".into();
        cfg.relay.max_filter_limit_count = 0;
        cfg.relay.negentropy_enabled = false;
        assert_eq!(supported_nips(&cfg), vec![1, 9, 11, 40, 42, 59, 70]);
    }
}
