//! The dashboard's posture card and Access panel: what the relay's access
//! settings mean, in sentences.

use wok_relay::restrict::ReadClass;
use wok_relay::{AccessPolicy, Config};

/// What the default restricted kinds are, for the Access panel.
fn kind_name(kind: u64) -> Option<&'static str> {
    Some(match kind {
        4 => "NIP-04 direct messages",
        1059 => "NIP-59 gift wraps",
        21059 => "ephemeral gift wraps",
        78 => "NIP-78 app data",
        30078 => "NIP-78 addressable app data",
        _ => return None,
    })
}

/// `[4, 1059]` as "kinds 4 and 1059".
fn kinds(kinds: &[u64]) -> String {
    let names: Vec<String> = kinds.iter().map(u64::to_string).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => format!("kind {one}"),
        [rest @ .., last] => format!("kinds {} and {last}", rest.join(", ")),
    }
}

/// The kinds of `list` that read class `class` governs: a kind also listed
/// in a stricter class takes that one.
fn effective(cfg: &Config, list: &[u64], class: ReadClass) -> Vec<u64> {
    let restrictor = cfg.read_restrictor();
    let mut kinds: Vec<u64> = list
        .iter()
        .copied()
        .filter(|&kind| restrictor.class(kind) == class)
        .collect();
    kinds.dedup();
    kinds
}

/// Who a policy admits, as the subject of a sentence.
fn who(policy: AccessPolicy) -> &'static str {
    match policy {
        AccessPolicy::Open => "Anyone",
        AccessPolicy::Authenticated => "Only logged-in users",
        AccessPolicy::Members => "Only members",
    }
}

/// A few sentences on what the relay lets clients do.
pub(super) fn posture(cfg: &Config) -> Vec<String> {
    let auth = &cfg.relay.auth;
    let mut sentences = Vec::new();

    let mut access = if auth.read_policy == auth.write_policy {
        format!("{} can read and write", who(auth.read_policy))
    } else {
        format!(
            "{} can read; {} can write",
            who(auth.read_policy),
            who(auth.write_policy).to_lowercase()
        )
    };
    if auth.write_policy == AccessPolicy::Members && !auth.inbox_kinds.is_empty() {
        access.push_str(&format!(
            ", and anyone can deliver {} to a member",
            kinds(&auth.inbox_kinds)
        ));
    }
    access.push('.');
    if let Some(accepted) = cfg.accepted_kind_list() {
        access.push_str(&format!(
            " It accepts only {}; other kinds are refused.",
            kinds(&accepted)
        ));
    }
    sentences.push(access);

    // Each kind under the class that governs it, the strictest it is in.
    let recipient = effective(cfg, &auth.recipient_only_kinds, ReadClass::Recipient);
    let owner = effective(cfg, &auth.owner_only_kinds, ReadClass::Owner);
    let authenticated = effective(cfg, &auth.authenticated_kinds, ReadClass::Authenticated);
    let mut reads = Vec::new();
    if !recipient.is_empty() {
        reads.push(format!(
            "{} only to their author and recipient",
            kinds(&recipient)
        ));
    }
    if !owner.is_empty() {
        reads.push(format!("{} only to their author", kinds(&owner)));
    }
    if !authenticated.is_empty() {
        reads.push(format!("{} to any logged-in user", kinds(&authenticated)));
    }
    if !reads.is_empty() {
        let mut sentence = format!("It shows {}", reads.join("; "));
        sentence.push_str(if cfg.auth_usable() {
            ", once they log in."
        } else if !auth.enabled {
            ". Nobody can log in while relay.auth.enabled is false, so nobody can read them."
        } else {
            ". Nobody can log in until relay.auth.service_url is set, so nobody can read them."
        });
        sentences.push(sentence);
    }
    // NIP-78: an owner-only kind is published only by its author, too.
    if !owner.is_empty() {
        sentences.push(if cfg.auth_usable() {
            format!(
                "It accepts {} only from a connection logged in as their author.",
                kinds(&owner)
            )
        } else {
            format!(
                "It refuses {}, which only a connection logged in as their author may publish.",
                kinds(&owner)
            )
        });
    }
    if cfg.relay.filter_validation.require_scoped_filters {
        sentences.push("Every query must name ids, authors or a tag.".into());
    }

    let abuse = &cfg.relay.abuse;
    sentences.push(if abuse.enabled {
        // Zero in a rate or a burst turns its bucket off.
        let own = &abuse.per_connection;
        let connection = if own.req_rate_per_second == 0 || own.req_burst == 0 {
            "Each connection's query budget is off".to_string()
        } else {
            format!(
                "Each connection can open {} queries a second, {} at once, {}× that after login",
                own.req_rate_per_second, own.req_burst, own.authenticated_multiplier
            )
        };
        let address = if abuse.req_rate_per_second == 0 || abuse.req_burst == 0 {
            "the per-address backstop is off".to_string()
        } else {
            format!(
                "all the connections from one address share {} a second",
                abuse.req_rate_per_second
            )
        };
        format!("{connection}; {address}.")
    } else {
        "Rate limits, storage quotas, the query work ceiling and proof of work are off.".into()
    });
    sentences
}

/// The access settings, read-only on the dashboard: each policy and read
/// class with what it means, and what NIP-11 says of them.
pub(super) fn access(cfg: &Config) -> serde_json::Value {
    let auth = &cfg.relay.auth;
    // A kind listed in a stricter class too is named here with the list
    // that governs it.
    let restrictor = cfg.read_restrictor();
    let named = |list: &[u64], class: Option<ReadClass>| -> Vec<serde_json::Value> {
        list.iter()
            .map(|&kind| {
                let stricter = class
                    .filter(|&class| restrictor.class(kind) != class)
                    .map(|_| match restrictor.class(kind) {
                        ReadClass::Owner => "owner_only_kinds",
                        _ => "recipient_only_kinds",
                    });
                serde_json::json!({"kind": kind, "name": kind_name(kind), "stricter": stricter})
            })
            .collect()
    };
    const MEMBER: &str = "A member is a pubkey allowlisted or given a role with NIP-86, or \
                          one of admin.pubkeys, that is not banned.";
    let read_means = match auth.read_policy {
        AccessPolicy::Open => "Anyone may read.".to_string(),
        AccessPolicy::Authenticated => "A connection must log in (NIP-42 AUTH) to read.".into(),
        AccessPolicy::Members => format!("A connection must log in as a member to read. {MEMBER}"),
    };
    let write_means = match auth.write_policy {
        AccessPolicy::Open => "Anyone may write.".to_string(),
        AccessPolicy::Authenticated => {
            "A connection must log in (NIP-42 AUTH) to write; the event may be signed by any key."
                .into()
        }
        AccessPolicy::Members => format!(
            "An event is accepted when a member signed it, from any connection; when its \
             connection logged in as a member, whatever key signed it; or, for the inbox kinds, \
             when its first p tag is a member. {MEMBER}"
        ),
    };
    serde_json::json!({
        "read_policy": auth.read_policy.name(),
        "read_policy_means": read_means,
        "write_policy": auth.write_policy.name(),
        "write_policy_means": write_means,
        "recipient_only_kinds": named(&auth.recipient_only_kinds, Some(ReadClass::Recipient)),
        "owner_only_kinds": named(&auth.owner_only_kinds, Some(ReadClass::Owner)),
        "authenticated_kinds": named(&auth.authenticated_kinds, Some(ReadClass::Authenticated)),
        "inbox_kinds": named(&auth.inbox_kinds, None),
        "accepted_kinds": cfg.accepted_kind_list(),
        "auth_enabled": auth.enabled,
        "service_url": auth.service_url,
        "auth_usable": cfg.auth_usable(),
        "auth_required": cfg.auth_required(),
        "restricted_writes": cfg.restricted_writes(),
        "warning": cfg.auth_configuration_warning(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(name: &str, extra: &str) -> Config {
        Config::parse_toml(&format!("preset = \"{name}\"\n{extra}")).unwrap()
    }

    #[test]
    fn the_public_preset_is_open_with_private_inboxes() {
        let cfg = preset(
            "public",
            "[relay.auth]\nservice_url = \"wss://relay.test\"\n",
        );
        assert_eq!(
            posture(&cfg),
            [
                "Anyone can read and write.",
                "It shows kinds 4, 1059 and 21059 only to their author and recipient; kinds 78 \
                 and 30078 only to their author, once they log in.",
                "It accepts kinds 78 and 30078 only from a connection logged in as their author.",
                "Each connection can open 20 queries a second, 100 at once, 4× that after login; \
                 all the connections from one address share 200 a second.",
            ]
        );
        // Without a service URL nobody can log in to read them, and with AUTH
        // off neither can anybody, whatever the URL.
        assert!(posture(&preset("public", ""))[1]
            .ends_with("until relay.auth.service_url is set, so nobody can read them."));
        let off = preset(
            "public",
            "[relay.auth]\nenabled = false\nservice_url = \"wss://relay.test\"\n",
        );
        assert!(posture(&off)[1]
            .ends_with("while relay.auth.enabled is false, so nobody can read them."));
        // Zero in a rate or a burst turns its budget off, not down.
        let zeroed = preset(
            "public",
            "[relay.abuse]\nreq_burst = 0\n\n[relay.abuse.per_connection]\nreq_rate_per_second = 0\n",
        );
        assert_eq!(
            posture(&zeroed)[3],
            "Each connection's query budget is off; the per-address backstop is off."
        );
    }

    #[test]
    fn the_marmot_preset_names_its_kinds_and_scoped_filters() {
        let cfg = preset(
            "marmot",
            "[relay.auth]\nservice_url = \"wss://relay.test\"\n",
        );
        let sentences = posture(&cfg);
        assert_eq!(
            sentences[0],
            "Anyone can read and write. It accepts only kinds 0, 3, 5, 62, 445, 1059, 10000, \
             10002, 10050 and 30443; other kinds are refused."
        );
        assert_eq!(sentences[3], "Every query must name ids, authors or a tag.");
        assert!(
            sentences[4].starts_with("Each connection can open 50 queries a second, 300 at once")
        );
    }

    #[test]
    fn a_kind_in_several_read_classes_is_described_by_the_strictest() {
        // 30078 stays owner-only, and 4 recipient-only, wherever else they
        // are listed.
        let cfg = preset(
            "public",
            "[relay.auth]\nservice_url = \"wss://relay.test\"\n\
             recipient_only_kinds = [4, 30078]\nauthenticated_kinds = [4, 30078, 30000]\n",
        );
        assert_eq!(
            posture(&cfg)[1],
            "It shows kind 4 only to their author and recipient; kinds 78 and 30078 only to \
             their author; kind 30000 to any logged-in user, once they log in."
        );
        let access = access(&cfg);
        let stricter = |list: &str, kind: u64| {
            access[list]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["kind"] == kind)
                .unwrap()["stricter"]
                .clone()
        };
        assert_eq!(stricter("authenticated_kinds", 30078), "owner_only_kinds");
        assert_eq!(stricter("authenticated_kinds", 4), "recipient_only_kinds");
        assert_eq!(stricter("recipient_only_kinds", 30078), "owner_only_kinds");
        assert_eq!(
            stricter("authenticated_kinds", 30000),
            serde_json::Value::Null
        );
        assert_eq!(stricter("owner_only_kinds", 30078), serde_json::Value::Null);
    }

    #[test]
    fn policies_and_inbox_kinds_are_described() {
        let cfg = preset(
            "public",
            "[relay.auth]\nservice_url = \"wss://relay.test\"\nread_policy = \"authenticated\"\n\
             write_policy = \"members\"\nrecipient_only_kinds = [4]\nowner_only_kinds = []\n\n\
             [relay.abuse]\nenabled = false\n",
        );
        assert_eq!(
            posture(&cfg),
            [
                "Only logged-in users can read; only members can write, and anyone can deliver \
                 kinds 1059 and 21059 to a member.",
                "It shows kind 4 only to their author and recipient, once they log in.",
                "Rate limits, storage quotas, the query work ceiling and proof of work are off.",
            ]
        );
        let access = access(&cfg);
        assert_eq!(access["read_policy"], "authenticated");
        assert!(access["read_policy_means"]
            .as_str()
            .unwrap()
            .starts_with("A connection must log in (NIP-42 AUTH) to read."));
        // A member's own events, and inbox kinds addressed to a member, need
        // no login.
        let writes = access["write_policy_means"].as_str().unwrap();
        assert!(
            writes.contains("when a member signed it, from any connection"),
            "{writes}"
        );
        assert!(
            writes.contains("when its first p tag is a member"),
            "{writes}"
        );
        assert_eq!(
            access["recipient_only_kinds"][0]["name"],
            "NIP-04 direct messages"
        );
        assert_eq!(access["accepted_kinds"], serde_json::Value::Null);
        assert_eq!(access["auth_required"], true);
    }
}
