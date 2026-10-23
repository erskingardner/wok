//! The dashboard's posture card and Access panel: what the relay's access
//! settings mean, in sentences.

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

    let mut reads = Vec::new();
    if !auth.recipient_only_kinds.is_empty() {
        reads.push(format!(
            "{} only to their author and recipient",
            kinds(&auth.recipient_only_kinds)
        ));
    }
    if !auth.owner_only_kinds.is_empty() {
        reads.push(format!(
            "{} only to their author",
            kinds(&auth.owner_only_kinds)
        ));
    }
    if !auth.authenticated_kinds.is_empty() {
        reads.push(format!(
            "{} to any logged-in user",
            kinds(&auth.authenticated_kinds)
        ));
    }
    if !reads.is_empty() {
        let mut sentence = format!("It shows {}", reads.join("; "));
        sentence.push_str(if cfg.auth_usable() {
            ", once they log in."
        } else {
            ". Nobody can log in until relay.auth.service_url is set, so nobody can read them."
        });
        sentences.push(sentence);
    }
    if cfg.relay.filter_validation.require_scoped_filters {
        sentences.push("Every query must name ids, authors or a tag.".into());
    }

    let abuse = &cfg.relay.abuse;
    sentences.push(if abuse.enabled {
        let own = &abuse.per_connection;
        format!(
            "Each connection can open {} queries a second, {} at once, {}× that after login; \
             all the connections from one address share {} a second.",
            own.req_rate_per_second,
            own.req_burst,
            own.authenticated_multiplier,
            abuse.req_rate_per_second
        )
    } else {
        "Rate limits, storage quotas, the query work ceiling and proof of work are off.".into()
    });
    sentences
}

/// The access settings, read-only on the dashboard: each policy and read
/// class with what it means, and what NIP-11 says of them.
pub(super) fn access(cfg: &Config) -> serde_json::Value {
    let auth = &cfg.relay.auth;
    let named = |list: &[u64]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|&kind| serde_json::json!({"kind": kind, "name": kind_name(kind)}))
            .collect()
    };
    let policy = |policy: AccessPolicy, verb: &str| match policy {
        AccessPolicy::Open => format!("Anyone may {verb}."),
        AccessPolicy::Authenticated => format!("A connection must log in (NIP-42 AUTH) to {verb}."),
        AccessPolicy::Members => format!(
            "A connection must log in as a member to {verb}: a pubkey allowlisted or given a \
             role with NIP-86, or one of admin.pubkeys, that is not banned."
        ),
    };
    serde_json::json!({
        "read_policy": auth.read_policy.name(),
        "read_policy_means": policy(auth.read_policy, "read"),
        "write_policy": auth.write_policy.name(),
        "write_policy_means": policy(auth.write_policy, "write"),
        "recipient_only_kinds": named(&auth.recipient_only_kinds),
        "owner_only_kinds": named(&auth.owner_only_kinds),
        "authenticated_kinds": named(&auth.authenticated_kinds),
        "inbox_kinds": named(&auth.inbox_kinds),
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
                "Each connection can open 20 queries a second, 100 at once, 4× that after login; \
                 all the connections from one address share 200 a second.",
            ]
        );
        // Without a service URL nobody can log in to read them.
        assert!(posture(&preset("public", ""))[1].ends_with("so nobody can read them."));
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
        assert_eq!(sentences[2], "Every query must name ids, authors or a tag.");
        assert!(
            sentences[3].starts_with("Each connection can open 50 queries a second, 300 at once")
        );
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
        assert_eq!(
            access["recipient_only_kinds"][0]["name"],
            "NIP-04 direct messages"
        );
        assert_eq!(access["accepted_kinds"], serde_json::Value::Null);
        assert_eq!(access["auth_required"], true);
    }
}
