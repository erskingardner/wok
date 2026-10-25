//! Setting combinations: each security setting below, alone and with every
//! other, turned on over the `public` profile and sent the golden transcript
//! script. A reply refuses its step when it carries a refusal (an `OK` that is
//! false, a `CLOSED`, `NEG-ERR` or `NOTICE`, or an HTTP status of 400 or more)
//! and no data (no `EVENT`, `COUNT` or `NEG-MSG`). Three rules hold, unless
//! `OPENS` or `UNPROBED` gives the reason they should not:
//!
//! - a step one setting refuses for a reason of its own, where `public` serves
//!   it or refuses it differently, stays refused with any other setting on;
//! - a step two settings each refuse stays refused with both on;
//! - every setting changes some answer of the script other than what NIP-11
//!   advertises, so a setting that is advertised but not enforced, or does
//!   nothing, is noticed.
//!
//! A combination Wok refuses to load or start is printed, not failed:
//! refusing it is the safe outcome.

use futures_util::{stream, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use wok_relay::Config;

#[path = "support/surface.rs"]
mod surface;
#[path = "support/transcript.rs"]
mod transcript;
use surface::*;

/// The `public` profile, as dotted keys so that settings can follow it.
const BASE: &str = r#"relay.auth.service_url = "wss://relay.example.com""#;

/// Security settings, each as the dotted keys that turn it on.
const SETTINGS: &[(&str, &str)] = &[
    ("AUTH off", "relay.auth.enabled = false"),
    (
        "read_policy authenticated",
        r#"relay.auth.read_policy = "authenticated""#,
    ),
    (
        "read_policy members",
        r#"relay.auth.read_policy = "members""#,
    ),
    (
        "write_policy authenticated",
        r#"relay.auth.write_policy = "authenticated""#,
    ),
    (
        "write_policy members",
        r#"relay.auth.write_policy = "members""#,
    ),
    (
        "accepted_kinds without notes",
        "relay.auth.accepted_kinds = [0, 3]",
    ),
    (
        "notes recipient-only",
        // The default list plus notes: the list replaces the default.
        "relay.auth.recipient_only_kinds = [1, 4, 1059, 21059]",
    ),
    (
        "notes authenticated-only",
        "relay.auth.authenticated_kinds = [1]",
    ),
    ("no owner-only kinds", "relay.auth.owner_only_kinds = []"),
    (
        "no recipient-only kinds",
        "relay.auth.recipient_only_kinds = []",
    ),
    ("COUNT off", "relay.max_filter_limit_count = 0"),
    ("negentropy off", "relay.negentropy_enabled = false"),
    ("search off", "relay.search_enabled = false"),
    ("NIP-62 off", "relay.nip62.enabled = false"),
    // High enough that no note of the script meets it by chance.
    ("proof of work", "relay.abuse.min_pow_difficulty = 24"),
    ("abuse limits off", "relay.abuse.enabled = false"),
    (
        "scoped filters",
        "relay.filter_validation.require_scoped_filters = true",
    ),
    (
        "author or tag",
        "relay.filter_validation.require_author_or_tag = true",
    ),
    (
        "real_ip_header",
        r#"relay.real_ip_header = "X-Forwarded-For""#,
    ),
    (
        "trusted_proxies",
        r#"relay.trusted_proxies = ["127.0.0.1", "::1"]"#,
    ),
    // An admin the script never signs as, so this opens the endpoints
    // without making the script's author a member.
    (
        "admin",
        r#"admin.enabled = true
admin.public_url = "https://relay.example.com"
admin.pubkeys = ["f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"]"#,
    ),
    ("metrics", "observability.metrics_enabled = true"),
    ("NodeInfo", "relay.nodeinfo_enabled = true"),
    (
        "metrics listener",
        r#"observability.metrics_listen = "127.0.0.1:9777""#,
    ),
    ("marmot preset", r#"preset = "marmot""#),
];

/// Settings the script cannot see, and why.
const UNPROBED: &[(&str, &str)] = &[
    (
        "real_ip_header",
        "the script sends no proxy header; proxied_client_address.rs covers it",
    ),
    (
        "trusted_proxies",
        "the script sends no proxy header; proxied_client_address.rs covers it",
    ),
    (
        "abuse limits off",
        "the script stays under every budget and quota; rate_keying.rs covers them, \
         and OPENS records that it turns proof of work off",
    ),
];

/// Steps the first setting serves, with the second on, that the second
/// refuses alone or with a reason of its own, by design, and why.
const OPENS: &[(&str, &str, &[&str], &str)] = &[
    (
        "abuse limits off",
        "proof of work",
        &[
            "EVENT a note",
            "EVENT the same note again",
            "EVENT a note from another key",
            "EVENT a gift wrap to the author",
        ],
        "relay.abuse.enabled = false turns proof of work off with the other abuse \
         limits, as docs/config.md says, and NIP-11 then advertises 0",
    ),
    (
        "no recipient-only kinds",
        "AUTH off",
        &[
            "EVENT a gift wrap to the author",
            "REQ only gift wraps",
            "REQ only gift wraps, after AUTH",
        ],
        "without AUTH, gift wraps are refused, to write and to read, only because they \
         are recipient-only",
    ),
    (
        "no owner-only kinds",
        "AUTH off",
        &["EVENT owner-only app data"],
        "without AUTH, kind 30078 is refused only because it is owner-only",
    ),
    (
        "metrics",
        "metrics listener",
        &["HTTP GET /metrics on the metrics listener"],
        "observability.metrics_enabled is what serves /metrics, on the listener \
         metrics_listen names",
    ),
];

/// Steps that only advertise what the relay does. A setting that changes
/// nothing else is not enforced, whatever NIP-11 says.
const ADVERTISED: &[&str] = &["HTTP GET / for NIP-11"];

/// How many relays run the script at once.
const PARALLEL: usize = 4;

/// What the relay answered each step of the script, by step.
type Steps = BTreeMap<String, String>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_setting_shows_and_none_opens_what_another_closes() {
    let mut runs: Vec<Vec<usize>> = vec![vec![]];
    runs.extend((0..SETTINGS.len()).map(|a| vec![a]));
    for (a, (_, first)) in SETTINGS.iter().enumerate() {
        for (b, (_, second)) in SETTINGS.iter().enumerate().skip(a + 1) {
            // Two settings of one key are one setting, not a combination.
            if keys(first).is_disjoint(&keys(second)) {
                runs.push(vec![a, b]);
            }
        }
    }
    // One date for every run, so they all send the same events.
    let base = now() - 1_000;
    let answers: BTreeMap<Vec<usize>, Result<Steps, String>> = stream::iter(runs)
        .map(|run| async move {
            let toml: Vec<&str> = std::iter::once(BASE)
                .chain(run.iter().map(|&setting| SETTINGS[setting].1))
                .collect();
            let steps = answer(&toml.join("\n"), base).await;
            (run, steps)
        })
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    let base = answers[&vec![]]
        .as_ref()
        .expect("the base configuration loads");
    let effects = |steps: &Steps| -> Steps {
        steps
            .iter()
            .filter(|(step, _)| !ADVERTISED.contains(&step.as_str()))
            .map(|(step, reply)| (step.clone(), reply.clone()))
            .collect()
    };
    let name = |setting: usize| SETTINGS[setting].0;

    let mut problems = Vec::new();
    let listed = UNPROBED.iter().map(|(setting, _)| *setting).chain(
        OPENS
            .iter()
            .flat_map(|(opener, closer, ..)| [*opener, *closer]),
    );
    for listed in listed {
        if !SETTINGS.iter().any(|(setting, _)| *setting == listed) {
            problems.push(format!("{listed} is listed but is not a setting"));
        }
    }
    for setting in 0..SETTINGS.len() {
        let unprobed = UNPROBED.iter().any(|(listed, _)| *listed == name(setting));
        match &answers[&vec![setting]] {
            Err(error) => problems.push(format!("Wok refuses {}: {error}", name(setting))),
            Ok(alone) if (effects(alone) == effects(base)) != unprobed => {
                problems.push(if unprobed {
                    format!(
                        "{} now changes the script's answers; take it out of UNPROBED",
                        name(setting)
                    )
                } else {
                    format!(
                        "{} changes none of the script's answers beyond what NIP-11 advertises: \
                     give the script a step that shows it, or list it in UNPROBED with the reason",
                        name(setting)
                    )
                })
            }
            Ok(_) => {}
        }
    }

    let mut refused_to_load = Vec::new();
    let mut opened = BTreeSet::new();
    for (run, result) in &answers {
        let &[a, b] = &run[..] else { continue };
        let together = match result {
            Ok(together) => together,
            Err(error) => {
                refused_to_load.push(format!("{} + {}: {error}", name(a), name(b)));
                continue;
            }
        };
        let (Ok(first), Ok(second)) = (&answers[&vec![a]], &answers[&vec![b]]) else {
            continue;
        };
        for (step, combined) in together {
            if refused(combined) {
                continue;
            }
            let by_design = |opener: usize, closer: usize| {
                OPENS
                    .iter()
                    .any(|(listed_opener, listed_closer, steps, _)| {
                        *listed_opener == name(opener)
                            && *listed_closer == name(closer)
                            && steps.contains(&step.as_str())
                    })
            };
            for (closer, alone, opener) in [(a, first, b), (b, second, a)] {
                if alone
                    .get(step)
                    .is_some_and(|reply| closes(reply, base.get(step)))
                    && !by_design(opener, closer)
                {
                    opened.insert(format!(
                        "{} opens what {} closes: \"{step}\"\n  {} alone: {}  with {}: {}",
                        name(opener),
                        name(closer),
                        name(closer),
                        alone[step].trim_end(),
                        name(opener),
                        combined.trim_end(),
                    ));
                }
            }
            let each_refuses = [first, second]
                .iter()
                .all(|alone| alone.get(step).is_some_and(|reply| refused(reply)));
            if each_refuses && !by_design(a, b) && !by_design(b, a) {
                opened.insert(format!(
                    "{} and {} each refuse \"{step}\" but serve it together: {}",
                    name(a),
                    name(b),
                    combined.trim_end(),
                ));
            }
        }
    }
    problems.extend(opened);
    eprintln!(
        "{} settings, {} combinations; Wok refuses to load {}:\n  {}",
        SETTINGS.len(),
        answers.len() - 1 - SETTINGS.len(),
        refused_to_load.len(),
        refused_to_load.join("\n  ")
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Start a relay of `toml`, send it the script, and return its answers.
async fn answer(toml: &str, base: u64) -> Result<Steps, String> {
    let cfg = Config::parse_toml(toml)?;
    let relay = Relay::try_start(cfg.clone()).await?;
    let text = transcript::record_at("combination", &relay, &cfg, base).await;
    relay.stop().await;
    let mut steps = Steps::new();
    let mut step = None;
    for line in text.lines().filter(|line| !line.is_empty()) {
        if let Some(label) = line.strip_prefix("## ") {
            step = Some(label.to_string());
        } else if let Some(step) = &step {
            let reply = steps.entry(step.clone()).or_default();
            reply.push_str(line);
            reply.push('\n');
        }
    }
    Ok(steps)
}

/// Whether a reply refuses its step: it carries a refusal and no data.
fn refused(reply: &str) -> bool {
    let lines = || reply.lines().map(|line| line.trim_start_matches("< "));
    let refusal = lines().any(|line| {
        (line.starts_with(r#"["OK""#) && line.contains(",false,"))
            || [r#"["CLOSED""#, r#"["NEG-ERR""#, r#"["NOTICE""#]
                .iter()
                .any(|verb| line.starts_with(verb))
            || line
                .split(' ')
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .is_some_and(|code| code >= 400)
    });
    let data = lines().any(|line| {
        [r#"["EVENT""#, r#"["COUNT""#, r#"["NEG-MSG""#]
            .iter()
            .any(|verb| line.starts_with(verb))
    });
    refusal && !data
}

/// Whether a setting's reply refuses a step for a reason of its own: the
/// `public` profile serves the step, does not have it, or refuses it with
/// another reply. Ids are numbered by first appearance, so a setting that
/// changes an earlier step can renumber this one; numbers are ignored.
fn closes(reply: &str, base: Option<&String>) -> bool {
    let unnumbered = |reply: &str| {
        let mut out = String::new();
        let mut rest = reply;
        while let Some(at) = rest.find("<h") {
            out.push_str(&rest[..at]);
            rest = &rest[at + 2..];
            rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
            out.push_str("<h");
        }
        out + rest
    };
    refused(reply)
        && base.is_none_or(|base| !refused(base) || unnumbered(base) != unnumbered(reply))
}

/// The dotted keys a setting sets.
fn keys(setting: &str) -> BTreeSet<&str> {
    setting
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .map(|(key, _)| key.trim())
        .collect()
}
