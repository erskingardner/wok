//! Setting combinations: each security setting below, alone and with every
//! other, turned on over the `public` profile and sent the golden transcript
//! script. Two rules hold:
//!
//! - a request one setting refuses stays refused whatever other setting is
//!   on with it, so no setting opens a gate another one closes;
//! - every setting changes some answer of the script, unless `UNPROBED` says
//!   why the script cannot see it, so a setting that does nothing is noticed.
//!
//! A combination Wok refuses to load is listed, not failed: refusing it is
//! the safe outcome.

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
        "relay.auth.recipient_only_kinds = [1, 4, 1059]",
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
    ("NIP-62 off", "relay.nip62.enabled = false"),
    ("proof of work", "relay.abuse.min_pow_difficulty = 8"),
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
    // An admin the script never signs as, so this opens the endpoints
    // without making the script's author a member.
    (
        "admin",
        r#"admin.enabled = true
admin.public_url = "https://relay.example.com"
admin.pubkeys = ["f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"]"#,
    ),
    ("metrics", "observability.metrics_enabled = true"),
    (
        "metrics listener",
        r#"observability.metrics_listen = "127.0.0.1:9777""#,
    ),
    ("marmot preset", r#"preset = "marmot""#),
];

/// Settings the script cannot see, and why.
const UNPROBED: &[(&str, &str)] = &[(
    "real_ip_header",
    "the script sends no proxy header; proxied_client_address.rs covers it",
)];

/// Pairs in which the first setting serves requests the second refuses
/// alone, by design, and why.
const OPENS: &[(&str, &str, &str)] = &[
    (
        "abuse limits off",
        "proof of work",
        "relay.abuse.enabled = false turns proof of work off with the other abuse \
         limits, as docs/config.md says, and NIP-11 then advertises 0",
    ),
    (
        "no recipient-only kinds",
        "AUTH off",
        "without AUTH, gift wraps are refused only because they are recipient-only",
    ),
];

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
    let answers: BTreeMap<Vec<usize>, Result<Steps, String>> = stream::iter(runs)
        .map(|run| async move {
            let toml: Vec<&str> = std::iter::once(BASE)
                .chain(run.iter().map(|&setting| SETTINGS[setting].1))
                .collect();
            let steps = answer(&toml.join("\n")).await;
            (run, steps)
        })
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    let base = answers[&vec![]]
        .as_ref()
        .expect("the base configuration loads");
    let name = |setting: usize| SETTINGS[setting].0;

    let mut problems = Vec::new();
    let listed = UNPROBED.iter().map(|(setting, _)| *setting).chain(
        OPENS
            .iter()
            .flat_map(|(opener, closer, _)| [*opener, *closer]),
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
            Ok(alone) if (alone == base) != unprobed => problems.push(if unprobed {
                format!(
                    "{} now changes the script's answers; take it out of UNPROBED",
                    name(setting)
                )
            } else {
                format!(
                    "{} changes none of the script's answers: give the script a step that \
                     shows it, or list it in UNPROBED with the reason",
                    name(setting)
                )
            }),
            Ok(_) => {}
        }
    }

    let mut refused_to_load = Vec::new();
    for (run, result) in &answers {
        let &[a, b] = &run[..] else { continue };
        let together = match result {
            Ok(together) => together,
            Err(error) => {
                refused_to_load.push(format!("{} + {}: {error}", name(a), name(b)));
                continue;
            }
        };
        for (closer, other) in [(a, b), (b, a)] {
            let Ok(alone) = &answers[&vec![closer]] else {
                continue;
            };
            for (step, reply) in alone {
                let closes = refused(reply) && base.get(step).is_some_and(|base| !refused(base));
                let Some(combined) = together.get(step) else {
                    continue;
                };
                if !closes || refused(combined) {
                    continue;
                }
                let by_design = OPENS
                    .iter()
                    .any(|(opener, closed, _)| *opener == name(other) && *closed == name(closer));
                if !by_design {
                    problems.push(format!(
                        "{} opens what {} closes: \"{step}\"\n  {} alone: {}  with {}: {}",
                        name(other),
                        name(closer),
                        name(closer),
                        reply.trim_end(),
                        name(other),
                        combined.trim_end(),
                    ));
                }
            }
        }
    }
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
async fn answer(toml: &str) -> Result<Steps, String> {
    let cfg = Config::parse_toml(toml)?;
    let relay = Relay::try_start(cfg.clone()).await?;
    let text = transcript::record("combination", &relay, &cfg).await;
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

/// Whether an answer refuses its step: an OK that is false, a CLOSED,
/// NEG-ERR or NOTICE, or an HTTP status of 400 or more.
fn refused(reply: &str) -> bool {
    reply.lines().any(|line| {
        let line = line.trim_start_matches("< ");
        (line.starts_with(r#"["OK""#) && line.contains(",false,"))
            || [r#"["CLOSED""#, r#"["NEG-ERR""#, r#"["NOTICE""#]
                .iter()
                .any(|verb| line.starts_with(verb))
            || line
                .split(' ')
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .is_some_and(|code| code >= 400)
    })
}

/// The dotted keys a setting sets.
fn keys(setting: &str) -> BTreeSet<&str> {
    setting
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .map(|(key, _)| key.trim())
        .collect()
}
