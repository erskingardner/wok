//! Keys that earlier releases read and later ones replaced. A file that still
//! sets one is translated as it loads, with a deprecation warning, so it keeps
//! the behavior it had; `wok config minimize` and dashboard saves write the
//! translation back to the file.

use super::provenance::leaf;

/// Through 0.7, `[relay.filter_validation]` applied its rules only with
/// `enabled = true`, and had its own filter-count limits besides
/// `relay.max_filters_per_req` (#97 F3). Now each rule applies when it is set.
const FILTER_VALIDATION: [&str; 2] = ["relay", "filter_validation"];

/// The rules of a section that kept them, as 0.7 and strfry defaulted them
/// when an enabled section left them out.
pub(super) const LEGACY_MAX_FILTERS_PER_REQ: u64 = 3;
pub(super) const LEGACY_MAX_KINDS_PER_FILTER: u64 = 3;

/// The warning for a zero kind cap in a section that applied it. Through 0.7
/// it refused every filter that listed kinds; 0 now means no limit, which the
/// owner chose over refusing to load (#97).
pub(super) fn zero_kind_cap_warning(key: &str) -> String {
    format!(
        "{key} = 0 in an enabled section refused every filter that lists kinds through 0.7. \
         0 now means no limit, so such filters are accepted; to restrict the kinds a filter \
         may list, set relay.filter_validation.allowed_kinds."
    )
}

/// Through 0.7, `relay.abuse.max_query_cost` capped an estimate that ignored
/// `limit` and the query plan. `max_query_work` replaced it, counting the
/// index entries a request touches (#97 §3.4). Its values mean something
/// else in those units (1,000 would refuse every filter without a `limit`),
/// so an old value is ignored rather than carried over.
const QUERY_COST: [&str; 3] = ["relay", "abuse", "max_query_cost"];

/// Through 0.7, `relay.auth.restricted_read_kinds` limited reads of its kinds
/// to the author and first `p`-tag recipient, unless
/// `restrict_read_to_involved_pubkey = false` let any authenticated
/// connection read them, and any REQ that mixed in another kind read them
/// without AUTH. Read classes replaced both (#97 §3.6). Likewise
/// `restrict_writes = true` accepted only events whose author was a member;
/// `write_policy = "members"` replaced it.
const AUTH: [&str; 2] = ["relay", "auth"];

/// The rules that remain, each off at its zero or empty value.
const RULES: [&str; 4] = [
    "max_kinds_per_filter",
    "allowed_kinds",
    "require_author_or_tag",
    "require_scoped_filters",
];

/// One change to the operator's file.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Change {
    Remove(Vec<&'static str>),
    Set(Vec<&'static str>, toml::Value),
}

impl Change {
    pub(super) fn path(&self) -> &[&'static str] {
        match self {
            Change::Remove(path) | Change::Set(path, _) => path,
        }
    }
}

/// How a file's deprecated keys translate.
#[derive(Debug, Clone, Default)]
pub(super) struct Translation {
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
    /// Each key the translation sets, with the deprecated key it comes from,
    /// so the file's line for it can still be found.
    pub sources: Vec<(Vec<&'static str>, Vec<&'static str>)>,
}

impl Translation {
    /// Set `to` to `value` in place of the deprecated key `from`.
    fn replace(&mut self, from: Vec<&'static str>, to: Vec<&'static str>, value: toml::Value) {
        self.changes.push(Change::Set(to.clone(), value));
        self.changes.push(Change::Remove(from.clone()));
        self.sources.push((to, from));
    }

    fn extend(&mut self, other: Translation) {
        self.changes.extend(other.changes);
        self.warnings.extend(other.warnings);
        self.sources.extend(other.sources);
    }

    /// The deprecated key that the key at `path` was translated from.
    pub(super) fn source(&self, path: &[&str]) -> Option<&[&'static str]> {
        self.sources
            .iter()
            .find(|(to, _)| to == path)
            .map(|(_, from)| from.as_slice())
    }

    /// Apply the changes to the file's parsed layer.
    pub(super) fn apply(&self, file: &mut toml::Value) {
        for change in &self.changes {
            let (key, parents) = change.path().split_last().expect("a change names a key");
            let mut table = &mut *file;
            for parent in parents {
                let toml::Value::Table(map) = table else {
                    return;
                };
                table = map
                    .entry(*parent)
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            }
            let toml::Value::Table(map) = table else {
                return;
            };
            match change {
                Change::Remove(_) => {
                    map.remove(*key);
                }
                Change::Set(_, value) => {
                    map.insert((*key).to_string(), value.clone());
                }
            }
        }
    }
}

/// Translate the deprecated keys of `file`, an operator's parsed file.
/// `preset` is the configuration its preset gives, for the values the file
/// leaves out.
pub(super) fn translate(file: &toml::Value, preset: &toml::Value) -> Result<Translation, String> {
    let mut translation = filter_validation(file, preset)?;
    if leaf(file, &QUERY_COST).is_some() {
        translation
            .changes
            .push(Change::Remove(QUERY_COST.to_vec()));
        translation.warnings.push(
            "relay.abuse.max_query_cost is deprecated and ignored: it capped an estimate that \
             ignored `limit` and the query plan. relay.abuse.max_query_work now bounds the \
             index entries a query may touch (20000 in the public preset). `wok config \
             minimize` removes the old key."
                .to_string(),
        );
    }
    translation.extend(read_classes(file, preset)?);
    translation.extend(restrict_writes(file)?);
    Ok(translation)
}

fn restrict_writes(file: &toml::Value) -> Result<Translation, String> {
    let mut translation = Translation::default();
    let key = |name: &'static str| [AUTH[0], AUTH[1], name].to_vec();
    let Some(value) = leaf(file, &key("restrict_writes")) else {
        return Ok(translation);
    };
    let restrict = value
        .as_bool()
        .ok_or("relay.auth.restrict_writes: expected a boolean")?;
    if leaf(file, &key("write_policy")).is_some() {
        return Err(
            "relay.auth.restrict_writes was replaced by relay.auth.write_policy; set only \
             the new key"
                .into(),
        );
    }
    if restrict {
        translation.replace(
            key("restrict_writes"),
            key("write_policy"),
            toml::Value::String("members".into()),
        );
        translation.warnings.push(
            "relay.auth.restrict_writes = true is deprecated: it is now relay.auth.write_policy \
             = \"members\", which accepts members' events as before, and also events a member \
             sends on a connection authenticated as them, such as Marmot group messages from \
             throwaway keys, and gift wraps addressed to a member (relay.auth.inbox_kinds). \
             `wok config minimize` rewrites it."
                .to_string(),
        );
    } else {
        translation
            .changes
            .push(Change::Remove(key("restrict_writes")));
        translation.warnings.push(
            "relay.auth.restrict_writes = false is deprecated: relay.auth.write_policy = \
             \"open\" is the default. `wok config minimize` removes it."
                .to_string(),
        );
    }
    Ok(translation)
}

/// A list of kinds at `dotted`, as a file or preset sets one.
fn kinds(value: &toml::Value, dotted: &str) -> Result<Vec<u64>, String> {
    let expected = || format!("{dotted}: expected an array of kind numbers");
    value
        .as_array()
        .ok_or_else(expected)?
        .iter()
        .map(|kind| {
            kind.as_integer()
                .and_then(|n| u64::try_from(n).ok())
                .ok_or_else(expected)
        })
        .collect()
}

/// What a warning about kinds moved to a read class adds for those that
/// `owner_only` also lists: the strictest class applies, so only their author
/// may still read them.
pub(super) fn owner_only_note(kinds: &[u64], owner_only: &[u64]) -> String {
    let covered: Vec<u64> = kinds
        .iter()
        .copied()
        .filter(|kind| owner_only.contains(kind))
        .collect();
    if covered.is_empty() {
        return String::new();
    }
    format!(
        " Kinds {covered:?} are also in relay.auth.owner_only_kinds, the strictest class, so \
         only their author may read them."
    )
}

fn read_classes(file: &toml::Value, preset: &toml::Value) -> Result<Translation, String> {
    let mut translation = Translation::default();
    let Some(section) = file
        .get(AUTH[0])
        .and_then(|relay| relay.get(AUTH[1]))
        .and_then(toml::Value::as_table)
    else {
        return Ok(translation);
    };
    let key = |name: &'static str| [AUTH[0], AUTH[1], name].to_vec();
    let dotted = |name: &str| format!("relay.auth.{name}");
    let old_kinds = section.get("restricted_read_kinds");
    if let Some(value) = old_kinds {
        kinds(value, &dotted("restricted_read_kinds"))?;
        if section.contains_key("recipient_only_kinds") {
            return Err(format!(
                "{} was renamed {}; set only the new key",
                dotted("restricted_read_kinds"),
                dotted("recipient_only_kinds")
            ));
        }
    }
    let involved = section
        .get("restrict_read_to_involved_pubkey")
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                format!(
                    "{}: expected a boolean",
                    dotted("restrict_read_to_involved_pubkey")
                )
            })
        })
        .transpose()?;
    // A class as the file, or else the preset, sets it.
    let class_kinds = |name: &'static str| -> Result<Vec<u64>, String> {
        section
            .get(name)
            .or_else(|| leaf(preset, &key(name)))
            .map_or(Ok(Vec::new()), |value| kinds(value, &dotted(name)))
    };
    let owner_only = class_kinds("owner_only_kinds")?;
    if involved == Some(false) {
        // The nearest meaning that never shows the kinds to a connection
        // that has not authenticated.
        let moved = match old_kinds {
            Some(value) => kinds(value, &dotted("restricted_read_kinds"))?,
            None => class_kinds("recipient_only_kinds")?,
        };
        let mut authenticated = class_kinds("authenticated_kinds")?;
        for kind in &moved {
            if !authenticated.contains(kind) {
                authenticated.push(*kind);
            }
        }
        let list = |kinds: &[u64]| {
            toml::Value::Array(
                kinds
                    .iter()
                    .map(|&k| toml::Value::Integer(k as i64))
                    .collect(),
            )
        };
        let from = key("restrict_read_to_involved_pubkey");
        translation.replace(
            from.clone(),
            key("authenticated_kinds"),
            list(&authenticated),
        );
        translation
            .changes
            .push(Change::Set(key("recipient_only_kinds"), list(&[])));
        translation
            .sources
            .push((key("recipient_only_kinds"), from));
        if old_kinds.is_some() {
            translation
                .changes
                .push(Change::Remove(key("restricted_read_kinds")));
        }
        translation.warnings.push(format!(
            "{} = false is no longer supported: it let a REQ that mixed in another kind read \
             kinds {moved:?} without AUTH. They are now {}, which any authenticated connection \
             may read and no other can.{} `wok config minimize` rewrites the file.",
            dotted("restrict_read_to_involved_pubkey"),
            dotted("authenticated_kinds"),
            owner_only_note(&moved, &owner_only)
        ));
        return Ok(translation);
    }
    if let Some(value) = old_kinds {
        translation.replace(
            key("restricted_read_kinds"),
            key("recipient_only_kinds"),
            value.clone(),
        );
        translation.warnings.push(format!(
            "{} is deprecated: it is now {}, which only the author and first p-tag recipient \
             may read, as before.{} `wok config minimize` renames it.",
            dotted("restricted_read_kinds"),
            dotted("recipient_only_kinds"),
            owner_only_note(
                &kinds(value, &dotted("restricted_read_kinds"))?,
                &owner_only
            )
        ));
    }
    if involved == Some(true) {
        translation
            .changes
            .push(Change::Remove(key("restrict_read_to_involved_pubkey")));
        translation.warnings.push(format!(
            "{} = true is deprecated: {} are always limited to the author and first p-tag \
             recipient. `wok config minimize` removes it.",
            dotted("restrict_read_to_involved_pubkey"),
            dotted("recipient_only_kinds")
        ));
    }
    Ok(translation)
}

fn filter_validation(file: &toml::Value, preset: &toml::Value) -> Result<Translation, String> {
    let mut translation = Translation::default();
    let Some(section) = file
        .get(FILTER_VALIDATION[0])
        .and_then(|relay| relay.get(FILTER_VALIDATION[1]))
        .and_then(toml::Value::as_table)
    else {
        return Ok(translation);
    };
    let key = |name: &'static str| [FILTER_VALIDATION[0], FILTER_VALIDATION[1], name].to_vec();
    let dotted = |name: &str| format!("relay.filter_validation.{name}");
    let count = |name: &'static str| -> Result<Option<u64>, String> {
        section
            .get(name)
            .map(|value| {
                value
                    .as_integer()
                    .and_then(|n| u64::try_from(n).ok())
                    .ok_or_else(|| format!("{}: expected a non-negative integer", dotted(name)))
            })
            .transpose()
    };
    let enabled = section
        .get("enabled")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("{}: expected a boolean", dotted("enabled")))
        })
        .transpose()?;
    let max_filters = count("max_filters_per_req")?;
    let min_filters = count("min_filters_per_req")?;
    for name in ["enabled", "max_filters_per_req", "min_filters_per_req"] {
        if section.contains_key(name) {
            translation.changes.push(Change::Remove(key(name)));
        }
    }
    if enabled != Some(true) {
        // Without `enabled = true`, 0.7 applied none of the section, so none
        // of it applies now. A section without `enabled` is a current one,
        // whose rules apply as set.
        if enabled == Some(false) {
            for rule in RULES {
                if section.contains_key(rule) {
                    translation.changes.push(Change::Remove(key(rule)));
                }
            }
            translation.warnings.push(format!(
                "{} = false is deprecated: each filter rule now applies when it is set, so this \
                 section's rules are ignored, as before. `wok config minimize` removes them.",
                dotted("enabled")
            ));
        }
        for (name, value) in [
            ("max_filters_per_req", max_filters),
            ("min_filters_per_req", min_filters),
        ] {
            if value.is_some() && enabled.is_none() {
                translation.warnings.push(format!(
                    "{} is no longer a setting and is ignored; relay.max_filters_per_req bounds \
                     the filters in a REQ",
                    dotted(name)
                ));
            }
        }
        return Ok(translation);
    }
    translation.warnings.push(format!(
        "{} = true is deprecated: each filter rule now applies when it is set, so this \
         section's rules still apply. `wok config minimize` rewrites it.",
        dotted("enabled")
    ));
    // An enabled section enforced the 0.7 default for a rule it left out.
    match count("max_kinds_per_filter")? {
        None => translation.changes.push(Change::Set(
            key("max_kinds_per_filter"),
            toml::Value::Integer(LEGACY_MAX_KINDS_PER_FILTER as i64),
        )),
        Some(0) => translation
            .warnings
            .push(zero_kind_cap_warning(&dotted("max_kinds_per_filter"))),
        Some(_) => {}
    }
    // Its filter-count cap moves to the relay's own, whichever is lower.
    let cap = max_filters.unwrap_or(LEGACY_MAX_FILTERS_PER_REQ);
    let relay_cap = ["relay", "max_filters_per_req"];
    let current = leaf(file, &relay_cap)
        .or_else(|| leaf(preset, &relay_cap))
        .and_then(toml::Value::as_integer)
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(u64::MAX);
    if cap < current {
        translation.changes.push(Change::Set(
            relay_cap.to_vec(),
            toml::Value::Integer(cap as i64),
        ));
        translation.warnings.push(match max_filters {
            Some(_) => format!(
                "{} is deprecated: relay.max_filters_per_req = {cap} now bounds the filters in a \
                 REQ",
                dotted("max_filters_per_req")
            ),
            None => format!(
                "relay.max_filters_per_req = {cap} keeps the filter cap this section had by \
                 default through 0.7"
            ),
        });
    } else if max_filters.is_some() {
        translation.warnings.push(format!(
            "{} is deprecated and ignored: relay.max_filters_per_req = {current} is already as low",
            dotted("max_filters_per_req")
        ));
    }
    match min_filters {
        Some(minimum) if minimum > 1 => translation.warnings.push(format!(
            "{} = {minimum} is no longer supported and is ignored: a REQ needs only one filter",
            dotted("min_filters_per_req")
        )),
        Some(_) => translation.warnings.push(format!(
            "{} is deprecated and ignored: every REQ needs a filter",
            dotted("min_filters_per_req")
        )),
        None => {}
    }
    Ok(translation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translated(text: &str) -> (Translation, toml::Value) {
        let mut file: toml::Value = toml::from_str(text).unwrap();
        let preset: toml::Value = toml::from_str("[relay]\nmax_filters_per_req = 200\n").unwrap();
        let translation = translate(&file, &preset).unwrap();
        translation.apply(&mut file);
        (translation, file)
    }

    #[test]
    fn a_disabled_section_loads_with_every_rule_off() {
        let (translation, file) = translated(
            "[relay.filter_validation]\n\
             enabled = false\n\
             max_filters_per_req = 3\n\
             min_filters_per_req = 1\n\
             max_kinds_per_filter = 3\n\
             allowed_kinds = \"1\"\n\
             require_author_or_tag = true\n\
             require_scoped_filters = true\n",
        );
        assert_eq!(
            file["relay"]["filter_validation"],
            toml::Value::Table(toml::Table::new())
        );
        assert!(file["relay"].get("max_filters_per_req").is_none());
        assert_eq!(translation.warnings.len(), 1, "{:?}", translation.warnings);
    }

    #[test]
    fn an_enabled_section_keeps_its_rules_and_the_lower_filter_cap() {
        let (translation, file) = translated(
            "[relay.filter_validation]\n\
             enabled = true\n\
             max_filters_per_req = 5\n\
             min_filters_per_req = 2\n\
             allowed_kinds = \"1,7\"\n",
        );
        let section = &file["relay"]["filter_validation"];
        assert_eq!(section["max_kinds_per_filter"].as_integer(), Some(3));
        assert_eq!(section["allowed_kinds"].as_str(), Some("1,7"));
        assert!(section.get("enabled").is_none());
        assert!(section.get("max_filters_per_req").is_none());
        assert!(section.get("min_filters_per_req").is_none());
        assert_eq!(file["relay"]["max_filters_per_req"].as_integer(), Some(5));
        let warnings = translation.warnings.join("\n");
        assert!(
            warnings.contains("relay.max_filters_per_req = 5"),
            "{warnings}"
        );
        assert!(
            warnings.contains("min_filters_per_req = 2 is no longer supported"),
            "{warnings}"
        );

        // A zero kind cap no longer refuses every kind filter, loudly.
        let (translation, file) =
            translated("[relay.filter_validation]\nenabled = true\nmax_kinds_per_filter = 0\n");
        assert_eq!(
            file["relay"]["filter_validation"]["max_kinds_per_filter"].as_integer(),
            Some(0)
        );
        assert!(
            translation
                .warnings
                .iter()
                .any(|warning| warning.starts_with(
                    "relay.filter_validation.max_kinds_per_filter = 0 in an enabled section"
                ) && warning.contains("allowed_kinds")),
            "{:?}",
            translation.warnings
        );

        // A lower relay cap in the file stays.
        let (_, file) = translated(
            "[relay]\nmax_filters_per_req = 2\n\
             [relay.filter_validation]\nenabled = true\nmax_kinds_per_filter = 6\n",
        );
        assert_eq!(file["relay"]["max_filters_per_req"].as_integer(), Some(2));
        assert_eq!(
            file["relay"]["filter_validation"]["max_kinds_per_filter"].as_integer(),
            Some(6)
        );
        // Left out, the cap was 0.7's default of 3.
        let (_, file) = translated("[relay.filter_validation]\nenabled = true\n");
        assert_eq!(file["relay"]["max_filters_per_req"].as_integer(), Some(3));
    }

    #[test]
    fn a_current_section_is_left_alone() {
        let (translation, file) =
            translated("[relay.filter_validation]\nmax_kinds_per_filter = 6\n");
        assert!(translation.changes.is_empty() && translation.warnings.is_empty());
        assert_eq!(
            file["relay"]["filter_validation"]["max_kinds_per_filter"].as_integer(),
            Some(6)
        );
        // Stray filter counts did nothing without `enabled`, and still don't.
        let (translation, file) =
            translated("[relay.filter_validation]\nmax_filters_per_req = 1\n");
        assert_eq!(translation.warnings.len(), 1);
        assert!(file["relay"].get("max_filters_per_req").is_none());
    }

    #[test]
    fn an_old_query_cost_ceiling_is_ignored() {
        let (translation, file) =
            translated("[relay.abuse]\nmax_query_cost = 1000\nreq_burst = 80\n");
        let abuse = &file["relay"]["abuse"];
        assert!(abuse.get("max_query_cost").is_none());
        assert_eq!(abuse["req_burst"].as_integer(), Some(80));
        assert_eq!(translation.warnings.len(), 1);
        assert!(
            translation.warnings[0].contains("relay.abuse.max_query_work"),
            "{:?}",
            translation.warnings
        );
        // Whatever its value, and next to the key that replaced it.
        let (_, file) = translated("[relay.abuse]\nmax_query_cost = 0\nmax_query_work = 500\n");
        assert!(file["relay"]["abuse"].get("max_query_cost").is_none());
        assert_eq!(
            file["relay"]["abuse"]["max_query_work"].as_integer(),
            Some(500)
        );

        let config = crate::Config::parse_toml("[relay.abuse]\nmax_query_cost = 1000\n").unwrap();
        assert_eq!(config.relay.abuse.max_query_work, 20_000);
        assert_eq!(config.deprecations.len(), 1);
        let minimized =
            crate::Config::minimize_toml("[relay.abuse]\nmax_query_cost = 1000\n").unwrap();
        assert_eq!(minimized.rewritten, ["relay.abuse.max_query_cost"]);
        assert!(
            !minimized.text.contains("max_query_cost"),
            "{}",
            minimized.text
        );
    }

    /// Who may read each kind: (kind, read class).
    fn read_classes(config: &crate::Config) -> Vec<(u64, crate::restrict::ReadClass)> {
        let restrictor = config.read_restrictor();
        [1, 4, 7, 78, 1059, 21059, 30078]
            .into_iter()
            .map(|kind| (kind, restrictor.class(kind)))
            .collect()
    }

    #[test]
    fn restricted_read_kinds_are_recipient_only_kinds() {
        use crate::restrict::ReadClass::{Open, Owner, Recipient};
        let (translation, file) = translated("[relay.auth]\nrestricted_read_kinds = [4, 7]\n");
        let auth = &file["relay"]["auth"];
        assert!(auth.get("restricted_read_kinds").is_none());
        assert_eq!(auth["recipient_only_kinds"], toml::Value::from(vec![4, 7]));
        assert_eq!(translation.warnings.len(), 1, "{:?}", translation.warnings);
        assert_eq!(
            translation.source(&["relay", "auth", "recipient_only_kinds"]),
            Some(&["relay", "auth", "restricted_read_kinds"][..])
        );

        let config = crate::Config::parse_toml(
            "[relay.auth]\nrestricted_read_kinds = [4, 7]\nrestrict_read_to_involved_pubkey = true\n",
        )
        .unwrap();
        assert_eq!(config.deprecations.len(), 2, "{:?}", config.deprecations);
        assert_eq!(
            read_classes(&config),
            [
                (1, Open),
                (4, Recipient),
                (7, Recipient),
                (78, Owner),
                (1059, Open),
                (21059, Open),
                (30078, Owner),
            ]
        );
        // A kind the owner-only class also lists stays readable by its
        // author alone, and the warning says so.
        let config =
            crate::Config::parse_toml("[relay.auth]\nrestricted_read_kinds = [4, 30078]\n")
                .unwrap();
        assert_eq!(config.read_restrictor().class(30078), Owner);
        assert!(
            config.deprecations[0]
                .contains("Kinds [30078] are also in relay.auth.owner_only_kinds"),
            "{:?}",
            config.deprecations
        );
        let config = crate::Config::parse_toml(
            "[relay.auth]\nrestricted_read_kinds = [4, 78]\nrestrict_read_to_involved_pubkey = false\n",
        )
        .unwrap();
        assert_eq!(config.read_restrictor().class(78), Owner);
        assert!(
            config.deprecations[0].contains("Kinds [78] are also"),
            "{:?}",
            config.deprecations
        );
        // Not when the file empties that class.
        let config = crate::Config::parse_toml(
            "[relay.auth]\nrestricted_read_kinds = [30078]\nowner_only_kinds = []\n",
        )
        .unwrap();
        assert!(!config.deprecations[0].contains("owner_only_kinds"));
        // Both names at once are ambiguous.
        let both = "[relay.auth]\nrestricted_read_kinds = [4]\nrecipient_only_kinds = [4]\n";
        assert!(crate::Config::parse_toml(both)
            .unwrap_err()
            .contains("set only the new key"));
    }

    #[test]
    fn reads_not_limited_to_the_involved_pubkey_need_authentication() {
        use crate::restrict::ReadClass::{Authenticated, Open, Owner};
        // The old kinds, or the preset's when the file left them out, are
        // readable by any authenticated connection.
        for (text, moved) in [
            (
                "[relay.auth]\nrestricted_read_kinds = [4, 7]\n\
                 restrict_read_to_involved_pubkey = false\n",
                [4, 7].as_slice(),
            ),
            (
                "[relay.auth]\nrestrict_read_to_involved_pubkey = false\n",
                [4, 1059, 21059].as_slice(),
            ),
        ] {
            let config = crate::Config::parse_toml(text).unwrap();
            let auth = &config.relay.auth;
            assert!(auth.recipient_only_kinds.is_empty(), "{text}");
            assert_eq!(auth.authenticated_kinds, moved, "{text}");
            assert_eq!(config.deprecations.len(), 1, "{:?}", config.deprecations);
            assert!(
                config.deprecations[0].contains("relay.auth.authenticated_kinds"),
                "{:?}",
                config.deprecations
            );
            for (kind, class) in read_classes(&config) {
                let expected = match kind {
                    78 | 30078 => Owner,
                    kind if moved.contains(&kind) => Authenticated,
                    _ => Open,
                };
                assert_eq!(class, expected, "kind {kind}: {text}");
            }

            // Rewritten, the file loads the same without deprecated keys.
            let minimized = crate::Config::minimize_toml(text).unwrap();
            assert!(!minimized.text.contains("restrict"), "{}", minimized.text);
            let rewritten = crate::Config::parse_toml(&minimized.text).unwrap();
            assert!(rewritten.deprecations.is_empty());
            assert_eq!(read_classes(&rewritten), read_classes(&config));
        }

        // Kinds the file already reads after AUTH stay, once each.
        let config = crate::Config::parse_toml(
            "[relay.auth]\nauthenticated_kinds = [7, 4]\nrecipient_only_kinds = [4, 30]\n\
             restrict_read_to_involved_pubkey = false\n",
        )
        .unwrap();
        assert_eq!(config.relay.auth.authenticated_kinds, [7, 4, 30]);
        assert!(config.relay.auth.recipient_only_kinds.is_empty());
    }

    #[test]
    fn restrict_writes_is_the_members_write_policy() {
        use crate::config::AccessPolicy;
        let (translation, file) = translated("[relay.auth]\nrestrict_writes = true\n");
        let auth = &file["relay"]["auth"];
        assert!(auth.get("restrict_writes").is_none());
        assert_eq!(auth["write_policy"].as_str(), Some("members"));
        assert_eq!(translation.warnings.len(), 1);
        assert!(translation.warnings[0].contains("write_policy = \"members\""));
        assert_eq!(
            translation.source(&["relay", "auth", "write_policy"]),
            Some(&["relay", "auth", "restrict_writes"][..])
        );
        let members = crate::Config::parse_toml("[relay.auth]\nrestrict_writes = true\n").unwrap();
        assert_eq!(members.relay.auth.write_policy, AccessPolicy::Members);
        assert_eq!(members.relay.auth.read_policy, AccessPolicy::Open);
        let open = crate::Config::parse_toml("[relay.auth]\nrestrict_writes = false\n").unwrap();
        assert_eq!(open.relay.auth.write_policy, AccessPolicy::Open);
        assert_eq!(open.deprecations.len(), 1);

        // Rewritten, the file loads the same without the deprecated key.
        let minimized =
            crate::Config::minimize_toml("[relay.auth]\nrestrict_writes = true\n").unwrap();
        assert_eq!(minimized.text, "[relay.auth]\nwrite_policy = \"members\"\n");
        assert_eq!(
            crate::Config::parse_toml(&minimized.text)
                .unwrap()
                .relay
                .auth
                .write_policy,
            AccessPolicy::Members
        );
        // Both keys at once are ambiguous.
        let both = "[relay.auth]\nrestrict_writes = true\nwrite_policy = \"open\"\n";
        assert!(crate::Config::parse_toml(both)
            .unwrap_err()
            .contains("set only the new key"));
    }

    #[test]
    fn malformed_legacy_keys_are_errors() {
        let file: toml::Value = toml::from_str("[relay.filter_validation]\nenabled = 1\n").unwrap();
        assert!(translate(&file, &file).is_err());
        let file: toml::Value =
            toml::from_str("[relay.filter_validation]\nmax_filters_per_req = -1\n").unwrap();
        assert!(translate(&file, &file).is_err());
        for auth in [
            "restricted_read_kinds = [-4]",
            "restricted_read_kinds = 4",
            "restrict_read_to_involved_pubkey = 0",
            "restrict_writes = \"yes\"",
        ] {
            let file: toml::Value = toml::from_str(&format!("[relay.auth]\n{auth}\n")).unwrap();
            assert!(translate(&file, &file).is_err(), "{auth}");
        }
    }

    /// `docs/wok.toml` as Wok 0.7.0 shipped it.
    const SAMPLE_0_7_0: &str = include_str!("testdata/wok-0.7.0.toml");

    /// The rules a REQ meets: the relay's filter cap and the section's rules.
    fn rules(config: &crate::Config) -> (usize, u64, String, bool) {
        let f = &config.relay.filter_validation;
        (
            config.relay.max_filters_per_req,
            f.max_kinds_per_filter,
            f.allowed_kinds.clone(),
            f.require_author_or_tag,
        )
    }

    #[test]
    fn the_0_7_0_sample_upgrades_with_its_rules_unchanged() {
        // 0.7 applied the sample's disabled section not at all. Its query
        // cost ceiling is ignored, in favor of the preset's in new units.
        let upgraded = crate::Config::parse_toml(SAMPLE_0_7_0).unwrap();
        assert_eq!(rules(&upgraded), (200, 0, String::new(), false));
        assert_eq!(upgraded.relay.abuse.max_query_work, 20_000);
        // Its access keys are renamed, and keep their meaning.
        assert_eq!(
            upgraded.deprecations.len(),
            5,
            "{:?}",
            upgraded.deprecations
        );
        assert!(upgraded.deprecations[0].contains("enabled = false is deprecated"));
        assert!(upgraded.deprecations[1].starts_with("relay.abuse.max_query_cost is deprecated"));
        assert!(upgraded.deprecations[2].starts_with("relay.auth.restricted_read_kinds"));
        assert!(upgraded.deprecations[3].starts_with("relay.auth.restrict_read_to_involved"));
        assert!(upgraded.deprecations[4].starts_with("relay.auth.restrict_writes = false"));
        assert_eq!(upgraded.relay.auth.recipient_only_kinds, [4, 1059]);
        assert_eq!(
            upgraded.relay.auth.write_policy,
            crate::config::AccessPolicy::Open
        );

        // Enabled, 0.7 refused more than three filters or three kinds per
        // filter, which the upgrade keeps.
        let enabled = SAMPLE_0_7_0.replace(
            "[relay.filter_validation]\nenabled = false",
            "[relay.filter_validation]\nenabled = true",
        );
        assert_ne!(enabled, SAMPLE_0_7_0);
        let upgraded = crate::Config::parse_toml(&enabled).unwrap();
        assert_eq!(rules(&upgraded), (3, 3, String::new(), false));
        assert_eq!(
            upgraded.deprecations.len(),
            7,
            "{:?}",
            upgraded.deprecations
        );

        // Rewritten, the file loads the same without deprecated keys.
        for text in [SAMPLE_0_7_0.to_string(), enabled] {
            let minimized = crate::Config::minimize_toml(&text).unwrap();
            let file: toml::Value = toml::from_str(&minimized.text).unwrap();
            let section = file["relay"]
                .get("filter_validation")
                .and_then(toml::Value::as_table);
            for key in ["enabled", "max_filters_per_req", "min_filters_per_req"] {
                assert!(
                    section.is_none_or(|section| !section.contains_key(key)),
                    "{key}: {}",
                    minimized.text
                );
            }
            assert!(file["relay"]["abuse"].get("max_query_cost").is_none());
            assert!(!minimized.text.contains("restrict"), "{}", minimized.text);
            let rewritten = crate::Config::parse_toml(&minimized.text).unwrap();
            assert!(
                rewritten.deprecations.is_empty(),
                "{:?}",
                rewritten.deprecations
            );
            assert_eq!(
                rules(&rewritten),
                rules(&crate::Config::parse_toml(&text).unwrap())
            );
        }
    }

    #[test]
    fn minimize_and_dashboard_saves_rewrite_a_legacy_section() {
        let text = "[relay]\n\
                    port = 7778\n\
                    \n\
                    [relay.filter_validation]\n\
                    enabled = true\n\
                    max_filters_per_req = 5\n\
                    allowed_kinds = \"1,7\"\n";
        let minimized = crate::Config::minimize_toml(text).unwrap();
        assert_eq!(
            minimized.text,
            "[relay]\n\
             port = 7778\n\
             max_filters_per_req = 5\n\
             \n\
             [relay.filter_validation]\n\
             allowed_kinds = \"1,7\"\n\
             max_kinds_per_filter = 3\n"
        );
        assert_eq!(
            minimized.rewritten,
            [
                "relay.filter_validation.max_kinds_per_filter",
                "relay.max_filters_per_req",
                "relay.filter_validation.enabled",
                "relay.filter_validation.max_filters_per_req",
            ]
        );
        assert!(minimized.removed.is_empty());

        // A save from the dashboard can change a rule of a disabled section,
        // which the deprecated switch would otherwise turn off again.
        let (edited, config) = crate::Config::edit_toml(
            "[relay.filter_validation]\nenabled = false\nmax_kinds_per_filter = 3\n",
            |config| config.relay.filter_validation.max_kinds_per_filter = 6,
        )
        .unwrap();
        assert_eq!(
            edited,
            "[relay.filter_validation]\nmax_kinds_per_filter = 6\n"
        );
        assert_eq!(config.relay.filter_validation.max_kinds_per_filter, 6);
        assert!(config.deprecations.is_empty());
    }
}
