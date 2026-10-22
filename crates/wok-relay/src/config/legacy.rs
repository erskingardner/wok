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

/// The rules that remain, each off at its zero or empty value.
const RULES: [&str; 3] = [
    "max_kinds_per_filter",
    "allowed_kinds",
    "require_author_or_tag",
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
}

impl Translation {
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
             require_author_or_tag = true\n",
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
    fn malformed_legacy_keys_are_errors() {
        let file: toml::Value = toml::from_str("[relay.filter_validation]\nenabled = 1\n").unwrap();
        assert!(translate(&file, &file).is_err());
        let file: toml::Value =
            toml::from_str("[relay.filter_validation]\nmax_filters_per_req = -1\n").unwrap();
        assert!(translate(&file, &file).is_err());
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
        // 0.7 applied the sample's disabled section not at all.
        let upgraded = crate::Config::parse_toml(SAMPLE_0_7_0).unwrap();
        assert_eq!(rules(&upgraded), (200, 0, String::new(), false));
        assert_eq!(
            upgraded.deprecations.len(),
            1,
            "{:?}",
            upgraded.deprecations
        );
        assert!(upgraded.deprecations[0].contains("enabled = false is deprecated"));

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
            3,
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
