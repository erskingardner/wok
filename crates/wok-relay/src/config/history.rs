//! Built-in defaults that later releases replaced, and the keys of an
//! operator's file still pinned to one, or to a built-in default its preset
//! replaces.

use super::provenance::{leaf, ConfigEntry, ConfigExplanation, Origin};
use super::{encode, Config, Preset};

/// Built-in defaults a later release replaced, oldest first: the dotted key,
/// the old value encoded as TOML, and the last release whose default it was.
///
/// When you change a default, add its old value here. The test against the
/// complete 0.7.0 sample catches only the first change, since 0.7.0, to a key
/// that sample lists; record every other change by hand.
const PAST_DEFAULTS: &[(&str, &str, &str)] = &[
    ("database.map_size", "10995116277760", "0.1.0"),
    ("relay.abuse.max_stored_events_per_pubkey", "0", "0.1.0"),
    ("events.max_event_size", "65536", "0.4.0"),
    ("relay.max_websocket_payload_size", "131072", "0.4.0"),
    ("relay.unix.max_frame_bytes", "131072", "0.4.0"),
    ("events.reject_older_than_secs", "94608000", "0.7.0"),
    ("relay.auth.recipient_only_kinds", "[4, 1059]", "0.7.0"),
    ("relay.max_req_filter_size", "65536", "0.7.0"),
    ("events.max_num_tags", "2000", "0.7.0"),
    ("relay.max_filter_limit", "500", "0.7.0"),
    ("relay.max_tags_per_filter", "3", "0.7.0"),
    ("relay.max_total_events_per_req", "2000", "0.7.0"),
    ("relay.abuse.max_stored_events", "10000000", "0.7.0"),
    (
        "relay.abuse.max_stored_events_per_pubkey",
        "100000",
        "0.7.0",
    ),
    ("relay.filter_validation.max_kinds_per_filter", "3", "0.7.0"),
    ("relay.abuse.req_rate_per_second", "20", "0.7.0"),
    ("relay.abuse.req_burst", "40", "0.7.0"),
    ("relay.abuse.count_rate_per_second", "5", "0.7.0"),
    ("relay.abuse.count_burst", "10", "0.7.0"),
];

/// A key the operator's file pins to a built-in default that a later release
/// replaced. The file keeps the old value, so the relay does not get the new
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleDefault {
    /// Dotted key path, such as `events.reject_older_than_secs`.
    pub key: String,
    /// The pinned value, encoded as TOML.
    pub value: String,
    /// The last release whose built-in default `value` was.
    pub last_release: &'static str,
    /// The value the preset gives now.
    pub preset_value: String,
    /// The 1-based line of the key in the file, when it could be located.
    pub line: Option<usize>,
}

/// A key the operator's file pins to the public preset's value, the built-in
/// default, where the file's own preset gives another. A file written for
/// the public preset, such as a copy of the 0.7 sample that listed every
/// default, keeps these when it selects another preset, so the relay does
/// not get that preset's values. None is a past default, so
/// [`ConfigExplanation::stale_defaults`] does not list them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicValue {
    /// Dotted key path, such as `events.max_event_size`.
    pub key: String,
    /// The pinned value, encoded as TOML: the public preset's.
    pub value: String,
    /// The value the file's preset gives.
    pub preset_value: String,
    /// The 1-based line of the key in the file, when it could be located.
    pub line: Option<usize>,
}

impl ConfigExplanation {
    /// The keys the file pins to a past built-in default that the preset no
    /// longer uses, in key order.
    pub fn stale_defaults(&self) -> Vec<StaleDefault> {
        self.entries.iter().filter_map(stale_default).collect()
    }

    /// The keys the file pins to the public preset's value that its own
    /// preset replaces, in key order. Empty under the public preset.
    pub fn public_values(&self) -> Vec<PublicValue> {
        if self.config.preset == Preset::Public {
            return Vec::new();
        }
        let Ok(public) = encode(&Config::default()) else {
            return Vec::new();
        };
        self.entries
            .iter()
            .filter_map(|entry| {
                let Origin::File { line } = entry.origin else {
                    return None;
                };
                let preset_value = entry.preset_value.clone()?;
                let path: Vec<&str> = entry.key.split('.').collect();
                (leaf(&public, &path)?.to_string() == entry.value).then(|| PublicValue {
                    key: entry.key.clone(),
                    value: entry.value.clone(),
                    preset_value,
                    line,
                })
            })
            .collect()
    }

    /// The keys the file sets to the value its preset already gives. They
    /// change nothing today, but stop the relay from following the preset
    /// when a default changes; `wok config minimize` removes them.
    pub fn repeated_preset_values(&self) -> impl Iterator<Item = &ConfigEntry> {
        self.entries.iter().filter(|entry| entry.repeats_preset())
    }
}

fn stale_default(entry: &ConfigEntry) -> Option<StaleDefault> {
    let Origin::File { line } = entry.origin else {
        return None;
    };
    let preset_value = entry.preset_value.clone()?;
    let &(_, _, last_release) = PAST_DEFAULTS
        .iter()
        .rev()
        .find(|&&(key, value, _)| key == entry.key && value == entry.value)?;
    Some(StaleDefault {
        key: entry.key.clone(),
        value: entry.value.clone(),
        last_release,
        preset_value,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{encode, provenance::leaf, Config, Preset};

    /// `docs/wok.toml` as Wok 0.7.0 shipped it: every 0.7.0 default.
    const SAMPLE_0_7_0: &str = include_str!("testdata/wok-0.7.0.toml");

    #[test]
    fn past_defaults_are_encoded_like_effective_values() {
        let defaults = encode(&Config::default()).unwrap();
        for &(key, value, release) in PAST_DEFAULTS {
            let path: Vec<&str> = key.split('.').collect();
            let current =
                leaf(&defaults, &path).unwrap_or_else(|| panic!("{key} is not a setting"));
            let parsed: toml::Table = toml::from_str(&format!("v = {value}")).unwrap();
            assert_eq!(
                parsed["v"].to_string(),
                value,
                "{key}: encode {value} as TOML prints it"
            );
            assert_ne!(
                *current, parsed["v"],
                "{key} = {value} is still the default"
            );
            assert!(
                release.split('.').all(|part| part.parse::<u32>().is_ok()),
                "{key}: release {release:?}"
            );
        }
    }

    #[test]
    fn past_defaults_record_every_default_changed_since_0_7_0() {
        let explained = Config::explain_toml(SAMPLE_0_7_0).unwrap();
        assert_eq!(explained.config.preset, Preset::Public);
        let changed: Vec<&str> = explained
            .entries
            .iter()
            .filter(|entry| entry.is_override())
            .map(|entry| entry.key.as_str())
            .collect();
        let stale = explained.stale_defaults();
        let recorded: Vec<&str> = stale.iter().map(|stale| stale.key.as_str()).collect();
        assert_eq!(
            recorded, changed,
            "a default changed since 0.7.0: add its 0.7.0 value to PAST_DEFAULTS"
        );
        assert_eq!(
            stale[1],
            StaleDefault {
                key: "events.reject_older_than_secs".into(),
                value: "94608000".into(),
                last_release: "0.7.0",
                preset_value: "0".into(),
                line: Some(28),
            }
        );
    }

    #[test]
    fn stale_defaults_skip_deliberate_values_and_current_defaults() {
        let explained = Config::explain_toml(
            "[events]\n\
             reject_older_than_secs = 31536000\n\
             max_event_size = 65536\n\
             max_num_tags = 5000\n",
        )
        .unwrap();
        let stale = explained.stale_defaults();
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert_eq!(stale[0].key, "events.max_event_size");
        assert_eq!(stale[0].last_release, "0.4.0");
        assert_eq!(stale[0].preset_value, "1048576");
        assert_eq!(stale[0].line, Some(3));
        let repeated: Vec<&str> = explained
            .repeated_preset_values()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(repeated, ["events.max_num_tags"]);
    }

    #[test]
    fn a_0_7_0_sample_moved_to_marmot_names_the_public_values_it_keeps() {
        let explained =
            Config::explain_toml(&format!("preset = \"marmot\"\n{SAMPLE_0_7_0}")).unwrap();
        let kept = |key: &str, value: &str, preset_value: &str, line| PublicValue {
            key: key.into(),
            value: value.into(),
            preset_value: preset_value.into(),
            line: Some(line),
        };
        assert_eq!(
            explained.public_values(),
            [
                kept("events.max_event_size", "1048576", "4194304", 27),
                kept("relay.abuse.event_burst", "100", "300", 139),
                kept("relay.compression_enabled", "true", "false", 81),
                kept("relay.max_filter_limit_count", "1000000", "0", 73),
                kept("relay.max_sync_events", "1000000", "65536", 93),
                kept("relay.max_websocket_payload_size", "2097152", "8388608", 53),
                kept(
                    "relay.sync_memory_per_connection",
                    "268435456",
                    "134217728",
                    94
                ),
                kept("relay.unix.max_frame_bytes", "2097152", "8388608", 163),
            ]
        );
    }

    #[test]
    fn every_override_of_a_0_7_0_sample_is_named_under_each_preset() {
        for &preset in Preset::ALL {
            let explained =
                Config::explain_toml(&format!("preset = \"{preset}\"\n{SAMPLE_0_7_0}")).unwrap();
            let stale = explained.stale_defaults();
            let kept = explained.public_values();
            for entry in explained.entries.iter().filter(|entry| entry.is_override()) {
                let named = stale.iter().filter(|stale| stale.key == entry.key).count()
                    + kept.iter().filter(|kept| kept.key == entry.key).count();
                assert_eq!(
                    named, 1,
                    "preset {preset}: {} = {} keeps the file from the preset's {:?}; \
                     stale_defaults or public_values must name it, once",
                    entry.key, entry.value, entry.preset_value
                );
            }
        }
    }

    #[test]
    fn public_values_skip_the_public_preset_and_other_values() {
        let file = "[relay]\ncompression_enabled = true\n[relay.abuse]\nevent_burst = 500\n";
        let public = Config::explain_toml(file).unwrap();
        assert_eq!(public.public_values(), []);
        let marmot = Config::explain_toml(&format!("preset = \"marmot\"\n{file}")).unwrap();
        let kept = marmot.public_values();
        let keys: Vec<&str> = kept.iter().map(|kept| kept.key.as_str()).collect();
        assert_eq!(keys, ["relay.compression_enabled"]);
    }
}
