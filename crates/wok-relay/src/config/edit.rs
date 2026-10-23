//! Edit an operator's file in place, keeping its comments and layout.
//!
//! A key in the file pins its value, so a file that repeats the preset's
//! values never picks up a better default. Dashboard saves therefore change
//! only the keys they edit and remove a key set back to its preset value, and
//! `wok config minimize` removes every key that repeats the preset. Both
//! rewrite deprecated keys as their translation.

use super::legacy::{Change, Translation};
use super::provenance::{explain, flatten, leaf};
use super::{encode, validate, Config, Layers, OverlayFn, TomlConfig};
use std::io::Write;
use std::path::Path;
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike, Value};

/// A file without the keys that repeated its preset's values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minimized {
    /// The file with those keys removed, its deprecated keys rewritten, and
    /// everything else unchanged.
    pub text: String,
    /// The dotted keys removed, sorted.
    pub removed: Vec<String>,
    /// The dotted keys set or removed to rewrite deprecated keys as their
    /// translation, in the order written.
    pub rewritten: Vec<String>,
}

pub(super) fn edit(
    text: &str,
    overlay_of: OverlayFn,
    edit: impl FnOnce(&mut Config),
) -> Result<(String, Config), String> {
    let invalid = |error| format!("the current file is invalid: {error}");
    let layers = Layers::parse(text, overlay_of).map_err(invalid)?;
    let current = layers.resolve().map_err(invalid)?;
    let mut target = current.clone();
    edit(&mut target);
    if target.preset != current.preset {
        return Err("an edit cannot change the preset".into());
    }
    // Normalize the target the way parsing the edited file will.
    let target = validate(TomlConfig::from(target))?;
    let before = encode(&current)?;
    let after = encode(&target)?;
    let preset = layers.preset_encoded()?;

    let mut document = parse_document(text)?;
    rewrite_legacy(&mut document, &layers.legacy)?;
    let mut leaves = Vec::new();
    flatten(&after, &mut Vec::new(), &mut leaves);
    for (path, value) in leaves {
        if leaf(&before, &path) == Some(value) {
            continue;
        }
        if leaf(&preset, &path) == Some(value) {
            remove_key(document.as_table_mut(), &path);
        } else {
            set_key(document.as_item_mut(), &path, value)?;
        }
    }
    let edited = render(&document, text);
    let verified = Layers::parse(&edited, overlay_of)?.resolve()?;
    if encode(&verified)? != after {
        return Err("the edited file does not resolve to the requested configuration".into());
    }
    Ok((edited, verified))
}

pub(super) fn minimize(text: &str, overlay_of: OverlayFn) -> Result<Minimized, String> {
    let explanation = explain(text, overlay_of)?;
    let legacy = Layers::parse(text, overlay_of)?.legacy;
    let removed: Vec<String> = explanation
        .entries
        .iter()
        .filter(|entry| entry.repeats_preset())
        .map(|entry| entry.key.clone())
        .collect();
    if removed.is_empty() && legacy.changes.is_empty() {
        return Ok(Minimized {
            text: text.to_string(),
            removed,
            rewritten: Vec::new(),
        });
    }
    let mut document = parse_document(text)?;
    let rewritten = rewrite_legacy(&mut document, &legacy)?;
    for key in &removed {
        // Every setting is a plain identifier, so dots only separate tables.
        let path: Vec<&str> = key.split('.').collect();
        if !remove_key(document.as_table_mut(), &path) {
            return Err(format!("cannot locate {key} in the file"));
        }
    }
    let minimized = render(&document, text);
    let verified = Layers::parse(&minimized, overlay_of)?.resolve()?;
    if encode(&verified)? != encode(&explanation.config)? {
        return Err("removing the keys would change the configuration".into());
    }
    Ok(Minimized {
        text: minimized,
        removed,
        rewritten,
    })
}

/// Write the translation of the file's deprecated keys into the document:
/// the keys it sets first, so a table that keeps keys keeps its place, then
/// the keys it removes. Returns the dotted keys written.
fn rewrite_legacy(document: &mut DocumentMut, legacy: &Translation) -> Result<Vec<String>, String> {
    let (sets, removes): (Vec<&Change>, Vec<&Change>) = legacy
        .changes
        .iter()
        .partition(|change| matches!(change, Change::Set(..)));
    for change in sets.iter().chain(&removes) {
        match change {
            Change::Set(path, value) => set_key(document.as_item_mut(), path, value)?,
            Change::Remove(path) => {
                remove_key(document.as_table_mut(), path);
            }
        }
    }
    Ok(sets
        .iter()
        .chain(&removes)
        .map(|change| change.path().join("."))
        .collect())
}

fn parse_document(text: &str) -> Result<DocumentMut, String> {
    text.parse::<DocumentMut>().map_err(|e| e.to_string())
}

/// Set the key at `path` to `value`. An existing value keeps its comments; a
/// new key goes at the end of its table, and a missing table is created in
/// the style of its parent.
fn set_key(root: &mut Item, path: &[&str], value: &toml::Value) -> Result<(), String> {
    let not_a_table = || format!("{}: a parent is not a table", path.join("."));
    let (key, parents) = path.split_last().ok_or_else(not_a_table)?;
    let mut item = root;
    for parent in parents {
        // Some(dotted) for a table, None for an inline table.
        let style = match &*item {
            Item::Table(table) => Some(table.is_dotted()),
            Item::Value(Value::InlineTable(_)) => None,
            _ => return Err(not_a_table()),
        };
        let table = item.as_table_like_mut().ok_or_else(not_a_table)?;
        item = table.entry(parent).or_insert_with(|| match style {
            Some(dotted) => {
                let mut child = Table::new();
                // No header until it holds values of its own.
                child.set_implicit(true);
                child.set_dotted(dotted);
                Item::Table(child)
            }
            None => Item::Value(Value::InlineTable(InlineTable::new())),
        });
    }
    let mut value: Value = value
        .to_string()
        .parse()
        .map_err(|e: toml_edit::TomlError| e.to_string())?;
    let table = item.as_table_like_mut().ok_or_else(not_a_table)?;
    match table.get_mut(key) {
        Some(Item::Value(old)) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        _ => {
            table.insert(key, Item::Value(value));
            // An inline table holds no comments; respace it so the new key
            // reads like the others.
            if let Some(inline) = item.as_inline_table_mut() {
                inline.fmt();
            }
        }
    }
    Ok(())
}

/// Remove the key at `path`, with the comments above it. A table left empty
/// goes too, and one left with only subtables loses its header.
/// Returns whether the key was present.
fn remove_key(table: &mut dyn TableLike, path: &[&str]) -> bool {
    match path {
        [] => false,
        [key] => table.remove(key).is_some(),
        [key, rest @ ..] => {
            let Some(child) = table.get_mut(key) else {
                return false;
            };
            if !child
                .as_table_like_mut()
                .is_some_and(|child| remove_key(child, rest))
            {
                return false;
            }
            if child.as_table_like().is_some_and(TableLike::is_empty) {
                table.remove(key);
            } else if let (Item::Table(child), [_]) = (child, rest) {
                if child.iter().all(|(_, item)| item.is_table()) {
                    child.set_implicit(true);
                }
            }
            true
        }
    }
}

/// Render an edited document. Removing the first entries can leave the
/// blank lines that separated them at the top; drop those unless the file
/// began with one.
fn render(document: &DocumentMut, original: &str) -> String {
    let text = document.to_string();
    if original.starts_with(['\n', '\r']) {
        text
    } else {
        text.trim_start_matches(['\n', '\r']).to_string()
    }
}

/// Replace the file at `path` with `contents` atomically: write a temporary
/// file beside it with the same permissions, sync it, rename it over the
/// file, and sync the directory.
pub fn write_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
        None => return Err("config path has no parent directory".into()),
    };
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    if let Ok(metadata) = std::fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())
            .map_err(|e| e.to_string())?;
    }
    temporary.write_all(contents).map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    temporary.persist(path).map_err(|e| e.error.to_string())?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    /// A hand-written file. The keys marked "repeat" equal the public preset.
    const FILE: &str = r#"# Example relay.
preset = "public"
observability.log_format = "pretty"   # repeat, as a dotted key
admin = { enabled = false, auth_window_secs = 30 }

[relay]
# Behind nginx.
bind = "127.0.0.1"                # repeat
real_ip_header = "x-real-ip"

[relay.abuse]
# Copied from the old sample.
event_burst = 100
invalid_burst = 20

[events]
max_num_tags = 8000
"#;

    const MINIMIZED: &str = r#"# Example relay.
preset = "public"
admin = { auth_window_secs = 30 }

[relay]
real_ip_header = "x-real-ip"

[events]
max_num_tags = 8000
"#;

    #[test]
    fn minimize_removes_exactly_the_keys_equal_to_the_preset() {
        let minimized = Config::minimize_toml(FILE).unwrap();
        assert_eq!(
            minimized.removed,
            [
                "admin.enabled",
                "observability.log_format",
                "relay.abuse.event_burst",
                "relay.abuse.invalid_burst",
                "relay.bind",
            ]
        );
        assert_eq!(minimized.text, MINIMIZED);
        assert_eq!(
            Config::parse_toml(MINIMIZED).unwrap().to_toml(),
            Config::parse_toml(FILE).unwrap().to_toml()
        );

        // A second pass finds nothing.
        let again = Config::minimize_toml(&minimized.text).unwrap();
        assert!(again.removed.is_empty());
        assert_eq!(again.text, MINIMIZED);
    }

    #[test]
    fn minimize_keeps_the_preset_and_deliberate_values() {
        let text = "preset = \"public\"\n[events]\nreject_older_than_secs = 94608000\n";
        let minimized = Config::minimize_toml(text).unwrap();
        assert!(minimized.removed.is_empty());
        assert_eq!(minimized.text, text);
        assert_eq!(Config::minimize_toml("").unwrap().text, "");
    }

    #[test]
    fn minimize_reduces_the_0_7_0_sample_to_its_replaced_defaults() {
        let sample = include_str!("testdata/wok-0.7.0.toml");
        let minimized = Config::minimize_toml(sample).unwrap();
        assert_eq!(
            minimized.text,
            "[events]\n\
             reject_older_than_secs = 94608000\n\
             max_num_tags = 2000\n\
             \n\
             [relay]\n\
             # Maximum combined compact-JSON bytes across all filters in one REQ/COUNT.\n\
             max_req_filter_size = 65536\n\
             max_filter_limit = 500\n\
             max_tags_per_filter = 3\n\
             # Zero means unlimited.\n\
             max_total_events_per_req = 2000\n\
             \n\
             [relay.auth]\n\
             restricted_read_kinds = [4, 1059]\n\
             \n\
             [relay.abuse]\n\
             req_rate_per_second = 20\n\
             req_burst = 40\n\
             count_rate_per_second = 5\n\
             count_burst = 10\n\
             # Zero means unlimited. Secure defaults bound both global and per-author use.\n\
             max_stored_events = 10000000\n\
             max_stored_events_per_pubkey = 100000\n"
        );
        // Every line left is one of the sample's, in its order.
        let mut remaining = sample.lines();
        for line in minimized.text.lines() {
            assert!(remaining.any(|kept| kept == line), "{line:?} is new");
        }
    }

    #[test]
    fn edit_adds_tables_in_the_style_of_their_parent() {
        let text = "relay.port = 9000\nadmin = { enabled = false }\n";
        let (edited, config) = Config::edit_toml(text, |config| {
            config.relay.abuse.event_burst = 500;
            config.admin.auth_window_secs = 30;
        })
        .unwrap();
        assert_eq!(
            edited,
            "relay.port = 9000\n\
             relay.abuse.event_burst = 500\n\
             admin = { enabled = false, auth_window_secs = 30 }\n"
        );
        assert_eq!(config.relay.abuse.event_burst, 500);
        assert_eq!(config.admin.auth_window_secs, 30);
    }

    #[test]
    fn edit_measures_preset_values_against_the_overlay() {
        let overlay = |_| "[relay.abuse]\nevent_burst = 300\n";
        // The overlay's value removes the key and the table it leaves empty.
        let (edited, config) =
            super::edit("[relay.abuse]\nevent_burst = 500\n", overlay, |config| {
                config.relay.abuse.event_burst = 300;
            })
            .unwrap();
        assert_eq!(edited, "");
        assert_eq!(config.relay.abuse.event_burst, 300);
        // The built-in default is an override under this preset.
        let (edited, _) = super::edit("", overlay, |config| {
            config.relay.abuse.event_burst = 100;
        })
        .unwrap();
        assert_eq!(edited, "[relay.abuse]\nevent_burst = 100\n");
    }

    #[test]
    fn edit_refuses_an_invalid_file() {
        let error = Config::edit_toml("[relay]\nport = \"x\"\n", |_| {}).unwrap_err();
        assert!(
            error.starts_with("the current file is invalid: "),
            "{error}"
        );
    }
}
