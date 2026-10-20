//! Where each effective configuration value comes from: the built-in
//! defaults, the selected preset's overlay, or the operator's file.

use super::{Config, Layers, OverlayFn, Preset, TomlConfig};

/// The layer that supplied an effective configuration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A built-in default. The built-in defaults are the public preset.
    Default,
    /// The selected preset's overlay.
    Preset(Preset),
    /// The operator's file, with the 1-based line of the key when it could
    /// be located.
    File { line: Option<usize> },
}

/// One effective configuration value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    /// Dotted key path, such as `relay.abuse.event_burst`.
    pub key: String,
    /// The effective value, encoded as TOML.
    pub value: String,
    pub origin: Origin,
    /// The value the preset alone gives, when the file sets a different one.
    pub preset_value: Option<String>,
}

impl ConfigEntry {
    /// True when the operator's file sets this key to a value that differs
    /// from the preset's.
    pub fn is_override(&self) -> bool {
        self.preset_value.is_some()
    }
}

/// The effective configuration of one TOML file, key by key.
#[derive(Debug, Clone)]
pub struct ConfigExplanation {
    /// The resolved configuration, as [`Config::parse_toml`] returns it.
    pub config: Config,
    /// Every leaf key, `preset` first and the rest sorted by key.
    pub entries: Vec<ConfigEntry>,
}

pub(super) fn explain(text: &str, overlay_of: OverlayFn) -> Result<ConfigExplanation, String> {
    let layers = Layers::parse(text, overlay_of)?;
    let config = layers.resolve()?;
    let effective =
        toml::Value::try_from(TomlConfig::from(config.clone())).map_err(|e| e.to_string())?;
    // Round-trip the preset layer through its typed form so its values are
    // encoded exactly like the effective ones.
    let preset: TomlConfig = layers
        .preset_value()?
        .try_into()
        .map_err(|e: toml::de::Error| e.to_string())?;
    let preset = toml::Value::try_from(preset).map_err(|e| e.to_string())?;
    // `toml` already accepted the text, so this only fails if the two
    // parsers disagree; values then keep their file origin without a line.
    let document = toml_edit::ImDocument::parse(text).ok();

    let mut leaves = Vec::new();
    flatten(&effective, &mut Vec::new(), &mut leaves);
    let mut entries: Vec<ConfigEntry> = leaves
        .into_iter()
        .map(|(path, value)| {
            let origin = if leaf(&layers.file, &path).is_some() {
                Origin::File {
                    line: document
                        .as_ref()
                        .and_then(|document| key_line(document, &path)),
                }
            } else if leaf(&layers.overlay, &path).is_some() {
                Origin::Preset(layers.preset)
            } else {
                Origin::Default
            };
            let preset_value = match origin {
                Origin::File { .. } => leaf(&preset, &path)
                    .filter(|preset_value| *preset_value != value)
                    .map(ToString::to_string),
                _ => None,
            };
            ConfigEntry {
                key: path.join("."),
                value: value.to_string(),
                origin,
                preset_value,
            }
        })
        .collect();
    entries.sort_by(|a, b| (a.key != "preset", &a.key).cmp(&(b.key != "preset", &b.key)));
    Ok(ConfigExplanation { config, entries })
}

/// Collect every non-table value under `value` with its key path.
fn flatten<'a>(
    value: &'a toml::Value,
    path: &mut Vec<&'a str>,
    out: &mut Vec<(Vec<&'a str>, &'a toml::Value)>,
) {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                path.push(key);
                flatten(value, path, out);
                path.pop();
            }
        }
        value => out.push((path.clone(), value)),
    }
}

/// The non-table value at `path`, if this layer sets one.
fn leaf<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    let found = path
        .iter()
        .try_fold(value, |value, key| value.as_table()?.get(*key))?;
    (!found.is_table()).then_some(found)
}

/// The 1-based line on which the file sets `path`.
fn key_line(document: &toml_edit::ImDocument<&str>, path: &[&str]) -> Option<usize> {
    let (last, parents) = path.split_last()?;
    let mut table: &dyn toml_edit::TableLike = document.as_table();
    for key in parents {
        table = table.get(key)?.as_table_like()?;
    }
    let (key, _) = table.get_key_value(last)?;
    let start = key.span()?.start;
    Some(document.raw()[..start].matches('\n').count() + 1)
}
