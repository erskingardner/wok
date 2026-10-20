//! `wok config show`: the effective configuration, one key per line, with
//! the layer each value came from.

use anyhow::{anyhow, Result};
use std::path::Path;
use wok_relay::config::{ConfigExplanation, Origin};
use wok_relay::Config;

/// Lines whose `key = value` part is longer than this are not used to align
/// the origin column, so one long array doesn't push every comment right.
const ALIGN_LIMIT: usize = 60;

/// Explain the config file at `path`. A missing file explains the built-in
/// defaults, which is what the relay would run with.
pub fn run(path: &Path, overrides_only: bool) -> Result<String> {
    let label = path.display();
    let (text, found) = match std::fs::read_to_string(path) {
        Ok(text) => (text, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(error) => return Err(anyhow!("{label}: {error}")),
    };
    let explanation = Config::explain_toml(&text).map_err(|error| anyhow!("{label}: {error}"))?;
    Ok(render(&explanation, path, found, overrides_only))
}

/// Render an explanation as TOML dotted keys with the origin of each value
/// in a trailing comment. The output parses as TOML. The header names the
/// file by its path, and each origin by its file name.
fn render(
    explanation: &ConfigExplanation,
    path: &Path,
    found: bool,
    overrides_only: bool,
) -> String {
    let preset = explanation.config.preset;
    let label = path.display();
    let file = path
        .file_name()
        .map_or_else(|| label.to_string(), |name| name.to_string_lossy().into());
    let mut out = if !found {
        format!("# {label} not found: built-in defaults (preset {preset})\n")
    } else if overrides_only {
        format!("# Keys {label} sets to a value other than preset {preset}'s\n")
    } else {
        format!("# Effective configuration of {label} (preset {preset})\n")
    };
    let lines: Vec<(String, String)> = explanation
        .entries
        .iter()
        .filter(|entry| !overrides_only || entry.is_override())
        .map(|entry| {
            let mut origin = match entry.origin {
                Origin::Default => "default".to_string(),
                Origin::Preset(preset) => format!("preset {preset}"),
                Origin::File { line: Some(line) } => format!("{file}:{line}"),
                Origin::File { line: None } => file.clone(),
            };
            if let Some(value) = &entry.preset_value {
                origin.push_str(&format!(" (preset {preset}: {value})"));
            }
            (format!("{} = {}", entry.key, entry.value), origin)
        })
        .collect();
    let width = lines
        .iter()
        .map(|(assignment, _)| assignment.len())
        .filter(|&len| len <= ALIGN_LIMIT)
        .max()
        .unwrap_or(0);
    for (assignment, origin) in lines {
        out.push_str(&format!("{assignment:<width$}  # {origin}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explain(text: &str) -> ConfigExplanation {
        Config::explain_toml(text).unwrap()
    }

    fn line_for<'a>(rendered: &'a str, key: &str) -> &'a str {
        let prefix = format!("{key} = ");
        rendered
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("no line for {key} in\n{rendered}"))
    }

    const FILE: &str = "preset = \"public\"\n\
                        \n\
                        [relay]\n\
                        port = 9000\n\
                        \n\
                        [relay.abuse]\n\
                        event_burst = 100\n";

    #[test]
    fn show_names_each_origin() {
        let rendered = render(&explain(FILE), Path::new("wok.toml"), true, false);
        assert!(rendered.starts_with("# Effective configuration of wok.toml (preset public)\n"));
        assert!(rendered
            .lines()
            .nth(1)
            .unwrap()
            .starts_with("preset = \"public\""));
        assert!(line_for(&rendered, "preset").ends_with("  # wok.toml:1"));
        assert!(line_for(&rendered, "relay.port").ends_with("  # wok.toml:4 (preset public: 7777)"));
        // Set in the file, but equal to the preset's value.
        assert!(line_for(&rendered, "relay.abuse.event_burst").ends_with("  # wok.toml:7"));
        assert!(line_for(&rendered, "relay.bind").ends_with("  # default"));
        assert!(line_for(&rendered, "relay.info.name")
            .starts_with("relay.info.name = \"wok default\" "));
        // The output is itself TOML that resolves to the same configuration.
        let reparsed = Config::parse_toml(&rendered).unwrap();
        assert_eq!(
            reparsed.to_toml().unwrap(),
            explain(FILE).config.to_toml().unwrap()
        );
    }

    #[test]
    fn overrides_lists_only_file_values_that_differ_from_the_preset() {
        let rendered = render(&explain(FILE), Path::new("/etc/wok/wok.toml"), true, true);
        assert_eq!(
            rendered,
            "# Keys /etc/wok/wok.toml sets to a value other than preset public's\n\
             relay.port = 9000  # wok.toml:4 (preset public: 7777)\n"
        );
    }

    #[test]
    fn missing_file_shows_the_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let rendered = run(&directory.path().join("absent.toml"), false).unwrap();
        assert!(rendered
            .lines()
            .next()
            .unwrap()
            .ends_with("not found: built-in defaults (preset public)"));
        assert!(rendered
            .lines()
            .skip(1)
            .all(|line| line.ends_with("  # default")));
        let overrides = run(&directory.path().join("absent.toml"), true).unwrap();
        assert_eq!(overrides.lines().count(), 1, "{overrides}");
    }

    #[test]
    fn invalid_file_names_the_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(&path, "preset = \"private\"\n").unwrap();
        let error = run(&path, false).unwrap_err().to_string();
        assert!(
            error.contains("wok.toml: unknown preset \"private\"; valid presets: public"),
            "{error}"
        );
    }
}
