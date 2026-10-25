//! Named configuration presets.
//!
//! A preset is a TOML overlay on the built-in defaults, selected with the
//! top-level `preset` key. Configuration resolves in three layers: built-in
//! defaults, then the preset's overlay, then the operator's file. Overlays
//! ship in the binary from `crates/wok-relay/presets/` and are mirrored in
//! `docs/presets/`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A named configuration preset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// A general public relay. Its values are the built-in defaults.
    #[default]
    Public,
    /// A relay dedicated to Marmot group messaging.
    Marmot,
}

impl Preset {
    /// Every preset, in the order error messages list them.
    pub const ALL: &'static [Preset] = &[Preset::Public, Preset::Marmot];

    /// The name the `preset` key uses.
    pub fn name(self) -> &'static str {
        match self {
            Preset::Public => "public",
            Preset::Marmot => "marmot",
        }
    }

    /// Who the preset is for and what it does, in a few sentences.
    pub fn summary(self) -> &'static str {
        match self {
            Preset::Public => {
                "A general public relay that any client can read from and write to: feeds, \
                 threads and outbox lookups. Its values are Wok's built-in defaults."
            }
            Preset::Marmot => {
                "A relay dedicated to Marmot group messaging, such as one a Marmot app ships \
                 as a default. It accepts only the Marmot kinds, needs every filter to name \
                 ids, authors or a tag, takes 4 MiB events, turns off COUNT and \
                 permessage-deflate, which Marmot clients do not use, sizes NIP-77 sync \
                 limits to their per-group syncs, and leaves writes open so the relay \
                 cannot link group messages to their senders. It needs \
                 relay.auth.service_url, because recipients read their gift wraps after \
                 NIP-42 AUTH."
            }
        }
    }

    /// The preset's overlay: only the keys it changes from the built-in
    /// defaults.
    pub fn overlay(self) -> &'static str {
        match self {
            Preset::Public => include_str!("../../presets/public.toml"),
            Preset::Marmot => include_str!("../../presets/marmot.toml"),
        }
    }

    /// Read the `preset` key of an operator's file. An absent key selects
    /// the public preset.
    pub(super) fn select(file: &toml::Value) -> Result<Self, String> {
        match file.get("preset") {
            None => Ok(Self::default()),
            Some(toml::Value::String(name)) => name.parse(),
            Some(other) => Err(format!(
                "preset must be a string naming one of: {}; got {other}",
                names()
            )),
        }
    }
}

impl FromStr for Preset {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|preset| preset.name() == name)
            .ok_or_else(|| format!("unknown preset {name:?}; valid presets: {}", names()))
    }
}

impl fmt::Display for Preset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

fn names() -> String {
    Preset::ALL
        .iter()
        .map(|preset| preset.name())
        .collect::<Vec<_>>()
        .join(", ")
}
