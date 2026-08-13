//! Transport-neutral Nostr relay core.

pub mod capabilities;
pub mod config;
pub mod metrics;
pub mod plugin;
pub mod protocol;
pub mod restrict;
pub mod rlimit;
pub mod server;

pub use capabilities::{
    relay_capabilities, supported_nips, CapabilityCondition, RelayCapability,
    RELAY_CAPABILITY_CATALOG,
};
pub use config::{Config, EphemeralPersistence};
pub use protocol::{ClientCommand, RelayMessage};
pub use rlimit::apply_nofiles_limit;
pub use server::{start, Outbound, OutboundFrame, RelayHandle};
