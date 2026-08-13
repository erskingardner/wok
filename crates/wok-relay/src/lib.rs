//! Transport-neutral Nostr relay core.

pub mod config;
pub mod metrics;
pub mod plugin;
pub mod protocol;
pub mod restrict;
pub mod server;

pub use config::Config;
pub use protocol::{ClientCommand, RelayMessage};
pub use server::{start, supported_nips, Outbound, OutboundFrame, RelayHandle};
