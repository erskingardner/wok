//! Transport-neutral Nostr relay core.

pub mod config;
pub mod metrics;
pub mod plugin;
pub mod protocol;
pub mod restrict;
pub mod rlimit;
pub mod server;

pub use config::Config;
pub use protocol::{ClientCommand, RelayMessage};
pub use rlimit::apply_nofiles_limit;
pub use server::{start, supported_nips, Outbound, OutboundFrame, RelayHandle};
