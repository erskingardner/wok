#![forbid(unsafe_code)]
//! Wok transport over the experimental FIPS native datagram API.

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos", test))]
mod session;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
use std::sync::Arc;
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
use wok_relay::{Config, RelayHandle};

#[derive(Debug, thiserror::Error)]
pub enum FipsError {
    #[error("native FIPS transport is supported only on Linux, FreeBSD, and macOS")]
    UnsupportedPlatform,
    #[error("FIPS native API: {0}")]
    Io(#[from] std::io::Error),
    #[error("FIPS message protocol: {0}")]
    Protocol(#[from] fips_message::ProtocolError),
    #[error("FIPS relay task failed: {0}")]
    Task(String),
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod native;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub use native::serve;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
pub async fn serve(_handle: RelayHandle, cfg: Arc<Config>) -> Result<(), FipsError> {
    if cfg.relay.fips.enabled {
        Err(FipsError::UnsupportedPlatform)
    } else {
        Ok(())
    }
}

#[cfg(all(
    test,
    not(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))
))]
mod unsupported_tests {
    use super::*;
    use wok_db::{Env, EnvOptions};

    #[tokio::test]
    async fn enabled_transport_fails_cleanly_on_an_unsupported_platform() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        config.relay.fips.enabled = true;
        let handle = wok_relay::start(env, config.clone()).unwrap();
        let result = serve(handle.clone(), Arc::new(config)).await;
        assert!(matches!(result, Err(FipsError::UnsupportedPlatform)));
        handle.request_shutdown();
    }
}
