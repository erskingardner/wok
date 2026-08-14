//! Length-prefixed Unix `SOCK_STREAM` Nostr transport.
//!
//! Frame: 4-byte big-endian payload length + UTF-8 JSON Nostr message.

#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use wok_relay::{Config, Outbound, OutboundFrame, RelayHandle};

#[derive(Debug, thiserror::Error)]
pub enum UnixError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Bind a Unix socket, replacing a stale socket path only after confirming it
/// is a socket and that no live listener owns it. `owner`/`group` (empty =
/// skip) chown the socket like a deployment would expect.
pub fn bind_unix(
    path: &Path,
    mode: u32,
    owner: &str,
    group: &str,
) -> Result<UnixListener, UnixError> {
    if path.exists() {
        let meta = std::fs::metadata(path)?;
        if !is_socket(&meta) {
            return Err(UnixError::Message(format!(
                "refusing to replace non-socket path {}",
                path.display()
            )));
        }
        if live_listener(path) {
            return Err(UnixError::Message(format!(
                "socket {} is in use by a live listener",
                path.display()
            )));
        }
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    if !owner.is_empty() || !group.is_empty() {
        let uid = if owner.is_empty() {
            None
        } else {
            Some(
                nix::unistd::User::from_name(owner)
                    .map_err(|e| UnixError::Message(format!("unknown unix.owner {owner:?}: {e}")))?
                    .ok_or_else(|| UnixError::Message(format!("unknown unix.owner {owner:?}")))?
                    .uid,
            )
        };
        let gid = if group.is_empty() {
            None
        } else {
            Some(
                nix::unistd::Group::from_name(group)
                    .map_err(|e| UnixError::Message(format!("unknown unix.group {group:?}: {e}")))?
                    .ok_or_else(|| UnixError::Message(format!("unknown unix.group {group:?}")))?
                    .gid,
            )
        };
        nix::unistd::chown(path, uid, gid)
            .map_err(|e| UnixError::Message(format!("chown {}: {e}", path.display())))?;
    }
    Ok(listener)
}

fn is_socket(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_socket()
}

fn live_listener(path: &Path) -> bool {
    StdUnixStream::connect(path).is_ok()
}

pub async fn serve(handle: RelayHandle, cfg: Config) -> Result<(), UnixError> {
    if !cfg.relay.unix.enabled {
        return Ok(());
    }
    let path = cfg.relay.unix.path.clone();
    let listener = bind_unix(
        &path,
        cfg.relay.unix.mode,
        &cfg.relay.unix.owner,
        &cfg.relay.unix.group,
    )?;
    tracing::info!("Unix socket listening on {}", path.display());
    let handle = Arc::new(handle);
    let shutdown = handle.shutdown_handle();
    let cfg = Arc::new(cfg);
    loop {
        let (stream, _addr) = tokio::select! {
            _ = shutdown.notified() => break,
            res = listener.accept() => match res {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("unix accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let handle = handle.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, handle, cfg).await {
                tracing::debug!("unix conn error: {e}");
            }
        });
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

async fn handle_conn(
    mut stream: UnixStream,
    handle: Arc<RelayHandle>,
    cfg: Arc<Config>,
) -> Result<(), UnixError> {
    if !peer_allowed(&stream, &cfg)? {
        return Err(UnixError::Message("peer credentials rejected".into()));
    }
    let conn_id = handle.next_conn_id();
    handle
        .metrics
        .active_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let max_frame = cfg.relay.unix.max_frame_bytes;
    // Outbound's byte accounting is the single queue bound. Keeping a second
    // message-count ceiling makes small historical frames fail prematurely.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
    let outbound = Outbound::new(tx, cfg.relay.unix.max_pending_outbound_bytes);
    let killed = outbound.killed();
    handle.register(conn_id, outbound).await;
    tracing::info!(conn_id, transport = "unix", "client connected");
    let mut len_buf = [0u8; 4];
    let result = async {
        loop {
            tokio::select! {
                _ = killed.notified() => {
                    tracing::debug!("[{conn_id}] unix: terminated slow client");
                    break;
                }
                read = stream.read_exact(&mut len_buf) => {
                    read?;
                    let n = u32::from_be_bytes(len_buf) as usize;
                    if n > max_frame {
                        return Err(UnixError::Message(format!("frame too large: {n}")));
                    }
                    let mut body = vec![0u8; n];
                    stream.read_exact(&mut body).await?;
                    let text = String::from_utf8(body)
                        .map_err(|_| UnixError::Message("frame not utf-8".into()))?;
                    handle.client_message(conn_id, Vec::new(), text).await;
                }
                out = rx.recv() => {
                    match out {
                        Some(frame) => {
                            write_frame(&mut stream, frame.into_text().as_bytes()).await?;
                        }
                        None => break,
                    }
                }
            }
        }
        Ok::<_, UnixError>(())
    }
    .await;
    handle.close(conn_id).await;
    handle
        .metrics
        .active_connections
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    tracing::info!(conn_id, transport = "unix", "client disconnected");
    result
}

pub async fn write_frame(stream: &mut UnixStream, body: &[u8]) -> Result<(), UnixError> {
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_frame(stream: &mut UnixStream, max: usize) -> Result<Vec<u8>, UnixError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > max {
        return Err(UnixError::Message(format!("frame too large: {n}")));
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

fn peer_allowed(stream: &UnixStream, cfg: &Config) -> Result<bool, UnixError> {
    if cfg.relay.unix.auth_uids.is_empty() && cfg.relay.unix.auth_gids.is_empty() {
        return Ok(true);
    }
    let (uid, gid) = peer_creds(stream)?;
    let uid_ok = cfg.relay.unix.auth_uids.is_empty() || cfg.relay.unix.auth_uids.contains(&uid);
    let gid_ok = cfg.relay.unix.auth_gids.is_empty() || cfg.relay.unix.auth_gids.contains(&gid);
    Ok(uid_ok && gid_ok)
}

/// (uid, gid) of the peer process.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_creds(stream: &UnixStream) -> Result<(u32, u32), UnixError> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|e| UnixError::Message(format!("SO_PEERCRED: {e}")))?;
    Ok((creds.uid(), creds.gid()))
}

/// (uid, gid) of the peer process.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_creds(stream: &UnixStream) -> Result<(u32, u32), UnixError> {
    let (uid, gid) = nix::unistd::getpeereid(stream)
        .map_err(|e| UnixError::Message(format!("getpeereid: {e}")))?;
    Ok((uid.as_raw(), gid.as_raw()))
}

/// Client helper: connect and send one JSON message, reading frames until timeout-free EOSE/OK.
pub async fn connect(path: impl AsRef<Path>) -> Result<UnixStream, UnixError> {
    Ok(UnixStream::connect(path).await?)
}

#[cfg(test)]
mod tests {
    use super::{bind_unix, read_frame, write_frame};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn frame_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = bind_unix(&path, 0o600, "", "").unwrap();
        let client = tokio::spawn({
            let path = path.clone();
            async move {
                let mut s = UnixStream::connect(path).await.unwrap();
                write_frame(&mut s, br#"["REQ","x",{"kinds":[1]}]"#)
                    .await
                    .unwrap();
                read_frame(&mut s, 1_000_000).await.unwrap()
            }
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let body = read_frame(&mut server, 1_000_000).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("REQ"));
        write_frame(&mut server, br#"["EOSE","x"]"#).await.unwrap();
        let got = client.await.unwrap();
        assert_eq!(got, br#"["EOSE","x"]"#);
    }

    #[tokio::test]
    async fn frame_handles_fragmented_writes() {
        use tokio::io::AsyncWriteExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frag.sock");
        let listener = bind_unix(&path, 0o600, "", "").unwrap();
        let client = tokio::spawn({
            let path = path.clone();
            async move {
                let mut s = UnixStream::connect(path).await.unwrap();
                let body = br#"["CLOSE","z"]"#;
                let len = (body.len() as u32).to_be_bytes();
                for b in len.iter().chain(body.iter()) {
                    s.write_all(&[*b]).await.unwrap();
                }
                s.flush().await.unwrap();
            }
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let body = read_frame(&mut server, 1_000_000).await.unwrap();
        assert_eq!(body, br#"["CLOSE","z"]"#);
        client.await.unwrap();
    }

    #[test]
    fn refuses_nonsocket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"hi").unwrap();
        assert!(bind_unix(&path, 0o600, "", "").is_err());
    }

    #[tokio::test]
    async fn replaces_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        {
            let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        }
        assert!(path.exists());
        bind_unix(&path, 0o600, "", "").expect("replace stale socket leftover");
    }
}
