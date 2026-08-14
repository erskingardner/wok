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
///
/// The socket is bound at a sibling temp path, chmod/chowned there, and
/// atomically renamed into place: the final path never exists with
/// umask-derived permissions (no bind→chmod race window), and the stale
/// socket is replaced by a single rename syscall rather than a
/// check-then-remove-then-bind sequence.
pub fn bind_unix(
    path: &Path,
    mode: u32,
    owner: &str,
    group: &str,
) -> Result<UnixListener, UnixError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Non-following metadata: refuse to replace symlinks or non-sockets.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !is_socket(&meta) {
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
    }
    let tmp = bind_temp_path(path);
    let _ = std::fs::remove_file(&tmp); // leftover from a previous crash
    let listener = UnixListener::bind(&tmp)?;
    // Best-effort cleanup of the temp path on any error below; after the
    // rename the path no longer exists and this is a no-op.
    struct TmpGuard<'a>(&'a Path);
    impl Drop for TmpGuard<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _guard = TmpGuard(&tmp);
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
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
        nix::unistd::chown(&tmp, uid, gid)
            .map_err(|e| UnixError::Message(format!("chown {}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(listener)
}

/// Sibling temp path used for bind-then-rename; never the final socket path.
fn bind_temp_path(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wok.sock".into());
    path.with_file_name(format!(".{name}.bind-{}", std::process::id()))
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
    // Identity of this process's socket (dev+ino), re-checked before the
    // shutdown unlink so we never delete a path someone else swapped in.
    let bound_stat = nix::sys::stat::fstat(std::os::fd::AsRawFd::as_raw_fd(&listener))
        .map_err(|e| UnixError::Message(format!("fstat listener: {e}")))?;
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
    // Unlink only if the path still refers to this process's socket.
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        use std::os::unix::fs::MetadataExt;
        if is_socket(&meta)
            && meta.dev() == bound_stat.st_dev as u64
            && meta.ino() == bound_stat.st_ino
        {
            let _ = std::fs::remove_file(&path);
        }
    }
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
    let source: Arc<[u8]> = Arc::from([]);
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
                    handle.client_message(conn_id, source.clone(), text).await;
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

    #[test]
    fn refuses_symlink_even_pointing_at_socket() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&real).unwrap();
        let link = dir.path().join("link.sock");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(bind_unix(&link, 0o600, "", "").is_err());
    }

    #[tokio::test]
    async fn socket_has_requested_mode_and_no_temp_leftovers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mode.sock");
        let _listener = bind_unix(&path, 0o640, "", "").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        // The bind-temp sibling must be gone after a successful bind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".bind-"))
            .collect();
        assert!(leftovers.is_empty(), "temp bind paths left behind");
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
