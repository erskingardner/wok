use super::session::ServerSession;
use super::FipsError;
use fips::native::client::{FipsListener, FipsStream};
use fips_message::{chunk_message, Limits};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinSet;
use wok_relay::{Config, Outbound, OutboundFrame, RelayHandle, TransportSource};

pub async fn serve(handle: RelayHandle, cfg: Arc<Config>) -> Result<(), FipsError> {
    if !cfg.relay.fips.enabled {
        return Ok(());
    }
    let shutdown = handle.shutdown_handle();
    let mut backoff = Duration::from_millis(100);
    loop {
        if handle.is_shutdown() {
            return Ok(());
        }
        match FipsListener::bind_at(&cfg.relay.fips.socket_path, cfg.relay.fips.port) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                tracing::info!(
                    path = %cfg.relay.fips.socket_path.display(),
                    port = cfg.relay.fips.port,
                    transport = "fips",
                    "FIPS listener started"
                );
                backoff = Duration::from_millis(100);
                match run_listener(handle.clone(), Arc::clone(&cfg), listener).await {
                    Ok(()) if handle.is_shutdown() => return Ok(()),
                    Ok(()) => {
                        tracing::warn!(transport = "fips", "FIPS listener exited unexpectedly")
                    }
                    Err(error) => {
                        tracing::warn!(%error, transport = "fips", "FIPS listener failed; rebinding")
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, transport = "fips", "FIPS bind failed; retrying");
            }
        }
        tokio::select! {
            _ = shutdown.notified() => return Ok(()),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(Duration::from_secs(10));
    }
}

async fn run_listener(
    handle: RelayHandle,
    cfg: Arc<Config>,
    listener: FipsListener,
) -> Result<(), FipsError> {
    let listener = AsyncFd::new(listener)?;
    let shutdown = handle.shutdown_handle();
    let mut flows = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                flows.abort_all();
                return Ok(());
            }
            accepted = accept_available(&listener) => {
                for (stream, peer) in accepted? {
                    stream.set_nonblocking(true)?;
                    let source = TransportSource::Fips {
                        public_key: peer.key().serialize(),
                        port: peer.port(),
                    };
                    if !handle.admit_connection(&source) {
                        tracing::warn!(peer = %peer, transport = "fips", "FIPS connection rate-limited");
                        continue;
                    }
                    let handle = handle.clone();
                    let cfg = Arc::clone(&cfg);
                    flows.spawn(async move { run_flow(handle, cfg, stream, source).await });
                }
            }
            result = flows.join_next(), if !flows.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(FlowError::DaemonGone(error)))) => {
                        flows.abort_all();
                        return Err(FipsError::Io(error));
                    }
                    Some(Ok(Err(error))) => {
                        tracing::debug!(%error, transport = "fips", "FIPS flow ended");
                    }
                    Some(Err(error)) => {
                        return Err(FipsError::Task(error.to_string()));
                    }
                    None => {}
                }
            }
        }
    }
}

trait FlowListener: AsRawFd {
    type Stream;
    type Peer;

    fn accept_flow(&self) -> io::Result<(Self::Stream, Self::Peer)>;
}

impl FlowListener for FipsListener {
    type Stream = FipsStream;
    type Peer = fips::native::client::FipsAddr;

    fn accept_flow(&self) -> io::Result<(Self::Stream, Self::Peer)> {
        self.accept()
    }
}

async fn accept_available<L: FlowListener>(
    listener: &AsyncFd<L>,
) -> io::Result<Vec<(L::Stream, L::Peer)>> {
    let mut accepted = Vec::new();
    let mut ready = listener.readable().await?;
    loop {
        match ready.try_io(|inner| inner.get_ref().accept_flow()) {
            Ok(Ok(flow)) => accepted.push(flow),
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => return Ok(accepted),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum FlowError {
    #[error("FIPS daemon disappeared: {0}")]
    DaemonGone(io::Error),
    #[error("FIPS flow I/O: {0}")]
    Io(io::Error),
    #[error("FIPS protocol: {0}")]
    Protocol(#[from] fips_message::ProtocolError),
    #[error("FIPS logical message is not UTF-8")]
    Utf8,
}

async fn run_flow(
    handle: RelayHandle,
    cfg: Arc<Config>,
    stream: FipsStream,
    source: TransportSource,
) -> Result<(), FlowError> {
    let max_datagram = stream.max_payload();
    let stream = AsyncFd::new(stream).map_err(classify_io)?;
    let limits = message_limits(&cfg);
    let mut session = ServerSession::new(limits)?;
    let mut recv_buf = vec![0u8; max_datagram];
    let setup_timeout = Duration::from_secs(cfg.relay.fips.setup_timeout_secs);
    let opening = tokio::time::timeout(setup_timeout, recv_datagram(&stream, &mut recv_buf))
        .await
        .map_err(|_| FlowError::Protocol(fips_message::ProtocolError::SetupTimeout))?
        .map_err(classify_io)?;
    let output = session.receive(&recv_buf[..opening], Instant::now())?;
    if let Some(reply) = output.reply {
        send_datagram(&stream, &reply).await.map_err(classify_io)?;
    }
    let session_id = session.session().expect("HELLO established session");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
    let outbound = Outbound::new(tx, cfg.relay.fips.max_pending_outbound_bytes);
    let killed = outbound.killed();
    let connection = handle.register_connection(source.clone(), outbound).await;
    let conn_id = connection.conn_id();
    tracing::info!(
        conn_id,
        peer = %source.plugin_info(),
        transport = "fips",
        "client connected"
    );

    let mut outbound_message_id = 0u64;
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = 'session: loop {
        tokio::select! {
            _ = killed.notified() => break Ok(()),
            _ = expiry.tick() => {
                if let Err(error) = session.expire(Instant::now()) {
                    break Err(FlowError::Protocol(error));
                }
            }
            received = recv_datagram(&stream, &mut recv_buf) => {
                let len = match received {
                    Ok(len) => len,
                    Err(error) => break Err(classify_io(error)),
                };
                let output = match session.receive(&recv_buf[..len], Instant::now()) {
                    Ok(output) => output,
                    Err(error) => break Err(FlowError::Protocol(error)),
                };
                if let Some(reply) = output.reply {
                    if let Err(error) = send_datagram(&stream, &reply).await {
                        break Err(classify_io(error));
                    }
                }
                for message in output.messages {
                    let text = match String::from_utf8(message) {
                        Ok(text) => text,
                        Err(_) => break 'session Err(FlowError::Utf8),
                    };
                    connection.client_message(text).await;
                }
            }
            outbound = rx.recv() => {
                let Some(outbound) = outbound else { break Ok(()); };
                let datagrams = match chunk_message(
                    session_id,
                    outbound_message_id,
                    outbound.into_text().as_bytes(),
                    max_datagram,
                    limits,
                ) {
                    Ok(datagrams) => datagrams,
                    Err(error) => break Err(FlowError::Protocol(error)),
                };
                for datagram in datagrams {
                    if let Err(error) = send_datagram(&stream, &datagram).await {
                        break 'session Err(classify_io(error));
                    }
                }
                outbound_message_id = match outbound_message_id.checked_add(1) {
                    Some(next) => next,
                    None => break Err(FlowError::Protocol(fips_message::ProtocolError::MessageIdExhausted)),
                };
            }
        }
    };
    connection.close().await;
    tracing::info!(conn_id, transport = "fips", "client disconnected");
    result
}

fn message_limits(cfg: &Config) -> Limits {
    Limits {
        max_message_size: cfg.relay.max_websocket_payload_size,
        max_chunks: cfg.relay.fips.max_chunks,
        max_incomplete_messages: cfg.relay.fips.max_incomplete_messages,
        max_reassembly_bytes: cfg.relay.fips.max_reassembly_bytes,
        max_completed_messages: cfg.relay.fips.max_completed_messages,
        incomplete_timeout: Duration::from_secs(cfg.relay.fips.incomplete_message_timeout_secs),
    }
}

async fn recv_datagram(stream: &AsyncFd<FipsStream>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = stream.readable().await?;
        match ready.try_io(|inner| inner.get_ref().recv(buf)) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

async fn send_datagram(stream: &AsyncFd<FipsStream>, datagram: &[u8]) -> io::Result<()> {
    loop {
        let mut ready = stream.writable().await?;
        match ready.try_io(|inner| inner.get_ref().send(datagram)) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

fn classify_io(error: io::Error) -> FlowError {
    if error.raw_os_error() == Some(libc::EPIPE) {
        FlowError::DaemonGone(error)
    } else {
        FlowError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    struct TestListener {
        socket: UnixDatagram,
    }

    impl AsRawFd for TestListener {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.socket.as_raw_fd()
        }
    }

    impl FlowListener for TestListener {
        type Stream = u8;
        type Peer = ();

        fn accept_flow(&self) -> io::Result<(Self::Stream, Self::Peer)> {
            let mut value = [0];
            self.socket.recv(&mut value)?;
            Ok((value[0], ()))
        }
    }

    #[tokio::test]
    async fn readiness_is_drained_through_would_block() {
        let (reader, writer) = UnixDatagram::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        for value in [1, 2, 3] {
            writer.send(&[value]).unwrap();
        }
        let listener = AsyncFd::new(TestListener { socket: reader }).unwrap();
        let accepted = accept_available(&listener).await.unwrap();
        assert_eq!(
            accepted
                .into_iter()
                .map(|(value, ())| value)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn epipe_is_daemon_loss_and_other_io_is_per_flow() {
        let daemon = classify_io(io::Error::from_raw_os_error(libc::EPIPE));
        assert!(matches!(daemon, FlowError::DaemonGone(_)));
        let peer = classify_io(io::Error::from_raw_os_error(libc::ECONNRESET));
        assert!(matches!(peer, FlowError::Io(_)));
    }
}
