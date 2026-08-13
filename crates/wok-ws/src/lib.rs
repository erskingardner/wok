//! HTTP + WebSocket transport matching C++ `RelayWebsocket.cpp`.
//!
//! The WebSocket framing is a small in-house RFC 6455 + RFC 7692 codec
//! (`frame` module) so wok can offer permessage-deflate like C++ uWS
//! (tungstenite and fastwebsockets have no extension support).

pub mod frame;

use bytes::Bytes;
use frame::{
    read_events, write_bytes, DeflateCtx, InflateCtx, MessageKind, WsEncoder, WsEvent, WsParser,
    OP_PING, OP_PONG,
};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::UPGRADE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha1::Digest as _;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use wok_relay::{supported_nips, Config, Outbound, OutboundFrame, RelayHandle};

const SOFTWARE: &str = "git+https://github.com/erskingardner/wok.git";
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn serve(handle: RelayHandle, bind: SocketAddr) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(bind).await?;
    serve_listener(handle, listener).await
}

pub async fn serve_listener(
    handle: RelayHandle,
    listener: TcpListener,
) -> Result<(), std::io::Error> {
    tracing::info!("Started websocket server on {}", listener.local_addr()?);
    let handle = Arc::new(handle);
    let shutdown = handle.shutdown_handle();
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.notified() => break,
            res = listener.accept() => match res {
                Ok(x) => x,
                Err(e) => {
                    // Transient accept failures (e.g. fd exhaustion) must not
                    // kill the listener task.
                    tracing::warn!("ws accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        if handle.config.read().relay.enable_tcp_keepalive {
            let sock_ref = socket2::SockRef::from(&stream);
            let _ = sock_ref.set_keepalive(true);
        }
        let handle = handle.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let handle = handle.clone();
                async move { Ok::<_, Infallible>(dispatch(req, handle, peer).await) }
            });
            let _ = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        });
    }
    tracing::info!("Websocket listener stopped");
    Ok(())
}

async fn dispatch(
    req: Request<Incoming>,
    handle: Arc<RelayHandle>,
    peer: SocketAddr,
) -> Response<Full<Bytes>> {
    // Honor relay.realIpHeader for reverse-proxied deployments (C++ strfry
    // uses the header value as the client IP).
    let real_ip_header = handle.config.read().relay.real_ip_header.clone();
    let peer = if real_ip_header.is_empty() {
        peer
    } else {
        req.headers()
            .get(real_ip_header.as_str())
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 0))
            .unwrap_or(peer)
    };
    let is_ws_upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws_upgrade {
        let ip = match peer.ip() {
            std::net::IpAddr::V4(value) => value.octets().to_vec(),
            std::net::IpAddr::V6(value) => value.octets().to_vec(),
        };
        if !handle.admit_connection(&ip) {
            return text_status_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate-limited: connection budget exhausted",
            );
        }
        return upgrade_ws(req, handle, peer).await;
    }
    let path = req.uri().path().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let accept = req
        .headers()
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cfg = handle.config.read().clone();
    if path == "/metrics" {
        return text_response("text/plain; version=0.0.4", handle.metrics.render());
    }
    if path == "/.well-known/nodeinfo" {
        let body = serde_json::json!({
            "links": [{
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                "href": format!("https://{host}/nodeinfo/2.1"),
            }]
        });
        return json_response(&body);
    }
    if path == "/nodeinfo/2.1" {
        let body = serde_json::json!({
            "version": "2.1",
            "software": {
                "name": "wok",
                "version": VERSION,
                "repository": "https://github.com/erskingardner/wok",
                "homepage": "https://github.com/erskingardner/wok",
            },
            "protocols": ["nostr"],
            "services": { "inbound": [], "outbound": [] },
            "openRegistrations": false,
            "usage": { "users": {} },
            "metadata": { "features": ["nostr_relay"] },
        });
        return json_response(&body);
    }
    if path == "/favicon.ico" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "image/x-icon")
            .header("Cache-Control", "public, max-age=31536000")
            .header("Access-Control-Allow-Origin", "*")
            .body(Full::new(Bytes::from_static(&[0, 0, 1, 0])))
            .unwrap_or_else(|_| empty(StatusCode::OK));
    }
    if accept == "application/nostr+json" {
        return json_response(&nip11(&cfg, &handle));
    }
    html_response(&landing(&cfg, &handle))
}

fn maybe_npub(s: &str) -> String {
    // NIP-11 accepts npub or hex; C++ converts npub to hex.
    if s.starts_with("npub1") {
        if let Ok(pk) = wok_event::decode_npub(s) {
            return hex::encode(pk);
        }
    }
    s.to_string()
}

fn nip11(cfg: &Config, handle: &RelayHandle) -> serde_json::Value {
    let min_pow_difficulty = if cfg.relay.abuse.enabled {
        cfg.relay.abuse.min_pow_difficulty
    } else {
        0
    };
    let mut v = serde_json::json!({
        "supported_nips": supported_nips(cfg),
        "software": SOFTWARE,
        "version": VERSION,
        "negentropy": PROTOCOL_NEG,
        "limitation": {
            "max_message_length": cfg.relay.max_websocket_payload_size,
            "max_subscriptions": cfg.relay.max_subs_per_connection,
            "max_limit": cfg.relay.max_filter_limit,
            "max_total_events_per_req": cfg.relay.max_total_events_per_req,
            "max_event_tags": cfg.events.max_num_tags,
            "created_at_lower_limit": cfg.events.reject_older_than_secs,
            "created_at_upper_limit": cfg.events.reject_newer_than_secs,
            "default_limit": cfg.relay.max_filter_limit,
            "min_pow_difficulty": min_pow_difficulty,
            "max_query_cost": cfg.relay.abuse.max_query_cost,
            "max_concurrent_historical_queries": cfg.relay.abuse.max_concurrent_historical_queries,
        }
    });
    let info = &cfg.relay.info;
    if !info.name.is_empty() {
        v["name"] = serde_json::json!(info.name);
    }
    if !info.description.is_empty() {
        v["description"] = serde_json::json!(info.description);
    }
    if !info.contact.is_empty() {
        v["contact"] = serde_json::json!(info.contact);
    }
    if !info.pubkey.is_empty() {
        v["pubkey"] = serde_json::json!(maybe_npub(&info.pubkey));
    }
    if !info.icon.is_empty() {
        v["icon"] = serde_json::json!(info.icon);
    }
    if !info.banner.is_empty() {
        v["banner"] = serde_json::json!(info.banner);
    }
    if !info.self_pk.is_empty() {
        v["self"] = serde_json::json!(maybe_npub(&info.self_pk));
    }
    if !info.privacy.is_empty() {
        v["privacy_policy"] = serde_json::json!(info.privacy);
    }
    if !info.terms.is_empty() {
        v["terms_of_service"] = serde_json::json!(info.terms);
    }
    let _ = handle;
    v
}

const PROTOCOL_NEG: u64 = 1;

fn landing(cfg: &Config, handle: &RelayHandle) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>wok</title><h1>{}</h1><p>{}</p><p>nips: {:?}</p><p>version {VERSION}</p>",
        html_escape(&cfg.relay.info.name),
        html_escape(&cfg.relay.info.description),
        handle.supported_nips(),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn json_response(v: &serde_json::Value) -> Response<Full<Bytes>> {
    let body = v.to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Server", "wok")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| empty(StatusCode::OK))
}

fn text_response(ct: &str, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", ct)
        .header("Access-Control-Allow-Origin", "*")
        .header("Server", "wok")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| empty(StatusCode::OK))
}

fn text_status_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Access-Control-Allow-Origin", "*")
        .header("Server", "wok")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .unwrap_or_else(|_| empty(status))
}

fn html_response(body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .header("Access-Control-Allow-Origin", "*")
        .header("Server", "wok")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| empty(StatusCode::OK))
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn upgrade_ws(
    mut req: Request<Incoming>,
    handle: Arc<RelayHandle>,
    peer: SocketAddr,
) -> Response<Full<Bytes>> {
    let key = match req.headers().get("sec-websocket-key") {
        Some(k) => k.clone(),
        None => return empty(StatusCode::BAD_REQUEST),
    };
    // RFC 6455: only version 13 is supported.
    match req
        .headers()
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
    {
        Some("13") => {}
        _ => return empty(StatusCode::BAD_REQUEST),
    }
    // permessage-deflate negotiation mirroring uWS as strfry configures it:
    // respond with plain `permessage-deflate` (context takeover per
    // compression.slidingWindow), echoing client_no_context_takeover.
    let (compression_on, sliding) = {
        let cfg = handle.config.read();
        (
            cfg.relay.compression_enabled,
            cfg.relay.compression_sliding_window,
        )
    };
    let mut ext_response: Option<String> = None;
    if compression_on {
        if let Some(offer) = req
            .headers()
            .get("sec-websocket-extensions")
            .and_then(|v| v.to_str().ok())
        {
            if offer
                .split(';')
                .next()
                .map(|t| t.trim().eq_ignore_ascii_case("permessage-deflate"))
                .unwrap_or(false)
            {
                let mut resp = "permessage-deflate".to_string();
                if offer
                    .split(';')
                    .skip(1)
                    .any(|t| t.trim().eq_ignore_ascii_case("client_no_context_takeover"))
                {
                    resp.push_str("; client_no_context_takeover");
                }
                ext_response = Some(resp);
            }
        }
    }
    let cfg_snap = handle.config.read().clone();
    let max = cfg_snap.relay.max_websocket_payload_size;
    let deflate = ext_response.is_some();
    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                handle_ws(io, handle, peer, max, sliding, deflate).await;
            }
            Err(e) => tracing::warn!("ws upgrade failed: {e}"),
        }
    });
    let accept = ws_accept_key(key.as_bytes());
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept);
    if let Some(ext) = ext_response {
        builder = builder.header("Sec-WebSocket-Extensions", ext);
    }
    builder
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| empty(StatusCode::SWITCHING_PROTOCOLS))
}

/// `Sec-WebSocket-Accept`: base64(SHA1(key || RFC6455 magic)).
fn ws_accept_key(key: &[u8]) -> String {
    let mut h = sha1::Sha1::new();
    h.update(key);
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.finalize())
}

async fn handle_ws<S>(
    stream: S,
    handle: Arc<RelayHandle>,
    peer: SocketAddr,
    max_message: usize,
    sliding: bool,
    deflate: bool,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let conn_id = handle.next_conn_id();
    handle
        .metrics
        .active_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ip = match peer.ip() {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    };
    let auto_ping = handle.config.read().relay.auto_ping_seconds;
    // Pending memory is bounded by max_pending_outbound_bytes in Outbound.
    // A second message-count bound incorrectly disconnected healthy clients
    // during bursty historical responses with many small events.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
    let max_pending = handle.config.read().relay.max_pending_outbound_bytes;
    let outbound = Outbound::new(tx, max_pending);
    let killed = outbound.killed();
    handle.register(conn_id, outbound).await;
    tracing::info!(conn_id, peer = %peer, transport = "websocket", "client connected");
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut parser = WsParser::new(
        max_message,
        if deflate {
            Some(InflateCtx::new(sliding))
        } else {
            None
        },
    );
    let mut encoder = WsEncoder::new(if deflate {
        Some(DeflateCtx::new(sliding))
    } else {
        None
    });
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(auto_ping.max(1)));
    if auto_ping > 0 {
        ping.tick().await; // first tick is immediate; skip it
    }
    'outer: loop {
        tokio::select! {
            _ = killed.notified() => {
                tracing::info!(conn_id, peer = %peer, reason = "slow_client", "client terminated");
                break;
            }
            _ = ping.tick(), if auto_ping > 0 => {
                if write_bytes(&mut wr, &encoder.encode_control(OP_PING, &[])).await.is_err() {
                    break;
                }
            }
            incoming = read_events(&mut rd, &mut parser) => {
                match incoming {
                    Ok(events) => {
                        for ev in events {
                            match ev {
                                WsEvent::Message(MessageKind::Text, t) => {
                                    match String::from_utf8(t) {
                                        Ok(text) => handle.client_message(conn_id, ip.clone(), text).await,
                                        Err(_) => handle.client_message(conn_id, ip.clone(), "x".into()).await,
                                    }
                                }
                                WsEvent::Message(MessageKind::Binary, b) => {
                                    match String::from_utf8(b) {
                                        Ok(text) => handle.client_message(conn_id, ip.clone(), text).await,
                                        Err(_) => handle.client_message(conn_id, ip.clone(), "x".into()).await,
                                    }
                                }
                                WsEvent::Ping(p) => {
                                    if write_bytes(&mut wr, &encoder.encode_control(OP_PONG, &p)).await.is_err() {
                                        break 'outer;
                                    }
                                }
                                WsEvent::Pong(_) => {}
                                WsEvent::Close(c) => {
                                    let _ = write_bytes(&mut wr, &encoder.encode_control(frame::OP_CLOSE, &c)).await;
                                    break 'outer;
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            out = rx.recv() => {
                match out {
                    Some(frame) => {
                        let bytes = match encoder.encode_message(MessageKind::Text, frame.into_text().as_bytes()) {
                            Ok(b) => b,
                            Err(_) => break,
                        };
                        if write_bytes(&mut wr, &bytes).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    handle.close(conn_id).await;
    handle
        .metrics
        .active_connections
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    tracing::info!(conn_id, peer = %peer, transport = "websocket", "client disconnected");
}
