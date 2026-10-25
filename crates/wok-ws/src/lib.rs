//! HTTP + WebSocket transport matching C++ `RelayWebsocket.cpp`.
//!
//! The WebSocket framing is a small in-house RFC 6455 + RFC 7692 codec
//! (`frame` module) so wok can offer permessage-deflate like C++ uWS
//! (tungstenite and fastwebsockets have no extension support).

#![forbid(unsafe_code)]

mod admin;
pub mod forwarded;
pub mod frame;
mod nip86;

use bytes::Bytes;
use forwarded::Forwarded;
use frame::{
    read_events_into, write_bytes, DeflateCtx, InflateCtx, MessageKind, ReadDeadlines, WsEncoder,
    WsEvent, WsParser, OP_PING, OP_PONG,
};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::UPGRADE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use sha1::Digest as _;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use wok_relay::{
    supported_nips, Config, HeldMessages, Outbound, OutboundFrame, RelayHandle, TransportSource,
};

/// NIP-11 `software` MUST be the project's homepage URL.
const SOFTWARE: &str = "https://github.com/erskingardner/wok";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("WOK_GIT_HASH");
pub(crate) const WOK_MARK_SVG: &str = r##"<svg viewBox="0 0 1028 1028" aria-hidden="true" focusable="false"><rect width="1028" height="1028" fill="#090B0F"/><path fill="currentColor" d="M299.15 797.05C278.15 797.05 260 791.65 244.7 780.85C229.7 769.75 217.1 754 206.9 733.6C196.7 712.9 188 688.15 180.8 659.35C176.9 643.45 173.3 625.6 170 605.8C167 585.7 164.3 564.55 161.9 542.35C159.8 520.15 158 497.65 156.5 474.85C155.3 452.05 154.4 429.7 153.8 407.8C153.5 385.9 153.35 365.5 153.35 346.6C153.35 333.4 153.95 320.95 155.15 309.25C156.65 297.25 159.5 286.75 163.7 277.75C167.9 268.45 173.9 261.25 181.7 256.15C189.5 250.75 199.7 248.05 212.3 248.05C232.4 248.05 246.65 253.6 255.05 264.7C263.75 275.8 269 291.85 270.8 312.85C271.1 334.15 271.55 354.25 272.15 373.15C272.75 391.75 273.5 409.6 274.4 426.7C275.3 443.5 276.2 460 277.1 476.2C278.3 492.1 279.65 507.85 281.15 523.45C282.65 539.05 284.3 554.95 286.1 571.15C289.4 601.15 294.65 623.95 301.85 639.55C309.05 655.15 318.65 662.95 330.65 662.95C342.65 662.95 352.25 655.75 359.45 641.35C366.65 626.95 373.7 604.6 380.6 574.3C384.2 558.1 387.8 540.85 391.4 522.55C395 504.25 398.6 485.65 402.2 466.75C405.8 447.55 409.4 428.95 413 410.95C416.6 392.65 419.9 375.4 422.9 359.2C430.7 319.9 441.35 289.6 454.85 268.3C468.65 247 488.6 236.35 514.7 236.35C530 236.35 542.75 241.75 552.95 252.55C563.45 263.35 572.15 277.75 579.05 295.75C585.95 313.75 591.8 333.4 596.6 354.7C599.3 368.2 602 382.15 604.7 396.55C607.4 410.95 610.1 425.5 612.8 440.2C615.5 454.9 618.2 469.6 620.9 484.3C623.6 499 626.15 513.4 628.55 527.5C630.95 541.3 633.2 554.5 635.3 567.1C640.1 596.2 645.2 618.25 650.6 633.25C656.3 648.25 665.3 655.75 677.6 655.75C689 655.75 698.3 647.8 705.5 631.9C713 615.7 719.45 594.7 724.85 568.9C728.15 553.9 731.15 537.7 733.85 520.3C736.85 502.6 739.4 484.45 741.5 465.85C743.9 446.95 746 428.5 747.8 410.5C749.9 392.2 751.7 374.95 753.2 358.75C754.7 342.25 756.05 327.55 757.25 314.65C759.05 302.95 762.05 292.9 766.25 284.5C770.45 275.8 776.75 269.05 785.15 264.25C793.55 259.15 804.65 256.6 818.45 256.6C828.95 256.6 837.65 258.7 844.55 262.9C851.75 267.1 857.45 272.95 861.65 280.45C865.85 287.65 868.85 296.2 870.65 306.1C872.45 315.7 873.35 326.35 873.35 338.05C873.35 353.65 872.6 372.55 871.1 394.75C869.6 416.65 867.35 440.2 864.35 465.4C861.65 490.6 858.05 515.95 853.55 541.45C849.35 566.65 844.4 590.65 838.7 613.45C833.3 635.95 827.15 655.6 820.25 672.4C805.25 710.8 786.8 740.2 764.9 760.6C743 780.7 719 790.75 692.9 790.75C663.8 790.75 640.7 782.2 623.6 765.1C606.5 747.7 592.55 720.55 581.75 683.65C579.05 671.95 576.35 659.95 573.65 647.65C570.95 635.05 568.25 622.15 565.55 608.95C563.15 595.75 560.6 582.25 557.9 568.45C555.2 554.35 552.5 540.1 549.8 525.7C547.4 511 545 496.15 542.6 481.15C538.1 453.55 533.45 431.5 528.65 415C523.85 398.2 517.4 389.8 509.3 389.8C501.5 389.8 494.75 398.65 489.05 416.35C483.65 433.75 478.4 455.2 473.3 480.7C465.8 517.9 458.6 554.05 451.7 589.15C445.1 623.95 437 656.35 427.4 686.35C416.9 714.25 405.5 736.3 393.2 752.5C380.9 768.4 366.95 779.8 351.35 786.7C336.05 793.6 318.65 797.05 299.15 797.05Z"/></svg>"##;

/// Binds `relay.bind` / `relay.port`.
///
/// `host` is an IPv4 literal, an IPv6 literal (bare or bracketed), or a
/// hostname. A literal binds exactly that address. A hostname binds every
/// address it resolves to (`localhost` → `127.0.0.1` and `::1`); resolved
/// addresses that are not assigned on this host, or whose family it lacks,
/// are skipped with a warning, but at least one must bind. With port 0 every listener shares the port
/// assigned to the first.
pub async fn bind_listeners(host: &str, port: u16) -> std::io::Result<Vec<TcpListener>> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| bind_error(addr, e))?;
        return Ok(vec![listener]);
    }
    let mut resolved: Vec<SocketAddr> = Vec::new();
    let lookup = tokio::net::lookup_host((unbracketed, port))
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("resolve {host:?}: {e}")))?;
    for addr in lookup {
        if !resolved.contains(&addr) {
            resolved.push(addr);
        }
    }
    let mut listeners = Vec::new();
    let mut port = port;
    let mut skipped = None;
    for mut addr in resolved {
        addr.set_port(port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                port = listener.local_addr()?.port();
                listeners.push(listener);
            }
            Err(e) if is_unusable_address(&e) => {
                tracing::warn!("skipping websocket listener on {addr}: {e}");
                skipped.get_or_insert(bind_error(addr, e));
            }
            Err(e) => return Err(bind_error(addr, e)),
        }
    }
    if listeners.is_empty() {
        return Err(skipped.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{host:?} resolved to no addresses"),
            )
        }));
    }
    Ok(listeners)
}

fn bind_error(addr: SocketAddr, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("bind {addr}: {e}"))
}

/// The address is not assigned on this host, or its whole family is absent,
/// e.g. `::1` from `/etc/hosts` on a machine with IPv6 disabled. Linux
/// reports an unassigned address and `disable_ipv6=1` with the same errno,
/// so the two cannot be told apart.
fn is_unusable_address(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrNotAvailable || e.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

/// Serves every listener until shutdown. NIP-98 replay state is shared, so
/// an admin token accepted on one listener cannot be replayed on another.
pub async fn serve(handle: RelayHandle, listeners: Vec<TcpListener>) -> std::io::Result<()> {
    let handle = Arc::new(handle);
    let admin_state = Arc::new(admin::AdminState::default());
    futures_util::future::try_join_all(
        listeners
            .into_iter()
            .map(|listener| accept_loop(handle.clone(), listener, admin_state.clone())),
    )
    .await?;
    Ok(())
}

fn configure_accepted_stream(stream: &tokio::net::TcpStream, peer: SocketAddr, keepalive: bool) {
    // Relay responses are commonly a sequence of small EVENT frames followed
    // by EOSE. Nagle's algorithm can otherwise combine with delayed ACKs to
    // add a roughly 40 ms pause between those frames on Linux.
    if let Err(error) = stream.set_nodelay(true) {
        tracing::warn!(%peer, %error, "failed to enable TCP_NODELAY");
    }
    if keepalive {
        let sock_ref = socket2::SockRef::from(stream);
        let _ = sock_ref.set_keepalive(true);
    }
}

pub async fn serve_listener(
    handle: RelayHandle,
    listener: TcpListener,
) -> Result<(), std::io::Error> {
    serve(handle, vec![listener]).await
}

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Serves `observability.metrics_listen`: `GET /metrics` while
/// `observability.metrics_enabled` is on, and 404 for everything else. It
/// is meant for a private address and a scraper, so it sends no CORS
/// headers, but like the relay listener it refuses a NIP-86 `blockip`
/// address and charges the per-address connection budget.
pub async fn serve_metrics(handle: RelayHandle, listener: TcpListener) -> std::io::Result<()> {
    tracing::info!("Started metrics server on {}", listener.local_addr()?);
    let handle = Arc::new(handle);
    let shutdown = handle.shutdown_handle();
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.notified() => break,
            res = listener.accept() => match res {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("metrics accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let handshake_timeout = handle.config.read().relay.handshake_timeout_secs;
        let handle = handle.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let handle = handle.clone();
                async move {
                    // The scraper's own address: real_ip_header is for the
                    // relay listener's proxy.
                    if !handle.admit_connection(&TransportSource::ip_address(peer.ip())) {
                        return Ok::<_, Infallible>(empty(StatusCode::TOO_MANY_REQUESTS));
                    }
                    let served = req.uri().path() == "/metrics"
                        && req.method() == hyper::Method::GET
                        && handle.config.read().observability.metrics_enabled;
                    Ok::<_, Infallible>(if served {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", METRICS_CONTENT_TYPE)
                            .body(Full::new(Bytes::from(handle.metrics.render())))
                            .unwrap_or_else(|_| empty(StatusCode::OK))
                    } else {
                        empty(StatusCode::NOT_FOUND)
                    })
                }
            });
            let mut builder = http1::Builder::new();
            builder.timer(TokioTimer::new());
            builder.header_read_timeout(
                (handshake_timeout > 0).then(|| Duration::from_secs(handshake_timeout)),
            );
            let _ = builder.serve_connection(TokioIo::new(stream), svc).await;
        });
    }
    tracing::info!("Metrics listener stopped");
    Ok(())
}

async fn accept_loop(
    handle: Arc<RelayHandle>,
    listener: TcpListener,
    admin_state: Arc<admin::AdminState>,
) -> Result<(), std::io::Error> {
    tracing::info!("Started websocket server on {}", listener.local_addr()?);
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
        let keepalive = handle.config.read().relay.enable_tcp_keepalive;
        configure_accepted_stream(&stream, peer, keepalive);
        let handshake_timeout = handle.config.read().relay.handshake_timeout_secs;
        let handle = handle.clone();
        let admin_state = admin_state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let handle = handle.clone();
                let admin_state = admin_state.clone();
                async move { Ok::<_, Infallible>(dispatch(req, handle, peer, admin_state).await) }
            });
            let mut builder = http1::Builder::new();
            builder.timer(TokioTimer::new());
            // Slowloris guard: bound the pre-upgrade header read. Without a
            // deadline a client can park partial HTTP headers forever. The
            // Option must be passed through: installing a timer while
            // leaving hyper's 30s default in place would keep the guard
            // active when configured off, and an explicit None disables it.
            builder.header_read_timeout(
                (handshake_timeout > 0).then(|| std::time::Duration::from_secs(handshake_timeout)),
            );
            let _ = builder.serve_connection(io, svc).with_upgrades().await;
        });
    }
    tracing::info!("Websocket listener stopped");
    Ok(())
}

async fn dispatch(
    req: Request<Incoming>,
    handle: Arc<RelayHandle>,
    peer: SocketAddr,
    admin_state: Arc<admin::AdminState>,
) -> Response<Full<Bytes>> {
    // Honor relay.real_ip_header for reverse-proxied deployments. C++ strfry
    // reads the whole value as one address; Wok reads the last entry, the
    // one the proxy wrote, and reads `Forwarded` as RFC 7239.
    let peer = {
        let cfg = handle.config.read();
        let header = cfg.relay.real_ip_header.as_str();
        if header.is_empty() {
            peer
        } else {
            match forwarded::client(req.headers(), header) {
                Forwarded::Client(ip) => SocketAddr::new(ip, 0),
                Forwarded::Absent => peer,
                Forwarded::Unparsed(entry) => {
                    handle
                        .metrics
                        .real_ip_header_unparsed
                        .fetch_add(1, Ordering::Relaxed);
                    if warning_due(&UNPARSED_WARNED_AT, unix_now()) {
                        let entry: String = entry.chars().take(64).collect();
                        tracing::warn!(
                            header,
                            entry = ?entry,
                            "relay.real_ip_header ends in an entry that names no IP \
                             address, so the connecting address stands in for the client's; \
                             check that the proxy writes the client's address last (warned \
                             at most once a minute, counted by \
                             wok_real_ip_header_unparsed_total)"
                        );
                    }
                    peer
                }
            }
        }
    };
    let is_ws_upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    // WebSocket upgrades and plain HTTP share the per-IP connection budget.
    // Plain HTTP endpoints (/admin/api/*, /metrics, NIP-11, ...) would
    // otherwise have none: every /admin/api attempt runs a Schnorr
    // verification before rejection, a straight unauthenticated CPU drain.
    let source = TransportSource::ip_address(peer.ip());
    if !handle.admit_connection(&source) {
        return text_status_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate-limited: connection budget exhausted",
        );
    }
    let path = req.uri().path().to_string();
    // NIP-01: the relay is a single endpoint. Extra path segments change
    // nothing, so only the root upgrades and serves the relay documents.
    if is_ws_upgrade {
        if path != "/" {
            return not_found();
        }
        return upgrade_ws(req, handle, peer).await;
    }
    if matches!(path.as_str(), "/admin" | "/admin/") || path.starts_with("/admin/api/") {
        return admin::dispatch(req, handle, admin_state).await;
    }
    // `/metrics` and the NodeInfo paths are routes only while the relay
    // listener serves them, so a relay without them answers them, preflight
    // included, like any path.
    let (metrics_here, nodeinfo_here) = {
        let cfg = handle.config.read();
        (
            path == "/metrics" && cfg.metrics_on_relay_listener(),
            matches!(path.as_str(), "/.well-known/nodeinfo" | "/nodeinfo/2.1")
                && cfg.relay.nodeinfo_enabled,
        )
    };
    if !metrics_here && !nodeinfo_here && !matches!(path.as_str(), "/" | "/favicon.ico") {
        return not_found();
    }
    if req.method() == hyper::Method::OPTIONS {
        return preflight_response();
    }
    // NIP-86 management RPC arrives as an HTTP POST to the relay URI itself.
    // Browser management tools call it cross-origin, so it carries CORS too.
    if path == "/"
        && req.method() == hyper::Method::POST
        && req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with(nip86::RPC_CONTENT_TYPE))
            .unwrap_or(false)
    {
        return with_cors(nip86::dispatch(req, handle, admin_state).await);
    }
    let wants_nip11 = accepts_nip11(req.headers());
    let cfg = handle.config.read().clone();
    if metrics_here {
        return text_response(METRICS_CONTENT_TYPE, handle.metrics.render());
    }
    if nodeinfo_here {
        return nodeinfo(&path, req.headers());
    }
    if path == "/favicon.ico" {
        return with_cors(
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "image/x-icon")
                .header("Cache-Control", "public, max-age=31536000")
                .body(Full::new(Bytes::from_static(&[0, 0, 1, 0])))
                .unwrap_or_else(|_| empty(StatusCode::OK)),
        );
    }
    let mut response = if wants_nip11 {
        json_response(&nip11(&cfg))
    } else {
        html_response(&landing(&cfg, &handle.supported_nips()))
    };
    // `/` serves two documents, so caches must key on Accept too.
    response.headers_mut().insert(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("Accept"),
    );
    response
}

/// NodeInfo discovery (`/.well-known/nodeinfo`) or its document
/// (`/nodeinfo/2.1`), served while `relay.nodeinfo_enabled` is on. The
/// discovery link's host is the request's `Host` header.
fn nodeinfo(path: &str, headers: &hyper::HeaderMap) -> Response<Full<Bytes>> {
    if path == "/.well-known/nodeinfo" {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        return json_response(&serde_json::json!({
            "links": [{
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                "href": format!("https://{host}/nodeinfo/2.1"),
            }]
        }));
    }
    json_response(&serde_json::json!({
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
    }))
}

/// When the relay last warned about an unparsed `relay.real_ip_header`, in
/// seconds since the epoch, 0 for never. Every request from a misconfigured
/// proxy would warn; one a minute shows it without flooding the log.
static UNPARSED_WARNED_AT: AtomicU64 = AtomicU64::new(0);

/// Whether a warning last logged at `warned_at` is due again at `now`, at
/// most once a minute. A due warning is claimed, so of several requests at
/// once only one logs it.
fn warning_due(warned_at: &AtomicU64, now: u64) -> bool {
    let last = warned_at.load(Ordering::Relaxed);
    (last == 0 || now >= last.saturating_add(60))
        && warned_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether the `Accept` media-range list names `application/nostr+json` with
/// a nonzero quality. Wildcards don't count: browsers send `*/*` and get the
/// landing page.
fn accepts_nip11(headers: &hyper::HeaderMap) -> bool {
    headers
        .get_all(hyper::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|range| {
            let mut parts = range.split(';');
            let media_type = parts.next().unwrap_or("").trim();
            media_type.eq_ignore_ascii_case("application/nostr+json")
                && !parts.any(|param| {
                    param.split_once('=').is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("q")
                            && value.trim().parse::<f32>() == Ok(0.0)
                    })
                })
        })
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

pub(crate) fn nip11(cfg: &Config) -> serde_json::Value {
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
            "max_tags_per_filter": cfg.relay.max_tags_per_filter,
            "max_and_entries": cfg.relay.max_and_entries,
            "created_at_upper_limit": cfg.events.reject_newer_than_secs,
            "default_limit": cfg.relay.max_filter_limit,
            "min_pow_difficulty": min_pow_difficulty,
            "max_concurrent_historical_queries": cfg.relay.abuse.max_concurrent_historical_queries,
            "max_subid_length": wok_event::MAX_SUBID_CHARS,
            "auth_required": cfg.auth_required(),
            "restricted_writes": cfg.restricted_writes(),
        }
    });
    // The ceiling applies only while abuse controls are on, and zero is no
    // ceiling.
    if cfg.relay.abuse.enabled && cfg.relay.abuse.max_query_work != 0 {
        v["limitation"]["max_query_work"] = serde_json::json!(cfg.relay.abuse.max_query_work);
    }
    // NIP-11 has no value for "no lower bound", so the field is omitted.
    if cfg.events.reject_older_than_secs != 0 {
        v["limitation"]["created_at_lower_limit"] =
            serde_json::json!(cfg.events.reject_older_than_secs);
    }
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
    v
}

const PROTOCOL_NEG: u64 = 1;

/// How often a permessage-deflate connection drops compression state it has
/// not used since the previous check, so a quiet connection gives it back
/// after one to two intervals (see `frame::DeflateCtx`).
const DEFLATE_IDLE_CHECK: Duration = Duration::from_secs(30);

/// Outbound frames queued behind a write are encoded into the next write until
/// it reaches this size, so a history burst costs a few syscalls rather than
/// one per event. A frame that finds the queue empty is written alone, so
/// coalescing never delays the first frame of a response.
const COALESCE_BYTES: usize = 16 * 1024;

/// How long the Close frame that fails a connection may take to write. The
/// client broke the protocol, so a full send buffer is not waited out.
const FAIL_CLOSE_WRITE: Duration = Duration::from_secs(1);

/// Fail the connection (RFC 6455 §7.1.7): send its `close` frame, as far as
/// it goes, before the stream is dropped.
async fn send_close<W>(wr: &mut W, close: Vec<u8>)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(FAIL_CLOSE_WRITE, write_bytes(wr, &close)).await;
}

fn nip_description(nip: u64) -> Option<&'static str> {
    match nip {
        1 => Some("Defines the core event format, filters, and client-relay message flow."),
        9 => Some("Lets event authors request deletion of their own published events."),
        11 => Some("Publishes relay metadata, capabilities, limitations, and contact details over HTTP."),
        13 => Some("Adds verifiable proof of work to events as a configurable spam deterrent."),
        40 => Some("Allows events to declare an expiration timestamp after which they should not be served."),
        42 => Some("Authenticates clients to relays with a signed, challenge-bound ephemeral event."),
        45 => Some("Adds COUNT requests and mergeable HyperLogLog estimates without transferring every event."),
        50 => Some("Adds full-text search queries and relevance-ordered results to relay filters."),
        59 => Some("Encapsulates events in encrypted gift wraps to reduce exposed messaging metadata."),
        62 => Some("Lets a key request complete, durable deletion of its relay-hosted footprint."),
        70 => Some("Restricts publication of protected events to their authenticated author."),
        77 => Some("Synchronizes event sets efficiently with the Negentropy reconciliation protocol."),
        91 => Some("Requires every value in an &-prefixed tag filter while preserving compatible #-filter fallback."),
        _ => None,
    }
}

fn public_npub(value: &str) -> Option<String> {
    let value = value.trim();
    if wok_event::decode_npub(value).is_ok() {
        return Some(value.to_ascii_lowercase());
    }
    let bytes = hex::decode(value).ok()?;
    let pubkey: [u8; 32] = bytes.try_into().ok()?;
    Some(wok_event::encode_npub(&pubkey))
}

fn safe_http_url(value: &str) -> Option<&str> {
    let value = value.trim();
    let uri = value.parse::<hyper::Uri>().ok()?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return None;
    }
    Some(value)
}

fn metadata_row(label: &str, value: &str, href: Option<&str>, code: bool) -> String {
    let escaped_value = html_escape(value);
    let display = if code {
        format!("<code>{escaped_value}</code>")
    } else {
        escaped_value
    };
    let display = match href {
        Some(href) => format!("<a href=\"{}\">{display}</a>", html_escape(href)),
        None => display,
    };
    format!(
        "<div class=\"metadata-row\"><dt>{}</dt><dd>{display}</dd></div>",
        html_escape(label)
    )
}

fn contact_href(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(url) = safe_http_url(value) {
        return Some(url.to_owned());
    }
    if let Some(npub) = public_npub(value) {
        return Some(format!("nostr:{npub}"));
    }
    if value.starts_with("mailto:") {
        return Some(value.to_owned());
    }
    (value.contains('@') && !value.chars().any(char::is_whitespace))
        .then(|| format!("mailto:{value}"))
}

fn landing(cfg: &Config, supported_nips: &[u64]) -> String {
    let info = &cfg.relay.info;
    let nip_items = supported_nips
        .iter()
        .filter_map(|nip| {
            nip_description(*nip).map(|description| {
                format!(
                    "<li><a href=\"https://github.com/nostr-protocol/nips/blob/master/{nip:02}.md\">NIP-{nip:02}</a><span>{description}</span></li>"
                )
            })
        })
        .collect::<String>();
    // Only show a revision when the build embedded a real commit hash;
    // tarball builds without .git fall back to "unknown", which is noise.
    let revision = if GIT_HASH == "unknown" {
        String::new()
    } else {
        let short_hash = GIT_HASH.get(..8).unwrap_or(GIT_HASH);
        // Build-time input, but escape like every other interpolated value.
        format!(
            " (<a href=\"https://github.com/erskingardner/wok/commit/{}\">{}</a>)",
            html_escape(GIT_HASH),
            html_escape(short_hash)
        )
    };
    let banner = safe_http_url(&info.banner)
        .map(|url| {
            format!(
                "<img class=\"hero-banner\" src=\"{}\" alt=\"\" referrerpolicy=\"no-referrer\" decoding=\"async\">",
                html_escape(url)
            )
        })
        .unwrap_or_default();
    let mark = safe_http_url(&info.icon)
        .map(|url| {
            format!(
                "<img class=\"mark relay-icon\" src=\"{}\" alt=\"{} icon\" referrerpolicy=\"no-referrer\" decoding=\"async\">",
                html_escape(url),
                html_escape(&info.name)
            )
        })
        .unwrap_or_else(|| format!("<span class=\"mark\">{WOK_MARK_SVG}</span>"));

    let mut metadata = Vec::new();
    if !info.pubkey.trim().is_empty() {
        let display = public_npub(&info.pubkey).unwrap_or_else(|| info.pubkey.trim().to_owned());
        let href = display
            .starts_with("npub1")
            .then(|| format!("nostr:{display}"));
        metadata.push(metadata_row(
            "Operator npub",
            &display,
            href.as_deref(),
            true,
        ));
    }
    if !info.self_pk.trim().is_empty() {
        let display = public_npub(&info.self_pk).unwrap_or_else(|| info.self_pk.trim().to_owned());
        let href = display
            .starts_with("npub1")
            .then(|| format!("nostr:{display}"));
        metadata.push(metadata_row("Relay npub", &display, href.as_deref(), true));
    }
    if !info.contact.trim().is_empty() {
        let contact = info.contact.trim();
        let href = contact_href(contact);
        metadata.push(metadata_row("Contact", contact, href.as_deref(), false));
    }
    for (label, value) in [
        ("Icon URL", info.icon.as_str()),
        ("Banner URL", info.banner.as_str()),
        ("Privacy policy", info.privacy.as_str()),
        ("Terms of service", info.terms.as_str()),
    ] {
        if !value.trim().is_empty() {
            metadata.push(metadata_row(
                label,
                value.trim(),
                safe_http_url(value),
                false,
            ));
        }
    }
    let metadata = if metadata.is_empty() {
        "<p class=\"metadata-empty\">No public operator details have been configured.</p>"
            .to_owned()
    } else {
        format!("<dl>{}</dl>", metadata.concat())
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name} · Wok relay</title><style>{css}</style></head>
<body><main><header>{banner}<div class="eyebrow">{mark} Wok relay</div>
<h1>{name}</h1><h2>{description}</h2></header>
<section class="metadata"><div class="section-heading"><p>About this relay</p><h2>Relay information</h2></div>
{metadata}</section>
<section><div class="section-heading"><p>Relay capabilities</p><h2>Supported NIPs</h2></div>
<ul>{nip_items}</ul></section>
<footer><span class="status-dot"></span> Wok {VERSION}{revision}</footer>
</main></body></html>"#,
        name = html_escape(&cfg.relay.info.name),
        description = html_escape(&cfg.relay.info.description),
        css = LANDING_CSS,
    )
}

const LANDING_CSS: &str = r#"
:root{color-scheme:light;--ink:#17211d;--muted:#617069;--line:#dce4df;--paper:#f7faf8;--card:#fff;--accent:#ff8a3d;--accent-soft:#fff0e7;--green:#2d7a5f}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 85% 0,#ffe7d8 0,transparent 31rem),var(--paper);color:var(--ink);font-family:Inter,"SF Pro Text","Segoe UI",system-ui,-apple-system,sans-serif}main{width:min(880px,calc(100% - 40px));margin:0 auto;padding:54px 0 42px}header{margin-bottom:42px}.hero-banner{display:block;width:100%;height:clamp(180px,34vw,300px);margin-bottom:25px;object-fit:cover;border:1px solid var(--line);border-radius:16px;background:#e8efeb;box-shadow:0 20px 55px #243a2f12}.eyebrow{display:flex;align-items:center;gap:11px;margin-bottom:23px;color:var(--green);font-size:13px;font-weight:750;letter-spacing:.08em;text-transform:uppercase}.mark{display:grid;place-items:center;width:38px;height:38px;background:#090b0f;color:#ff8a3d;box-shadow:0 8px 24px #090b0f33}.mark svg{display:block;width:100%;height:100%}.relay-icon{object-fit:cover;border:1px solid #ffffffb8;border-radius:10px}h1,h2,p{margin:0}h1{max-width:720px;font-family:"SF Pro Display",Inter,"Segoe UI",system-ui,sans-serif;font-size:clamp(42px,8vw,72px);font-weight:760;letter-spacing:-.055em;line-height:.98}header h2{max-width:680px;margin-top:22px;color:var(--muted);font-family:"SF Pro Display",Inter,"Segoe UI",system-ui,sans-serif;font-size:clamp(19px,3vw,27px);font-weight:430;letter-spacing:-.02em;line-height:1.38}section{overflow:hidden;background:color-mix(in srgb,var(--card) 94%,transparent);border:1px solid var(--line);border-radius:16px;box-shadow:0 20px 55px #243a2f0b}section+section{margin-top:18px}.section-heading{padding:25px 28px 20px;border-bottom:1px solid var(--line)}.section-heading p{margin-bottom:5px;color:var(--accent);font-size:12px;font-weight:750;letter-spacing:.09em;text-transform:uppercase}.section-heading h2{font-size:23px;letter-spacing:-.025em}dl{margin:0}.metadata-row{display:grid;grid-template-columns:150px minmax(0,1fr);gap:20px;padding:16px 28px;border-bottom:1px solid #edf1ee}.metadata-row:last-child{border-bottom:0}dt{color:var(--muted);font-size:13px;font-weight:650}dd{min-width:0;margin:0;overflow-wrap:anywhere}dd a{color:var(--green);text-decoration:none}dd a:hover{text-decoration:underline;text-underline-offset:3px}code{font-family:"SFMono-Regular",Consolas,monospace;font-size:12px;line-height:1.55}.metadata-empty{padding:20px 28px;color:var(--muted)}ul{list-style:none;margin:0;padding:0}li{display:grid;grid-template-columns:92px 1fr;gap:18px;padding:17px 28px;border-bottom:1px solid #edf1ee}li:last-child{border-bottom:0}li a{color:var(--green);font-weight:760;text-decoration:none}li a:hover{text-decoration:underline;text-underline-offset:3px}li span{color:var(--muted);line-height:1.55}footer{display:flex;align-items:center;justify-content:center;gap:8px;padding-top:28px;color:#75827c;font-size:13px}footer a{color:inherit;text-decoration-color:#b7c1bc;text-underline-offset:3px}.status-dot{width:7px;height:7px;border-radius:50%;background:#4eb889;box-shadow:0 0 0 4px #4eb88918}@media(max-width:600px){main{width:min(100% - 28px,880px);padding-top:28px}header{margin-bottom:34px}.hero-banner{height:190px;border-radius:12px}.metadata-row,li{grid-template-columns:1fr;gap:6px;padding:16px 20px}.section-heading{padding:21px 20px}.metadata-empty{padding:18px 20px}}
"#;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// NIP-11 requires CORS on the relay URI. Every public response carries
/// these headers, NIP-86 replies included.
const CORS_HEADERS: [(&str, &str); 3] = [
    ("Access-Control-Allow-Origin", "*"),
    (
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, Accept",
    ),
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
];

fn with_cors(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    for (name, value) in CORS_HEADERS {
        response
            .headers_mut()
            .insert(name, hyper::header::HeaderValue::from_static(value));
    }
    response
}

/// Answer a CORS preflight. The headers already say what is allowed.
fn preflight_response() -> Response<Full<Bytes>> {
    with_cors(empty(StatusCode::NO_CONTENT))
}

fn public_response(status: StatusCode, content_type: &str, body: Bytes) -> Response<Full<Bytes>> {
    with_cors(
        Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Server", "wok")
            .body(Full::new(body))
            .unwrap_or_else(|_| empty(status)),
    )
}

fn json_response(v: &serde_json::Value) -> Response<Full<Bytes>> {
    public_response(
        StatusCode::OK,
        "application/json",
        Bytes::from(v.to_string()),
    )
}

fn text_response(ct: &str, body: String) -> Response<Full<Bytes>> {
    public_response(StatusCode::OK, ct, Bytes::from(body))
}

fn text_status_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    public_response(
        status,
        "text/plain; charset=utf-8",
        Bytes::copy_from_slice(body.as_bytes()),
    )
}

fn html_response(body: &str) -> Response<Full<Bytes>> {
    public_response(StatusCode::OK, "text/html", Bytes::from(body.to_string()))
}

fn not_found() -> Response<Full<Bytes>> {
    text_status_response(StatusCode::NOT_FOUND, "not found")
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
    // Each connection multiplies what one address may queue, be sent and
    // keep subscribed, so an address may hold only so many open. The slot
    // is taken before the upgrade and given back when the connection ends.
    let Some(slot) = handle.hold_connection(&TransportSource::ip_address(peer.ip())) else {
        return text_status_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate-limited: too many connections from this address",
        );
    };
    // permessage-deflate negotiation mirroring uWS as strfry configures it:
    // respond with plain `permessage-deflate` (our context takeover per
    // compression.slidingWindow), echoing client_no_context_takeover.
    let (compression_on, sliding) = {
        let cfg = handle.config.read();
        (
            cfg.relay.compression_enabled,
            cfg.relay.compression_sliding_window,
        )
    };
    let mut ext_response: Option<String> = None;
    let mut deflate = None;
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
                let client_no_takeover = offer
                    .split(';')
                    .skip(1)
                    .any(|t| t.trim().eq_ignore_ascii_case("client_no_context_takeover"));
                if client_no_takeover {
                    resp.push_str("; client_no_context_takeover");
                }
                ext_response = Some(resp);
                deflate = Some(Deflate {
                    server_takeover: sliding,
                    client_takeover: !client_no_takeover,
                });
            }
        }
    }
    let max = handle.config.read().relay.max_websocket_payload_size;
    tokio::spawn(async move {
        let _slot = slot;
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                handle_ws(io, handle, peer, max, deflate, DEFLATE_IDLE_CHECK).await;
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

/// What a WebSocket upgrade negotiated for permessage-deflate.
#[derive(Clone, Copy)]
struct Deflate {
    /// Our compressor keeps history between messages (slidingWindow).
    server_takeover: bool,
    /// The client did not agree to client_no_context_takeover, so its
    /// compressor may refer back into earlier messages.
    client_takeover: bool,
}

async fn handle_ws<S>(
    stream: S,
    handle: Arc<RelayHandle>,
    peer: SocketAddr,
    max_message: usize,
    deflate: Option<Deflate>,
    deflate_idle_check: Duration,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let source = TransportSource::ip_address(peer.ip());
    let auto_ping = handle.config.read().relay.auto_ping_seconds;
    let (frame_read_timeout, message_read_timeout) = {
        let cfg = handle.config.read();
        let timeout = |secs: u64| (secs > 0).then(|| Duration::from_secs(secs));
        (
            timeout(cfg.relay.frame_read_timeout_secs),
            timeout(cfg.relay.message_read_timeout_secs),
        )
    };
    // Pending memory is bounded by max_pending_outbound_bytes in Outbound.
    // A second message-count bound incorrectly disconnected healthy clients
    // during bursty historical responses with many small events.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
    let max_pending = handle.config.read().relay.max_pending_outbound_bytes;
    let outbound = Outbound::new(tx, max_pending);
    let killed = outbound.killed();
    let connection = handle.register_connection(source, outbound).await;
    let conn_id = connection.conn_id();
    tracing::info!(conn_id, peer = %peer, transport = "websocket", "client connected");
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut parser = WsParser::new(
        max_message,
        deflate.map(|d| InflateCtx::new(d.client_takeover)),
    );
    let mut encoder = WsEncoder::new(deflate.map(|d| DeflateCtx::new(d.server_takeover)));
    // Both intervals first tick one period from now. Awaiting an immediate
    // first tick instead holds a new connection until the timer's next
    // millisecond before it reads anything.
    let mut deflate_idle = tokio::time::interval_at(
        tokio::time::Instant::now() + deflate_idle_check,
        deflate_idle_check,
    );
    deflate_idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut incoming_events = Vec::with_capacity(4);
    let ping_every = std::time::Duration::from_secs(auto_ping.max(1));
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + ping_every, ping_every);
    // Delay (not the Burst default): after the select is stalled elsewhere
    // for two or more intervals, Burst would fire back-to-back ticks — send
    // a ping, then immediately close for a pong the peer never got a window
    // to send. Delay guarantees one full interval per outstanding ping.
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Liveness: a ping unanswered when the next ping interval elapses means
    // the peer is gone (or deliberately silent) — close the connection.
    let mut awaiting_pong = false;
    // The partial-frame and partial-message deadlines, kept here (not inside
    // the read future) so select! cancellation by outbound traffic or pings
    // cannot restart them.
    let mut deadlines = ReadDeadlines::new(frame_read_timeout, message_read_timeout);
    // Messages read while the relay has paused this connection's ingress
    // (earlier work is parked behind a busy worker). The socket stays read,
    // so control frames, Close and EOF are still handled while paused. Once
    // ingress resumes the hold is handed over a batch per pass of the loop,
    // with messages read meanwhile queued behind it; reading stops only while
    // those have taken it past its limit, and starts again if ingress pauses.
    let mut held = HeldMessages::new(max_message);
    // Frames were still queued after the last write: coalesce the next one.
    let mut backlog = false;
    let io = async {
        'outer: loop {
            let draining = connection.draining(&held);
            // While the hold is full the relay, not the client, has stopped
            // reading, so that pause counts neither against the frame gap or
            // the message deadline nor against a ping, whose pong it could
            // not read: no ping goes out meanwhile, and the next one waits a
            // full interval after reading resumes.
            if draining {
                deadlines.pause();
                awaiting_pong = false;
                ping.reset();
            } else {
                deadlines.resume();
            }
            tokio::select! {
                _ = ping.tick(), if auto_ping > 0 && !draining => {
                    if awaiting_pong {
                        tracing::info!(conn_id, peer = %peer, reason = "pong_timeout", "client terminated");
                        break;
                    }
                    if write_bytes(&mut wr, &encoder.encode_control(OP_PING, &[])).await.is_err() {
                        break;
                    }
                    // The next tick was scheduled when this one was consumed,
                    // before the write above. Restart the interval so a stalled
                    // write can't eat the peer's pong window.
                    ping.reset();
                    awaiting_pong = true;
                }
                _ = deflate_idle.tick(), if deflate.is_some() => {
                    encoder.release_idle();
                    parser.release_idle();
                }
                _ = connection.ready(held.front_len()), if !held.is_empty() => {
                    connection.hand_over(&mut held).await;
                }
                _ = connection.ingress_pauses(), if draining => {}
                incoming = read_events_into(&mut rd, &mut parser, &mut incoming_events, &mut deadlines), if !draining => {
                    match incoming {
                        Ok(()) => {
                            for ev in incoming_events.drain(..) {
                                match ev {
                                    WsEvent::Message(kind, bytes) => {
                                        let wire_len = bytes.len();
                                        let text = match String::from_utf8(bytes) {
                                            Ok(text) => text,
                                            // RFC 6455 §8.1, checked once the
                                            // message is whole and inflated.
                                            Err(_) if kind == MessageKind::Text => {
                                                connection.hand_over_rest(&mut held).await;
                                                send_close(&mut wr, encoder.encode_close(frame::CLOSE_INVALID_DATA)).await;
                                                break 'outer;
                                            }
                                            // A binary message that is not
                                            // UTF-8 is not JSON either: this
                                            // stand-in gets the relay's NOTICE.
                                            Err(_) => "x".into(),
                                        };
                                        if !connection.receive(&mut held, text, wire_len).await {
                                            tracing::info!(conn_id, peer = %peer, reason = "ingress_paused_overflow", "client terminated");
                                            break 'outer;
                                        }
                                    }
                                    WsEvent::Ping(p) => {
                                        if write_bytes(&mut wr, &encoder.encode_control(OP_PONG, &p)).await.is_err() {
                                            break 'outer;
                                        }
                                    }
                                    WsEvent::Pong(_) => {
                                        awaiting_pong = false;
                                    }
                                    WsEvent::Close(c) => {
                                        // What ingress still accepts goes
                                        // through; anything held behind a
                                        // pause is dropped, as the close drops
                                        // the parked work ahead of it.
                                        connection.hand_over_rest(&mut held).await;
                                        let _ = write_bytes(&mut wr, &encoder.encode_control(frame::OP_CLOSE, &c)).await;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            connection.hand_over_rest(&mut held).await;
                            if let Some(code) = e.close_code() {
                                send_close(&mut wr, encoder.encode_close(code)).await;
                            }
                            break;
                        }
                    }
                }
                out = rx.recv() => {
                    let Some(frame) = out else { break };
                    // Frames are encoded and dropped (releasing their pending
                    // bytes) before the write, which holds at most about
                    // COALESCE_BYTES more than a single frame would.
                    let limit = if backlog { COALESCE_BYTES } else { 0 };
                    let mut bytes = Vec::new();
                    let mut next = Some(frame);
                    while let Some(frame) = next.take() {
                        // Its subscription was replaced or closed while it
                        // waited: the client no longer wants it.
                        if !frame.is_stale()
                            && encoder.encode_message_into(MessageKind::Text, frame.text.as_bytes(), &mut bytes).is_err()
                        {
                            break 'outer;
                        }
                        if bytes.len() < limit {
                            next = rx.try_recv().ok();
                        }
                    }
                    if !bytes.is_empty() && write_bytes(&mut wr, &bytes).await.is_err() {
                        break;
                    }
                    backlog = !rx.is_empty();
                }
            }
        }
    };
    connection.run_until_cancelled(&killed, io).await;
    connection.close().await;
    tracing::info!(conn_id, peer = %peer, transport = "websocket", "client disconnected");
}

#[cfg(test)]
#[path = "review_regressions.rs"]
mod review_regressions;

#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;

#[cfg(test)]
mod landing_tests {
    use super::*;

    #[test]
    fn landing_has_hierarchy_links_descriptions_and_revision() {
        let mut cfg = Config::default();
        cfg.relay.info.name = "A <useful> relay".into();
        cfg.relay.info.description = "Fast & friendly".into();
        cfg.relay.info.pubkey =
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d".into();
        cfg.relay.info.self_pk =
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6".into();
        cfg.relay.info.contact = "ops@example.com".into();
        cfg.relay.info.icon = "https://relay.example/icon.png?small=1&square=1".into();
        cfg.relay.info.banner = "https://relay.example/banner.jpg".into();
        cfg.relay.info.privacy = "https://relay.example/privacy".into();
        cfg.relay.info.terms = "javascript:alert('no')".into();
        let html = landing(&cfg, &[1, 62, 77]);

        assert!(html.contains("<h1>A &lt;useful&gt; relay</h1>"));
        assert!(html.contains("<h2>Fast &amp; friendly</h2>"));
        assert!(html.contains("class=\"hero-banner\""));
        assert!(html.contains("class=\"mark relay-icon\""));
        assert!(html.contains("icon.png?small=1&amp;square=1"));
        assert!(html.contains("Relay information"));
        assert!(html.contains("Operator npub"));
        assert!(html.contains("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"));
        assert!(html.contains("href=\"mailto:ops@example.com\""));
        assert!(html.contains("href=\"https://relay.example/privacy\""));
        assert!(html.contains("javascript:alert(&#39;no&#39;)"));
        assert!(!html.contains("href=\"javascript:"));
        assert!(html.find("Relay information").unwrap() < html.find("Supported NIPs").unwrap());
        assert!(html.contains("nostr-protocol/nips/blob/master/01.md"));
        assert!(html.contains("Defines the core event format"));
        assert!(html.contains("nostr-protocol/nips/blob/master/62.md"));
        assert!(html.contains("durable deletion"));
        assert!(html.contains("nostr-protocol/nips/blob/master/77.md"));
        assert!(html.contains(&format!("Wok {VERSION}")));
        if GIT_HASH == "unknown" {
            // No commit hash embedded (e.g. tarball build): no parenthetical.
            assert!(!html.contains("(unknown)"));
            assert!(html.contains(&format!("Wok {VERSION}</footer>")));
        } else {
            assert!(html.contains(GIT_HASH.get(..8).unwrap_or(GIT_HASH)));
        }
    }

    #[test]
    fn landing_uses_the_wok_mark_without_a_custom_icon() {
        let html = landing(&Config::default(), &[]);

        assert!(html.contains(&format!("<span class=\"mark\">{WOK_MARK_SVG}</span>")));
    }

    #[tokio::test]
    async fn accepted_connections_disable_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let client = client.unwrap();
        let (server, peer) = accepted.unwrap();

        configure_accepted_stream(&server, peer, false);

        assert!(server.nodelay().unwrap());
        drop(client);
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;

    fn accept(values: &[&str]) -> bool {
        let mut headers = hyper::HeaderMap::new();
        for value in values {
            headers.append(
                hyper::header::ACCEPT,
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        accepts_nip11(&headers)
    }

    #[test]
    fn accept_is_parsed_as_a_media_range_list() {
        assert!(accept(&["application/nostr+json"]));
        assert!(accept(&["application/nostr+json, application/json;q=0.9"]));
        assert!(accept(&["application/json;q=0.9 , Application/Nostr+JSON"]));
        assert!(accept(&["application/nostr+json; charset=utf-8; q=0.5"]));
        assert!(accept(&["text/html", "application/nostr+json"]));
        assert!(!accept(&[]));
        assert!(!accept(&["application/json"]));
        assert!(!accept(&["*/*"]));
        assert!(!accept(&["application/*"]));
        assert!(!accept(&["text/html,application/xhtml+xml,*/*;q=0.8"]));
        assert!(!accept(&["application/nostr+json;q=0"]));
        assert!(!accept(&["application/nostr+json; q=0.000"]));
        assert!(!accept(&["application/nostr+jsonx"]));
    }

    #[test]
    fn the_unparsed_warning_is_due_at_most_once_a_minute() {
        let warned_at = AtomicU64::new(0);
        assert!(warning_due(&warned_at, 1_000));
        assert!(!warning_due(&warned_at, 1_000));
        assert!(!warning_due(&warned_at, 1_059));
        assert!(warning_due(&warned_at, 1_060));
        assert!(!warning_due(&warned_at, 1_061));
    }

    #[test]
    fn public_responses_carry_every_cors_header() {
        for response in [
            json_response(&serde_json::json!({})),
            text_status_response(StatusCode::NOT_FOUND, "not found"),
            html_response("<p>"),
            preflight_response(),
        ] {
            let headers = response.headers();
            assert_eq!(headers["access-control-allow-origin"], "*");
            assert_eq!(
                headers["access-control-allow-headers"],
                "Content-Type, Authorization, Accept"
            );
            assert_eq!(
                headers["access-control-allow-methods"],
                "GET, POST, OPTIONS"
            );
        }
        assert_eq!(preflight_response().status(), StatusCode::NO_CONTENT);
    }
}

#[cfg(test)]
mod bind_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn local_addrs(listeners: &[TcpListener]) -> Vec<SocketAddr> {
        listeners.iter().map(|l| l.local_addr().unwrap()).collect()
    }

    fn ipv6_loopback_available() -> bool {
        std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok()
    }

    #[tokio::test]
    async fn binds_ipv4_literal() {
        let addrs = local_addrs(&bind_listeners("127.0.0.1", 0).await.unwrap());
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn binds_bare_and_bracketed_ipv6_literals() {
        if !ipv6_loopback_available() {
            return;
        }
        for host in ["::1", "[::1]"] {
            let addrs = local_addrs(&bind_listeners(host, 0).await.unwrap());
            assert_eq!(addrs.len(), 1, "{host}");
            assert_eq!(addrs[0].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST), "{host}");
        }
    }

    #[tokio::test]
    async fn binds_every_address_a_hostname_resolves_to_on_one_port() {
        let resolved: BTreeSet<IpAddr> = tokio::net::lookup_host(("localhost", 0))
            .await
            .unwrap()
            .map(|a| a.ip())
            .filter(|ip| ip.is_ipv4() || ipv6_loopback_available())
            .collect();
        assert!(resolved.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let addrs = local_addrs(&bind_listeners("localhost", 0).await.unwrap());
        let bound: BTreeSet<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        assert_eq!(bound, resolved);
        assert_eq!(addrs.len(), bound.len(), "one listener per address");
        let ports: BTreeSet<u16> = addrs.iter().map(|a| a.port()).collect();
        assert_eq!(ports.len(), 1, "all listeners share one port: {addrs:?}");
    }

    #[tokio::test]
    async fn unresolvable_host_is_an_error() {
        assert!(bind_listeners("wok-no-such-host.invalid", 0).await.is_err());
    }
}

#[cfg(test)]
mod stalled_write_tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::time::Instant;

    /// Read side pends forever. The first write stalls for a fixed (paused-
    /// time) duration, then everything flows. Used to prove the pong window
    /// starts when the ping hits the wire, not when its tick was consumed.
    struct StalledStream {
        state: Arc<Mutex<StalledState>>,
    }

    struct StalledState {
        stall_for: Duration,
        release_at: Option<Instant>,
        wake_task_spawned: bool,
        waker: Option<Waker>,
    }

    impl StalledStream {
        fn new(stall_for: Duration) -> Self {
            Self {
                state: Arc::new(Mutex::new(StalledState {
                    stall_for,
                    release_at: None,
                    wake_task_spawned: false,
                    waker: None,
                })),
            }
        }
    }

    impl AsyncRead for StalledStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for StalledStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            if state.release_at.is_none() && !state.wake_task_spawned {
                state.release_at = Some(Instant::now() + state.stall_for);
            }
            if let Some(release_at) = state.release_at {
                state.waker = Some(cx.waker().clone());
                if !state.wake_task_spawned {
                    state.wake_task_spawned = true;
                    let state_ref = self.state.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep_until(release_at).await;
                        let mut state = state_ref.lock().unwrap();
                        state.release_at = None;
                        if let Some(waker) = state.waker.take() {
                            waker.wake();
                        }
                    });
                }
                return Poll::Pending;
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[allow(clippy::field_reassign_with_default)]
    async fn pong_window_starts_after_stalled_ping_write() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.unix.enabled = false;
        cfg.relay.auto_ping_seconds = 2;
        let handle = Arc::new(wok_relay::start(env, cfg).unwrap());

        let stream = StalledStream::new(Duration::from_secs(3));
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let start = Instant::now();
        handle_ws(stream, handle, peer, 1 << 20, None, DEFLATE_IDLE_CHECK).await;
        let elapsed = start.elapsed();

        // Timeline: first ping tick at t=2s, its write stalls until t=5s.
        // The peer never pongs, so the connection must close — but only
        // after a full interval measured from the write (t=7s), not from
        // the consumed tick (which would close immediately at t=5s).
        assert!(
            elapsed >= Duration::from_millis(6500),
            "closed too early after stalled ping write: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "pong liveness never fired: {elapsed:?}"
        );
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Served {
        handle: RelayHandle,
        relay: SocketAddr,
        metrics: SocketAddr,
        _dir: tempfile::TempDir,
    }

    /// A relay with `tweak` applied, its relay listener and a metrics
    /// listener on ephemeral loopback ports.
    async fn serve_both(tweak: impl FnOnce(&mut Config)) -> Served {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        let mut cfg = Config::default();
        tweak(&mut cfg);
        let handle = wok_relay::start(env, cfg).unwrap();
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let served = Served {
            handle: handle.clone(),
            relay: relay_listener.local_addr().unwrap(),
            metrics: metrics_listener.local_addr().unwrap(),
            _dir: dir,
        };
        tokio::spawn(serve_listener(handle.clone(), relay_listener));
        tokio::spawn(serve_metrics(handle, metrics_listener));
        served
    }

    /// The status line and headers, lower-cased, and the body of `method
    /// path` sent to `addr`.
    async fn request(addr: SocketAddr, method: &str, path: &str) -> (u16, String, String) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&response).into_owned();
        let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        (status, head.to_ascii_lowercase(), body.to_string())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metrics_are_off_by_default() {
        let served = serve_both(|_| {}).await;
        for method in ["GET", "OPTIONS"] {
            assert_eq!(request(served.relay, method, "/metrics").await.0, 404);
        }
        assert_eq!(request(served.metrics, "GET", "/metrics").await.0, 404);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enabled_metrics_are_served_on_the_relay_listener() {
        let served = serve_both(|cfg| cfg.observability.metrics_enabled = true).await;
        let (status, _, body) = request(served.relay, "GET", "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("wok_active_connections"), "{body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_metrics_listener_takes_metrics_off_the_relay_listener() {
        let served = serve_both(|cfg| {
            cfg.observability.metrics_enabled = true;
            cfg.observability.metrics_listen = "127.0.0.1:9777".into();
        })
        .await;
        assert_eq!(request(served.relay, "GET", "/metrics").await.0, 404);
        let (status, head, body) = request(served.metrics, "GET", "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("wok_active_connections"), "{body}");
        assert!(!head.contains("access-control-allow-origin"), "{head}");
        // It serves nothing else.
        for (method, path) in [
            ("GET", "/"),
            ("POST", "/metrics"),
            ("HEAD", "/metrics"),
            ("GET", "/admin"),
        ] {
            assert_eq!(
                request(served.metrics, method, path).await.0,
                404,
                "{method} {path}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metrics_listener_refuses_a_blocked_address() {
        let served = serve_both(|cfg| {
            cfg.observability.metrics_enabled = true;
            cfg.observability.metrics_listen = "127.0.0.1:9777".into();
        })
        .await;
        served
            .handle
            .manage(wok_relay::ManagementCmd::BlockIp {
                ip: "127.0.0.1".into(),
                reason: "test".into(),
            })
            .await
            .unwrap();
        let (status, head, _) = request(served.metrics, "GET", "/metrics").await;
        assert_eq!(status, 429);
        assert!(!head.contains("access-control-allow-origin"), "{head}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metrics_listener_follows_metrics_enabled_live() {
        let served = serve_both(|cfg| {
            cfg.observability.metrics_listen = "127.0.0.1:9777".into();
        })
        .await;
        assert_eq!(request(served.metrics, "GET", "/metrics").await.0, 404);
        served.handle.config.write().observability.metrics_enabled = true;
        assert_eq!(request(served.metrics, "GET", "/metrics").await.0, 200);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nodeinfo_is_off_by_default_and_follows_its_setting_live() {
        let served = serve_both(|_| {}).await;
        for path in ["/.well-known/nodeinfo", "/nodeinfo/2.1"] {
            for method in ["GET", "OPTIONS"] {
                assert_eq!(request(served.relay, method, path).await.0, 404);
            }
        }
        served.handle.config.write().relay.nodeinfo_enabled = true;
        let (status, _, body) = request(served.relay, "GET", "/.well-known/nodeinfo").await;
        assert_eq!(status, 200);
        assert!(body.contains("https://localhost/nodeinfo/2.1"), "{body}");
        let (status, _, body) = request(served.relay, "GET", "/nodeinfo/2.1").await;
        assert_eq!(status, 200);
        assert!(body.contains("\"protocols\":[\"nostr\"]"), "{body}");
        assert_eq!(
            request(served.relay, "OPTIONS", "/nodeinfo/2.1").await.0,
            204
        );
        served.handle.config.write().relay.nodeinfo_enabled = false;
        assert_eq!(request(served.relay, "GET", "/nodeinfo/2.1").await.0, 404);
    }
}

#[cfg(test)]
mod admin_http_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unsigned_admin_request_is_refused_before_its_body_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec!["ab".repeat(32)];
        let handle = wok_relay::start(env, cfg).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(handle, listener));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = |event: serde_json::Value| {
            format!(
                "Authorization: Nostr {}\r\n",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    event.to_string()
                )
            )
        };
        for (target, content_type, url, method) in [
            (
                "PUT /admin/api/config",
                "application/json",
                "https://relay.example/admin/api/config",
                "PUT",
            ),
            (
                "POST /",
                nip86::RPC_CONTENT_TYPE,
                "https://relay.example",
                "POST",
            ),
        ] {
            // A NIP-98 event for this endpoint in every respect but its
            // signature.
            let unsigned = |pubkey: String| {
                serde_json::json!({
                    "id": "00".repeat(32),
                    "pubkey": pubkey,
                    "created_at": now,
                    "kind": 27235,
                    "tags": [["u", url], ["method", method], ["payload", "00".repeat(32)]],
                    "content": "",
                    "sig": "00".repeat(64),
                })
            };
            let malformed = [
                String::new(),
                "Authorization: Bearer token\r\n".into(),
                "Authorization: Nostr !!!!\r\n".into(),
                // Valid base64 of something that is not JSON.
                "Authorization: Nostr bm90IGpzb24=\r\n".into(),
                // JSON that is not a NIP-98 event.
                header(serde_json::Value::Null),
                header(serde_json::json!({})),
                header(serde_json::json!({"kind": 1, "content": ""})),
                // A stranger, and a forgery naming the admin: one reply for
                // both, and neither waits for the body.
                header(unsigned("cd".repeat(32))),
                header(unsigned("ab".repeat(32))),
            ];
            for authorization in &malformed {
                // The body the request announces never arrives: a handler
                // that read it first would wait for it.
                let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                let request = format!(
                    "{target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\n\
                     {authorization}Content-Length: 1000000\r\n\r\n"
                );
                stream.write_all(request.as_bytes()).await.unwrap();
                let mut head = [0u8; 64];
                let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut head))
                    .await
                    .unwrap_or_else(|_| panic!("{target} {authorization:?}: no answer"))
                    .unwrap();
                let head = String::from_utf8_lossy(&head[..read]);
                assert!(
                    head.starts_with("HTTP/1.1 401"),
                    "{target} {authorization:?}: {head}"
                );
            }
        }
    }
}

#[cfg(test)]
mod ingress_pause_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn masked_text(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x81];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        let mask = [1u8, 2, 3, 4];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    /// Answer every ping the relay sends and collect its text frames, until
    /// one contains `until`.
    async fn answer_pings_until(
        mut rd: tokio::net::tcp::OwnedReadHalf,
        wr: std::sync::Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>,
        until: &[u8],
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            while buf.len() >= 2 {
                let (opcode, len) = (buf[0] & 0x0f, (buf[1] & 0x7f) as usize);
                let (start, len) = if len == 126 {
                    if buf.len() < 4 {
                        break;
                    }
                    (4, u16::from_be_bytes([buf[2], buf[3]]) as usize)
                } else {
                    (2, len)
                };
                if buf.len() < start + len {
                    break;
                }
                let payload: Vec<u8> = buf[start..start + len].to_vec();
                buf.drain(..start + len);
                if opcode == 0x9 {
                    let mask = [5u8, 6, 7, 8];
                    let mut pong = vec![0x8a, 0x80 | payload.len() as u8];
                    pong.extend_from_slice(&mask);
                    pong.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
                    wr.lock().await.write_all(&pong).await.unwrap();
                } else if payload.windows(until.len()).any(|w| w == until) {
                    return;
                }
            }
            let read = rd.read(&mut chunk).await.unwrap();
            assert!(read > 0, "the relay closed the connection");
            buf.extend_from_slice(&chunk[..read]);
        }
    }

    /// Nor does it count against a ping: a client that answers every ping is
    /// not closed for a pong the relay could not read while its hold was
    /// full.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pause_with_a_full_hold_does_not_spend_a_ping() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        let mut cfg = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        cfg.relay.ingester_threads = 1;
        cfg.relay.max_websocket_payload_size = 4096;
        cfg.relay.unix.max_frame_bytes = 4096;
        cfg.relay.auto_ping_seconds = 1;
        cfg.relay.compression_enabled = false;
        cfg.relay.abuse.enabled = false;
        let handle = wok_relay::start(env, cfg).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(handle.clone(), listener));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"));
        let (rd, wr) = stream.into_split();
        let wr = std::sync::Arc::new(tokio::sync::Mutex::new(wr));
        let answered = tokio::spawn(answer_pings_until(rd, wr.clone(), br#"["EOSE","last""#));

        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let config = handle.config.clone();
        let stall = std::thread::spawn(move || {
            let _guard = config.write();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        let mut burst = Vec::new();
        for n in 0..120 {
            let req = format!(r#"["REQ","s{n:03}",{{"ids":["{}"]}}]"#, "0".repeat(64));
            burst.extend(masked_text(req.as_bytes()));
        }
        burst.extend(masked_text(br#"["REQ","last",{"kinds":[1]}]"#));
        wr.lock().await.write_all(&burst).await.unwrap();
        // Longer than a ping and its pong window.
        tokio::time::sleep(Duration::from_millis(3_000)).await;
        release_tx.send(()).unwrap();
        stall.join().unwrap();
        tokio::time::timeout(Duration::from_secs(10), answered)
            .await
            .expect("no answer once the pause ended")
            .expect("the relay closed the connection");
        handle.request_shutdown();
    }

    /// Waiting with a full hold is the relay's pause, not the client's: once
    /// the relay reads again, a frame the client then completes is read,
    /// however long the pause outlasted `frame_read_timeout_secs`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pause_with_a_full_hold_does_not_spend_the_frame_gap() {
        completes_a_frame_after_a_full_hold_pause(1, 0).await;
    }

    /// Nor does it count against `message_read_timeout_secs`, which runs
    /// from the frame's first byte, read before the pause.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pause_with_a_full_hold_does_not_spend_the_message_deadline() {
        completes_a_frame_after_a_full_hold_pause(0, 2).await;
    }

    /// Fill a connection's hold behind a stalled ingester, with the first
    /// byte of one more frame read, wait 2.5 s, then complete the frame and
    /// expect its answer.
    async fn completes_a_frame_after_a_full_hold_pause(frame_timeout: u64, message_timeout: u64) {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        let mut cfg = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        cfg.relay.ingester_threads = 1;
        cfg.relay.max_websocket_payload_size = 4096;
        cfg.relay.unix.max_frame_bytes = 4096;
        cfg.relay.frame_read_timeout_secs = frame_timeout;
        cfg.relay.message_read_timeout_secs = message_timeout;
        cfg.relay.compression_enabled = false;
        cfg.relay.abuse.enabled = false;
        let handle = wok_relay::start(env, cfg).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(handle.clone(), listener));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"));

        // Stall the ingester, so the connection's share and then its hold
        // fill, with the first byte of one more frame read behind them. A
        // REQ of 22 ids is about 1.5 KiB: two fill the 4 KiB share and three
        // more take the hold past its limit. The fifth arrives on its own
        // with that byte, so nothing read is left to decode, and nothing
        // finished, once the relay stops reading.
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let config = handle.config.clone();
        let stall = std::thread::spawn(move || {
            let _guard = config.write();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        let ids = vec![format!("\"{}\"", "0".repeat(64)); 22].join(",");
        let req = |n: usize| masked_text(format!(r#"["REQ","s{n}",{{"ids":[{ids}]}}]"#).as_bytes());
        stream
            .write_all(&(0..4).flat_map(req).collect::<Vec<_>>())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let last = masked_text(br#"["REQ","last",{"kinds":[1]}]"#);
        let mut fifth = req(4);
        fifth.push(last[0]);
        stream.write_all(&fifth).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        release_tx.send(()).unwrap();
        stall.join().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream.write_all(&last[1..]).await.unwrap();

        let mut seen = Vec::new();
        let answered = tokio::time::timeout(Duration::from_secs(10), async {
            let mut chunk = [0u8; 4096];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "the relay closed the connection");
                seen.extend_from_slice(&chunk[..read]);
                if seen.windows(13).any(|w| w == br#"["EOSE","last"#) {
                    return;
                }
            }
        })
        .await;
        assert!(answered.is_ok(), "no answer to the completed frame");
        handle.request_shutdown();
    }
}
