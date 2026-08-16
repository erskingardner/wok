//! HTTP + WebSocket transport matching C++ `RelayWebsocket.cpp`.
//!
//! The WebSocket framing is a small in-house RFC 6455 + RFC 7692 codec
//! (`frame` module) so wok can offer permessage-deflate like C++ uWS
//! (tungstenite and fastwebsockets have no extension support).

#![forbid(unsafe_code)]

mod admin;
pub mod frame;

use bytes::Bytes;
use frame::{
    read_events_into, write_bytes, DeflateCtx, InflateCtx, MessageKind, WsEncoder, WsEvent,
    WsParser, OP_PING, OP_PONG,
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
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use wok_relay::{supported_nips, Config, Outbound, OutboundFrame, RelayHandle};

const SOFTWARE: &str = "git+https://github.com/erskingardner/wok.git";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("WOK_GIT_HASH");
pub(crate) const WOK_MARK_SVG: &str = r##"<svg viewBox="0 0 1028 1028" aria-hidden="true" focusable="false"><rect width="1028" height="1028" fill="#090B0F"/><path fill="currentColor" d="M299.15 797.05C278.15 797.05 260 791.65 244.7 780.85C229.7 769.75 217.1 754 206.9 733.6C196.7 712.9 188 688.15 180.8 659.35C176.9 643.45 173.3 625.6 170 605.8C167 585.7 164.3 564.55 161.9 542.35C159.8 520.15 158 497.65 156.5 474.85C155.3 452.05 154.4 429.7 153.8 407.8C153.5 385.9 153.35 365.5 153.35 346.6C153.35 333.4 153.95 320.95 155.15 309.25C156.65 297.25 159.5 286.75 163.7 277.75C167.9 268.45 173.9 261.25 181.7 256.15C189.5 250.75 199.7 248.05 212.3 248.05C232.4 248.05 246.65 253.6 255.05 264.7C263.75 275.8 269 291.85 270.8 312.85C271.1 334.15 271.55 354.25 272.15 373.15C272.75 391.75 273.5 409.6 274.4 426.7C275.3 443.5 276.2 460 277.1 476.2C278.3 492.1 279.65 507.85 281.15 523.45C282.65 539.05 284.3 554.95 286.1 571.15C289.4 601.15 294.65 623.95 301.85 639.55C309.05 655.15 318.65 662.95 330.65 662.95C342.65 662.95 352.25 655.75 359.45 641.35C366.65 626.95 373.7 604.6 380.6 574.3C384.2 558.1 387.8 540.85 391.4 522.55C395 504.25 398.6 485.65 402.2 466.75C405.8 447.55 409.4 428.95 413 410.95C416.6 392.65 419.9 375.4 422.9 359.2C430.7 319.9 441.35 289.6 454.85 268.3C468.65 247 488.6 236.35 514.7 236.35C530 236.35 542.75 241.75 552.95 252.55C563.45 263.35 572.15 277.75 579.05 295.75C585.95 313.75 591.8 333.4 596.6 354.7C599.3 368.2 602 382.15 604.7 396.55C607.4 410.95 610.1 425.5 612.8 440.2C615.5 454.9 618.2 469.6 620.9 484.3C623.6 499 626.15 513.4 628.55 527.5C630.95 541.3 633.2 554.5 635.3 567.1C640.1 596.2 645.2 618.25 650.6 633.25C656.3 648.25 665.3 655.75 677.6 655.75C689 655.75 698.3 647.8 705.5 631.9C713 615.7 719.45 594.7 724.85 568.9C728.15 553.9 731.15 537.7 733.85 520.3C736.85 502.6 739.4 484.45 741.5 465.85C743.9 446.95 746 428.5 747.8 410.5C749.9 392.2 751.7 374.95 753.2 358.75C754.7 342.25 756.05 327.55 757.25 314.65C759.05 302.95 762.05 292.9 766.25 284.5C770.45 275.8 776.75 269.05 785.15 264.25C793.55 259.15 804.65 256.6 818.45 256.6C828.95 256.6 837.65 258.7 844.55 262.9C851.75 267.1 857.45 272.95 861.65 280.45C865.85 287.65 868.85 296.2 870.65 306.1C872.45 315.7 873.35 326.35 873.35 338.05C873.35 353.65 872.6 372.55 871.1 394.75C869.6 416.65 867.35 440.2 864.35 465.4C861.65 490.6 858.05 515.95 853.55 541.45C849.35 566.65 844.4 590.65 838.7 613.45C833.3 635.95 827.15 655.6 820.25 672.4C805.25 710.8 786.8 740.2 764.9 760.6C743 780.7 719 790.75 692.9 790.75C663.8 790.75 640.7 782.2 623.6 765.1C606.5 747.7 592.55 720.55 581.75 683.65C579.05 671.95 576.35 659.95 573.65 647.65C570.95 635.05 568.25 622.15 565.55 608.95C563.15 595.75 560.6 582.25 557.9 568.45C555.2 554.35 552.5 540.1 549.8 525.7C547.4 511 545 496.15 542.6 481.15C538.1 453.55 533.45 431.5 528.65 415C523.85 398.2 517.4 389.8 509.3 389.8C501.5 389.8 494.75 398.65 489.05 416.35C483.65 433.75 478.4 455.2 473.3 480.7C465.8 517.9 458.6 554.05 451.7 589.15C445.1 623.95 437 656.35 427.4 686.35C416.9 714.25 405.5 736.3 393.2 752.5C380.9 768.4 366.95 779.8 351.35 786.7C336.05 793.6 318.65 797.05 299.15 797.05Z"/></svg>"##;

pub async fn serve(handle: RelayHandle, bind: SocketAddr) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(bind).await?;
    serve_listener(handle, listener).await
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
    tracing::info!("Started websocket server on {}", listener.local_addr()?);
    let handle = Arc::new(handle);
    let admin_state = Arc::new(admin::AdminState::default());
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
    // Honor relay.realIpHeader for reverse-proxied deployments (C++ strfry
    // uses the header value as the client IP).
    let peer = {
        let cfg = handle.config.read();
        if cfg.relay.real_ip_header.is_empty() {
            peer
        } else {
            req.headers()
                .get(cfg.relay.real_ip_header.as_str())
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or(peer)
        }
    };
    let is_ws_upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let ip = match peer.ip() {
        std::net::IpAddr::V4(value) => value.octets().to_vec(),
        std::net::IpAddr::V6(value) => value.octets().to_vec(),
    };
    if is_ws_upgrade {
        if !handle.admit_connection(&ip) {
            return text_status_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate-limited: connection budget exhausted",
            );
        }
        return upgrade_ws(req, handle, peer).await;
    }
    // Plain HTTP endpoints (/admin/api/*, /metrics, NIP-11, ...) otherwise
    // have no per-IP budget: every /admin/api attempt runs a Schnorr
    // verification before rejection, a straight unauthenticated CPU drain.
    // Gate them behind the connection budget.
    if !handle.admit_connection(&ip) {
        return text_status_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate-limited: connection budget exhausted",
        );
    }
    let path = req.uri().path().to_string();
    if matches!(path.as_str(), "/admin" | "/admin/") || path.starts_with("/admin/api/") {
        return admin::dispatch(req, handle, admin_state).await;
    }
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
    html_response(&landing(&cfg, &handle.supported_nips()))
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
    let max = handle.config.read().relay.max_websocket_payload_size;
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
    let ip: Arc<[u8]> = match peer.ip() {
        std::net::IpAddr::V4(v) => Arc::from(v.octets()),
        std::net::IpAddr::V6(v) => Arc::from(v.octets()),
    };
    let auto_ping = handle.config.read().relay.auto_ping_seconds;
    let frame_read_timeout = handle.config.read().relay.frame_read_timeout_secs;
    let frame_idle_timeout =
        (frame_read_timeout > 0).then(|| std::time::Duration::from_secs(frame_read_timeout));
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
    let mut incoming_events = Vec::with_capacity(4);
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(auto_ping.max(1)));
    // Delay (not the Burst default): after the select is stalled elsewhere
    // for two or more intervals, Burst would fire back-to-back ticks — send
    // a ping, then immediately close for a pong the peer never got a window
    // to send. Delay guarantees one full interval per outstanding ping.
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    if auto_ping > 0 {
        ping.tick().await; // first tick is immediate; skip it
    }
    // Liveness: a ping unanswered when the next ping interval elapses means
    // the peer is gone (or deliberately silent) — close the connection.
    let mut awaiting_pong = false;
    'outer: loop {
        tokio::select! {
            _ = killed.notified() => {
                tracing::info!(conn_id, peer = %peer, reason = "slow_client", "client terminated");
                break;
            }
            _ = ping.tick(), if auto_ping > 0 => {
                if awaiting_pong {
                    tracing::info!(conn_id, peer = %peer, reason = "pong_timeout", "client terminated");
                    break;
                }
                if write_bytes(&mut wr, &encoder.encode_control(OP_PING, &[])).await.is_err() {
                    break;
                }
                awaiting_pong = true;
            }
            incoming = read_events_into(&mut rd, &mut parser, &mut incoming_events, frame_idle_timeout) => {
                match incoming {
                    Ok(()) => {
                        for ev in incoming_events.drain(..) {
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
                                WsEvent::Pong(_) => {
                                    awaiting_pong = false;
                                }
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
