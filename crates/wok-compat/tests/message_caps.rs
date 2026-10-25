//! Message caps against the limits behind them. A WebSocket message as large
//! as `relay.max_websocket_payload_size` is read, and one a byte larger
//! closes the connection with 1009, so `Config::message_caps` warns exactly
//! when an EVENT of `events.max_event_size`, or a REQ (or, while COUNT is on,
//! a COUNT) of `relay.max_req_filter_size`, cannot arrive in its shortest
//! envelope.

use serde_json::{json, Value};
use wok_relay::Config;

#[path = "support/surface.rs"]
mod surface;
use surface::*;

/// A relay whose WebSocket messages are capped at `cap` bytes.
fn capped(cap: usize, max_event_size: usize, max_req_filter_size: usize) -> Config {
    let mut cfg = Config::default();
    cfg.relay.max_websocket_payload_size = cap;
    cfg.events.max_event_size = max_event_size;
    cfg.relay.max_req_filter_size = max_req_filter_size;
    // The cap applies to the inflated message; keep the test to plain frames.
    cfg.relay.compression_enabled = false;
    cfg
}

#[tokio::test]
async fn an_event_of_the_largest_size_arrives_exactly_when_no_cap_warns() {
    let event = wok_compat::sign_event(json!({
        "created_at": now(),
        "kind": 1,
        "tags": [],
        "content": "a note as large as the relay accepts",
    }));
    let event = wok_event::normalize_event_json(&event).unwrap();
    let message = format!(r#"["EVENT",{event}]"#);
    let size = event.len();

    let cfg = capped(message.len(), size, 16);
    assert_eq!(cfg.message_caps(), []);
    let relay = Relay::start(cfg).await;
    let mut wire = Wire::connect(relay.addr).await;
    wire.send_text(message.clone()).await;
    let ok = wire.until("OK", |frame| frame[0] == "OK").await;
    assert_eq!(ok[2], true, "{ok}");
    wire.close().await;
    relay.stop().await;

    let cfg = capped(message.len() - 1, size, 16);
    let keys: Vec<Vec<String>> = cfg.message_caps().into_iter().map(|w| w.keys).collect();
    assert_eq!(
        keys,
        [["relay.max_websocket_payload_size", "events.max_event_size"]]
    );
    let relay = Relay::start(cfg).await;
    let mut wire = Wire::connect(relay.addr).await;
    wire.send_text(message).await;
    assert_eq!(wire.closed().await, Some(1009));
    relay.stop().await;
}

#[tokio::test]
async fn a_req_of_the_largest_filters_arrives_exactly_when_no_cap_warns() {
    let filter = json!({"ids": [UNKNOWN_ID]});
    let size = filter.to_string().len();
    let message = format!(r#"["REQ","x",{filter}]"#);
    // COUNT's longer envelope would move the boundary; this case is the REQ's.
    let capped = |cap| {
        let mut cfg = capped(cap, 16, size);
        cfg.relay.max_filter_limit_count = 0;
        cfg
    };

    let cfg = capped(message.len());
    assert_eq!(cfg.message_caps(), []);
    let relay = Relay::start(cfg).await;
    let mut wire = Wire::connect(relay.addr).await;
    wire.send_text(message.clone()).await;
    let eose = wire.until("EOSE", |frame: &Value| frame[0] != "AUTH").await;
    assert_eq!(
        (&eose[0], &eose[1]),
        (&json!("EOSE"), &json!("x")),
        "{eose}"
    );
    wire.close().await;
    relay.stop().await;

    let cfg = capped(message.len() - 1);
    let keys: Vec<Vec<String>> = cfg.message_caps().into_iter().map(|w| w.keys).collect();
    assert_eq!(
        keys,
        [[
            "relay.max_websocket_payload_size",
            "relay.max_req_filter_size"
        ]]
    );
    let relay = Relay::start(cfg).await;
    let mut wire = Wire::connect(relay.addr).await;
    wire.send_text(message).await;
    assert_eq!(wire.closed().await, Some(1009));
    relay.stop().await;
}

#[tokio::test]
async fn a_count_of_the_largest_filters_arrives_exactly_when_no_cap_warns() {
    // A COUNT whose filter could match a restricted kind is refused.
    let filter = json!({"kinds": [1]});
    let size = filter.to_string().len();
    let message = format!(r#"["COUNT","x",{filter}]"#);

    let cfg = capped(message.len(), 16, size);
    assert!(cfg.relay.max_filter_limit_count > 0);
    assert_eq!(cfg.message_caps(), []);
    let relay = Relay::start(cfg).await;
    let mut wire = Wire::connect(relay.addr).await;
    wire.send_text(message.clone()).await;
    let count = wire
        .until("COUNT", |frame: &Value| frame[0] != "AUTH")
        .await;
    assert_eq!(count, json!(["COUNT", "x", {"count": 0}]), "{count}");
    wire.close().await;
    relay.stop().await;

    let cfg = capped(message.len() - 1, 16, size);
    let keys: Vec<Vec<String>> = cfg.message_caps().into_iter().map(|w| w.keys).collect();
    assert_eq!(
        keys,
        [[
            "relay.max_websocket_payload_size",
            "relay.max_req_filter_size"
        ]]
    );
    let relay = Relay::start(cfg).await;
    let mut wire = Wire::connect(relay.addr).await;
    wire.send_text(message).await;
    assert_eq!(wire.closed().await, Some(1009));
    relay.stop().await;
}
