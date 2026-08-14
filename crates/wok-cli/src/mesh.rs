//! Shared helpers for outbound mesh (relay-to-relay) websocket connections.

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// Inbound messages on mesh connections carry at most one full event
/// (<= max_event_size) plus envelope overhead. Cap at 2x (+ slack) so a
/// malicious peer can't exploit tungstenite's 64 MiB default max message
/// size to amplify memory usage.
pub(crate) fn mesh_ws_config(max_event_size: usize) -> WebSocketConfig {
    let cap = max_event_size.saturating_mul(2).saturating_add(4096);
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(cap);
    cfg.max_frame_size = Some(cap);
    cfg
}

pub(crate) async fn connect_mesh(
    url: &str,
    max_event_size: usize,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WsError> {
    let (ws, _) = tokio_tungstenite::connect_async_with_config(
        url,
        Some(mesh_ws_config(max_event_size)),
        false,
    )
    .await?;
    Ok(ws)
}
