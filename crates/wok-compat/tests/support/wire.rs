//! Shared real-transport client for lifecycle tests and the soak driver.
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::time::Duration;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

pub enum Wire {
    Ws(Box<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>),
    Unix(tokio::net::UnixStream),
}

impl Wire {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        if let Some(path) = endpoint.strip_prefix("unix://") {
            Ok(Self::Unix(
                wok_unix::connect(std::path::Path::new(path)).await?,
            ))
        } else {
            Ok(Self::Ws(Box::new(
                tokio_tungstenite::connect_async_with_config(endpoint, None, true)
                    .await?
                    .0,
            )))
        }
    }

    pub async fn send(&mut self, value: Value) -> Result<()> {
        let text = wok_event::json::to_tao_string(&value);
        tokio::time::timeout(Duration::from_secs(10), async {
            match self {
                Self::Ws(ws) => ws.send(Message::Text(text.into())).await?,
                Self::Unix(socket) => wok_unix::write_frame(socket, text.as_bytes()).await?,
            }
            Ok(())
        })
        .await
        .context("send deadline")?
    }

    pub async fn recv(&mut self) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let text = match self {
                    Self::Ws(ws) => match ws.next().await.context("WebSocket closed")?? {
                        Message::Text(text) => text.to_string(),
                        Message::Ping(bytes) => {
                            ws.send(Message::Pong(bytes)).await?;
                            continue;
                        }
                        Message::Close(_) => anyhow::bail!("WebSocket closed"),
                        other => anyhow::bail!("unexpected frame: {other:?}"),
                    },
                    Self::Unix(socket) => {
                        String::from_utf8(wok_unix::read_frame(socket, 2 * 1024 * 1024).await?)?
                    }
                };
                return Ok(wok_event::json::parse_strict(&text)?);
            }
        })
        .await
        .context("receive deadline")?
    }
}
