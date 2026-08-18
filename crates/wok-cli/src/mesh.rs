//! Shared helpers for outbound mesh (relay-to-relay) websocket connections.

use futures_util::future::{BoxFuture, FutureExt, Shared};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const NIP11_TIMEOUT: Duration = Duration::from_secs(3);
const NIP11_VALID_TTL: Duration = Duration::from_secs(60 * 60);
const NIP11_FAILURE_TTL: Duration = Duration::from_secs(5 * 60);
const NIP11_MAX_BYTES: usize = 256 * 1024;
const NIP11_CACHE_CAPACITY: usize = 256;

#[derive(Clone)]
struct CapabilityResult {
    supported_nips: Result<Arc<HashSet<u64>>, Arc<str>>,
    expires_at: Instant,
}

type CapabilityFuture = Shared<BoxFuture<'static, Arc<CapabilityResult>>>;

struct CacheEntry {
    generation: u64,
    last_used: Instant,
    result: CapabilityFuture,
}

#[derive(Default)]
struct CapabilityCache {
    entries: HashMap<String, CacheEntry>,
    next_generation: u64,
}

static NIP11_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(NIP11_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("NIP-11 HTTP client configuration is valid")
});

static CAPABILITY_CACHE: std::sync::LazyLock<tokio::sync::Mutex<CapabilityCache>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(CapabilityCache::default()));

fn nip11_url(relay_url: &str) -> Option<String> {
    let mut url = url::Url::parse(relay_url).ok()?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        _ => return None,
    };
    url.set_scheme(scheme).ok()?;
    url.set_fragment(None);
    Some(url.to_string())
}

async fn fetch_nip11(http_url: String) -> Arc<CapabilityResult> {
    let fetched_at = Instant::now();
    let fetched = async {
        let mut response = NIP11_CLIENT
            .get(&http_url)
            .header(reqwest::header::ACCEPT, "application/nostr+json")
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("HTTP {}", response.status());
        }
        if response
            .content_length()
            .is_some_and(|length| length > NIP11_MAX_BYTES as u64)
        {
            anyhow::bail!("response exceeds {NIP11_MAX_BYTES} bytes");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > NIP11_MAX_BYTES {
                anyhow::bail!("response exceeds {NIP11_MAX_BYTES} bytes");
            }
            bytes.extend_from_slice(&chunk);
        }
        let document: Value = serde_json::from_slice(&bytes)?;
        parse_supported_nips(&document)
    }
    .await;

    match fetched {
        Ok(supported_nips) => {
            tracing::debug!(url = %http_url, ?supported_nips, "cached relay NIP-11 capabilities");
            Arc::new(CapabilityResult {
                supported_nips: Ok(Arc::new(supported_nips)),
                expires_at: fetched_at + NIP11_VALID_TTL,
            })
        }
        Err(error) => {
            tracing::warn!(url = %http_url, %error, "NIP-11 capability lookup failed");
            Arc::new(CapabilityResult {
                supported_nips: Err(Arc::from(error.to_string())),
                expires_at: fetched_at + NIP11_FAILURE_TTL,
            })
        }
    }
}

fn parse_supported_nips(document: &Value) -> anyhow::Result<HashSet<u64>> {
    let Some(nips) = document.get("supported_nips") else {
        return Ok(HashSet::new());
    };
    let nips = nips
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("supported_nips is not an array"))?;
    nips.iter()
        .map(|nip| {
            nip.as_u64()
                .ok_or_else(|| anyhow::anyhow!("supported_nips contains a non-integer"))
        })
        .collect()
}

async fn relay_supported_nips(relay_url: &str) -> Result<Arc<HashSet<u64>>, Arc<str>> {
    let Some(http_url) = nip11_url(relay_url) else {
        return Err(Arc::from("invalid relay URL"));
    };

    loop {
        let now = Instant::now();
        let (generation, result) = {
            let mut cache = CAPABILITY_CACHE.lock().await;
            if let Some(entry) = cache.entries.get_mut(&http_url) {
                entry.last_used = now;
                (entry.generation, entry.result.clone())
            } else {
                if cache.entries.len() >= NIP11_CACHE_CAPACITY {
                    let evict = cache
                        .entries
                        .iter()
                        .min_by_key(|(_, entry)| entry.last_used)
                        .map(|(url, _)| url.clone());
                    if let Some(evict) = evict {
                        cache.entries.remove(&evict);
                    }
                }
                let generation = cache.next_generation;
                cache.next_generation = cache.next_generation.wrapping_add(1);
                let result = fetch_nip11(http_url.clone()).boxed().shared();
                cache.entries.insert(
                    http_url.clone(),
                    CacheEntry {
                        generation,
                        last_used: now,
                        result: result.clone(),
                    },
                );
                (generation, result)
            }
        };

        let capability = result.await;
        if capability.expires_at > Instant::now() {
            return capability.supported_nips.clone();
        }

        let mut cache = CAPABILITY_CACHE.lock().await;
        if cache
            .entries
            .get(&http_url)
            .is_some_and(|entry| entry.generation == generation)
        {
            cache.entries.remove(&http_url);
        }
    }
}

/// True when a filter object carries at least one NIP-91 `&x` query key.
fn carries_and_tags(filter: &Value) -> bool {
    filter
        .as_object()
        .is_some_and(|object| object.keys().any(|key| key.starts_with('&')))
}

/// Rewrite one filter object into the NIP-91 compatibility form: every `&x`
/// value set is folded into the `#x` OR clause (creating it when absent) and
/// the `&x` key is removed.
///
/// The fold, rather than a plain strip, is what the draft asks clients to send:
/// "Tag values used in `AND` by libraries and clients `MUST` include standard
/// `OR` tags [`#`] for compatibility with relays that do not support NIP-91."
/// Every event matching the AND clause carries all of its required values, so
/// the rewritten filter is a strict superset — it can never collapse into a
/// match-all the way dropping the keys outright would.
fn compatibility_filter(filter: &Value) -> anyhow::Result<Value> {
    let Some(object) = filter.as_object() else {
        return Ok(filter.clone());
    };

    let mut compatible = serde_json::Map::new();
    let mut required: Vec<(String, &Vec<Value>)> = Vec::new();
    for (key, value) in object {
        let Some(tag) = key.strip_prefix('&') else {
            compatible.insert(key.clone(), value.clone());
            continue;
        };
        if tag.len() != 1 || !tag.as_bytes()[0].is_ascii_alphabetic() {
            anyhow::bail!("unindexed AND tag filter: {key}");
        }
        let values = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("{key} not an array"))?;
        if values.is_empty() {
            anyhow::bail!("{key} array must not be empty");
        }
        required.push((format!("#{tag}"), values));
    }

    for (compat_key, values) in required {
        let alternatives = compatible
            .entry(compat_key.clone())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("{compat_key} not an array"))?;
        for value in values {
            if !alternatives.contains(value) {
                alternatives.push(value.clone());
            }
        }
    }

    Ok(Value::Object(compatible))
}

/// Adapt an outbound REQ or NEG-OPEN filter to what the upstream relay
/// understands. Relays reject unrecognised filter keys, so NIP-91 `&x` clauses
/// are only forwarded when the upstream advertises NIP 91 in its NIP-11
/// document; otherwise they are folded into the `#x` compatibility clause and
/// the exact AND semantics are re-applied locally by the caller.
///
/// NIP-11 governs the NIP-91 decision alone. An unreachable or malformed
/// document means "unknown", which degrades to the compatibility filter rather
/// than failing — no other protocol support is inferred from it.
pub(crate) async fn outbound_filter_for_relay(
    relay_url: &str,
    filter: &Value,
) -> anyhow::Result<Value> {
    let carries_and = match filter {
        Value::Array(entries) => entries.iter().any(carries_and_tags),
        other => carries_and_tags(other),
    };
    if !carries_and {
        return Ok(filter.clone());
    }

    // Reject malformed `&` clauses before the network round trip so the error
    // never depends on upstream reachability.
    let compatible = match filter {
        Value::Array(entries) => Value::Array(
            entries
                .iter()
                .map(compatibility_filter)
                .collect::<anyhow::Result<Vec<_>>>()?,
        ),
        other => compatibility_filter(other)?,
    };

    match relay_supported_nips(relay_url).await {
        Ok(nips) if nips.contains(&91) => return Ok(filter.clone()),
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(url = relay_url, %error, "NIP-11 unavailable; assuming no NIP-91 support")
        }
    }
    tracing::warn!(
        url = relay_url,
        "upstream does not advertise NIP-91; sending the `#` compatibility filter and applying AND tags locally"
    );
    Ok(compatible)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn nip11_server(
        document: &'static str,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut request = vec![0; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    document.len(),
                    document
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (format!("ws://{address}/relay"), requests, task)
    }

    #[test]
    fn nip11_uses_the_relay_websocket_uri() {
        assert_eq!(
            nip11_url("wss://relay.example:7447/nostr?network=main#fragment").as_deref(),
            Some("https://relay.example:7447/nostr?network=main")
        );
        assert_eq!(
            nip11_url("ws://relay.example/").as_deref(),
            Some("http://relay.example/")
        );
        assert!(nip11_url("https://relay.example/").is_none());
    }

    #[tokio::test]
    async fn advertised_nip91_preserves_and_fields() {
        let (url, requests, server) = nip11_server(r#"{"supported_nips":[1,11,91]}"#).await;
        let filter = serde_json::json!({"&t":["a","b"],"#t":["a","b","c"]});
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            filter
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn unsupported_nip91_folds_and_values_into_the_compatibility_clause() {
        let (url, requests, server) = nip11_server(r#"{"supported_nips":[1,11]}"#).await;
        let filter = serde_json::json!({
            "&t":["a","b"],
            "#t":["b","c"],
            "kinds":[1]
        });
        let checks = (0..8).map(|_| outbound_filter_for_relay(&url, &filter));
        let results = futures_util::future::join_all(checks).await;
        for result in results {
            assert_eq!(
                result.unwrap(),
                serde_json::json!({"#t":["b","c","a"],"kinds":[1]})
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let _ = outbound_filter_for_relay(&url, &filter).await;
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
    }

    /// An `&`-only filter must not degrade into a match-all: stripping the key
    /// outright would subscribe the router to the whole remote firehose and
    /// make `wok sync` reconcile the entire remote set.
    #[tokio::test]
    async fn and_only_filter_never_widens_to_the_remote_firehose() {
        let (url, _, server) = nip11_server(r#"{"supported_nips":[1,11]}"#).await;
        let filter = serde_json::json!({"&t":["a","b"],"kinds":[1],"limit":10});
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            serde_json::json!({"#t":["a","b"],"kinds":[1],"limit":10})
        );
        server.abort();
    }

    #[tokio::test]
    async fn every_and_key_gets_its_own_compatibility_clause() {
        let (url, _, server) = nip11_server(r#"{"supported_nips":[1,11]}"#).await;
        let author = "11".repeat(32);
        let filter = serde_json::json!({"&t":["a"],"&p":[author.clone()]});
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            serde_json::json!({"#t":["a"],"#p":[author]})
        );
        server.abort();
    }

    #[tokio::test]
    async fn filter_arrays_are_rewritten_per_element() {
        let (url, _, server) = nip11_server(r#"{"supported_nips":[1,11]}"#).await;
        let filter = serde_json::json!([{"&t":["a"]},{"#e":["ff".repeat(32)]}]);
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            serde_json::json!([{"#t":["a"]},{"#e":["ff".repeat(32)]}])
        );
        server.abort();
    }

    #[tokio::test]
    async fn malformed_nip11_uses_and_caches_the_compatibility_filter() {
        let (url, requests, server) = nip11_server("not-json").await;
        let filter = serde_json::json!({"&t":["a"]});
        let expected = serde_json::json!({"#t":["a"]});
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            expected
        );
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            expected
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
    }

    /// NIP-11 governs the NIP-91 decision only. `wok sync` sends NEG-OPEN and
    /// lets the relay answer for NIP-77 itself, so an upstream that omits 77
    /// from `supported_nips` must not be rejected before the websocket opens.
    #[tokio::test]
    async fn nip77_is_not_inferred_from_the_nip11_document() {
        let (url, _, server) = nip11_server(r#"{"supported_nips":[1,11,91]}"#).await;
        let filter = serde_json::json!({"&t":["a"],"#t":["a","b"]});
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            filter
        );
        server.abort();

        let (url, _, server) = nip11_server(r#"{"supported_nips":[1,11]}"#).await;
        assert_eq!(
            outbound_filter_for_relay(&url, &filter).await.unwrap(),
            serde_json::json!({"#t":["a","b"]})
        );
        server.abort();
    }

    #[tokio::test]
    async fn an_unavailable_relay_falls_back_to_the_compatibility_filter() {
        let filter = serde_json::json!({"&t":["a"]});
        assert_eq!(
            outbound_filter_for_relay("not a relay URL", &filter)
                .await
                .unwrap(),
            serde_json::json!({"#t":["a"]})
        );
    }

    #[tokio::test]
    async fn malformed_and_clauses_fail_before_any_capability_lookup() {
        for filter in [
            serde_json::json!({"&t":"a"}),
            serde_json::json!({"&t":[]}),
            serde_json::json!({"&foo":["a"]}),
            serde_json::json!({"&t":["a"],"#t":"a"}),
        ] {
            assert!(
                outbound_filter_for_relay("not a relay URL", &filter)
                    .await
                    .is_err(),
                "{filter} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn filters_without_nip91_fields_do_not_trigger_discovery() {
        let filter = serde_json::json!({"#t":["a","b"]});
        assert_eq!(
            outbound_filter_for_relay("not a relay URL", &filter)
                .await
                .unwrap(),
            filter
        );
    }

    #[test]
    fn supported_nips_require_integer_entries() {
        let nips = parse_supported_nips(&serde_json::json!({"supported_nips":[77,91]})).unwrap();
        assert!(nips.contains(&77));
        assert!(nips.contains(&91));
        assert!(parse_supported_nips(&serde_json::json!({"supported_nips":["91"]})).is_err());
    }
}
