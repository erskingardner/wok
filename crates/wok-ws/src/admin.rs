use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::Digest;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use wok_relay::{Config, RelayHandle};

const MAX_ADMIN_BODY: usize = 64 * 1024;
const MAX_REPLAY_IDS: usize = 4096;

#[derive(Default)]
pub struct AdminState {
    used_auth: Mutex<HashMap<[u8; 32], u64>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigPatch {
    info: Option<InfoPatch>,
    limits: Option<LimitsPatch>,
    abuse: Option<AbusePatch>,
    history: Option<HistoryPatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfoPatch {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsPatch {
    max_filter_limit: Option<u64>,
    max_filter_limit_count: Option<u64>,
    max_total_events_per_req: Option<u64>,
    max_pending_outbound_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbusePatch {
    enabled: Option<bool>,
    max_concurrent_historical_queries: Option<usize>,
    max_query_cost: Option<u64>,
    max_stored_events_per_pubkey: Option<u64>,
    min_pow_difficulty: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryPatch {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    max_points: Option<usize>,
}

pub async fn dispatch(
    req: Request<Incoming>,
    handle: Arc<RelayHandle>,
    state: Arc<AdminState>,
) -> Response<Full<Bytes>> {
    let cfg = handle.config.read().clone();
    if !cfg.admin.enabled {
        return response(StatusCode::NOT_FOUND, "text/plain", "not found");
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(&path)
        .to_string();
    if matches!(path.as_str(), "/admin" | "/admin/") && method == Method::GET {
        return admin_page(&cfg);
    }
    if !path.starts_with("/admin/api/") {
        return response(StatusCode::NOT_FOUND, "text/plain", "not found");
    }

    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match read_body(req.into_body(), MAX_ADMIN_BODY).await {
        Ok(body) => body,
        Err(error) => return response(StatusCode::PAYLOAD_TOO_LARGE, "text/plain", &error),
    };
    let absolute_url = format!("{}{}", cfg.admin.public_url, path_and_query);
    let admin_pubkey = match authorize(
        authorization.as_deref(),
        &method,
        &absolute_url,
        &body,
        &cfg,
        &state,
    ) {
        Ok(pubkey) => pubkey,
        Err(error) => return unauthorized(&error),
    };

    tracing::info!(
        admin_pubkey = %admin_pubkey,
        method = %method,
        path = %path,
        "authorized admin request"
    );
    match (method, path.as_str()) {
        (Method::GET, "/admin/api/overview") => overview(&handle),
        (Method::PUT, "/admin/api/config") => update_config(&handle, &body),
        _ => response(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

async fn read_body(mut body: Incoming, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| error.to_string())?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > maximum {
                return Err(format!("admin request body exceeds {maximum} bytes"));
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

fn authorize(
    authorization: Option<&str>,
    method: &Method,
    absolute_url: &str,
    body: &[u8],
    cfg: &Config,
    state: &AdminState,
) -> Result<String, String> {
    let encoded = authorization
        .and_then(|value| value.strip_prefix("Nostr "))
        .ok_or_else(|| "missing Nostr authorization".to_string())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid Nostr authorization encoding".to_string())?;
    let event: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| "invalid Nostr authorization JSON".to_string())?;
    let parsed = wok_event::parse_and_verify_event(
        &event,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .map_err(|error| format!("invalid Nostr authorization event: {error}"))?;
    let packed = parsed.packed.view();
    if packed.kind() != 27235 {
        return Err("NIP-98 authorization must be kind 27235".into());
    }
    if event.get("content").and_then(serde_json::Value::as_str) != Some("") {
        return Err("NIP-98 authorization content must be empty".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if packed.created_at().abs_diff(now) > cfg.admin.auth_window_secs {
        return Err("NIP-98 authorization is outside the accepted time window".into());
    }
    if single_tag(&event, "u")? != absolute_url {
        return Err("NIP-98 u tag does not match the absolute request URL".into());
    }
    if single_tag(&event, "method")? != method.as_str() {
        return Err("NIP-98 method tag does not match the request method".into());
    }
    if !body.is_empty() {
        let payload = single_tag(&event, "payload")?;
        if payload != hex::encode(sha2::Sha256::digest(body)) {
            return Err("NIP-98 payload tag does not match the request body".into());
        }
    }
    let pubkey = hex::encode(packed.pubkey());
    if !cfg.admin.pubkeys.iter().any(|allowed| allowed == &pubkey) {
        return Err("NIP-98 signer is not an administrator".into());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(packed.id());
    let mut used = state.used_auth.lock();
    used.retain(|_, created_at| created_at.abs_diff(now) <= cfg.admin.auth_window_secs);
    if used.contains_key(&id) {
        return Err("NIP-98 authorization event has already been used".into());
    }
    if used.len() >= MAX_REPLAY_IDS {
        return Err("NIP-98 replay cache is full".into());
    }
    used.insert(id, packed.created_at());
    Ok(pubkey)
}

fn single_tag<'a>(event: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    let matching: Vec<_> = event
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_array)
        .filter(|tag| tag.first().and_then(serde_json::Value::as_str) == Some(name))
        .collect();
    if matching.len() != 1 {
        return Err(format!(
            "NIP-98 authorization requires exactly one {name} tag"
        ));
    }
    matching[0]
        .get(1)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("NIP-98 {name} tag must contain a string value"))
}

fn overview(handle: &RelayHandle) -> Response<Full<Bytes>> {
    let cfg = handle.config.read();
    json(
        StatusCode::OK,
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "history": handle.metrics.history_json(),
            "can_write_config": cfg.admin.allow_config_writes && handle.config_path().is_some(),
            "config": {
                "info": {
                    "name": cfg.relay.info.name,
                    "description": cfg.relay.info.description,
                },
                "limits": {
                    "max_filter_limit": cfg.relay.max_filter_limit,
                    "max_filter_limit_count": cfg.relay.max_filter_limit_count,
                    "max_total_events_per_req": cfg.relay.max_total_events_per_req,
                    "max_pending_outbound_bytes": cfg.relay.max_pending_outbound_bytes,
                },
                "abuse": {
                    "enabled": cfg.relay.abuse.enabled,
                    "max_concurrent_historical_queries": cfg.relay.abuse.max_concurrent_historical_queries,
                    "max_query_cost": cfg.relay.abuse.max_query_cost,
                    "max_stored_events_per_pubkey": cfg.relay.abuse.max_stored_events_per_pubkey,
                    "min_pow_difficulty": cfg.relay.abuse.min_pow_difficulty,
                },
                "history": {
                    "enabled": cfg.observability.history_enabled,
                    "interval_secs": cfg.observability.history_interval_secs,
                    "max_points": cfg.observability.history_max_points,
                }
            }
        }),
    )
}

fn update_config(handle: &RelayHandle, body: &[u8]) -> Response<Full<Bytes>> {
    let current = handle.config.read().clone();
    if !current.admin.allow_config_writes {
        return response(
            StatusCode::FORBIDDEN,
            "text/plain",
            "config writes are disabled",
        );
    }
    let Some(path) = handle.config_path() else {
        return response(
            StatusCode::CONFLICT,
            "text/plain",
            "relay was not started from a writable config file",
        );
    };
    let patch: ConfigPatch = match serde_json::from_slice(body) {
        Ok(patch) => patch,
        Err(error) => return response(StatusCode::BAD_REQUEST, "text/plain", &error.to_string()),
    };
    let mut next = current;
    apply_patch(&mut next, patch);
    let encoded = match next.to_toml() {
        Ok(encoded) => encoded,
        Err(error) => return response(StatusCode::BAD_REQUEST, "text/plain", &error),
    };
    let verified = match Config::parse_toml(&encoded) {
        Ok(config) => config,
        Err(error) => return response(StatusCode::BAD_REQUEST, "text/plain", &error),
    };
    if let Err(error) = atomic_write_config(&path, encoded.as_bytes()) {
        return response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", &error);
    }
    handle.config.write().apply_reload(verified);
    json(StatusCode::OK, serde_json::json!({"saved": true}))
}

fn apply_patch(config: &mut Config, patch: ConfigPatch) {
    if let Some(info) = patch.info {
        if let Some(value) = info.name {
            config.relay.info.name = value;
        }
        if let Some(value) = info.description {
            config.relay.info.description = value;
        }
    }
    if let Some(limits) = patch.limits {
        if let Some(value) = limits.max_filter_limit {
            config.relay.max_filter_limit = value;
        }
        if let Some(value) = limits.max_filter_limit_count {
            config.relay.max_filter_limit_count = value;
        }
        if let Some(value) = limits.max_total_events_per_req {
            config.relay.max_total_events_per_req = value;
        }
        if let Some(value) = limits.max_pending_outbound_bytes {
            config.relay.max_pending_outbound_bytes = value;
        }
    }
    if let Some(abuse) = patch.abuse {
        if let Some(value) = abuse.enabled {
            config.relay.abuse.enabled = value;
        }
        if let Some(value) = abuse.max_concurrent_historical_queries {
            config.relay.abuse.max_concurrent_historical_queries = value;
        }
        if let Some(value) = abuse.max_query_cost {
            config.relay.abuse.max_query_cost = value;
        }
        if let Some(value) = abuse.max_stored_events_per_pubkey {
            config.relay.abuse.max_stored_events_per_pubkey = value;
        }
        if let Some(value) = abuse.min_pow_difficulty {
            config.relay.abuse.min_pow_difficulty = value;
        }
    }
    if let Some(history) = patch.history {
        if let Some(value) = history.enabled {
            config.observability.history_enabled = value;
        }
        if let Some(value) = history.interval_secs {
            config.observability.history_interval_secs = value;
        }
        if let Some(value) = history.max_points {
            config.observability.history_max_points = value;
        }
    }
}

fn atomic_write_config(path: &std::path::Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "config path has no parent directory".to_string())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    if let Ok(metadata) = std::fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())
            .map_err(|e| e.to_string())?;
    }
    temporary.write_all(contents).map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    temporary.persist(path).map_err(|e| e.error.to_string())?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn unauthorized(message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("WWW-Authenticate", "Nostr")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap()
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    response(status, "application/json", &value.to_string())
}

fn response(status: StatusCode, content_type: &str, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .unwrap()
}

fn admin_page(cfg: &Config) -> Response<Full<Bytes>> {
    let public_url = serde_json::to_string(&cfg.admin.public_url).unwrap_or_else(|_| "\"\"".into());
    let body = ADMIN_HTML.replace("__PUBLIC_URL__", &public_url);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
        )
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

const ADMIN_HTML: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wok operator</title><style>
:root{color-scheme:dark;--bg:#090b0f;--panel:#11151c;--line:#252c38;--text:#f7f4ed;--muted:#96a0b2;--hot:#ff8a3d;--green:#5bd6a2;--red:#ff6b6b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#3a1c0e 0,transparent 35%),var(--bg);color:var(--text);font:15px/1.45 ui-sans-serif,system-ui,-apple-system,sans-serif}main{max-width:1180px;margin:auto;padding:34px 24px 70px}header{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:14px}.mark{display:grid;place-items:center;width:46px;height:46px;border-radius:14px;background:var(--hot);color:#1b0c04;font-size:25px;font-weight:900;box-shadow:0 12px 35px #ff8a3d44}h1{font-size:24px;margin:0}small,.muted{color:var(--muted)}button{border:0;border-radius:10px;padding:10px 14px;background:var(--hot);color:#1e0c02;font-weight:750;cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}.status{padding:9px 12px;border:1px solid var(--line);border-radius:10px;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card,.panel{background:linear-gradient(180deg,#141922,#0f1319);border:1px solid var(--line);border-radius:16px;box-shadow:0 16px 45px #0004}.card{padding:18px}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.value{font-size:29px;font-weight:780;margin-top:8px}.panels{display:grid;grid-template-columns:1.5fr 1fr;gap:16px;margin-top:16px}.panel{padding:20px}h2{font-size:16px;margin:0 0 15px}.chart{height:245px;width:100%;background:#0b0e13;border-radius:12px;border:1px solid #1e2530}.form{display:grid;grid-template-columns:1fr 1fr;gap:13px}label{display:grid;gap:6px;color:var(--muted);font-size:12px}input{width:100%;background:#0a0d12;border:1px solid var(--line);border-radius:9px;padding:10px;color:var(--text)}label.wide{grid-column:1/-1}.actions{display:flex;align-items:center;justify-content:space-between;margin-top:16px}.ok{color:var(--green)}.bad{color:var(--red)}@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}.panels{grid-template-columns:1fr}}@media(max-width:480px){main{padding:22px 14px}.grid,.form{grid-template-columns:1fr}label.wide{grid-column:auto}header{align-items:flex-start;flex-direction:column}}
</style></head><body><main><header><div class="brand"><div class="mark">W</div><div><h1>Wok operator</h1><small>Authenticated relay control surface</small></div></div><div style="display:flex;gap:10px;align-items:center"><span id="status" class="status">Not connected</span><button id="connect">Connect signer</button></div></header>
<section class="grid"><div class="card"><div class="label">Connections</div><div id="connections" class="value">—</div></div><div class="card"><div class="label">Events written</div><div id="written" class="value">—</div></div><div class="card"><div class="label">Rejected</div><div id="rejected" class="value">—</div></div><div class="card"><div class="label">Protocol messages</div><div id="messages" class="value">—</div></div></section>
<section class="panels"><div class="panel"><h2>Connections over time</h2><canvas id="chart" class="chart"></canvas><p class="muted">Bounded in-memory samples; restart clears history.</p></div><div class="panel"><h2>Relay identity</h2><div class="form"><label class="wide">Name<input id="name"></label><label class="wide">Description<input id="description"></label></div></div></section>
<section class="panel" style="margin-top:16px"><h2>Runtime guardrails</h2><div class="form"><label>REQ event ceiling<input id="max_total" type="number" min="0"></label><label>COUNT ceiling<input id="max_count" type="number" min="0"></label><label>Query cost ceiling<input id="max_cost" type="number" min="0"></label><label>Concurrent history queries<input id="max_queries" type="number" min="0"></label><label>History interval (seconds)<input id="history_interval" type="number" min="1"></label><label>History points<input id="history_points" type="number" min="0" max="100000"></label></div><div class="actions"><span id="saveStatus" class="muted">Read-only until authenticated</span><button id="save" disabled>Save configuration</button></div></section>
</main><script>
const PUBLIC_BASE=__PUBLIC_URL__;let data=null;const $=id=>document.getElementById(id);const fmt=n=>new Intl.NumberFormat().format(n??0);
async function sha256(text){const bytes=new TextEncoder().encode(text),hash=await crypto.subtle.digest('SHA-256',bytes);return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,'0')).join('')}
async function authFetch(path,method='GET',body=''){if(!window.nostr)throw Error('A NIP-07 signer extension is required');const url=PUBLIC_BASE+path,tags=[['u',url],['method',method]];if(body)tags.push(['payload',await sha256(body)]);const ev=await window.nostr.signEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags});const headers={Authorization:'Nostr '+btoa(JSON.stringify(ev))};if(body)headers['Content-Type']='application/json';const res=await fetch(path,{method,body:body||undefined,headers});if(!res.ok)throw Error((await res.text())||res.statusText);return res.json()}
function field(id,value){$(id).value=value??''}function render(d){data=d;const c=d.history.current;$('connections').textContent=fmt(c.active_connections);$('written').textContent=fmt(c.written_events_total);$('rejected').textContent=fmt(c.rejected_events_total);$('messages').textContent=fmt(c.client_messages_total+c.relay_messages_total);field('name',d.config.info.name);field('description',d.config.info.description);field('max_total',d.config.limits.max_total_events_per_req);field('max_count',d.config.limits.max_filter_limit_count);field('max_cost',d.config.abuse.max_query_cost);field('max_queries',d.config.abuse.max_concurrent_historical_queries);field('history_interval',d.config.history.interval_secs);field('history_points',d.config.history.max_points);$('save').disabled=!d.can_write_config;$('saveStatus').textContent=d.can_write_config?'Changes are validated and atomically persisted':'Config writes are disabled';draw(d.history.points)}
function draw(points){const c=$('chart'),dpr=devicePixelRatio||1,r=c.getBoundingClientRect();c.width=r.width*dpr;c.height=r.height*dpr;const x=c.getContext('2d');x.scale(dpr,dpr);x.clearRect(0,0,r.width,r.height);x.strokeStyle='#252c38';for(let i=1;i<4;i++){x.beginPath();x.moveTo(0,r.height*i/4);x.lineTo(r.width,r.height*i/4);x.stroke()}if(!points.length)return;const max=Math.max(1,...points.map(p=>p.active_connections));x.strokeStyle='#ff8a3d';x.lineWidth=2;x.beginPath();points.forEach((p,i)=>{const px=i*Math.max(1,r.width/(points.length-1)),py=r.height-12-(p.active_connections/max)*(r.height-24);i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()}
async function load(){try{$('status').textContent='Signing…';render(await authFetch('/admin/api/overview'));$('status').textContent='Connected';$('status').className='status ok'}catch(e){$('status').textContent=e.message;$('status').className='status bad'}}
$('connect').onclick=load;$('save').onclick=async()=>{const body=JSON.stringify({info:{name:$('name').value,description:$('description').value},limits:{max_total_events_per_req:+$('max_total').value,max_filter_limit_count:+$('max_count').value},abuse:{max_query_cost:+$('max_cost').value,max_concurrent_historical_queries:+$('max_queries').value},history:{interval_secs:+$('history_interval').value,max_points:+$('history_points').value}});try{$('saveStatus').textContent='Signing and saving…';await authFetch('/admin/api/config','PUT',body);$('saveStatus').textContent='Saved atomically';await load()}catch(e){$('saveStatus').textContent=e.message}};addEventListener('resize',()=>data&&draw(data.history.points));setInterval(()=>data&&load(),15000);
</script></body></html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;

    fn signed_auth(key: &Keypair, url: &str, method: &str, body: &[u8]) -> String {
        let (pubkey, _) = key.x_only_public_key();
        let mut tags = vec![json!(["u", url]), json!(["method", method])];
        if !body.is_empty() {
            tags.push(json!(["payload", hex::encode(sha2::Sha256::digest(body))]));
        }
        let mut event = json!({
            "pubkey": hex::encode(pubkey.serialize()),
            "created_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "kind": 27235,
            "tags": tags,
            "content": "",
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.to_string())
        )
    }

    #[test]
    fn nip98_binds_admin_method_url_payload_and_prevents_replay() {
        let mut rng = rand::thread_rng();
        let key = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = key.x_only_public_key();
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec![hex::encode(pubkey.serialize())];
        let state = AdminState::default();
        let body = br#"{"history":{"max_points":10}}"#;
        let header = signed_auth(&key, "https://relay.example/admin/api/config", "PUT", body);
        assert!(authorize(
            Some(&header),
            &Method::PUT,
            "https://relay.example/admin/api/config",
            body,
            &cfg,
            &state
        )
        .is_ok());
        assert!(authorize(
            Some(&header),
            &Method::PUT,
            "https://relay.example/admin/api/config",
            body,
            &cfg,
            &state
        )
        .unwrap_err()
        .contains("already been used"));

        let wrong_payload = signed_auth(
            &key,
            "https://relay.example/admin/api/config",
            "PUT",
            b"different",
        );
        assert!(authorize(
            Some(&wrong_payload),
            &Method::PUT,
            "https://relay.example/admin/api/config",
            body,
            &cfg,
            &AdminState::default()
        )
        .unwrap_err()
        .contains("payload"));

        let wrong_url = signed_auth(&key, "https://relay.example/admin/api/other", "GET", b"");
        assert!(authorize(
            Some(&wrong_url),
            &Method::GET,
            "https://relay.example/admin/api/overview",
            b"",
            &cfg,
            &AdminState::default()
        )
        .unwrap_err()
        .contains("absolute request URL"));

        let other_key = Keypair::new(SECP256K1, &mut rng);
        let unauthorized = signed_auth(
            &other_key,
            "https://relay.example/admin/api/overview",
            "GET",
            b"",
        );
        assert!(authorize(
            Some(&unauthorized),
            &Method::GET,
            "https://relay.example/admin/api/overview",
            b"",
            &cfg,
            &AdminState::default()
        )
        .unwrap_err()
        .contains("not an administrator"));
    }

    #[test]
    fn nip98_rejects_duplicate_or_malformed_binding_tags() {
        let duplicate = json!({"tags": [["u", "https://relay.example"], ["u"]]});
        assert!(single_tag(&duplicate, "u")
            .unwrap_err()
            .contains("exactly one"));
        let malformed = json!({"tags": [["method"]]});
        assert!(single_tag(&malformed, "method")
            .unwrap_err()
            .contains("string value"));
    }

    #[test]
    fn config_patch_is_typed_and_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(&path, "old").unwrap();
        atomic_write_config(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");

        let patch: ConfigPatch = serde_json::from_value(json!({
            "limits": {"max_total_events_per_req": 123},
            "history": {"max_points": 10}
        }))
        .unwrap();
        let mut cfg = Config::default();
        apply_patch(&mut cfg, patch);
        assert_eq!(cfg.relay.max_total_events_per_req, 123);
        assert_eq!(cfg.observability.history_max_points, 10);
        assert!(serde_json::from_value::<ConfigPatch>(json!({"database": {}})).is_err());
    }
}
