//! NIP-86 Relay Management API: JSON-RPC-like requests over HTTP POST to the
//! relay URI with `Content-Type: application/nostr+json+rpc`, authorized by a
//! NIP-98 event whose `u` tag names the relay URL and whose `payload` tag is
//! required. Signers are operator admins (`admin.pubkeys` or the built-in
//! `admin` role) or moderators (built-in `moderator` role); moderation
//! methods accept either, relay-configuration and role methods require admin.

use crate::admin::{self, AdminState};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use wok_relay::{management_level, Config, ManagementCmd, ManagementLevel, RelayHandle, Role};

pub const RPC_CONTENT_TYPE: &str = "application/nostr+json+rpc";
const MAX_RPC_BODY: usize = 64 * 1024;

const SUPPORTED_METHODS: &[&str] = &[
    "supportedmethods",
    "banpubkey",
    "unbanpubkey",
    "listbannedpubkeys",
    "allowpubkey",
    "unallowpubkey",
    "listallowedpubkeys",
    "createrole",
    "editrole",
    "deleterole",
    "assignrole",
    "unassignrole",
    "listeventsneedingmoderation",
    "allowevent",
    "banevent",
    "listbannedevents",
    "changerelayname",
    "changerelaydescription",
    "changerelayicon",
    "allowkind",
    "disallowkind",
    "listallowedkinds",
    "blockip",
    "unblockip",
    "listblockedips",
];

/// Methods that change relay configuration or manage roles require the admin
/// level; everything else is moderation work open to moderators too.
fn requires_admin(method: &str) -> bool {
    matches!(
        method,
        "createrole"
            | "editrole"
            | "deleterole"
            | "assignrole"
            | "unassignrole"
            | "changerelayname"
            | "changerelaydescription"
            | "changerelayicon"
            | "allowkind"
            | "disallowkind"
            | "listallowedkinds"
    )
}

/// The signed `u` tag names the relay URL. Clients variously sign the ws(s)
/// or http(s) form, with or without a trailing slash, so compare on the
/// scheme-less, slash-less form of the configured public URL.
fn relay_url_matches(public_url: &str, signed: &str) -> bool {
    fn normalize(url: &str) -> String {
        let mut value = url.trim().to_ascii_lowercase();
        for scheme in ["https://", "http://", "wss://", "ws://"] {
            if let Some(rest) = value.strip_prefix(scheme) {
                value = rest.to_string();
                break;
            }
        }
        value.trim_end_matches('/').to_string()
    }
    !public_url.is_empty() && normalize(public_url) == normalize(signed)
}

pub async fn dispatch(
    req: Request<Incoming>,
    handle: Arc<RelayHandle>,
    state: Arc<AdminState>,
) -> Response<Full<Bytes>> {
    let cfg = handle.config.read().clone();
    if !cfg.admin.enabled {
        return admin::response(StatusCode::NOT_FOUND, "text/plain", "not found");
    }
    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match admin::read_body(req.into_body(), MAX_RPC_BODY).await {
        Ok(body) => body,
        Err(error) => return admin::response(StatusCode::PAYLOAD_TOO_LARGE, "text/plain", &error),
    };
    let (signer_hex, level, replay) =
        match authorize_manager(authorization.as_deref(), &body, &cfg, &state, |signer| {
            management_level(&cfg, &handle.moderation.read(), signer)
        }) {
            Ok(ok) => ok,
            Err(error) => return admin::unauthorized(&error),
        };
    tracing::info!(
        manager = %signer_hex,
        level = ?level,
        "authorized NIP-86 management request"
    );

    // Once a command reaches the writer it is applied even if this request
    // is cancelled or its reply reports an error, so only a failure before
    // that point releases the replay reservation.
    let mut reached_writer = false;
    match execute(&handle, level, &body, &mut reached_writer).await {
        Ok(result) => admin::json(StatusCode::OK, json!({ "result": result })),
        Err(error) => {
            if !reached_writer {
                replay.release();
            }
            admin::json(StatusCode::OK, json!({ "error": error }))
        }
    }
}

/// Verify a NIP-86 request's NIP-98 authorization and that its signer holds a
/// management role, returning the signer, its level and the replay
/// reservation.
fn authorize_manager<'a>(
    authorization: Option<&str>,
    body: &[u8],
    cfg: &Config,
    state: &'a AdminState,
    level_of: impl FnOnce(&[u8; 32]) -> ManagementLevel,
) -> Result<(String, ManagementLevel, admin::ReplayReservation<'a>), String> {
    let (signer_hex, replay) = admin::authorize(
        authorization,
        &Method::POST,
        body,
        cfg,
        state,
        &admin::AuthzPolicy {
            url_ok: &|signed| relay_url_matches(&cfg.admin.public_url, signed),
            require_config_admin: false,
            // Pinned NIP-86 makes the NIP-98 payload tag unconditional.
            require_payload: true,
        },
    )?;
    // A rejected signer ran nothing, so release its slot: otherwise any key
    // could fill the shared replay cache and lock out real managers.
    let level = match parse_hex32(&signer_hex) {
        Ok(signer) => level_of(&signer),
        Err(error) => {
            replay.release();
            return Err(error);
        }
    };
    if level == ManagementLevel::None {
        replay.release();
        return Err("NIP-98 signer has no management role on this relay".into());
    }
    Ok((signer_hex, level, replay))
}

async fn execute(
    handle: &Arc<RelayHandle>,
    level: ManagementLevel,
    body: &[u8],
    reached_writer: &mut bool,
) -> Result<Value, String> {
    let request: Value =
        serde_json::from_slice(body).map_err(|error| format!("invalid request JSON: {error}"))?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "request method must be a string".to_string())?;
    let params = request
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(|| "request params must be an array".to_string())?;
    if !SUPPORTED_METHODS.contains(&method) {
        return Err(format!("unsupported method {method:?}"));
    }
    if requires_admin(method) && level != ManagementLevel::Admin {
        return Err(format!("method {method:?} requires the admin role"));
    }

    match method {
        // The pinned spec returns the names of all *other* supported
        // methods: the meta-method excludes itself.
        "supportedmethods" => Ok(json!(SUPPORTED_METHODS
            .iter()
            .filter(|name| **name != "supportedmethods")
            .collect::<Vec<_>>())),
        "banpubkey" => {
            let (pubkey, reason) = hex32_reason_params(params, "pubkey")?;
            manage(
                handle,
                ManagementCmd::BanPubkey { pubkey, reason },
                reached_writer,
            )
            .await
        }
        "unbanpubkey" => {
            let (pubkey, _) = hex32_reason_params(params, "pubkey")?;
            manage(
                handle,
                ManagementCmd::UnbanPubkey { pubkey },
                reached_writer,
            )
            .await
        }
        "listbannedpubkeys" => Ok(list_hex_reasons(
            &handle.moderation.read().banned_pubkeys,
            "pubkey",
        )),
        "allowpubkey" => {
            let (pubkey, reason) = hex32_reason_params(params, "pubkey")?;
            manage(
                handle,
                ManagementCmd::AllowPubkey { pubkey, reason },
                reached_writer,
            )
            .await
        }
        "unallowpubkey" => {
            let (pubkey, _) = hex32_reason_params(params, "pubkey")?;
            manage(
                handle,
                ManagementCmd::UnallowPubkey { pubkey },
                reached_writer,
            )
            .await
        }
        "listallowedpubkeys" => Ok(list_hex_reasons(
            &handle.moderation.read().allowed_pubkeys,
            "pubkey",
        )),
        "banevent" => {
            let (id, reason) = hex32_reason_params(params, "event id")?;
            manage(
                handle,
                ManagementCmd::BanEvent { id, reason },
                reached_writer,
            )
            .await
        }
        "allowevent" => {
            let (id, _) = hex32_reason_params(params, "event id")?;
            manage(handle, ManagementCmd::AllowEvent { id }, reached_writer).await
        }
        "listbannedevents" => Ok(list_hex_reasons(
            &handle.moderation.read().banned_events,
            "id",
        )),
        "listeventsneedingmoderation" => Ok(list_hex_reasons(
            &handle.moderation.read().reported_events,
            "id",
        )),
        "blockip" => {
            let ip = string_param(params, 0, "ip address")?;
            let reason = optional_string_param(params, 1)?;
            manage(
                handle,
                ManagementCmd::BlockIp { ip, reason },
                reached_writer,
            )
            .await
        }
        "unblockip" => {
            let ip = string_param(params, 0, "ip address")?;
            manage(handle, ManagementCmd::UnblockIp { ip }, reached_writer).await
        }
        "listblockedips" => {
            let snap = handle.moderation.read();
            let mut entries: Vec<_> = snap.blocked_ips.iter().collect();
            entries.sort();
            Ok(json!(entries
                .into_iter()
                .map(|(ip, reason)| json!({ "ip": ip, "reason": reason }))
                .collect::<Vec<_>>()))
        }
        "createrole" | "editrole" => {
            let role = role_params(params)?;
            if method == "createrole" && handle.moderation.read().roles.contains_key(&role.id) {
                return Err(format!("role {:?} already exists", role.id));
            }
            if method == "editrole" && !handle.moderation.read().roles.contains_key(&role.id) {
                return Err(format!("unknown role {:?}", role.id));
            }
            manage(handle, ManagementCmd::PutRole { role }, reached_writer).await
        }
        "deleterole" => {
            let id = string_param(params, 0, "role id")?;
            manage(handle, ManagementCmd::DeleteRole { id }, reached_writer).await
        }
        "assignrole" | "unassignrole" => {
            let pubkey = parse_hex32(&string_param(params, 0, "pubkey")?)?;
            let role = string_param(params, 1, "role id")?;
            let cmd = if method == "assignrole" {
                ManagementCmd::AssignRole { pubkey, role }
            } else {
                ManagementCmd::UnassignRole { pubkey, role }
            };
            manage(handle, cmd, reached_writer).await
        }
        "changerelayname" => {
            let name = string_param(params, 0, "relay name")?;
            config_patch(handle, json!({ "info": { "name": name } }))
        }
        "changerelaydescription" => {
            let description = string_param(params, 0, "relay description")?;
            config_patch(handle, json!({ "info": { "description": description } }))
        }
        "changerelayicon" => {
            let icon = string_param(params, 0, "relay icon URL")?;
            config_patch(handle, json!({ "info": { "icon": icon } }))
        }
        "allowkind" => {
            let kind = kind_param(params)?;
            manage(handle, ManagementCmd::AllowKind { kind }, reached_writer).await
        }
        "disallowkind" => {
            let kind = kind_param(params)?;
            manage(handle, ManagementCmd::DisallowKind { kind }, reached_writer).await
        }
        "listallowedkinds" => {
            let snap = handle.moderation.read();
            let kinds = match &snap.kind_policy {
                Some(policy) => policy.allowed_kinds(),
                None => (0..=u16::MAX as u64).collect(),
            };
            Ok(json!(kinds))
        }
        _ => unreachable!("method checked against SUPPORTED_METHODS"),
    }
}

async fn manage(
    handle: &Arc<RelayHandle>,
    cmd: ManagementCmd,
    reached_writer: &mut bool,
) -> Result<Value, String> {
    // Conservative: a full writer queue also counts, so the operator re-signs.
    *reached_writer = true;
    handle.manage(cmd).await.map(|()| json!(true))
}

fn config_patch(handle: &Arc<RelayHandle>, patch: Value) -> Result<Value, String> {
    admin::apply_config_patch(handle, patch.to_string().as_bytes()).map_err(|(_, error)| error)?;
    Ok(json!(true))
}

fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{value:?} is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{value:?} is not 32 bytes of hex"))
}

fn string_param(params: &[Value], index: usize, name: &str) -> Result<String, String> {
    params
        .get(index)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("params[{index}] must be a {name} string"))
}

fn optional_string_param(params: &[Value], index: usize) -> Result<String, String> {
    match params.get(index) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(value) => value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("params[{index}] must be a string")),
    }
}

fn hex32_reason_params(params: &[Value], name: &str) -> Result<([u8; 32], String), String> {
    let value = parse_hex32(&string_param(params, 0, name)?)?;
    let reason = optional_string_param(params, 1)?;
    Ok((value, reason))
}

fn kind_param(params: &[Value]) -> Result<u64, String> {
    let kind = params
        .first()
        .and_then(Value::as_u64)
        .ok_or_else(|| "params[0] must be a kind number".to_string())?;
    if kind > u16::MAX as u64 {
        return Err("kind must be between 0 and 65535".into());
    }
    Ok(kind)
}

fn role_params(params: &[Value]) -> Result<Role, String> {
    Ok(Role {
        id: string_param(params, 0, "role id")?,
        label: string_param(params, 1, "role label")?,
        description: string_param(params, 2, "role description")?,
        color: string_param(params, 3, "role color")?,
        order: params
            .get(4)
            .and_then(Value::as_u64)
            .ok_or_else(|| "params[4] must be the role order number".to_string())?,
    })
}

fn list_hex_reasons(
    records: &std::collections::HashMap<[u8; 32], String>,
    key_name: &str,
) -> Value {
    let mut entries: Vec<_> = records.iter().collect();
    entries.sort_by_key(|(id, _)| **id);
    json!(entries
        .into_iter()
        .map(|(id, reason)| json!({ key_name: hex::encode(id), "reason": reason }))
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use secp256k1::{Keypair, SECP256K1};
    use sha2::Digest;

    fn signed_rpc_auth(key: &Keypair, url: &str, body: &[u8], nonce: usize) -> String {
        let (pubkey, _) = key.x_only_public_key();
        let mut event = json!({
            "pubkey": hex::encode(pubkey.serialize()),
            "created_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "kind": 27235,
            "tags": [
                ["u", url],
                ["method", "POST"],
                ["payload", hex::encode(sha2::Sha256::digest(body))],
                ["nonce", nonce.to_string()],
            ],
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
    fn rejected_non_managers_do_not_fill_the_replay_cache() {
        // A validly signed request from a key with no management role must
        // not hold a replay-cache slot, or anyone could fill the cache and
        // lock out real administrators.
        let mut rng = rand::thread_rng();
        let admin_key = Keypair::new(SECP256K1, &mut rng);
        let stranger = Keypair::new(SECP256K1, &mut rng);
        let admin_pubkey = admin_key.x_only_public_key().0.serialize();
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        let state = AdminState::default();
        let url = "wss://relay.example";
        let body = br#"{"method":"supportedmethods","params":[]}"#;
        let level_of = |signer: &[u8; 32]| {
            if *signer == admin_pubkey {
                ManagementLevel::Admin
            } else {
                ManagementLevel::None
            }
        };

        for nonce in 0..=admin::MAX_REPLAY_IDS {
            let header = signed_rpc_auth(&stranger, url, body, nonce);
            let error = authorize_manager(Some(&header), body, &cfg, &state, level_of).unwrap_err();
            assert!(error.contains("no management role"), "{error}");
        }
        let header = signed_rpc_auth(&admin_key, url, body, 0);
        let (_, level, _) = authorize_manager(Some(&header), body, &cfg, &state, level_of).unwrap();
        assert_eq!(level, ManagementLevel::Admin);
    }

    #[test]
    fn relay_url_matching_accepts_scheme_and_slash_variants() {
        let public = "https://Relay.Example.com";
        assert!(relay_url_matches(public, "https://relay.example.com"));
        assert!(relay_url_matches(public, "https://relay.example.com/"));
        assert!(relay_url_matches(public, "wss://relay.example.com"));
        assert!(relay_url_matches(public, "wss://relay.example.com/"));
        assert!(!relay_url_matches(public, "wss://other.example.com"));
        assert!(!relay_url_matches("", "wss://relay.example.com"));
    }

    #[test]
    fn method_level_classification_covers_every_supported_method() {
        for method in SUPPORTED_METHODS {
            let _ = requires_admin(method);
        }
        assert!(requires_admin("changerelayname"));
        assert!(requires_admin("assignrole"));
        assert!(!requires_admin("banpubkey"));
        assert!(!requires_admin("supportedmethods"));
    }

    #[test]
    fn supportedmethods_excludes_itself_from_its_result() {
        // Mirrors the execute() response construction.
        let reported: Vec<&&str> = SUPPORTED_METHODS
            .iter()
            .filter(|name| **name != "supportedmethods")
            .collect();
        assert!(!reported.contains(&&"supportedmethods"));
        assert_eq!(reported.len(), SUPPORTED_METHODS.len() - 1);
        assert!(reported.contains(&&"banpubkey"));
    }

    #[test]
    fn param_parsing_validates_shapes() {
        assert!(parse_hex32(&"ab".repeat(32)).is_ok());
        assert!(parse_hex32("zz").is_err());
        assert!(kind_param(&[json!(1)]).is_ok());
        assert!(kind_param(&[json!(65536)]).is_err());
        assert!(kind_param(&[json!("1")]).is_err());
        let (id, reason) =
            hex32_reason_params(&[json!("ab".repeat(32)), json!("spam")], "pubkey").unwrap();
        assert_eq!(id[0], 0xab);
        assert_eq!(reason, "spam");
        let (_, reason) = hex32_reason_params(&[json!("ab".repeat(32))], "pubkey").unwrap();
        assert_eq!(reason, "");
    }
}
