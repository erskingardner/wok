//! `wok_refusals_total{setting}` (tracking issue #97 §5.1): each refusal is
//! counted once, by the config key that refused it, and refusals no setting
//! makes (a NIP's fixed window, a NIP-86 decision) are not counted.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wok_relay::metrics::Setting;
use wok_relay::{
    Config, ConnectionGuard, ManagementCmd, Outbound, OutboundFrame, RelayHandle, TransportSource,
};

const AUTH_RELAY: &str = "wss://refusals.test";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn note(kind: u64, created_at: u64, tags: Value, content: &str) -> Value {
    wok_compat::sign_event(json!({
        "created_at": created_at, "kind": kind, "tags": tags, "content": content,
    }))
}

fn neg_initial() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}

struct Relay {
    _dir: tempfile::TempDir,
    handle: RelayHandle,
    base: Config,
    next_ip: u32,
}

impl Relay {
    fn start() -> Self {
        let (dir, env) = wok_compat::temp_db();
        let mut base = Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        base.relay.auth.service_url = AUTH_RELAY.into();
        let handle = wok_relay::start(env, base.clone()).unwrap();
        Self {
            _dir: dir,
            handle,
            base,
            next_ip: 0,
        }
    }

    /// A source no earlier case has charged.
    fn fresh_source(&mut self) -> TransportSource {
        self.next_ip += 1;
        let ip = std::net::Ipv4Addr::from(0x0a00_0000 + self.next_ip);
        TransportSource::ip_address(ip.into())
    }

    async fn client(&mut self) -> Client {
        let source = self.fresh_source();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = self
            .handle
            .register_connection(source, Outbound::new(tx, 0))
            .await;
        Client {
            conn,
            rx,
            challenge: None,
        }
    }

    fn counts(&self) -> HashMap<&'static str, u64> {
        self.handle
            .metrics
            .refusals
            .counts()
            .map(|(setting, count)| (setting.key(), count))
            .collect()
    }

    /// Run `case` under the base config changed by `tweak`, and check that
    /// it is refused once by `expected` and by no other setting.
    async fn expect<F>(
        &mut self,
        expected: Option<Setting>,
        tweak: impl FnOnce(&mut Config),
        case: F,
    ) where
        F: AsyncFnOnce(&mut Self),
    {
        let mut cfg = self.base.clone();
        tweak(&mut cfg);
        *self.handle.config.write() = cfg;
        let before = self.counts();
        case(self).await;
        let changed: HashMap<_, _> = self
            .counts()
            .into_iter()
            .filter_map(|(key, count)| {
                let delta = count - before[key];
                (delta != 0).then_some((key, delta))
            })
            .collect();
        let expected: HashMap<_, _> = expected.map(|s| (s.key(), 1)).into_iter().collect();
        assert_eq!(changed, expected);
        *self.handle.config.write() = self.base.clone();
    }
}

struct Client {
    conn: ConnectionGuard,
    rx: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    /// The NIP-42 challenge, once the relay has sent it.
    challenge: Option<Value>,
}

impl Client {
    async fn send(&self, msg: Value) {
        self.conn.client_message(msg.to_string()).await;
    }

    async fn recv(&mut self) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .expect("a frame from the relay")
            .unwrap();
        let msg: Value = serde_json::from_str(&frame.into_text()).unwrap();
        if msg[0] == "AUTH" {
            self.challenge = Some(msg[1].clone());
        }
        msg
    }

    /// The next frame for `id` that is one of `types`.
    async fn reply(&mut self, id: &str, types: &[&str]) -> Value {
        loop {
            let msg = self.recv().await;
            if msg[1] == id && types.iter().any(|t| msg[0] == *t) {
                return msg;
            }
        }
    }

    /// Publish `event` and return whether it was accepted.
    async fn publish(&mut self, event: &Value) -> bool {
        self.send(json!(["EVENT", event])).await;
        let ok = self.reply(event["id"].as_str().unwrap(), &["OK"]).await;
        ok[2] == true
    }

    async fn refused(&mut self, event: &Value) {
        assert!(!self.publish(event).await, "{event}");
    }

    /// Send a REQ or COUNT, and return the frame that ends it.
    async fn ask(&mut self, verb: &str, sub: &str, filters: &[Value]) -> Value {
        let mut msg = vec![json!(verb), json!(sub)];
        msg.extend_from_slice(filters);
        self.send(Value::Array(msg)).await;
        self.reply(sub, &["EOSE", "CLOSED", "COUNT"]).await
    }

    async fn closed(&mut self, verb: &str, sub: &str, filters: &[Value]) {
        let reply = self.ask(verb, sub, filters).await;
        assert_eq!(reply[0], "CLOSED", "{reply}");
    }

    /// Send `verb` requests until one is refused, at most 20.
    async fn until_closed(&mut self, verb: &str) {
        for i in 0..20 {
            let reply = self
                .ask(verb, &format!("u{i}"), &[json!({"kinds": [1], "limit": 1})])
                .await;
            if reply[0] == "CLOSED" {
                return;
            }
        }
        panic!("no {verb} was refused");
    }

    /// An AUTH event for this connection's challenge, with `extra` tags.
    async fn auth_event(&mut self, key: &Keypair, created_at: u64, extra: &[Value]) -> Value {
        while self.challenge.is_none() {
            self.recv().await;
        }
        let challenge = self.challenge.clone();
        let mut tags = vec![
            json!(["relay", AUTH_RELAY]),
            json!(["challenge", challenge]),
        ];
        tags.extend_from_slice(extra);
        wok_compat::sign_event_with_key(
            json!({"created_at": created_at, "kind": 22242, "tags": tags, "content": ""}),
            key,
        )
    }

    /// Send an AUTH and return whether it was accepted.
    async fn auth(&mut self, event: &Value) -> bool {
        self.send(json!(["AUTH", event])).await;
        let ok = self.reply(event["id"].as_str().unwrap(), &["OK"]).await;
        ok[2] == true
    }

    async fn neg_open(&mut self, sub: &str, filter: Value) -> Value {
        self.send(json!(["NEG-OPEN", sub, filter, neg_initial()]))
            .await;
        self.reply(sub, &["NEG-MSG", "NEG-ERR"]).await
    }

    async fn neg_refused(&mut self, sub: &str, filter: Value) {
        let reply = self.neg_open(sub, filter).await;
        assert_eq!(reply[0], "NEG-ERR", "{reply}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_refusal_is_counted_by_the_setting_that_made_it() {
    let mut relay = Relay::start();
    let t = now();

    // Events.
    relay
        .expect(
            Some(Setting::MaxEventSize),
            |c| c.events.max_event_size = 2048,
            async |r| {
                r.client()
                    .await
                    .refused(&note(1, t, json!([]), &"x".repeat(3000)))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxNumTags),
            |c| c.events.max_num_tags = 3,
            async |r| {
                let tags = json!([["t", "a"], ["t", "b"], ["t", "c"], ["t", "d"]]);
                r.client().await.refused(&note(1, t, tags, "")).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxTagValSize),
            |c| c.events.max_tag_val_size = 100,
            async |r| {
                let tags = json!([["t", "x".repeat(101)]]);
                r.client().await.refused(&note(1, t, tags, "")).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::RejectOlderThan),
            |c| c.events.reject_older_than_secs = 3600,
            async |r| {
                r.client()
                    .await
                    .refused(&note(1, t - 7200, json!([]), ""))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::RejectNewerThan),
            |_| {},
            async |r| {
                r.client()
                    .await
                    .refused(&note(1, t + 2000, json!([]), ""))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::RejectEphemeralOlderThan),
            |_| {},
            async |r| {
                r.client()
                    .await
                    .refused(&note(20001, t - 120, json!([]), ""))
                    .await
            },
        )
        .await;
    // AUTH's window and a gift wrap's backdating come from NIPs.
    relay
        .expect(
            None,
            |_| {},
            async |r| {
                let mut client = r.client().await;
                client.refused(&note(22242, t - 2000, json!([]), "")).await;
                client
                    .refused(&note(21059, t - 4 * 86_400, json!([]), ""))
                    .await;
                let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
                let stale = client.auth_event(&key, t - 2000, &[]).await;
                assert!(!client.auth(&stale).await);
            },
        )
        .await;
    // AUTH needs NIP-42 on and the relay's URL. Neither relay sends a
    // challenge, so the AUTH names one of its own.
    for (setting, tweak) in [
        (
            Setting::AuthEnabled,
            (|c: &mut Config| c.relay.auth.enabled = false) as fn(&mut Config),
        ),
        (Setting::AuthServiceUrl, |c: &mut Config| {
            c.relay.auth.service_url.clear()
        }),
    ] {
        relay
            .expect(Some(setting), tweak, async |r| {
                let mut client = r.client().await;
                client.challenge = Some(json!("none"));
                let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
                let auth = client.auth_event(&key, t, &[]).await;
                assert!(!client.auth(&auth).await);
            })
            .await;
    }
    // An AUTH meets the event limits.
    relay
        .expect(
            Some(Setting::MaxNumTags),
            |c| c.events.max_num_tags = 2,
            async |r| {
                let mut client = r.client().await;
                let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
                let tagged = client.auth_event(&key, t, &[json!(["t", "x"])]).await;
                assert!(!client.auth(&tagged).await);
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::AcceptedKinds),
            |c| c.relay.auth.accepted_kinds = vec![1],
            async |r| r.client().await.refused(&note(7, t, json!([]), "")).await,
        )
        .await;
    // A NIP-86 kind policy is the moderation counter's.
    relay
        .handle
        .manage(ManagementCmd::DisallowKind { kind: 7 })
        .await
        .unwrap();
    relay
        .expect(
            None,
            |_| {},
            async |r| r.client().await.refused(&note(7, t, json!([]), "")).await,
        )
        .await;
    relay
        .handle
        .manage(ManagementCmd::AllowKind { kind: 7 })
        .await
        .unwrap();
    relay
        .expect(
            Some(Setting::WritePolicy),
            |c| c.relay.auth.write_policy = wok_relay::AccessPolicy::Authenticated,
            async |r| r.client().await.refused(&note(1, t, json!([]), "")).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::OwnerOnlyKinds),
            |_| {},
            async |r| {
                let tags = json!([["d", "app"]]);
                r.client().await.refused(&note(30078, t, tags, "")).await
            },
        )
        .await;
    // While AUTH is unusable nobody could read a recipient-only or
    // authenticated kind, so it is refused by its read class.
    let p = json!([["p", "33".repeat(32)]]);
    relay
        .expect(
            Some(Setting::RecipientOnlyKinds),
            |c| c.relay.auth.service_url.clear(),
            async |r| r.client().await.refused(&note(1059, t, p, "")).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::AuthenticatedKinds),
            |c| {
                c.relay.auth.enabled = false;
                c.relay.auth.authenticated_kinds = vec![30000];
            },
            async |r| {
                let tags = json!([["d", "list"]]);
                r.client().await.refused(&note(30000, t, tags, "")).await
            },
        )
        .await;
    // NIP-70 is not a setting, whatever the kind.
    relay
        .expect(
            None,
            |_| {},
            async |r| {
                let mut client = r.client().await;
                client.refused(&note(1, t, json!([["-"]]), "")).await;
                let tags = json!([["d", "app"], ["-"]]);
                client.refused(&note(30078, t, tags, "")).await;
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::Nip62Enabled),
            |c| c.relay.nip62.enabled = false,
            async |r| {
                let tags = json!([["relay", "ALL_RELAYS"]]);
                r.client().await.refused(&note(62, t, tags, "")).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MinPowDifficulty),
            |c| c.relay.abuse.min_pow_difficulty = 40,
            async |r| r.client().await.refused(&note(1, t, json!([]), "")).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::EventBurst),
            |c| {
                c.relay.abuse.event_rate_per_second = 1;
                c.relay.abuse.event_burst = 1;
            },
            async |r| {
                let mut client = r.client().await;
                for i in 0..20 {
                    if !client.publish(&note(1, t, json!([]), &i.to_string())).await {
                        return;
                    }
                }
                panic!("no EVENT was refused");
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::PubkeyEventBurst),
            |c| {
                c.relay.abuse.pubkey_event_rate_per_second = 1;
                c.relay.abuse.pubkey_event_burst = 1;
            },
            async |r| {
                let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
                for i in 0..20 {
                    let event = wok_compat::sign_event_with_key(
                        json!({"created_at": t, "kind": 1, "tags": [], "content": i.to_string()}),
                        &key,
                    );
                    if !r.client().await.publish(&event).await {
                        return;
                    }
                }
                panic!("no EVENT was refused");
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxStoredEventsPerPubkey),
            |c| c.relay.abuse.max_stored_events_per_pubkey = 1,
            async |r| {
                let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
                let mut client = r.client().await;
                for (i, accepted) in [(0, true), (1, false)] {
                    let event = wok_compat::sign_event_with_key(
                        json!({"created_at": t, "kind": 1, "tags": [], "content": i.to_string()}),
                        &key,
                    );
                    assert_eq!(client.publish(&event).await, accepted);
                }
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxStoredEvents),
            |c| c.relay.abuse.max_stored_events = 1,
            async |r| r.client().await.refused(&note(1, t, json!([]), "")).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::MinFreeDiskBytes),
            |c| c.db_min_free_disk_bytes = u64::MAX,
            async |r| r.client().await.refused(&note(1, t, json!([]), "")).await,
        )
        .await;
    let plugin = relay._dir.path().join("reject.sh");
    std::fs::write(
        &plugin,
        "#!/bin/sh\nwhile read line; do\n\
         id=$(echo \"$line\" | sed -n 's/.*\"id\":\"\\([^\"]*\\)\".*/\\1/p')\n\
         echo '{\"id\":\"'$id'\",\"action\":\"reject\",\"msg\":\"blocked: no\"}'\n\
         done\n",
    )
    .unwrap();
    relay
        .expect(
            Some(Setting::WritePolicyPlugin),
            |c| c.relay.write_policy_plugin = format!("sh {}", plugin.display()),
            async |r| r.client().await.refused(&note(1, t, json!([]), "")).await,
        )
        .await;

    // Requests.
    let one = || json!({"kinds": [1], "limit": 1});
    relay
        .expect(
            Some(Setting::MaxFiltersPerReq),
            |c| c.relay.max_filters_per_req = 2,
            async |r| {
                let filters = [one(), one(), one()];
                r.client().await.closed("REQ", "s", &filters).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxReqFilterSize),
            |c| c.relay.max_req_filter_size = 200,
            async |r| {
                let filter = json!({"kinds": [1], "#t": ["x".repeat(250)]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxFilterLimitCount),
            |c| c.relay.max_filter_limit_count = 0,
            async |r| r.client().await.closed("COUNT", "c", &[one()]).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxTagsPerFilter),
            |c| c.relay.max_tags_per_filter = 2,
            async |r| {
                let filter = json!({"#t": ["a"], "#r": ["b"], "#g": ["c"]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxAndEntries),
            |c| c.relay.max_and_entries = 1,
            async |r| {
                let filter = json!({"&t": ["a", "b"]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxKindsPerFilter),
            |c| c.relay.filter_validation.max_kinds_per_filter = 2,
            async |r| {
                let filter = json!({"kinds": [1, 6, 7]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::AllowedKinds),
            |c| c.relay.filter_validation.allowed_kinds = "1".into(),
            async |r| {
                let filter = json!({"kinds": [7]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::RequireAuthorOrTag),
            |c| c.relay.filter_validation.require_author_or_tag = true,
            async |r| r.client().await.closed("REQ", "s", &[one()]).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::RequireScopedFilters),
            |c| c.relay.filter_validation.require_scoped_filters = true,
            async |r| {
                r.client()
                    .await
                    .neg_refused("n", json!({"kinds": [1]}))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxQueryWork),
            |c| c.relay.abuse.max_query_work = 10,
            async |r| {
                let filter = json!({"kinds": [1]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::ReadPolicy),
            |c| c.relay.auth.read_policy = wok_relay::AccessPolicy::Authenticated,
            async |r| r.client().await.closed("REQ", "s", &[one()]).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::RecipientOnlyKinds),
            |_| {},
            async |r| {
                let filter = json!({"kinds": [4]});
                r.client().await.closed("REQ", "s", &[filter]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::OwnerOnlyKinds),
            |_| {},
            async |r| {
                let filter = json!({"kinds": [30078]});
                r.client().await.closed("COUNT", "c", &[filter]).await
            },
        )
        .await;
    // A COUNT is refused for the filter its reader is not scoped to.
    relay
        .expect(
            Some(Setting::RecipientOnlyKinds),
            |_| {},
            async |r| {
                let mut client = r.client().await;
                let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
                let auth = client.auth_event(&key, t, &[]).await;
                assert!(client.auth(&auth).await);
                let own = json!({"kinds": [30078], "authors": [auth["pubkey"]]});
                let dms = json!({"kinds": [4]});
                client.closed("COUNT", "c", &[own, dms]).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::AuthenticatedKinds),
            |c| c.relay.auth.authenticated_kinds = vec![30000],
            async |r| {
                let filter = json!({"kinds": [30000]});
                r.client().await.neg_refused("n", filter).await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxSubsPerConnection),
            |c| c.relay.max_subs_per_connection = 1,
            async |r| {
                let mut client = r.client().await;
                assert_eq!(client.ask("REQ", "a", &[one()]).await[0], "EOSE");
                client.closed("REQ", "b", &[one()]).await;
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxFilterBytesPerConnection),
            |c| c.relay.max_filter_bytes_per_connection = 100,
            async |r| {
                let mut client = r.client().await;
                let filter = || json!({"kinds": [1], "#t": ["x".repeat(40)]});
                assert_eq!(client.ask("REQ", "a", &[filter()]).await[0], "EOSE");
                client.closed("REQ", "b", &[filter()]).await;
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxConcurrentHistoricalQueries),
            |c| c.relay.abuse.max_concurrent_historical_queries = 0,
            async |r| r.client().await.closed("REQ", "s", &[one()]).await,
        )
        .await;
    relay
        .expect(
            Some(Setting::PerConnectionReqBurst),
            |c| {
                c.relay.abuse.per_connection.req_rate_per_second = 1;
                c.relay.abuse.per_connection.req_burst = 1;
            },
            async |r| r.client().await.until_closed("REQ").await,
        )
        .await;
    relay
        .expect(
            Some(Setting::PerConnectionCountBurst),
            |c| {
                c.relay.abuse.per_connection.count_rate_per_second = 1;
                c.relay.abuse.per_connection.count_burst = 1;
            },
            async |r| r.client().await.until_closed("COUNT").await,
        )
        .await;
    relay
        .expect(
            Some(Setting::ReqBurst),
            |c| {
                c.relay.abuse.req_rate_per_second = 1;
                c.relay.abuse.req_burst = 1;
            },
            async |r| r.client().await.until_closed("REQ").await,
        )
        .await;
    relay
        .expect(
            Some(Setting::CountBurst),
            |c| {
                c.relay.abuse.count_rate_per_second = 1;
                c.relay.abuse.count_burst = 1;
            },
            async |r| r.client().await.until_closed("COUNT").await,
        )
        .await;
    relay
        .expect(
            Some(Setting::PerConnectionNegMsgBurst),
            |c| {
                c.relay.abuse.per_connection.neg_msg_rate_per_second = 1;
                c.relay.abuse.per_connection.neg_msg_burst = 1;
            },
            async |r| {
                let mut client = r.client().await;
                assert_eq!(
                    client.neg_open("n", json!({"kinds": [1]})).await[0],
                    "NEG-MSG"
                );
                for _ in 0..20 {
                    client.send(json!(["NEG-MSG", "n", neg_initial()])).await;
                    let reply = client.reply("n", &["NEG-MSG", "NEG-ERR"]).await;
                    if reply[0] == "NEG-ERR" {
                        assert!(
                            reply[2].as_str().unwrap().starts_with("rate-limited:"),
                            "{reply}"
                        );
                        return;
                    }
                }
                panic!("no NEG-MSG was refused");
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::InvalidBurst),
            |c| {
                c.relay.abuse.invalid_rate_per_second = 1;
                c.relay.abuse.invalid_burst = 1;
            },
            async |r| {
                let mut client = r.client().await;
                // Each message is answered until the budget runs out, and the
                // first refusal then gets one NOTICE of its own.
                for _ in 0..20 {
                    client.conn.client_message("[\"bogus\"]".into()).await;
                    let notice = loop {
                        let msg = client.recv().await;
                        if msg[0] == "NOTICE" {
                            break msg;
                        }
                    };
                    if notice[1].as_str().unwrap().starts_with("rate-limited:") {
                        return;
                    }
                }
                panic!("no malformed message was refused");
            },
        )
        .await;

    // Sync.
    relay
        .expect(
            Some(Setting::NegentropyEnabled),
            |c| c.relay.negentropy_enabled = false,
            async |r| {
                r.client()
                    .await
                    .neg_refused("n", json!({"kinds": [1]}))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::SyncMemoryPerConnection),
            |c| c.relay.sync_memory_per_connection = 1,
            async |r| {
                r.client()
                    .await
                    .neg_refused("n", json!({"kinds": [1]}))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::SyncMemoryTotal),
            |c| c.relay.sync_memory_total = 1,
            async |r| {
                r.client()
                    .await
                    .neg_refused("n", json!({"kinds": [1]}))
                    .await
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxSubsPerConnection),
            |c| c.relay.max_subs_per_connection = 1,
            async |r| {
                let mut client = r.client().await;
                assert_eq!(
                    client.neg_open("a", json!({"kinds": [1]})).await[0],
                    "NEG-MSG"
                );
                client.neg_refused("b", json!({"kinds": [1]})).await;
            },
        )
        .await;
    relay
        .expect(
            Some(Setting::MaxSyncEvents),
            |c| c.relay.max_sync_events = 0,
            async |r| {
                r.client()
                    .await
                    .neg_refused("n", json!({"kinds": [1]}))
                    .await
            },
        )
        .await;

    // Connections.
    relay
        .expect(
            Some(Setting::ConnectionBurst),
            |c| {
                c.relay.abuse.connection_rate_per_second = 1;
                c.relay.abuse.connection_burst = 1;
            },
            async |r| {
                let source = r.fresh_source();
                for _ in 0..20 {
                    if !r.handle.admit_connection(&source) {
                        return;
                    }
                }
                panic!("no connection was refused");
            },
        )
        .await;
    relay.handle.request_shutdown();
}
