//! Seeded operation sequences through both real transports. The expected set
//! is computed from signed JSON and an independent model, never relay filters.
mod support {
    pub mod wire;
}
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::wire::Wire;
use wok_relay::{moderation::ManagementCmd, Config, RelayHandle};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn keys() -> Vec<Keypair> {
    (1..=4)
        .map(|i| {
            Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[i; 32]).unwrap())
        })
        .collect()
}
fn pk(key: &Keypair) -> String {
    hex::encode(key.x_only_public_key().0.serialize())
}
fn signed(key: &Keypair, kind: u64, time: u64, tags: Value, content: String) -> Value {
    wok_compat::sign_event_with_key(
        json!({"kind":kind,"created_at":time,"tags":tags,"content":content}),
        key,
    )
}

struct Fixture {
    handle: RelayHandle,
    endpoints: [String; 2],
    _dir: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(
            dir.path(),
            wok_db::EnvOptions {
                map_size: 128 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config {
            db: dir.path().to_owned(),
            ..Default::default()
        };
        cfg.relay.auth.service_url = "wss://lifecycle.test".into();
        cfg.relay.abuse.enabled = false;
        cfg.relay.unix.enabled = true;
        cfg.relay.unix.path = dir.path().join("r.sock");
        cfg.relay.req_worker_threads = 2;
        cfg.relay.negentropy_threads = 2;
        let unix = format!("unix://{}", cfg.relay.unix.path.display());
        let handle = wok_relay::start(env, cfg.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws = format!("ws://{}", listener.local_addr().unwrap());
        let h = handle.clone();
        tokio::spawn(async move {
            wok_ws::serve_listener(h, listener).await.unwrap();
        });
        let h = handle.clone();
        tokio::spawn(async move {
            wok_unix::serve(h, cfg).await.unwrap();
        });
        for _ in 0..200 {
            if std::path::Path::new(unix.strip_prefix("unix://").unwrap()).exists() {
                return Self {
                    handle,
                    endpoints: [ws, unix],
                    _dir: dir,
                };
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("Unix listener did not start");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

#[derive(Default)]
struct Model {
    events: BTreeMap<String, Value>,
    banned_ids: BTreeSet<String>,
    banned_authors: BTreeSet<String>,
}
impl Model {
    fn visible(&self, event: &Value, identities: &BTreeSet<String>) -> bool {
        if self.banned_ids.contains(event["id"].as_str().unwrap())
            || self
                .banned_authors
                .contains(event["pubkey"].as_str().unwrap())
        {
            return false;
        }
        let tags = event["tags"].as_array().unwrap();
        if tags.iter().any(|t| {
            t[0] == "expiration" && t[1].as_str().unwrap().parse::<u64>().unwrap() <= now()
        }) {
            return false;
        }
        if matches!(event["kind"].as_u64().unwrap(), 4 | 1059) {
            let first = tags.iter().find(|t| t[0] == "p");
            return first.is_some_and(|t| {
                identities.contains(t[1].as_str().unwrap())
                    || identities.contains(event["pubkey"].as_str().unwrap())
            });
        }
        true
    }
    fn insert(&mut self, event: Value) {
        if event["kind"] == 0 {
            self.events
                .retain(|_, old| !(old["kind"] == 0 && old["pubkey"] == event["pubkey"]));
        }
        if event["kind"] == 5 {
            for tag in event["tags"].as_array().unwrap() {
                if tag[0] == "e" {
                    let id = tag[1].as_str().unwrap();
                    if self
                        .events
                        .get(id)
                        .is_some_and(|old| old["pubkey"] == event["pubkey"])
                    {
                        self.events.remove(id);
                    }
                }
            }
        }
        self.events
            .insert(event["id"].as_str().unwrap().into(), event);
    }
    fn expected(
        &self,
        identities: &BTreeSet<String>,
        author: Option<&str>,
        public_only: bool,
    ) -> BTreeMap<String, Value> {
        self.events
            .iter()
            .filter(|(_, e)| {
                self.visible(e, identities)
                    && author.is_none_or(|p| e["pubkey"] == p)
                    && (!public_only || !matches!(e["kind"].as_u64().unwrap(), 4 | 1059))
            })
            .map(|(id, e)| (id.clone(), e.clone()))
            .collect()
    }
}

struct Reader {
    wire: Wire,
    identities: BTreeSet<String>,
    challenge: String,
    pending: BTreeMap<String, Value>,
}
impl Reader {
    async fn connect(endpoint: &str) -> Self {
        let mut wire = Wire::connect(endpoint).await.unwrap();
        wire.send(json!(["REQ","challenge",{"kinds":[4]}]))
            .await
            .unwrap();
        let auth = wire.recv().await.unwrap();
        assert_eq!(auth[0], "AUTH", "{auth}");
        assert_eq!(wire.recv().await.unwrap()[0], "CLOSED");
        wire.send(json!(["REQ","live",{"kinds":[0,1,4,5,1059],"limit":0}]))
            .await
            .unwrap();
        assert_eq!(wire.recv().await.unwrap(), json!(["EOSE", "live"]));
        Self {
            wire,
            identities: BTreeSet::new(),
            challenge: auth[1].as_str().unwrap().into(),
            pending: BTreeMap::new(),
        }
    }
    fn consume_live(&mut self, reply: &Value) {
        let id = reply[2]["id"].as_str().unwrap();
        let expected = self
            .pending
            .remove(id)
            .unwrap_or_else(|| panic!("unauthorized, duplicate or unexpected live event: {reply}"));
        assert_eq!(reply[2], expected);
    }
    async fn response(&mut self) -> Value {
        loop {
            let reply = self.wire.recv().await.unwrap();
            if reply[0] == "EVENT" && reply[1] == "live" {
                self.consume_live(&reply);
            } else {
                return reply;
            }
        }
    }
    async fn auth(&mut self, key: &Keypair) {
        let event = signed(
            key,
            22242,
            now(),
            json!([
                ["relay", "wss://lifecycle.test"],
                ["challenge", self.challenge]
            ]),
            String::new(),
        );
        self.wire.send(json!(["AUTH", event])).await.unwrap();
        let reply = self.response().await;
        assert_eq!(reply[0], "OK", "{reply}");
        assert_eq!(reply[1], event["id"]);
        assert_eq!(reply[2], true, "{reply}");
        self.identities.insert(pk(key));
    }
    async fn history(&mut self, filter: Value, expected: &BTreeMap<String, Value>) {
        self.wire
            .send(json!(["REQ", "history", filter]))
            .await
            .unwrap();
        let mut got = BTreeMap::new();
        loop {
            let reply = self.response().await;
            assert_eq!(reply[1], "history", "{reply}");
            match reply[0].as_str() {
                Some("EOSE") => break,
                Some("EVENT") => {
                    let event = reply[2].clone();
                    assert!(
                        got.insert(event["id"].as_str().unwrap().to_owned(), event)
                            .is_none(),
                        "duplicate history"
                    );
                }
                _ => panic!("unexpected history response: {reply}"),
            }
        }
        assert_eq!(
            &got, expected,
            "history differs from independent visibility model"
        );
        self.wire.send(json!(["CLOSE", "history"])).await.unwrap();
    }
    async fn sync(&mut self, expected: &BTreeMap<String, Value>) {
        let mut vector = wok_negentropy::Vector::new();
        vector.seal().unwrap();
        let mut peer = wok_negentropy::Negentropy::new(vector, 4096).unwrap();
        let init = peer.initiate().unwrap();
        self.wire
            .send(json!(["NEG-OPEN", "sync", {}, hex::encode(init)]))
            .await
            .unwrap();
        let mut ids = BTreeSet::new();
        for _ in 0..100 {
            let reply = self.response().await;
            assert_eq!(reply[0], "NEG-MSG", "{reply}");
            let mut have = Vec::new();
            let mut need = Vec::new();
            let next = peer
                .reconcile_with_ids(
                    &hex::decode(reply[2].as_str().unwrap()).unwrap(),
                    &mut have,
                    &mut need,
                )
                .unwrap();
            assert!(have.is_empty());
            for id in need {
                assert!(ids.insert(hex::encode(id)), "duplicate sync id");
            }
            if let Some(next) = next {
                self.wire
                    .send(json!(["NEG-MSG", "sync", hex::encode(next)]))
                    .await
                    .unwrap();
            } else {
                assert_eq!(
                    ids,
                    expected.keys().cloned().collect(),
                    "sync differs from independent visibility model"
                );
                self.wire.send(json!(["NEG-CLOSE", "sync"])).await.unwrap();
                return;
            }
        }
        panic!("sync exceeded round budget");
    }
    async fn observe(&mut self, model: &Model) {
        let all = model.expected(&self.identities, None, false);
        self.history(json!({}), &all).await;
        self.sync(&all).await;
        if self.identities.is_empty() {
            self.wire
                .send(json!(["COUNT", "unscoped", {}]))
                .await
                .unwrap();
            let reply = self.response().await;
            assert_eq!(
                reply[0], "CLOSED",
                "unscoped COUNT disclosed restricted population: {reply}"
            );
        }
        let scopes: Vec<_> = self
            .identities
            .iter()
            .cloned()
            .map(Some)
            .chain(std::iter::once(None))
            .collect();
        for author in scopes {
            let expected = model.expected(&self.identities, author.as_deref(), author.is_none());
            let filter = author
                .as_ref()
                .map_or_else(|| json!({"kinds":[0,1,5]}), |p| json!({"authors":[p]}));
            self.history(filter.clone(), &expected).await;
            self.wire
                .send(json!(["COUNT", "count", filter]))
                .await
                .unwrap();
            let reply = self.response().await;
            assert_eq!(reply[0], "COUNT", "{reply}");
            assert_eq!(reply[2]["count"], expected.len(), "{reply}");
        }
        assert!(self.pending.is_empty(), "missing expected live deliveries");
    }
}

async fn publish(publisher: &mut Wire, readers: &mut [Reader], model: &mut Model, event: Value) {
    eprintln!("publish fixture: {event}");
    let accepted = !model
        .banned_authors
        .contains(event["pubkey"].as_str().unwrap())
        && !model.banned_ids.contains(event["id"].as_str().unwrap());
    if accepted {
        for r in readers.iter_mut() {
            if model.visible(&event, &r.identities) {
                r.pending
                    .insert(event["id"].as_str().unwrap().into(), event.clone());
            }
        }
    }
    publisher.send(json!(["EVENT", event])).await.unwrap();
    let ack = publisher.recv().await.unwrap();
    assert_eq!(ack[0], "OK", "{ack}");
    assert_eq!(ack[1], event["id"]);
    assert_eq!(ack[2], accepted, "{ack}");
    if accepted {
        model.insert(event.clone());
        for r in readers {
            while r.pending.contains_key(event["id"].as_str().unwrap()) {
                let reply = r.wire.recv().await.unwrap();
                assert_eq!(reply[0], "EVENT", "{reply}");
                assert_eq!(reply[1], "live", "{reply}");
                r.consume_live(&reply);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_privacy_lifecycle_matches_model_over_both_transports() {
    for seed in [7, 29, 113, 2026] {
        let fixture = Fixture::new().await;
        let keys = keys();
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut publisher = Wire::connect(&fixture.endpoints[0]).await.unwrap();
        let mut readers = vec![
            Reader::connect(&fixture.endpoints[0]).await,
            Reader::connect(&fixture.endpoints[1]).await,
        ];
        let mut model = Model::default();
        for step in 0..40 {
            // The prefix guarantees coverage; the suffix explores ordering.
            let op = if step < 14 {
                step
            } else {
                rng.gen_range(0..14)
            };
            let actor = rng.gen_range(0..keys.len());
            let reader = rng.gen_range(0..readers.len());
            eprintln!("lifecycle seed={seed} step={step} op={op} actor={actor} reader={reader}");
            let timestamp = now() - 1000 + step;
            match op {
                0..=3 | 12 => {
                    let kind = match op {
                        1 => 4,
                        2 => 1059,
                        3 => 0,
                        _ => 1,
                    };
                    let tags = if matches!(kind, 4 | 1059) {
                        json!([
                            ["p", pk(&keys[(actor + 1) % 4])],
                            ["p", pk(&keys[(actor + 2) % 4])]
                        ])
                    } else {
                        json!([])
                    };
                    publish(
                        &mut publisher,
                        &mut readers,
                        &mut model,
                        signed(
                            &keys[actor],
                            kind,
                            timestamp,
                            tags,
                            format!("{seed}/{step}"),
                        ),
                    )
                    .await;
                }
                4 => readers[reader].auth(&keys[actor]).await,
                5 => {
                    readers[reader].auth(&keys[(actor + 1) % 4]).await;
                    readers[reader].auth(&keys[(actor + 2) % 4]).await;
                }
                6 => {
                    readers[reader] = Reader::connect(&fixture.endpoints[reader]).await;
                }
                7 | 8 => {
                    let selected = if op == 8 {
                        model.banned_ids.iter().next().cloned()
                    } else {
                        model
                            .events
                            .keys()
                            .nth(rng.gen_range(0..model.events.len().max(1)))
                            .cloned()
                    };
                    if let Some(id) = selected {
                        eprintln!("moderation event: {id}");
                        let bytes = hex::decode(&id).unwrap().try_into().unwrap();
                        let cmd = if op == 7 {
                            model.banned_ids.insert(id);
                            ManagementCmd::BanEvent {
                                id: bytes,
                                reason: "model".into(),
                            }
                        } else {
                            model.banned_ids.remove(&id);
                            ManagementCmd::AllowEvent { id: bytes }
                        };
                        fixture.handle.manage(cmd).await.unwrap();
                    }
                }
                9 | 10 => {
                    let actor = if op == 10 {
                        keys.iter()
                            .position(|key| model.banned_authors.contains(&pk(key)))
                            .unwrap_or(actor)
                    } else {
                        actor
                    };
                    let pubkey = keys[actor].x_only_public_key().0.serialize();
                    let cmd = if op == 9 {
                        model.banned_authors.insert(pk(&keys[actor]));
                        ManagementCmd::BanPubkey {
                            pubkey,
                            reason: "model".into(),
                        }
                    } else {
                        model.banned_authors.remove(&pk(&keys[actor]));
                        ManagementCmd::UnbanPubkey { pubkey }
                    };
                    fixture.handle.manage(cmd).await.unwrap();
                }
                11 => {
                    if let Some(event) = model.events.values().find(|e| e["kind"] == 1).cloned() {
                        let key = keys.iter().find(|k| event["pubkey"] == pk(k)).unwrap();
                        publish(
                            &mut publisher,
                            &mut readers,
                            &mut model,
                            signed(
                                key,
                                5,
                                timestamp,
                                json!([["e", event["id"]]]),
                                String::new(),
                            ),
                        )
                        .await;
                    }
                }
                13 => {
                    let expires = now() + 2;
                    publish(
                        &mut publisher,
                        &mut readers,
                        &mut model,
                        signed(
                            &keys[actor],
                            1,
                            timestamp,
                            json!([["expiration", expires.to_string()]]),
                            format!("expiry {seed}/{step}"),
                        ),
                    )
                    .await;
                    while now() <= expires {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                _ => unreachable!(),
            }
            for reader in &mut readers {
                reader.observe(&model).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_sync_revokes_on_auth_policy_deletion_ban_and_expiry() {
    for transport in 0..2 {
        for change in ["auth", "policy", "delete", "ban", "expiry"] {
            eprintln!("in-flight sync transport={transport} change={change}");
            let fixture = Fixture::new().await;
            let keys = keys();
            let mut publisher = Wire::connect(&fixture.endpoints[1 - transport])
                .await
                .unwrap();
            let mut reader = Wire::connect(&fixture.endpoints[transport]).await.unwrap();
            reader
                .send(json!(["REQ","challenge",{"kinds":[4]}]))
                .await
                .unwrap();
            let challenge = reader.recv().await.unwrap();
            assert_eq!(challenge[0], "AUTH");
            assert_eq!(reader.recv().await.unwrap()[0], "CLOSED");
            let tags = if change == "expiry" {
                json!([["expiration", (now() + 3).to_string()]])
            } else {
                json!([])
            };
            let event = signed(&keys[0], 1, now(), tags, change.into());
            publisher.send(json!(["EVENT", event])).await.unwrap();
            assert_eq!(publisher.recv().await.unwrap()[2], true);
            let mut vector = wok_negentropy::Vector::new();
            vector.seal().unwrap();
            let initial = wok_negentropy::Negentropy::new(vector, 4096)
                .unwrap()
                .initiate()
                .unwrap();
            reader
                .send(json!(["NEG-OPEN", "held", {}, hex::encode(&initial)]))
                .await
                .unwrap();
            assert_eq!(reader.recv().await.unwrap()[0], "NEG-MSG");
            match change {
                "auth" => {
                    let auth = signed(
                        &keys[0],
                        22242,
                        now(),
                        json!([
                            ["relay", "wss://lifecycle.test"],
                            ["challenge", challenge[1]]
                        ]),
                        String::new(),
                    );
                    reader.send(json!(["AUTH", auth])).await.unwrap();
                    let mut ack = false;
                    let mut revoked = false;
                    for _ in 0..2 {
                        let reply = reader.recv().await.unwrap();
                        match reply[0].as_str() {
                            Some("OK") => {
                                assert_eq!(reply[1], auth["id"]);
                                assert_eq!(reply[2], true);
                                ack = true;
                            }
                            Some("NEG-ERR") => {
                                assert_eq!(reply[1], "held");
                                revoked = true;
                            }
                            _ => panic!("{reply}"),
                        }
                    }
                    assert!(ack && revoked);
                }
                "policy" => fixture
                    .handle
                    .config
                    .write()
                    .relay
                    .auth
                    .restricted_read_kinds
                    .push(1),
                "ban" => fixture
                    .handle
                    .manage(ManagementCmd::BanEvent {
                        id: hex::decode(event["id"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        reason: "test".into(),
                    })
                    .await
                    .unwrap(),
                "delete" => {
                    let deletion = signed(
                        &keys[0],
                        5,
                        now(),
                        json!([["e", event["id"]]]),
                        String::new(),
                    );
                    publisher.send(json!(["EVENT", deletion])).await.unwrap();
                    assert_eq!(publisher.recv().await.unwrap()[2], true);
                }
                "expiry" => {}
                _ => unreachable!(),
            }
            if change != "auth" {
                let reply = reader.recv().await.unwrap();
                assert_eq!(reply[0], "NEG-ERR", "{reply}");
                assert_eq!(reply[1], "held");
            }
            reader
                .send(json!(["NEG-MSG", "held", hex::encode(initial)]))
                .await
                .unwrap();
            let reply = reader.recv().await.unwrap();
            assert_eq!(reply[0], "NEG-ERR", "revoked session resumed: {reply}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_rejects_old_auth_proof_and_drops_previous_identities() {
    let fixture = Fixture::new().await;
    let keys = keys();
    for endpoint in &fixture.endpoints {
        let old = Reader::connect(endpoint).await;
        let proof = signed(
            &keys[0],
            22242,
            now(),
            json!([
                ["relay", "wss://lifecycle.test"],
                ["challenge", old.challenge]
            ]),
            String::new(),
        );
        drop(old);
        let mut fresh = Reader::connect(endpoint).await;
        fresh.wire.send(json!(["AUTH", proof])).await.unwrap();
        let reply = fresh.response().await;
        assert_eq!(reply[0], "OK");
        assert_eq!(reply[2], false, "reused old connection proof: {reply}");
        fresh
            .wire
            .send(json!(["REQ","private",{"kinds":[4]}]))
            .await
            .unwrap();
        let reply = fresh.response().await;
        assert_eq!(
            reply[0], "CLOSED",
            "stale authentication granted access: {reply}"
        );
        fresh.auth(&keys[0]).await;
        fresh
            .wire
            .send(json!(["REQ","private",{"kinds":[4]}]))
            .await
            .unwrap();
        assert_eq!(fresh.response().await, json!(["EOSE", "private"]));
    }
}
