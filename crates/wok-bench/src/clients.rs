//! `--scenario clients`: client-realistic load with abuse controls and AUTH on.
//!
//! The other scenarios turn `[relay.abuse]` and `[relay.auth]` off and send
//! one REQ at a time, so they cannot say whether a limit refuses real
//! clients. This scenario keeps both on (or runs a supplied relay TOML) and
//! models the client traffic shapes W1–W10 of the limits plan (tracking issue
//! #97, whose appendix also defines the C and F finding IDs cited below):
//!
//! - outbox clients that open about 30 subscriptions at once (W1): 15
//!   fetch-and-close (W2–W5), 5 replaced every few seconds (W6) and 10 live
//!   (W7), with author lists of 100–2,000;
//! - Marmot clients modelled on MDK: an AUTHed `1059 #p` inbox, a live
//!   `445 #h` subscription and a NIP-77 pass per group, directory batches,
//!   and add-member bursts of one commit plus N gift wraps from throwaway
//!   keys;
//! - background publishing while all of that runs.
//!
//! Every client sends from its own address (`X-Forwarded-For`, with the
//! relay's `real_ip_header` pointed at it) unless `--clients-per-address`
//! groups them, and negotiates permessage-deflate with wok-ws's client codec.
//!
//! Refusals (`CLOSED`, `OK false`, `NOTICE`, `NEG-ERR`, HTTP 429) are counted
//! by reason; they are the measurement, not a failure. Correctness still
//! gates the trial: every history is checked against an oracle built from the
//! imported corpus, every live subscription must receive each matching event
//! published after its EOSE, NIP-77 must report exactly the missing IDs, and
//! no restricted event may reach a connection that is not its recipient.

use anyhow::{Context, Result};
use base64::Engine as _;
use hdrhistogram::Histogram;
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SECP256K1};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use wok_ws::frame::{
    DeflateCtx, InflateCtx, MessageKind, Role, WsEncoder, WsEvent, WsParser, OP_CLOSE, OP_PONG,
};

const DAY: u64 = 86_400;
/// Corpus timestamps are unique seconds spread over this window.
const SPAN: u64 = 30 * DAY;
/// Popular authors appear in every follow list and sign the background notes.
const POPULAR: usize = 20;
const NOTES_PER_AUTHOR: usize = 5;
const GROUP_EVENTS: usize = 40;
const INBOX_EVENTS: usize = 6;
/// MDK fetches the IDs a NIP-77 pass reports missing in REQs of at most 64.
const IDS_PER_FETCH: usize = 64;
/// MDK's NIP-77 filter limit. Wok reserves sync memory per session from the
/// limit (or, without one, from `min(max_sync_events, stored events)`).
const NEG_LIMIT: u64 = 16_385;
/// Kinds of the audit's 11-kind global feed (C4).
const GLOBAL_KINDS: [u64; 11] = [1, 6, 7, 9735, 30023, 1063, 20, 21, 22, 1111, 9802];
const MAX_MESSAGE: usize = 32 << 20;
const DRAIN: Duration = Duration::from_millis(2_000);
/// Header that carries each simulated client's address.
pub const FORWARDED_HEADER: &str = "x-forwarded-for";

#[derive(Clone, Debug, Serialize)]
pub struct ClientsOptions {
    pub outbox_clients: usize,
    pub marmot_clients: usize,
    pub marmot_groups: usize,
    pub marmot_invitees: usize,
    pub max_follows: usize,
    pub duration_secs: u64,
    pub replace_interval_ms: u64,
    pub publish_rate: f64,
    pub publishers: usize,
    pub clients_per_address: usize,
    pub deflate: bool,
    pub expect_no_refusals: bool,
}

// ---------------------------------------------------------------------------
// Plan: the deterministic corpus and what each client asks for
// ---------------------------------------------------------------------------

pub struct Plan {
    pub events: Vec<Value>,
    anchor: u64,
    popular: Vec<Keypair>,
    popular_pk: Vec<String>,
    /// First note of each popular author; background replies target these.
    hot_roots: Vec<(String, String)>,
    /// (note id, outbox client) pairs that background reactions target.
    client_notes: Vec<(String, usize)>,
    outbox: Vec<OutboxUser>,
    marmot: Vec<MarmotUser>,
    groups: Vec<Group>,
}

struct OutboxUser {
    keys: Keypair,
    pubkey: String,
    follows: Vec<String>,
    profile_lookups: Vec<String>,
    relay_lookups: Vec<String>,
    friend: String,
    quoted: Vec<String>,
    thread_roots: Vec<String>,
    reaction_targets: Vec<String>,
    profile_feed: String,
    watched_roots: Vec<String>,
    rotation: Vec<String>,
}

struct MarmotUser {
    keys: Keypair,
    pubkey: String,
    groups: Vec<usize>,
    /// Per group (aligned with `groups`): the events this client already has.
    held: Vec<Vec<(u64, [u8; 32])>>,
    directory: Vec<Vec<String>>,
    invitees: Vec<String>,
}

#[derive(Clone)]
struct Group {
    gid: String,
    members: Vec<usize>,
}

fn pubkey_hex(keys: &Keypair) -> String {
    hex::encode(keys.x_only_public_key().0.serialize())
}

pub(crate) fn signed(
    keys: &Keypair,
    created_at: u64,
    kind: u64,
    tags: Vec<Value>,
    content: String,
) -> Value {
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "pubkey": pubkey_hex(keys),
    });
    let id = wok_event::event_id_hash(&event).expect("generated event is valid JSON");
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&id, keys);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    event
}

fn b64(rng: &mut impl Rng, bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rng.fill(&mut buffer[..]);
    base64::engine::general_purpose::STANDARD.encode(buffer)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Builder {
    rng: rand::rngs::StdRng,
    anchor: u64,
    counter: u64,
    events: Vec<Value>,
}

impl Builder {
    /// Unique, shuffled timestamps: 7919 is coprime with SPAN, so the first
    /// SPAN values of `counter * 7919 mod SPAN` are distinct. Unique times keep
    /// `limit` cuts independent of tie order (see `verify_history`).
    fn ts(&mut self) -> u64 {
        assert!(
            self.counter < SPAN,
            "clients corpus exceeds its timestamp span"
        );
        let offset = (self.counter * 7_919) % SPAN;
        self.counter += 1;
        self.anchor - 1 - offset
    }

    fn fresh(&mut self) -> Keypair {
        Keypair::new(SECP256K1, &mut self.rng)
    }

    fn push(
        &mut self,
        keys: &Keypair,
        kind: u64,
        tags: Vec<Value>,
        content: String,
    ) -> (String, u64) {
        let created_at = self.ts();
        let event = signed(keys, created_at, kind, tags, content);
        let id = event["id"].as_str().expect("signed id").to_owned();
        self.events.push(event);
        (id, created_at)
    }

    fn text(&mut self, label: &str) -> String {
        let words = self.rng.gen_range(8..40);
        let mut text = format!("{label}:");
        for _ in 0..words {
            text.push(' ');
            text.push_str(
                [
                    "nostr", "relay", "outbox", "note", "client", "today", "sats", "group",
                ][self.rng.gen_range(0..8)],
            );
        }
        text
    }

    fn sample<T: Clone>(&mut self, from: &[T], n: usize) -> Vec<T> {
        rand::seq::index::sample(&mut self.rng, from.len(), n.min(from.len()))
            .into_iter()
            .map(|i| from[i].clone())
            .collect()
    }
}

impl Plan {
    pub fn generate(opts: &ClientsOptions, seed: u64, anchor: u64) -> Self {
        assert!(
            anchor > SPAN,
            "clients corpus anchor must be after 1970 + 30 days"
        );
        let mut b = Builder {
            rng: rand::rngs::StdRng::seed_from_u64(seed),
            anchor,
            counter: 0,
            events: Vec::new(),
        };
        let follows_max = opts.max_follows.max(1);
        let follows_min = follows_max.min(100);
        let universe = follows_max + (follows_max / 4).max(50);
        let popular_n = POPULAR.min(follows_min);
        let authors: Vec<Keypair> = (0..universe).map(|_| b.fresh()).collect();
        let author_pk: Vec<String> = authors.iter().map(pubkey_hex).collect();

        let mut notes: Vec<(String, usize)> = Vec::new();
        let mut hot_roots = Vec::new();
        for (a, keys) in authors.iter().enumerate() {
            let profile =
                json!({"name": format!("author-{a}"), "about": b.text("about")}).to_string();
            b.push(keys, 0, vec![], profile);
            let contacts = b
                .sample(&author_pk, 25)
                .into_iter()
                .map(|pk| json!(["p", pk]))
                .collect();
            b.push(keys, 3, contacts, String::new());
            b.push(
                keys,
                10_002,
                vec![
                    json!(["r", "wss://relay.example"]),
                    json!(["r", "wss://inbox.example", "read"]),
                ],
                String::new(),
            );
            if a % 2 == 0 {
                b.push(
                    keys,
                    10_050,
                    vec![json!(["relay", "wss://dm.example"])],
                    String::new(),
                );
            }
            if a % 10 == 0 {
                let body = b.text("article").repeat(12);
                b.push(
                    keys,
                    30_023,
                    vec![json!(["d", format!("article-{a}")])],
                    body,
                );
            }
            let count = if a < popular_n {
                NOTES_PER_AUTHOR * 4
            } else {
                NOTES_PER_AUTHOR
            };
            for k in 0..count {
                let mut tags = Vec::new();
                if k % 5 == 0 {
                    tags.push(json!(["t", "nostr"]));
                }
                if k % 3 == 1 && !notes.is_empty() {
                    let (root, root_author) = notes[b.rng.gen_range(0..notes.len())].clone();
                    tags.push(json!(["e", root, "", "root"]));
                    tags.push(json!(["p", author_pk[root_author]]));
                }
                let content = b.text("note");
                let (id, _) = b.push(keys, 1, tags, content);
                if k == 0 && a < popular_n {
                    hot_roots.push((id.clone(), author_pk[a].clone()));
                }
                notes.push((id, a));
            }
            if a % 4 == 0 {
                let (target, target_author) = notes[b.rng.gen_range(0..notes.len())].clone();
                b.push(
                    keys,
                    6,
                    vec![json!(["e", target]), json!(["p", author_pk[target_author]])],
                    String::new(),
                );
            }
        }
        for (a, keys) in authors.iter().enumerate() {
            for _ in 0..2 {
                let (target, target_author) = notes[b.rng.gen_range(0..notes.len())].clone();
                b.push(
                    keys,
                    7,
                    vec![json!(["e", target]), json!(["p", author_pk[target_author]])],
                    "+".into(),
                );
            }
            if a % 8 == 0 {
                let (target, target_author) = notes[b.rng.gen_range(0..notes.len())].clone();
                b.push(
                    keys,
                    9_735,
                    vec![
                        json!(["e", target]),
                        json!(["p", author_pk[target_author]]),
                        json!(["bolt11", "lnbc10n1bench"]),
                    ],
                    String::new(),
                );
            }
        }
        let note_ids: Vec<String> = notes.iter().map(|(id, _)| id.clone()).collect();
        let hot: HashSet<&str> = hot_roots.iter().map(|(id, _)| id.as_str()).collect();
        let cold_notes: Vec<String> = note_ids
            .iter()
            .filter(|id| !hot.contains(id.as_str()))
            .cloned()
            .collect();
        let unpopular: Vec<String> = author_pk[popular_n..].to_vec();

        let mut outbox = Vec::new();
        let mut client_notes = Vec::new();
        for c in 0..opts.outbox_clients {
            let keys = b.fresh();
            let me = pubkey_hex(&keys);
            // Log-uniform follow-list size, so a few clients carry the long lists.
            let u: f64 = b.rng.gen();
            let wanted = ((follows_min as f64).ln()
                + u * ((follows_max as f64).ln() - (follows_min as f64).ln()))
            .exp()
            .round() as usize;
            let wanted = wanted.clamp(follows_min, follows_max);
            let mut follows: Vec<String> = author_pk[..popular_n].to_vec();
            follows.extend(b.sample(&unpopular, wanted.saturating_sub(popular_n)));
            let follow_set: HashSet<&String> = follows.iter().collect();
            let strangers: Vec<usize> = (popular_n..universe)
                .filter(|a| !follow_set.contains(&author_pk[*a]))
                .collect();

            let profile = json!({"name": format!("client-{c}")}).to_string();
            b.push(&keys, 0, vec![], profile);
            let contacts = follows
                .iter()
                .take(1_000)
                .map(|pk| json!(["p", pk]))
                .collect();
            b.push(&keys, 3, contacts, String::new());
            b.push(
                &keys,
                10_002,
                vec![json!(["r", "wss://relay.example"])],
                String::new(),
            );
            b.push(
                &keys,
                10_050,
                vec![json!(["relay", "wss://dm.example"])],
                String::new(),
            );
            let mut own_notes = Vec::new();
            for _ in 0..5 {
                let content = b.text("mine");
                let (id, _) = b.push(&keys, 1, vec![], content);
                client_notes.push((id.clone(), c));
                own_notes.push(id);
            }
            let mut mention_authors = Vec::new();
            for k in 0..23 {
                let a = b.rng.gen_range(0..universe);
                mention_authors.push(author_pk[a].clone());
                let target = own_notes[k % own_notes.len()].clone();
                let (kind, content, mut tags) = match k % 3 {
                    0 => (1, b.text("reply"), vec![json!(["e", target, "", "reply"])]),
                    1 => (7, "+".to_string(), vec![json!(["e", target])]),
                    _ => (
                        9_735,
                        String::new(),
                        vec![json!(["e", target]), json!(["bolt11", "lnbc1"])],
                    ),
                };
                tags.push(json!(["p", me]));
                b.push(&authors[a], kind, tags, content);
            }
            // DM senders are never followed: a follows-scoped filter sent before
            // AUTH must not change visibility once the connection AUTHs.
            for _ in 0..4 {
                let sender = strangers[b.rng.gen_range(0..strangers.len())];
                let content = format!("{}?iv={}", b64(&mut b.rng, 150), b64(&mut b.rng, 16));
                b.push(&authors[sender], 4, vec![json!(["p", me])], content);
            }
            for _ in 0..4 {
                let wrapper = b.fresh();
                let content = b64(&mut b.rng, 2_400);
                b.push(&wrapper, 1_059, vec![json!(["p", me])], content);
            }
            let mut profile_lookups = mention_authors;
            profile_lookups.extend(b.sample(&author_pk, 40));
            profile_lookups.sort();
            profile_lookups.dedup();
            let friend = follows[popular_n.min(follows.len() - 1)].clone();
            let watched_roots = (0..3)
                .filter(|_| !hot_roots.is_empty())
                .map(|k| hot_roots[(c * 3 + k) % hot_roots.len()].0.clone())
                .collect();
            outbox.push(OutboxUser {
                relay_lookups: b.sample(&author_pk, 300),
                quoted: b.sample(&note_ids, 20),
                thread_roots: b.sample(&cold_notes, 3),
                reaction_targets: b.sample(&cold_notes, 45),
                profile_feed: unpopular[b.rng.gen_range(0..unpopular.len())].clone(),
                rotation: b.sample(&unpopular, 16),
                keys,
                pubkey: me,
                follows,
                profile_lookups,
                friend,
                watched_roots,
            });
        }

        let mut marmot = Vec::new();
        let mut groups = Vec::new();
        if opts.marmot_clients > 0 {
            // Directory batches draw 200 others; each burst invites N others.
            let pool = (opts.marmot_clients + 250).max(opts.marmot_invitees + 1);
            let users: Vec<Keypair> = (0..pool).map(|_| b.fresh()).collect();
            let user_pk: Vec<String> = users.iter().map(pubkey_hex).collect();
            for (u, keys) in users.iter().enumerate() {
                b.push(
                    keys,
                    0,
                    vec![],
                    json!({"name": format!("marmot-{u}")}).to_string(),
                );
                b.push(
                    keys,
                    10_002,
                    vec![json!(["r", "wss://relay.example"])],
                    String::new(),
                );
                b.push(
                    keys,
                    10_050,
                    vec![json!(["relay", "wss://inbox.example"])],
                    String::new(),
                );
                for _ in 0..(1 + u % 2) {
                    let mut d = [0u8; 32];
                    b.rng.fill(&mut d);
                    let content = b64(&mut b.rng, 900);
                    b.push(
                        keys,
                        30_443,
                        vec![
                            json!(["d", hex::encode(d)]),
                            json!(["mls_protocol_version", "1.0"]),
                            json!(["encoding", "base64"]),
                        ],
                        content,
                    );
                }
            }
            let g = opts.marmot_groups.max(1);
            let pool_groups = g.max((g * opts.marmot_clients).div_ceil(4));
            let mut group_events: Vec<Vec<(u64, [u8; 32])>> = Vec::new();
            for _ in 0..pool_groups {
                let mut gid = [0u8; 32];
                b.rng.fill(&mut gid);
                let gid = hex::encode(gid);
                let mut events = Vec::new();
                for _ in 0..GROUP_EVENTS {
                    let sender = b.fresh();
                    let size = b.rng.gen_range(300..1_200);
                    let content = b64(&mut b.rng, size);
                    let (id, created_at) = b.push(&sender, 445, vec![json!(["h", gid])], content);
                    let mut raw = [0u8; 32];
                    raw.copy_from_slice(&hex::decode(id).expect("hex id"));
                    events.push((created_at, raw));
                }
                group_events.push(events);
                groups.push(Group {
                    gid,
                    members: Vec::new(),
                });
            }
            let stride = (pool_groups / opts.marmot_clients).max(1);
            let sync_point = anchor - 3 * DAY;
            for (j, keys) in users.iter().take(opts.marmot_clients).enumerate() {
                let me = user_pk[j].clone();
                let joined: Vec<usize> = (0..g).map(|k| (j * stride + k) % pool_groups).collect();
                let held = joined
                    .iter()
                    .map(|&group| {
                        groups[group].members.push(j);
                        group_events[group]
                            .iter()
                            .filter(|(created_at, id)| *created_at < sync_point && id[0] % 16 != 0)
                            .copied()
                            .collect()
                    })
                    .collect();
                for _ in 0..INBOX_EVENTS {
                    let wrapper = b.fresh();
                    let content = b64(&mut b.rng, 3_000);
                    b.push(&wrapper, 1_059, vec![json!(["p", me])], content);
                }
                let others: Vec<String> = user_pk
                    .iter()
                    .enumerate()
                    .filter(|(u, _)| *u != j)
                    .map(|(_, pk)| pk.clone())
                    .collect();
                let directory = (0..2).map(|_| b.sample(&others, 200)).collect();
                // Invite the other benchmark clients first so their live inboxes
                // see the burst, then fill from the directory pool.
                let invitees = others.iter().take(opts.marmot_invitees).cloned().collect();
                marmot.push(MarmotUser {
                    keys: *keys,
                    pubkey: me,
                    groups: joined,
                    held,
                    directory,
                    invitees,
                });
            }
        }

        Self {
            events: b.events,
            anchor,
            popular: authors[..popular_n].to_vec(),
            popular_pk: author_pk[..popular_n].to_vec(),
            hot_roots,
            client_notes,
            outbox,
            marmot,
            groups,
        }
    }
}

// ---------------------------------------------------------------------------
// Oracle
// ---------------------------------------------------------------------------

/// A compiled NIP-01 filter. Only the keys this scenario sends are supported.
#[derive(Clone, Debug)]
struct Matcher {
    ids: Option<HashSet<String>>,
    authors: Option<HashSet<String>>,
    kinds: Option<HashSet<u64>>,
    tags: Vec<(String, HashSet<String>)>,
    since: u64,
    until: u64,
    limit: Option<u64>,
}

fn string_set(value: &Value) -> HashSet<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

impl Matcher {
    fn new(filter: &Value) -> Self {
        let mut matcher = Self {
            ids: None,
            authors: None,
            kinds: None,
            tags: Vec::new(),
            since: 0,
            until: u64::MAX,
            limit: None,
        };
        for (key, value) in filter.as_object().expect("filters are objects") {
            match key.as_str() {
                "ids" => matcher.ids = Some(string_set(value)),
                "authors" => matcher.authors = Some(string_set(value)),
                "kinds" => {
                    matcher.kinds = Some(
                        value
                            .as_array()
                            .expect("kinds array")
                            .iter()
                            .filter_map(Value::as_u64)
                            .collect(),
                    )
                }
                "since" => matcher.since = value.as_u64().expect("since"),
                "until" => matcher.until = value.as_u64().expect("until"),
                "limit" => matcher.limit = value.as_u64(),
                tag if tag.starts_with('#') => {
                    matcher.tags.push((tag[1..].to_owned(), string_set(value)))
                }
                other => panic!("unsupported clients filter key {other}"),
            }
        }
        matcher
    }

    fn matches(&self, event: &Value) -> bool {
        let field = |name: &str| event.get(name).and_then(Value::as_str).unwrap_or_default();
        let created_at = event["created_at"].as_u64().unwrap_or_default();
        self.ids
            .as_ref()
            .is_none_or(|ids| ids.contains(field("id")))
            && self
                .authors
                .as_ref()
                .is_none_or(|authors| authors.contains(field("pubkey")))
            && self
                .kinds
                .as_ref()
                .is_none_or(|kinds| event["kind"].as_u64().is_some_and(|k| kinds.contains(&k)))
            && created_at >= self.since
            && created_at <= self.until
            && self.tags.iter().all(|(name, values)| {
                event["tags"].as_array().is_some_and(|tags| {
                    tags.iter().any(|tag| {
                        tag[0].as_str() == Some(name.as_str())
                            && tag[1].as_str().is_some_and(|v| values.contains(v))
                    })
                })
            })
    }
}

/// Which restricted events a connection may read (mirrors
/// `wok_query::visibility::ReadRestrictor` on JSON events): by each kind's
/// read class, any authenticated pubkey, the author or the first `p` tag, or
/// the author alone.
#[derive(Clone, Debug)]
struct ReadPolicy(wok_relay::restrict::ReadRestrictor);

impl ReadPolicy {
    fn visible(&self, event: &Value, identities: &[String]) -> bool {
        use wok_relay::restrict::ReadClass;
        let class = self.0.class(event["kind"].as_u64().unwrap_or_default());
        let author = event["pubkey"].as_str().unwrap_or_default();
        let recipient = event["tags"]
            .as_array()
            .and_then(|tags| tags.iter().find(|tag| tag[0] == "p"))
            .and_then(|tag| tag[1].as_str());
        match class {
            ReadClass::Open => true,
            ReadClass::Authenticated => !identities.is_empty(),
            ReadClass::Recipient => identities
                .iter()
                .any(|pk| pk == author || Some(pk.as_str()) == recipient),
            ReadClass::Owner => identities.iter().any(|pk| pk == author),
        }
    }
}

/// Every event imported before the run, indexed for filter evaluation.
struct Oracle {
    events: Vec<Value>,
    created: Vec<u64>,
    by_id: HashMap<String, usize>,
    by_author: HashMap<String, Vec<usize>>,
    by_kind: HashMap<u64, Vec<usize>>,
    by_tag: HashMap<(String, String), Vec<usize>>,
}

impl Oracle {
    fn new(events: Vec<Value>) -> Self {
        let mut oracle = Self {
            created: events
                .iter()
                .map(|e| e["created_at"].as_u64().unwrap_or_default())
                .collect(),
            events: Vec::new(),
            by_id: HashMap::new(),
            by_author: HashMap::new(),
            by_kind: HashMap::new(),
            by_tag: HashMap::new(),
        };
        for (index, event) in events.iter().enumerate() {
            let text = |name: &str| event[name].as_str().unwrap_or_default().to_owned();
            oracle.by_id.insert(text("id"), index);
            oracle
                .by_author
                .entry(text("pubkey"))
                .or_default()
                .push(index);
            oracle
                .by_kind
                .entry(event["kind"].as_u64().unwrap_or_default())
                .or_default()
                .push(index);
            for tag in event["tags"].as_array().into_iter().flatten() {
                if let (Some(name), Some(value)) = (tag[0].as_str(), tag[1].as_str()) {
                    if name.len() == 1 {
                        oracle
                            .by_tag
                            .entry((name.to_owned(), value.to_owned()))
                            .or_default()
                            .push(index);
                    }
                }
            }
        }
        oracle.events = events;
        oracle
    }

    fn candidates(&self, m: &Matcher) -> Vec<usize> {
        let mut out: Vec<usize> = if let Some(ids) = &m.ids {
            ids.iter()
                .filter_map(|id| self.by_id.get(id).copied())
                .collect()
        } else if let Some((name, values)) = m.tags.first() {
            values
                .iter()
                .filter_map(|v| self.by_tag.get(&(name.clone(), v.clone())))
                .flatten()
                .copied()
                .collect()
        } else if let Some(authors) = &m.authors {
            authors
                .iter()
                .filter_map(|a| self.by_author.get(a))
                .flatten()
                .copied()
                .collect()
        } else if let Some(kinds) = &m.kinds {
            kinds
                .iter()
                .filter_map(|k| self.by_kind.get(k))
                .flatten()
                .copied()
                .collect()
        } else {
            (0..self.events.len()).collect()
        };
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Every visible corpus match, newest first, ignoring `limit`.
    fn expected(&self, m: &Matcher, policy: &ReadPolicy, identities: &[String]) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .candidates(m)
            .into_iter()
            .filter(|&i| m.matches(&self.events[i]) && policy.visible(&self.events[i], identities))
            .collect();
        out.sort_by(|&a, &b| {
            self.created[b].cmp(&self.created[a]).then_with(|| {
                self.events[a]["id"]
                    .as_str()
                    .cmp(&self.events[b]["id"].as_str())
            })
        });
        out
    }
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Complete,
    /// The relay returned fewer events than the filter asks for, with no
    /// refusal (C1: `max_filter_limit` and `max_total_events_per_req` cut
    /// silently).
    Truncated {
        returned: usize,
        expected: usize,
    },
    Mismatch(String),
}

/// The relay's own cuts: `max_filter_limit` per filter and
/// `max_total_events_per_req` per REQ. Wok applies them without telling the
/// client (C1), so a history may come back short only when one explains it.
#[derive(Clone, Copy, Debug)]
struct Caps {
    filter: u64,
    req: u64,
}

impl Caps {
    fn from_config(cfg: &wok_relay::Config) -> Self {
        let cap = |n: u64| if n == 0 { u64::MAX } else { n };
        Self {
            filter: cap(cfg.relay.max_filter_limit),
            req: cap(cfg.relay.max_total_events_per_req),
        }
    }
}

/// Whether one received event may be delivered at all: known (imported or
/// published during the run), unaltered, matching, and visible to the
/// connection. Checked as each EVENT arrives, so a refusal that follows
/// cannot discard a leak.
fn event_problem(
    oracle: &Oracle,
    published: &HashMap<String, Published>,
    policy: &ReadPolicy,
    identities: &[String],
    filters: &[Matcher],
    event: &Value,
) -> Option<String> {
    let Some(id) = event["id"].as_str() else {
        return Some(format!("event without id: {event}"));
    };
    if !filters.iter().any(|m| m.matches(event)) {
        return Some(format!("event {id} does not match the filter"));
    }
    if !policy.visible(event, identities) {
        return Some(format!(
            "restricted event {id} reached a connection that is not its recipient"
        ));
    }
    match (oracle.by_id.get(id), published.get(id)) {
        (Some(&index), _) if oracle.events[index] != *event => {
            Some(format!("altered corpus event {id}"))
        }
        (Some(_), _) => None,
        (None, Some(p)) if p.event != *event => Some(format!("altered published event {id}")),
        (None, Some(_)) => None,
        (None, None) => Some(format!("unknown event {id}")),
    }
}

/// Check one subscription's history (everything before EOSE).
///
/// Events published during the run may also match, so the corpus part is
/// checked as a newest-first prefix of the oracle's answer: a relay that
/// returns the newest `limit` of everything it holds always returns a prefix
/// of the corpus matches, wherever the published events fall. The prefix is
/// tie-tolerant because Wok orders equal timestamps by insertion, not by
/// lowest ID as NIP-01 asks. A
/// history shorter than the filter asks for is `Truncated` when a relay cap
/// explains it, and a mismatch otherwise.
fn verify_history(
    oracle: &Oracle,
    published: &HashMap<String, Published>,
    policy: &ReadPolicy,
    identities: &[String],
    filters: &[Matcher],
    caps: Caps,
    history: &[Value],
) -> Verdict {
    let mut seen = HashSet::new();
    let mut corpus = Vec::new();
    let mut extra = 0usize;
    for event in history {
        if let Some(problem) = event_problem(oracle, published, policy, identities, filters, event)
        {
            return Verdict::Mismatch(problem);
        }
        let id = event["id"].as_str().unwrap_or_default();
        if !seen.insert(id) {
            return Verdict::Mismatch(format!("duplicate event {id}"));
        }
        match oracle.by_id.get(id) {
            Some(&index) => corpus.push(index),
            None => extra += 1,
        }
    }
    let returned = history.len() as u64;
    if let [m] = filters {
        let expected = oracle.expected(m, policy, identities);
        // strfry, and Wok before #95, send events written during the scan just
        // before EOSE (a catch-up after the history), so only the stored part
        // of a history is bounded by `limit`. Current Wok sends them after
        // EOSE, as live events.
        if m.limit.is_some_and(|limit| corpus.len() as u64 > limit) {
            return Verdict::Mismatch(format!(
                "{} stored events returned for limit {}",
                corpus.len(),
                m.limit.unwrap_or_default()
            ));
        }
        if let Some(&last) = corpus.len().checked_sub(1).and_then(|k| expected.get(k)) {
            let boundary = oracle.created[last];
            let got: HashSet<usize> = corpus.iter().copied().collect();
            let newer_missing = expected
                .iter()
                .take_while(|&&i| oracle.created[i] > boundary)
                .any(|i| !got.contains(i));
            if newer_missing || corpus.iter().any(|&i| oracle.created[i] < boundary) {
                return Verdict::Mismatch("history is not the newest events".into());
            }
        } else if corpus.len() > expected.len() {
            return Verdict::Mismatch("more corpus events than the filter matches".into());
        }
        let under_limit = m.limit.is_none_or(|limit| returned < limit);
        if corpus.len() < expected.len() && under_limit {
            let wanted = (expected.len() + extra).min(m.limit.map_or(usize::MAX, |l| l as usize));
            // Catch-up events count towards `returned`, so this is an upper
            // bound on what the relay's cap admitted.
            if returned >= caps.filter.min(caps.req) {
                return Verdict::Truncated {
                    returned: history.len(),
                    expected: wanted,
                };
            }
            return Verdict::Mismatch(format!(
                "history ended after {returned} of {wanted} matching events, below every relay cap"
            ));
        }
        return Verdict::Complete;
    }
    let mut full = HashSet::new();
    let mut capped = HashSet::new();
    for m in filters {
        let expected = oracle.expected(m, policy, identities);
        let take = |n: u64| {
            expected
                .iter()
                .take(n.min(usize::MAX as u64) as usize)
                .copied()
        };
        let limit = m.limit.unwrap_or(u64::MAX);
        full.extend(take(limit));
        capped.extend(take(limit.min(caps.filter)));
    }
    if corpus.iter().any(|i| !full.contains(i)) {
        return Verdict::Mismatch("event outside every filter's newest events".into());
    }
    if corpus.len() == full.len() {
        return Verdict::Complete;
    }
    // A published event can take a slot only in a filter with a `limit`.
    let displaceable = filters.iter().any(|m| m.limit.is_some());
    if displaceable && corpus.len() + extra >= full.len() {
        return Verdict::Complete;
    }
    // The per-filter cap explains a short union only where it cuts a filter;
    // within the cap, published events can take slots as under a `limit`.
    let per_filter_cut = capped.len() < full.len()
        && corpus.iter().all(|i| capped.contains(i))
        && corpus.len() + extra >= capped.len();
    if per_filter_cut || returned >= caps.req {
        return Verdict::Truncated {
            returned: history.len(),
            expected: full.len(),
        };
    }
    Verdict::Mismatch(format!(
        "history ended after {returned} of {} matching events, below every relay cap",
        full.len()
    ))
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Collapse digits so refusals group by reason, not by the numbers in them.
fn normalize_reason(message: &str) -> String {
    let mut out = String::new();
    let mut in_digits = false;
    for ch in message.trim().chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                out.push('N');
            }
            in_digits = true;
        } else {
            in_digits = false;
            out.push(ch);
        }
    }
    if out.chars().count() > 120 {
        out = out.chars().take(117).collect::<String>() + "...";
    }
    if out.is_empty() {
        "(empty reason)".into()
    } else {
        out
    }
}

/// The configuration that produced a refusal, for the proposal's
/// `wok_refusals_total{setting}` mapping.
fn setting_for(reason: &str) -> &'static str {
    let r = reason.to_ascii_lowercase();
    if r.contains("author event budget") || r.contains("for the authenticated pubkey") {
        "relay.abuse.pubkey_event_rate_per_second / pubkey_event_burst"
    } else if r.contains("event budget") || r.contains("auth budget") {
        "relay.abuse.event_rate_per_second / event_burst"
    } else if (r.contains("req budget")
        || r.contains("neg-open budget")
        || r.contains("neg-msg budget"))
        && r.contains("for this address")
    {
        "relay.abuse.req_rate_per_second / req_burst"
    } else if r.contains("req budget") || r.contains("neg-open budget") {
        "relay.abuse.per_connection.req_rate_per_second / req_burst"
    } else if r.contains("neg-msg budget") {
        "relay.abuse.per_connection.neg_msg_rate_per_second / neg_msg_burst"
    } else if r.contains("count budget") && r.contains("for this address") {
        "relay.abuse.count_rate_per_second / count_burst"
    } else if r.contains("count budget") {
        "relay.abuse.per_connection.count_rate_per_second / count_burst"
    } else if r.contains("too many connections from this address") {
        "relay.abuse.max_connections_per_address"
    } else if r.contains("connection budget") || r.contains("http 429") {
        "relay.abuse.connection_rate_per_second / connection_burst"
    } else if r.contains("invalid messages") {
        "relay.abuse.invalid_rate_per_second / invalid_burst"
    } else if r.contains("query too broad") {
        "relay.abuse.max_query_work"
    } else if r.contains("synchronization memory") {
        "relay.sync_memory_per_connection / sync_memory_total"
    } else if r.contains("concurrent historical") {
        "relay.abuse.max_concurrent_historical_queries"
    } else if r.contains("historical queries waiting") || r.contains("too many concurrent reqs") {
        "relay.max_subs_per_connection"
    } else if r.contains("connection's filters exceed") {
        "relay.max_filter_bytes_per_connection"
    } else if r.contains("filters exceed") {
        "relay.max_req_filter_size"
    } else if r.contains("arr too big") {
        "relay.max_filters_per_req"
    } else if r.contains("too many tags") || r.contains("tag filters") {
        "relay.max_tags_per_filter"
    } else if r.contains("filter validation") {
        "relay.filter_validation"
    } else if r.contains("too large") || r.contains("too big") {
        "events.max_event_size / relay.max_websocket_payload_size"
    } else if r.contains("created_at") || r.contains("too early") || r.contains("expired") {
        "events.reject_*_secs"
    } else if r.contains("stored events") || r.contains("quota") {
        "relay.abuse.max_stored_events*"
    } else if r.starts_with("auth-required") || r.starts_with("restricted") {
        "relay.auth"
    } else {
        "-"
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct ClassStats {
    sent: u64,
    completed: u64,
    refused: u64,
    truncated: u64,
    events: u64,
    live_events: u64,
    mismatches: u64,
    first: Histogram<u64>,
    done: Histogram<u64>,
}

impl Default for ClassStats {
    fn default() -> Self {
        Self {
            sent: 0,
            completed: 0,
            refused: 0,
            truncated: 0,
            events: 0,
            live_events: 0,
            mismatches: 0,
            first: Histogram::new(3).expect("histogram"),
            done: Histogram::new(3).expect("histogram"),
        }
    }
}

fn micros(d: Duration) -> u64 {
    d.as_micros().clamp(1, u128::from(u64::MAX)) as u64
}

/// `saturating_record` clamps to the initial bounds before auto-resizing, so
/// record through `record`, which grows the histogram.
fn record_us(histogram: &mut Histogram<u64>, value: u64) {
    let _ = histogram.record(value);
}

#[derive(Default)]
struct Stats {
    classes: BTreeMap<&'static str, ClassStats>,
    refusals: BTreeMap<String, BTreeMap<&'static str, u64>>,
    mismatches: u64,
    mismatch_samples: Vec<String>,
    errors: u64,
    error_samples: Vec<String>,
    truncation_samples: Vec<String>,
    auth_round_trips: u64,
    connections: u64,
    deflate: u64,
    missed_deliveries: u64,
    largest_commit: usize,
    largest_welcome: usize,
}

impl Stats {
    fn class(&mut self, class: &'static str) -> &mut ClassStats {
        self.classes.entry(class).or_default()
    }

    fn refusal(&mut self, class: &'static str, message: &str) {
        *self
            .refusals
            .entry(normalize_reason(message))
            .or_default()
            .entry(class)
            .or_default() += 1;
    }

    fn mismatch(&mut self, class: &'static str, detail: String) {
        self.mismatches += 1;
        self.class(class).mismatches += 1;
        if self.mismatch_samples.len() < 20 {
            self.mismatch_samples.push(format!("{class}: {detail}"));
        }
    }

    fn error(&mut self, detail: String) {
        self.errors += 1;
        if self.error_samples.len() < 20 {
            self.error_samples.push(detail);
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket client (wok-ws codec in client mode, so deflate works)
// ---------------------------------------------------------------------------

enum Out {
    Text(String),
    Pong(Vec<u8>),
    Close,
}

enum In {
    Msg(Instant, Value),
    Bad(String),
    Gone(String),
}

struct WsConn {
    out: mpsc::UnboundedSender<Out>,
    inbound: mpsc::UnboundedReceiver<In>,
    deflate: bool,
}

pub(crate) enum ConnectFailure {
    Refused(String),
    Failed(String),
}

impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "refused: {reason}"),
            Self::Failed(error) => f.write_str(error),
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Upgrade a fresh TCP connection. Returns the stream, any bytes read past
/// the response head, and whether the relay accepted permessage-deflate.
pub(crate) async fn ws_handshake(
    addr: SocketAddr,
    forwarded_for: Option<IpAddr>,
    offer_deflate: bool,
    nodelay: bool,
) -> Result<(tokio::net::TcpStream, Vec<u8>, bool), ConnectFailure> {
    let failed = |e: String| ConnectFailure::Failed(e);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| failed("TCP connect timed out".into()))?
    .map_err(|e| failed(format!("TCP connect: {e}")))?;
    let _ = stream.set_nodelay(nodelay);
    let key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    let mut request = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    if offer_deflate {
        request.push_str("Sec-WebSocket-Extensions: permessage-deflate\r\n");
    }
    if let Some(ip) = forwarded_for {
        request.push_str(&format!("X-Forwarded-For: {ip}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| failed(format!("handshake write: {e}")))?;
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
        if buffer.len() > 64 * 1024 {
            return Err(failed("oversized handshake response".into()));
        }
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .map_err(|_| failed("handshake timed out".into()))?
            .map_err(|e| failed(format!("handshake read: {e}")))?;
        if n == 0 {
            return Err(failed("relay closed during handshake".into()));
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buffer[..end]).to_string();
    let mut rest = buffer[end + 4..].to_vec();
    let status = head.lines().next().unwrap_or_default().to_owned();
    if status.split_whitespace().nth(1) != Some("101") {
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while rest.len() < length {
            match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => rest.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        let body = String::from_utf8_lossy(&rest).trim().to_owned();
        if status.split_whitespace().nth(1) == Some("429") {
            return Err(ConnectFailure::Refused(if body.is_empty() {
                "HTTP 429".into()
            } else {
                body
            }));
        }
        return Err(failed(format!("handshake refused: {status} {body}")));
    }
    let deflate = offer_deflate
        && head.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.starts_with("sec-websocket-extensions:") && line.contains("permessage-deflate")
        });
    Ok((stream, rest, deflate))
}

async fn ws_connect(
    addr: SocketAddr,
    forwarded_for: Option<IpAddr>,
    offer_deflate: bool,
    nodelay: bool,
) -> Result<WsConn, ConnectFailure> {
    let (stream, rest, deflate) = ws_handshake(addr, forwarded_for, offer_deflate, nodelay).await?;
    let (mut reader, mut writer) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<In>();
    tokio::spawn(async move {
        let mut encoder =
            WsEncoder::with_role(deflate.then(|| DeflateCtx::new(true)), Role::Client);
        while let Some(out) = out_rx.recv().await {
            let frame = match out {
                Out::Text(text) => match encoder.encode_message(MessageKind::Text, text.as_bytes())
                {
                    Ok(frame) => frame,
                    Err(_) => break,
                },
                Out::Pong(payload) => encoder.encode_control(OP_PONG, &payload),
                Out::Close => {
                    let _ = writer
                        .write_all(&encoder.encode_control(OP_CLOSE, &[]))
                        .await;
                    let _ = writer.shutdown().await;
                    break;
                }
            };
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    let pong_tx = out_tx.clone();
    tokio::spawn(async move {
        let mut parser = WsParser::with_role(
            MAX_MESSAGE,
            deflate.then(|| InflateCtx::new(true)),
            Role::Client,
        );
        let mut chunk = vec![0u8; 64 * 1024];
        let mut events = match parser.feed(&rest) {
            Ok(events) => events,
            Err(e) => {
                let _ = in_tx.send(In::Gone(format!("frame error: {e}")));
                return;
            }
        };
        loop {
            for event in events.drain(..) {
                let message = match event {
                    WsEvent::Message(MessageKind::Text, body) => {
                        let at = Instant::now();
                        match serde_json::from_slice::<Value>(&body) {
                            Ok(value) => In::Msg(at, value),
                            Err(e) => In::Bad(format!("invalid JSON from relay: {e}")),
                        }
                    }
                    WsEvent::Message(MessageKind::Binary, _) => In::Bad("binary frame".into()),
                    WsEvent::Ping(payload) => {
                        let _ = pong_tx.send(Out::Pong(payload));
                        continue;
                    }
                    WsEvent::Pong(_) => continue,
                    WsEvent::Close(_) => {
                        let _ = in_tx.send(In::Gone("relay sent a close frame".into()));
                        return;
                    }
                };
                if in_tx.send(message).is_err() {
                    return;
                }
            }
            let n = match reader.read(&mut chunk).await {
                Ok(0) => {
                    let _ = in_tx.send(In::Gone("relay closed the connection".into()));
                    return;
                }
                Ok(n) => n,
                Err(e) => {
                    let _ = in_tx.send(In::Gone(format!("read: {e}")));
                    return;
                }
            };
            events = match parser.feed(&chunk[..n]) {
                Ok(events) => events,
                Err(e) => {
                    let _ = in_tx.send(In::Gone(format!("frame error: {e}")));
                    return;
                }
            };
        }
    });
    Ok(WsConn {
        out: out_tx,
        inbound: in_rx,
        deflate,
    })
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

struct Published {
    event: Value,
    /// When the copy that was finally accepted was sent.
    sent: Instant,
    accepted: Option<bool>,
    acked: Option<Instant>,
}

struct Ctx {
    addr: SocketAddr,
    service_url: String,
    opts: ClientsOptions,
    nodelay: bool,
    plan: Arc<Plan>,
    oracle: Oracle,
    policy: ReadPolicy,
    caps: Caps,
    published: Mutex<HashMap<String, Published>>,
    stats: Mutex<Stats>,
    start: Instant,
    end: Instant,
    drain_end: Instant,
}

impl Ctx {
    fn stats(&self) -> std::sync::MutexGuard<'_, Stats> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn published(&self) -> std::sync::MutexGuard<'_, HashMap<String, Published>> {
        self.published.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// REQ → EOSE → CLOSE (W5).
    FetchClose,
    /// Stays open after EOSE and must receive matching publications.
    Live,
    /// Stays open until the client re-REQs the same id (W6).
    Replace,
}

struct Sub {
    class: &'static str,
    mode: Mode,
    filters: Vec<Value>,
    matchers: Vec<Matcher>,
    identities: Vec<String>,
    started: Instant,
    first_event: Option<Instant>,
    history: Vec<Value>,
    oldest: Option<u64>,
    seen: HashSet<String>,
    eose: Option<Instant>,
    closed: bool,
    refused: bool,
    live: HashMap<String, Instant>,
}

struct LiveRecord {
    label: String,
    sid: String,
    class: &'static str,
    matchers: Vec<Matcher>,
    identities: Vec<String>,
    eose: Instant,
    delivered: HashMap<String, Instant>,
    /// Every event the subscription received, history included.
    seen: HashSet<String>,
}

struct NegState {
    group: usize,
    started: Instant,
    first: Option<Instant>,
    client: wok_negentropy::Negentropy<wok_negentropy::Vector>,
    held: HashSet<[u8; 32]>,
    have: Vec<Vec<u8>>,
    need: Vec<Vec<u8>>,
}

struct Pending {
    class: &'static str,
    attempts: u32,
    retry: bool,
}

#[derive(PartialEq, Eq)]
enum Auth {
    None,
    Pending(String, Instant),
    Done,
    Failed,
}

struct Burst {
    started: Instant,
    total: usize,
    accepted: usize,
    failed: usize,
}

struct Session {
    ctx: Arc<Ctx>,
    label: String,
    conn: WsConn,
    keys: Option<Keypair>,
    identities: Vec<String>,
    challenge: Option<String>,
    auth: Auth,
    auth_waiting: Vec<String>,
    /// Publications refused with `auth-required:`, resent after AUTH.
    auth_events: Vec<String>,
    /// NOTICEs that refuse the live part of the next subscription to EOSE.
    live_refusals: std::collections::VecDeque<String>,
    subs: HashMap<String, Sub>,
    negs: HashMap<String, NegState>,
    ids_fetches: usize,
    pending: HashMap<String, Pending>,
    retries: Vec<(Instant, String)>,
    burst: Option<Burst>,
    gone: bool,
    rng: rand::rngs::StdRng,
}

/// Address of simulated user `user`, or None when every client shares the
/// bench host's loopback address.
fn user_address(ctx: &Ctx, user: usize) -> Option<IpAddr> {
    let k = ctx.opts.clients_per_address;
    (k > 0).then(|| {
        let a = user / k;
        IpAddr::V4(Ipv4Addr::new(
            10,
            64 | ((a >> 16) & 63) as u8,
            (a >> 8) as u8,
            a as u8,
        ))
    })
}

impl Session {
    fn new(ctx: &Arc<Ctx>, label: String, conn: WsConn, keys: Option<Keypair>, seed: u64) -> Self {
        Self {
            ctx: ctx.clone(),
            label,
            conn,
            keys,
            identities: Vec::new(),
            challenge: None,
            auth: Auth::None,
            auth_waiting: Vec::new(),
            auth_events: Vec::new(),
            live_refusals: std::collections::VecDeque::new(),
            subs: HashMap::new(),
            negs: HashMap::new(),
            ids_fetches: 0,
            pending: HashMap::new(),
            retries: Vec::new(),
            burst: None,
            gone: false,
            rng: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }

    async fn connect(
        ctx: &Arc<Ctx>,
        label: String,
        address: Option<IpAddr>,
        keys: Option<Keypair>,
        seed: u64,
    ) -> Option<Self> {
        for _ in 0..3 {
            let started = Instant::now();
            match ws_connect(ctx.addr, address, ctx.opts.deflate, ctx.nodelay).await {
                Ok(conn) => {
                    {
                        let mut stats = ctx.stats();
                        stats.connections += 1;
                        stats.deflate += u64::from(conn.deflate);
                        let class = stats.class("connect");
                        class.sent += 1;
                        class.completed += 1;
                        record_us(&mut class.done, micros(started.elapsed()));
                    }
                    return Some(Self::new(ctx, label, conn, keys, seed));
                }
                Err(ConnectFailure::Refused(reason)) => {
                    {
                        let mut stats = ctx.stats();
                        stats.refusal("connect", &reason);
                        let class = stats.class("connect");
                        class.sent += 1;
                        class.refused += 1;
                    }
                    // Clients reconnect after a refused handshake.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(ConnectFailure::Failed(e)) => {
                    ctx.stats().error(format!("{label}: {e}"));
                    return None;
                }
            }
            if Instant::now() >= ctx.end {
                break;
            }
        }
        None
    }

    fn send(&mut self, frame: Value) {
        let _ = self.conn.out.send(Out::Text(frame.to_string()));
    }

    fn req(&mut self, sid: &str, class: &'static str, mode: Mode, filters: Vec<Value>) {
        self.ctx.stats().class(class).sent += 1;
        self.send_req(sid, class, mode, filters, Instant::now());
    }

    fn send_req(
        &mut self,
        sid: &str,
        class: &'static str,
        mode: Mode,
        filters: Vec<Value>,
        started: Instant,
    ) {
        let mut frame = vec![json!("REQ"), json!(sid)];
        frame.extend(filters.iter().cloned());
        self.send(Value::Array(frame));
        self.subs.insert(
            sid.to_owned(),
            Sub {
                class,
                mode,
                matchers: filters.iter().map(Matcher::new).collect(),
                filters,
                identities: self.identities.clone(),
                started,
                first_event: None,
                history: Vec::new(),
                oldest: None,
                seen: HashSet::new(),
                eose: None,
                closed: false,
                refused: false,
                live: HashMap::new(),
            },
        );
    }

    fn finished(&self, sid: &str) -> bool {
        self.subs
            .get(sid)
            .is_none_or(|sub| sub.eose.is_some() || sub.refused)
    }

    fn start_auth(&mut self) -> bool {
        let (Some(keys), Some(challenge)) = (self.keys, self.challenge.clone()) else {
            return false;
        };
        if self.auth != Auth::None {
            return matches!(self.auth, Auth::Pending(..) | Auth::Done);
        }
        let event = signed(
            &keys,
            unix_now(),
            22_242,
            vec![
                json!(["relay", self.ctx.service_url]),
                json!(["challenge", challenge]),
            ],
            String::new(),
        );
        let id = event["id"].as_str().unwrap_or_default().to_owned();
        self.send(json!(["AUTH", event]));
        self.auth = Auth::Pending(id, Instant::now());
        self.ctx.stats().class("auth").sent += 1;
        true
    }

    fn publish(&mut self, event: Value, class: &'static str, retry: bool) {
        let id = event["id"].as_str().unwrap_or_default().to_owned();
        self.ctx.published().insert(
            id.clone(),
            Published {
                event: event.clone(),
                sent: Instant::now(),
                accepted: None,
                acked: None,
            },
        );
        self.ctx.stats().class(class).sent += 1;
        self.pending.insert(
            id,
            Pending {
                class,
                attempts: 1,
                retry,
            },
        );
        self.send(json!(["EVENT", event]));
    }

    fn next_timer(&self) -> Option<Instant> {
        self.retries.iter().map(|(at, _)| *at).min()
    }

    fn on_timer(&mut self, now: Instant) {
        let due: Vec<String> = self
            .retries
            .iter()
            .filter(|(at, _)| *at <= now)
            .map(|(_, id)| id.clone())
            .collect();
        self.retries.retain(|(at, _)| *at > now);
        for id in due {
            self.resend(&id);
        }
    }

    async fn pump_until(&mut self, deadline: Instant, done: impl Fn(&Session) -> bool) {
        while !self.gone && !done(self) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let wake = self.next_timer().map_or(deadline, |t| t.min(deadline));
            tokio::select! {
                message = self.conn.inbound.recv() => self.on_inbound(message),
                _ = tokio::time::sleep_until(wake.into()) => self.on_timer(Instant::now()),
            }
        }
    }

    fn on_inbound(&mut self, message: Option<In>) {
        match message {
            Some(In::Msg(at, value)) => self.on_message(at, value),
            Some(In::Bad(detail)) => {
                let detail = format!("{}: {detail}", self.label);
                self.ctx.stats().mismatch("protocol", detail);
            }
            Some(In::Gone(reason)) => {
                self.gone = true;
                if Instant::now() < self.ctx.drain_end {
                    self.ctx
                        .stats()
                        .error(format!("{}: {reason} before the run ended", self.label));
                }
            }
            None => self.gone = true,
        }
    }

    fn protocol(&self, detail: String) {
        self.ctx
            .stats()
            .mismatch("protocol", format!("{}: {detail}", self.label));
    }

    fn on_message(&mut self, at: Instant, value: Value) {
        let Value::Array(mut frame) = value else {
            return self.protocol(format!("non-array relay message {value}"));
        };
        let text =
            |frame: &[Value], i: usize| frame.get(i).and_then(Value::as_str).map(str::to_owned);
        match text(&frame, 0).as_deref() {
            Some("EVENT") if frame.len() == 3 && frame[1].is_string() && frame[2].is_object() => {
                let event = frame.swap_remove(2);
                let sid = text(&frame, 1).unwrap_or_default();
                self.on_event(at, &sid, event);
            }
            // A third element carries NIP-67 hints.
            Some("EOSE") if matches!(frame.len(), 2 | 3) => {
                self.on_eose(at, &text(&frame, 1).unwrap_or_default())
            }
            Some("CLOSED") if frame.len() == 3 => {
                let (sid, reason) = (
                    text(&frame, 1).unwrap_or_default(),
                    text(&frame, 2).unwrap_or_default(),
                );
                self.on_closed(&sid, &reason);
            }
            Some("OK") if frame.len() == 4 && frame[2].is_boolean() => {
                let id = text(&frame, 1).unwrap_or_default();
                let reason = text(&frame, 3).unwrap_or_default();
                self.on_ok(at, &id, frame[2].as_bool().unwrap_or(false), &reason);
            }
            Some("NOTICE") if frame.len() == 2 => {
                let reason = text(&frame, 1).unwrap_or_default();
                // Over `max_subs_per_connection` (or, in Wok, without a
                // monitor) strfry and Wok before #95 still send the history,
                // then this NOTICE, then EOSE, and never deliver live events,
                // where NIP-01 asks for CLOSED (current Wok sends CLOSED). One
                // req worker serves a connection, so the next EOSE is that
                // subscription.
                if reason.contains("too many concurrent REQs")
                    || reason.contains("monitor unavailable")
                {
                    self.live_refusals.push_back(reason);
                } else {
                    self.ctx.stats().refusal("notice", &reason);
                }
            }
            Some("AUTH") if frame.len() == 2 => self.challenge = text(&frame, 1),
            Some("NEG-MSG") if frame.len() == 3 => {
                let (sid, payload) = (
                    text(&frame, 1).unwrap_or_default(),
                    text(&frame, 2).unwrap_or_default(),
                );
                self.on_neg_msg(at, &sid, &payload);
            }
            Some("NEG-ERR") if frame.len() == 3 => {
                let (sid, reason) = (
                    text(&frame, 1).unwrap_or_default(),
                    text(&frame, 2).unwrap_or_default(),
                );
                if self.negs.remove(&sid).is_some() {
                    let mut stats = self.ctx.stats();
                    stats.refusal("marmot.neg", &reason);
                    stats.class("marmot.neg").refused += 1;
                } else {
                    self.protocol(format!("NEG-ERR for unknown session {sid}: {reason}"));
                }
            }
            _ => self.protocol(format!("unexpected relay message {}", Value::Array(frame))),
        }
    }

    fn on_event(&mut self, at: Instant, sid: &str, event: Value) {
        let ctx = self.ctx.clone();
        let label = self.label.clone();
        let Some(sub) = self.subs.get_mut(sid) else {
            return self.protocol(format!("EVENT for unknown subscription {sid}"));
        };
        let id = event["id"].as_str().unwrap_or_default().to_owned();
        if !sub.seen.insert(id.clone()) {
            ctx.stats().mismatch(
                sub.class,
                format!("{label} {sid}: event {id} delivered twice"),
            );
            return;
        }
        if sub.eose.is_none() {
            sub.first_event.get_or_insert(at);
            let problem = event_problem(
                &ctx.oracle,
                &ctx.published(),
                &ctx.policy,
                &sub.identities,
                &sub.matchers,
                &event,
            );
            match problem {
                Some(problem) => ctx
                    .stats()
                    .mismatch(sub.class, format!("{label} {sid}: {problem}")),
                None => sub.history.push(event),
            }
            return;
        }
        // After EOSE only events published during the run can arrive.
        let valid = ctx.published().get(&id).is_some_and(|p| p.event == event)
            && sub.matchers.iter().any(|m| m.matches(&event))
            && ctx.policy.visible(&event, &sub.identities);
        if sub.closed {
            // Fetch-and-close: a publication can race the CLOSE.
            if !valid {
                ctx.stats()
                    .mismatch(sub.class, format!("{label} {sid}: invalid late event {id}"));
            }
            return;
        }
        if !valid {
            ctx.stats()
                .mismatch(sub.class, format!("{label} {sid}: invalid live event {id}"));
            return;
        }
        sub.live.insert(id, at);
        ctx.stats().class(sub.class).live_events += 1;
    }

    fn on_eose(&mut self, at: Instant, sid: &str) {
        let ctx = self.ctx.clone();
        let label = self.label.clone();
        let Some(sub) = self.subs.get_mut(sid) else {
            return self.protocol(format!("EOSE for unknown subscription {sid}"));
        };
        if sub.eose.is_some() || sub.refused {
            ctx.stats().mismatch(
                sub.class,
                format!("{label} {sid}: EOSE after EOSE or CLOSED"),
            );
            return;
        }
        sub.eose = Some(at);
        let live_refusal = self.live_refusals.pop_front();
        sub.oldest = sub
            .history
            .iter()
            .filter_map(|e| e["created_at"].as_u64())
            .min();
        let verdict = {
            let published = ctx.published();
            verify_history(
                &ctx.oracle,
                &published,
                &ctx.policy,
                &sub.identities,
                &sub.matchers,
                ctx.caps,
                &sub.history,
            )
        };
        let mut stats = ctx.stats();
        let class = stats.class(sub.class);
        class.completed += 1;
        class.events += sub.history.len() as u64;
        record_us(&mut class.done, micros(at - sub.started));
        if let Some(first) = sub.first_event {
            record_us(&mut class.first, micros(first - sub.started));
        }
        match verdict {
            Verdict::Complete => {}
            Verdict::Truncated { returned, expected } => {
                class.truncated += 1;
                if stats.truncation_samples.len() < 20 {
                    stats.truncation_samples.push(format!(
                        "{}: returned {returned} of {expected} matching events",
                        sub.class
                    ));
                }
            }
            Verdict::Mismatch(detail) => {
                stats.mismatch(sub.class, format!("{label} {sid}: {detail}"));
            }
        }
        if let Some(reason) = live_refusal {
            sub.refused = true;
            stats.refusal(sub.class, &reason);
            stats.class(sub.class).refused += 1;
        }
        drop(stats);
        sub.history = Vec::new();
        if sub.mode == Mode::FetchClose {
            sub.closed = true;
            let _ = self
                .conn
                .out
                .send(Out::Text(json!(["CLOSE", sid]).to_string()));
        }
    }

    fn on_closed(&mut self, sid: &str, reason: &str) {
        let Some(sub) = self.subs.get_mut(sid) else {
            return self.protocol(format!("CLOSED for unknown subscription {sid}: {reason}"));
        };
        if sub.closed {
            return;
        }
        let class = sub.class;
        let can_auth = self.keys.is_some() && matches!(self.auth, Auth::None | Auth::Pending(..));
        if reason.starts_with("auth-required:") && sub.eose.is_none() && can_auth {
            // NIP-42: authenticate, then send the same REQ again.
            self.auth_waiting.push(sid.to_owned());
            self.ctx.stats().auth_round_trips += 1;
            if self.start_auth() {
                return;
            }
            self.auth_waiting.pop();
        }
        if let Some(sub) = self.subs.get_mut(sid) {
            sub.refused = true;
        }
        let mut stats = self.ctx.stats();
        stats.refusal(class, reason);
        stats.class(class).refused += 1;
    }

    fn on_ok(&mut self, at: Instant, id: &str, accepted: bool, reason: &str) {
        if let Auth::Pending(auth_id, sent) = &self.auth {
            if auth_id == id {
                let sent = *sent;
                if accepted {
                    self.auth = Auth::Done;
                    if let Some(keys) = &self.keys {
                        self.identities.push(pubkey_hex(keys));
                    }
                    let mut stats = self.ctx.stats();
                    let class = stats.class("auth");
                    class.completed += 1;
                    record_us(&mut class.done, micros(at - sent));
                    drop(stats);
                    for sid in std::mem::take(&mut self.auth_waiting) {
                        if let Some(old) = self.subs.remove(&sid) {
                            self.send_req(&sid, old.class, old.mode, old.filters, old.started);
                        }
                    }
                    for event_id in std::mem::take(&mut self.auth_events) {
                        self.resend(&event_id);
                    }
                } else {
                    self.auth = Auth::Failed;
                    let mut stats = self.ctx.stats();
                    stats.refusal("auth", reason);
                    stats.class("auth").refused += 1;
                    for sid in std::mem::take(&mut self.auth_waiting) {
                        if let Some(sub) = self.subs.get_mut(&sid) {
                            sub.refused = true;
                            stats.refusal(sub.class, "auth-required: AUTH was refused");
                            stats.class(sub.class).refused += 1;
                        }
                    }
                    drop(stats);
                    for event_id in std::mem::take(&mut self.auth_events) {
                        self.give_up(at, &event_id, Some("auth-required: AUTH was refused"));
                    }
                }
                return;
            }
        }
        let Some(pending) = self.pending.get(id) else {
            return self.protocol(format!("OK for unknown event {id}"));
        };
        let (class, retry, attempts) = (pending.class, pending.retry, pending.attempts);
        if accepted {
            let mut published = self.ctx.published();
            let sent = published.get(id).map_or(at, |p| p.sent);
            if let Some(p) = published.get_mut(id) {
                p.accepted = Some(true);
                p.acked = Some(at);
            }
            drop(published);
            self.pending.remove(id);
            let mut stats = self.ctx.stats();
            let row = stats.class(class);
            row.completed += 1;
            record_us(&mut row.done, micros(at - sent));
            drop(stats);
            if class != "publish.background" {
                self.burst_progress(at, true);
            }
            return;
        }
        // MDK publishes anonymously and authenticates only when a relay
        // answers `auth-required:`, then publishes again.
        let can_auth = self.keys.is_some() && matches!(self.auth, Auth::None | Auth::Pending(..));
        if retry && reason.starts_with("auth-required:") && can_auth {
            self.auth_events.push(id.to_owned());
            self.ctx.stats().auth_round_trips += 1;
            if self.start_auth() {
                return;
            }
            self.auth_events.pop();
        }
        {
            let mut stats = self.ctx.stats();
            stats.refusal(class, reason);
            stats.class(class).refused += 1;
        }
        // MDK retries `rate-limited:` publications with backoff.
        if retry && reason.starts_with("rate-limited:") && at < self.ctx.end {
            let delay = Duration::from_millis(250 * u64::from(attempts.min(12)));
            if let Some(pending) = self.pending.get_mut(id) {
                pending.attempts += 1;
            }
            self.retries.push((at + delay, id.to_owned()));
            return;
        }
        self.give_up(at, id, None);
    }

    fn resend(&mut self, id: &str) {
        let event = {
            let mut published = self.ctx.published();
            let Some(p) = published.get_mut(id) else {
                return;
            };
            p.sent = Instant::now();
            p.event.clone()
        };
        self.send(json!(["EVENT", event]));
    }

    /// Stop publishing `id`; `refusal` is recorded when no OK said why.
    fn give_up(&mut self, at: Instant, id: &str, refusal: Option<&str>) {
        let Some(pending) = self.pending.remove(id) else {
            return;
        };
        if let Some(reason) = refusal {
            let mut stats = self.ctx.stats();
            stats.refusal(pending.class, reason);
            stats.class(pending.class).refused += 1;
        }
        if let Some(p) = self.ctx.published().get_mut(id) {
            p.accepted = Some(false);
        }
        if pending.class != "publish.background" {
            self.burst_progress(at, false);
        }
    }

    fn burst_progress(&mut self, at: Instant, accepted: bool) {
        let Some(burst) = &mut self.burst else {
            return;
        };
        if accepted {
            burst.accepted += 1;
        } else {
            burst.failed += 1;
        }
        if burst.accepted == burst.total {
            let mut stats = self.ctx.stats();
            let class = stats.class("marmot.burst");
            class.completed += 1;
            record_us(&mut class.done, micros(at - burst.started));
        } else if burst.accepted + burst.failed == burst.total {
            self.ctx.stats().class("marmot.burst").refused += 1;
        }
    }

    fn open_neg(&mut self, sid: &str, group: usize, held: &[(u64, [u8; 32])]) {
        let mut store = wok_negentropy::Vector::new();
        for (created_at, id) in held {
            store.insert(*created_at, id).expect("insert held event");
        }
        store.seal().expect("seal negentropy store");
        let mut client = wok_negentropy::Negentropy::new(store, 60_000).expect("negentropy client");
        let init = client.initiate().expect("negentropy initiate");
        let gid = &self.ctx.plan.groups[group].gid;
        self.send(json!(["NEG-OPEN", sid, {"kinds":[445],"#h":[gid],"limit":NEG_LIMIT}, hex::encode(init)]));
        self.ctx.stats().class("marmot.neg").sent += 1;
        self.negs.insert(
            sid.to_owned(),
            NegState {
                group,
                started: Instant::now(),
                first: None,
                client,
                held: held.iter().map(|(_, id)| *id).collect(),
                have: Vec::new(),
                need: Vec::new(),
            },
        );
    }

    fn on_neg_msg(&mut self, at: Instant, sid: &str, payload: &str) {
        let Some(neg) = self.negs.get_mut(sid) else {
            return self.protocol(format!("NEG-MSG for unknown session {sid}"));
        };
        neg.first.get_or_insert(at);
        let Ok(bytes) = hex::decode(payload) else {
            self.negs.remove(sid);
            return self.protocol(format!("NEG-MSG {sid} is not hex"));
        };
        let NegState {
            client, have, need, ..
        } = neg;
        match client.reconcile_with_ids(&bytes, have, need) {
            Ok(Some(next)) => {
                let frame = json!(["NEG-MSG", sid, hex::encode(next)]);
                self.send(frame);
            }
            Ok(None) => {
                let neg = self.negs.remove(sid).expect("session present");
                self.send(json!(["NEG-CLOSE", sid]));
                self.finish_neg(at, neg);
            }
            Err(e) => {
                self.negs.remove(sid);
                let label = self.label.clone();
                self.ctx.stats().mismatch(
                    "marmot.neg",
                    format!("{label} {sid}: reconcile failed: {e}"),
                );
            }
        }
    }

    /// The relay holds every corpus event of the group plus whatever 445s were
    /// published into it, so `need` must cover exactly the corpus events this
    /// client lacks, plus only published events of the same group.
    fn finish_neg(&mut self, at: Instant, neg: NegState) {
        let ctx = self.ctx.clone();
        let gid = ctx.plan.groups[neg.group].gid.clone();
        let matcher = Matcher::new(&json!({"kinds":[445],"#h":[gid]}));
        let need: HashSet<String> = neg.need.iter().map(hex::encode).collect();
        let mut problems = Vec::new();
        if !neg.have.is_empty() {
            problems.push(format!("{} ids reported as client-only", neg.have.len()));
        }
        for index in ctx.oracle.expected(&matcher, &ctx.policy, &[]) {
            let id = ctx.oracle.events[index]["id"].as_str().unwrap_or_default();
            let mut raw = [0u8; 32];
            if hex::decode_to_slice(id, &mut raw).is_ok()
                && !neg.held.contains(&raw)
                && !need.contains(id)
            {
                problems.push(format!("missing need {id}"));
                break;
            }
        }
        {
            let published = ctx.published();
            for id in &need {
                let mut raw = [0u8; 32];
                if hex::decode_to_slice(id, &mut raw).is_ok() && neg.held.contains(&raw) {
                    problems.push(format!("need {id} is already held by the client"));
                    break;
                }
                let known_corpus = ctx
                    .oracle
                    .by_id
                    .get(id)
                    .is_some_and(|&i| matcher.matches(&ctx.oracle.events[i]));
                let known_published = published.get(id).is_some_and(|p| matcher.matches(&p.event));
                if !known_corpus && !known_published {
                    problems.push(format!("unexpected need {id}"));
                    break;
                }
            }
        }
        {
            let mut stats = ctx.stats();
            let class = stats.class("marmot.neg");
            class.completed += 1;
            class.events += need.len() as u64;
            record_us(&mut class.done, micros(at - neg.started));
            if let Some(first) = neg.first {
                record_us(&mut class.first, micros(first - neg.started));
            }
            for problem in problems {
                stats.mismatch(
                    "marmot.neg",
                    format!("{} group {}: {problem}", self.label, neg.group),
                );
            }
        }
        let mut need: Vec<String> = need.into_iter().collect();
        need.sort();
        for chunk in need.chunks(IDS_PER_FETCH) {
            let sid = format!("i{}", self.ids_fetches);
            self.ids_fetches += 1;
            self.req(
                &sid,
                "marmot.ids_fetch",
                Mode::FetchClose,
                vec![json!({"ids": chunk})],
            );
        }
    }

    /// End the session: report subscriptions that never finished, keep the
    /// live ones for the delivery check, and close the socket.
    fn finish(self) -> Vec<LiveRecord> {
        let mut stats = self.ctx.stats();
        for (sid, sub) in &self.subs {
            // A REQ sent after the run ended may still be answering.
            if sub.eose.is_none() && !sub.refused && !self.gone && sub.started < self.ctx.end {
                stats.error(format!(
                    "{} {sid} ({}): no EOSE or CLOSED by the end of the run",
                    self.label, sub.class
                ));
            }
        }
        for (sid, neg) in &self.negs {
            stats.error(format!(
                "{} {sid}: NEG session for group {} did not finish",
                self.label, neg.group
            ));
        }
        for reason in &self.live_refusals {
            stats.refusal("notice", reason);
        }
        if !self.pending.is_empty() && !self.gone {
            stats.error(format!(
                "{}: {} publications never got an OK",
                self.label,
                self.pending.len()
            ));
        }
        drop(stats);
        let _ = self.conn.out.send(Out::Close);
        let label = self.label;
        self.subs
            .into_iter()
            .filter(|(_, sub)| sub.mode == Mode::Live && !sub.refused && !sub.closed)
            .filter_map(|(sid, sub)| {
                Some(LiveRecord {
                    label: label.clone(),
                    sid,
                    class: sub.class,
                    eose: sub.eose?,
                    matchers: sub.matchers,
                    identities: sub.identities,
                    delivered: sub.live,
                    seen: sub.seen,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Client behaviour
// ---------------------------------------------------------------------------

/// The 30 subscriptions an outbox client opens at startup, in a realistic
/// order: own data, metadata, feed, notifications, DMs, then the rest.
fn outbox_startup(user: &OutboxUser, anchor: u64) -> Vec<(String, &'static str, Mode, Vec<Value>)> {
    let until = anchor - 15 * DAY;
    let follows = &user.follows;
    let me = &user.pubkey;
    let head = |n: usize| follows[..n.min(follows.len())].to_vec();
    let one = |sid: &str, class, mode, filter: Value| (sid.to_owned(), class, mode, vec![filter]);
    let mut subs = vec![
        one(
            "l4",
            "live.own_replaceables",
            Mode::Live,
            json!({"authors":[me],"kinds":[0,3,10000,10002,10050]}),
        ),
        one(
            "f0",
            "w2.metadata",
            Mode::FetchClose,
            json!({"authors":follows,"kinds":[0,3,10002,10050]}),
        ),
        one(
            "l0",
            "live.home_feed",
            Mode::Live,
            json!({"authors":follows,"kinds":[1,6],"limit":100}),
        ),
        one(
            "l1",
            "live.notifications",
            Mode::Live,
            json!({"#p":[me],"kinds":[1,6,7,9735],"limit":50}),
        ),
        one(
            "l2",
            "live.dm_nip04",
            Mode::Live,
            json!({"kinds":[4],"#p":[me]}),
        ),
        one(
            "l3",
            "live.dm_giftwrap",
            Mode::Live,
            json!({"kinds":[1059],"#p":[me]}),
        ),
        one(
            "f1",
            "w1.profiles",
            Mode::FetchClose,
            json!({"authors":user.profile_lookups,"kinds":[0]}),
        ),
        one(
            "f2",
            "w1.relay_lists",
            Mode::FetchClose,
            json!({"authors":user.relay_lookups,"kinds":[10002]}),
        ),
        one(
            "f3",
            "w1.contacts",
            Mode::FetchClose,
            json!({"authors":[user.friend],"kinds":[3]}),
        ),
        one(
            "l5",
            "live.zaps",
            Mode::Live,
            json!({"#p":[me],"kinds":[9735]}),
        ),
        one("f4", "w4.ids", Mode::FetchClose, json!({"ids":user.quoted})),
    ];
    for (k, root) in user.thread_roots.iter().enumerate() {
        subs.push(one(
            &format!("f{}", 5 + k),
            "w4.thread",
            Mode::FetchClose,
            json!({"#e":[root],"kinds":[1,6,7,9735]}),
        ));
    }
    for (k, root) in user.watched_roots.iter().enumerate() {
        subs.push(one(
            &format!("l{}", 6 + k),
            "live.thread",
            Mode::Live,
            json!({"#e":[root],"kinds":[1,7,9735]}),
        ));
    }
    subs.push((
        "f8".into(),
        "w4.reaction_batch",
        Mode::FetchClose,
        user.reaction_targets
            .iter()
            .map(|id| json!({"#e":[id],"kinds":[7]}))
            .collect(),
    ));
    subs.extend([
        one(
            "f9",
            "w4.notifications_page",
            Mode::FetchClose,
            json!({"#p":[me],"kinds":[1,6,7,9735],"until":until,"limit":50}),
        ),
        one(
            "f10",
            "w3.feed_page",
            Mode::FetchClose,
            json!({"authors":follows,"kinds":[1,6],"until":until,"limit":50}),
        ),
        one(
            "f11",
            "w3.profile_feed",
            Mode::FetchClose,
            json!({"authors":[user.profile_feed],"kinds":[1,6],"limit":20}),
        ),
        one(
            "f12",
            "w3.global_kinds",
            Mode::FetchClose,
            json!({"kinds":GLOBAL_KINDS,"limit":50}),
        ),
        one(
            "f13",
            "w3.authors_no_kinds",
            Mode::FetchClose,
            json!({"authors":head(150),"limit":20}),
        ),
        one(
            "f14",
            "w3.longform",
            Mode::FetchClose,
            json!({"authors":head(300),"kinds":[30023],"limit":20}),
        ),
        one(
            "l9",
            "live.hashtag",
            Mode::Live,
            json!({"#t":["nostr"],"kinds":[1],"limit":20}),
        ),
    ]);
    for k in 0..3 {
        subs.push(one(
            &format!("r{k}"),
            "w6.scroll_replace",
            Mode::Replace,
            scroll_filter(user, until),
        ));
    }
    for k in 0..2 {
        subs.push(one(
            &format!("r{}", 3 + k),
            "w6.profile_replace",
            Mode::Replace,
            rotation_filter(user, k),
        ));
    }
    subs
}

fn scroll_filter(user: &OutboxUser, until: u64) -> Value {
    json!({"authors":user.follows[..200.min(user.follows.len())],"kinds":[1,6],"until":until,"limit":20})
}

fn rotation_filter(user: &OutboxUser, step: usize) -> Value {
    json!({"authors":[user.rotation[step % user.rotation.len()]],"kinds":[0,1,6],"limit":20})
}

async fn outbox_client(ctx: Arc<Ctx>, index: usize) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.outbox[index];
    let label = format!("outbox-{index}");
    let address = user_address(&ctx, index);
    let Some(mut s) = Session::connect(&ctx, label, address, Some(user.keys), index as u64).await
    else {
        return Vec::new();
    };
    // Real clients take the challenge from the connect-time AUTH frame.
    s.pump_until(Instant::now() + Duration::from_millis(50), |s| {
        s.challenge.is_some()
    })
    .await;
    for (sid, class, mode, filters) in outbox_startup(user, plan.anchor) {
        s.req(&sid, class, mode, filters);
    }
    let interval = Duration::from_millis(ctx.opts.replace_interval_ms.max(1));
    let mut next = Instant::now() + interval;
    let mut until = [plan.anchor - 15 * DAY; 3];
    let mut step = 2;
    while !s.gone && Instant::now() < ctx.end {
        s.pump_until(next.min(ctx.end), |_| false).await;
        if Instant::now() < next || Instant::now() >= ctx.end {
            continue;
        }
        next += interval;
        for (k, until) in until.iter_mut().enumerate() {
            let sid = format!("r{k}");
            if s.finished(&sid) {
                // Page further back from the oldest event of the last page.
                *until = s.subs[&sid].oldest.map_or(*until - 3 * DAY, |t| t - 1);
                s.req(
                    &sid,
                    "w6.scroll_replace",
                    Mode::Replace,
                    vec![scroll_filter(user, *until)],
                );
            }
        }
        for k in 0..2 {
            let sid = format!("r{}", 3 + k);
            if s.finished(&sid) {
                step += 1;
                s.req(
                    &sid,
                    "w6.profile_replace",
                    Mode::Replace,
                    vec![rotation_filter(user, step)],
                );
            }
        }
    }
    s.pump_until(ctx.drain_end, |_| false).await;
    s.finish()
}

async fn marmot_receiver(ctx: Arc<Ctx>, index: usize) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.marmot[index];
    let label = format!("marmot-{index}-recv");
    let address = user_address(&ctx, ctx.opts.outbox_clients + index);
    let seed = 1_000 + index as u64;
    let Some(mut s) = Session::connect(&ctx, label, address, Some(user.keys), seed).await else {
        return Vec::new();
    };
    // MDK authenticates its receive connection with the account key. Wok
    // challenges on connect whenever AUTH can complete.
    let wait = Instant::now() + Duration::from_secs(2);
    s.pump_until(wait, |s| s.challenge.is_some()).await;
    if s.start_auth() {
        s.pump_until(wait, |s| !matches!(s.auth, Auth::Pending(..)))
            .await;
    }
    let anchor = plan.anchor;
    s.req(
        "inbox",
        "marmot.inbox",
        Mode::Live,
        vec![json!({"kinds":[1059],"#p":[user.pubkey],"since":anchor - 9 * DAY})],
    );
    for (k, &group) in user.groups.iter().enumerate() {
        let gid = &plan.groups[group].gid;
        s.req(
            &format!("g{k}"),
            "marmot.group_live",
            Mode::Live,
            vec![json!({"kinds":[445],"#h":[gid],"since":anchor - 2 * DAY})],
        );
        s.open_neg(&format!("n{k}"), group, &user.held[k]);
    }
    s.pump_until(ctx.end, |_| false).await;
    s.pump_until(ctx.drain_end, |_| false).await;
    s.finish()
}

async fn marmot_directory(ctx: Arc<Ctx>, index: usize) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.marmot[index];
    let label = format!("marmot-{index}-dir");
    let address = user_address(&ctx, ctx.opts.outbox_clients + index);
    let Some(mut s) = Session::connect(&ctx, label, address, None, 2_000 + index as u64).await
    else {
        return Vec::new();
    };
    for (k, batch) in user.directory.iter().enumerate() {
        s.req(
            &format!("d{k}"),
            "marmot.directory",
            Mode::FetchClose,
            vec![json!({"authors":batch,"kinds":[0,10002,10050,30443],"limit":800})],
        );
    }
    let sids: Vec<String> = (0..user.directory.len()).map(|k| format!("d{k}")).collect();
    s.pump_until(ctx.drain_end, |s| sids.iter().all(|sid| s.finished(sid)))
        .await;
    s.finish()
}

async fn marmot_publisher(ctx: Arc<Ctx>, index: usize) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.marmot[index];
    let label = format!("marmot-{index}-pub");
    let address = user_address(&ctx, ctx.opts.outbox_clients + index);
    let Some(mut s) =
        Session::connect(&ctx, label, address, Some(user.keys), 3_000 + index as u64).await
    else {
        return Vec::new();
    };
    let window = ctx.end.saturating_duration_since(ctx.start) / 3;
    let stagger = window / ctx.opts.marmot_clients.max(1) as u32;
    let burst_at = ctx.start + Duration::from_millis(1_500) + stagger * index as u32;
    s.pump_until(burst_at, |_| false).await;
    if Instant::now() < ctx.end {
        let invitees = &user.invitees;
        let group = &plan.groups[user.groups[0]];
        let members = group.members.len() + invitees.len();
        // An Add commit carries every new member's KeyPackage; each Welcome
        // carries the ratchet tree, so both grow with the group.
        let committer = fresh_keys(&mut s.rng);
        let commit_body = b64(&mut s.rng, 1_600 * invitees.len().max(1));
        let commit = signed(
            &committer,
            unix_now(),
            445,
            vec![json!(["h", group.gid])],
            commit_body,
        );
        let welcome_bytes = 8_192 + 256 * members;
        let mut wraps = Vec::new();
        for invitee in invitees {
            let keys = fresh_keys(&mut s.rng);
            // NIP-59 backdates wraps by up to two days.
            let created_at = unix_now() - s.rng.gen_range(0..2 * DAY);
            let content = b64(&mut s.rng, welcome_bytes);
            wraps.push(signed(
                &keys,
                created_at,
                1_059,
                vec![json!(["p", invitee])],
                content,
            ));
        }
        {
            let mut stats = ctx.stats();
            stats.largest_commit = stats.largest_commit.max(commit.to_string().len());
            if let Some(wrap) = wraps.first() {
                stats.largest_welcome = stats.largest_welcome.max(wrap.to_string().len());
            }
            stats.class("marmot.burst").sent += 1;
        }
        s.burst = Some(Burst {
            started: Instant::now(),
            total: 1 + wraps.len(),
            accepted: 0,
            failed: 0,
        });
        s.publish(commit, "publish.marmot_commit", true);
        for wrap in wraps {
            s.publish(wrap, "publish.marmot_welcome", true);
        }
    }
    s.pump_until(ctx.end, |s| s.pending.is_empty()).await;
    // Retries stop when the run ends; what is still refused stays refused.
    for (_, id) in std::mem::take(&mut s.retries) {
        s.give_up(Instant::now(), &id, None);
    }
    s.pump_until(ctx.drain_end, |s| s.pending.is_empty()).await;
    s.finish()
}

fn fresh_keys(rng: &mut rand::rngs::StdRng) -> Keypair {
    Keypair::new(SECP256K1, rng)
}

/// Background publisher: popular authors post notes, reply to hot threads and
/// react to clients' notes; with Marmot clients, every fourth event is a 445
/// from a throwaway key into a random group.
async fn background_publisher(ctx: Arc<Ctx>, index: usize) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let label = format!("publisher-{index}");
    let address = Some(IpAddr::V4(Ipv4Addr::new(10, 200, 0, index as u8)));
    let Some(mut s) = Session::connect(&ctx, label, address, None, 4_000 + index as u64).await
    else {
        return Vec::new();
    };
    let per_publisher = ctx.opts.publish_rate / ctx.opts.publishers.max(1) as f64;
    let interval = Duration::from_secs_f64(1.0 / per_publisher.max(0.01));
    let mut next = ctx.start + interval.mul_f64(index as f64 / ctx.opts.publishers.max(1) as f64);
    let mut n = index as u64;
    while !s.gone && Instant::now() < ctx.end {
        s.pump_until(next.min(ctx.end), |_| false).await;
        if Instant::now() < next || Instant::now() >= ctx.end {
            continue;
        }
        next += interval;
        n += 1;
        let now = unix_now();
        // Each publisher signs for its own popular authors, so two publishers
        // never produce the same event in the same second.
        let publishers = ctx.opts.publishers.max(1);
        let own = plan.popular.len().div_ceil(publishers).max(1);
        let author = (index + publishers * ((n as usize / 4) % own)) % plan.popular.len().max(1);
        let event = match n % 4 {
            3 if !plan.groups.is_empty() => {
                let group = &plan.groups[s.rng.gen_range(0..plan.groups.len())];
                let keys = fresh_keys(&mut s.rng);
                let size = s.rng.gen_range(300..1_200);
                signed(
                    &keys,
                    now,
                    445,
                    vec![json!(["h", group.gid])],
                    b64(&mut s.rng, size),
                )
            }
            1 if !plan.hot_roots.is_empty() => {
                let (root, root_author) = &plan.hot_roots[s.rng.gen_range(0..plan.hot_roots.len())];
                signed(
                    &plan.popular[author],
                    now,
                    1,
                    vec![json!(["e", root, "", "root"]), json!(["p", root_author])],
                    format!("live reply {n}"),
                )
            }
            2 if !plan.client_notes.is_empty() => {
                let (note, client) =
                    &plan.client_notes[s.rng.gen_range(0..plan.client_notes.len())];
                let target = &plan.outbox[*client].pubkey;
                signed(
                    &plan.popular[author],
                    now,
                    7,
                    vec![json!(["e", note]), json!(["p", target])],
                    "+".into(),
                )
            }
            _ => {
                let tags = if n % 5 == 0 {
                    vec![json!(["t", "nostr"])]
                } else {
                    vec![]
                };
                signed(
                    &plan.popular[author],
                    now,
                    1,
                    tags,
                    format!("live note {n} from {}", plan.popular_pk[author]),
                )
            }
        };
        // A repeat (same author, tags and content within one second) would be
        // answered `duplicate:` and never broadcast again.
        let id = event["id"].as_str().unwrap_or_default();
        if !ctx.published().contains_key(id) {
            s.publish(event, "publish.background", false);
        }
    }
    s.pump_until(ctx.drain_end, |s| s.pending.is_empty()).await;
    s.finish()
}

// ---------------------------------------------------------------------------
// Run and report
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct ClassRow {
    pub class: String,
    pub sent: u64,
    pub completed: u64,
    pub refused: u64,
    pub truncated: u64,
    pub events: u64,
    pub live_events: u64,
    pub mismatches: u64,
    pub first_p50_ms: f64,
    pub first_p99_ms: f64,
    pub done_p50_ms: f64,
    pub done_p99_ms: f64,
}

#[derive(Serialize, Clone, Debug)]
pub struct RefusalRow {
    pub reason: String,
    pub setting: String,
    pub count: u64,
    pub classes: BTreeMap<String, u64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClientsReport {
    pub relay_config: String,
    pub config_overrides: Vec<String>,
    pub limits: BTreeMap<String, String>,
    pub options: ClientsOptions,
    pub scenario_events: u64,
    pub background_events: u64,
    pub elapsed_secs: f64,
    pub connections: u64,
    pub deflate_negotiated: u64,
    pub subscriptions: u64,
    pub refusals_total: u64,
    pub auth_round_trips: u64,
    pub truncated_total: u64,
    pub missed_deliveries: u64,
    pub largest_commit_bytes: u64,
    pub largest_welcome_bytes: u64,
    pub mismatches: u64,
    pub errors: u64,
    pub mismatch_samples: Vec<String>,
    pub error_samples: Vec<String>,
    pub truncation_samples: Vec<String>,
    pub classes: Vec<ClassRow>,
    pub refusals: Vec<RefusalRow>,
}

impl ClientsReport {
    pub fn ok(&self) -> bool {
        self.mismatches == 0
            && self.errors == 0
            && (!self.options.expect_no_refusals || self.refusals_total == 0)
    }

    /// Completed subscriptions (EOSE) of every REQ class.
    pub fn eose_count(&self) -> u64 {
        self.classes
            .iter()
            .filter(|row| is_req_class(&row.class))
            .map(|row| row.completed)
            .sum()
    }
}

fn is_req_class(class: &str) -> bool {
    [
        "w",
        "live.",
        "marmot.inbox",
        "marmot.group",
        "marmot.ids",
        "marmot.dir",
    ]
    .iter()
    .any(|prefix| class.starts_with(prefix))
}

fn effective_limits(cfg: &wok_relay::Config) -> BTreeMap<String, String> {
    let r = &cfg.relay;
    let a = &r.abuse;
    [
        ("relay.abuse.enabled", a.enabled.to_string()),
        (
            "relay.abuse.per_connection.req_rate_per_second / req_burst",
            format!(
                "{} / {}",
                a.per_connection.req_rate_per_second, a.per_connection.req_burst
            ),
        ),
        (
            "relay.abuse.per_connection.neg_msg_rate_per_second / neg_msg_burst",
            format!(
                "{} / {}",
                a.per_connection.neg_msg_rate_per_second, a.per_connection.neg_msg_burst
            ),
        ),
        (
            "relay.abuse.per_connection.authenticated_multiplier",
            a.per_connection.authenticated_multiplier.to_string(),
        ),
        (
            "relay.abuse.req_rate_per_second / req_burst",
            format!("{} / {}", a.req_rate_per_second, a.req_burst),
        ),
        (
            "relay.abuse.event_rate_per_second / event_burst",
            format!("{} / {}", a.event_rate_per_second, a.event_burst),
        ),
        (
            "relay.abuse.connection_rate_per_second / connection_burst",
            format!("{} / {}", a.connection_rate_per_second, a.connection_burst),
        ),
        (
            "relay.abuse.max_connections_per_address",
            a.max_connections_per_address.to_string(),
        ),
        ("relay.abuse.max_query_work", a.max_query_work.to_string()),
        (
            "relay.abuse.max_concurrent_historical_queries",
            a.max_concurrent_historical_queries.to_string(),
        ),
        (
            "relay.max_req_filter_size",
            r.max_req_filter_size.to_string(),
        ),
        (
            "relay.max_filter_bytes_per_connection",
            r.max_filter_bytes_per_connection.to_string(),
        ),
        ("relay.max_filter_limit", r.max_filter_limit.to_string()),
        (
            "relay.max_total_events_per_req",
            r.max_total_events_per_req.to_string(),
        ),
        (
            "relay.max_subs_per_connection",
            r.max_subs_per_connection.to_string(),
        ),
        (
            "relay.max_websocket_payload_size",
            r.max_websocket_payload_size.to_string(),
        ),
        (
            "events.max_event_size",
            cfg.events.max_event_size.to_string(),
        ),
        ("relay.auth.enabled", r.auth.enabled.to_string()),
        (
            "relay.auth.recipient_only_kinds",
            format!("{:?}", r.auth.recipient_only_kinds),
        ),
        (
            "relay.auth.owner_only_kinds",
            format!("{:?}", r.auth.owner_only_kinds),
        ),
        (
            "relay.auth.authenticated_kinds",
            format!("{:?}", r.auth.authenticated_kinds),
        ),
        (
            "relay.compression_enabled",
            r.compression_enabled.to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

pub struct RunInput<'a> {
    pub addr: SocketAddr,
    pub plan: Plan,
    pub background: Vec<Value>,
    pub config: &'a wok_relay::Config,
    pub relay_config: String,
    pub config_overrides: Vec<String>,
    pub opts: ClientsOptions,
    pub nodelay: bool,
}

/// Run the scenario against a relay that already holds `plan.events` and
/// `background`. Also returns every REQ class's time to EOSE, merged.
pub async fn run(input: RunInput<'_>) -> Result<(ClientsReport, Histogram<u64>)> {
    let RunInput {
        addr,
        mut plan,
        background,
        config,
        relay_config,
        config_overrides,
        opts,
        nodelay,
    } = input;
    let scenario_events = plan.events.len() as u64;
    let background_events = background.len() as u64;
    let mut corpus = std::mem::take(&mut plan.events);
    corpus.extend(background);
    let start = Instant::now();
    let end = start + Duration::from_secs(opts.duration_secs.max(1));
    let ctx = Arc::new(Ctx {
        addr,
        service_url: config.relay.auth.service_url.clone(),
        nodelay,
        plan: Arc::new(plan),
        oracle: Oracle::new(corpus),
        policy: ReadPolicy(config.read_restrictor()),
        caps: Caps::from_config(config),
        published: Mutex::new(HashMap::new()),
        stats: Mutex::new(Stats::default()),
        start,
        end,
        drain_end: end + DRAIN,
        opts: opts.clone(),
    });
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..opts.outbox_clients {
        tasks.spawn(outbox_client(ctx.clone(), i));
    }
    for i in 0..opts.marmot_clients {
        tasks.spawn(marmot_receiver(ctx.clone(), i));
        tasks.spawn(marmot_directory(ctx.clone(), i));
        tasks.spawn(marmot_publisher(ctx.clone(), i));
    }
    if opts.publish_rate > 0.0 {
        for i in 0..opts.publishers.max(1) {
            tasks.spawn(background_publisher(ctx.clone(), i));
        }
    }
    let mut records = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        records.extend(joined.context("client task panicked")?);
    }
    let elapsed = start.elapsed();
    check_deliveries(&ctx, &records);

    let stats = std::mem::take(&mut *ctx.stats());
    let mut eose = Histogram::<u64>::new(3)?;
    for (class, row) in &stats.classes {
        if is_req_class(class) {
            eose.add(&row.done)?;
        }
    }
    let ms = |h: &Histogram<u64>, q: f64| {
        if h.is_empty() {
            0.0
        } else {
            h.value_at_quantile(q) as f64 / 1000.0
        }
    };
    let classes: Vec<ClassRow> = stats
        .classes
        .iter()
        .map(|(class, s)| ClassRow {
            class: (*class).to_owned(),
            sent: s.sent,
            completed: s.completed,
            refused: s.refused,
            truncated: s.truncated,
            events: s.events,
            live_events: s.live_events,
            mismatches: s.mismatches,
            first_p50_ms: ms(&s.first, 0.5),
            first_p99_ms: ms(&s.first, 0.99),
            done_p50_ms: ms(&s.done, 0.5),
            done_p99_ms: ms(&s.done, 0.99),
        })
        .collect();
    let mut refusals: Vec<RefusalRow> = stats
        .refusals
        .iter()
        .map(|(reason, by_class)| RefusalRow {
            reason: reason.clone(),
            setting: setting_for(reason).to_owned(),
            count: by_class.values().sum(),
            classes: by_class
                .iter()
                .map(|(c, n)| ((*c).to_owned(), *n))
                .collect(),
        })
        .collect();
    refusals.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    let report = ClientsReport {
        relay_config,
        config_overrides,
        limits: effective_limits(config),
        options: opts,
        scenario_events,
        background_events,
        elapsed_secs: elapsed.as_secs_f64(),
        connections: stats.connections,
        deflate_negotiated: stats.deflate,
        subscriptions: classes
            .iter()
            .filter(|row| is_req_class(&row.class))
            .map(|row| row.sent)
            .sum(),
        refusals_total: refusals.iter().map(|row| row.count).sum(),
        auth_round_trips: stats.auth_round_trips,
        truncated_total: classes.iter().map(|row| row.truncated).sum(),
        missed_deliveries: stats.missed_deliveries,
        largest_commit_bytes: stats.largest_commit as u64,
        largest_welcome_bytes: stats.largest_welcome as u64,
        mismatches: stats.mismatches,
        errors: stats.errors,
        mismatch_samples: stats.mismatch_samples,
        error_samples: stats.error_samples,
        truncation_samples: stats.truncation_samples,
        classes,
        refusals,
    };
    Ok((report, eose))
}

/// Every live subscription must receive each accepted, matching, visible
/// event that was sent after its EOSE arrived. Events sent earlier may show
/// up in history instead, so they are not required.
fn check_deliveries(ctx: &Ctx, records: &[LiveRecord]) {
    let published = ctx.published();
    let mut stats = ctx.stats();
    for record in records {
        let delivery = if record.class.starts_with("marmot") {
            "delivery.marmot"
        } else {
            "delivery.outbox"
        };
        for (id, p) in published.iter() {
            if p.accepted != Some(true)
                || p.sent <= record.eose
                || !record.matchers.iter().any(|m| m.matches(&p.event))
                || !ctx.policy.visible(&p.event, &record.identities)
            {
                continue;
            }
            stats.class(delivery).sent += 1;
            match record.delivered.get(id) {
                Some(at) => {
                    let row = stats.class(delivery);
                    row.completed += 1;
                    record_us(&mut row.done, micros(at.saturating_duration_since(p.sent)));
                }
                None => {
                    stats.missed_deliveries += 1;
                    let at = |t: Instant| t.saturating_duration_since(ctx.start).as_millis();
                    let what = if record.seen.contains(id) {
                        "arrived before EOSE although it was sent after it"
                    } else {
                        "was never delivered"
                    };
                    let detail = format!(
                        "{} {}: live event {id} {what} (sent {} ms, OK {} ms, EOSE {} ms, run end {} ms)",
                        record.label,
                        record.sid,
                        at(p.sent),
                        p.acked.map_or_else(|| "-".into(), |t| at(t).to_string()),
                        at(record.eose),
                        at(ctx.end),
                    );
                    stats.mismatch(record.class, detail);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Local relay plumbing (used by main.rs)
// ---------------------------------------------------------------------------

pub struct PreparedConfig {
    pub path: PathBuf,
    pub effective: wok_relay::Config,
    pub overrides: Vec<String>,
    pub source: String,
}

/// Write the relay TOML for one trial: the supplied file (or built-in
/// defaults) with only the keys a disposable local trial needs replaced.
pub fn prepare_config(
    dbdir: &Path,
    port: u16,
    relay_config: Option<&Path>,
    per_client_addresses: bool,
) -> Result<PreparedConfig> {
    let (mut table, source) = match relay_config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read relay config {}", path.display()))?;
            let table: toml::Table =
                toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            (table, path.display().to_string())
        }
        None => (toml::Table::new(), "built-in defaults".to_owned()),
    };
    let mut overrides = Vec::new();
    fn section<'t>(table: &'t mut toml::Table, path: &[&str]) -> &'t mut toml::Table {
        let mut current = table;
        for key in path {
            current = current
                .entry((*key).to_owned())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .expect("config section is a table");
        }
        current
    }
    section(&mut table, &["database"]).insert("path".into(), dbdir.display().to_string().into());
    let relay = section(&mut table, &["relay"]);
    relay.insert("bind".into(), "127.0.0.1".into());
    relay.insert("port".into(), i64::from(port).into());
    if per_client_addresses {
        relay.insert("real_ip_header".into(), FORWARDED_HEADER.into());
        overrides.push(format!(
            "relay.real_ip_header = \"{FORWARDED_HEADER}\" (each simulated client sends its own address)"
        ));
    }
    section(&mut table, &["relay", "unix"]).insert("enabled".into(), false.into());
    let auth = section(&mut table, &["relay", "auth"]);
    if auth
        .get("service_url")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        let url = format!("ws://127.0.0.1:{port}");
        auth.insert("service_url".into(), url.clone().into());
        overrides.push(format!(
            "relay.auth.service_url = \"{url}\" (NIP-42 needs the relay URL)"
        ));
    }
    let text = toml::to_string(&table)?;
    let effective = wok_relay::Config::parse_toml(&text)
        .map_err(|e| anyhow::anyhow!("relay config is not valid Wok TOML: {e}"))?;
    let path = dbdir.join("wok.toml");
    std::fs::write(&path, text)?;
    Ok(PreparedConfig {
        path,
        effective,
        overrides,
        source,
    })
}

pub fn render_markdown(report: &ClientsReport, relay: &str, repetition: u32) -> String {
    let o = &report.options;
    let mut s = format!(
        "\n## clients: {relay} r{repetition}\n\nRelay config: {}. {} outbox clients (follow lists up to {}), {} Marmot clients × {} groups, {} invitees per add-member burst, {} s, {} publications/s, {} client(s) per address, deflate {} ({} of {} connections negotiated it). Dataset: {} scenario + {} background events.\n\n",
        report.relay_config,
        o.outbox_clients,
        o.max_follows,
        o.marmot_clients,
        o.marmot_groups,
        o.marmot_invitees,
        o.duration_secs,
        o.publish_rate,
        o.clients_per_address,
        if o.deflate { "offered" } else { "off" },
        report.deflate_negotiated,
        report.connections,
        report.scenario_events,
        report.background_events,
    );
    for line in &report.config_overrides {
        s.push_str(&format!("- bench override: `{line}`\n"));
    }
    s.push_str(&format!(
        "\n{} subscriptions, {} refusals, {} silently truncated histories, {} NIP-42 round trips, {} missed live deliveries, {} mismatches, {} errors. Largest commit {} B, largest Welcome wrap {} B.\n\n",
        report.subscriptions,
        report.refusals_total,
        report.truncated_total,
        report.auth_round_trips,
        report.missed_deliveries,
        report.mismatches,
        report.errors,
        report.largest_commit_bytes,
        report.largest_welcome_bytes,
    ));
    s.push_str("First = time to first EVENT (first NEG-MSG for `marmot.neg`). Done = time to EOSE, NEG completion, OK, burst completion, or publish-to-delivery for `delivery.*`.\n\n");
    s.push_str("| class | sent | done | refused | truncated | events | live | first p50 ms | first p99 ms | done p50 ms | done p99 ms |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in &report.classes {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {:.1} |\n",
            row.class,
            row.sent,
            row.completed,
            row.refused,
            row.truncated,
            row.events,
            row.live_events,
            row.first_p50_ms,
            row.first_p99_ms,
            row.done_p50_ms,
            row.done_p99_ms
        ));
    }
    s.push_str("\n| refusal | setting | count | classes |\n|---|---|---:|---|\n");
    for row in &report.refusals {
        let classes: Vec<String> = row
            .classes
            .iter()
            .map(|(c, n)| format!("{c} {n}"))
            .collect();
        s.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            row.reason.replace('|', "\\|"),
            row.setting,
            row.count,
            classes.join(", ")
        ));
    }
    for (title, samples) in [
        ("Truncation samples", &report.truncation_samples),
        ("Mismatch samples", &report.mismatch_samples),
        ("Error samples", &report.error_samples),
    ] {
        if !samples.is_empty() {
            s.push_str(&format!("\n{title}:\n\n"));
            for sample in samples.iter().take(10) {
                s.push_str(&format!("- {sample}\n"));
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str, created_at: u64, kind: u64, tags: Value) -> Value {
        json!({"id": id, "pubkey": "author", "created_at": created_at, "kind": kind, "tags": tags, "content": "", "sig": "s"})
    }

    fn open_policy() -> ReadPolicy {
        ReadPolicy(wok_relay::restrict::ReadRestrictor {
            recipient_only: vec![4, 1059],
            ..Default::default()
        })
    }

    const NO_CAPS: Caps = Caps {
        filter: u64::MAX,
        req: u64::MAX,
    };

    fn check(
        oracle: &Oracle,
        published: &HashMap<String, Published>,
        filters: &[Value],
        history: &[Value],
    ) -> Verdict {
        check_with(oracle, published, filters, NO_CAPS, history)
    }

    fn check_with(
        oracle: &Oracle,
        published: &HashMap<String, Published>,
        filters: &[Value],
        caps: Caps,
        history: &[Value],
    ) -> Verdict {
        let matchers: Vec<Matcher> = filters.iter().map(Matcher::new).collect();
        verify_history(
            oracle,
            published,
            &open_policy(),
            &[],
            &matchers,
            caps,
            history,
        )
    }

    #[test]
    fn history_must_be_the_newest_prefix_of_the_corpus() {
        let corpus: Vec<Value> = (0..5)
            .map(|i| event(&format!("e{i}"), 100 + i, 1, json!([])))
            .collect();
        let oracle = Oracle::new(corpus.clone());
        let none = HashMap::new();
        let filter = [json!({"kinds":[1],"limit":2})];
        assert_eq!(
            check(
                &oracle,
                &none,
                &filter,
                &[corpus[4].clone(), corpus[3].clone()]
            ),
            Verdict::Complete
        );
        assert!(matches!(
            check(
                &oracle,
                &none,
                &filter,
                &[corpus[4].clone(), corpus[2].clone()]
            ),
            Verdict::Mismatch(_)
        ));
        assert!(matches!(
            check(
                &oracle,
                &none,
                &filter,
                &[corpus[4].clone(), corpus[4].clone()]
            ),
            Verdict::Mismatch(_)
        ));
        let mut altered = corpus[4].clone();
        altered["content"] = json!("changed");
        assert!(matches!(
            check(&oracle, &none, &filter, &[altered]),
            Verdict::Mismatch(_)
        ));
        let all: Vec<Value> = corpus.iter().rev().cloned().collect();
        assert!(
            matches!(check(&oracle, &none, &filter, &all), Verdict::Mismatch(_)),
            "over the limit"
        );
    }

    #[test]
    fn short_history_is_truncation_only_when_a_relay_cap_explains_it() {
        let corpus: Vec<Value> = (0..5)
            .map(|i| event(&format!("e{i}"), 100 + i, 1, json!([])))
            .collect();
        let oracle = Oracle::new(corpus.clone());
        let none = HashMap::new();
        let newest: Vec<Value> = corpus.iter().rev().take(3).cloned().collect();
        let truncated = Verdict::Truncated {
            returned: 3,
            expected: 5,
        };
        for caps in [
            Caps {
                filter: 3,
                req: u64::MAX,
            },
            Caps {
                filter: u64::MAX,
                req: 3,
            },
        ] {
            for filter in [json!({"kinds":[1]}), json!({"kinds":[1],"limit":10})] {
                assert_eq!(
                    check_with(&oracle, &none, &[filter], caps, &newest),
                    truncated
                );
            }
        }
        // Below every cap, missing events are a failure, not a measurement.
        let caps = Caps {
            filter: 500,
            req: 2_000,
        };
        for history in [&newest[..], &[]] {
            assert!(matches!(
                check_with(
                    &oracle,
                    &none,
                    &[json!({"kinds":[1],"limit":10})],
                    caps,
                    history
                ),
                Verdict::Mismatch(_)
            ));
        }
    }

    #[test]
    fn published_events_may_displace_corpus_events() {
        let corpus: Vec<Value> = (0..5)
            .map(|i| event(&format!("e{i}"), 100 + i, 1, json!([])))
            .collect();
        let oracle = Oracle::new(corpus.clone());
        let live = event("p0", 500, 1, json!([]));
        let published = HashMap::from([(
            "p0".to_owned(),
            Published {
                event: live.clone(),
                sent: Instant::now(),
                accepted: Some(true),
                acked: None,
            },
        )]);
        let filter = [json!({"kinds":[1],"limit":3})];
        let history = [live.clone(), corpus[4].clone(), corpus[3].clone()];
        assert_eq!(
            check(&oracle, &published, &filter, &history),
            Verdict::Complete
        );
        // Catch-up: an event written during the scan may arrive on top of a
        // full page of stored events.
        let catch_up = [
            live.clone(),
            corpus[4].clone(),
            corpus[3].clone(),
            corpus[2].clone(),
        ];
        assert_eq!(
            check(&oracle, &published, &filter, &catch_up),
            Verdict::Complete
        );
        let over = [
            corpus[4].clone(),
            corpus[3].clone(),
            corpus[2].clone(),
            corpus[1].clone(),
        ];
        assert!(matches!(
            check(&oracle, &published, &filter, &over),
            Verdict::Mismatch(_)
        ));
        let unknown = event("zz", 600, 1, json!([]));
        assert!(matches!(
            check(&oracle, &published, &filter, &[unknown]),
            Verdict::Mismatch(_)
        ));
    }

    #[test]
    fn equal_timestamps_at_the_cut_are_accepted_in_either_order() {
        let corpus = vec![
            event("a", 100, 1, json!([])),
            event("b", 100, 1, json!([])),
            event("c", 200, 1, json!([])),
        ];
        let oracle = Oracle::new(corpus.clone());
        let none = HashMap::new();
        let filter = [json!({"kinds":[1],"limit":2})];
        assert_eq!(
            check(
                &oracle,
                &none,
                &filter,
                &[corpus[2].clone(), corpus[1].clone()]
            ),
            Verdict::Complete
        );
        assert_eq!(
            check(
                &oracle,
                &none,
                &filter,
                &[corpus[2].clone(), corpus[0].clone()]
            ),
            Verdict::Complete
        );
    }

    #[test]
    fn restricted_events_need_the_recipient_identity() {
        let dm = json!({"id":"dm","pubkey":"alice","created_at":1,"kind":4,"tags":[["p","bob"]],"content":"","sig":"s"});
        let oracle = Oracle::new(vec![dm.clone()]);
        let none = HashMap::new();
        let filters = [Matcher::new(&json!({"authors":["alice"]}))];
        let policy = open_policy();
        assert!(matches!(
            verify_history(
                &oracle,
                &none,
                &policy,
                &[],
                &filters,
                NO_CAPS,
                std::slice::from_ref(&dm)
            ),
            Verdict::Mismatch(_)
        ));
        assert!(matches!(
            verify_history(
                &oracle,
                &none,
                &policy,
                &["carol".into()],
                &filters,
                NO_CAPS,
                std::slice::from_ref(&dm)
            ),
            Verdict::Mismatch(_)
        ));
        assert_eq!(
            verify_history(
                &oracle,
                &none,
                &policy,
                &["bob".into()],
                &filters,
                NO_CAPS,
                std::slice::from_ref(&dm)
            ),
            Verdict::Complete
        );
        assert_eq!(
            verify_history(
                &oracle,
                &none,
                &policy,
                &["alice".into()],
                &filters,
                NO_CAPS,
                &[dm]
            ),
            Verdict::Complete
        );
        // An unauthenticated history that leaves the DM out is complete.
        assert_eq!(
            verify_history(&oracle, &none, &policy, &[], &filters, NO_CAPS, &[]),
            Verdict::Complete
        );
    }

    #[test]
    fn multi_filter_requests_use_the_union_of_each_filters_newest_events() {
        let corpus = vec![
            event("r1", 10, 7, json!([["e", "x"]])),
            event("r2", 11, 7, json!([["e", "y"]])),
            event("n1", 12, 1, json!([["e", "x"]])),
        ];
        let oracle = Oracle::new(corpus.clone());
        let none = HashMap::new();
        let filters = [
            json!({"#e":["x"],"kinds":[7]}),
            json!({"#e":["y"],"kinds":[7]}),
        ];
        assert_eq!(
            check(
                &oracle,
                &none,
                &filters,
                &[corpus[1].clone(), corpus[0].clone()]
            ),
            Verdict::Complete
        );
        // Short with no cap to explain it fails; the per-REQ cap explains it.
        assert!(matches!(
            check(&oracle, &none, &filters, &[corpus[1].clone()]),
            Verdict::Mismatch(_)
        ));
        assert_eq!(
            check_with(
                &oracle,
                &none,
                &filters,
                Caps {
                    filter: u64::MAX,
                    req: 1
                },
                &[corpus[1].clone()]
            ),
            Verdict::Truncated {
                returned: 1,
                expected: 2
            }
        );
        assert!(matches!(
            check(&oracle, &none, &filters, &[corpus[2].clone()]),
            Verdict::Mismatch(_)
        ));
        // A catch-up event cannot hide a missing event when no filter has a
        // `limit` it could have displaced.
        let live = event("p0", 500, 7, json!([["e", "x"]]));
        let published = HashMap::from([(
            "p0".to_owned(),
            Published {
                event: live.clone(),
                sent: Instant::now(),
                accepted: Some(true),
                acked: None,
            },
        )]);
        assert!(matches!(
            check(&oracle, &published, &filters, &[live, corpus[1].clone()]),
            Verdict::Mismatch(_)
        ));
    }

    #[test]
    fn refusals_group_by_reason_and_name_their_setting() {
        assert_eq!(
            normalize_reason(
                "blocked: query too broad (cost 102000 > 20000); split the REQ or narrow \
                 authors/kinds"
            ),
            "blocked: query too broad (cost N > N); split the REQ or narrow authors/kinds"
        );
        for (reason, setting) in [
            (
                "rate-limited: REQ budget exhausted",
                "relay.abuse.per_connection.req_rate_per_second / req_burst",
            ),
            (
                "rate-limited: NEG-OPEN budget exhausted",
                "relay.abuse.per_connection.req_rate_per_second / req_burst",
            ),
            (
                "rate-limited: NEG-MSG budget exhausted",
                "relay.abuse.per_connection.neg_msg_rate_per_second / neg_msg_burst",
            ),
            (
                "rate-limited: COUNT budget exhausted",
                "relay.abuse.per_connection.count_rate_per_second / count_burst",
            ),
            (
                "rate-limited: REQ budget exhausted for this address",
                "relay.abuse.req_rate_per_second / req_burst",
            ),
            (
                "rate-limited: NEG-MSG budget exhausted for this address",
                "relay.abuse.req_rate_per_second / req_burst",
            ),
            (
                "rate-limited: COUNT budget exhausted for this address",
                "relay.abuse.count_rate_per_second / count_burst",
            ),
            (
                "rate-limited: author EVENT budget exhausted",
                "relay.abuse.pubkey_event_rate_per_second / pubkey_event_burst",
            ),
            (
                "rate-limited: EVENT budget exhausted for the authenticated pubkey",
                "relay.abuse.pubkey_event_rate_per_second / pubkey_event_burst",
            ),
            (
                "rate-limited: EVENT budget exhausted",
                "relay.abuse.event_rate_per_second / event_burst",
            ),
            (
                "blocked: query too broad (cost N > N); split the REQ or narrow authors/kinds",
                "relay.abuse.max_query_work",
            ),
            (
                "rate-limited: too many concurrent historical queries",
                "relay.abuse.max_concurrent_historical_queries",
            ),
            (
                "rate-limited: too many historical queries waiting on this connection",
                "relay.max_subs_per_connection",
            ),
            (
                "invalid: bad req: filters exceed N serialized bytes",
                "relay.max_req_filter_size",
            ),
            (
                "blocked: this connection's filters exceed N bytes",
                "relay.max_filter_bytes_per_connection",
            ),
            (
                "ERROR: too many concurrent REQs",
                "relay.max_subs_per_connection",
            ),
            (
                "rate-limited: connection budget exhausted",
                "relay.abuse.connection_rate_per_second / connection_burst",
            ),
            (
                "rate-limited: too many connections from this address",
                "relay.abuse.max_connections_per_address",
            ),
            (
                "auth-required: requested filter requires authentication",
                "relay.auth",
            ),
        ] {
            assert_eq!(setting_for(reason), setting, "{reason}");
        }
    }

    #[test]
    fn plan_is_deterministic_and_covers_every_shape() {
        let opts = small_options();
        let a = Plan::generate(&opts, 7, 1_800_000_000);
        let b = Plan::generate(&opts, 7, 1_800_000_000);
        assert_eq!(a.events, b.events);
        let ids: HashSet<&str> = a.events.iter().filter_map(|e| e["id"].as_str()).collect();
        assert_eq!(ids.len(), a.events.len(), "event ids are unique");
        let times: HashSet<u64> = a
            .events
            .iter()
            .filter_map(|e| e["created_at"].as_u64())
            .collect();
        assert_eq!(times.len(), a.events.len(), "timestamps are unique");
        assert!(a
            .events
            .iter()
            .all(|e| e["created_at"].as_u64().unwrap() < 1_800_000_000));
        let kinds: HashSet<u64> = a.events.iter().filter_map(|e| e["kind"].as_u64()).collect();
        for kind in [
            0, 1, 3, 4, 6, 7, 445, 1059, 9735, 10002, 10050, 30023, 30443,
        ] {
            assert!(kinds.contains(&kind), "corpus has kind {kind}");
        }
        let subs = outbox_startup(&a.outbox[0], a.anchor);
        assert_eq!(subs.len(), 30);
        assert_eq!(subs.iter().filter(|s| s.2 == Mode::FetchClose).count(), 15);
        assert_eq!(subs.iter().filter(|s| s.2 == Mode::Replace).count(), 5);
        assert_eq!(subs.iter().filter(|s| s.2 == Mode::Live).count(), 10);
        assert!(a
            .marmot
            .iter()
            .all(|m| m.groups.len() == opts.marmot_groups));
    }

    #[test]
    fn prepared_config_keeps_the_file_and_replaces_only_trial_keys() {
        let dir = tempfile::tempdir().unwrap();
        let supplied = dir.path().join("preset.toml");
        std::fs::write(
            &supplied,
            "[relay]\nport = 9\nmax_filter_limit = 2000\n\n[relay.abuse]\nreq_burst = 100\n\n[relay.auth]\nservice_url = \"wss://relay.example\"\n",
        )
        .unwrap();
        let prepared = prepare_config(dir.path(), 4242, Some(&supplied), true).unwrap();
        let cfg = &prepared.effective;
        assert_eq!(cfg.relay.port, 4242);
        assert_eq!(cfg.relay.max_filter_limit, 2000);
        assert_eq!(cfg.relay.abuse.req_burst, 100);
        assert!(cfg.relay.abuse.enabled);
        assert!(cfg.relay.auth.enabled);
        assert_eq!(cfg.relay.auth.service_url, "wss://relay.example");
        assert_eq!(cfg.relay.real_ip_header, FORWARDED_HEADER);
        assert_eq!(cfg.db, dir.path());
        let defaults = prepare_config(dir.path(), 4243, None, false).unwrap();
        assert_eq!(
            defaults.effective.relay.auth.service_url,
            "ws://127.0.0.1:4243"
        );
        assert_eq!(
            defaults.effective.relay.abuse.req_burst,
            wok_relay::Config::default().relay.abuse.req_burst
        );
        assert!(defaults.effective.relay.real_ip_header.is_empty());
    }

    /// A session over channels instead of a socket, against `corpus`.
    fn offline_session(corpus: Vec<Value>, groups: Vec<Group>, keys: Option<Keypair>) -> Session {
        let start = Instant::now();
        let plan = Plan {
            events: Vec::new(),
            anchor: 1_800_000_000,
            popular: Vec::new(),
            popular_pk: Vec::new(),
            hot_roots: Vec::new(),
            client_notes: Vec::new(),
            outbox: Vec::new(),
            marmot: Vec::new(),
            groups,
        };
        let ctx = Arc::new(Ctx {
            addr: SocketAddr::from(([127, 0, 0, 1], 9)),
            service_url: "ws://127.0.0.1:9".into(),
            opts: small_options(),
            nodelay: true,
            plan: Arc::new(plan),
            oracle: Oracle::new(corpus),
            policy: open_policy(),
            caps: NO_CAPS,
            published: Mutex::new(HashMap::new()),
            stats: Mutex::new(Stats::default()),
            start,
            end: start + Duration::from_secs(60),
            drain_end: start + Duration::from_secs(62),
        });
        let (out, _) = mpsc::unbounded_channel();
        let (_, inbound) = mpsc::unbounded_channel();
        let conn = WsConn {
            out,
            inbound,
            deflate: false,
        };
        Session::new(&ctx, "test".into(), conn, keys, 1)
    }

    #[test]
    fn an_event_leaked_before_closed_is_still_a_mismatch() {
        let dm = json!({"id":"dm","pubkey":"alice","created_at":1,"kind":4,"tags":[["p","bob"]],"content":"","sig":"s"});
        let keys = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(3));
        let mut s = offline_session(vec![dm.clone()], Vec::new(), Some(keys));
        s.challenge = Some("c".into());
        s.req(
            "l2",
            "live.dm_nip04",
            Mode::Live,
            vec![json!({"kinds":[4],"#p":["bob"]})],
        );
        let at = Instant::now();
        s.on_message(at, json!(["EVENT", "l2", dm]));
        s.on_message(
            at,
            json!([
                "CLOSED",
                "l2",
                "auth-required: requested filter requires authentication"
            ]),
        );
        assert!(
            matches!(s.auth, Auth::Pending(..)),
            "the client answers with AUTH"
        );
        let stats = s.ctx.stats();
        assert_eq!(stats.mismatches, 1, "{:?}", stats.mismatch_samples);
        assert!(stats.mismatch_samples[0].contains("restricted event dm"));
    }

    #[test]
    fn a_notice_before_eose_refuses_that_subscriptions_live_part() {
        let note = event("n", 100, 1, json!([]));
        let mut s = offline_session(vec![note.clone()], Vec::new(), None);
        s.req(
            "l0",
            "live.home_feed",
            Mode::Live,
            vec![json!({"kinds":[1]})],
        );
        s.req("l1", "live.thread", Mode::Live, vec![json!({"kinds":[1]})]);
        let at = Instant::now();
        s.on_message(at, json!(["EVENT", "l0", note.clone()]));
        s.on_message(at, json!(["EOSE", "l0"]));
        s.on_message(at, json!(["EVENT", "l1", note]));
        s.on_message(at, json!(["NOTICE", "ERROR: too many concurrent REQs"]));
        s.on_message(at, json!(["EOSE", "l1"]));
        {
            let mut stats = s.ctx.stats();
            assert_eq!(stats.mismatches, 0, "{:?}", stats.mismatch_samples);
            assert_eq!(stats.class("live.thread").refused, 1);
            assert_eq!(stats.class("live.home_feed").refused, 0);
            assert!(stats
                .refusals
                .contains_key("ERROR: too many concurrent REQs"));
        }
        let live: Vec<&str> = s.finish().iter().map(|r| r.class).collect();
        assert_eq!(
            live,
            ["live.home_feed"],
            "only the admitted subscription is checked for deliveries"
        );
    }

    #[test]
    fn a_nip77_need_the_client_already_holds_is_a_mismatch() {
        let gid = "ab".repeat(32);
        let id = |b: u8| hex::encode([b; 32]);
        let corpus = vec![
            json!({"id":id(1),"pubkey":"k1","created_at":10,"kind":445,"tags":[["h",gid]],"content":"","sig":"s"}),
            json!({"id":id(2),"pubkey":"k2","created_at":11,"kind":445,"tags":[["h",gid]],"content":"","sig":"s"}),
        ];
        let groups = vec![Group {
            gid,
            members: vec![0],
        }];
        for (need, problem) in [
            (vec![2u8], None),
            (vec![1, 2], Some("already held")),
            (vec![], Some("missing need")),
        ] {
            let mut s = offline_session(corpus.clone(), groups.clone(), None);
            let mut store = wok_negentropy::Vector::new();
            store.insert(10, &[1; 32]).unwrap();
            store.seal().unwrap();
            let neg = NegState {
                group: 0,
                started: Instant::now(),
                first: None,
                client: wok_negentropy::Negentropy::new(store, 60_000).unwrap(),
                held: HashSet::from([[1u8; 32]]),
                have: Vec::new(),
                need: need.iter().map(|b| vec![*b; 32]).collect(),
            };
            s.finish_neg(Instant::now(), neg);
            let stats = s.ctx.stats();
            match problem {
                None => assert_eq!(stats.mismatches, 0, "{:?}", stats.mismatch_samples),
                Some(text) => assert!(
                    stats.mismatch_samples.iter().any(|m| m.contains(text)),
                    "{need:?}: {:?}",
                    stats.mismatch_samples
                ),
            }
        }
    }

    #[test]
    fn large_bursts_get_every_requested_invitee() {
        let opts = ClientsOptions {
            outbox_clients: 0,
            marmot_clients: 1,
            marmot_groups: 1,
            marmot_invitees: 300,
            max_follows: 1,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 5, 1_800_000_000);
        assert_eq!(plan.marmot[0].invitees.len(), 300);
    }

    pub(super) fn small_options() -> ClientsOptions {
        ClientsOptions {
            outbox_clients: 2,
            marmot_clients: 2,
            marmot_groups: 3,
            marmot_invitees: 3,
            max_follows: 120,
            // A scroll page is replaced only once it finishes, and the first
            // queues behind the connection's other startup REQs. A debug
            // build on a loaded runner took up to 5 s for that, so run past
            // it and tick often enough to replace soon after.
            duration_secs: 6,
            replace_interval_ms: 250,
            publish_rate: 8.0,
            publishers: 2,
            clients_per_address: 1,
            deflate: true,
            expect_no_refusals: false,
        }
    }

    /// The CI-sized version of the scenario, against an in-process relay with
    /// default limits, abuse controls and AUTH on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn small_run_against_default_limits_is_correct_and_counts_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let opts = small_options();
        let anchor = unix_now() - 5;
        let plan = Plan::generate(&opts, 11, anchor);
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        {
            let mut batch: Vec<_> = plan
                .events
                .iter()
                .map(|event| {
                    let parsed = wok_event::parse_and_verify_event(
                        event,
                        &wok_event::EventLimits::default(),
                        None,
                        true,
                        false,
                    )
                    .unwrap();
                    wok_db::EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
                })
                .collect();
            let mut txn = env.begin_rw().unwrap();
            wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut batch, false).unwrap();
            txn.commit().unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = wok_relay::Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        cfg.relay.port = addr.port();
        cfg.relay.real_ip_header = FORWARDED_HEADER.into();
        cfg.relay.auth.service_url = format!("ws://{addr}");
        let handle = wok_relay::start(env, cfg.clone()).unwrap();
        let server = handle.clone();
        tokio::spawn(async move {
            let _ = wok_ws::serve_listener(server, listener).await;
        });
        let (report, _) = run(RunInput {
            addr,
            plan,
            background: Vec::new(),
            config: &cfg,
            relay_config: "built-in defaults".into(),
            config_overrides: Vec::new(),
            opts: opts.clone(),
            nodelay: true,
        })
        .await
        .unwrap();
        handle.request_shutdown();
        let row = |class: &str| {
            report
                .classes
                .iter()
                .find(|r| r.class == class)
                .cloned()
                .unwrap_or_else(|| panic!("no {class} row in {:#?}", report.classes))
        };
        assert_eq!(report.mismatches, 0, "{:#?}", report.mismatch_samples);
        assert_eq!(report.errors, 0, "{:#?}", report.error_samples);
        assert!(report.ok());
        assert_eq!(
            report.deflate_negotiated, report.connections,
            "every connection negotiates deflate"
        );
        // The cost model counts `limit` and the planner's work, so the
        // audit's C4 shapes are served (#97 §3.4).
        assert!(
            !report
                .refusals
                .iter()
                .any(|r| setting_for(&r.reason) == "relay.abuse.max_query_work"),
            "{:#?}",
            report.refusals
        );
        for class in [
            "w3.authors_no_kinds",
            "w3.global_kinds",
            "w4.reaction_batch",
        ] {
            assert_eq!(row(class).completed, row(class).sent, "{class}");
        }
        // AUTH works: the Marmot inbox and both DM subscriptions complete.
        assert_eq!(row("auth").completed, row("auth").sent);
        assert_eq!(row("marmot.inbox").completed, opts.marmot_clients as u64);
        assert_eq!(row("live.dm_nip04").completed, opts.outbox_clients as u64);
        assert_eq!(report.auth_round_trips, 2 * opts.outbox_clients as u64);
        // NIP-77 finishes for every group, then the missing ids are fetched.
        let neg = row("marmot.neg");
        assert_eq!(
            neg.completed,
            (opts.marmot_clients * opts.marmot_groups) as u64
        );
        assert!(neg.events > 0 && row("marmot.ids_fetch").events >= neg.events);
        // Bursts land and are delivered live.
        assert_eq!(row("marmot.burst").completed, opts.marmot_clients as u64);
        assert!(row("delivery.marmot").completed > 0);
        assert!(row("delivery.outbox").completed > 0);
        let scroll = row("w6.scroll_replace");
        assert!(
            scroll.sent > 3 * opts.outbox_clients as u64,
            "replacements happen: {scroll:#?}"
        );
        let md = render_markdown(&report, "wok", 1);
        assert!(
            md.contains("| marmot.neg |") && md.contains("| w4.reaction_batch |"),
            "{md}"
        );
    }
}
