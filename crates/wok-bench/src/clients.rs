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
//! The load is open-loop, as in `rate.rs`: clients arrive on a fixed
//! schedule (`--client-arrival-rate`), optionally leaving after
//! `--client-session-secs` and coming back as the schedule cycles through
//! them, and background publications are due at fixed times. Latency counts
//! from when an action was due, so a relay that falls behind cannot slow the
//! load down. The relay may be one this harness starts or a remote one
//! (`--target-url`) that already holds the same corpus; [`RelayFacts`] says
//! what the oracle must know about it.
//!
//! Refusals (`CLOSED`, `OK false`, `NOTICE`, `NEG-ERR`, HTTP 429 and 503) and
//! disconnects the relay chooses are counted by reason; they are the
//! measurement, not a failure. Correctness still gates the trial: every
//! history is checked against an oracle built from the imported corpus, every
//! live subscription must receive each matching event published after its
//! EOSE exactly once while it is connected, NIP-77 must report exactly the
//! missing IDs, and no restricted event may reach a connection that is not
//! its recipient.

use anyhow::{Context, Result};
use base64::Engine as _;
use hdrhistogram::Histogram;
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SECP256K1};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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
/// How long a Marmot receiver waits for a connect-time AUTH challenge, well
/// under the 1.5 s before its group's burst.
const CHALLENGE_WAIT: Duration = Duration::from_millis(250);
/// A write that cannot finish for this long means the relay stopped reading:
/// the connection is given up and counted as a disconnect.
const WRITE_STALL: Duration = Duration::from_secs(10);
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
    /// Client sessions that start per second, cycling through the planned
    /// clients; 0 starts every client at once.
    pub arrival_rate: f64,
    /// Seconds a session lasts before its client leaves; 0 keeps every
    /// session to the end of the run, so each client arrives once.
    pub session_secs: u64,
}

impl ClientsOptions {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.arrival_rate.is_finite() && self.arrival_rate >= 0.0,
            "--client-arrival-rate must be zero or positive"
        );
        anyhow::ensure!(
            self.publish_rate.is_finite() && self.publish_rate >= 0.0,
            "--publish-rate must be zero or positive"
        );
        if self.session_secs > 0 {
            anyhow::ensure!(
                self.arrival_rate > 0.0,
                "--client-session-secs needs --client-arrival-rate"
            );
            // A client's sessions start `clients / rate` seconds apart, and
            // each reads for DRAIN after it ends.
            let clients = self.outbox_clients + self.marmot_clients;
            let busy = self.arrival_rate * (self.session_secs as f64 + DRAIN.as_secs_f64());
            anyhow::ensure!(
                clients as f64 >= busy,
                "{clients} clients would arrive again before their last session ended: \
                 --client-arrival-rate x (--client-session-secs + 2) is {busy:.0}; plan more \
                 --clients or --marmot-clients"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum User {
    Outbox(usize),
    Marmot(usize),
}

/// One client session: who, which of that client's sessions, and when it is
/// due after the start.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Arrival {
    due: Duration,
    user: User,
    session: u32,
}

/// When each session starts. Outbox and Marmot clients take turns in
/// proportion to their numbers. Without an arrival rate every client starts
/// at once; with one, session `a` is due `a / rate` seconds in, as the
/// `a mod clients`-th client, until the run ends or, when sessions last to
/// the end, every client has arrived once.
fn arrivals(opts: &ClientsOptions) -> Vec<Arrival> {
    let (outbox, marmot) = (opts.outbox_clients, opts.marmot_clients);
    let mut order: Vec<(f64, User)> = (0..outbox)
        .map(|i| ((i as f64 + 0.5) / outbox as f64, User::Outbox(i)))
        .chain((0..marmot).map(|j| ((j as f64 + 0.5) / marmot as f64, User::Marmot(j))))
        .collect();
    order.sort_by(|a, b| a.0.total_cmp(&b.0));
    let order: Vec<User> = order.into_iter().map(|(_, user)| user).collect();
    if opts.arrival_rate <= 0.0 {
        return order
            .into_iter()
            .map(|user| Arrival {
                due: Duration::ZERO,
                user,
                session: 0,
            })
            .collect();
    }
    let secs = opts.duration_secs.max(1) as f64;
    let once = opts.session_secs == 0;
    (0u64..)
        .map(|a| (a, a as f64 / opts.arrival_rate))
        .take_while(|&(a, due)| due < secs && !(once && a as usize >= order.len()))
        .map(|(a, due)| Arrival {
            due: Duration::from_secs_f64(due),
            user: order[a as usize % order.len()],
            session: (a as usize / order.len()) as u32,
        })
        .collect()
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
    fn new(filter: u64, req: u64) -> Self {
        let cap = |n: u64| if n == 0 { u64::MAX } else { n };
        Self {
            filter: cap(filter),
            req: cap(req),
        }
    }
}

/// What the oracle must know about the relay: the URL its AUTH events name,
/// which kinds it serves only to their recipient, and the caps it cuts
/// histories at without saying so (0 for none). A relay this harness starts
/// is described by its config; a remote one by the `--target-*` options,
/// since strfry and older Wok releases have no config this build can read.
pub struct RelayFacts {
    pub service_url: String,
    pub read: wok_relay::restrict::ReadRestrictor,
    pub max_filter_limit: u64,
    pub max_events_per_req: u64,
    /// The settings the report lists.
    pub limits: BTreeMap<String, String>,
}

impl RelayFacts {
    pub fn from_config(cfg: &wok_relay::Config) -> Self {
        Self {
            service_url: cfg.relay.auth.service_url.clone(),
            read: cfg.read_restrictor(),
            max_filter_limit: cfg.relay.max_filter_limit,
            max_events_per_req: cfg.relay.max_total_events_per_req,
            limits: effective_limits(cfg),
        }
    }

    /// A remote relay, AUTHed against the URL the harness connects to.
    pub fn remote(
        url: &str,
        recipient_kinds: &[u64],
        max_filter_limit: u64,
        max_events_per_req: u64,
    ) -> Self {
        let limits = [
            ("target.max_filter_limit", max_filter_limit.to_string()),
            ("target.max_events_per_req", max_events_per_req.to_string()),
            ("target.recipient_kinds", format!("{recipient_kinds:?}")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        Self {
            service_url: url.to_owned(),
            read: wok_relay::restrict::ReadRestrictor {
                recipient_only: recipient_kinds.to_vec(),
                ..Default::default()
            },
            max_filter_limit,
            max_events_per_req,
            limits,
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
    /// Neither answered nor refused when its session stopped reading.
    unanswered: u64,
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
            unanswered: 0,
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

struct Stats {
    classes: BTreeMap<&'static str, ClassStats>,
    refusals: BTreeMap<String, BTreeMap<&'static str, u64>>,
    /// Connections the relay closed, by reason and by connection role.
    disconnects: BTreeMap<String, BTreeMap<&'static str, u64>>,
    mismatches: u64,
    mismatch_samples: Vec<String>,
    errors: u64,
    error_samples: Vec<String>,
    truncation_samples: Vec<String>,
    auth_round_trips: u64,
    sessions: u64,
    connections: u64,
    deflate: u64,
    missed_deliveries: u64,
    duplicate_deliveries: u64,
    largest_commit: usize,
    largest_welcome: usize,
    /// From when a scheduled action was due to when the harness started it.
    lag: Histogram<u64>,
    publish_due: u64,
    /// Background publications written to the socket.
    publish_sent: u64,
    /// When the last of them was written, after the start.
    publish_last: Duration,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            classes: BTreeMap::new(),
            refusals: BTreeMap::new(),
            disconnects: BTreeMap::new(),
            mismatches: 0,
            mismatch_samples: Vec::new(),
            errors: 0,
            error_samples: Vec::new(),
            truncation_samples: Vec::new(),
            auth_round_trips: 0,
            sessions: 0,
            connections: 0,
            deflate: 0,
            missed_deliveries: 0,
            duplicate_deliveries: 0,
            largest_commit: 0,
            largest_welcome: 0,
            lag: Histogram::new(3).expect("histogram"),
            publish_due: 0,
            publish_sent: 0,
            publish_last: Duration::ZERO,
        }
    }
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

    fn disconnect(&mut self, role: &'static str, reason: &str) {
        *self
            .disconnects
            .entry(reason.to_owned())
            .or_default()
            .entry(role)
            .or_default() += 1;
    }

    fn lag(&mut self, due: Instant) {
        record_us(&mut self.lag, micros(due.elapsed()));
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
    /// A publication `(id, frame)`, recorded in [`Written`] once it is on the
    /// socket.
    Event(String, String),
    Pong(Vec<u8>),
    Close,
}

/// Publications the writer has put on the socket, and when: a relay that
/// stops reading holds them in the queue instead.
#[derive(Default)]
struct Written {
    /// Distinct publications written.
    events: u64,
    last: Option<Instant>,
    /// When the last copy of each was written.
    at: HashMap<String, Instant>,
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
    written: Arc<Mutex<Written>>,
    writer: Option<Writer>,
}

/// A connection's writer task; `written` is final once it is done.
struct Writer {
    task: tokio::task::JoinHandle<()>,
    halt: Arc<tokio::sync::Notify>,
}

/// Let the writers send what they were given until `deadline`, then halt
/// every one still running at once and reset its connection. All are done
/// when this returns.
async fn stop_writers(writers: Vec<Writer>, deadline: Instant) {
    let mut running = Vec::new();
    for mut writer in writers {
        if tokio::time::timeout_at(deadline.into(), &mut writer.task)
            .await
            .is_err()
        {
            running.push(writer);
        }
    }
    for writer in &running {
        writer.halt.notify_one();
    }
    for writer in running {
        let _ = writer.task.await;
    }
}

/// Close with a reset rather than a FIN, which cannot pass a zero receive
/// window, and stop the reader: the relay sees the connection drop. A zero
/// linger does not block.
fn reset(writer: &tokio::net::tcp::OwnedWriteHalf, reader: &tokio::sync::Notify) {
    #[allow(deprecated)]
    let _ = writer.as_ref().set_linger(Some(Duration::ZERO));
    reader.notify_one();
}

/// Why a connect did not become a WebSocket. Whatever the relay does is a
/// result: it refused, or did not answer in time. A response that is not
/// HTTP is the relay's protocol error. Only a failure of the load host
/// itself is the harness's error.
pub(crate) enum ConnectFailure {
    /// The relay refused or dropped the connection: an HTTP status other
    /// than 101, or a refused, reset or closed connection.
    Refused(String),
    /// The relay did not take the connection, or answer the upgrade, in time.
    TimedOut(String),
    /// The relay answered with something that is not an HTTP response.
    Invalid(String),
    /// The load host could not make the connection.
    Failed(String),
}

impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "refused: {reason}"),
            Self::Invalid(error) => write!(f, "invalid handshake response: {error}"),
            Self::TimedOut(error) | Self::Failed(error) => f.write_str(error),
        }
    }
}

/// The address of a `ws://host[:port]` relay URL. This client speaks plain
/// WebSocket to the root path, so TLS and other paths are refused.
pub fn target_addr(url: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let rest = url
        .strip_prefix("ws://")
        .with_context(|| format!("--scenario clients needs a ws:// relay URL, not {url}"))?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    anyhow::ensure!(
        !authority.is_empty() && !authority.contains('/'),
        "--scenario clients connects to a relay's root path, not {url}"
    );
    let has_port = authority
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    let authority = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    authority
        .to_socket_addrs()
        .with_context(|| format!("resolve {url}"))?
        .next()
        .with_context(|| format!("{url} resolves to no address"))
}

/// A close frame's status code and reason (RFC 6455 §5.5.1), with digits in
/// the reason collapsed so disconnects group like refusals.
fn close_reason(payload: &[u8]) -> String {
    match payload {
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            let reason = String::from_utf8_lossy(reason);
            if reason.trim().is_empty() {
                format!("close {code}")
            } else {
                format!("close {code}: {}", normalize_reason(&reason))
            }
        }
        _ => "close without a status".into(),
    }
}

/// An I/O error on the way to the relay is its refusal, counted by reason,
/// unless the load host ran out of ports, descriptors, buffers or memory, or
/// was not allowed the socket.
fn io_failure(stage: &str, e: std::io::Error) -> ConnectFailure {
    use std::io::ErrorKind::{
        AddrInUse, AddrNotAvailable, InvalidInput, OutOfMemory, PermissionDenied, Unsupported,
    };
    // ENFILE and EMFILE are 23 and 24 on Linux and the BSDs; ENOBUFS is not.
    const ENOBUFS: i32 = if cfg!(target_os = "linux") { 105 } else { 55 };
    let local = matches!(
        e.kind(),
        AddrInUse | AddrNotAvailable | InvalidInput | OutOfMemory | PermissionDenied | Unsupported
    ) || matches!(e.raw_os_error(), Some(23 | 24 | ENOBUFS));
    if local {
        ConnectFailure::Failed(format!("{stage}: {e}"))
    } else {
        ConnectFailure::Refused(format!("{stage}: {e}"))
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
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| ConnectFailure::TimedOut("TCP connect timed out".into()))?
    .map_err(|e| io_failure("TCP connect", e))?;
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
        .map_err(|e| io_failure("handshake write", e))?;
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
        if buffer.len() > 64 * 1024 {
            return Err(ConnectFailure::Invalid("over 64 KiB with no end".into()));
        }
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .map_err(|_| ConnectFailure::TimedOut("handshake timed out".into()))?
            .map_err(|e| io_failure("handshake read", e))?;
        if n == 0 {
            return Err(ConnectFailure::Refused(
                "relay closed during handshake".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buffer[..end]).to_string();
    let mut rest = buffer[end + 4..].to_vec();
    let status = head.lines().next().unwrap_or_default().to_owned();
    let code = match status.split_whitespace().collect::<Vec<_>>()[..] {
        [version, code, ..]
            if version.starts_with("HTTP/")
                && code.len() == 3
                && code.bytes().all(|b| b.is_ascii_digit()) =>
        {
            code.to_owned()
        }
        _ => {
            let status: String = status.chars().take(80).collect();
            return Err(ConnectFailure::Invalid(status));
        }
    };
    if code != "101" {
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
        // Too many requests, a relay shedding load, or any other refusal,
        // by the relay's own reason when it gives a short one.
        let reason = if body.is_empty() || body.len() > 200 || body.contains('\n') {
            format!("HTTP {code}")
        } else {
            body
        };
        return Err(ConnectFailure::Refused(reason));
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
    let written = Arc::new(Mutex::new(Written::default()));
    let writes = written.clone();
    let stalled = in_tx.clone();
    let abort = Arc::new(tokio::sync::Notify::new());
    let abort_reader = abort.clone();
    let halt = Arc::new(tokio::sync::Notify::new());
    let halted = halt.clone();
    let task = tokio::spawn(async move {
        let mut encoder =
            WsEncoder::with_role(deflate.then(|| DeflateCtx::new(true)), Role::Client);
        loop {
            let out = tokio::select! {
                out = out_rx.recv() => out,
                _ = halted.notified() => return reset(&writer, &abort),
            };
            let Some(out) = out else { break };
            let close = matches!(out, Out::Close);
            let (frame, event) = match out {
                Out::Text(text) => (
                    encoder.encode_message(MessageKind::Text, text.as_bytes()),
                    None,
                ),
                Out::Event(id, text) => (
                    encoder.encode_message(MessageKind::Text, text.as_bytes()),
                    Some(id),
                ),
                Out::Pong(payload) => (Ok(encoder.encode_control(OP_PONG, &payload)), None),
                Out::Close => (Ok(encoder.encode_control(OP_CLOSE, &[])), None),
            };
            let Ok(frame) = frame else { break };
            let wrote = tokio::select! {
                wrote = tokio::time::timeout(WRITE_STALL, writer.write_all(&frame)) => Some(wrote),
                _ = halted.notified() => None,
            };
            let Some(wrote) = wrote else {
                return reset(&writer, &abort);
            };
            match wrote {
                Ok(Ok(())) if close => {
                    let _ = writer.shutdown().await;
                    break;
                }
                Ok(Ok(())) => {
                    if let Some(id) = event {
                        let now = Instant::now();
                        let mut written = writes.lock().unwrap_or_else(|e| e.into_inner());
                        if written.at.insert(id, now).is_none() {
                            written.events += 1;
                        }
                        written.last = Some(now);
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    reset(&writer, &abort);
                    let _ = stalled.send(In::Gone(format!(
                        "write stalled for {} s: the relay stopped reading",
                        WRITE_STALL.as_secs()
                    )));
                    break;
                }
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
        // A frame the codec rejects is the relay's protocol error, not a
        // disconnect it chose.
        let broken = |in_tx: &mpsc::UnboundedSender<In>, e: &dyn std::fmt::Display| {
            let _ = in_tx.send(In::Bad(format!("frame error: {e}")));
            let _ = in_tx.send(In::Gone("invalid frame".into()));
        };
        let mut events = match parser.feed(&rest) {
            Ok(events) => events,
            Err(e) => return broken(&in_tx, &e),
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
                    WsEvent::Close(payload) => {
                        let _ = in_tx.send(In::Gone(close_reason(&payload)));
                        return;
                    }
                };
                if in_tx.send(message).is_err() {
                    return;
                }
            }
            let read = tokio::select! {
                read = reader.read(&mut chunk) => read,
                // The writer gave the connection up.
                _ = abort_reader.notified() => return,
            };
            let n = match read {
                Ok(0) => {
                    let _ = in_tx.send(In::Gone("closed without a close frame".into()));
                    return;
                }
                Ok(n) => n,
                Err(e) => {
                    let _ = in_tx.send(In::Gone(format!("read: {:?}", e.kind())));
                    return;
                }
            };
            events = match parser.feed(&chunk[..n]) {
                Ok(events) => events,
                Err(e) => return broken(&in_tx, &e),
            };
        }
    });
    Ok(WsConn {
        out: out_tx,
        inbound: in_rx,
        deflate,
        written,
        writer: Some(Writer { task, halt }),
    })
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

struct Published {
    event: Value,
    /// When the publication was due; OK and delivery latency count from here.
    due: Instant,
    /// When the copy that was finally accepted was sent: queued, until the
    /// run ends and takes the writer's time for putting it on the socket.
    sent: Instant,
    accepted: Option<bool>,
    acked: Option<Instant>,
}

struct ConnLog {
    role: &'static str,
    written: Arc<Mutex<Written>>,
    writer: Option<Writer>,
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
    /// Every connection the run opened, for when its publications were
    /// sent.
    conns: Mutex<Vec<ConnLog>>,
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
    /// Events sent after this need not have arrived: the session ended, or
    /// the relay disconnected it `DRAIN` later.
    required_until: Instant,
    delivered: HashMap<String, Instant>,
    /// Every event the subscription received, history included.
    seen: HashSet<String>,
}

struct NegState {
    group: usize,
    started: Instant,
    first: Option<Instant>,
    client: wok_negentropy::Negentropy<wok_negentropy::Vector>,
    /// What the client holds, to open the pass again.
    items: Vec<(u64, [u8; 32])>,
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

/// When a session runs: it is due at `due`, starts no work after `until`,
/// and reads for `DRAIN` after that.
#[derive(Clone, Copy)]
struct Visit {
    session: u32,
    due: Instant,
    until: Instant,
}

impl Visit {
    fn label(&self, base: String) -> String {
        if self.session == 0 {
            base
        } else {
            format!("{base}.{}", self.session)
        }
    }

    fn seed(&self, base: u64) -> u64 {
        base ^ (u64::from(self.session) << 32)
    }
}

const NO_CHALLENGE: &str = "auth-required: the relay sent no AUTH challenge";

struct Session {
    ctx: Arc<Ctx>,
    label: String,
    /// Which kind of connection this is, for disconnect counts.
    role: &'static str,
    conn: WsConn,
    keys: Option<Keypair>,
    identities: Vec<String>,
    challenge: Option<String>,
    auth: Auth,
    /// Subscriptions refused with `auth-required:`, and why, sent again
    /// after AUTH.
    auth_waiting: Vec<(String, String)>,
    /// Publications refused with `auth-required:`, and why, resent after
    /// AUTH.
    auth_events: Vec<(String, String)>,
    /// NOTICEs that refuse the live part of the next subscription to EOSE.
    live_refusals: std::collections::VecDeque<String>,
    subs: HashMap<String, Sub>,
    negs: HashMap<String, NegState>,
    ids_fetches: usize,
    pending: HashMap<String, Pending>,
    retries: Vec<(Instant, String)>,
    burst: Option<Burst>,
    gone: bool,
    /// When the relay disconnected this session.
    gone_at: Option<Instant>,
    /// When the visit ends: see `open`.
    until: Instant,
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
    fn new(
        ctx: &Arc<Ctx>,
        label: String,
        role: &'static str,
        conn: WsConn,
        keys: Option<Keypair>,
        seed: u64,
        until: Instant,
    ) -> Self {
        Self {
            ctx: ctx.clone(),
            label,
            role,
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
            gone_at: None,
            until,
            rng: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }

    /// Connect for `visit`; connect latency counts from when it was due. A
    /// refused or timed-out attempt is made again until the visit ends; a
    /// relay that has not taken the connection by then leaves the connect
    /// unanswered, and the visit does nothing.
    async fn connect(
        ctx: &Arc<Ctx>,
        label: String,
        role: &'static str,
        address: Option<IpAddr>,
        keys: Option<Keypair>,
        seed: u64,
        visit: Visit,
    ) -> Option<Self> {
        let unanswered = || {
            let mut stats = ctx.stats();
            let class = stats.class("connect");
            class.sent += 1;
            class.unanswered += 1;
            record_us(&mut class.done, micros(visit.due.elapsed()));
        };
        while Instant::now() < visit.until {
            let attempt = ws_connect(ctx.addr, address, ctx.opts.deflate, ctx.nodelay);
            let Ok(outcome) = tokio::time::timeout_at(visit.until.into(), attempt).await else {
                unanswered();
                return None;
            };
            match outcome {
                Ok(mut conn) => {
                    ctx.conns
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(ConnLog {
                            role,
                            written: conn.written.clone(),
                            writer: conn.writer.take(),
                        });
                    {
                        let mut stats = ctx.stats();
                        stats.connections += 1;
                        stats.deflate += u64::from(conn.deflate);
                        let class = stats.class("connect");
                        class.sent += 1;
                        class.completed += 1;
                        record_us(&mut class.done, micros(visit.due.elapsed()));
                    }
                    return Some(Self::new(ctx, label, role, conn, keys, seed, visit.until));
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
                    let retry = (Instant::now() + Duration::from_secs(1)).min(visit.until);
                    tokio::time::sleep_until(retry.into()).await;
                }
                Err(ConnectFailure::TimedOut(_)) => unanswered(),
                Err(failure @ ConnectFailure::Invalid(_)) => {
                    ctx.stats()
                        .mismatch("protocol", format!("{label}: {failure}"));
                    return None;
                }
                Err(ConnectFailure::Failed(e)) => {
                    ctx.stats().error(format!("{label}: {e}"));
                    return None;
                }
            }
        }
        None
    }

    fn send(&mut self, frame: Value) {
        let _ = self.conn.out.send(Out::Text(frame.to_string()));
    }

    /// Whether the session may still give the relay new work: it is
    /// connected and its visit has not ended. Requests, publications,
    /// NIP-77 passes, AUTH, and the retries of any of them all start only
    /// while this holds, so nothing new reaches the relay after the session
    /// ends; only what finishes an exchange the relay is in the middle of
    /// (NEG-MSG, NEG-CLOSE, CLOSE) still goes out. What could not be sent or
    /// retried keeps the relay's last answer: due and not sent, refused, or
    /// unanswered.
    fn open(&self) -> bool {
        !self.gone && Instant::now() < self.until
    }

    /// Wait for answers to what is in flight, `DRAIN` past the visit.
    async fn drain(&mut self, done: impl Fn(&Session) -> bool) {
        self.pump_until(self.until + DRAIN, done).await;
    }

    fn req(&mut self, sid: &str, class: &'static str, mode: Mode, filters: Vec<Value>) {
        self.req_due(sid, class, mode, filters, Instant::now());
    }

    /// A REQ that was due at `due`; time to EOSE counts from then. False,
    /// with nothing sent, once the session has ended.
    fn req_due(
        &mut self,
        sid: &str,
        class: &'static str,
        mode: Mode,
        filters: Vec<Value>,
        due: Instant,
    ) -> bool {
        if !self.open() {
            return false;
        }
        self.ctx.stats().class(class).sent += 1;
        self.send_req(sid, class, mode, filters, due);
        true
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
        if !self.open() {
            return false;
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

    /// Publish `event`, due at `due`. False, with nothing sent, once the
    /// session has ended.
    fn publish(&mut self, event: Value, class: &'static str, retry: bool, due: Instant) -> bool {
        if !self.open() {
            return false;
        }
        let id = event["id"].as_str().unwrap_or_default().to_owned();
        let frame = json!(["EVENT", event]).to_string();
        self.ctx.published().insert(
            id.clone(),
            Published {
                event,
                due,
                sent: Instant::now(),
                accepted: None,
                acked: None,
            },
        );
        self.ctx.stats().class(class).sent += 1;
        self.pending.insert(
            id.clone(),
            Pending {
                class,
                attempts: 1,
                retry,
            },
        );
        let _ = self.conn.out.send(Out::Event(id, frame));
        true
    }

    /// Publish a group's Add commit and its Welcomes, due at `due`, as one
    /// burst; nothing once the session has ended.
    fn send_burst(&mut self, due: Instant, commit: Value, wraps: Vec<Value>) {
        if !self.open() {
            return;
        }
        {
            let mut stats = self.ctx.stats();
            stats.lag(due);
            stats.largest_commit = stats.largest_commit.max(commit.to_string().len());
            if let Some(wrap) = wraps.first() {
                stats.largest_welcome = stats.largest_welcome.max(wrap.to_string().len());
            }
            stats.class("marmot.burst").sent += 1;
        }
        self.burst = Some(Burst {
            started: due,
            total: 1 + wraps.len(),
            accepted: 0,
            failed: 0,
        });
        self.publish(commit, "publish.marmot_commit", true, due);
        for wrap in wraps {
            self.publish(wrap, "publish.marmot_welcome", true, due);
        }
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
        // A retry the session's end overtook stays refused.
        for id in due {
            if self.open() {
                self.resend(&id);
            } else {
                self.give_up(now, &id, None);
            }
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
            // The session closes its own socket only once it stops reading,
            // so any end of the stream before then is the relay's choice.
            Some(In::Gone(reason)) => {
                self.gone = true;
                self.gone_at = Some(Instant::now());
                self.ctx.stats().disconnect(self.role, &reason);
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
            Some("AUTH") if frame.len() == 2 => {
                self.challenge = text(&frame, 1);
                // Requests refused before the challenge came wait for it.
                if !self.auth_waiting.is_empty() || !self.auth_events.is_empty() {
                    self.start_auth();
                }
            }
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
                // Wok closes open passes when the connection authenticates,
                // and the client opens them again while its session lasts,
                // timed from the first open. One it already finished needs
                // nothing.
                let reopen = reason.starts_with("closed: authentication changed");
                match self.negs.remove(&sid) {
                    Some(neg) if reopen && self.open() => {
                        self.send_neg_open(&sid, neg.group, neg.items, neg.started);
                    }
                    Some(_) => {
                        let mut stats = self.ctx.stats();
                        stats.refusal("marmot.neg", &reason);
                        stats.class("marmot.neg").refused += 1;
                    }
                    None if reopen => {}
                    None => {
                        self.protocol(format!("NEG-ERR for unknown session {sid}: {reason}"));
                    }
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
            let mut stats = ctx.stats();
            if sub.eose.is_some() {
                stats.duplicate_deliveries += 1;
            }
            stats.mismatch(
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
        let (class, answered) = (sub.class, sub.eose.is_some());
        let can_auth = self.open()
            && self.keys.is_some()
            && matches!(self.auth, Auth::None | Auth::Pending(..));
        if reason.starts_with("auth-required:") && !answered && can_auth {
            // NIP-42: authenticate, then send the same REQ again. Before the
            // relay's challenge arrives, AUTH waits for it.
            self.auth_waiting.push((sid.to_owned(), reason.to_owned()));
            self.ctx.stats().auth_round_trips += 1;
            if self.start_auth() || self.challenge.is_none() {
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
                    // What AUTH was for goes out again while the session
                    // lasts; after that it stays refused.
                    let open = self.open();
                    for (sid, reason) in std::mem::take(&mut self.auth_waiting) {
                        if !open {
                            self.refuse_sub(&sid, &reason);
                        } else if let Some(old) = self.subs.remove(&sid) {
                            self.send_req(&sid, old.class, old.mode, old.filters, old.started);
                        }
                    }
                    for (event_id, reason) in std::mem::take(&mut self.auth_events) {
                        if open {
                            self.resend(&event_id);
                        } else {
                            self.give_up(at, &event_id, Some(&reason));
                        }
                    }
                } else {
                    self.auth = Auth::Failed;
                    let mut stats = self.ctx.stats();
                    stats.refusal("auth", reason);
                    stats.class("auth").refused += 1;
                    drop(stats);
                    for (sid, _) in std::mem::take(&mut self.auth_waiting) {
                        self.refuse_sub(&sid, "auth-required: AUTH was refused");
                    }
                    for (event_id, _) in std::mem::take(&mut self.auth_events) {
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
            let due = published.get(id).map_or(at, |p| p.due);
            if let Some(p) = published.get_mut(id) {
                p.accepted = Some(true);
                p.acked = Some(at);
            }
            drop(published);
            self.pending.remove(id);
            let mut stats = self.ctx.stats();
            let row = stats.class(class);
            row.completed += 1;
            record_us(&mut row.done, micros(at.saturating_duration_since(due)));
            drop(stats);
            if class != "publish.background" {
                self.burst_progress(at, true);
            }
            return;
        }
        // MDK publishes anonymously and authenticates only when a relay
        // answers `auth-required:`, then publishes again.
        let can_auth = self.open()
            && self.keys.is_some()
            && matches!(self.auth, Auth::None | Auth::Pending(..));
        if retry && reason.starts_with("auth-required:") && can_auth {
            self.auth_events.push((id.to_owned(), reason.to_owned()));
            self.ctx.stats().auth_round_trips += 1;
            if self.start_auth() || self.challenge.is_none() {
                return;
            }
            self.auth_events.pop();
        }
        {
            let mut stats = self.ctx.stats();
            stats.refusal(class, reason);
            stats.class(class).refused += 1;
        }
        // MDK retries `rate-limited:` publications with backoff, within the
        // session.
        let delay = Duration::from_millis(250 * u64::from(attempts.min(12)));
        if retry && reason.starts_with("rate-limited:") && at + delay < self.until {
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
        let frame = json!(["EVENT", event]).to_string();
        let _ = self.conn.out.send(Out::Event(id.to_owned(), frame));
    }

    /// A subscription the relay refused, and that is not asked again.
    fn refuse_sub(&mut self, sid: &str, reason: &str) {
        if let Some(sub) = self.subs.get_mut(sid) {
            sub.refused = true;
            let mut stats = self.ctx.stats();
            stats.refusal(sub.class, reason);
            stats.class(sub.class).refused += 1;
        }
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
        if !self.open() {
            return;
        }
        self.ctx.stats().class("marmot.neg").sent += 1;
        self.send_neg_open(sid, group, held.to_vec(), Instant::now());
    }

    fn send_neg_open(
        &mut self,
        sid: &str,
        group: usize,
        items: Vec<(u64, [u8; 32])>,
        started: Instant,
    ) {
        let mut store = wok_negentropy::Vector::new();
        for (created_at, id) in &items {
            store.insert(*created_at, id).expect("insert held event");
        }
        store.seal().expect("seal negentropy store");
        let mut client = wok_negentropy::Negentropy::new(store, 60_000).expect("negentropy client");
        let init = client.initiate().expect("negentropy initiate");
        let gid = &self.ctx.plan.groups[group].gid;
        self.send(json!(["NEG-OPEN", sid, {"kinds":[445],"#h":[gid],"limit":NEG_LIMIT}, hex::encode(init)]));
        let held = items.iter().map(|(_, id)| *id).collect();
        self.negs.insert(
            sid.to_owned(),
            NegState {
                group,
                started,
                first: None,
                client,
                items,
                held,
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

    /// End the session: count what was never answered, keep the live
    /// subscriptions for the delivery check, and close the socket.
    ///
    /// As in `rate.rs`, a request still unanswered when the session stops
    /// reading counts in its class's latency until then, a lower bound.
    /// Work a relay disconnect cut off is that disconnect's result, so it
    /// does not count.
    fn finish(mut self) -> Vec<LiveRecord> {
        let now = Instant::now();
        // What still waited on AUTH stays refused: for want of a challenge,
        // or with the relay's reason.
        let challenged = self.challenge.is_some();
        for (sid, reason) in std::mem::take(&mut self.auth_waiting) {
            self.refuse_sub(&sid, if challenged { &reason } else { NO_CHALLENGE });
        }
        for (id, reason) in std::mem::take(&mut self.auth_events) {
            let reason = if challenged { &reason } else { NO_CHALLENGE };
            self.give_up(now, &id, Some(reason));
        }
        // Retries the session's end overtook stay refused.
        for (_, id) in std::mem::take(&mut self.retries) {
            self.give_up(now, &id, None);
        }
        let cut_off = self.gone;
        let until = self.until;
        let pending: Vec<(&'static str, Instant)> = {
            let published = self.ctx.published();
            self.pending
                .iter()
                .filter_map(|(id, pending)| Some((pending.class, published.get(id)?.due)))
                .collect()
        };
        let mut stats = self.ctx.stats();
        let mut unanswered = |class: &'static str, since: Instant| {
            if !cut_off && since < until {
                let row = stats.class(class);
                row.unanswered += 1;
                record_us(&mut row.done, micros(now.saturating_duration_since(since)));
            }
        };
        for sub in self.subs.values() {
            if sub.eose.is_none() && !sub.refused {
                unanswered(sub.class, sub.started);
            }
        }
        for neg in self.negs.values() {
            unanswered("marmot.neg", neg.started);
        }
        if let Auth::Pending(_, sent) = self.auth {
            unanswered("auth", sent);
        }
        for (class, due) in pending {
            unanswered(class, due);
        }
        if let Some(burst) = &self.burst {
            if burst.accepted + burst.failed < burst.total {
                unanswered("marmot.burst", burst.started);
            }
        }
        for reason in &self.live_refusals {
            stats.refusal("notice", reason);
        }
        drop(stats);
        let _ = self.conn.out.send(Out::Close);
        let required_until = match self.gone_at {
            Some(gone) => until.min(gone.checked_sub(DRAIN).unwrap_or(gone)),
            None => until,
        };
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
                    required_until,
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

/// Start one session when it is due and run it as its client's role.
async fn arrive(ctx: Arc<Ctx>, arrival: Arrival) -> Vec<LiveRecord> {
    let due = ctx.start + arrival.due;
    tokio::time::sleep_until(due.into()).await;
    let until = match ctx.opts.session_secs {
        0 => ctx.end,
        secs => (due + Duration::from_secs(secs)).min(ctx.end),
    };
    let visit = Visit {
        session: arrival.session,
        due,
        until,
    };
    {
        let mut stats = ctx.stats();
        stats.sessions += 1;
        stats.lag(due);
    }
    match arrival.user {
        User::Outbox(i) => outbox_client(ctx, i, visit).await,
        User::Marmot(j) => {
            let roles = [
                tokio::spawn(marmot_receiver(ctx.clone(), j, visit)),
                tokio::spawn(marmot_directory(ctx.clone(), j, visit)),
                tokio::spawn(marmot_publisher(ctx, j, visit)),
            ];
            let mut records = Vec::new();
            for role in roles {
                match role.await {
                    Ok(live) => records.extend(live),
                    Err(e) => std::panic::resume_unwind(e.into_panic()),
                }
            }
            records
        }
    }
}

async fn outbox_client(ctx: Arc<Ctx>, index: usize, visit: Visit) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.outbox[index];
    let label = visit.label(format!("outbox-{index}"));
    let address = user_address(&ctx, index);
    let seed = visit.seed(index as u64);
    let Some(mut s) =
        Session::connect(&ctx, label, "outbox", address, Some(user.keys), seed, visit).await
    else {
        return Vec::new();
    };
    // Clients send their subscriptions once connected; a DM inbox refused
    // for want of AUTH answers the relay's challenge, then asks again.
    for (sid, class, mode, filters) in outbox_startup(user, plan.anchor) {
        s.req(&sid, class, mode, filters);
    }
    // Every interval, each replaced subscription (r0–r2 scroll, r3–r4
    // rotate) is due a re-REQ with the same id. One due while its last REQ
    // is unfinished waits for it and keeps its due time, so a slow relay
    // builds a backlog that the latency shows instead of being offered less.
    let interval = Duration::from_millis(ctx.opts.replace_interval_ms.max(1));
    let mut next = visit.due + interval;
    let mut queued: [VecDeque<Instant>; 5] = Default::default();
    let sid = |k: usize| format!("r{k}");
    let replace_class = |k: usize| {
        if k < 3 {
            "w6.scroll_replace"
        } else {
            "w6.profile_replace"
        }
    };
    let mut until = [plan.anchor - 15 * DAY; 3];
    let mut step = 2;
    while s.open() {
        let ready = |s: &Session| (0..5).any(|k| !queued[k].is_empty() && s.finished(&sid(k)));
        s.pump_until(next.min(visit.until), ready).await;
        if !s.open() {
            break;
        }
        let now = Instant::now();
        if now >= next {
            ctx.stats().lag(next);
            for slots in &mut queued {
                slots.push_back(next);
            }
            next += interval;
        }
        for (k, slots) in queued.iter_mut().enumerate() {
            let id = sid(k);
            if !s.finished(&id) {
                continue;
            }
            let Some(due) = slots.pop_front() else {
                continue;
            };
            let filter = if k < 3 {
                // Page further back from the oldest event of the last page.
                until[k] = s.subs[&id].oldest.map_or(until[k] - 3 * DAY, |t| t - 1);
                scroll_filter(user, until[k])
            } else {
                step += 1;
                rotation_filter(user, step)
            };
            if !s.req_due(&id, replace_class(k), Mode::Replace, vec![filter], due) {
                slots.push_front(due);
            }
        }
    }
    s.drain(|_| false).await;
    // Re-REQs still waiting when the session stopped reading were due and
    // never answered, unless the relay ended the session.
    if !s.gone {
        let now = Instant::now();
        let mut stats = ctx.stats();
        for (k, slots) in queued.iter().enumerate() {
            for due in slots {
                let row = stats.class(replace_class(k));
                row.unanswered += 1;
                record_us(&mut row.done, micros(now.saturating_duration_since(*due)));
            }
        }
    }
    s.finish()
}

async fn marmot_receiver(ctx: Arc<Ctx>, index: usize, visit: Visit) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.marmot[index];
    let label = visit.label(format!("marmot-{index}-recv"));
    let address = user_address(&ctx, ctx.opts.outbox_clients + index);
    let seed = visit.seed(1_000 + index as u64);
    let Some(mut s) = Session::connect(
        &ctx,
        label,
        "marmot.recv",
        address,
        Some(user.keys),
        seed,
        visit,
    )
    .await
    else {
        return Vec::new();
    };
    // MDK authenticates its receive connection with the account key before
    // it subscribes. Wok challenges on connect whenever AUTH can complete;
    // strfry, and Wok with AUTH off, never do, so the wait for a challenge
    // is short and the subscriptions exist before the group's burst. Once
    // AUTH is sent its answer is waited for, since the relay may already
    // serve the subscriptions as the account. A pass a late AUTH closes is
    // opened again.
    let wait = (Instant::now() + CHALLENGE_WAIT).min(visit.until);
    s.pump_until(wait, |s| s.challenge.is_some()).await;
    if s.start_auth() {
        s.pump_until(visit.until, |s| !matches!(s.auth, Auth::Pending(..)))
            .await;
    }
    // A late upgrade or AUTH can leave the session over: then nothing is
    // subscribed.
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
    s.drain(|_| false).await;
    s.finish()
}

async fn marmot_directory(ctx: Arc<Ctx>, index: usize, visit: Visit) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.marmot[index];
    let label = visit.label(format!("marmot-{index}-dir"));
    let address = user_address(&ctx, ctx.opts.outbox_clients + index);
    let seed = visit.seed(2_000 + index as u64);
    let Some(mut s) = Session::connect(&ctx, label, "marmot.dir", address, None, seed, visit).await
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
    s.drain(|s| sids.iter().all(|sid| s.finished(sid))).await;
    s.finish()
}

async fn marmot_publisher(ctx: Arc<Ctx>, index: usize, visit: Visit) -> Vec<LiveRecord> {
    let plan = ctx.plan.clone();
    let user = &plan.marmot[index];
    let label = visit.label(format!("marmot-{index}-pub"));
    let address = user_address(&ctx, ctx.opts.outbox_clients + index);
    let seed = visit.seed(3_000 + index as u64);
    let Some(mut s) = Session::connect(
        &ctx,
        label,
        "marmot.pub",
        address,
        Some(user.keys),
        seed,
        visit,
    )
    .await
    else {
        return Vec::new();
    };
    let window = visit.until.saturating_duration_since(visit.due) / 3;
    let stagger = window / ctx.opts.marmot_clients.max(1) as u32;
    let burst_at = visit.due + Duration::from_millis(1_500) + stagger * index as u32;
    if burst_at < visit.until {
        let invitees = &user.invitees;
        let group = &plan.groups[user.groups[0]];
        let members = group.members.len() + invitees.len();
        // Signed before the burst is due, so signing costs it nothing. An
        // Add commit carries every new member's KeyPackage; each Welcome
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
        s.pump_until(burst_at, |_| false).await;
        // A late upgrade and the preparation can leave the session over.
        s.send_burst(burst_at, commit, wraps);
    }
    s.drain(|s| s.pending.is_empty()).await;
    s.finish()
}

fn fresh_keys(rng: &mut rand::rngs::StdRng) -> Keypair {
    Keypair::new(SECP256K1, rng)
}

/// Background publisher. Publication `k` is due at a fixed time and goes
/// out then, answered or not, as in `rate.rs`. One the relay refuses or
/// disconnects connects again and resumes with the slot due then; the
/// slots it missed are due and not sent.
async fn background_publisher(ctx: Arc<Ctx>, index: usize) -> Vec<LiveRecord> {
    let address = (ctx.opts.clients_per_address > 0)
        .then(|| IpAddr::V4(Ipv4Addr::new(10, 200, 0, index as u8)));
    let publishers = ctx.opts.publishers.max(1);
    let per_publisher = ctx.opts.publish_rate / publishers as f64;
    let interval = Duration::from_secs_f64(1.0 / per_publisher.max(0.01));
    let mut next = ctx.start + interval.mul_f64(index as f64 / publishers as f64);
    let mut n = index as u64;
    let mut session = 0;
    while next < ctx.end {
        let visit = Visit {
            session,
            due: Instant::now(),
            until: ctx.end,
        };
        session += 1;
        let label = visit.label(format!("publisher-{index}"));
        let seed = visit.seed(4_000 + index as u64);
        let Some(mut s) =
            Session::connect(&ctx, label, "publisher", address, None, seed, visit).await
        else {
            break;
        };
        {
            // What fell due while the relay refused or had dropped the
            // connection is due and not sent, as when `rate.rs` loses one;
            // the slot due now goes out, instead of the whole backlog.
            let now = Instant::now();
            let mut stats = ctx.stats();
            while next + interval <= now && next < ctx.end {
                stats.publish_due += 1;
                next += interval;
            }
        }
        while s.open() && next < ctx.end {
            s.pump_until(next, |_| false).await;
            if Instant::now() < next {
                continue;
            }
            let due = next;
            next += interval;
            n += 1;
            let event = background_event(&ctx, &mut s.rng, index, n);
            {
                let mut stats = ctx.stats();
                stats.lag(due);
                stats.publish_due += 1;
            }
            // Due either way; sent only while the session lasts.
            s.publish(event, "publish.background", false, due);
        }
        s.drain(|s| s.pending.is_empty()).await;
        s.finish();
    }
    // Publications due once the relay no longer took the connection.
    let mut stats = ctx.stats();
    while next < ctx.end {
        stats.publish_due += 1;
        next += interval;
    }
    Vec::new()
}

/// Background publication `n` of publisher `index`: popular authors post
/// notes, reply to hot threads and react to clients' notes; with Marmot
/// clients, every fourth event is a 445 from a throwaway key into a random
/// group.
fn background_event(ctx: &Ctx, rng: &mut rand::rngs::StdRng, index: usize, n: u64) -> Value {
    let plan = &ctx.plan;
    // Each publisher signs for its own popular authors, so two publishers
    // never produce the same event.
    let publishers = ctx.opts.publishers.max(1);
    let own = plan.popular.len().div_ceil(publishers).max(1);
    let author = (index + publishers * ((n as usize / 4) % own)) % plan.popular.len().max(1);
    let (keys, kind, tags, content) = match n % 4 {
        3 if !plan.groups.is_empty() => {
            let group = &plan.groups[rng.gen_range(0..plan.groups.len())];
            let keys = fresh_keys(rng);
            let size = rng.gen_range(300..1_200);
            (keys, 445, vec![json!(["h", group.gid])], b64(rng, size))
        }
        1 if !plan.hot_roots.is_empty() => {
            let (root, root_author) = &plan.hot_roots[rng.gen_range(0..plan.hot_roots.len())];
            (
                plan.popular[author],
                1,
                vec![json!(["e", root, "", "root"]), json!(["p", root_author])],
                format!("live reply {n}"),
            )
        }
        2 if !plan.client_notes.is_empty() => {
            let (note, client) = &plan.client_notes[rng.gen_range(0..plan.client_notes.len())];
            let target = &plan.outbox[*client].pubkey;
            (
                plan.popular[author],
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
            (
                plan.popular[author],
                1,
                tags,
                format!("live note {n} from {}", plan.popular_pk[author]),
            )
        }
    };
    // The same author, tags and content within one second make the same
    // event, which a relay answers `duplicate:` and never broadcasts again,
    // so a repeat goes out dated a second later.
    let mut created_at = unix_now();
    loop {
        let event = signed(&keys, created_at, kind, tags.clone(), content.clone());
        if !ctx
            .published()
            .contains_key(event["id"].as_str().unwrap_or_default())
        {
            return event;
        }
        created_at += 1;
    }
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
    pub unanswered: u64,
    pub truncated: u64,
    pub events: u64,
    pub live_events: u64,
    pub mismatches: u64,
    pub first_p50_ms: f64,
    pub first_p99_ms: f64,
    pub done_p50_ms: f64,
    pub done_p99_ms: f64,
    pub done_max_ms: f64,
}

#[derive(Serialize, Clone, Debug)]
pub struct RefusalRow {
    pub reason: String,
    pub setting: String,
    pub count: u64,
    pub classes: BTreeMap<String, u64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DisconnectRow {
    pub reason: String,
    pub count: u64,
    /// Connections by role: `outbox`, `marmot.recv`, `marmot.dir`,
    /// `marmot.pub` or `publisher`.
    pub roles: BTreeMap<String, u64>,
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
    pub sessions: u64,
    pub connections: u64,
    pub deflate_negotiated: u64,
    pub subscriptions: u64,
    pub refusals_total: u64,
    pub disconnects_total: u64,
    pub unanswered_total: u64,
    pub auth_round_trips: u64,
    pub truncated_total: u64,
    pub missed_deliveries: u64,
    /// Live events a subscription received more than once.
    pub duplicate_deliveries: u64,
    pub largest_commit_bytes: u64,
    pub largest_welcome_bytes: u64,
    /// From when a scheduled action (an arrival, a re-REQ, a publication or
    /// a burst) was due to when the harness started it: the load generator's
    /// own lateness.
    pub lag_p99_ms: f64,
    pub lag_max_ms: f64,
    pub publish_due: u64,
    /// Background publications written to the socket; one still queued
    /// behind a relay that stopped reading is not sent.
    pub publish_sent: u64,
    /// Background publications sent per second over the run, or to the last
    /// send if that was later.
    pub publish_achieved_rate: f64,
    pub mismatches: u64,
    pub errors: u64,
    pub mismatch_samples: Vec<String>,
    pub error_samples: Vec<String>,
    pub truncation_samples: Vec<String>,
    pub classes: Vec<ClassRow>,
    pub refusals: Vec<RefusalRow>,
    pub disconnects: Vec<DisconnectRow>,
}

impl ClientsReport {
    /// Correct, with background publishing at its planned rate. Refusals,
    /// disconnects and unanswered requests are results, except with
    /// `--expect-no-refusals`, which fails the trial on any of them.
    pub fn ok(&self) -> bool {
        self.mismatches == 0
            && self.errors == 0
            && self.publish_rate_held()
            && (!self.options.expect_no_refusals
                || self.refusals_total + self.disconnects_total + self.unanswered_total == 0)
    }

    /// Background publications kept their schedule, as `rate.rs` measures
    /// it: sends over the run, or to the last send if that was later, reach
    /// 99% of the publications due.
    pub fn publish_rate_held(&self) -> bool {
        let planned = self.publish_due as f64 / self.options.duration_secs.max(1) as f64;
        self.publish_due == 0 || self.publish_achieved_rate >= crate::rate::RATE_HELD * planned
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

pub struct RunInput {
    pub addr: SocketAddr,
    pub plan: Plan,
    pub background: Vec<Value>,
    pub facts: RelayFacts,
    pub relay_config: String,
    pub config_overrides: Vec<String>,
    pub opts: ClientsOptions,
    pub nodelay: bool,
}

/// Run the scenario against a relay that imported `plan.events` and
/// `background`. Also returns every REQ class's time to EOSE, merged.
pub async fn run(input: RunInput) -> Result<(ClientsReport, Histogram<u64>)> {
    let RunInput {
        addr,
        mut plan,
        background,
        facts,
        relay_config,
        config_overrides,
        opts,
        nodelay,
    } = input;
    opts.validate()?;
    let scenario_events = plan.events.len() as u64;
    // What the relay keeps of the background, `--event-mix social`'s
    // deletions and replacements applied, is what it can hold and serve.
    let background = crate::retained_events(&background);
    let background_events = background.len() as u64;
    let mut corpus = std::mem::take(&mut plan.events);
    corpus.extend(background);
    let oracle = Oracle::new(corpus);
    check_target(addr, nodelay, &plan, &oracle, scenario_events as usize).await?;
    let schedule = arrivals(&opts);
    let start = Instant::now();
    let end = start + Duration::from_secs(opts.duration_secs.max(1));
    let ctx = Arc::new(Ctx {
        addr,
        service_url: facts.service_url.clone(),
        nodelay,
        plan: Arc::new(plan),
        oracle,
        policy: ReadPolicy(facts.read.clone()),
        caps: Caps::new(facts.max_filter_limit, facts.max_events_per_req),
        published: Mutex::new(HashMap::new()),
        conns: Mutex::new(Vec::new()),
        stats: Mutex::new(Stats::default()),
        start,
        end,
        drain_end: end + DRAIN,
        opts: opts.clone(),
    });
    let mut tasks = tokio::task::JoinSet::new();
    for arrival in schedule {
        tasks.spawn(arrive(ctx.clone(), arrival));
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
    // A write may still finish within its stall budget; none goes on after.
    settle_writes(&ctx, ctx.drain_end + WRITE_STALL).await;
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
            unanswered: s.unanswered,
            truncated: s.truncated,
            events: s.events,
            live_events: s.live_events,
            mismatches: s.mismatches,
            first_p50_ms: ms(&s.first, 0.5),
            first_p99_ms: ms(&s.first, 0.99),
            done_p50_ms: ms(&s.done, 0.5),
            done_p99_ms: ms(&s.done, 0.99),
            done_max_ms: ms(&s.done, 1.0),
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
    let mut disconnects: Vec<DisconnectRow> = stats
        .disconnects
        .iter()
        .map(|(reason, by_role)| DisconnectRow {
            reason: reason.clone(),
            count: by_role.values().sum(),
            roles: by_role
                .iter()
                .map(|(role, n)| ((*role).to_owned(), *n))
                .collect(),
        })
        .collect();
    disconnects.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    // As in `rate.rs`, the last send closes an interval of 1 / rate.
    let publish_window = if opts.publish_rate > 0.0 {
        (opts.duration_secs.max(1) as f64)
            .max(stats.publish_last.as_secs_f64() + 1.0 / opts.publish_rate)
    } else {
        1.0
    };
    let report = ClientsReport {
        relay_config,
        config_overrides,
        limits: facts.limits,
        options: opts,
        scenario_events,
        background_events,
        elapsed_secs: elapsed.as_secs_f64(),
        sessions: stats.sessions,
        connections: stats.connections,
        deflate_negotiated: stats.deflate,
        subscriptions: classes
            .iter()
            .filter(|row| is_req_class(&row.class))
            .map(|row| row.sent)
            .sum(),
        refusals_total: refusals.iter().map(|row| row.count).sum(),
        disconnects_total: disconnects.iter().map(|row| row.count).sum(),
        unanswered_total: classes.iter().map(|row| row.unanswered).sum(),
        auth_round_trips: stats.auth_round_trips,
        truncated_total: classes.iter().map(|row| row.truncated).sum(),
        missed_deliveries: stats.missed_deliveries,
        duplicate_deliveries: stats.duplicate_deliveries,
        largest_commit_bytes: stats.largest_commit as u64,
        largest_welcome_bytes: stats.largest_welcome as u64,
        lag_p99_ms: ms(&stats.lag, 0.99),
        lag_max_ms: ms(&stats.lag, 1.0),
        publish_due: stats.publish_due,
        publish_sent: stats.publish_sent,
        publish_achieved_rate: stats.publish_sent as f64 / publish_window,
        mismatches: stats.mismatches,
        errors: stats.errors,
        mismatch_samples: stats.mismatch_samples,
        error_samples: stats.error_samples,
        truncation_samples: stats.truncation_samples,
        classes,
        refusals,
        disconnects,
    };
    Ok((report, eose))
}

/// Before the clock starts, check that the relay holds both corpora and
/// nothing this scenario published after the anchor. A remote relay must be
/// given them, and a database an earlier run published into restored, or
/// every history check would fail without saying why.
async fn check_target(
    addr: SocketAddr,
    nodelay: bool,
    plan: &Plan,
    oracle: &Oracle,
    scenario_events: usize,
) -> Result<()> {
    // Notes are never replaced, and the oracle holds only those a relay
    // keeps, so every one sampled must be there.
    let sample = |events: &[Value]| -> Vec<String> {
        let notes: Vec<&str> = events
            .iter()
            .filter(|event| event["kind"] == 1)
            .filter_map(|event| event["id"].as_str())
            .collect();
        [0, notes.len() / 2, notes.len().saturating_sub(1)]
            .iter()
            .filter_map(|&i| notes.get(i).map(|id| (*id).to_owned()))
            .collect()
    };
    let (own, background) = oracle
        .events
        .split_at(scenario_events.min(oracle.events.len()));
    let mut ids = sample(own);
    ids.extend(sample(background));
    ids.sort();
    ids.dedup();
    let mut conn = ws_connect(addr, None, false, nodelay)
        .await
        .map_err(|e| anyhow::anyhow!("connect to the relay: {e}"))?;
    if !ids.is_empty() {
        let held = probe(&mut conn, "check-corpus", json!({"ids": ids})).await?;
        let missing: Vec<&String> = ids.iter().filter(|id| !held.contains(*id)).collect();
        anyhow::ensure!(
            missing.is_empty(),
            "the relay lacks {} of {} sampled corpus events, {} among them: it must hold the \
             --corpus file and the clients corpus that --generate-corpus-only --scenario clients \
             writes with the same seed, --base-timestamp and client options",
            missing.len(),
            ids.len(),
            missing[0]
        );
    }
    // Background publishers sign as the popular authors, and every Marmot
    // burst and background 445 lands in the scenario's groups.
    let gids: Vec<&str> = plan.groups.iter().map(|g| g.gid.as_str()).collect();
    let fresh = [
        (!plan.popular_pk.is_empty())
            .then(|| json!({"authors": plan.popular_pk, "since": plan.anchor, "limit": 1})),
        (!gids.is_empty())
            .then(|| json!({"kinds": [445], "#h": gids, "since": plan.anchor, "limit": 1})),
    ];
    for filter in fresh.into_iter().flatten() {
        let newer = probe(&mut conn, "check-fresh", filter).await?;
        anyhow::ensure!(
            newer.is_empty(),
            "the relay holds events this scenario published after --base-timestamp {}: an \
             earlier run published into this database, so restore it first",
            plan.anchor
        );
    }
    let _ = conn.out.send(Out::Close);
    Ok(())
}

/// The ids one REQ returns before its EOSE.
async fn probe(conn: &mut WsConn, sid: &str, filter: Value) -> Result<HashSet<String>> {
    let _ = conn
        .out
        .send(Out::Text(json!(["REQ", sid, filter]).to_string()));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut ids = HashSet::new();
    loop {
        let message = tokio::time::timeout_at(deadline, conn.inbound.recv())
            .await
            .map_err(|_| anyhow::anyhow!("no EOSE for the relay check {sid} within 30 s"))?;
        let frame = match message {
            Some(In::Msg(_, frame)) => frame,
            Some(In::Bad(detail)) => anyhow::bail!("relay check {sid}: {detail}"),
            Some(In::Gone(reason)) => anyhow::bail!("relay check {sid}: {reason}"),
            None => anyhow::bail!("relay check {sid}: the connection ended"),
        };
        if frame[1] != sid {
            continue;
        }
        match frame[0].as_str() {
            Some("EVENT") => ids.extend(frame[2]["id"].as_str().map(str::to_owned)),
            Some("EOSE") => break,
            Some("CLOSED") => anyhow::bail!("the relay refused the check {sid}: {}", frame[2]),
            _ => {}
        }
    }
    let _ = conn.out.send(Out::Text(json!(["CLOSE", sid]).to_string()));
    Ok(ids)
}

/// Stop every connection's writer by `deadline`, then take from their logs
/// what was sent. A publication reached the relay when it was written, not
/// when it was queued, and that decides whether a subscription had to see
/// it live; a background publication still queued was not sent.
async fn settle_writes(ctx: &Ctx, deadline: Instant) {
    let conns = std::mem::take(&mut *ctx.conns.lock().unwrap_or_else(|e| e.into_inner()));
    let mut writers = Vec::new();
    let mut logs = Vec::new();
    for conn in conns {
        writers.extend(conn.writer);
        logs.push((conn.role, conn.written));
    }
    stop_writers(writers, deadline).await;
    let mut published = ctx.published();
    let mut stats = ctx.stats();
    for (role, written) in logs {
        let written = written.lock().unwrap_or_else(|e| e.into_inner());
        for (id, at) in &written.at {
            if let Some(p) = published.get_mut(id) {
                p.sent = *at;
            }
        }
        if role == "publisher" {
            stats.publish_sent += written.events;
            if let Some(last) = written.last {
                stats.publish_last = stats
                    .publish_last
                    .max(last.saturating_duration_since(ctx.start));
            }
        }
    }
}

/// Every live subscription must receive each accepted, matching, visible
/// event sent after its EOSE arrived while it was connected. Events sent
/// earlier may show up in history instead, and events sent after
/// `required_until` may still be on their way, so neither is required.
/// Latency counts from when the publication was due.
fn check_deliveries(ctx: &Ctx, records: &[LiveRecord]) {
    let published = ctx.published();
    // In send order, so each subscription scans only what was sent while it
    // was live.
    let mut accepted: Vec<(&String, &Published)> = published
        .iter()
        .filter(|(_, p)| p.accepted == Some(true))
        .collect();
    accepted.sort_by_key(|(_, p)| p.sent);
    let mut stats = ctx.stats();
    for record in records {
        let delivery = if record.class.starts_with("marmot") {
            "delivery.marmot"
        } else {
            "delivery.outbox"
        };
        let first = accepted.partition_point(|(_, p)| p.sent <= record.eose);
        for &(id, p) in &accepted[first..] {
            if p.sent > record.required_until {
                break;
            }
            if !record.matchers.iter().any(|m| m.matches(&p.event))
                || !ctx.policy.visible(&p.event, &record.identities)
            {
                continue;
            }
            stats.class(delivery).sent += 1;
            match record.delivered.get(id) {
                Some(at) => {
                    let row = stats.class(delivery);
                    row.completed += 1;
                    record_us(&mut row.done, micros(at.saturating_duration_since(p.due)));
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
                        "{} {}: live event {id} {what} (sent {} ms, OK {} ms, EOSE {} ms, required until {} ms)",
                        record.label,
                        record.sid,
                        at(p.sent),
                        p.acked.map_or_else(|| "-".into(), |t| at(t).to_string()),
                        at(record.eose),
                        at(record.required_until),
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
    let arrivals = if o.arrival_rate > 0.0 {
        let stay = match o.session_secs {
            0 => "staying to the end".to_owned(),
            secs => format!("{secs} s each"),
        };
        format!(
            "{} sessions arriving at {}/s, {stay}",
            report.sessions, o.arrival_rate
        )
    } else {
        format!("{} sessions, all at the start", report.sessions)
    };
    let mut s = format!(
        "\n## clients: {relay} r{repetition}\n\nRelay config: {}. {} outbox clients (follow lists up to {}), {} Marmot clients × {} groups, {} invitees per add-member burst, {} s; {arrivals}; {} background publications/s ({} of {} due sent, {:.1}/s{}), {} client(s) per address, deflate {} ({} of {} connections negotiated it). Dataset: {} scenario + {} background events. Load-generator lag p99 {:.1} ms, max {:.1} ms.\n\n",
        report.relay_config,
        o.outbox_clients,
        o.max_follows,
        o.marmot_clients,
        o.marmot_groups,
        o.marmot_invitees,
        o.duration_secs,
        o.publish_rate,
        report.publish_sent,
        report.publish_due,
        report.publish_achieved_rate,
        if report.publish_rate_held() { "" } else { ", rate NOT held" },
        o.clients_per_address,
        if o.deflate { "offered" } else { "off" },
        report.deflate_negotiated,
        report.connections,
        report.scenario_events,
        report.background_events,
        report.lag_p99_ms,
        report.lag_max_ms,
    );
    for line in &report.config_overrides {
        s.push_str(&format!("- bench override: `{line}`\n"));
    }
    s.push_str(&format!(
        "\n{} subscriptions, {} refusals, {} relay disconnects, {} unanswered, {} silently truncated histories, {} NIP-42 round trips, {} missed and {} duplicate live deliveries, {} mismatches, {} errors. Largest commit {} B, largest Welcome wrap {} B.\n\n",
        report.subscriptions,
        report.refusals_total,
        report.disconnects_total,
        report.unanswered_total,
        report.truncated_total,
        report.auth_round_trips,
        report.missed_deliveries,
        report.duplicate_deliveries,
        report.mismatches,
        report.errors,
        report.largest_commit_bytes,
        report.largest_welcome_bytes,
    ));
    s.push_str("First = time to first EVENT (first NEG-MSG for `marmot.neg`). Done = time to EOSE, NEG completion, OK, burst completion, or publish-to-delivery for `delivery.*`, from when each was due; an unanswered request counts until its session stopped reading.\n\n");
    s.push_str("| class | sent | done | refused | unanswered | truncated | events | live | first p50 ms | first p99 ms | done p50 ms | done p99 ms | done max ms |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in &report.classes {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |\n",
            row.class,
            row.sent,
            row.completed,
            row.refused,
            row.unanswered,
            row.truncated,
            row.events,
            row.live_events,
            row.first_p50_ms,
            row.first_p99_ms,
            row.done_p50_ms,
            row.done_p99_ms,
            row.done_max_ms,
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
    if !report.disconnects.is_empty() {
        s.push_str("\n| relay disconnect | count | connections |\n|---|---:|---|\n");
        for row in &report.disconnects {
            let roles: Vec<String> = row.roles.iter().map(|(r, n)| format!("{r} {n}")).collect();
            s.push_str(&format!(
                "| `{}` | {} | {} |\n",
                row.reason.replace('|', "\\|"),
                row.count,
                roles.join(", ")
            ));
        }
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
                due: Instant::now(),
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
                due: Instant::now(),
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

    /// A run's shared state for `plan`, against `corpus`, ending in `secs`.
    fn test_ctx(
        addr: SocketAddr,
        plan: Plan,
        corpus: Vec<Value>,
        opts: ClientsOptions,
        secs: u64,
    ) -> Arc<Ctx> {
        let start = Instant::now();
        let end = start + Duration::from_secs(secs);
        Arc::new(Ctx {
            addr,
            service_url: format!("ws://{addr}"),
            opts,
            nodelay: true,
            plan: Arc::new(plan),
            oracle: Oracle::new(corpus),
            policy: open_policy(),
            caps: NO_CAPS,
            published: Mutex::new(HashMap::new()),
            conns: Mutex::new(Vec::new()),
            stats: Mutex::new(Stats::default()),
            start,
            end,
            drain_end: end + DRAIN,
        })
    }

    /// A session over channels instead of a socket, against `corpus`.
    fn offline_session(corpus: Vec<Value>, groups: Vec<Group>, keys: Option<Keypair>) -> Session {
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
        let addr = SocketAddr::from(([127, 0, 0, 1], 9));
        let ctx = test_ctx(addr, plan, corpus, small_options(), 60);
        let (out, _) = mpsc::unbounded_channel();
        let (_, inbound) = mpsc::unbounded_channel();
        let conn = WsConn {
            out,
            inbound,
            deflate: false,
            written: Arc::default(),
            writer: None,
        };
        let until = ctx.end;
        Session::new(&ctx, "test".into(), "outbox", conn, keys, 1, until)
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
                items: vec![(10, [1; 32])],
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

    #[test]
    fn arrivals_interleave_clients_and_cycle_at_the_rate() {
        use User::{Marmot, Outbox};
        let opts = ClientsOptions {
            outbox_clients: 3,
            marmot_clients: 1,
            duration_secs: 4,
            ..small_options()
        };
        let at_once = arrivals(&opts);
        let users: Vec<User> = at_once.iter().map(|a| a.user).collect();
        assert_eq!(users, [Outbox(0), Outbox(1), Marmot(0), Outbox(2)]);
        assert!(at_once
            .iter()
            .all(|a| a.due == Duration::ZERO && a.session == 0));

        // Sessions that last to the end: each client arrives once.
        let once = arrivals(&ClientsOptions {
            arrival_rate: 2.0,
            ..opts.clone()
        });
        let dues: Vec<f64> = once.iter().map(|a| a.due.as_secs_f64()).collect();
        assert_eq!(dues, [0.0, 0.5, 1.0, 1.5]);

        // Shorter sessions: the clients come back in turn until the run ends.
        let cycling = arrivals(&ClientsOptions {
            arrival_rate: 2.0,
            session_secs: 1,
            ..opts.clone()
        });
        assert_eq!(cycling.len(), 8);
        assert_eq!(
            cycling[7],
            Arrival {
                due: Duration::from_millis(3_500),
                user: Outbox(2),
                session: 1,
            }
        );
        let cycled: Vec<User> = cycling.iter().map(|a| a.user).collect();
        assert_eq!(cycled[..4], users[..]);

        // A client may not come back before its last session stopped reading.
        let overlapping = ClientsOptions {
            arrival_rate: 2.0,
            session_secs: 1,
            ..opts.clone()
        };
        assert!(overlapping.validate().is_err());
        let fits = ClientsOptions {
            arrival_rate: 1.0,
            session_secs: 2,
            ..opts.clone()
        };
        fits.validate().unwrap();
        for bad in [
            ClientsOptions {
                session_secs: 2,
                ..opts.clone()
            },
            ClientsOptions {
                arrival_rate: f64::NAN,
                ..opts.clone()
            },
            ClientsOptions {
                publish_rate: -1.0,
                ..opts.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn filters_name_ids_and_authors_in_full() {
        let plan = Plan::generate(&small_options(), 7, 1_800_000_000);
        let mut filters: Vec<Value> = Vec::new();
        for user in &plan.outbox {
            filters.extend(
                outbox_startup(user, plan.anchor)
                    .into_iter()
                    .flat_map(|sub| sub.3),
            );
            filters.push(scroll_filter(user, plan.anchor));
            filters.extend((0..user.rotation.len()).map(|k| rotation_filter(user, k)));
        }
        // What the Marmot clients ask for, by the values they ask with.
        for user in &plan.marmot {
            filters.extend(user.directory.iter().map(|batch| json!({"authors": batch})));
            filters.push(json!({"#p": [user.pubkey], "authors": user.invitees}));
        }
        filters.extend(plan.groups.iter().map(|group| json!({"#h": [group.gid]})));
        let full = |value: &Value| {
            value
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        };
        let mut checked = 0;
        for filter in &filters {
            for key in ["ids", "authors", "#e", "#p", "#h"] {
                if let Some(values) = filter.get(key) {
                    let values = values.as_array().unwrap();
                    assert!(
                        !values.is_empty() && values.iter().all(full),
                        "{key} in {filter}"
                    );
                    checked += values.len();
                }
            }
        }
        assert!(checked > 1_000, "{checked}");
    }

    #[test]
    fn close_reasons_and_target_urls() {
        let close = |code: u16, reason: &str| {
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend(reason.as_bytes());
            close_reason(&payload)
        };
        assert_eq!(close(1013, "overloaded"), "close 1013: overloaded");
        assert_eq!(
            close(1008, "slow reader: 4096 messages"),
            "close 1008: slow reader: N messages"
        );
        assert_eq!(close(1001, " "), "close 1001");
        assert_eq!(close_reason(&[]), "close without a status");

        assert_eq!(
            target_addr("ws://127.0.0.1:7777").unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 7777))
        );
        assert_eq!(
            target_addr("ws://127.0.0.1:7777/").unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 7777))
        );
        assert_eq!(target_addr("ws://127.0.0.1").unwrap().port(), 80);
        assert_eq!(target_addr("ws://[::1]:7777").unwrap().port(), 7777);
        for bad in [
            "wss://127.0.0.1:7777",
            "ws://127.0.0.1:7777/relay",
            "ws://",
            "127.0.0.1:7777",
        ] {
            assert!(target_addr(bad).is_err(), "{bad}");
        }

        let facts = RelayFacts::remote("ws://10.0.0.1:7777", &[4, 1059], 500, 0);
        assert_eq!(facts.service_url, "ws://10.0.0.1:7777");
        assert_eq!(facts.read.recipient_only, [4, 1059]);
        assert_eq!(facts.limits["target.max_filter_limit"], "500");
        let caps = Caps::new(facts.max_filter_limit, facts.max_events_per_req);
        assert_eq!((caps.filter, caps.req), (500, u64::MAX));
    }

    #[test]
    fn a_relay_disconnect_is_a_result_and_ends_what_is_required() {
        let note = event("n", 100, 1, json!([]));
        for disconnect in [false, true] {
            let mut s = offline_session(vec![note.clone()], Vec::new(), None);
            let ctx = s.ctx.clone();
            s.req(
                "l0",
                "live.home_feed",
                Mode::Live,
                vec![json!({"kinds":[1]})],
            );
            s.req(
                "f0",
                "w3.feed_page",
                Mode::FetchClose,
                vec![json!({"kinds":[1]})],
            );
            let at = Instant::now();
            s.on_message(at, json!(["EVENT", "l0", note.clone()]));
            s.on_message(at, json!(["EOSE", "l0"]));
            if disconnect {
                s.on_inbound(Some(In::Gone("close 1013: overloaded".into())));
            }
            let gone = s.gone_at;
            let until = s.until;
            let records = s.finish();
            let mut stats = ctx.stats();
            assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
            assert_eq!(stats.mismatches, 0, "{:?}", stats.mismatch_samples);
            assert_eq!(records.len(), 1);
            if disconnect {
                assert_eq!(stats.disconnects["close 1013: overloaded"]["outbox"], 1);
                assert_eq!(
                    stats.class("w3.feed_page").unanswered,
                    0,
                    "the relay ended the request, so it is not unanswered"
                );
                let gone = gone.unwrap();
                assert_eq!(
                    records[0].required_until,
                    gone.checked_sub(DRAIN).unwrap_or(gone)
                );
            } else {
                assert!(stats.disconnects.is_empty());
                assert_eq!(stats.class("w3.feed_page").unanswered, 1);
                assert_eq!(stats.class("live.home_feed").unanswered, 0);
                assert_eq!(records[0].required_until, until);
            }
        }
    }

    #[test]
    fn deliveries_are_required_once_while_the_subscription_is_live() {
        let mut s = offline_session(Vec::new(), Vec::new(), None);
        let ctx = s.ctx.clone();
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let note = |id: &str| event(id, 1, 1, json!([]));
        for (id, sent) in [("early", 0), ("got", 200), ("lost", 300), ("late", 900)] {
            ctx.published().insert(
                id.into(),
                Published {
                    event: note(id),
                    due: at(sent)
                        .checked_sub(Duration::from_millis(10))
                        .unwrap_or(t0),
                    sent: at(sent),
                    accepted: Some(true),
                    acked: Some(at(sent + 5)),
                },
            );
        }
        // A second copy of a live event is a duplicate delivery.
        s.req(
            "l0",
            "live.home_feed",
            Mode::Live,
            vec![json!({"kinds":[1]})],
        );
        s.on_message(at(100), json!(["EOSE", "l0"]));
        s.on_message(at(250), json!(["EVENT", "l0", note("got")]));
        s.on_message(at(260), json!(["EVENT", "l0", note("got")]));
        {
            let stats = ctx.stats();
            assert_eq!(stats.duplicate_deliveries, 1);
            assert_eq!(stats.mismatches, 1, "{:?}", stats.mismatch_samples);
        }
        let mut record = s.finish().pop().unwrap();
        record.required_until = at(500);
        ctx.stats().mismatches = 0;
        check_deliveries(&ctx, &[record]);
        let mut stats = ctx.stats();
        // "early" went out before EOSE and "late" after the window closed.
        assert_eq!(stats.missed_deliveries, 1);
        let row = stats.class("delivery.outbox");
        assert_eq!((row.sent, row.completed), (2, 1));
        assert!(
            row.done.equivalent(row.done.max(), 60_000),
            "latency counts from the due time"
        );
        assert!(
            stats
                .mismatch_samples
                .iter()
                .any(|m| m.contains("live event lost was never delivered")),
            "{:?}",
            stats.mismatch_samples
        );
    }

    const UPGRADE: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

    /// A relay that answers every WebSocket handshake with `response`, then
    /// closes its side, or with `hold` keeps the connection open and never
    /// reads from it again.
    async fn scripted_relay(response: Vec<u8>, hold: bool) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let response = response.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let _ = stream.write_all(&response).await;
                    if hold {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn refusals_and_disconnects_come_back_with_the_relays_reason() {
        let mut closing = UPGRADE.to_vec();
        closing.extend([0x88, 12]);
        closing.extend(1013u16.to_be_bytes());
        closing.extend(b"overloaded");
        for (response, expected) in [
            (closing, "close 1013: overloaded"),
            (UPGRADE.to_vec(), "closed without a close frame"),
        ] {
            let addr = scripted_relay(response, false).await;
            let Ok(mut conn) = ws_connect(addr, None, false, true).await else {
                panic!("handshake with the scripted relay failed");
            };
            match conn.inbound.recv().await {
                Some(In::Gone(reason)) => assert_eq!(reason, expected),
                _ => panic!("expected the connection to end with {expected}"),
            }
        }
        for (response, expected) in [
            (
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                "HTTP 503",
            ),
            (
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 11\r\n\r\nslow down\r\n",
                "slow down",
            ),
            // Any status but 101 is the relay declining; a page is no reason.
            (
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 26\r\n\r\n<html>\n<p>denied</p>\n</html>",
                "HTTP 403",
            ),
        ] {
            let addr = scripted_relay(response.as_bytes().to_vec(), false).await;
            match ws_connect(addr, None, false, true).await {
                Err(ConnectFailure::Refused(reason)) => assert_eq!(reason, expected),
                Err(other) => panic!("not a refusal: {other}"),
                Ok(_) => panic!("{response} upgraded"),
            }
        }
        let addr = scripted_relay(b"SSH-2.0-OpenSSH\r\n\r\n".to_vec(), false).await;
        assert!(matches!(
            ws_connect(addr, None, false, true).await,
            Err(ConnectFailure::Invalid(_))
        ));
    }

    #[test]
    fn io_failures_are_the_relays_unless_the_load_host_ran_out() {
        use std::io::{Error, ErrorKind};
        for relay in [
            Error::from(ErrorKind::ConnectionRefused),
            Error::from(ErrorKind::ConnectionReset),
            Error::from(ErrorKind::BrokenPipe),
            Error::from(ErrorKind::TimedOut),
            Error::from(ErrorKind::HostUnreachable),
        ] {
            let kind = relay.kind();
            assert!(
                matches!(io_failure("x", relay), ConnectFailure::Refused(_)),
                "{kind:?}"
            );
        }
        for local in [
            Error::from(ErrorKind::AddrNotAvailable),
            Error::from(ErrorKind::PermissionDenied),
            Error::from_raw_os_error(24),
        ] {
            let shown = local.to_string();
            assert!(
                matches!(io_failure("x", local), ConnectFailure::Failed(_)),
                "{shown}"
            );
        }
    }

    /// Once a session's visit is over it gives the relay nothing new: no
    /// REQ, publication, NIP-77 pass, burst or AUTH, and none is counted.
    #[test]
    fn a_session_whose_visit_is_over_starts_nothing() {
        let keys = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(6));
        let groups = vec![Group {
            gid: "ab".repeat(32),
            members: vec![0],
        }];
        let mut s = offline_session(Vec::new(), groups, Some(keys));
        s.challenge = Some("c".into());
        s.until = Instant::now();
        s.req(
            "l0",
            "live.home_feed",
            Mode::Live,
            vec![json!({"kinds":[1]})],
        );
        let now = Instant::now();
        assert!(!s.req_due(
            "r0",
            "w6.scroll_replace",
            Mode::Replace,
            vec![json!({"kinds":[1]})],
            now
        ));
        assert!(!s.publish(
            event("e", 1, 1, json!([])),
            "publish.background",
            false,
            now
        ));
        s.open_neg("n0", 0, &[]);
        s.send_burst(
            now,
            event("c", 1, 445, json!([])),
            vec![event("w", 1, 1059, json!([]))],
        );
        assert!(!s.start_auth());
        assert!(s.subs.is_empty() && s.pending.is_empty() && s.negs.is_empty());
        assert!(s.ctx.published().is_empty());
        let stats = s.ctx.stats();
        assert!(
            stats.classes.values().all(|c| c.sent == 0),
            "{:?}",
            stats.classes.keys()
        );
    }

    /// AUTH accepted after the visit ended: what it was for is not sent
    /// again and stays refused, by the relay's reason.
    #[test]
    fn what_waited_on_an_auth_answered_after_the_visit_stays_refused() {
        let keys = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(7));
        let mut s = offline_session(Vec::new(), Vec::new(), Some(keys));
        s.challenge = Some("c".into());
        s.req(
            "l2",
            "live.dm_nip04",
            Mode::Live,
            vec![json!({"kinds":[4],"#p":["bob"]})],
        );
        let dm_refused = "auth-required: requested filter requires authentication";
        s.on_message(Instant::now(), json!(["CLOSED", "l2", dm_refused]));
        assert!(s.publish(
            event("e", 1, 1, json!([])),
            "publish.marmot_commit",
            true,
            Instant::now()
        ));
        let event_refused = "auth-required: publishing requires authentication";
        s.on_message(Instant::now(), json!(["OK", "e", false, event_refused]));
        let Auth::Pending(auth_id, _) = &s.auth else {
            panic!("the client answers with AUTH");
        };
        let auth_id = auth_id.clone();
        s.until = Instant::now();
        s.on_message(Instant::now(), json!(["OK", auth_id, true, ""]));
        assert!(s.subs["l2"].refused, "the REQ was not sent again");
        assert!(s.pending.is_empty(), "the publication was not sent again");
        let stats = s.ctx.stats();
        assert_eq!(stats.refusals[dm_refused]["live.dm_nip04"], 1);
        assert_eq!(stats.refusals[event_refused]["publish.marmot_commit"], 1);
    }

    /// A `rate-limited:` retry that would fall after the visit is not
    /// scheduled, and a NIP-77 pass Wok closes for a late AUTH after the
    /// visit is not opened again: both stay refused.
    #[test]
    fn retries_the_visits_end_overtakes_are_not_made() {
        let groups = vec![Group {
            gid: "ab".repeat(32),
            members: vec![0],
        }];
        let mut s = offline_session(Vec::new(), groups, None);
        s.open_neg("n0", 0, &[(10, [1; 32])]);
        s.until = Instant::now() + Duration::from_millis(100);
        assert!(s.publish(
            event("e", 1, 1, json!([])),
            "publish.marmot_commit",
            true,
            Instant::now()
        ));
        s.on_message(
            Instant::now(),
            json!(["OK", "e", false, "rate-limited: slow down"]),
        );
        assert!(s.retries.is_empty() && s.pending.is_empty());
        s.until = Instant::now();
        let reset = "closed: authentication changed; reopen synchronization";
        s.on_message(Instant::now(), json!(["NEG-ERR", "n0", reset]));
        assert!(s.negs.is_empty(), "the pass was not opened again");
        let mut stats = s.ctx.stats();
        assert_eq!(
            stats.refusals["rate-limited: slow down"]["publish.marmot_commit"],
            1
        );
        let neg = stats.class("marmot.neg");
        assert_eq!((neg.sent, neg.refused), (1, 1));
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
            arrival_rate: 0.0,
            session_secs: 0,
        }
    }

    /// An in-process relay with default limits, abuse controls and AUTH on,
    /// holding `events`, as `configure` leaves it.
    async fn spawn_relay(
        dir: &Path,
        events: &[Value],
        configure: impl FnOnce(&mut wok_relay::Config),
    ) -> (SocketAddr, wok_relay::RelayHandle, wok_relay::Config) {
        let env = wok_db::Env::open(dir, wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        {
            let mut batch: Vec<_> = events
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
            db: dir.to_path_buf(),
            ..Default::default()
        };
        cfg.relay.port = addr.port();
        cfg.relay.real_ip_header = FORWARDED_HEADER.into();
        cfg.relay.auth.service_url = format!("ws://{addr}");
        configure(&mut cfg);
        let handle = wok_relay::start(env, cfg.clone()).unwrap();
        let server = handle.clone();
        tokio::spawn(async move {
            let _ = wok_ws::serve_listener(server, listener).await;
        });
        (addr, handle, cfg)
    }

    /// The CI-sized version of the scenario, against an in-process relay with
    /// default limits, abuse controls and AUTH on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn small_run_against_default_limits_is_correct_and_counts_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let opts = small_options();
        let anchor = unix_now() - 5;
        let plan = Plan::generate(&opts, 11, anchor);
        let (addr, handle, cfg) = spawn_relay(dir.path(), &plan.events, |_| {}).await;
        let (report, _) = run(RunInput {
            addr,
            plan,
            background: Vec::new(),
            facts: RelayFacts::from_config(&cfg),
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

    /// Remote mode against a relay the run knows only by URL and the
    /// `--target-*` facts: clients come and go at a fixed rate, and a second
    /// run into the same database is refused until it is restored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn remote_run_at_a_fixed_arrival_rate() {
        let dir = tempfile::tempdir().unwrap();
        let opts = ClientsOptions {
            outbox_clients: 3,
            marmot_clients: 1,
            arrival_rate: 1.0,
            session_secs: 2,
            duration_secs: 7,
            ..small_options()
        };
        let anchor = unix_now() - 5;
        let plan = Plan::generate(&opts, 13, anchor);
        let author = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(9));
        let note = |i: u64| {
            signed(
                &author,
                anchor - 100 + i,
                1,
                Vec::new(),
                format!("note {i}"),
            )
        };
        let background: Vec<Value> = (0..4).map(note).collect();
        let mut stored = plan.events.clone();
        stored.extend(background.iter().cloned());
        let (addr, handle, cfg) = spawn_relay(dir.path(), &stored, |_| {}).await;
        let url = format!("ws://{addr}");
        let facts = || {
            RelayFacts::remote(
                &url,
                &cfg.relay.auth.recipient_only_kinds,
                cfg.relay.max_filter_limit,
                cfg.relay.max_total_events_per_req,
            )
        };
        let input = |plan: Plan, background: Vec<Value>| RunInput {
            addr: target_addr(&url).unwrap(),
            plan,
            background,
            facts: facts(),
            relay_config: format!("remote target {url}"),
            config_overrides: Vec::new(),
            opts: opts.clone(),
            nodelay: true,
        };
        let plan_again = || Plan::generate(&opts, 13, anchor);

        // A relay without the whole corpus is refused before the clock starts.
        let mut unknown = background.clone();
        unknown.push(note(50));
        let refused = run(input(plan_again(), unknown))
            .await
            .expect_err("missing corpus");
        assert!(refused.to_string().contains("lacks 1 of"), "{refused}");

        let (report, _) = run(input(plan, background.clone())).await.unwrap();
        assert_eq!(report.mismatches, 0, "{:#?}", report.mismatch_samples);
        assert_eq!(report.errors, 0, "{:#?}", report.error_samples);
        assert!(report.ok(), "{report:#?}");
        assert_eq!(report.background_events, 4);
        // Seven arrivals over 7 s: every client, then the first three again.
        assert_eq!(report.sessions, 7);
        assert_eq!(report.disconnects_total, 0, "{:#?}", report.disconnects);
        assert_eq!(report.duplicate_deliveries, 0);
        assert!(
            report.publish_due > 0 && report.publish_rate_held(),
            "{report:#?}"
        );
        let row = |class: &str| report.classes.iter().find(|r| r.class == class).cloned();
        assert!(row("delivery.outbox").is_some_and(|r| r.completed > 0));
        assert!(row("marmot.burst").is_some_and(|r| r.completed == 1));
        assert!(report.limits.contains_key("target.max_filter_limit"));

        // The gate: a disconnect fails only a run that expects none, and a
        // publisher that fell behind fails any run.
        let mut strict = report.clone();
        strict.disconnects_total = 1;
        assert!(strict.ok());
        strict.options.expect_no_refusals = true;
        assert!(!strict.ok());
        let mut behind = report.clone();
        behind.publish_achieved_rate = 0.9 * behind.publish_due as f64 / opts.duration_secs as f64;
        assert!(!behind.publish_rate_held() && !behind.ok());

        // The database now holds this run's publications.
        let refused = run(input(plan_again(), background))
            .await
            .expect_err("a used database is refused");
        assert!(
            refused.to_string().contains("restore it first"),
            "{refused}"
        );
        handle.request_shutdown();
    }
    #[tokio::test]
    async fn a_publication_is_sent_once_written_and_a_stalled_write_ends_the_connection() {
        let addr = scripted_relay(UPGRADE.to_vec(), true).await;
        let Ok(mut conn) = ws_connect(addr, None, false, true).await else {
            panic!("handshake with the scripted relay failed");
        };
        // Far more than the socket buffers hold.
        let frame = format!(r#"["EVENT",{{"content":"{}"}}]"#, "x".repeat(64 << 10));
        for i in 0..1_024 {
            let _ = conn.out.send(Out::Event(i.to_string(), frame.clone()));
        }
        let ended = tokio::time::timeout(WRITE_STALL * 2, conn.inbound.recv()).await;
        match ended {
            Ok(Some(In::Gone(reason))) => {
                assert!(reason.starts_with("write stalled"), "{reason}")
            }
            _ => panic!("a relay that stops reading must end the connection"),
        }
        let written = conn.written.lock().unwrap().events;
        assert!(written > 0 && written < 1_024, "{written} written");
        // The connection is reset, so the reader stops too.
        let reader = tokio::time::timeout(Duration::from_secs(2), conn.inbound.recv()).await;
        assert!(matches!(reader, Ok(None)), "the reader is still waiting");
    }

    /// An outbox client against a relay whose first EOSE for `r0` comes late:
    /// the re-REQs due meanwhile wait, keep their due times and all go out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replacements_due_behind_a_slow_req_keep_their_schedule() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let late = Duration::from_millis(900);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut sink, mut stream) = ws.split();
            let mut held: Option<(tokio::time::Instant, String)> = None;
            let mut first = true;
            loop {
                let wake = held.as_ref().map(|(at, _)| *at);
                tokio::select! {
                    message = stream.next() => {
                        let Some(Ok(Message::Text(text))) = message else { break };
                        let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                        if frame[0] != "REQ" {
                            continue;
                        }
                        let eose = json!(["EOSE", frame[1]]).to_string();
                        if frame[1] == "r0" && std::mem::take(&mut first) {
                            held = Some((tokio::time::Instant::now() + late, eose));
                        } else if sink.send(Message::Text(eose.into())).await.is_err() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep_until(wake.unwrap_or_else(tokio::time::Instant::now)), if wake.is_some() => {
                        let (_, eose) = held.take().unwrap();
                        let _ = sink.send(Message::Text(eose.into())).await;
                    }
                }
            }
        });
        let opts = ClientsOptions {
            outbox_clients: 1,
            marmot_clients: 0,
            replace_interval_ms: 250,
            deflate: false,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 3, 1_800_000_000);
        let ctx = test_ctx(addr, plan, Vec::new(), opts, 60);
        let due = Instant::now();
        // Re-REQs are due at 0.25, 0.5, ... 1.5 s: six per subscription.
        let visit = Visit {
            session: 0,
            due,
            until: due + Duration::from_millis(1_600),
        };
        outbox_client(ctx.clone(), 0, visit).await;
        let mut stats = ctx.stats();
        assert_eq!(stats.mismatches, 0, "{:?}", stats.mismatch_samples);
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        let scroll = stats.class("w6.scroll_replace");
        assert_eq!(scroll.sent, 3 + 3 * 6, "every scheduled re-REQ goes out");
        assert_eq!(scroll.completed, scroll.sent);
        assert_eq!(scroll.unanswered, 0);
        // The 0.25 s re-REQ of r0 waited for the 0.9 s EOSE.
        assert!(
            scroll.done.max() >= 600_000,
            "latency counts from the due time: {} us",
            scroll.done.max()
        );
        let rotation = stats.class("w6.profile_replace");
        assert_eq!(rotation.sent, 2 + 2 * 6);
    }
    #[test]
    fn a_pass_closed_by_a_late_auth_is_opened_again() {
        let groups = vec![Group {
            gid: "ab".repeat(32),
            members: vec![0],
        }];
        let mut s = offline_session(Vec::new(), groups, None);
        s.open_neg("n0", 0, &[(10, [1; 32])]);
        let started = s.negs["n0"].started;
        let reset = "closed: authentication changed; reopen synchronization";
        s.on_message(Instant::now(), json!(["NEG-ERR", "n0", reset]));
        // The client had already closed this one.
        s.on_message(Instant::now(), json!(["NEG-ERR", "n1", reset]));
        assert_eq!(s.negs["n0"].started, started, "timed from the first open");
        let mut stats = s.ctx.stats();
        assert_eq!(stats.mismatches, 0, "{:?}", stats.mismatch_samples);
        let row = stats.class("marmot.neg");
        assert_eq!((row.sent, row.refused), (1, 0));
    }

    /// Engine mode: a relay that never challenges still has the Marmot
    /// receiver subscribed before its group's burst, so the commit is a
    /// live delivery there too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_is_delivered_live_on_a_relay_that_never_challenges() {
        let dir = tempfile::tempdir().unwrap();
        let opts = ClientsOptions {
            outbox_clients: 0,
            marmot_clients: 1,
            marmot_groups: 2,
            duration_secs: 4,
            publish_rate: 0.0,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 17, unix_now() - 5);
        let (addr, handle, cfg) = spawn_relay(dir.path(), &plan.events, |cfg| {
            cfg.relay.auth.enabled = false;
            cfg.relay.auth.recipient_only_kinds.clear();
        })
        .await;
        let (report, _) = run(RunInput {
            addr,
            plan,
            background: Vec::new(),
            facts: RelayFacts::from_config(&cfg),
            relay_config: "AUTH off".into(),
            config_overrides: Vec::new(),
            opts,
            nodelay: true,
        })
        .await
        .unwrap();
        handle.request_shutdown();
        assert_eq!(report.mismatches, 0, "{:#?}", report.mismatch_samples);
        assert_eq!(report.errors, 0, "{:#?}", report.error_samples);
        assert_eq!(report.auth_round_trips, 0);
        let delivery = report
            .classes
            .iter()
            .find(|row| row.class == "delivery.marmot")
            .unwrap_or_else(|| panic!("no live Marmot deliveries: {:#?}", report.classes));
        assert!(
            delivery.sent > 0 && delivery.completed == delivery.sent,
            "{delivery:#?}"
        );
    }

    /// A relay that refuses the publisher with HTTP 503 for 3 s, then drops
    /// it and takes a second to accept it again: the publisher keeps
    /// dialing, and the slots due meanwhile are not sent in a burst once it
    /// is back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconnected_publisher_resumes_its_schedule_without_a_burst() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let gap = Duration::from_secs(1);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = received.clone();
        tokio::spawn(async move {
            for connection in 0.. {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                if connection < 3 {
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let refusal = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                    let _ = stream.write_all(refusal.as_bytes()).await;
                    continue;
                }
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut events = 0;
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                    log.lock().unwrap().push(Instant::now());
                    let ok = json!(["OK", frame[1]["id"], true, ""]).to_string();
                    let _ = ws.send(Message::Text(ok.into())).await;
                    events += 1;
                    if connection == 3 && events == 5 {
                        let _ = ws.close(None).await;
                        tokio::time::sleep(gap).await;
                        break;
                    }
                }
            }
        });
        let opts = ClientsOptions {
            outbox_clients: 1,
            marmot_clients: 0,
            publish_rate: 10.0,
            publishers: 1,
            deflate: false,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 19, unix_now() - 5);
        let ctx = test_ctx(addr, plan, Vec::new(), opts, 6);
        background_publisher(ctx.clone(), 0).await;
        settle_writes(&ctx, ctx.drain_end).await;
        let stats = ctx.stats();
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        assert_eq!(stats.refusals["HTTP N"]["connect"], 3);
        assert_eq!(stats.publish_due, 60);
        assert_eq!(stats.publish_sent, received.lock().unwrap().len() as u64);
        // About 3 s lost to refusals and 1 s to the reconnect; the rest is
        // still offered.
        assert!(stats.publish_sent >= 15, "{} sent", stats.publish_sent);
        assert!(
            stats.publish_sent + 25 <= stats.publish_due,
            "{} of {} sent: the gap's slots were flushed",
            stats.publish_sent,
            stats.publish_due
        );
        let times = received.lock().unwrap();
        assert!(
            times
                .windows(3)
                .all(|w| w[2] - w[0] >= Duration::from_millis(100)),
            "no three publications within 100 ms"
        );
    }
    #[tokio::test]
    async fn a_connect_the_relay_has_not_taken_by_the_visits_end_is_unanswered() {
        // Listening, so TCP connects, but never upgrading.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let plan = Plan::generate(&small_options(), 3, 1_800_000_000);
        let ctx = test_ctx(addr, plan, Vec::new(), small_options(), 60);
        let due = Instant::now();
        let visit = Visit {
            session: 0,
            due,
            until: due + Duration::from_millis(300),
        };
        let session = Session::connect(&ctx, "late".into(), "outbox", None, None, 1, visit).await;
        assert!(session.is_none(), "nothing starts after the visit ended");
        assert!(
            due.elapsed() < Duration::from_secs(2),
            "{:?}",
            due.elapsed()
        );
        let mut stats = ctx.stats();
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        let connect = stats.class("connect");
        assert_eq!((connect.sent, connect.unanswered), (1, 1));
        drop(listener);
    }

    #[tokio::test]
    async fn a_publication_counts_as_sent_when_written_not_when_queued() {
        let mut s = offline_session(Vec::new(), Vec::new(), None);
        let ctx = s.ctx.clone();
        let note = event("w", 1, 1, json!([]));
        let queued = Instant::now();
        s.publish(note.clone(), "publish.background", false, queued);
        let written = queued + Duration::from_millis(500);
        s.conn
            .written
            .lock()
            .unwrap()
            .at
            .insert("w".into(), written);
        ctx.published().get_mut("w").unwrap().accepted = Some(true);
        let record = LiveRecord {
            label: "receiver".into(),
            sid: "l0".into(),
            class: "live.home_feed",
            matchers: vec![Matcher::new(&json!({"kinds":[1]}))],
            identities: Vec::new(),
            eose: queued + Duration::from_millis(100),
            required_until: queued + Duration::from_secs(5),
            delivered: HashMap::new(),
            seen: HashSet::new(),
        };
        ctx.conns.lock().unwrap().push(ConnLog {
            role: "publisher",
            written: s.conn.written.clone(),
            writer: None,
        });
        s.finish();
        settle_writes(&ctx, Instant::now()).await;
        assert_eq!(ctx.published()["w"].sent, written);
        // Written after the subscription's EOSE, so it had to arrive live.
        check_deliveries(&ctx, &[record]);
        assert_eq!(ctx.stats().missed_deliveries, 1);
    }
    #[tokio::test]
    async fn writers_stopped_at_the_deadline_send_nothing_more() {
        let addr = scripted_relay(UPGRADE.to_vec(), true).await;
        let frame = format!(r#"["EVENT",{{"content":"{}"}}]"#, "x".repeat(64 << 10));
        let mut conns = Vec::new();
        for _ in 0..2 {
            let Ok(conn) = ws_connect(addr, None, false, true).await else {
                panic!("handshake with the scripted relay failed");
            };
            for i in 0..1_024 {
                let _ = conn.out.send(Out::Event(i.to_string(), frame.clone()));
            }
            conns.push(conn);
        }
        // The first is closing behind its backlog, as a finished session is.
        let _ = conns[0].out.send(Out::Close);
        let started = Instant::now();
        let writers = conns.iter_mut().filter_map(|c| c.writer.take()).collect();
        stop_writers(writers, started + Duration::from_millis(300)).await;
        assert!(started.elapsed() < WRITE_STALL, "{:?}", started.elapsed());
        let written: Vec<u64> = conns
            .iter()
            .map(|c| c.written.lock().unwrap().events)
            .collect();
        tokio::time::sleep(Duration::from_millis(300)).await;
        for (conn, written) in conns.iter_mut().zip(written) {
            assert_eq!(conn.written.lock().unwrap().events, written);
            let reader = tokio::time::timeout(Duration::from_secs(2), conn.inbound.recv()).await;
            assert!(matches!(reader, Ok(None)), "the reader is still waiting");
        }
    }

    /// A publication sent again after a refusal is timed by its last
    /// write, the copy the relay accepted, and still counts once.
    #[tokio::test]
    async fn a_resent_publication_is_timed_by_its_last_write() {
        let addr = scripted_relay(UPGRADE.to_vec(), true).await;
        let Ok(conn) = ws_connect(addr, None, false, true).await else {
            panic!("handshake with the scripted relay failed");
        };
        let frame = r#"["EVENT",{}]"#.to_owned();
        let _ = conn.out.send(Out::Event("a".into(), frame.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let resent = Instant::now();
        let _ = conn.out.send(Out::Event("a".into(), frame));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let written = conn.written.lock().unwrap();
        assert_eq!(written.events, 1);
        assert!(written.at["a"] >= resent);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_marmot_only_database_an_earlier_run_published_into_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let opts = ClientsOptions {
            outbox_clients: 0,
            marmot_clients: 1,
            publish_rate: 0.0,
            ..small_options()
        };
        let anchor = unix_now() - 5;
        let plan = Plan::generate(&opts, 23, anchor);
        // What a burst leaves behind: a commit into one of the groups.
        let keys = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(4));
        let gid = plan.groups[0].gid.clone();
        let commit = signed(&keys, anchor + 1, 445, vec![json!(["h", gid])], "c".into());
        let mut stored = plan.events.clone();
        stored.push(commit);
        let (addr, handle, _) = spawn_relay(dir.path(), &stored, |_| {}).await;
        let oracle = Oracle::new(plan.events.clone());
        let refused = check_target(addr, true, &plan, &oracle, plan.events.len())
            .await
            .expect_err("a used database is refused");
        assert!(
            refused.to_string().contains("restore it first"),
            "{refused}"
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_receiver_upgraded_just_before_its_visit_ends_subscribes_nothing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let _ = stream.write_all(UPGRADE).await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        let opts = ClientsOptions {
            outbox_clients: 0,
            marmot_clients: 1,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 29, 1_800_000_000);
        let ctx = test_ctx(addr, plan, Vec::new(), opts, 60);
        let due = Instant::now();
        // Upgraded at 150 ms; the challenge wait runs past the end.
        let visit = Visit {
            session: 0,
            due,
            until: due + Duration::from_millis(350),
        };
        marmot_receiver(ctx.clone(), 0, visit).await;
        let mut stats = ctx.stats();
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        assert_eq!(stats.class("connect").completed, 1);
        for class in ["marmot.inbox", "marmot.group_live", "marmot.neg"] {
            assert_eq!(stats.class(class).sent, 0, "{class}");
        }
    }

    /// A relay that drops the connection before answering, and one whose
    /// port is closed: refusals, dialled again until the visit ends.
    #[tokio::test]
    async fn a_connection_dropped_before_the_upgrade_is_refused_and_retried() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dropping = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        for addr in [dropping, closed] {
            let plan = Plan::generate(&small_options(), 3, 1_800_000_000);
            let ctx = test_ctx(addr, plan, Vec::new(), small_options(), 60);
            let due = Instant::now();
            let visit = Visit {
                session: 0,
                due,
                until: due + Duration::from_millis(2_500),
            };
            let session = Session::connect(&ctx, "s".into(), "outbox", None, None, 1, visit).await;
            assert!(session.is_none());
            let mut stats = ctx.stats();
            assert_eq!(stats.errors, 0, "{addr}: {:?}", stats.error_samples);
            let refused: u64 = stats
                .refusals
                .values()
                .filter_map(|r| r.get("connect"))
                .sum();
            assert!(refused >= 2, "{addr}: {:?}", stats.refusals);
            assert_eq!(stats.class("connect").refused, refused);
        }
        assert!(accepted.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }

    /// A relay that takes TCP connections but never upgrades them, for
    /// longer than the handshake's own timeout: a result, not an error.
    #[tokio::test]
    async fn a_handshake_that_times_out_is_unanswered_not_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let plan = Plan::generate(&small_options(), 3, 1_800_000_000);
        let ctx = test_ctx(addr, plan, Vec::new(), small_options(), 60);
        let due = Instant::now();
        let visit = Visit {
            session: 0,
            due,
            until: due + Duration::from_millis(10_500),
        };
        let session = Session::connect(&ctx, "slow".into(), "outbox", None, None, 1, visit).await;
        assert!(session.is_none());
        assert!(
            due.elapsed() < Duration::from_secs(12),
            "{:?}",
            due.elapsed()
        );
        let mut stats = ctx.stats();
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        let connect = stats.class("connect");
        assert_eq!((connect.sent, connect.unanswered), (2, 2));
    }
    /// A relay that challenges at once, serves the receiver's REQs as the
    /// account it is authenticating, and answers AUTH only after 300 ms:
    /// recipient-only history is not a leak.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_receiver_whose_auth_is_answered_late_sees_its_inbox_as_the_account() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let opts = ClientsOptions {
            outbox_clients: 0,
            marmot_clients: 1,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 31, 1_800_000_000);
        // A Welcome inside the receiver's `since`.
        let keys = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(5));
        let me = plan.marmot[0].pubkey.clone();
        let wrap = signed(
            &keys,
            plan.anchor - 1,
            1_059,
            vec![json!(["p", me])],
            "w".into(),
        );
        let wrap_id = wrap["id"].as_str().unwrap().to_owned();
        let mut stored = plan.events.clone();
        stored.push(wrap);
        let corpus = stored.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let challenge = json!(["AUTH", "c"]).to_string();
            let _ = ws.send(Message::Text(challenge.into())).await;
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                match frame[0].as_str() {
                    Some("AUTH") => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let ok = json!(["OK", frame[1]["id"], true, ""]).to_string();
                        let _ = ws.send(Message::Text(ok.into())).await;
                    }
                    Some("REQ") => {
                        let sid = frame[1].clone();
                        let matchers: Vec<Matcher> = frame.as_array().unwrap()[2..]
                            .iter()
                            .map(Matcher::new)
                            .collect();
                        for event in stored
                            .iter()
                            .filter(|e| matchers.iter().any(|m| m.matches(e)))
                        {
                            let reply = json!(["EVENT", sid, event]).to_string();
                            let _ = ws.send(Message::Text(reply.into())).await;
                        }
                        let eose = json!(["EOSE", sid]).to_string();
                        let _ = ws.send(Message::Text(eose.into())).await;
                    }
                    _ => {}
                }
            }
        });
        let ctx = test_ctx(addr, plan, corpus, opts, 60);
        let due = Instant::now();
        let visit = Visit {
            session: 0,
            due,
            until: due + Duration::from_secs(1),
        };
        let records = marmot_receiver(ctx.clone(), 0, visit).await;
        let mut stats = ctx.stats();
        assert_eq!(stats.mismatches, 0, "{:?}", stats.mismatch_samples);
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        assert_eq!(stats.class("auth").completed, 1);
        let inbox = stats.class("marmot.inbox");
        assert_eq!((inbox.sent, inbox.completed), (1, 1));
        let inbox = records.iter().find(|r| r.sid == "inbox").unwrap();
        assert!(inbox.seen.contains(&wrap_id), "the Welcome was not served");
    }

    /// A Marmot sender upgraded after its burst was due, with enough
    /// invitees that preparing the burst runs past the session's end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_prepared_past_the_sessions_end_is_not_sent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    tokio::time::sleep(Duration::from_millis(1_600)).await;
                    let _ = stream.write_all(UPGRADE).await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                });
            }
        });
        let opts = ClientsOptions {
            outbox_clients: 0,
            marmot_clients: 1,
            marmot_invitees: 150,
            ..small_options()
        };
        let plan = Plan::generate(&opts, 37, 1_800_000_000);
        let ctx = test_ctx(addr, plan, Vec::new(), opts, 60);
        let due = Instant::now();
        // The burst is due at 1.5 s and the upgrade comes at 1.6 s.
        let until = due + Duration::from_millis(1_700);
        let visit = Visit {
            session: 0,
            due,
            until,
        };
        marmot_publisher(ctx.clone(), 0, visit).await;
        assert!(
            ctx.published().values().all(|p| p.sent < until),
            "a burst publication was queued after the session ended"
        );
        let mut stats = ctx.stats();
        assert_eq!(stats.errors, 0, "{:?}", stats.error_samples);
        assert_eq!(stats.class("connect").completed, 1);
    }

    /// A background corpus in which an author deletes a note and replaces
    /// a profile, as `--event-mix social` does: a relay that applied both
    /// passes the preflight and the history checks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_corpus_with_deletions_and_replacements_is_checked_as_the_relay_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let opts = ClientsOptions {
            outbox_clients: 1,
            marmot_clients: 0,
            duration_secs: 3,
            ..small_options()
        };
        let anchor = unix_now() - 5;
        let plan = Plan::generate(&opts, 41, anchor);
        let author = Keypair::new(SECP256K1, &mut rand::rngs::StdRng::seed_from_u64(10));
        let at = |offset: u64| anchor - 100 + offset;
        let tagged = vec![json!(["t", "nostr"])];
        let mut background: Vec<Value> = (0..3)
            .map(|i| signed(&author, at(i), 1, tagged.clone(), format!("note {i}")))
            .collect();
        let deleted = signed(&author, at(3), 1, tagged, "deleted".into());
        let deletion = signed(
            &author,
            at(4),
            5,
            vec![json!(["e", deleted["id"]])],
            String::new(),
        );
        background.extend([
            deleted,
            deletion,
            signed(&author, at(5), 0, Vec::new(), r#"{"name":"old"}"#.into()),
            signed(&author, at(6), 0, Vec::new(), r#"{"name":"new"}"#.into()),
        ]);
        let mut stored = plan.events.clone();
        stored.extend(background.iter().cloned());
        let (addr, handle, cfg) = spawn_relay(dir.path(), &stored, |_| {}).await;
        let url = format!("ws://{addr}");
        let (report, _) = run(RunInput {
            addr,
            plan,
            background,
            facts: RelayFacts::remote(
                &url,
                &cfg.relay.auth.recipient_only_kinds,
                cfg.relay.max_filter_limit,
                cfg.relay.max_total_events_per_req,
            ),
            relay_config: format!("remote target {url}"),
            config_overrides: Vec::new(),
            opts,
            nodelay: true,
        })
        .await
        .unwrap();
        handle.request_shutdown();
        assert_eq!(report.mismatches, 0, "{:#?}", report.mismatch_samples);
        assert_eq!(report.errors, 0, "{:#?}", report.error_samples);
    }
}
