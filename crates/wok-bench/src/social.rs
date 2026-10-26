//! `--event-mix social`: a public social relay's history at relay scale,
//! written to disk as it is generated.
//!
//! - Authors (`--social-authors`) post in proportion to a Zipf law over rank
//!   ([`crate::author_kinds::ZIPF`]); replies, reactions, reposts, zaps and
//!   follows name popular authors more often.
//! - Timestamps cover [`SPAN`] up to `--base-timestamp`, with activity growing
//!   linearly over the window as a relay's does. NIP-59 wraps are backdated
//!   by up to two days.
//! - The kind mix is the publication mix of [`MIX`]. Profiles, follow lists,
//!   relay lists, articles and KeyPackages are replaced, and deletion
//!   requests delete their author's earlier events, so a relay keeps fewer
//!   events than the corpus holds. [`Summary::retained`] is that count.
//! - Sizes follow real clients: follow lists up to `--max-follows`, zap
//!   receipts that embed their request, reposts that embed the note, and
//!   Marmot Welcomes that grow with the group.
//!
//! Events are built in order on one thread, so ids are known before signing,
//! and signed in parallel in batches. The output depends only on the options,
//! not on the thread count.

use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::author_kinds::{mix, Popularity, WORDS};

/// Corpus timestamps fall in this window before the anchor.
pub(crate) const SPAN: u64 = 730 * 86_400;
const DAY: u64 = 86_400;
const FORMAT: &str = "wok-bench social v1";
/// Events built before each parallel signing pass. Reposts embed notes from
/// earlier batches only, since a note's signature exists once its batch is
/// signed.
const BATCH: usize = 16_384;
/// Signed notes kept for reposts to embed.
const REPOST_POOL: usize = 4_096;
/// Notes, by id, that replies, reactions and zaps may point to.
const NOTE_POOL: usize = 65_536;
/// Regular events per author that a deletion request may name.
const DELETABLE: usize = 4;
/// Zap services that sign receipts.
const ZAPPERS: usize = 16;
/// Marmot groups that 445 messages go to.
const GROUPS: usize = 2_000;

/// Publication mix in events per thousand, from tracking issue #226.
const MIX: [(u16, u32); 21] = [
    // Reactions, notes and replies.
    (7, 300),
    (1, 270),
    // Profiles, follow lists and relay lists.
    (0, 40),
    (3, 35),
    (10_002, 30),
    (10_050, 10),
    (10_000, 5),
    (1_059, 80),
    (6, 60),
    (9_735, 60),
    (1_111, 30),
    // Long-form, media and lists.
    (30_023, 15),
    (20, 15),
    (30_000, 10),
    (10_003, 10),
    (5, 10),
    // Other: Marmot group messages and KeyPackages, highlights, reports and
    // live events.
    (445, 8),
    (30_443, 4),
    (9_802, 4),
    (1_984, 3),
    (30_311, 1),
];

pub struct Options {
    pub events: u64,
    pub authors: usize,
    pub seed: u64,
    pub anchor: u64,
    pub max_follows: usize,
}

#[derive(Serialize, Default, Clone, Debug, PartialEq)]
pub struct KindCount {
    pub events: u64,
    pub bytes: u64,
}

/// What a relay should hold after importing the corpus, and the limits it
/// must allow to accept every event.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Summary {
    pub format: &'static str,
    pub authors: usize,
    pub span_secs: u64,
    pub max_follows: usize,
    /// Events a relay keeps after replacements and deletions.
    pub retained: u64,
    pub largest_event_bytes: u64,
    pub most_tags: u64,
    /// Longest value of a single-letter tag, the tags relays index and limit.
    pub largest_tag_value_bytes: u64,
    pub kinds: BTreeMap<u16, KindCount>,
}

fn author_key(seed: u64, rank: usize) -> Keypair {
    let mut counter = 0u32;
    loop {
        let mut digest = Sha256::new();
        digest.update(FORMAT.as_bytes());
        digest.update(seed.to_le_bytes());
        digest.update((rank as u64).to_le_bytes());
        digest.update(counter.to_le_bytes());
        if let Ok(secret) = SecretKey::from_slice(&digest.finalize()) {
            return Keypair::from_secret_key(SECP256K1, &secret);
        }
        counter += 1;
    }
}

fn hex_id(id: &[u8; 32]) -> String {
    hex::encode(id)
}

fn random_hex(rng: &mut StdRng, bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rng.fill(&mut buffer[..]);
    hex::encode(buffer)
}

fn b64(rng: &mut StdRng, bytes: usize) -> String {
    use base64::Engine;
    let mut buffer = vec![0u8; bytes];
    rng.fill(&mut buffer[..]);
    base64::engine::general_purpose::STANDARD.encode(buffer)
}

fn words(rng: &mut StdRng, count: usize) -> String {
    (0..count)
        .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

fn log_normal(rng: &mut StdRng, median: f64, sigma: f64) -> f64 {
    let normal: f64 = (0..12).map(|_| rng.gen::<f64>()).sum::<f64>() - 6.0;
    median * (sigma * normal).exp()
}

/// A median of 20 words with a long tail.
fn note_words(rng: &mut StdRng) -> usize {
    log_normal(rng, 20.0, 0.9).round().clamp(1.0, 600.0) as usize
}

fn log_uniform(rng: &mut StdRng, low: usize, high: usize) -> usize {
    let (low, high) = (low.max(1) as f64, high.max(low.max(1)) as f64);
    (low * (high / low).powf(rng.gen::<f64>())).round() as usize
}

#[derive(Clone, Copy)]
enum Signer {
    Author(u32),
    Own(Keypair),
}

/// An event with its id but not yet its signature.
struct Unsigned {
    event: Value,
    id: [u8; 32],
    signer: Signer,
}

#[derive(Clone)]
struct Note {
    id: [u8; 32],
    author: u32,
    kind: u16,
}

struct Builder {
    rng: StdRng,
    total: u64,
    anchor: u64,
    max_follows: usize,
    keys: Vec<Keypair>,
    pubkeys: Vec<String>,
    popularity: Popularity,
    zappers: Vec<Keypair>,
    groups: Vec<String>,
    kinds: Vec<(u16, u32)>,
    mix_total: u32,
    /// Recent notes that replies, reactions and zaps point to.
    notes: VecDeque<Note>,
    /// Each author's latest note.
    latest_note: HashMap<u32, Note>,
    /// Signed notes from earlier batches, for reposts to embed.
    signed_notes: VecDeque<String>,
    /// Each author's recent regular events a deletion may name.
    deletable: HashMap<u32, VecDeque<[u8; 32]>>,
    /// Latest timestamp of each replaceable address, kept increasing.
    addresses: HashMap<(u32, u16, String), u64>,
    /// Addressable identifiers in use per author and kind.
    identifiers: HashMap<(u32, u16), Vec<String>>,
    retained: u64,
}

impl Builder {
    fn new(opts: &Options) -> Self {
        let keys: Vec<_> = (0..opts.authors)
            .map(|rank| author_key(opts.seed, rank))
            .collect();
        let pubkeys = keys
            .iter()
            .map(|kp| hex::encode(kp.x_only_public_key().0.serialize()))
            .collect();
        let zappers = (0..ZAPPERS)
            .map(|index| author_key(opts.seed ^ 0x7a61_7073, index))
            .collect();
        let mut rng = StdRng::seed_from_u64(mix(&[opts.seed, 3]));
        let groups = (0..GROUPS).map(|_| random_hex(&mut rng, 32)).collect();
        Self {
            rng,
            total: opts.events,
            anchor: opts.anchor,
            max_follows: opts.max_follows,
            keys,
            pubkeys,
            popularity: Popularity::new(opts.authors),
            zappers,
            groups,
            kinds: MIX.to_vec(),
            mix_total: MIX.iter().map(|(_, weight)| weight).sum(),
            notes: VecDeque::new(),
            latest_note: HashMap::new(),
            signed_notes: VecDeque::new(),
            deletable: HashMap::new(),
            addresses: HashMap::new(),
            identifiers: HashMap::new(),
            retained: 0,
        }
    }

    /// Activity grows linearly over the window: event `i` of `n` sits at
    /// `sqrt(i / n)` of it.
    fn timestamp(&self, index: u64) -> u64 {
        let position = ((index as f64 + 0.5) / self.total as f64).sqrt();
        self.anchor - SPAN + (position * SPAN as f64) as u64
    }

    fn pick_kind(&mut self) -> u16 {
        let mut roll = self.rng.gen_range(0..self.mix_total);
        for &(kind, weight) in &self.kinds {
            if roll < weight {
                return kind;
            }
            roll -= weight;
        }
        1
    }

    fn popular(&mut self) -> u32 {
        self.popularity.sample(&mut self.rng) as u32
    }

    /// A note to reply to, react to or zap: usually a popular author's latest.
    fn target_note(&mut self) -> Option<Note> {
        if self.rng.gen_bool(0.6) {
            let author = self.popular();
            if let Some(note) = self.latest_note.get(&author) {
                return Some(note.clone());
            }
        }
        if self.notes.is_empty() {
            return None;
        }
        let index = self.rng.gen_range(0..self.notes.len());
        Some(self.notes[index].clone())
    }

    fn fresh_key(&mut self) -> Keypair {
        Keypair::new(SECP256K1, &mut self.rng)
    }

    fn next(&mut self, index: u64) -> Unsigned {
        let created_at = self.timestamp(index);
        let author = self.popular();
        let mut kind = self.pick_kind();
        // Kinds that point at earlier events fall back to a note until there
        // is something to point at.
        let target = match kind {
            1 if self.rng.gen_bool(0.4) => self.target_note(),
            6 | 7 | 9_735 | 1_111 | 9_802 => self.target_note(),
            _ => None,
        };
        if (matches!(kind, 6 | 7 | 9_735 | 1_111 | 9_802) && target.is_none())
            || (kind == 6 && self.signed_notes.is_empty())
            || (kind == 5 && self.deletable.get(&author).is_none_or(VecDeque::is_empty))
        {
            kind = 1;
        }
        let (signer, created_at, tags, content) = match kind {
            0 => self.profile(author, created_at),
            3 => self.follows(author, created_at),
            5 => self.deletion(author, created_at),
            6 => self.repost(author, created_at),
            7 => self.reaction(author, created_at, target.expect("checked above")),
            20 => self.picture(author, created_at),
            445 => self.group_message(created_at),
            1_059 => self.gift_wrap(created_at),
            1_111 => self.comment(author, created_at, target.expect("checked above")),
            1_984 => self.report(author, created_at),
            9_735 => self.zap(created_at, target.expect("checked above")),
            9_802 => self.highlight(author, created_at, target.expect("checked above")),
            10_000 | 10_002 | 10_003 | 10_050 => self.list(author, kind, created_at),
            30_000 | 30_023 | 30_311 | 30_443 => self.addressable(author, kind, created_at),
            _ => self.note(author, created_at, target),
        };
        let pubkey = match signer {
            Signer::Author(rank) => self.pubkeys[rank as usize].clone(),
            Signer::Own(keys) => hex::encode(keys.x_only_public_key().0.serialize()),
        };
        let event = json!({
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "pubkey": pubkey,
        });
        let id = wok_event::event_id_hash(&event).expect("generated event is valid JSON");
        self.account(kind, author, signer, id, &event);
        Unsigned { event, id, signer }
    }

    /// Track what a relay keeps, and what later events may point at.
    fn account(&mut self, kind: u16, author: u32, signer: Signer, id: [u8; 32], event: &Value) {
        let replaceable = kind == 0 || kind == 3 || (10_000..20_000).contains(&kind);
        let addressable = (30_000..40_000).contains(&kind);
        if replaceable || addressable {
            // Counted once per address by `replace`.
            return;
        }
        self.retained += 1;
        if kind == 5 {
            for tag in event["tags"].as_array().into_iter().flatten() {
                if tag[0] == "e" {
                    self.retained -= 1;
                }
            }
        }
        if matches!(signer, Signer::Author(_)) && kind != 5 {
            let ids = self.deletable.entry(author).or_default();
            ids.push_back(id);
            if ids.len() > DELETABLE {
                ids.pop_front();
            }
        }
        if kind == 1 {
            let note = Note { id, author, kind };
            self.latest_note.insert(author, note.clone());
            self.notes.push_back(note);
            if self.notes.len() > NOTE_POOL {
                self.notes.pop_front();
            }
        }
    }

    /// The timestamp for a new version of an address: after the last one, so
    /// the newest version is unambiguous. Counts the address once.
    fn replace(&mut self, author: u32, kind: u16, identifier: &str, created_at: u64) -> u64 {
        let key = (author, kind, identifier.to_owned());
        match self.addresses.get(&key) {
            Some(&prior) => {
                let created_at = created_at.max(prior + 1);
                self.addresses.insert(key, created_at);
                created_at
            }
            None => {
                self.retained += 1;
                self.addresses.insert(key, created_at);
                created_at
            }
        }
    }

    fn note(
        &mut self,
        author: u32,
        created_at: u64,
        target: Option<Note>,
    ) -> (Signer, u64, Vec<Value>, String) {
        let mut tags = Vec::new();
        if let Some(parent) = &target {
            tags.push(json!(["e", hex_id(&parent.id), "", "root"]));
            tags.push(json!(["p", self.pubkeys[parent.author as usize]]));
        }
        for _ in 0..[0, 0, 0, 1, 2][self.rng.gen_range(0..5)] {
            let mentioned = self.popular();
            tags.push(json!(["p", self.pubkeys[mentioned as usize]]));
        }
        let count = note_words(&mut self.rng);
        let mut content = words(&mut self.rng, count);
        if self.rng.gen_bool(0.2) {
            let topic = WORDS[self.rng.gen_range(0..WORDS.len())];
            tags.push(json!(["t", topic]));
            content.push_str(&format!(" #{topic}"));
        }
        if self.rng.gen_bool(0.15) {
            content.push_str(&format!(
                " https://image.example.com/{}.jpg",
                random_hex(&mut self.rng, 16)
            ));
        }
        (Signer::Author(author), created_at, tags, content)
    }

    fn reaction(
        &mut self,
        author: u32,
        created_at: u64,
        target: Note,
    ) -> (Signer, u64, Vec<Value>, String) {
        let tags = vec![
            json!(["e", hex_id(&target.id)]),
            json!(["p", self.pubkeys[target.author as usize]]),
            json!(["k", target.kind.to_string()]),
        ];
        let content = ["+", "+", "+", "🤙", "❤️", "🔥", "-"][self.rng.gen_range(0..7)];
        (Signer::Author(author), created_at, tags, content.into())
    }

    fn repost(&mut self, author: u32, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let index = self.rng.gen_range(0..self.signed_notes.len());
        let embedded = self.signed_notes[index].clone();
        let note: Value = serde_json::from_str(&embedded).expect("pool holds signed notes");
        let tags = vec![
            json!(["e", note["id"], "wss://relay.example.com"]),
            json!(["p", note["pubkey"]]),
        ];
        (Signer::Author(author), created_at, tags, embedded)
    }

    fn zap(&mut self, created_at: u64, target: Note) -> (Signer, u64, Vec<Value>, String) {
        let sender = self.popular();
        let recipient = &self.pubkeys[target.author as usize];
        let amount = [21, 100, 500, 1_000, 5_000, 21_000][self.rng.gen_range(0..6)] * 1_000u64;
        let mut relays = vec![json!("relays")];
        for n in 0..self.rng.gen_range(1..5) {
            relays.push(json!(format!("wss://relay{n}.example.com")));
        }
        let words_count = self.rng.gen_range(0..8);
        let request = json!({
            "id": random_hex(&mut self.rng, 32),
            "pubkey": self.pubkeys[sender as usize],
            "created_at": created_at,
            "kind": 9_734,
            "tags": [
                ["p", recipient],
                ["e", hex_id(&target.id)],
                ["amount", amount.to_string()],
                relays,
            ],
            "content": words(&mut self.rng, words_count),
            "sig": random_hex(&mut self.rng, 64),
        });
        let tags = vec![
            json!(["p", recipient]),
            json!(["e", hex_id(&target.id)]),
            json!(["P", self.pubkeys[sender as usize]]),
            json!([
                "bolt11",
                format!("lnbc{}n1{}", amount / 100, random_hex(&mut self.rng, 160))
            ]),
            json!(["description", request.to_string()]),
            json!(["preimage", random_hex(&mut self.rng, 32)]),
        ];
        let zapper = self.zappers[self.rng.gen_range(0..ZAPPERS)];
        (Signer::Own(zapper), created_at, tags, String::new())
    }

    fn comment(
        &mut self,
        author: u32,
        created_at: u64,
        target: Note,
    ) -> (Signer, u64, Vec<Value>, String) {
        let id = hex_id(&target.id);
        let pubkey = &self.pubkeys[target.author as usize];
        let tags = vec![
            json!(["E", id, "", pubkey]),
            json!(["K", "1"]),
            json!(["P", pubkey]),
            json!(["e", id, "", pubkey]),
            json!(["k", "1"]),
            json!(["p", pubkey]),
        ];
        let count = note_words(&mut self.rng);
        let content = words(&mut self.rng, count);
        (Signer::Author(author), created_at, tags, content)
    }

    fn highlight(
        &mut self,
        author: u32,
        created_at: u64,
        target: Note,
    ) -> (Signer, u64, Vec<Value>, String) {
        let tags = vec![
            json!(["e", hex_id(&target.id)]),
            json!(["p", self.pubkeys[target.author as usize], "", "author"]),
        ];
        let count = self.rng.gen_range(5..40);
        let content = words(&mut self.rng, count);
        (Signer::Author(author), created_at, tags, content)
    }

    fn deletion(&mut self, author: u32, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let ids = self.deletable.get_mut(&author).expect("checked above");
        let id = ids.pop_back().expect("checked above");
        let tags = vec![json!(["e", hex_id(&id)])];
        (Signer::Author(author), created_at, tags, String::new())
    }

    fn report(&mut self, author: u32, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let reported = self.popular();
        let reason = ["spam", "impersonation", "other"][self.rng.gen_range(0..3)];
        let tags = vec![json!(["p", self.pubkeys[reported as usize], reason])];
        (Signer::Author(author), created_at, tags, String::new())
    }

    fn picture(&mut self, author: u32, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let tags = (0..self.rng.gen_range(1..5))
            .map(|_| {
                let hash = random_hex(&mut self.rng, 32);
                json!([
                    "imeta",
                    format!("url https://media.example.com/{hash}.jpg"),
                    "m image/jpeg",
                    format!(
                        "dim {}x{}",
                        self.rng.gen_range(600..4_000),
                        self.rng.gen_range(600..4_000)
                    ),
                    format!("blurhash {}", b64(&mut self.rng, 24)),
                    format!("x {hash}"),
                ])
            })
            .collect();
        let count = self.rng.gen_range(0..20);
        let content = words(&mut self.rng, count);
        (Signer::Author(author), created_at, tags, content)
    }

    fn group_message(&mut self, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let group = self.groups[self.rng.gen_range(0..GROUPS)].clone();
        let bytes = log_uniform(&mut self.rng, 200, 4_000);
        let content = b64(&mut self.rng, bytes);
        let keys = self.fresh_key();
        (
            Signer::Own(keys),
            created_at,
            vec![json!(["h", group])],
            content,
        )
    }

    /// A NIP-17 message, or one time in twenty a Marmot Welcome, which
    /// carries the group's ratchet tree.
    fn gift_wrap(&mut self, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let recipient = self.popular();
        let bytes = if self.rng.gen_bool(0.05) {
            8_192 + 256 * log_uniform(&mut self.rng, 2, 250)
        } else {
            log_uniform(&mut self.rng, 600, 1_800)
        };
        let content = b64(&mut self.rng, bytes);
        let created_at = created_at
            .saturating_sub(self.rng.gen_range(0..2 * DAY))
            .max(self.anchor - SPAN);
        let keys = self.fresh_key();
        let tags = vec![json!(["p", self.pubkeys[recipient as usize]])];
        (Signer::Own(keys), created_at, tags, content)
    }

    fn profile(&mut self, author: u32, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let created_at = self.replace(author, 0, "", created_at);
        let count = log_uniform(&mut self.rng, 3, 120);
        let about = words(&mut self.rng, count);
        let content = json!({
            "name": format!("author{author}"),
            "display_name": format!("Author {author}"),
            "about": about,
            "picture": format!("https://image.example.com/{}.png", random_hex(&mut self.rng, 16)),
            "banner": format!("https://image.example.com/{}.png", random_hex(&mut self.rng, 16)),
            "nip05": format!("author{author}@example.com"),
            "lud16": format!("author{author}@wallet.example.com"),
            "website": format!("https://author{author}.example.com"),
        })
        .to_string();
        (Signer::Author(author), created_at, Vec::new(), content)
    }

    /// Each author keeps a follow count of their own, log-normal with a
    /// median of 150 up to `max_follows`, which drifts a little between
    /// versions.
    fn follows(&mut self, author: u32, created_at: u64) -> (Signer, u64, Vec<Value>, String) {
        let created_at = self.replace(author, 3, "", created_at);
        let mut own = StdRng::seed_from_u64(mix(&[u64::from(author), 4]));
        let base = (log_normal(&mut own, 150.0, 1.0) as usize).clamp(1, self.max_follows);
        let count = (base + self.rng.gen_range(0..=base / 20 + 1)).min(self.max_follows);
        let mut seen = HashSet::new();
        let mut tags = Vec::with_capacity(count);
        for attempt in 0.. {
            if tags.len() >= count || attempt >= count * 4 {
                break;
            }
            // Past the most popular, follows spread over everyone.
            let rank = if attempt % 2 == 0 {
                self.popular()
            } else {
                self.rng.gen_range(0..self.pubkeys.len() as u32)
            };
            if rank != author && seen.insert(rank) {
                tags.push(json!(["p", self.pubkeys[rank as usize]]));
            }
        }
        (Signer::Author(author), created_at, tags, String::new())
    }

    fn list(
        &mut self,
        author: u32,
        kind: u16,
        created_at: u64,
    ) -> (Signer, u64, Vec<Value>, String) {
        let created_at = self.replace(author, kind, "", created_at);
        let tags = match kind {
            10_002 => (0..self.rng.gen_range(2..9))
                .map(|_| {
                    let relay = format!("wss://relay{}.example.com", self.rng.gen_range(0..60));
                    match self.rng.gen_range(0..3) {
                        0 => json!(["r", relay]),
                        1 => json!(["r", relay, "read"]),
                        _ => json!(["r", relay, "write"]),
                    }
                })
                .collect(),
            10_050 => (0..self.rng.gen_range(1..4))
                .map(|_| {
                    json!([
                        "relay",
                        format!("wss://dm{}.example.com", self.rng.gen_range(0..10))
                    ])
                })
                .collect(),
            10_000 => (0..log_uniform(&mut self.rng, 1, 200))
                .map(|_| {
                    let muted = self.popular();
                    json!(["p", self.pubkeys[muted as usize]])
                })
                .collect(),
            _ => (0..log_uniform(&mut self.rng, 1, 100))
                .map(|_| json!(["e", random_hex(&mut self.rng, 32)]))
                .collect(),
        };
        (Signer::Author(author), created_at, tags, String::new())
    }

    /// Articles, follow sets, live events and KeyPackages. Each author keeps
    /// a few identifiers per kind; a new one is more likely than an edit,
    /// except for KeyPackages, which rotate a handful of slots.
    fn addressable(
        &mut self,
        author: u32,
        kind: u16,
        created_at: u64,
    ) -> (Signer, u64, Vec<Value>, String) {
        let existing = self.identifiers.get(&(author, kind)).map_or(0, Vec::len);
        let identifier = if kind == 30_443 {
            format!("keypackage-{}", self.rng.gen_range(0..3))
        } else if existing > 0 && self.rng.gen_bool(0.25) {
            self.identifiers[&(author, kind)][self.rng.gen_range(0..existing)].clone()
        } else {
            let identifier = random_hex(&mut self.rng, 8);
            self.identifiers
                .entry((author, kind))
                .or_default()
                .push(identifier.clone());
            identifier
        };
        let created_at = self.replace(author, kind, &identifier, created_at);
        let mut tags = vec![json!(["d", identifier])];
        let content = match kind {
            30_023 => {
                tags.push(json!(["title", words(&mut self.rng, 6)]));
                tags.push(json!(["summary", words(&mut self.rng, 25)]));
                tags.push(json!(["published_at", created_at.to_string()]));
                tags.push(json!(["t", WORDS[self.rng.gen_range(0..WORDS.len())]]));
                let paragraphs = log_uniform(&mut self.rng, 4, 60);
                (0..paragraphs)
                    .map(|_| {
                        let count = self.rng.gen_range(20..80);
                        words(&mut self.rng, count)
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
            30_000 => {
                tags.push(json!(["title", words(&mut self.rng, 2)]));
                for _ in 0..log_uniform(&mut self.rng, 5, 200) {
                    let followed = self.popular();
                    tags.push(json!(["p", self.pubkeys[followed as usize]]));
                }
                String::new()
            }
            30_311 => {
                tags.push(json!(["title", words(&mut self.rng, 5)]));
                tags.push(json!(["status", "ended"]));
                tags.push(json!([
                    "streaming",
                    format!(
                        "https://stream.example.com/{}.m3u8",
                        random_hex(&mut self.rng, 8)
                    )
                ]));
                for _ in 0..self.rng.gen_range(1..6) {
                    let host = self.popular();
                    tags.push(json!(["p", self.pubkeys[host as usize], "", "Speaker"]));
                }
                String::new()
            }
            _ => {
                tags.push(json!(["mls_protocol_version", "1.0"]));
                tags.push(json!(["mls_ciphersuite", "0x0001"]));
                tags.push(json!(["mls_extensions", "0x000a", "0xf2ee"]));
                tags.push(json!(["relays", "wss://relay.example.com"]));
                let bytes = self.rng.gen_range(300..700);
                b64(&mut self.rng, bytes)
            }
        };
        (Signer::Author(author), created_at, tags, content)
    }

    /// After a batch is signed, its notes become available to reposts.
    fn absorb(&mut self, kind: u16, line: &str) {
        if kind == 1 {
            self.signed_notes.push_back(line.to_owned());
            if self.signed_notes.len() > REPOST_POOL {
                self.signed_notes.pop_front();
            }
        }
    }
}

/// Write the corpus to `path`, one signed event per line.
pub fn generate(path: &Path, opts: &Options) -> Result<Summary> {
    anyhow::ensure!(opts.authors > 0, "--social-authors must be at least 1");
    anyhow::ensure!(
        opts.anchor >= SPAN,
        "--base-timestamp must be at least {SPAN}"
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut builder = Builder::new(opts);
    let mut out = BufWriter::new(std::fs::File::create(path)?);
    let mut summary = Summary {
        format: FORMAT,
        authors: opts.authors,
        span_secs: SPAN,
        max_follows: opts.max_follows,
        retained: 0,
        largest_event_bytes: 0,
        most_tags: 0,
        largest_tag_value_bytes: 0,
        kinds: BTreeMap::new(),
    };
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut index = 0u64;
    while index < opts.events {
        let count = (opts.events - index).min(BATCH as u64);
        let batch: Vec<Unsigned> = (index..index + count).map(|i| builder.next(i)).collect();
        index += count;
        let per_thread = batch.len().div_ceil(threads);
        let keys = &builder.keys;
        let lines: Vec<Vec<String>> = std::thread::scope(|scope| {
            let workers: Vec<_> = batch
                .chunks(per_thread)
                .map(|part| scope.spawn(move || part.iter().map(|e| sign(e, keys)).collect()))
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("signing worker panicked"))
                .collect()
        });
        for (unsigned, line) in batch.iter().zip(lines.into_iter().flatten()) {
            let kind = unsigned.event["kind"].as_u64().unwrap_or_default() as u16;
            let entry = summary.kinds.entry(kind).or_default();
            entry.events += 1;
            entry.bytes += line.len() as u64;
            summary.largest_event_bytes = summary.largest_event_bytes.max(line.len() as u64);
            let tags = unsigned.event["tags"]
                .as_array()
                .map_or(&[][..], Vec::as_slice);
            summary.most_tags = summary.most_tags.max(tags.len() as u64);
            for tag in tags {
                if tag[0].as_str().is_some_and(|name| name.len() == 1) {
                    let bytes = tag[1].as_str().map_or(0, str::len) as u64;
                    summary.largest_tag_value_bytes = summary.largest_tag_value_bytes.max(bytes);
                }
            }
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
            builder.absorb(kind, &line);
        }
    }
    out.flush()?;
    summary.retained = builder.retained;
    Ok(summary)
}

fn sign(unsigned: &Unsigned, keys: &[Keypair]) -> String {
    let keys = match unsigned.signer {
        Signer::Author(rank) => keys[rank as usize],
        Signer::Own(keys) => keys,
    };
    let mut event = unsigned.event.clone();
    event["id"] = json!(hex::encode(unsigned.id));
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&unsigned.id, &keys);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    wok_event::json::to_tao_string(&event)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: u64 = 1_760_000_000;

    fn corpus(events: u64, authors: usize, seed: u64) -> (Vec<Value>, Summary, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corpus.jsonl");
        let opts = Options {
            events,
            authors,
            seed,
            anchor: ANCHOR,
            max_follows: 300,
        };
        let summary = generate(&path, &opts).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let events = crate::read_event_values(&path).unwrap();
        (events, summary, bytes)
    }

    #[test]
    fn corpus_is_reproducible_across_batches() {
        let events = BATCH as u64 + 1_000;
        let (_, first, first_bytes) = corpus(events, 200, 7);
        let (_, second, second_bytes) = corpus(events, 200, 7);
        assert_eq!(first, second);
        assert!(first_bytes == second_bytes, "same options, different bytes");
        let (_, _, other) = corpus(events, 200, 8);
        assert!(first_bytes != other, "seed does not change the corpus");
    }

    #[test]
    fn every_event_passes_the_relays_validation() {
        let (events, _, _) = corpus(4_000, 100, 1);
        let limits = wok_event::EventLimits::default();
        for event in &events {
            wok_event::parse_and_verify_event(event, &limits, None, true, false)
                .unwrap_or_else(|e| panic!("{e}: {event}"));
        }
    }

    #[test]
    fn retained_count_matches_the_relay_oracle() {
        // Few authors, so replacements and deletions happen often.
        let (events, summary, _) = corpus(BATCH as u64 + 4_000, 60, 3);
        let retained = crate::retained_events(&events);
        assert_eq!(summary.retained, retained.len() as u64);
        let deletions = summary.kinds[&5].events;
        assert!(deletions > 0 && summary.retained < events.len() as u64);
        // Deleted and replaced events stay out of the retained set.
        let kept: HashSet<&str> = retained.iter().filter_map(|e| e["id"].as_str()).collect();
        for event in events.iter().filter(|e| e["kind"] == 5) {
            assert!(!kept.contains(event["tags"][0][1].as_str().unwrap()));
        }
    }

    #[test]
    fn mix_and_references_look_like_a_social_relay() {
        let (events, summary, _) = corpus(40_000, 2_000, 5);
        let share = |kind: u16| summary.kinds.get(&kind).map_or(0, |k| k.events) as f64 / 40_000.0;
        assert!((share(7) - 0.30).abs() < 0.03, "reactions {}", share(7));
        assert!((share(1059) - 0.08).abs() < 0.02, "wraps {}", share(1059));
        assert!(share(3) > 0.025 && share(9735) > 0.05);
        let ids: HashSet<&str> = events.iter().filter_map(|e| e["id"].as_str()).collect();
        let mut earlier = HashSet::new();
        for event in &events {
            let kind = event["kind"].as_u64().unwrap();
            if matches!(kind, 1 | 5 | 6 | 7 | 9_735) {
                for tag in event["tags"].as_array().unwrap() {
                    if tag[0] == "e" {
                        let target = tag[1].as_str().unwrap();
                        assert!(ids.contains(target), "kind {kind} names a missing event");
                        assert!(earlier.contains(target), "kind {kind} names a later event");
                    }
                }
            }
            earlier.insert(event["id"].as_str().unwrap());
        }
        // Popular authors write most of it.
        let mut by_author: HashMap<&str, u64> = HashMap::new();
        for event in events.iter().filter(|e| e["kind"] == 1) {
            *by_author
                .entry(event["pubkey"].as_str().unwrap())
                .or_default() += 1;
        }
        let mut counts: Vec<u64> = by_author.into_values().collect();
        counts.sort_unstable_by(|a, b| b.cmp(a));
        let top: u64 = counts.iter().take(counts.len() / 10).sum();
        assert!(
            top * 3 > counts.iter().sum::<u64>(),
            "activity is not skewed"
        );
    }

    #[test]
    fn sizes_follow_real_clients() {
        let (events, summary, _) = corpus(40_000, 2_000, 9);
        let follows = events
            .iter()
            .filter(|e| e["kind"] == 3)
            .map(|e| e["tags"].as_array().unwrap().len())
            .max()
            .unwrap();
        assert!(
            follows > 150 && follows <= 300,
            "largest follow list {follows}"
        );
        let welcome = events
            .iter()
            .filter(|e| e["kind"] == 1059)
            .map(|e| e["content"].as_str().unwrap().len())
            .max()
            .unwrap();
        assert!(welcome > 12_000, "largest wrap {welcome}");
        let zap = events.iter().find(|e| e["kind"] == 9735).unwrap();
        let description = zap["tags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t[0] == "description")
            .unwrap();
        let request: Value = serde_json::from_str(description[1].as_str().unwrap()).unwrap();
        assert_eq!(request["kind"], 9734);
        let first = events[0]["created_at"].as_u64().unwrap();
        assert!((ANCHOR - SPAN..ANCHOR - SPAN / 2).contains(&first));
        assert!(events
            .iter()
            .all(|e| e["created_at"].as_u64().unwrap() <= ANCHOR + 1));
        assert!(summary.largest_event_bytes > 10_000 && summary.most_tags >= follows as u64);
    }
}
