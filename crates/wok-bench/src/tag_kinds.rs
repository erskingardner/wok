//! `--scenario tag_kinds`: time to EOSE of `#p` and `#e` REQs with `kinds`,
//! the notification, zap, DM-inbox and reaction fetches clients send, on a
//! large corpus where a few pubkeys and notes are tagged by tens of thousands
//! of events. Wok answers them from the Tag index and reads each candidate's
//! event to check its kind, so their cost follows how many of the tag's
//! events have another kind.
//!
//! The dataset is generated once per (`--events`, `--authors`, `--seed`) and
//! kept under `--dataset-dir`, as `author_kinds` keeps its own:
//!
//! - every author has one kind 0, 3, 10002 and 10050 event, and a history of
//!   kind 1, 7, 6 and 1111 events ([`HISTORY_MIX`]) whose size follows a Zipf
//!   law over author rank;
//! - [`ZAP_PERCENT`] of the events are zap receipts, signed by a few zapper
//!   keys, and [`WRAP_PERCENT`] are gift wraps, each signed by a one-time key
//!   and `p`-tagging a recipient drawn half by popularity, half uniformly;
//! - replies, reactions, reposts, comments and zaps name a note of a popular
//!   author (Zipf over the author's [`NOTES_PER_AUTHOR`] notes) and `p`-tag
//!   that author, and follow lists name popular authors more often.
//!
//! Timestamps are uniform over [`SPAN`] before a fixed anchor, and events are
//! imported in timestamp order.
//!
//! The shapes target three pubkeys, chosen by how many events `p`-tag them
//! (the most tagged, the one nearest [`BUSY_POSTINGS`], and the median), and
//! the most tagged note. Before any relay starts, the bench walks the
//! dataset's Tag index for each shape in the order `DbScan` reads it and
//! counts the events a Tag-index plan reads before it has `limit` matches.
//! The relay must return the same events.
//!
//! Each shape and binary starts `--cold-runs` relays, each on a fresh
//! copy-on-write clone of the dataset database, and times the first query of
//! each (cold); warm runs follow on the last. The binaries alternate which
//! goes first, and their result sets must be equal.

use anyhow::{Context, Result};
use base64::Engine;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::author_kinds::{
    clone_db, connect_starting, history_sizes, mix, percentile, spawn_relay, time_to_eose,
    Popularity, WORDS, ZIPF,
};
use crate::{free_port, stop_relay};

/// Corpus timestamps fall in this window before [`ANCHOR`].
const SPAN: u64 = 730 * 86_400;
/// Fixed so the dataset, and so its reuse, does not depend on the clock.
const ANCHOR: u64 = 1_760_000_000;
const REPLACEABLE_KINDS: [u64; 4] = [0, 3, 10002, 10050];
/// Kinds of the authors' histories, in percent.
const HISTORY_MIX: [(u16, u32); 4] = [(1, 55), (7, 31), (6, 10), (1111, 4)];
/// Zap receipts, in percent of all events.
const ZAP_PERCENT: u64 = 4;
/// Gift wraps, in percent of all events.
const WRAP_PERCENT: u64 = 5;
/// Zap receipts are signed by the recipients' LNURL servers, not by authors.
const ZAPPERS: u64 = 16;
/// Notes of each author that replies, reactions, reposts, comments and zaps
/// name, by a Zipf law over the note's rank.
const NOTES_PER_AUTHOR: usize = 1_000;
const NOTIFICATION_KINDS: [u64; 5] = [1, 6, 7, 9735, 1111];
const LIMITS: [u64; 2] = [50, 500];
/// The busy tier is the pubkey whose `p` postings are nearest this.
const BUSY_POSTINGS: u64 = 10_000;
/// Gift wraps are readable only by their recipient after AUTH by default,
/// and AUTH is off in the bench relay. Reading them unauthenticated runs the
/// same plan; AUTH adds a recipient check for each event returned.
const RELAY_OVERRIDES: &[(&str, &str)] = &[("[relay.auth]", "restricted_read_kinds = []")];
const FORMAT: &str = "wok-bench tag_kinds v1";

pub struct Options {
    pub wok: PathBuf,
    pub baseline: Option<PathBuf>,
    pub dataset_dir: PathBuf,
    pub authors: usize,
    pub events: u64,
    pub seed: u64,
    pub cold_runs: usize,
    pub warm_runs: usize,
    pub shape_secs: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Dataset {
    format: String,
    pub events: u64,
    pub authors: usize,
    pub seed: u64,
    anchor: u64,
    span_secs: u64,
    zipf_exponent: f64,
    /// Pubkeys by activity rank, most active first.
    pubkeys: Vec<String>,
    /// Events that `p`-tag each author, by rank.
    p_postings: Vec<u64>,
    /// The note that replies, reactions, reposts and zaps name most often.
    popular_note: String,
    corpus_sha256: String,
    /// The wok binary that imported the corpus.
    imported_with: String,
}

impl Dataset {
    fn dir(opts: &Options) -> PathBuf {
        opts.dataset_dir.join(format!(
            "tag_kinds-e{}-a{}-s{}",
            opts.events, opts.authors, opts.seed
        ))
    }

    pub fn corpus_path(opts: &Options) -> PathBuf {
        Self::dir(opts).join("corpus.jsonl")
    }

    fn db_dir(opts: &Options) -> PathBuf {
        Self::dir(opts).join("db")
    }
}

/// What a Tag-index plan reads for one shape, from the dataset's index.
#[derive(Serialize, Clone, Default)]
pub struct Walk {
    /// Tag index entries for the shape's value.
    pub postings: u64,
    /// Of those, events of a requested kind.
    pub matching: u64,
    /// Events returned: the first `limit` matching, newest first.
    pub returned: u64,
    /// Events read before EOSE. With `kinds`, every entry is read to check
    /// its kind until `limit` match; without, only the events returned are.
    pub reads: u64,
    pub result_sha256: String,
}

#[derive(Serialize, Clone)]
pub struct Row {
    pub relay: String,
    pub group: &'static str,
    pub target: &'static str,
    pub shape: String,
    pub limit: u64,
    pub walk: Walk,
    pub events: usize,
    pub result_sha256: String,
    pub cold_runs: usize,
    pub cold_p50_ms: f64,
    pub cold_p95_ms: f64,
    pub cold_max_ms: f64,
    pub warm_runs: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
}

#[derive(Serialize, Clone)]
pub struct Report {
    pub dataset: String,
    pub events: u64,
    pub authors: usize,
    pub wok: String,
    pub baseline: Option<String>,
    pub rows: Vec<Row>,
    /// Shapes whose result sets differ between the binaries, or from the
    /// Tag index walk.
    pub mismatches: Vec<String>,
}

struct Shape {
    group: &'static str,
    target: &'static str,
    label: String,
    tag: char,
    /// Hex of the 32-byte tag value.
    value: String,
    kinds: Option<Vec<u64>>,
    limit: u64,
    filter: Value,
}

fn derived_key(label: &str, seed: u64, index: u64) -> Keypair {
    let mut counter = 0u32;
    loop {
        let mut digest = Sha256::new();
        digest.update(FORMAT.as_bytes());
        digest.update(label.as_bytes());
        digest.update(seed.to_le_bytes());
        digest.update(index.to_le_bytes());
        digest.update(counter.to_le_bytes());
        if let Ok(secret) = SecretKey::from_slice(&digest.finalize()) {
            return Keypair::from_secret_key(SECP256K1, &secret);
        }
        counter += 1;
    }
}

/// The id of an author's `note`-th note. Notes are named, not stored: only
/// their tag postings matter here.
fn note_id(seed: u64, author: usize, note: usize) -> String {
    let mut digest = Sha256::new();
    digest.update(FORMAT.as_bytes());
    digest.update(b"note");
    digest.update(seed.to_le_bytes());
    digest.update((author as u64).to_le_bytes());
    digest.update((note as u64).to_le_bytes());
    hex::encode(digest.finalize())
}

fn history_kind(roll: u32) -> u16 {
    let mut total = 0;
    for (kind, percent) in HISTORY_MIX {
        total += percent;
        if roll < total {
            return kind;
        }
    }
    HISTORY_MIX[0].0
}

/// One event before it is built and signed. `author` is the author's rank,
/// or for kind 9735 the zapper's index; `seq` numbers the events of that
/// author, or of all zap receipts or gift wraps.
#[derive(Clone, Copy)]
struct Skeleton {
    created_at: u64,
    kind: u16,
    author: u32,
    seq: u32,
}

fn skeletons(seed: u64, sizes: &[u64], zaps: u64, wraps: u64) -> Vec<Skeleton> {
    let history: u64 = sizes.iter().sum();
    let mut out = Vec::with_capacity(
        (history + zaps + wraps) as usize + sizes.len() * REPLACEABLE_KINDS.len(),
    );
    for (author, &history) in sizes.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(mix(&[seed, 1, author as u64]));
        for seq in 0..history + REPLACEABLE_KINDS.len() as u64 {
            let kind = if seq >= history {
                REPLACEABLE_KINDS[(seq - history) as usize] as u16
            } else {
                history_kind(rng.gen_range(0..100))
            };
            out.push(Skeleton {
                created_at: ANCHOR - rng.gen_range(0..SPAN),
                kind,
                author: author as u32,
                seq: seq as u32,
            });
        }
    }
    let mut rng = StdRng::seed_from_u64(mix(&[seed, 4]));
    for seq in 0..zaps {
        out.push(Skeleton {
            created_at: ANCHOR - rng.gen_range(0..SPAN),
            kind: 9735,
            author: (seq % ZAPPERS) as u32,
            seq: seq as u32,
        });
    }
    for seq in 0..wraps {
        out.push(Skeleton {
            created_at: ANCHOR - rng.gen_range(0..SPAN),
            kind: 1059,
            author: 0,
            seq: seq as u32,
        });
    }
    out.sort_unstable_by_key(|s| (s.created_at, s.kind, s.author, s.seq));
    out
}

struct Corpus<'a> {
    seed: u64,
    keys: &'a [Keypair],
    pubkeys: &'a [String],
    zappers: &'a [Keypair],
    popularity: &'a Popularity,
    notes: &'a Popularity,
}

impl Corpus<'_> {
    /// A popular author and one of their notes.
    fn target(&self, rng: &mut StdRng) -> (usize, String) {
        let author = self.popularity.sample(rng);
        (author, note_id(self.seed, author, self.notes.sample(rng)))
    }

    fn words(&self, rng: &mut StdRng) -> String {
        (0..rng.gen_range(5..30))
            .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The signed event, and the ranks of the authors it `p`-tags.
    fn build(&self, skeleton: Skeleton) -> (Value, Vec<usize>) {
        let author = skeleton.author as usize;
        let mut rng = StdRng::seed_from_u64(mix(&[
            self.seed,
            2,
            u64::from(skeleton.kind),
            author as u64,
            u64::from(skeleton.seq),
        ]));
        let pk = |rank: usize| self.pubkeys[rank].clone();
        let mut tagged = Vec::new();
        let (signer, tags, content): (Keypair, Vec<Value>, String) = match skeleton.kind {
            0 => (
                self.keys[author],
                vec![],
                json!({"name": format!("author{author}"), "about": "wok-bench tag_kinds"})
                    .to_string(),
            ),
            3 => {
                let follows = (10f64 * 50f64.powf(rng.gen::<f64>())) as usize;
                let mut seen = std::collections::BTreeSet::new();
                for _ in 0..follows {
                    let rank = self.popularity.sample(&mut rng);
                    if rank != author {
                        seen.insert(rank);
                    }
                }
                tagged.extend(seen.iter().copied());
                let tags = seen
                    .into_iter()
                    .map(|rank| json!(["p", pk(rank)]))
                    .collect();
                (self.keys[author], tags, String::new())
            }
            10002 => {
                let tags = (0..rng.gen_range(2..5))
                    .map(|_| {
                        json!([
                            "r",
                            format!("wss://relay{}.example.com", rng.gen_range(0..40))
                        ])
                    })
                    .collect();
                (self.keys[author], tags, String::new())
            }
            10050 => {
                let tags = (0..rng.gen_range(1..3))
                    .map(|_| {
                        json!([
                            "relay",
                            format!("wss://dm{}.example.com", rng.gen_range(0..10))
                        ])
                    })
                    .collect();
                (self.keys[author], tags, String::new())
            }
            7 | 6 => {
                let (target, note) = self.target(&mut rng);
                tagged.push(target);
                let mut tags = vec![json!(["e", note]), json!(["p", pk(target)])];
                let content = if skeleton.kind == 7 {
                    tags.push(json!(["k", "1"]));
                    "+"
                } else {
                    ""
                };
                (self.keys[author], tags, content.into())
            }
            1111 => {
                // NIP-22: uppercase tags name the root, lowercase the parent,
                // which is the root itself or another comment.
                let (root_author, root) = self.target(&mut rng);
                let (parent_author, parent, parent_kind) = if rng.gen_bool(0.5) {
                    (root_author, root.clone(), "1")
                } else {
                    let mut id = [0u8; 32];
                    rng.fill(&mut id);
                    (self.popularity.sample(&mut rng), hex::encode(id), "1111")
                };
                tagged.push(parent_author);
                let tags = vec![
                    json!(["E", root, "", pk(root_author)]),
                    json!(["K", "1"]),
                    json!(["P", pk(root_author)]),
                    json!(["e", parent, "", pk(parent_author)]),
                    json!(["k", parent_kind]),
                    json!(["p", pk(parent_author)]),
                ];
                (self.keys[author], tags, self.words(&mut rng))
            }
            9735 => {
                let (recipient, note) = self.target(&mut rng);
                let sender = rng.gen_range(0..self.pubkeys.len());
                tagged.push(recipient);
                let mut tags = vec![json!(["p", pk(recipient)]), json!(["P", pk(sender)])];
                if rng.gen_bool(0.7) {
                    tags.push(json!(["e", note]));
                }
                let sats = rng.gen_range(1..10_000u64);
                tags.push(json!(["bolt11", format!("lnbc{sats}0n1pwokbench")]));
                tags.push(json!([
                    "description",
                    json!({"kind": 9734, "pubkey": pk(sender), "tags": [["p", pk(recipient)]]})
                        .to_string()
                ]));
                (self.zappers[author], tags, String::new())
            }
            1059 => {
                let recipient = if rng.gen_bool(0.5) {
                    self.popularity.sample(&mut rng)
                } else {
                    rng.gen_range(0..self.pubkeys.len())
                };
                tagged.push(recipient);
                let mut sealed = vec![0u8; rng.gen_range(300..900)];
                rng.fill(&mut sealed[..]);
                (
                    derived_key("wrap", self.seed, u64::from(skeleton.seq)),
                    vec![json!(["p", pk(recipient)])],
                    base64::engine::general_purpose::STANDARD.encode(sealed),
                )
            }
            _ => {
                let tags = match rng.gen_range(0..10) {
                    0..=3 => {
                        let (target, note) = self.target(&mut rng);
                        tagged.push(target);
                        vec![json!(["e", note, "", "root"]), json!(["p", pk(target)])]
                    }
                    4 | 5 => {
                        let mut seen = std::collections::BTreeSet::new();
                        for _ in 0..rng.gen_range(1..4) {
                            seen.insert(self.popularity.sample(&mut rng));
                        }
                        tagged.extend(seen.iter().copied());
                        seen.into_iter()
                            .map(|rank| json!(["p", pk(rank)]))
                            .collect()
                    }
                    _ => vec![],
                };
                (self.keys[author], tags, self.words(&mut rng))
            }
        };
        let mut event = json!({
            "created_at": skeleton.created_at,
            "kind": skeleton.kind,
            "tags": tags,
            "content": content,
            "pubkey": hex::encode(signer.x_only_public_key().0.serialize()),
        });
        let id = wok_event::event_id_hash(&event).expect("generated event is valid JSON");
        event["id"] = json!(hex::encode(id));
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&id, &signer);
        event["sig"] = json!(hex::encode(signature.as_ref()));
        tagged.sort_unstable();
        tagged.dedup();
        (event, tagged)
    }
}

/// Generate and import the dataset unless a matching one is already kept.
pub fn ensure_dataset(opts: &Options) -> Result<Dataset> {
    let dir = Dataset::dir(opts);
    let manifest_path = dir.join("dataset.json");
    if let Ok(bytes) = std::fs::read(&manifest_path) {
        let dataset: Dataset = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            dataset.format == FORMAT && Dataset::db_dir(opts).join("data.mdb").is_file(),
            "{} is not a complete {FORMAT} dataset; remove it",
            dir.display()
        );
        return Ok(dataset);
    }
    let replaceable = (opts.authors * REPLACEABLE_KINDS.len()) as u64;
    let zaps = opts.events * ZAP_PERCENT / 100;
    let wraps = opts.events * WRAP_PERCENT / 100;
    anyhow::ensure!(
        opts.authors > 0 && opts.events >= replaceable + zaps + wraps + opts.authors as u64,
        "--events must leave at least as many history events as authors"
    );
    // Without a manifest, whatever is here is an interrupted generation.
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    let started = Instant::now();
    let keys: Vec<_> = (0..opts.authors as u64)
        .map(|rank| derived_key("author", opts.seed, rank))
        .collect();
    let zappers: Vec<_> = (0..ZAPPERS)
        .map(|index| derived_key("zapper", opts.seed, index))
        .collect();
    let pubkeys: Vec<_> = keys
        .iter()
        .map(|kp| hex::encode(kp.x_only_public_key().0.serialize()))
        .collect();
    let sizes = history_sizes(opts.authors, opts.events - replaceable - zaps - wraps);
    let skeletons = skeletons(opts.seed, &sizes, zaps, wraps);
    let popularity = Popularity::new(opts.authors);
    let notes = Popularity::new(NOTES_PER_AUTHOR);
    let corpus = Corpus {
        seed: opts.seed,
        keys: &keys,
        pubkeys: &pubkeys,
        zappers: &zappers,
        popularity: &popularity,
        notes: &notes,
    };

    let path = Dataset::corpus_path(opts);
    let mut out = BufWriter::new(std::fs::File::create(&path)?);
    let mut digest = Sha256::new();
    let mut p_postings = vec![0u64; opts.authors];
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    for batch in skeletons.chunks(200_000) {
        let per_thread = batch.len().div_ceil(threads);
        let built: Vec<Vec<(String, Vec<usize>)>> = std::thread::scope(|scope| {
            let workers: Vec<_> = batch
                .chunks(per_thread)
                .map(|part| {
                    let corpus = &corpus;
                    scope.spawn(move || {
                        part.iter()
                            .map(|&skeleton| {
                                let (event, tagged) = corpus.build(skeleton);
                                (wok_event::json::to_tao_string(&event), tagged)
                            })
                            .collect()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("corpus worker panicked"))
                .collect()
        });
        for (line, tagged) in built.into_iter().flatten() {
            for rank in tagged {
                p_postings[rank] += 1;
            }
            digest.update(line.as_bytes());
            digest.update(b"\n");
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
        }
    }
    out.flush()?;
    drop(out);
    eprintln!(
        "tag_kinds: generated {} events in {:.1}s",
        skeletons.len(),
        started.elapsed().as_secs_f64()
    );

    let started = Instant::now();
    let db = Dataset::db_dir(opts);
    std::fs::create_dir_all(&db)?;
    anyhow::ensure!(
        crate::import_with(&opts.wok, &db, &path, false),
        "importing the tag_kinds corpus with {} failed",
        opts.wok.display()
    );
    eprintln!(
        "tag_kinds: imported in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    let dataset = Dataset {
        format: FORMAT.into(),
        events: opts.events,
        authors: opts.authors,
        seed: opts.seed,
        anchor: ANCHOR,
        span_secs: SPAN,
        zipf_exponent: ZIPF,
        pubkeys,
        p_postings,
        popular_note: note_id(opts.seed, 0, 0),
        corpus_sha256: hex::encode(digest.finalize()),
        imported_with: crate::sha256_file(&opts.wok).unwrap_or_default(),
    };
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&dataset)?)?;
    Ok(dataset)
}

/// The most `p`-tagged rank, the one nearest [`BUSY_POSTINGS`], and the
/// median, with their labels.
fn tiers(p_postings: &[u64]) -> [(&'static str, usize); 3] {
    let mut by_postings: Vec<usize> = (0..p_postings.len()).collect();
    by_postings.sort_by_key(|&rank| (std::cmp::Reverse(p_postings[rank]), rank));
    let top = by_postings[0];
    let busy = by_postings[1..]
        .iter()
        .copied()
        .min_by_key(|&rank| p_postings[rank].abs_diff(BUSY_POSTINGS))
        .unwrap_or(top);
    let typical = by_postings[by_postings.len() / 2];
    [
        ("top pubkey", top),
        ("busy pubkey", busy),
        ("typical pubkey", typical),
    ]
}

fn shapes(dataset: &Dataset) -> Vec<Shape> {
    let mut shapes = Vec::new();
    let mut push = |group: &'static str,
                    target: &'static str,
                    label: &str,
                    tag: char,
                    value: &str,
                    kinds: Option<&[u64]>| {
        for limit in LIMITS {
            let mut filter = json!({ format!("#{tag}"): [value], "limit": limit });
            let mut shape = format!("{label} #{tag}");
            if let Some(kinds) = kinds {
                filter["kinds"] = json!(kinds);
                shape.push_str(&format!(" + kinds {}", json!(kinds)));
            }
            shapes.push(Shape {
                group,
                target,
                label: shape,
                tag,
                value: value.to_owned(),
                kinds: kinds.map(<[u64]>::to_vec),
                limit,
                filter,
            });
        }
    };
    for (target, rank) in tiers(&dataset.p_postings) {
        let pubkey = &dataset.pubkeys[rank];
        push(
            "notifications",
            target,
            "notifications",
            'p',
            pubkey,
            Some(&NOTIFICATION_KINDS[..]),
        );
        push("zaps", target, "zaps", 'p', pubkey, Some(&[9735][..]));
        push(
            "dm inbox",
            target,
            "DM inbox",
            'p',
            pubkey,
            Some(&[1059][..]),
        );
        if target == "top pubkey" {
            // The same postings without `kinds`: an index-only Tag scan.
            push("mentions", target, "mentions", 'p', pubkey, None);
        }
    }
    let note = &dataset.popular_note;
    push(
        "reactions",
        "popular note",
        "reactions",
        'e',
        note,
        Some(&[7][..]),
    );
    push(
        "note zaps",
        "popular note",
        "zaps",
        'e',
        note,
        Some(&[9735][..]),
    );
    shapes
}

/// Read the shape's postings in the order a single Tag-index cursor of
/// `DbScan` reads them: newest `created_at` first, then highest local id.
fn walk(txn: &wok_db::RoTxn<'_>, shape: &Shape) -> Result<Walk> {
    let dbis = txn.env().dbis();
    let mut search = vec![shape.tag as u8];
    search.extend(hex::decode(&shape.value)?);
    let mut start = search.clone();
    start.extend_from_slice(&[0xFF; 8]);
    let mut walk = Walk::default();
    let mut ids = Vec::new();
    let mut error = None;
    txn.foreach_full(
        dbis.event_tag,
        &start,
        &u64::MAX.to_ne_bytes(),
        true,
        |key, value| {
            if key.len() != search.len() + 8 || !key.starts_with(&search) {
                return false;
            }
            let read = (|| -> Result<(bool, String)> {
                let lev_id = u64::from_ne_bytes(value.try_into()?);
                let raw = txn
                    .get_u64(dbis.event, lev_id)?
                    .with_context(|| format!("tag posting names missing event {lev_id}"))?;
                let packed = wok_event::PackedEventView::new(raw)?;
                let matched = shape
                    .kinds
                    .as_ref()
                    .is_none_or(|kinds| kinds.contains(&packed.kind()));
                Ok((matched, hex::encode(packed.id())))
            })();
            let (matched, id) = match read {
                Ok(read) => read,
                Err(e) => {
                    error = Some(e);
                    return false;
                }
            };
            walk.postings += 1;
            if walk.returned < shape.limit {
                if shape.kinds.is_some() {
                    walk.reads += 1;
                }
                if matched {
                    walk.returned += 1;
                    ids.push(id);
                    if shape.kinds.is_none() {
                        walk.reads += 1;
                    }
                }
            }
            walk.matching += u64::from(matched);
            true
        },
    )?;
    if let Some(error) = error {
        return Err(error);
    }
    ids.sort();
    let mut digest = Sha256::new();
    for id in &ids {
        digest.update(id.as_bytes());
    }
    walk.result_sha256 = hex::encode(digest.finalize());
    Ok(walk)
}

fn ms(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

fn measure(
    rt: &tokio::runtime::Runtime,
    opts: &Options,
    bin: &Path,
    relay: &str,
    db: &Path,
    shape: &Shape,
    walk: &Walk,
) -> Result<Row> {
    let mut cold = Vec::new();
    let mut warm = Vec::new();
    let mut first: Option<(usize, String)> = None;
    for run in 0..opts.cold_runs {
        let scratch = tempfile::TempDir::new()?;
        clone_db(db, scratch.path())?;
        let port = free_port();
        let mut child = spawn_relay(bin, scratch.path(), port, RELAY_OVERRIDES)?;
        let url = format!("ws://127.0.0.1:{port}");
        let last = run + 1 == opts.cold_runs;
        let measured = rt.block_on(async {
            let mut socket = connect_starting(&url, &mut child).await?;
            let cold = time_to_eose(&mut socket, "cold", &shape.filter).await?;
            let mut runs = Vec::new();
            let started = Instant::now();
            while last
                && runs.len() < opts.warm_runs
                && (runs.len() < 3 || started.elapsed() < Duration::from_secs(opts.shape_secs))
            {
                let sid = format!("warm{}", runs.len());
                let run = time_to_eose(&mut socket, &sid, &shape.filter).await?;
                anyhow::ensure!(
                    run.sha256 == cold.sha256,
                    "{relay} returned different events on repeated runs of {}",
                    shape.label
                );
                runs.push(ms(run.elapsed));
            }
            let _ = socket.close(None).await;
            Ok::<_, anyhow::Error>((cold, runs))
        });
        stop_relay(&mut child, &url);
        let (received, runs) = measured?;
        match &first {
            Some((_, sha)) => anyhow::ensure!(
                *sha == received.sha256,
                "{relay} returned different events after restarting for {}",
                shape.label
            ),
            None => first = Some((received.events, received.sha256)),
        }
        cold.push(ms(received.elapsed));
        warm.extend(runs);
    }
    let (events, result_sha256) = first.context("no cold run")?;
    cold.sort_by(f64::total_cmp);
    warm.sort_by(f64::total_cmp);
    Ok(Row {
        relay: relay.into(),
        group: shape.group,
        target: shape.target,
        shape: shape.label.clone(),
        limit: shape.limit,
        walk: walk.clone(),
        events,
        result_sha256,
        cold_runs: cold.len(),
        cold_p50_ms: percentile(&cold, 50.0),
        cold_p95_ms: percentile(&cold, 95.0),
        cold_max_ms: cold.last().copied().unwrap_or(0.0),
        warm_runs: warm.len(),
        p50_ms: percentile(&warm, 50.0),
        p95_ms: percentile(&warm, 95.0),
        max_ms: warm.last().copied().unwrap_or(0.0),
    })
}

/// The dataset's `(tag, kind, created_at)` index, as a fresh reader sees it;
/// `None` when the database has no such table.
fn tag_kind_index_state(db: &Path) -> Result<Option<wok_db::TagKindIndexState>> {
    let env = wok_db::Env::open(
        db,
        wok_db::EnvOptions {
            read_only: true,
            create_dir: false,
            create_dbis: false,
            ..wok_db::EnvOptions::default()
        },
    )?;
    let txn = env.begin_ro()?;
    Ok(wok_db::tag_kind_index_state_ro(&txn)?)
}

/// Have `--wok` build the `(tag, kind, created_at)` index into the dataset
/// before anything is timed. A dataset imported by a release from before the
/// index lacks it, and a relay started on a clone of it would build it in the
/// background: the cold query would read the Tag index while the writer is
/// busy. A binary that keeps no such index leaves the dataset as it is.
fn ensure_tag_kind_index(rt: &tokio::runtime::Runtime, opts: &Options, db: &Path) -> Result<()> {
    if tag_kind_index_state(db)?.is_some_and(|state| state.complete()) {
        return Ok(());
    }
    let started = Instant::now();
    let port = free_port();
    let mut child = spawn_relay(&opts.wok, db, port, RELAY_OVERRIDES)?;
    let url = format!("ws://127.0.0.1:{port}");
    let built = rt
        .block_on(connect_starting(&url, &mut child))
        .map(drop)
        .and_then(|()| loop {
            match tag_kind_index_state(db)? {
                None => return Ok(false),
                Some(state) if state.complete() => return Ok(true),
                Some(_) if started.elapsed() > Duration::from_secs(3_600) => {
                    anyhow::bail!("the relay did not complete the tag-kind index in an hour")
                }
                Some(_) => std::thread::sleep(Duration::from_millis(500)),
            }
        });
    stop_relay(&mut child, &url);
    if built? {
        eprintln!(
            "tag_kinds: {} built the (tag, kind, created_at) index in {:.1}s",
            opts.wok.display(),
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

pub fn run(rt: &tokio::runtime::Runtime, opts: &Options) -> Result<Report> {
    anyhow::ensure!(opts.cold_runs > 0, "--cold-runs must be at least 1");
    let dataset = ensure_dataset(opts)?;
    let db = Dataset::db_dir(opts);
    ensure_tag_kind_index(rt, opts, &db)?;
    let shapes = shapes(&dataset);
    // Walk before any relay opens a clone, so no clone copies this reader.
    let walks = {
        let env = wok_db::Env::open(
            &db,
            wok_db::EnvOptions {
                read_only: true,
                create_dir: false,
                create_dbis: false,
                ..wok_db::EnvOptions::default()
            },
        )?;
        let txn = env.begin_ro()?;
        shapes
            .iter()
            .map(|shape| walk(&txn, shape).with_context(|| format!("walk {}", shape.label)))
            .collect::<Result<Vec<_>>>()?
    };
    let mut binaries = vec![("wok", opts.wok.clone())];
    if let Some(baseline) = &opts.baseline {
        binaries.push(("baseline", baseline.clone()));
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut mismatches = Vec::new();
    for (index, (shape, walk)) in shapes.iter().zip(&walks).enumerate() {
        let mut order = binaries.clone();
        if index % 2 == 1 {
            order.reverse();
        }
        for (relay, bin) in &order {
            let row = measure(rt, opts, bin, relay, &db, shape, walk)
                .with_context(|| format!("{relay}: {} ({})", shape.label, shape.target))?;
            eprintln!(
                "tag_kinds: {relay} {} {} limit {} events={} reads={} cold={:.2}ms p50={:.2}ms",
                row.target,
                row.shape,
                row.limit,
                row.events,
                walk.reads,
                row.cold_p50_ms,
                row.p50_ms
            );
            if row.result_sha256 != walk.result_sha256 {
                mismatches.push(format!(
                    "{relay} and the Tag index walk: {} {} limit {}",
                    shape.target, shape.label, shape.limit
                ));
            }
            rows.push(row);
        }
    }
    Ok(Report {
        dataset: Dataset::dir(opts).display().to_string(),
        events: dataset.events,
        authors: dataset.authors,
        wok: crate::sha256_file(&opts.wok).unwrap_or_default(),
        baseline: opts
            .baseline
            .as_ref()
            .map(|path| crate::sha256_file(path).unwrap_or_default()),
        rows,
        mismatches,
    })
}

pub fn render_markdown(report: &Report) -> String {
    let mut s = format!(
        "\n## tag_kinds: {} events, {} authors\n\nTime to EOSE in ms. Cold runs are the first query of a relay started on a fresh clone of the dataset; warm runs follow on the last one. Postings are the tag value's index entries, matching those of a requested kind, and reads the events a Tag-index plan reads before EOSE.\n\n",
        report.events, report.authors
    );
    let find = |relay: &str, row: &Row| {
        report.rows.iter().find(|other| {
            other.relay == relay
                && other.target == row.target
                && other.shape == row.shape
                && other.limit == row.limit
        })
    };
    if report.baseline.is_some() {
        s.push_str("| target | shape | limit | postings | matching | events | reads | baseline cold p50 | baseline p50 | baseline p95 | baseline max | wok cold p50 | wok p50 | wok p95 | wok max | p50 speedup | same results |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
        for row in report.rows.iter().filter(|row| row.relay == "wok") {
            let Some(base) = find("baseline", row) else {
                continue;
            };
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.1}× | {} |\n",
                row.target,
                row.shape,
                row.limit,
                row.walk.postings,
                row.walk.matching,
                row.events,
                row.walk.reads,
                base.cold_p50_ms,
                base.p50_ms,
                base.p95_ms,
                base.max_ms,
                row.cold_p50_ms,
                row.p50_ms,
                row.p95_ms,
                row.max_ms,
                base.p50_ms / row.p50_ms.max(0.001),
                if base.result_sha256 == row.result_sha256 {
                    "yes"
                } else {
                    "**no**"
                },
            ));
        }
    } else {
        s.push_str("| target | shape | limit | postings | matching | events | reads | cold p50 | cold p95 | cold max | p50 | p95 | max | cold / warm runs |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
        for row in &report.rows {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {} / {} |\n",
                row.target,
                row.shape,
                row.limit,
                row.walk.postings,
                row.walk.matching,
                row.events,
                row.walk.reads,
                row.cold_p50_ms,
                row.cold_p95_ms,
                row.cold_max_ms,
                row.p50_ms,
                row.p95_ms,
                row.max_ms,
                row.cold_runs,
                row.warm_runs,
            ));
        }
    }
    if !report.mismatches.is_empty() {
        s.push_str(&format!(
            "\nResult sets differ: {}\n",
            report.mismatches.join("; ")
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_fixture(authors: usize) -> (Vec<Keypair>, Vec<String>, Vec<Keypair>) {
        let keys: Vec<_> = (0..authors as u64)
            .map(|rank| derived_key("author", 1, rank))
            .collect();
        let pubkeys = keys
            .iter()
            .map(|kp| hex::encode(kp.x_only_public_key().0.serialize()))
            .collect();
        let zappers = (0..ZAPPERS)
            .map(|index| derived_key("zapper", 1, index))
            .collect();
        (keys, pubkeys, zappers)
    }

    #[test]
    fn skeletons_follow_the_mix_and_are_in_timestamp_order() {
        let sizes = history_sizes(50, 20_000);
        let all = skeletons(3, &sizes, 1_000, 1_200);
        assert_eq!(all.len(), 20_000 + 1_000 + 1_200 + 50 * 4);
        assert!(all
            .windows(2)
            .all(|pair| pair[0].created_at <= pair[1].created_at));
        let count = |kind| all.iter().filter(|s| s.kind == kind).count();
        assert_eq!(count(9735), 1_000);
        assert_eq!(count(1059), 1_200);
        assert_eq!(count(3), 50);
        // 55 % of history, within sampling error.
        assert!((10_400..11_600).contains(&count(1)), "{}", count(1));
        assert!((500..1_100).contains(&count(1111)), "{}", count(1111));
        let again = skeletons(3, &sizes, 1_000, 1_200);
        assert!(all.iter().zip(&again).all(|(a, b)| {
            (a.created_at, a.kind, a.author, a.seq) == (b.created_at, b.kind, b.author, b.seq)
        }));
    }

    #[test]
    fn events_tag_the_authors_they_report_and_sign_as_their_source() {
        let (keys, pubkeys, zappers) = corpus_fixture(20);
        let popularity = Popularity::new(20);
        let notes = Popularity::new(NOTES_PER_AUTHOR);
        let corpus = Corpus {
            seed: 1,
            keys: &keys,
            pubkeys: &pubkeys,
            zappers: &zappers,
            popularity: &popularity,
            notes: &notes,
        };
        let skeleton = |kind, author, seq| Skeleton {
            created_at: ANCHOR,
            kind,
            author,
            seq,
        };
        for kind in [1, 3, 6, 7, 1111, 9735, 1059] {
            for seq in 0..20 {
                let (event, tagged) = corpus.build(skeleton(kind, seq % 3, seq));
                let p: std::collections::BTreeSet<_> = event["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|tag| tag[0] == "p")
                    .map(|tag| tag[1].as_str().unwrap().to_owned())
                    .collect();
                let named: std::collections::BTreeSet<_> =
                    tagged.iter().map(|&rank| pubkeys[rank].clone()).collect();
                assert_eq!(p, named, "kind {kind}");
                let signer = event["pubkey"].as_str().unwrap();
                match kind {
                    9735 => assert_eq!(
                        signer,
                        hex::encode(zappers[seq as usize % 3].x_only_public_key().0.serialize())
                    ),
                    1059 => assert!(!pubkeys.iter().any(|pk| pk == signer)),
                    _ => assert_eq!(signer, pubkeys[(seq % 3) as usize]),
                }
            }
        }
        let (reaction, tagged) = corpus.build(skeleton(7, 0, 0));
        let tags = reaction["tags"].as_array().unwrap();
        assert_eq!(tags[1][1], json!(pubkeys[tagged[0]]));
        assert!(tags[0][1].as_str().unwrap().len() == 64);
    }

    #[test]
    fn tiers_pick_the_top_the_busy_and_the_median_pubkey() {
        let postings = [100_000, 30_000, 11_000, 9_500, 400, 300, 200, 100, 0];
        let [top, busy, typical] = tiers(&postings);
        assert_eq!(top.1, 0);
        assert_eq!(busy.1, 3);
        assert_eq!(typical.1, 4);
    }
}
