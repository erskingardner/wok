//! `--scenario author_kinds`: time-to-EOSE of `authors` × `kinds` REQs as
//! the author list grows, on a large corpus with skewed author activity, and
//! the same sweep against a second wok binary (`--wok-baseline`) for a
//! before/after comparison of the query planner.
//!
//! The dataset is generated once per (`--events`, `--authors`, `--seed`) and
//! kept under `--dataset-dir`, so repeated runs and both binaries read the
//! same database files:
//!
//! - every author has one kind 0, 3, 10002 and 10050 event, and a history of
//!   kind 1, 7 and 6 events (60/30/10 %) whose size follows a Zipf law over
//!   author rank (exponent [`ZIPF`]);
//! - timestamps are uniform over [`SPAN`] before a fixed anchor, and events
//!   are imported in timestamp order, so authors interleave in the Event
//!   table as they would on a relay;
//! - mentions, reactions, reposts and follow lists name popular authors more
//!   often.
//!
//! Each query shape runs against a fresh copy-on-write clone of the dataset
//! database and a freshly started relay: one cold run (none of that file's
//! pages are cached yet, on filesystems that clone), then warm runs. The
//! binaries alternate which goes first. Result sets are compared across
//! binaries by the SHA-256 of their sorted ids, and must be equal.

use anyhow::{Context, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

use crate::{connect_retry, free_port, stop_relay, write_conf, ClientConnection};

/// Zipf exponent of history size over author rank.
pub(crate) const ZIPF: f64 = 0.8;
/// Corpus timestamps fall in this window before [`ANCHOR`].
const SPAN: u64 = 730 * 86_400;
/// Fixed so the dataset, and so its reuse, does not depend on the clock.
const ANCHOR: u64 = 1_760_000_000;
const REPLACEABLE_KINDS: [u64; 4] = [0, 3, 10002, 10050];
/// Follow-list sizes of the sweep.
const FOLLOWS: [usize; 8] = [50, 100, 300, 333, 334, 500, 1000, 2000];
const SAMPLE_IDS: usize = 100;
const FORMAT: &str = "wok-bench author_kinds v1";

pub struct Options {
    pub wok: PathBuf,
    pub baseline: Option<PathBuf>,
    pub dataset_dir: PathBuf,
    pub authors: usize,
    pub events: u64,
    pub seed: u64,
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
    /// Events each author holds, by rank.
    author_events: Vec<u64>,
    sample_ids: Vec<String>,
    corpus_sha256: String,
    /// The wok binary that imported the corpus.
    imported_with: String,
}

impl Dataset {
    fn dir(opts: &Options) -> PathBuf {
        opts.dataset_dir.join(format!(
            "author_kinds-e{}-a{}-s{}",
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

#[derive(Serialize, Clone)]
pub struct Row {
    pub relay: String,
    pub group: &'static str,
    pub shape: String,
    /// Authors the filter names (0 when it names none).
    pub authors: usize,
    /// Events those authors hold: what a scan of the Pubkey index reads.
    pub author_events: u64,
    pub events: usize,
    pub result_sha256: String,
    pub cold_ms: f64,
    pub warm_runs: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
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
    /// Shapes whose result sets differ between the binaries.
    pub mismatches: Vec<String>,
}

struct Shape {
    group: &'static str,
    label: String,
    authors: usize,
    author_events: u64,
    filter: Value,
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

pub(crate) fn mix(parts: &[u64]) -> u64 {
    // FNV-1a over the parts: stable across Rust versions.
    let mut hash = 0xcbf29ce484222325u64;
    for part in parts {
        for byte in part.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

/// History events per author rank: Zipf over rank, summing to `history`.
pub(crate) fn history_sizes(authors: usize, history: u64) -> Vec<u64> {
    let weights: Vec<f64> = (0..authors)
        .map(|rank| ((rank + 1) as f64).powf(-ZIPF))
        .collect();
    let total: f64 = weights.iter().sum();
    let mut sizes: Vec<u64> = weights
        .iter()
        .map(|w| (history as f64 * w / total).floor() as u64)
        .collect();
    let mut left = history - sizes.iter().sum::<u64>();
    for size in sizes.iter_mut() {
        if left == 0 {
            break;
        }
        *size += 1;
        left -= 1;
    }
    sizes
}

/// One event before it is built and signed. Sorting these by timestamp gives
/// the import order without holding every signed event in memory.
#[derive(Clone, Copy)]
struct Skeleton {
    created_at: u64,
    author: u32,
    seq: u32,
    kind: u16,
}

fn skeletons(seed: u64, sizes: &[u64]) -> Vec<Skeleton> {
    let mut out = Vec::with_capacity(sizes.iter().sum::<u64>() as usize + sizes.len() * 4);
    for (author, &history) in sizes.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(mix(&[seed, 1, author as u64]));
        for seq in 0..history + REPLACEABLE_KINDS.len() as u64 {
            let kind = if seq >= history {
                REPLACEABLE_KINDS[(seq - history) as usize]
            } else {
                match rng.gen_range(0..10) {
                    0..=5 => 1,
                    6..=8 => 7,
                    _ => 6,
                }
            };
            out.push(Skeleton {
                created_at: ANCHOR - rng.gen_range(0..SPAN),
                author: author as u32,
                seq: seq as u32,
                kind: kind as u16,
            });
        }
    }
    out.sort_unstable_by_key(|s| (s.created_at, s.author, s.seq));
    out
}

/// Samples author ranks in proportion to their activity.
pub(crate) struct Popularity {
    cumulative: Vec<f64>,
}

impl Popularity {
    pub(crate) fn new(authors: usize) -> Self {
        let mut total = 0.0;
        let cumulative = (0..authors)
            .map(|rank| {
                total += ((rank + 1) as f64).powf(-ZIPF);
                total
            })
            .collect();
        Self { cumulative }
    }

    pub(crate) fn sample(&self, rng: &mut StdRng) -> usize {
        let target = rng.gen::<f64>() * self.cumulative.last().copied().unwrap_or(0.0);
        self.cumulative
            .partition_point(|&c| c < target)
            .min(self.cumulative.len() - 1)
    }
}

pub(crate) const WORDS: [&str; 24] = [
    "nostr", "relay", "outbox", "note", "client", "today", "sats", "zap", "follow", "key", "event",
    "filter", "index", "query", "coffee", "bitcoin", "music", "photo", "thread", "reply", "good",
    "morning", "build", "ship",
];

fn build_event(
    seed: u64,
    skeleton: Skeleton,
    keys: &[Keypair],
    pubkeys: &[String],
    popularity: &Popularity,
) -> Value {
    let author = skeleton.author as usize;
    let mut rng = StdRng::seed_from_u64(mix(&[seed, 2, author as u64, skeleton.seq as u64]));
    let random_id = |rng: &mut StdRng| {
        let mut id = [0u8; 32];
        rng.fill(&mut id);
        hex::encode(id)
    };
    let popular = |rng: &mut StdRng| pubkeys[popularity.sample(rng)].clone();
    let (tags, content): (Vec<Value>, String) = match skeleton.kind {
        0 => (
            vec![],
            json!({"name": format!("author{author}"), "about": "wok-bench author_kinds"})
                .to_string(),
        ),
        3 => {
            let follows = (10f64 * 50f64.powf(rng.gen::<f64>())) as usize;
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..follows {
                let rank = popularity.sample(&mut rng);
                if rank != author {
                    seen.insert(rank);
                }
            }
            let tags = seen
                .into_iter()
                .map(|rank| json!(["p", pubkeys[rank]]))
                .collect();
            (tags, String::new())
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
            (tags, String::new())
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
            (tags, String::new())
        }
        7 | 6 => {
            let tags = vec![
                json!(["e", random_id(&mut rng)]),
                json!(["p", popular(&mut rng)]),
            ];
            let content = if skeleton.kind == 7 { "+" } else { "" };
            (tags, content.into())
        }
        _ => {
            let mentions = if rng.gen_bool(0.3) {
                rng.gen_range(1..4)
            } else {
                0
            };
            let tags = (0..mentions)
                .map(|_| json!(["p", popular(&mut rng)]))
                .collect();
            let words = rng.gen_range(5..30);
            let content = (0..words)
                .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
                .collect::<Vec<_>>()
                .join(" ");
            (tags, content)
        }
    };
    let mut event = json!({
        "created_at": skeleton.created_at,
        "kind": skeleton.kind,
        "tags": tags,
        "content": content,
        "pubkey": pubkeys[author],
    });
    let id = wok_event::event_id_hash(&event).expect("generated event is valid JSON");
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&id, &keys[author]);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    event
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
    anyhow::ensure!(
        opts.authors > 0 && opts.events >= replaceable + opts.authors as u64,
        "--events must be at least five per author"
    );
    // Without a manifest, whatever is here is an interrupted generation.
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    let started = Instant::now();
    let keys: Vec<_> = (0..opts.authors)
        .map(|rank| author_key(opts.seed, rank))
        .collect();
    let pubkeys: Vec<_> = keys
        .iter()
        .map(|kp| hex::encode(kp.x_only_public_key().0.serialize()))
        .collect();
    let sizes = history_sizes(opts.authors, opts.events - replaceable);
    let skeletons = skeletons(opts.seed, &sizes);
    let popularity = Popularity::new(opts.authors);
    let sample_every = (skeletons.len() / SAMPLE_IDS).max(1);

    let corpus = Dataset::corpus_path(opts);
    let mut out = BufWriter::new(std::fs::File::create(&corpus)?);
    let mut digest = Sha256::new();
    let mut sample_ids = Vec::new();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    for (batch_index, batch) in skeletons.chunks(200_000).enumerate() {
        let per_thread = batch.len().div_ceil(threads);
        let lines: Vec<Vec<(String, String)>> = std::thread::scope(|scope| {
            let workers: Vec<_> = batch
                .chunks(per_thread)
                .map(|part| {
                    let (keys, pubkeys, popularity) = (&keys, &pubkeys, &popularity);
                    scope.spawn(move || {
                        part.iter()
                            .map(|&skeleton| {
                                let event =
                                    build_event(opts.seed, skeleton, keys, pubkeys, popularity);
                                let id = event["id"].as_str().unwrap_or_default().to_owned();
                                (id, wok_event::json::to_tao_string(&event))
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
        for (index, (id, line)) in (batch_index * 200_000..).zip(lines.into_iter().flatten()) {
            if index % sample_every == 0 && sample_ids.len() < SAMPLE_IDS {
                sample_ids.push(id);
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
        "author_kinds: generated {} events in {:.1}s",
        skeletons.len(),
        started.elapsed().as_secs_f64()
    );

    let started = Instant::now();
    let db = Dataset::db_dir(opts);
    std::fs::create_dir_all(&db)?;
    anyhow::ensure!(
        crate::import_with(&opts.wok, &db, &corpus, false),
        "importing the author_kinds corpus with {} failed",
        opts.wok.display()
    );
    eprintln!(
        "author_kinds: imported in {:.1}s",
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
        author_events: sizes
            .iter()
            .map(|history| history + REPLACEABLE_KINDS.len() as u64)
            .collect(),
        sample_ids,
        corpus_sha256: hex::encode(digest.finalize()),
        imported_with: crate::sha256_file(&opts.wok).unwrap_or_default(),
    };
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&dataset)?)?;
    Ok(dataset)
}

fn shapes(dataset: &Dataset, seed: u64) -> Vec<Shape> {
    // A follow list samples authors in proportion to their activity: one
    // weighted shuffle, so each larger list extends the smaller ones and 334
    // differs from 333 by one author.
    let mut rng = StdRng::seed_from_u64(mix(&[seed, 3]));
    let mut keyed: Vec<(f64, usize)> = (0..dataset.authors)
        .map(|rank| {
            let weight = ((rank + 1) as f64).powf(-ZIPF);
            (rng.gen::<f64>().powf(1.0 / weight), rank)
        })
        .collect();
    keyed.sort_by(|a, b| b.0.total_cmp(&a.0));
    let order: Vec<usize> = keyed.into_iter().map(|(_, rank)| rank).collect();
    let follows = |n: usize| -> (Vec<String>, u64) {
        let ranks = &order[..n.min(order.len())];
        (
            ranks
                .iter()
                .map(|&rank| dataset.pubkeys[rank].clone())
                .collect(),
            ranks.iter().map(|&rank| dataset.author_events[rank]).sum(),
        )
    };
    let mut shapes = Vec::new();
    let kind_sets: [(&str, Value, Option<u64>); 6] = [
        ("outbox", json!([0, 3, 10002]), None),
        ("outbox", json!([0, 3, 10002, 10050]), None),
        ("feed", json!([1]), Some(50)),
        ("feed", json!([1, 6]), Some(50)),
        ("feed", json!([1, 6, 7]), Some(100)),
        // A picture and video feed: kinds the authors never publish.
        ("media", json!([20, 21]), Some(50)),
    ];
    for (group, kinds, limit) in &kind_sets {
        for n in FOLLOWS {
            let (authors, author_events) = follows(n);
            let mut filter = json!({"authors": authors, "kinds": kinds});
            let mut label = format!("authors × kinds {kinds}");
            if let Some(limit) = limit {
                filter["limit"] = json!(limit);
                label.push_str(&format!(", limit {limit}"));
            }
            shapes.push(Shape {
                group,
                label,
                authors: n,
                author_events,
                filter,
            });
        }
    }
    for n in [100, 1000] {
        let (authors, author_events) = follows(n);
        shapes.push(Shape {
            group: "guard",
            label: "authors, limit 100".into(),
            authors: n,
            author_events,
            filter: json!({"authors": authors, "limit": 100}),
        });
    }
    let (mentioned, _) = follows(10);
    shapes.extend([
        Shape {
            group: "guard",
            label: "#p top author + kinds [1,6,7], limit 100".into(),
            authors: 0,
            author_events: 0,
            filter: json!({"#p": [dataset.pubkeys[0]], "kinds": [1, 6, 7], "limit": 100}),
        },
        Shape {
            group: "guard",
            label: "#p 10 follows + kinds [1,7], limit 100".into(),
            authors: 0,
            author_events: 0,
            filter: json!({"#p": mentioned, "kinds": [1, 7], "limit": 100}),
        },
        Shape {
            group: "guard",
            label: "kinds [1], limit 100".into(),
            authors: 0,
            author_events: 0,
            filter: json!({"kinds": [1], "limit": 100}),
        },
        Shape {
            group: "guard",
            label: "kinds [0,3,10002], limit 500".into(),
            authors: 0,
            author_events: 0,
            filter: json!({"kinds": [0, 3, 10002], "limit": 500}),
        },
        Shape {
            group: "guard",
            label: format!("ids × {}", dataset.sample_ids.len()),
            authors: 0,
            author_events: 0,
            filter: json!({"ids": dataset.sample_ids}),
        },
    ]);
    shapes
}

/// Clone the dataset database for one relay start. A copy-on-write clone
/// starts with none of its pages in the OS cache.
pub(crate) fn clone_db(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for name in ["data.mdb", "lock.mdb"] {
        let from = src.join(name);
        if !from.exists() {
            continue;
        }
        let to = dst.join(name);
        let cloned = if cfg!(target_os = "macos") {
            std::process::Command::new("cp")
                .arg("-c")
                .arg(&from)
                .arg(&to)
                .status()
        } else {
            std::process::Command::new("cp")
                .arg("--reflink=auto")
                .arg(&from)
                .arg(&to)
                .status()
        };
        if !cloned.is_ok_and(|status| status.success()) {
            std::fs::copy(&from, &to)
                .with_context(|| format!("copy {} to {}", from.display(), to.display()))?;
        }
    }
    Ok(())
}

pub(crate) struct Received {
    pub elapsed: Duration,
    pub events: usize,
    pub sha256: String,
}

/// Room for a 2,000-author filter on a baseline build too: the
/// `relay.max_req_filter_size` default of Wok 0.7 and earlier (64 KiB) refuses
/// a REQ naming about 970 authors or more.
const RELAY_OVERRIDES: &[(&str, &str)] = &[("[relay]", "max_req_filter_size = 1048576")];

/// Start a relay with the harness's usual file, plus each `(section, line)`
/// of `overrides` added at the top of that section.
pub(crate) fn spawn_relay(
    bin: &Path,
    dbdir: &Path,
    port: u16,
    overrides: &[(&str, &str)],
) -> Result<std::process::Child> {
    let conf = write_conf(bin, dbdir, port);
    let mut text = std::fs::read_to_string(&conf)?;
    for (section, line) in overrides {
        let header = format!("{section}\n");
        anyhow::ensure!(
            text.contains(&header),
            "relay file for {} has no {section}",
            bin.display()
        );
        text = text.replacen(&header, &format!("{header}{line}\n"), 1);
    }
    std::fs::write(&conf, text)?;
    std::process::Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .arg("relay")
        .current_dir(dbdir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))
}

/// Time from sending the REQ to its EOSE, and a digest of what it returned.
pub(crate) async fn time_to_eose(
    socket: &mut ClientConnection,
    sid: &str,
    filter: &Value,
) -> Result<Received> {
    let started = Instant::now();
    socket
        .send(Message::Text(
            json!(["REQ", sid, filter]).to_string().into(),
        ))
        .await?;
    let mut ids = Vec::new();
    tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let message = socket.next().await.context("closed before EOSE")??;
            if !message.is_text() {
                continue;
            }
            let reply: Value = serde_json::from_str(message.to_text()?)?;
            match reply[0].as_str() {
                Some("EVENT") if reply[1] == sid => {
                    ids.push(reply[2]["id"].as_str().unwrap_or_default().to_owned());
                }
                Some("EOSE") if reply[1] == sid => return Ok(()),
                Some("AUTH") => {}
                _ => anyhow::bail!("unexpected reply: {reply}"),
            }
        }
    })
    .await
    .context("time-to-EOSE deadline")??;
    let elapsed = started.elapsed();
    socket
        .send(Message::Text(json!(["CLOSE", sid]).to_string().into()))
        .await?;
    ids.sort();
    let mut digest = Sha256::new();
    for id in &ids {
        digest.update(id.as_bytes());
    }
    Ok(Received {
        elapsed,
        events: ids.len(),
        sha256: hex::encode(digest.finalize()),
    })
}

pub(crate) fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Connect to a relay that is still starting. A loaded host, or the OS
/// checking a newly built binary on its first launch, can take longer than
/// one `connect_retry` round; a relay that exits fails at once.
pub(crate) async fn connect_starting(
    url: &str,
    child: &mut std::process::Child,
) -> Result<ClientConnection> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match connect_retry(url).await {
            Ok(socket) => return Ok(socket),
            Err(e) => {
                if let Some(status) = child.try_wait()? {
                    anyhow::bail!("relay exited with {status} before accepting connections");
                }
                if Instant::now() >= deadline {
                    return Err(e);
                }
            }
        }
    }
}

fn measure(
    rt: &tokio::runtime::Runtime,
    opts: &Options,
    bin: &Path,
    relay: &str,
    db: &Path,
    shape: &Shape,
) -> Result<Row> {
    let scratch = tempfile::TempDir::new()?;
    clone_db(db, scratch.path())?;
    let port = free_port();
    let mut child = spawn_relay(bin, scratch.path(), port, RELAY_OVERRIDES)?;
    let url = format!("ws://127.0.0.1:{port}");
    let measured = rt.block_on(async {
        let mut socket = connect_starting(&url, &mut child).await?;
        let cold = time_to_eose(&mut socket, "cold", &shape.filter).await?;
        let mut warm = Vec::new();
        let started = Instant::now();
        while warm.len() < opts.warm_runs
            && (warm.len() < 3 || started.elapsed() < Duration::from_secs(opts.shape_secs))
        {
            let sid = format!("warm{}", warm.len());
            let run = time_to_eose(&mut socket, &sid, &shape.filter).await?;
            anyhow::ensure!(
                run.sha256 == cold.sha256,
                "{relay} returned different events on repeated runs of {}",
                shape.label
            );
            warm.push(run.elapsed.as_secs_f64() * 1000.0);
        }
        let _ = socket.close(None).await;
        Ok::<_, anyhow::Error>((cold, warm))
    });
    stop_relay(&mut child, &url);
    let (cold, mut warm) = measured?;
    warm.sort_by(f64::total_cmp);
    Ok(Row {
        relay: relay.into(),
        group: shape.group,
        shape: shape.label.clone(),
        authors: shape.authors,
        author_events: shape.author_events,
        events: cold.events,
        result_sha256: cold.sha256,
        cold_ms: cold.elapsed.as_secs_f64() * 1000.0,
        warm_runs: warm.len(),
        p50_ms: percentile(&warm, 50.0),
        p95_ms: percentile(&warm, 95.0),
        p99_ms: percentile(&warm, 99.0),
        max_ms: warm.last().copied().unwrap_or(0.0),
    })
}

pub fn run(rt: &tokio::runtime::Runtime, opts: &Options) -> Result<Report> {
    let dataset = ensure_dataset(opts)?;
    let db = Dataset::db_dir(opts);
    let mut binaries = vec![("wok", opts.wok.clone())];
    if let Some(baseline) = &opts.baseline {
        binaries.push(("baseline", baseline.clone()));
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut mismatches = Vec::new();
    for (index, shape) in shapes(&dataset, opts.seed).iter().enumerate() {
        let mut order = binaries.clone();
        if index % 2 == 1 {
            order.reverse();
        }
        let first = rows.len();
        for (relay, bin) in &order {
            let row = measure(rt, opts, bin, relay, &db, shape)
                .with_context(|| format!("{relay}: {} ({} authors)", shape.label, shape.authors))?;
            eprintln!(
                "author_kinds: {relay} {} N={} events={} cold={:.2}ms p50={:.2}ms",
                row.shape, row.authors, row.events, row.cold_ms, row.p50_ms
            );
            rows.push(row);
        }
        if let [ref a, ref b] = rows[first..] {
            if a.result_sha256 != b.result_sha256 {
                mismatches.push(format!("{} ({} authors)", shape.label, shape.authors));
            }
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
        "\n## author_kinds: {} events, {} authors\n\nTime to EOSE in ms. Cold is the first run after the relay starts on a fresh clone of the dataset; p50, p95, p99 and max are over the warm runs. Author events counts what the named authors hold.\n\n",
        report.events, report.authors
    );
    let find = |relay: &str, shape: &str, authors: usize| {
        report
            .rows
            .iter()
            .find(|row| row.relay == relay && row.shape == shape && row.authors == authors)
    };
    if report.baseline.is_some() {
        s.push_str("| shape | N | author events | events | baseline cold | baseline p50 | baseline p95 | baseline p99 | baseline max | wok cold | wok p50 | wok p95 | wok p99 | wok max | p50 speedup | same results |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
        for row in report.rows.iter().filter(|row| row.relay == "wok") {
            let Some(base) = find("baseline", &row.shape, row.authors) else {
                continue;
            };
            s.push_str(&format!(
                "| {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.1}× | {} |\n",
                row.shape,
                row.authors,
                row.author_events,
                row.events,
                base.cold_ms,
                base.p50_ms,
                base.p95_ms,
                base.p99_ms,
                base.max_ms,
                row.cold_ms,
                row.p50_ms,
                row.p95_ms,
                row.p99_ms,
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
        s.push_str("| shape | N | author events | events | cold | p50 | p95 | p99 | max | warm runs |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
        for row in &report.rows {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {} |\n",
                row.shape,
                row.authors,
                row.author_events,
                row.events,
                row.cold_ms,
                row.p50_ms,
                row.p95_ms,
                row.p99_ms,
                row.max_ms,
                row.warm_runs
            ));
        }
    }
    if !report.mismatches.is_empty() {
        s.push_str(&format!(
            "\nResult sets differ between the binaries for: {}\n",
            report.mismatches.join("; ")
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_follows_zipf_and_sums_to_the_total() {
        let sizes = history_sizes(100, 10_000);
        assert_eq!(sizes.iter().sum::<u64>(), 10_000);
        assert!(sizes.windows(2).all(|pair| pair[0] >= pair[1]));
        assert!(sizes[0] > 10 * sizes[99]);
    }

    #[test]
    fn skeletons_are_reproducible_and_in_timestamp_order() {
        let sizes = history_sizes(20, 400);
        let a = skeletons(7, &sizes);
        let b = skeletons(7, &sizes);
        assert_eq!(a.len(), 480);
        assert!(a
            .iter()
            .zip(&b)
            .all(|(x, y)| (x.created_at, x.author, x.seq) == (y.created_at, y.author, y.seq)));
        assert!(a
            .windows(2)
            .all(|pair| pair[0].created_at <= pair[1].created_at));
        for author in 0..20u32 {
            let kinds: Vec<_> = a
                .iter()
                .filter(|s| s.author == author && s.seq as u64 >= sizes[author as usize])
                .map(|s| s.kind as u64)
                .collect();
            assert_eq!(kinds.len(), 4);
            assert!(REPLACEABLE_KINDS.iter().all(|kind| kinds.contains(kind)));
        }
    }

    #[test]
    fn follow_lists_nest_so_adjacent_sizes_differ_by_one_author() {
        let dataset = Dataset {
            format: FORMAT.into(),
            events: 0,
            authors: 3000,
            seed: 1,
            anchor: ANCHOR,
            span_secs: SPAN,
            zipf_exponent: ZIPF,
            pubkeys: (0..3000).map(|i| format!("{i:064x}")).collect(),
            author_events: vec![1; 3000],
            sample_ids: vec!["00".repeat(32)],
            corpus_sha256: String::new(),
            imported_with: String::new(),
        };
        let shapes = shapes(&dataset, 9);
        let authors = |n: usize| {
            shapes
                .iter()
                .find(|shape| shape.authors == n)
                .and_then(|shape| shape.filter["authors"].as_array().cloned())
                .unwrap()
        };
        let (small, large) = (authors(333), authors(334));
        assert_eq!(&large[..333], &small[..]);
        assert_eq!(authors(2000).len(), 2000);
    }
}
