//! Many live subscriptions under churn: `--scenario monitor_index` and
//! `--scenario live_subscriptions`.
//!
//! Both build the same workload. Each of `conns` connections holds
//! `subs_per_conn` subscriptions: of every ten, six are home feeds with a
//! distinct list of `min_authors..=max_authors` authors, one follows `#p`
//! mentions, one `#p` zap receipts, and two follow `#e` threads. Authors are
//! ranked by popularity, and follow lists, posts and mentions pick them by a
//! Zipf law, so popular authors share large index buckets as on a public
//! relay. The event stream mixes notes, replies, reactions, reposts, zap
//! receipts and kind 3 contact lists of 300 to 1,000 `p` tags, which no
//! subscription wants but every event index has to look at.
//!
//! `monitor_index` drives the req monitor's index (`wok_query::ActiveMonitors`)
//! in process, so its times are monitor-thread CPU: per event matched, per REQ,
//! replacement and CLOSE, and per connection closed and resubscribed in a
//! reconnect storm. `live_subscriptions` runs the workload against a relay and
//! measures fan-out latency, publish to receipt, in four phases: steady ingest,
//! REQ/CLOSE churn from extra connections, a reconnect storm of every
//! connection, and steady ingest after it. Deliveries outside the storm are
//! checked against an independent matcher.

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use rand::{Rng, SeedableRng};
use secp256k1::{Keypair, SECP256K1};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use wok_query::{ActiveMonitors, NostrFilterGroup, PendingBuffer, SubId, Subscription};

use crate::{connect_retry, ClientConnection};

/// Notes that replies, reactions and `#e` subscriptions refer to.
const ROOTS: usize = 2_000;
/// Zipf exponent of author and note popularity.
const ZIPF: f64 = 0.8;
const FEED_KINDS: [u64; 2] = [1, 6];
const MENTION_KINDS: [u64; 3] = [1, 6, 7];
/// Zap receipts. Gift wraps would fit too, but need AUTH to read.
const ZAP_KIND: u64 = 9735;
const THREAD_KINDS: [u64; 2] = [1, 7];

#[derive(Clone, Debug)]
pub struct Options {
    /// Authors that follow lists, posts and mentions are drawn from.
    pub authors: usize,
    pub conns: usize,
    pub subs_per_conn: usize,
    pub min_authors: usize,
    pub max_authors: usize,
    /// Events `monitor_index` matches, before and after its churn.
    pub events: usize,
    /// Publications per second in `live_subscriptions`.
    pub rate: f64,
    /// Seconds of each timed `live_subscriptions` phase.
    pub phase_secs: u64,
    /// Extra connections that churn subscriptions in `live_subscriptions`.
    pub churners: usize,
    /// REQs per second the churners send in total.
    pub churn_rate: f64,
    pub seed: u64,
}

/// One subscription of the workload.
#[derive(Clone, Debug)]
enum Spec {
    /// Sorted author indexes.
    Feed(Vec<u32>),
    Mentions(u32),
    Zaps(u32),
    /// Sorted root note indexes.
    Thread(Vec<u32>),
}

/// An event before it is packed or signed.
#[derive(Clone, Debug)]
struct Draft {
    author: u32,
    kind: u64,
    /// Root note indexes in `e` tags.
    e: Vec<u32>,
    /// Author indexes in `p` tags.
    p: Vec<u32>,
}

impl Spec {
    /// The independent matcher deliveries are checked against.
    fn matches(&self, draft: &Draft) -> bool {
        match self {
            Spec::Feed(authors) => {
                FEED_KINDS.contains(&draft.kind) && authors.binary_search(&draft.author).is_ok()
            }
            Spec::Mentions(p) => MENTION_KINDS.contains(&draft.kind) && draft.p.contains(p),
            Spec::Zaps(p) => draft.kind == ZAP_KIND && draft.p.contains(p),
            Spec::Thread(roots) => {
                THREAD_KINDS.contains(&draft.kind)
                    && draft.e.iter().any(|e| roots.binary_search(e).is_ok())
            }
        }
    }
}

struct Zipf {
    cdf: Vec<f64>,
}

impl Zipf {
    fn new(n: usize) -> Self {
        let mut total = 0.0;
        let mut cdf: Vec<f64> = (0..n)
            .map(|rank| {
                total += 1.0 / ((rank + 1) as f64).powf(ZIPF);
                total
            })
            .collect();
        cdf.iter_mut().for_each(|c| *c /= total);
        Self { cdf }
    }

    fn sample(&self, rng: &mut impl Rng) -> u32 {
        let r: f64 = rng.gen();
        self.cdf.partition_point(|&c| c < r).min(self.cdf.len() - 1) as u32
    }

    /// `n` distinct ranks, sorted.
    fn distinct(&self, rng: &mut impl Rng, n: usize) -> Vec<u32> {
        let n = n.min(self.cdf.len() / 2);
        let mut set = HashSet::with_capacity(n);
        while set.len() < n {
            set.insert(self.sample(rng));
        }
        let mut out: Vec<u32> = set.into_iter().collect();
        out.sort_unstable();
        out
    }
}

struct Workload {
    opts: Options,
    keys: Vec<Keypair>,
    pubkeys: Vec<[u8; 32]>,
    pubkeys_hex: Vec<String>,
    /// Signed root notes, published before anything subscribes.
    roots: Vec<Value>,
    root_ids: Vec<[u8; 32]>,
    root_authors: Vec<u32>,
    authors: Zipf,
    root_rank: Zipf,
    conns: Vec<Vec<Spec>>,
}

impl Workload {
    fn new(opts: &Options) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(opts.seed);
        let keys: Vec<Keypair> = (0..opts.authors)
            .map(|_| Keypair::new(SECP256K1, &mut rng))
            .collect();
        let pubkeys: Vec<[u8; 32]> = keys
            .iter()
            .map(|key| key.x_only_public_key().0.serialize())
            .collect();
        let pubkeys_hex = pubkeys.iter().map(hex::encode).collect();
        let authors = Zipf::new(opts.authors);
        let root_rank = Zipf::new(ROOTS);
        let now = unix_now();
        let mut roots = Vec::with_capacity(ROOTS);
        let mut root_ids = Vec::with_capacity(ROOTS);
        let mut root_authors = Vec::with_capacity(ROOTS);
        for i in 0..ROOTS {
            let author = authors.sample(&mut rng);
            let event = signed(
                &keys[author as usize],
                now - 60,
                1,
                Vec::new(),
                format!("root {i}"),
            );
            root_ids.push(hex_id(&event));
            roots.push(event);
            root_authors.push(author);
        }
        let mut workload = Self {
            opts: opts.clone(),
            keys,
            pubkeys,
            pubkeys_hex,
            roots,
            root_ids,
            root_authors,
            authors,
            root_rank,
            conns: Vec::new(),
        };
        workload.conns = (0..opts.conns)
            .map(|_| {
                (0..opts.subs_per_conn)
                    .map(|slot| workload.spec(&mut rng, slot))
                    .collect()
            })
            .collect();
        workload
    }

    fn spec(&self, rng: &mut impl Rng, slot: usize) -> Spec {
        match slot % 10 {
            0..=5 => self.feed(rng),
            6 => Spec::Mentions(self.authors.sample(rng)),
            7 => Spec::Zaps(self.authors.sample(rng)),
            _ => {
                let n = rng.gen_range(1..=20);
                Spec::Thread(self.root_rank.distinct(rng, n))
            }
        }
    }

    fn feed(&self, rng: &mut impl Rng) -> Spec {
        let n = rng.gen_range(self.opts.min_authors..=self.opts.max_authors);
        Spec::Feed(self.authors.distinct(rng, n))
    }

    fn largest_feed(&self, rng: &mut impl Rng) -> Spec {
        Spec::Feed(self.authors.distinct(rng, self.opts.max_authors))
    }

    fn filter(&self, spec: &Spec) -> Value {
        let hexes = |idx: &[u32]| -> Vec<&str> {
            idx.iter()
                .map(|&i| self.pubkeys_hex[i as usize].as_str())
                .collect()
        };
        match spec {
            Spec::Feed(authors) => {
                json!({"authors": hexes(authors), "kinds": FEED_KINDS, "limit": 0})
            }
            Spec::Mentions(p) => json!({"#p": hexes(&[*p]), "kinds": MENTION_KINDS, "limit": 0}),
            Spec::Zaps(p) => json!({"#p": hexes(&[*p]), "kinds": [ZAP_KIND], "limit": 0}),
            Spec::Thread(roots) => {
                let ids: Vec<String> = roots
                    .iter()
                    .map(|&r| hex::encode(self.root_ids[r as usize]))
                    .collect();
                json!({"#e": ids, "kinds": THREAD_KINDS, "limit": 0})
            }
        }
    }

    fn draft(&self, rng: &mut impl Rng) -> Draft {
        let author = self.authors.sample(rng);
        let root = self.root_rank.sample(rng);
        let root_author = self.root_authors[root as usize];
        let roll = rng.gen_range(0..100);
        let (kind, e, p) = match roll {
            0..=49 => {
                let mut e = Vec::new();
                let mut p = Vec::new();
                if rng.gen_bool(0.35) {
                    e.push(root);
                    p.push(root_author);
                }
                if rng.gen_bool(0.2) {
                    p.push(self.authors.sample(rng));
                }
                (1, e, p)
            }
            50..=79 => (7, vec![root], vec![root_author]),
            80..=84 => (6, vec![root], vec![root_author]),
            85..=94 => {
                // Signed by any of the authors, standing in for zap services.
                let service = rng.gen_range(0..self.keys.len() as u32);
                let recipient = self.authors.sample(rng);
                return Draft {
                    author: service,
                    kind: ZAP_KIND,
                    e: Vec::new(),
                    p: vec![recipient],
                };
            }
            _ => {
                let n = rng.gen_range(300..=1_000);
                (3, Vec::new(), self.authors.distinct(rng, n))
            }
        };
        Draft { author, kind, e, p }
    }

    fn packed(&self, draft: &Draft, id: &[u8; 32], created_at: u64) -> wok_event::PackedEvent {
        let mut tags = wok_event::PackedEventTagBuilder::default();
        for &e in &draft.e {
            tags.add('e', &self.root_ids[e as usize]).unwrap();
        }
        for &p in &draft.p {
            tags.add('p', &self.pubkeys[p as usize]).unwrap();
        }
        let author = &self.pubkeys[draft.author as usize];
        wok_event::PackedEventBuilder::build(id, author, created_at, draft.kind, 0, &tags).unwrap()
    }

    /// The content carries the sequence number and whether deliveries of the
    /// event are checked.
    fn signed(&self, draft: &Draft, seq: u32, checked: bool) -> Value {
        let mut tags: Vec<Value> = draft
            .e
            .iter()
            .map(|&e| json!(["e", hex::encode(self.root_ids[e as usize])]))
            .collect();
        tags.extend(
            draft
                .p
                .iter()
                .map(|&p| json!(["p", self.pubkeys_hex[p as usize]])),
        );
        signed(
            &self.keys[draft.author as usize],
            unix_now(),
            draft.kind,
            tags,
            format!("live {seq} {}", u8::from(checked)),
        )
    }
}

fn signed(keys: &Keypair, created_at: u64, kind: u64, tags: Vec<Value>, content: String) -> Value {
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "pubkey": hex::encode(keys.x_only_public_key().0.serialize()),
    });
    let id = wok_event::event_id_hash(&event).expect("generated event is valid JSON");
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&id, keys);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    event
}

fn hex_id(event: &Value) -> [u8; 32] {
    let mut id = [0u8; 32];
    hex::decode_to_slice(event["id"].as_str().unwrap(), &mut id).unwrap();
    id
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sub_id(slot: usize) -> String {
    format!("s{slot}")
}

fn histogram() -> Histogram<u64> {
    Histogram::new(3).expect("histogram")
}

fn nanos(start: Instant) -> u64 {
    start.elapsed().as_nanos().max(1) as u64
}

// ---------------------------------------------------------------------------
// monitor_index
// ---------------------------------------------------------------------------

/// Times in microseconds.
#[derive(Clone, Debug, Serialize)]
pub struct StepRow {
    pub step: String,
    pub count: u64,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    pub total_ms: f64,
}

impl StepRow {
    fn new(step: &str, h: &Histogram<u64>) -> Self {
        let us = |ns: u64| ns as f64 / 1_000.0;
        Self {
            step: step.into(),
            count: h.len(),
            mean_us: h.mean() / 1_000.0,
            p50_us: us(h.value_at_quantile(0.5)),
            p99_us: us(h.value_at_quantile(0.99)),
            max_us: us(h.max()),
            total_ms: h.mean() * h.len() as f64 / 1e6,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct IndexReport {
    pub conns: usize,
    pub subscriptions: usize,
    pub feed_authors: u64,
    pub events: u64,
    pub recipients_per_event: f64,
    pub churn_cycles: u64,
    pub rows: Vec<StepRow>,
    /// Matches checked against the independent matcher, and how many differed.
    pub checked_events: u64,
    pub mismatches: u64,
    /// Per-event match times, ns.
    #[serde(skip)]
    pub matched: Histogram<u64>,
}

fn subscription(
    conn: usize,
    slot: usize,
    group: NostrFilterGroup,
    generation: u64,
) -> Subscription {
    let mut sub = Subscription::new(
        conn as u64,
        SubId::new(&sub_id(slot)).unwrap(),
        group,
        false,
    );
    sub.latest_event_id = 0;
    sub.generation = generation;
    sub
}

fn group(filter: &Value) -> NostrFilterGroup {
    NostrFilterGroup::from_value(filter, u64::MAX, 3, 16).expect("generated filter")
}

/// Register a subscription the way the req monitor does: pending at
/// admission, live once its (here empty) history is sent.
fn register(monitors: &mut ActiveMonitors, sub: Subscription) {
    let (conn, sid, generation) = (sub.conn_id, sub.sub_id.clone(), sub.generation);
    monitors.add_pending(sub, PendingBuffer::new(0, 0));
    monitors
        .finish_pending(conn, &sid, generation, 0)
        .expect("just registered");
}

/// Match one event the way the req monitor does, timing it.
fn match_event(
    monitors: &mut ActiveMonitors,
    lev: u64,
    packed: wok_event::PackedEventView<'_>,
) -> (u64, Vec<wok_query::Recipient>) {
    let start = Instant::now();
    let content = monitors.event_requires_content(packed);
    debug_assert!(!content, "the workload has no search subscriptions");
    let recipients = monitors.process(lev, packed, None);
    (nanos(start), recipients)
}

pub fn run_index(opts: &Options) -> Result<IndexReport> {
    let workload = Workload::new(opts);
    let mut rng = rand::rngs::StdRng::seed_from_u64(opts.seed ^ 0x6d6f_6e69);
    let groups: Vec<Vec<NostrFilterGroup>> = workload
        .conns
        .iter()
        .map(|specs| {
            specs
                .iter()
                .map(|spec| group(&workload.filter(spec)))
                .collect()
        })
        .collect();
    let mut monitors = ActiveMonitors::new(usize::MAX);
    let mut generation = 0u64;

    let mut subscribe = histogram();
    for (conn, subs) in groups.iter().enumerate() {
        for (slot, group) in subs.iter().enumerate() {
            generation += 1;
            let sub = subscription(conn, slot, group.clone(), generation);
            let start = Instant::now();
            register(&mut monitors, sub);
            subscribe.record(nanos(start))?;
        }
    }

    // Ingest. The first events are also checked against the reference.
    const CHECKED: usize = 500;
    let mut lev = 0u64;
    let mut matched = histogram();
    let mut contacts = histogram();
    let mut recipients_total = 0u64;
    let mut checked_events = 0;
    let mut mismatches = 0;
    let mut ingest = |monitors: &mut ActiveMonitors,
                      rng: &mut rand::rngs::StdRng,
                      count: usize,
                      specs: &[Vec<Spec>]|
     -> Result<()> {
        for i in 0..count {
            lev += 1;
            let draft = workload.draft(rng);
            let id: [u8; 32] = rng.gen();
            let packed = workload.packed(&draft, &id, 1_700_000_000 + lev);
            let (ns, recipients) = match_event(monitors, lev, packed.view());
            matched.record(ns)?;
            if draft.kind == 3 {
                contacts.record(ns)?;
            }
            recipients_total += recipients.len() as u64;
            if i < CHECKED {
                checked_events += 1;
                let mut expected: Vec<(u64, String)> = Vec::new();
                for (conn, subs) in specs.iter().enumerate() {
                    for (slot, spec) in subs.iter().enumerate() {
                        if spec.matches(&draft) {
                            expected.push((conn as u64, sub_id(slot)));
                        }
                    }
                }
                expected.sort();
                let actual: Vec<(u64, String)> = recipients
                    .iter()
                    .map(|r| (r.conn_id, r.sub_id.to_string()))
                    .collect();
                mismatches += u64::from(actual != expected);
            }
        }
        Ok(())
    };
    ingest(&mut monitors, &mut rng, opts.events, &workload.conns)?;

    // Churn: replace a feed with the largest list, CLOSE it, REQ it again.
    let feeds = opts.subs_per_conn.min(6);
    let cycles = if feeds == 0 { 0 } else { 2 * opts.conns };
    let (mut replace, mut close, mut req) = (histogram(), histogram(), histogram());
    for _ in 0..cycles {
        let conn = rng.gen_range(0..opts.conns);
        let slot = rng.gen_range(0..feeds);
        let sid = SubId::new(&sub_id(slot)).unwrap();
        generation += 1;
        let largest = group(&workload.filter(&workload.largest_feed(&mut rng)));
        let sub = subscription(conn, slot, largest, generation);
        let start = Instant::now();
        register(&mut monitors, sub);
        replace.record(nanos(start))?;
        let start = Instant::now();
        monitors.remove_sub(conn as u64, &sid);
        close.record(nanos(start))?;
        generation += 1;
        let sub = subscription(conn, slot, groups[conn][slot].clone(), generation);
        let start = Instant::now();
        register(&mut monitors, sub);
        req.record(nanos(start))?;
    }

    // Reconnect storm: every connection closes, then subscribes again.
    let (mut storm_close, mut storm_req) = (histogram(), histogram());
    for conn in 0..opts.conns {
        let start = Instant::now();
        monitors.close_conn(conn as u64);
        storm_close.record(nanos(start))?;
    }
    for (conn, subs) in groups.iter().enumerate() {
        let subs: Vec<_> = subs
            .iter()
            .enumerate()
            .map(|(slot, group)| {
                generation += 1;
                subscription(conn, slot, group.clone(), generation)
            })
            .collect();
        let start = Instant::now();
        for sub in subs {
            register(&mut monitors, sub);
        }
        storm_req.record(nanos(start))?;
    }

    // The same population again: matched and checked as before.
    ingest(
        &mut monitors,
        &mut rng,
        opts.events.min(CHECKED * 2),
        &workload.conns,
    )?;
    let events = matched.len();

    let feed_authors = workload
        .conns
        .iter()
        .flatten()
        .map(|spec| match spec {
            Spec::Feed(authors) => authors.len() as u64,
            _ => 0,
        })
        .sum();
    Ok(IndexReport {
        conns: opts.conns,
        subscriptions: opts.conns * opts.subs_per_conn,
        feed_authors,
        events,
        recipients_per_event: recipients_total as f64 / events.max(1) as f64,
        churn_cycles: cycles as u64,
        rows: vec![
            StepRow::new("REQ (subscribe)", &subscribe),
            StepRow::new("match event", &matched),
            StepRow::new("match kind 3 (300-1,000 p tags)", &contacts),
            StepRow::new(
                &format!("churn: REQ replacement ({} authors)", opts.max_authors),
                &replace,
            ),
            StepRow::new(
                &format!("churn: CLOSE ({} authors)", opts.max_authors),
                &close,
            ),
            StepRow::new("churn: REQ again", &req),
            StepRow::new("storm: close connection", &storm_close),
            StepRow::new("storm: resubscribe connection", &storm_req),
        ],
        checked_events,
        mismatches,
        matched,
    })
}

pub fn render_index_markdown(report: &IndexReport) -> String {
    let mut s = format!(
        "\n### monitor_index\n\n{} connections, {} subscriptions ({} feed authors in all), {} events matched, {:.1} recipients per event, {} churn cycles. {} events checked against the reference matcher: {} differed.\n\n",
        report.conns,
        report.subscriptions,
        report.feed_authors,
        report.events,
        report.recipients_per_event,
        report.churn_cycles,
        report.checked_events,
        report.mismatches,
    );
    s.push_str("| step | count | mean µs | p50 µs | p99 µs | max µs | total ms |\n|---|---:|---:|---:|---:|---:|---:|\n");
    for row in &report.rows {
        s.push_str(&format!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.1} |\n",
            row.step, row.count, row.mean_us, row.p50_us, row.p99_us, row.max_us, row.total_ms
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// live_subscriptions
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Setup,
    Steady,
    Churn,
    /// The publisher pauses while deliveries drain.
    Quiet,
    Storm,
    Recovered,
    Stop,
}

/// The phases a report row covers, in order.
const ROWS: [Phase; 4] = [Phase::Steady, Phase::Churn, Phase::Storm, Phase::Recovered];

impl Phase {
    fn row(self) -> usize {
        match self {
            Phase::Setup | Phase::Steady => 0,
            Phase::Churn => 1,
            Phase::Storm => 2,
            Phase::Quiet | Phase::Recovered | Phase::Stop => 3,
        }
    }
}

/// One event the publisher sent.
struct Published {
    draft: Draft,
    phase: Phase,
    sent_ns: u64,
    accepted: bool,
}

/// A delivery: subscription slot, event sequence number, receipt time.
type Delivery = (u8, u32, u64);

#[derive(Default)]
struct ConnLog {
    deliveries: Vec<Delivery>,
    subscribe_ns: u64,
    storm_ns: u64,
}

struct ChurnLog {
    eose: Histogram<u64>,
    reqs: u64,
    closes: u64,
    /// Deliveries after the churn, while the churner's feeds stay open.
    deliveries: Vec<Delivery>,
}

/// Per stable connection, the deliveries the reference matcher expects of
/// checked events published so far, and those received.
struct Tally {
    expected: Vec<std::sync::atomic::AtomicU64>,
    received: Vec<std::sync::atomic::AtomicU64>,
    /// The publisher saw [`Phase::Quiet`] after counting its last event.
    paused: std::sync::atomic::AtomicBool,
}

impl Tally {
    fn new(conns: usize) -> Self {
        let zeros = || (0..conns).map(|_| Default::default()).collect();
        Self {
            expected: zeros(),
            received: zeros(),
            paused: Default::default(),
        }
    }

    fn settled(&self) -> bool {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        self.paused.load(Acquire)
            && self
                .expected
                .iter()
                .zip(&self.received)
                .all(|(e, r)| r.load(Relaxed) >= e.load(Relaxed))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PhaseRow {
    pub phase: Phase,
    pub secs: f64,
    pub events: u64,
    pub deliveries: u64,
    pub fanout_p50_ms: f64,
    pub fanout_p90_ms: f64,
    pub fanout_p99_ms: f64,
    pub fanout_max_ms: f64,
    pub relay_cpu_s: Option<f64>,
    /// `req-monitor-*` threads, where the OS names them (Linux).
    pub monitor_cpu_s: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LiveReport {
    pub conns: usize,
    pub subscriptions: usize,
    pub churners: usize,
    pub published: u64,
    pub rejected: u64,
    pub phases: Vec<PhaseRow>,
    pub subscribe_p50_ms: f64,
    pub subscribe_p99_ms: f64,
    pub storm_p50_ms: f64,
    pub storm_p99_ms: f64,
    pub storm_max_ms: f64,
    pub churn_reqs: u64,
    pub churn_closes: u64,
    pub churn_req_eose_p50_ms: f64,
    pub churn_req_eose_p99_ms: f64,
    /// Seconds spent waiting for deliveries to drain before the storm and at
    /// the end, which a backlogged relay lengthens.
    pub drain_secs: f64,
    pub missing: u64,
    pub unexpected: u64,
    /// Steady-phase fan-out latency, µs.
    #[serde(skip)]
    pub steady_fanout: Histogram<u64>,
}

impl LiveReport {
    pub fn mismatches(&self) -> u64 {
        self.missing + self.unexpected
    }

    pub fn steady(&self) -> &PhaseRow {
        &self.phases[0]
    }
}

/// CPU seconds the relay process has used, and its req monitor threads where
/// the OS names threads.
fn relay_cpu(pid: Option<u32>) -> (Option<f64>, Option<f64>) {
    let Some(pid) = pid else {
        return (None, None);
    };
    if cfg!(target_os = "linux") {
        // utime and stime, in clock ticks of (almost always) 1/100 s.
        let ticks = |stat: &str| -> Option<f64> {
            let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
            let utime: f64 = fields.get(11)?.parse().ok()?;
            let stime: f64 = fields.get(12)?.parse().ok()?;
            Some((utime + stime) / 100.0)
        };
        let process = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| ticks(&stat));
        let monitors = std::fs::read_dir(format!("/proc/{pid}/task"))
            .ok()
            .map(|tasks| {
                tasks
                    .flatten()
                    .filter_map(|task| {
                        let comm = std::fs::read_to_string(task.path().join("comm")).ok()?;
                        if !comm.starts_with("req-monitor") {
                            return None;
                        }
                        ticks(&std::fs::read_to_string(task.path().join("stat")).ok()?)
                    })
                    .sum()
            });
        return (process, monitors);
    }
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .ok();
    let process = output.and_then(|out| {
        // [[dd-]hh:]mm:ss[.cc]
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let (days, rest) = text.split_once('-').unwrap_or(("0", &text));
        let mut secs = days.parse::<f64>().ok()? * 86_400.0;
        let mut scale = 1.0;
        for part in rest.rsplit(':') {
            secs += part.parse::<f64>().ok()? * scale;
            scale *= 60.0;
        }
        Some(secs)
    });
    (process, None)
}

/// Record an EVENT frame. True if its event is checked.
fn record_delivery(log: &mut Vec<Delivery>, frame: &Value, base: Instant) -> Result<bool> {
    let at = base.elapsed().as_nanos() as u64;
    let slot: u8 = frame[1]
        .as_str()
        .and_then(|sid| sid.strip_prefix('s'))
        .and_then(|n| n.parse().ok())
        .context("unexpected subscription id")?;
    let (seq, checked) = frame[2]["content"]
        .as_str()
        .and_then(|c| c.strip_prefix("live "))
        .and_then(|c| c.split_once(' '))
        .and_then(|(seq, checked)| Some((seq.parse().ok()?, checked == "1")))
        .context("unexpected event content")?;
    log.push((slot, seq, at));
    Ok(checked)
}

/// Where a connection's deliveries go.
struct Sink<'a> {
    log: &'a mut Vec<Delivery>,
    base: Instant,
    /// The stable connection's received count, for checked events.
    received: Option<&'a std::sync::atomic::AtomicU64>,
}

impl Sink<'_> {
    /// Handle a frame that is not an EOSE.
    fn frame(&mut self, frame: &Value) -> Result<()> {
        match frame[0].as_str() {
            Some("EVENT") => {
                if record_delivery(self.log, frame, self.base)? {
                    if let Some(received) = self.received {
                        received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            Some("CLOSED") => anyhow::bail!("subscription refused or closed: {frame}"),
            _ => {}
        }
        Ok(())
    }
}

async fn next_frame(ws: &mut ClientConnection) -> Result<Option<Value>> {
    let message = ws.next().await.context("relay closed the connection")??;
    if !message.is_text() {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_str(message.to_text()?).context("relay frame is not JSON")?,
    ))
}

/// Read until every id in `pending` has its EOSE.
async fn await_eose(
    ws: &mut ClientConnection,
    mut pending: HashSet<String>,
    sink: &mut Sink<'_>,
) -> Result<()> {
    while !pending.is_empty() {
        let frame = tokio::time::timeout(Duration::from_secs(120), next_frame(ws))
            .await
            .context("EOSE deadline")??;
        let Some(frame) = frame else { continue };
        if frame[0] == "EOSE" {
            pending.remove(frame[1].as_str().unwrap_or_default());
        } else {
            sink.frame(&frame)?;
        }
    }
    Ok(())
}

async fn subscribe(ws: &mut ClientConnection, reqs: &[String], sink: &mut Sink<'_>) -> Result<()> {
    for req in reqs {
        ws.send(Message::Text(req.clone().into())).await?;
    }
    await_eose(ws, (0..reqs.len()).map(sub_id).collect(), sink).await
}

/// A connection whose subscriptions never change, except that it drops and
/// reconnects in the storm. Signals `ready` after each set of EOSEs.
async fn stable_conn(
    url: String,
    reqs: Vec<String>,
    base: Instant,
    tally: Arc<Tally>,
    conn: usize,
    mut phase: watch::Receiver<Phase>,
    ready: mpsc::UnboundedSender<()>,
) -> Result<ConnLog> {
    let mut log = ConnLog::default();
    let mut deliveries = Vec::new();
    let mut sink = Sink {
        log: &mut deliveries,
        base,
        received: Some(&tally.received[conn]),
    };
    let start = Instant::now();
    let mut ws = connect_retry(&url).await?;
    subscribe(&mut ws, &reqs, &mut sink).await?;
    log.subscribe_ns = nanos(start);
    let _ = ready.send(());
    let mut stormed = false;
    loop {
        tokio::select! {
            frame = next_frame(&mut ws) => {
                if let Some(frame) = frame? {
                    sink.frame(&frame)?;
                }
            }
            changed = phase.changed() => {
                changed.context("coordinator gone")?;
                let now = *phase.borrow_and_update();
                if now == Phase::Storm && !stormed {
                    stormed = true;
                    let _ = ws.close(None).await;
                    let start = Instant::now();
                    ws = connect_retry(&url).await?;
                    subscribe(&mut ws, &reqs, &mut sink).await?;
                    log.storm_ns = nanos(start);
                    let _ = ready.send(());
                } else if now == Phase::Stop {
                    let _ = ws.close(None).await;
                    log.deliveries = deliveries;
                    return Ok(log);
                }
            }
        }
    }
}

async fn timed_req(
    ws: &mut ClientConnection,
    text: String,
    slot: usize,
    log: &mut ChurnLog,
) -> Result<()> {
    let start = Instant::now();
    ws.send(Message::Text(text.into())).await?;
    let mut ignored = Vec::new();
    let mut sink = Sink {
        log: &mut ignored,
        base: start,
        received: None,
    };
    await_eose(ws, HashSet::from([sub_id(slot)]), &mut sink).await?;
    log.reqs += 1;
    log.eose.record(start.elapsed().as_micros().max(1) as u64)?;
    Ok(())
}

/// In the churn phase, keep `slots` feeds of the largest size open and cycle
/// through them: replace one with a new list (a REQ with the same id), CLOSE
/// it, REQ it again. Each REQ waits for its EOSE. After the churn the feeds
/// stay open, and their deliveries time the storm.
async fn churner(
    url: String,
    workload: Arc<Workload>,
    seed: u64,
    slots: usize,
    interval: Duration,
    base: Instant,
    mut phase: watch::Receiver<Phase>,
) -> Result<ChurnLog> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut log = ChurnLog {
        eose: histogram(),
        reqs: 0,
        closes: 0,
        deliveries: Vec::new(),
    };
    let mut ws = connect_retry(&url).await?;
    while *phase.borrow_and_update() != Phase::Churn {
        phase.changed().await.context("coordinator gone")?;
    }
    let mut req = |slot: usize| {
        let filter = workload.filter(&workload.largest_feed(&mut rng));
        json!(["REQ", sub_id(slot), filter]).to_string()
    };
    for slot in 0..slots {
        timed_req(&mut ws, req(slot), slot, &mut log).await?;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let (mut slot, mut step) = (0, 0);
    while *phase.borrow() == Phase::Churn {
        ticker.tick().await;
        if step == 1 {
            let close = json!(["CLOSE", sub_id(slot)]).to_string();
            ws.send(Message::Text(close.into())).await?;
            log.closes += 1;
        } else {
            timed_req(&mut ws, req(slot), slot, &mut log).await?;
        }
        step = (step + 1) % 3;
        if step == 0 {
            slot = (slot + 1) % slots;
        }
    }
    if step == 2 {
        // Leave every feed open.
        timed_req(&mut ws, req(slot), slot, &mut log).await?;
    }
    let mut sink = Sink {
        log: &mut log.deliveries,
        base,
        received: None,
    };
    loop {
        tokio::select! {
            frame = next_frame(&mut ws) => {
                if let Some(frame) = frame? {
                    sink.frame(&frame)?;
                }
            }
            changed = phase.changed() => {
                changed.context("coordinator gone")?;
                if *phase.borrow_and_update() == Phase::Stop {
                    let _ = ws.close(None).await;
                    return Ok(log);
                }
            }
        }
    }
}

/// Publish drafts at `rate`, waiting for each OK, until told to stop. Counts
/// the deliveries the reference matcher expects of every accepted checked
/// event in `tally`.
async fn publisher(
    url: String,
    workload: Arc<Workload>,
    seed: u64,
    rate: f64,
    base: Instant,
    tally: Arc<Tally>,
    phase: watch::Receiver<Phase>,
) -> Result<Vec<Published>> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut ws = connect_retry(&url).await?;
    let mut published = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / rate));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let now = *phase.borrow();
        let paused = matches!(now, Phase::Quiet | Phase::Stop);
        tally
            .paused
            .store(paused, std::sync::atomic::Ordering::Release);
        if now == Phase::Stop {
            let _ = ws.close(None).await;
            return Ok(published);
        }
        if paused {
            continue;
        }
        let checked = now != Phase::Storm;
        let seq = u32::try_from(published.len()).context("too many events")?;
        let draft = workload.draft(&mut rng);
        let event = workload.signed(&draft, seq, checked);
        let sent_ns = base.elapsed().as_nanos() as u64;
        ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
            .await?;
        let accepted = crate::read_ack(&mut ws, &event).await?;
        if accepted && checked {
            for (conn, specs) in workload.conns.iter().enumerate() {
                let n = specs.iter().filter(|spec| spec.matches(&draft)).count();
                tally.expected[conn].fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        published.push(Published {
            draft,
            phase: now,
            sent_ns,
            accepted,
        });
    }
}

/// Publish the root notes and wait for their OKs.
async fn publish_roots(url: &str, workload: &Workload) -> Result<()> {
    let mut ws = connect_retry(url).await?;
    for event in &workload.roots {
        ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
            .await?;
        anyhow::ensure!(crate::read_ack(&mut ws, event).await?, "root note rejected");
    }
    let _ = ws.close(None).await;
    Ok(())
}

async fn wait_ready(ready: &mut mpsc::UnboundedReceiver<()>, n: usize) -> Result<()> {
    for _ in 0..n {
        tokio::time::timeout(Duration::from_secs(300), ready.recv())
            .await
            .context("connections did not subscribe in time")?
            .context("a connection failed")?;
    }
    Ok(())
}

/// Wait until the publisher has paused and every stable connection has every
/// delivery it is owed, or two minutes pass. Returns how long it took.
async fn drain(tally: &Tally) -> Duration {
    let start = Instant::now();
    while !tally.settled() && start.elapsed() < Duration::from_secs(120) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    start.elapsed()
}

type Mark = (Duration, (Option<f64>, Option<f64>));

/// The error of the first connection task that has failed.
async fn first_failure(
    tasks: Vec<tokio::task::JoinHandle<Result<ConnLog>>>,
) -> Option<anyhow::Error> {
    for task in tasks {
        if task.is_finished() {
            match task.await {
                Ok(Err(error)) => return Some(error.context("stable connection")),
                Err(error) => return Some(error.into()),
                Ok(Ok(_)) => {}
            }
        }
    }
    None
}

pub async fn run_live(url: &str, pid: Option<u32>, opts: &Options) -> Result<LiveReport> {
    anyhow::ensure!(
        (1..=100).contains(&opts.subs_per_conn) && opts.rate > 0.0,
        "need 1 to 100 subscriptions per connection and a positive rate"
    );
    let workload = Arc::new(Workload::new(opts));
    publish_roots(url, &workload).await?;
    let base = Instant::now();
    let tally = Arc::new(Tally::new(opts.conns));
    let (phase_tx, phase_rx) = watch::channel(Phase::Setup);
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
    let stable: Vec<_> = workload
        .conns
        .iter()
        .enumerate()
        .map(|(conn, specs)| {
            let reqs = specs
                .iter()
                .enumerate()
                .map(|(slot, spec)| json!(["REQ", sub_id(slot), workload.filter(spec)]).to_string())
                .collect();
            tokio::spawn(stable_conn(
                url.to_string(),
                reqs,
                base,
                tally.clone(),
                conn,
                phase_rx.clone(),
                ready_tx.clone(),
            ))
        })
        .collect();
    drop(ready_tx);
    // Two REQs and a CLOSE per cycle.
    let steps_per_sec = opts.churn_rate * 1.5 / opts.churners.max(1) as f64;
    let interval = Duration::from_secs_f64(1.0 / steps_per_sec.max(0.001));
    let churners: Vec<_> = (0..opts.churners)
        .map(|i| {
            tokio::spawn(churner(
                url.to_string(),
                workload.clone(),
                opts.seed ^ (0x6368_0000 + i as u64),
                opts.subs_per_conn.min(10),
                interval,
                base,
                phase_rx.clone(),
            ))
        })
        .collect();
    if let Err(error) = wait_ready(&mut ready_rx, opts.conns).await {
        return Err(first_failure(stable).await.unwrap_or(error));
    }

    let publisher = tokio::spawn(publisher(
        url.to_string(),
        workload.clone(),
        opts.seed ^ 0x7075_626c,
        opts.rate,
        base,
        tally.clone(),
        phase_rx.clone(),
    ));
    let mark = || -> Mark { (base.elapsed(), relay_cpu(pid)) };
    let phase_len = Duration::from_secs(opts.phase_secs);
    let mut rows: Vec<(Phase, Mark, Mark)> = Vec::new();
    let mut drained = Duration::ZERO;
    for phase in ROWS {
        if phase == Phase::Storm {
            // Nothing checked may be in flight when connections drop.
            phase_tx.send(Phase::Quiet)?;
            drained += drain(&tally).await;
        }
        let start = mark();
        phase_tx.send(phase)?;
        if phase == Phase::Storm {
            if let Err(error) = wait_ready(&mut ready_rx, opts.conns).await {
                return Err(first_failure(stable).await.unwrap_or(error));
            }
        } else {
            tokio::time::sleep(phase_len).await;
        }
        rows.push((phase, start, mark()));
    }
    phase_tx.send(Phase::Quiet)?;
    drained += drain(&tally).await;
    phase_tx.send(Phase::Stop)?;
    let published = publisher.await??;
    let mut logs = Vec::with_capacity(stable.len());
    for task in stable {
        logs.push(task.await??);
    }
    let mut churn = Vec::with_capacity(churners.len());
    for task in churners {
        churn.push(task.await??);
    }
    analyse(&workload, opts, &published, &logs, &churn, &rows, drained)
}

fn analyse(
    workload: &Workload,
    opts: &Options,
    published: &[Published],
    logs: &[ConnLog],
    churn: &[ChurnLog],
    rows: &[(Phase, Mark, Mark)],
    drained: Duration,
) -> Result<LiveReport> {
    let mut fanout: Vec<Histogram<u64>> = ROWS.iter().map(|_| histogram()).collect();
    let mut deliveries = [0u64; 4];
    let mut events = [0u64; 4];
    for event in published {
        events[event.phase.row()] += 1;
    }
    let mut unexpected = 0u64;
    let mut sample = |seq: u32, at: u64| -> Option<&Published> {
        let event = published.get(seq as usize)?;
        let row = event.phase.row();
        deliveries[row] += 1;
        let _ = fanout[row].record(at.saturating_sub(event.sent_ns).max(1_000) / 1_000);
        Some(event)
    };
    let mut actual: Vec<Vec<(u32, u8)>> = Vec::with_capacity(logs.len());
    for log in logs {
        let mut checked = Vec::new();
        for &(slot, seq, at) in &log.deliveries {
            match sample(seq, at) {
                Some(event) if event.phase != Phase::Storm => checked.push((seq, slot)),
                Some(_) => {}
                None => unexpected += 1,
            }
        }
        checked.sort_unstable();
        actual.push(checked);
    }
    for log in churn {
        for &(_, seq, at) in &log.deliveries {
            if sample(seq, at).is_none() {
                unexpected += 1;
            }
        }
    }
    let mut missing = 0u64;
    for (conn, actual) in actual.iter().enumerate() {
        let specs = &workload.conns[conn];
        let mut expected: Vec<(u32, u8)> = Vec::new();
        for (seq, event) in published.iter().enumerate() {
            if event.phase == Phase::Storm || !event.accepted {
                continue;
            }
            for (slot, spec) in specs.iter().enumerate() {
                if spec.matches(&event.draft) {
                    expected.push((seq as u32, slot as u8));
                }
            }
        }
        // Both sorted: count what only one side has, duplicates included.
        let (mut a, mut e) = (0, 0);
        while a < actual.len() || e < expected.len() {
            match (actual.get(a), expected.get(e)) {
                (Some(x), Some(y)) if x == y => {
                    a += 1;
                    e += 1;
                }
                (Some(x), Some(y)) if x > y => {
                    missing += 1;
                    e += 1;
                }
                (Some(_), _) => {
                    unexpected += 1;
                    a += 1;
                }
                (None, _) => {
                    missing += 1;
                    e += 1;
                }
            }
        }
    }
    let ms = |h: &Histogram<u64>, q: f64| h.value_at_quantile(q) as f64 / 1_000.0;
    let phases = rows
        .iter()
        .map(|&(phase, (start, (cpu0, mon0)), (end, (cpu1, mon1)))| {
            let i = phase.row();
            let delta = |a: Option<f64>, b: Option<f64>| Some(b? - a?);
            PhaseRow {
                phase,
                secs: (end - start).as_secs_f64(),
                events: events[i],
                deliveries: deliveries[i],
                fanout_p50_ms: ms(&fanout[i], 0.5),
                fanout_p90_ms: ms(&fanout[i], 0.9),
                fanout_p99_ms: ms(&fanout[i], 0.99),
                fanout_max_ms: fanout[i].max() as f64 / 1_000.0,
                relay_cpu_s: delta(cpu0, cpu1),
                monitor_cpu_s: delta(mon0, mon1),
            }
        })
        .collect();
    let (mut subscribe, mut storm) = (histogram(), histogram());
    for log in logs {
        subscribe.record(log.subscribe_ns / 1_000)?;
        storm.record(log.storm_ns / 1_000)?;
    }
    let mut eose = histogram();
    for log in churn {
        eose.add(&log.eose)?;
    }
    Ok(LiveReport {
        conns: opts.conns,
        subscriptions: opts.conns * opts.subs_per_conn,
        churners: opts.churners,
        published: published.len() as u64,
        rejected: published.iter().filter(|e| !e.accepted).count() as u64,
        phases,
        subscribe_p50_ms: ms(&subscribe, 0.5),
        subscribe_p99_ms: ms(&subscribe, 0.99),
        storm_p50_ms: ms(&storm, 0.5),
        storm_p99_ms: ms(&storm, 0.99),
        storm_max_ms: storm.max() as f64 / 1_000.0,
        churn_reqs: churn.iter().map(|log| log.reqs).sum(),
        churn_closes: churn.iter().map(|log| log.closes).sum(),
        churn_req_eose_p50_ms: ms(&eose, 0.5),
        churn_req_eose_p99_ms: ms(&eose, 0.99),
        drain_secs: drained.as_secs_f64(),
        missing,
        unexpected,
        steady_fanout: fanout.swap_remove(0),
    })
}

pub fn render_live_markdown(report: &LiveReport) -> String {
    let churn_secs = report.phases[1].secs.max(f64::MIN_POSITIVE);
    let mut s = format!(
        "\n### live_subscriptions\n\n{} connections with {} subscriptions, {} churners. {} events published ({} rejected). Deliveries outside the storm checked: {} missing, {} unexpected.\n\n",
        report.conns,
        report.subscriptions,
        report.churners,
        report.published,
        report.rejected,
        report.missing,
        report.unexpected,
    );
    s.push_str("| phase | secs | events | deliveries | fan-out p50 ms | p90 ms | p99 ms | max ms | relay CPU s | monitor CPU s |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    let opt = |v: Option<f64>| v.map_or_else(|| "n/a".to_string(), |v| format!("{v:.2}"));
    for row in &report.phases {
        s.push_str(&format!(
            "| {:?} | {:.1} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} |\n",
            row.phase,
            row.secs,
            row.events,
            row.deliveries,
            row.fanout_p50_ms,
            row.fanout_p90_ms,
            row.fanout_p99_ms,
            row.fanout_max_ms,
            opt(row.relay_cpu_s),
            opt(row.monitor_cpu_s),
        ));
    }
    s.push_str(&format!(
        "\nSubscribe (connect to last EOSE) p50 {:.1} ms, p99 {:.1} ms. Storm, per connection: p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms. Churn: {} REQs ({:.0}/s) and {} CLOSEs ({:.0}/s), REQ to EOSE p50 {:.2} ms, p99 {:.2} ms. Drain waits: {:.2} s.\n",
        report.subscribe_p50_ms,
        report.subscribe_p99_ms,
        report.storm_p50_ms,
        report.storm_p99_ms,
        report.storm_max_ms,
        report.churn_reqs,
        report.churn_reqs as f64 / churn_secs,
        report.churn_closes,
        report.churn_closes as f64 / churn_secs,
        report.churn_req_eose_p50_ms,
        report.churn_req_eose_p99_ms,
        report.drain_secs,
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Options {
        Options {
            authors: 2_000,
            conns: 20,
            subs_per_conn: 10,
            min_authors: 20,
            max_authors: 60,
            events: 300,
            rate: 100.0,
            phase_secs: 1,
            churners: 2,
            churn_rate: 40.0,
            seed: 7,
        }
    }

    #[test]
    fn monitor_index_matches_the_reference() {
        let report = run_index(&small()).unwrap();
        assert_eq!(report.mismatches, 0);
        assert!(report.checked_events > 0 && report.recipients_per_event > 0.0);
        assert!(render_index_markdown(&report).contains("| churn: CLOSE (60 authors) |"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_subscriptions_deliver_exactly_outside_the_storm() {
        let dir = tempfile::tempdir().unwrap();
        let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = wok_relay::Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        cfg.relay.port = addr.port();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.enabled = false;
        let handle = wok_relay::start(env, cfg).unwrap();
        let server = handle.clone();
        tokio::spawn(async move {
            let _ = wok_ws::serve_listener(server, listener).await;
        });
        let report = run_live(&format!("ws://{addr}"), None, &small())
            .await
            .unwrap();
        handle.request_shutdown();
        assert_eq!((report.missing, report.unexpected), (0, 0), "{report:#?}");
        assert!(report.steady().deliveries > 0);
        assert!(report.churn_reqs > 0 && report.churn_closes > 0);
        assert!(render_live_markdown(&report).contains("| Storm |"));
    }
}
