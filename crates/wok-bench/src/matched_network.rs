//! Matched fixed-arrival WebSocket requests and publications against a disposable relay.
//! Deadlines are absolute, arrivals never wait for earlier acknowledgements/EOSE,
//! and incomplete operations remain visible and censored at the common deadline.
use super::*;
use anyhow::ensure;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant as Clock;
use tokio_tungstenite::tungstenite::Message;

const AUTHORS: usize = 2048;
const POOL: usize = 64;
const PENDING: usize = 4096;
const SHAPES: [&str; 4] = ["author", "feed500", "tag", "id"];

type Shared<T> = Arc<Mutex<Vec<T>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(super) enum WriterAuthors {
    /// Preserve the original independent 32-author timed-write key domain.
    Disjoint,
    /// Cycle through every author named by the historical single-author plans.
    Queried,
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}
fn since(origin: Clock) -> u64 {
    micros(Clock::now().saturating_duration_since(origin))
}
fn due(seq: u64, rate: f64) -> Duration {
    Duration::from_secs_f64(seq as f64 / rate)
}
fn pick(seq: u64, workers: usize) -> usize {
    let shape = ((seq / workers as u64 + seq % workers as u64) % 4) as usize;
    let mixed = seq.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(23) ^ (seq >> 7);
    (mixed as usize % POOL) * 4 + shape
}
fn keys(seed: u64, domain: &[u8], count: usize) -> Vec<secp256k1::Keypair> {
    (0..count)
        .map(|i| {
            let mut nonce = 0u64;
            loop {
                let mut h = Sha256::new();
                h.update(domain);
                h.update(seed.to_le_bytes());
                h.update((i as u64).to_le_bytes());
                h.update(nonce.to_le_bytes());
                if let Ok(secret) = secp256k1::SecretKey::from_slice(&h.finalize()) {
                    break secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret);
                }
                nonce += 1;
            }
        })
        .collect()
}
fn signed(
    seq: u64,
    count: u64,
    anchor: u64,
    seed: u64,
    keys: &[secp256k1::Keypair],
    timed: bool,
) -> Value {
    let key = &keys[seq as usize % keys.len()];
    let pubkey = hex::encode(key.x_only_public_key().0.serialize());
    // Unique ordinal in signed content prevents deduplication even when timestamps tie.
    let created_at = if timed {
        anchor
    } else {
        anchor - 1 - (count - 1 - seq) / 100
    };
    let kind = if seq.is_multiple_of(10) { 7 } else { 1 };
    let bytes = 32 + (seq.wrapping_mul(7919) % 2017) as usize;
    let mut event = json!({"pubkey":pubkey,"created_at":created_at,"kind":kind,
        "tags":[["t",format!("matched-topic-{}",seq % 64)],
                 ["p",hex::encode(keys[(seq as usize + 17) % keys.len()].x_only_public_key().0.serialize())]],
        "content":format!("network-matched seed={seed} timed={timed} seq={seq} {}", "x".repeat(bytes))});
    let id = wok_event::event_id_hash(&event).expect("generated public event");
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(
        secp256k1::SECP256K1
            .sign_schnorr_no_aux_rand(&id, key)
            .as_ref()
    ));
    event
}

fn writer_keys(
    mode: WriterAuthors,
    seed: u64,
    filters: &[(&str, Value)],
) -> Result<Vec<secp256k1::Keypair>> {
    if mode == WriterAuthors::Disjoint {
        return Ok(keys(seed, b"matched-network-timed-v1", 32));
    }
    let mut available: HashMap<_, _> = keys(seed, b"matched-network-corpus-v1", AUTHORS)
        .into_iter()
        .map(|key| (hex::encode(key.x_only_public_key().0.serialize()), key))
        .collect();
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for (_, filter) in filters.iter().filter(|(shape, _)| *shape == "author") {
        let author = filter["authors"]
            .as_array()
            .filter(|authors| authors.len() == 1)
            .and_then(|authors| authors[0].as_str())
            .context("queried writer mode requires single-author historical plans")?;
        if seen.insert(author.to_owned()) {
            selected.push(available.remove(author).with_context(|| {
                format!("queried writer author does not belong to --seed {seed}'s matched corpus")
            })?);
        }
    }
    ensure!(
        selected.len() == POOL,
        "queried writers need 64 distinct author plans"
    );
    for (_, filter) in filters.iter().filter(|(shape, _)| *shape == "feed500") {
        ensure!(
            filter["authors"].as_array().is_some_and(|authors| authors
                .iter()
                .any(|author| author.as_str().is_some_and(|author| seen.contains(author)))),
            "queried writers must overlap every feed500 plan"
        );
    }
    Ok(selected)
}

fn annotate_writer_workload(
    report: &mut Value,
    args: &Args,
    filters: &[(&str, Value)],
    keyring: &[secp256k1::Keypair],
    events: &[Value],
) -> Result<()> {
    // Default reports and all existing input hashes keep their original bytes.
    if args.matched_writer_authors == WriterAuthors::Disjoint {
        return Ok(());
    }
    let authors: std::collections::BTreeSet<_> = keyring
        .iter()
        .map(|key| hex::encode(key.x_only_public_key().0.serialize()))
        .collect();
    let author_set_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&authors)?));
    let mut overlaps = serde_json::Map::new();
    for shape in SHAPES {
        let plans: Vec<_> = filters.iter().filter(|(name, _)| *name == shape).collect();
        let counts: Vec<_> = plans
            .iter()
            .filter_map(|(_, filter)| filter["authors"].as_array())
            .map(|selected| {
                selected
                    .iter()
                    .filter(|author| {
                        author
                            .as_str()
                            .is_some_and(|author| authors.contains(author))
                    })
                    .count()
            })
            .collect();
        overlaps.insert(shape.into(), json!({
            "plans":plans.len(),"author_filter_plans":counts.len(),
            "plans_with_writer_authors":counts.iter().filter(|&&count|count>0).count(),
            "minimum_writer_authors":counts.iter().min(),"maximum_writer_authors":counts.iter().max()
        }));
    }
    let mut event_ids = Sha256::new();
    for event in events {
        event_ids.update(
            event["id"]
                .as_str()
                .context("generated write has no ID")?
                .as_bytes(),
        );
    }
    let writer = json!({"mode":args.matched_writer_authors,"author_count":authors.len(),
        "pubkey_set_sha256":author_set_sha256,"query_shape_overlap":overlaps,
        "overlap_scope":"public author-key intersection, ignoring until; tag/id plans have no author restriction",
        "timed_event_ids_sha256":hex::encode(event_ids.finalize())});
    let mut workload = json!({"format":"network-matched-queried-authors-v1",
        "matched_writer_authors":args.matched_writer_authors,
        "corpus_sha256":report["corpus_sha256"],"query_plan_sha256":report["query_plan_sha256"],
        "history_cutoff":report["history_cutoff"],"seed":args.seed,
        "offered_writes":events.len(),"write_rate":args.send_rate,"read_rate":args.read_rate,
        "read_connections":args.read_connections,"publish_connections":args.publish_connections,
        "drain_secs":args.drain_secs,"writer_authors":writer});
    workload.sort_all_objects();
    report["matched_writer_authors"] = json!(args.matched_writer_authors);
    report["workload_sha256"] = json!(hex::encode(Sha256::digest(serde_json::to_vec(&workload)?)));
    report["workload"] = workload;
    Ok(())
}
fn generate(args: &Args) -> Result<()> {
    let n = args
        .events
        .context("matched_network_generate requires --events")?;
    ensure!(
        n >= AUTHORS as u64,
        "generated corpus needs at least2048 events"
    );
    let anchor = args.base_timestamp.context("timestamp anchor missing")?;
    ensure!(anchor > n / 100 + 1, "timestamp anchor too early");
    let path = args.out.join("corpus.jsonl");
    ensure!(!path.exists(), "refusing to overwrite existing corpus");
    let keyring = keys(args.seed, b"matched-network-corpus-v1", AUTHORS);
    let mut output = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&path)?);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let batch = 8192u64;
    for start in (0..n).step_by(batch as usize) {
        let end = (start + batch).min(n);
        let chunk = (end - start).div_ceil(threads as u64).max(1);
        let lines = std::thread::scope(|scope| {
            let tasks: Vec<_> = (start..end)
                .step_by(chunk as usize)
                .map(|first| {
                    let keyring = &keyring;
                    scope.spawn(move || {
                        (first..(first + chunk).min(end))
                            .map(|seq| {
                                wok_event::json::to_tao_string(&signed(
                                    seq, n, anchor, args.seed, keyring, false,
                                ))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            tasks
                .into_iter()
                .flat_map(|task| task.join().expect("corpus signer panicked"))
                .collect::<Vec<_>>()
        });
        for line in lines {
            writeln!(output, "{line}")?;
        }
        if start % 1_000_000 < batch {
            eprintln!("signed {} / {n}", end);
        }
    }
    output.flush()?;
    drop(output);
    let manifest = json!({"format":"network-public-corpus-v1","events":n,"authors":AUTHORS,
        "seed":args.seed,"base_timestamp":anchor,"cutoff":anchor-1,"sha256":sha256_file(&path)?,
        "bytes":std::fs::metadata(&path)?.len(),"kinds":[1,7],
        "method":"unique signed public append-only events; bounded parallel batches;32–2048byte content body plus ordinal"});
    std::fs::write(
        args.out.join("corpus-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn history_ordered(actual: &[Value]) -> bool {
    actual.iter().all(|event| event["created_at"].is_u64())
        && actual
            .windows(2)
            .all(|pair| pair[0]["created_at"].as_u64() >= pair[1]["created_at"].as_u64())
}
fn history_matches(expected: &corpus::OwnedExpected, actual: &[Value]) -> bool {
    history_ordered(actual) && expected.matches(actual)
}

struct Plan {
    shape: &'static str,
    filter: Value,
    wire_filter: String,
    expected: corpus::OwnedExpected,
}
#[derive(Serialize)]
struct WriteRecord {
    seq: u64,
    conn: usize,
    id: String,
    due_us: u64,
    send_started_us: Option<u64>,
    sent_us: Option<u64>,
    reply_us: Option<u64>,
    accepted: Option<bool>,
    message: Option<String>,
}
#[derive(Serialize)]
struct QueryRecord {
    seq: u64,
    conn: usize,
    plan: usize,
    shape: &'static str,
    due_us: u64,
    send_started_us: Option<u64>,
    sent_us: Option<u64>,
    first_event_us: Option<u64>,
    eose_us: Option<u64>,
    received: u64,
    matches: Option<bool>,
}
#[derive(Default)]
struct LaneResult {
    errors: Vec<String>,
    notices: u64,
}

async fn publisher(
    socket: WebSocketClient,
    frames: Vec<String>,
    index: HashMap<String, usize>,
    records: Shared<WriteRecord>,
    origin: Clock,
    hard: Clock,
) -> LaneResult {
    let (mut sink, mut stream) = socket.split();
    let (done_tx, mut done_rx) = watch::channel(false);
    let send_records = records.clone();
    let send = async {
        let mut errors = Vec::new();
        for (i, frame) in frames.into_iter().enumerate() {
            let deadline = origin + Duration::from_micros(send_records.lock().unwrap()[i].due_us);
            tokio::time::sleep_until(deadline).await;
            send_records.lock().unwrap()[i].send_started_us = Some(since(origin));
            match tokio::time::timeout_at(hard, sink.send(Message::Text(frame.into()))).await {
                Ok(Ok(())) => send_records.lock().unwrap()[i].sent_us = Some(since(origin)),
                other => {
                    errors.push(format!("publication send failed: {other:?}"));
                    break;
                }
            }
        }
        let _ = tokio::time::timeout_at(hard, done_rx.changed()).await;
        let _ = tokio::time::timeout_at(hard + Duration::from_secs(1), sink.close()).await;
        errors
    };
    let receive = async {
        let mut result = LaneResult::default();
        let mut replies = 0usize;
        loop {
            let message = match tokio::time::timeout_at(hard, stream.next()).await {
                Ok(Some(Ok(message))) => message,
                other => {
                    result
                        .errors
                        .push(format!("publication receive ended: {other:?}"));
                    break;
                }
            };
            let at = since(origin);
            if !message.is_text() {
                if message.is_close() {
                    result.errors.push("publisher disconnected".into());
                    break;
                }
                continue;
            }
            let reply: Value = match serde_json::from_str(message.to_text().unwrap_or_default()) {
                Ok(value) => value,
                Err(e) => {
                    result
                        .errors
                        .push(format!("malformed publisher frame: {e}"));
                    continue;
                }
            };
            match reply[0].as_str() {
                Some("AUTH") => continue,
                Some("NOTICE") => {
                    result.notices += 1;
                    result.errors.push(format!("publisher NOTICE: {reply}"));
                }
                Some("OK") => {
                    let Some(i) = reply[1].as_str().and_then(|id| index.get(id)).copied() else {
                        result
                            .errors
                            .push(format!("unknown publication ACK: {reply}"));
                        continue;
                    };
                    {
                        let mut rows = records.lock().unwrap();
                        let row = &mut rows[i];
                        if !reply.as_array().is_some_and(|a| a.len() == 4)
                            || !reply[2].is_boolean()
                            || !reply[3].is_string()
                            || row.reply_us.is_some()
                            || row.send_started_us.is_none()
                        {
                            result
                                .errors
                                .push(format!("malformed/duplicate/premature ACK: {reply}"));
                            continue;
                        }
                        row.reply_us = Some(at);
                        row.accepted = reply[2].as_bool();
                        row.message = reply[3].as_str().map(str::to_owned);
                        replies += 1;
                    }
                    if replies == index.len() {
                        // Capture duplicate ACKs queued behind the final legitimate reply.
                        let tail = Clock::now() + Duration::from_millis(300);
                        while let Ok(Some(message)) =
                            tokio::time::timeout_at(tail.min(hard), stream.next()).await
                        {
                            if let Ok(message) = message {
                                if message.is_text() {
                                    result
                                        .errors
                                        .push(format!("extra publisher frame: {message}"));
                                }
                            }
                        }
                        break;
                    }
                }
                _ => result
                    .errors
                    .push(format!("unexpected publisher frame: {reply}")),
            }
        }
        let _ = done_tx.send(true);
        result
    };
    let (errors, mut result) = tokio::join!(send, receive);
    result.errors.extend(errors);
    result
}

async fn reader(
    socket: WebSocketClient,
    plans: Arc<Vec<Plan>>,
    records: Shared<QueryRecord>,
    index: HashMap<String, usize>,
    origin: Clock,
    hard: Clock,
) -> LaneResult {
    let (mut sink, mut stream) = socket.split();
    let (close_tx, mut close_rx) = mpsc::unbounded_channel::<String>();
    let (done_tx, mut done_rx) = watch::channel(false);
    let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let send_records = records.clone();
    let send_pending = pending.clone();
    let send_plans = plans.clone();
    let count = records.lock().unwrap().len();
    let send = async {
        let mut errors = Vec::new();
        for i in 0..count {
            let (deadline, seq, plan) = {
                let rows = send_records.lock().unwrap();
                let r = &rows[i];
                (origin + Duration::from_micros(r.due_us), r.seq, r.plan)
            };
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    close = close_rx.recv() => if let Some(sid)=close {
                        if tokio::time::timeout_at(hard,sink.send(Message::Text(json!(["CLOSE",sid]).to_string().into()))).await.is_err() {
                            errors.push("CLOSE send timed out".into()); break;
                        }
                    },
                }
            }
            while let Ok(sid) = close_rx.try_recv() {
                match tokio::time::timeout_at(
                    hard,
                    sink.send(Message::Text(json!(["CLOSE", sid]).to_string().into())),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    other => errors.push(format!("CLOSE send failed: {other:?}")),
                }
            }
            if send_pending.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= PENDING {
                errors.push(format!(
                    "query pending safety bound {PENDING} exceeded; trial invalid"
                ));
                break;
            }
            let frame = format!("[\"REQ\",\"q{seq}\",{}]", send_plans[plan].wire_filter);
            send_records.lock().unwrap()[i].send_started_us = Some(since(origin));
            match tokio::time::timeout_at(hard, sink.send(Message::Text(frame.into()))).await {
                Ok(Ok(())) => send_records.lock().unwrap()[i].sent_us = Some(since(origin)),
                other => {
                    errors.push(format!("REQ send failed: {other:?}"));
                    break;
                }
            }
        }
        loop {
            tokio::select! {
                _=tokio::time::sleep_until(hard)=>break,
                _=done_rx.changed()=>break,
                close=close_rx.recv()=>if let Some(sid)=close {
                    let _=tokio::time::timeout_at(hard,sink.send(Message::Text(json!(["CLOSE",sid]).to_string().into()))).await;
                },
            }
        }
        while let Ok(sid) = close_rx.try_recv() {
            let _ = tokio::time::timeout_at(
                hard,
                sink.send(Message::Text(json!(["CLOSE", sid]).to_string().into())),
            )
            .await;
        }
        let _ = tokio::time::timeout_at(hard + Duration::from_secs(1), sink.close()).await;
        errors
    };
    let receive = async {
        let mut result = LaneResult::default();
        let mut completed = 0usize;
        let mut actual: HashMap<usize, Vec<Value>> = HashMap::new();
        loop {
            let message = match tokio::time::timeout_at(hard, stream.next()).await {
                Ok(Some(Ok(message))) => message,
                other => {
                    result
                        .errors
                        .push(format!("query receive ended: {other:?}"));
                    break;
                }
            };
            let at = since(origin);
            if !message.is_text() {
                if message.is_close() {
                    result.errors.push("query disconnected".into());
                    break;
                }
                continue;
            }
            let reply: Value = match serde_json::from_str(message.to_text().unwrap_or_default()) {
                Ok(value) => value,
                Err(e) => {
                    result.errors.push(format!("malformed query frame: {e}"));
                    continue;
                }
            };
            if reply[0] == "AUTH" {
                continue;
            }
            if reply[0] == "NOTICE" {
                result.notices += 1;
                result.errors.push(format!("query NOTICE: {reply}"));
                continue;
            }
            let Some(i) = reply[1].as_str().and_then(|sid| index.get(sid)).copied() else {
                result.errors.push(format!("unknown subscription: {reply}"));
                continue;
            };
            let mut rows = records.lock().unwrap();
            let row = &mut rows[i];
            if row.send_started_us.is_none() || row.eose_us.is_some() {
                result.errors.push(format!(
                    "premature/late/duplicate subscription frame: {reply}"
                ));
                continue;
            }
            match reply[0].as_str() {
                Some("EVENT") if reply.as_array().is_some_and(|a| a.len() == 3) => {
                    row.first_event_us.get_or_insert(at);
                    row.received += 1;
                    let values = actual.entry(i).or_default();
                    if values.len() < 51 {
                        values.push(reply[2].clone());
                    } else {
                        row.matches = Some(false);
                    }
                }
                Some("EOSE") if reply.as_array().is_some_and(|a| matches!(a.len(), 2 | 3)) => {
                    row.eose_us = Some(at);
                    let values = actual.remove(&i).unwrap_or_default();
                    row.matches = Some(
                        row.received <= 50 && history_matches(&plans[row.plan].expected, &values),
                    );
                    pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = close_tx.send(format!("q{}", row.seq));
                    completed += 1;
                    if completed == count {
                        break;
                    }
                }
                _ => result
                    .errors
                    .push(format!("unexpected/refused query frame: {reply}")),
            }
        }
        if completed == count {
            let tail = (Clock::now() + Duration::from_millis(300)).min(hard);
            while let Ok(Some(message)) = tokio::time::timeout_at(tail, stream.next()).await {
                match message {
                    Ok(message) if message.is_text() => {
                        let text = message.to_text().unwrap_or_default();
                        if !serde_json::from_str::<Value>(text).is_ok_and(|v| v[0] == "AUTH") {
                            result
                                .errors
                                .push(format!("extra query frame after final EOSE: {text}"));
                        }
                    }
                    Err(error) => result.errors.push(format!("query tail error: {error}")),
                    _ => {}
                }
            }
        }
        let _ = done_tx.send(true);
        result
    };
    let (errors, mut result) = tokio::join!(send, receive);
    result.errors.extend(errors);
    result
}

fn histogram(values: impl Iterator<Item = u64>) -> Result<Value> {
    let mut h = Histogram::<u64>::new(3)?;
    for value in values {
        h.record(value.max(1))?;
    }
    Ok(
        json!({"count":h.len(),"p50_us":h.value_at_quantile(0.5),"p90_us":h.value_at_quantile(0.9),
        "p99_us":h.value_at_quantile(0.99),"max_us":h.max()}),
    )
}
fn write_jsonl<T: Serialize>(path: &Path, rows: &[T]) -> Result<()> {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        writeln!(file)?;
    }
    file.flush()?;
    Ok(())
}
fn query_summary(rows: &[QueryRecord], shape: &str, censored: u64) -> Result<Value> {
    let selected: Vec<_> = rows.iter().filter(|r| r.shape == shape).collect();
    Ok(json!({"shape":shape,"offered":selected.len(),
        "completed":selected.iter().filter(|r|r.eose_us.is_some()).count(),
        "censored":selected.iter().filter(|r|r.eose_us.is_none()).count(),
        "scheduled_to_eose":histogram(selected.iter().map(|r|r.eose_us.unwrap_or(censored).saturating_sub(r.due_us)))?,
        "wire_to_eose":histogram(selected.iter().filter_map(|r|r.send_started_us.map(|s|r.eose_us.unwrap_or(censored).saturating_sub(s))))?,
        "first_event_censored":selected.iter().filter(|r|r.first_event_us.is_none()).count(),
        "scheduled_to_first_event":histogram(selected.iter().map(|r|r.first_event_us.unwrap_or(censored).saturating_sub(r.due_us)))?,
        "wire_to_first_event":histogram(selected.iter().filter_map(|r|r.send_started_us.map(|s|r.first_event_us.unwrap_or(censored).saturating_sub(s))))?,
        "send_lateness":histogram(selected.iter().filter_map(|r|r.send_started_us.map(|s|s.saturating_sub(r.due_us))))?}))
}

async fn verify_pool(url: &str, plans: &[Plan], retained: u64, cutoff: u64) -> Result<Value> {
    let mut socket = connect_retry(url).await?;
    for (i, plan) in plans.iter().enumerate() {
        let sid = format!("pre{i}");
        socket
            .send(Message::Text(
                json!(["REQ", sid, plan.filter]).to_string().into(),
            ))
            .await?;
        let actual = read_history(&mut socket, &sid).await?;
        ensure!(
            history_matches(&plan.expected, &actual),
            "preload query mismatch for {} pool{i}",
            plan.shape
        );
        socket
            .send(Message::Text(json!(["CLOSE", sid]).to_string().into()))
            .await?;
    }
    socket
        .send(Message::Text(
            json!(["COUNT","pre-count",{"until":cutoff}])
                .to_string()
                .into(),
        ))
        .await?;
    // A timed-out COUNT can continue running in the relay after socket close,
    // holding storage locks into the measured workload. Wait for its terminal
    // response before starting arrivals; a timeout invalidates preflight.
    let count_started = Clock::now();
    let count = tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let message = socket.next().await.context("COUNT connection closed")??;
            if !message.is_text() {
                continue;
            }
            let reply: Value = serde_json::from_str(message.to_text()?)?;
            if reply[0] == "COUNT" && reply[1] == "pre-count" {
                ensure!(
                    reply[2]["limited"] != true,
                    "preload COUNT is limited: {reply}"
                );
                return Ok::<_, anyhow::Error>(Some(
                    reply[2]["count"]
                        .as_u64()
                        .context("malformed COUNT count")?,
                ));
            }
            if matches!(reply[0].as_str(), Some("CLOSED" | "NOTICE")) {
                return Ok(None);
            }
        }
    })
    .await
    .context(
        "preload COUNT did not finish within600s; refusing to measure with pending preflight work",
    )??;
    let supported = count;
    if let Some(count) = supported {
        ensure!(
            count == retained,
            "COUNT preload cardinality {count} != {retained}"
        );
    }
    let _ = socket.close(None).await;
    Ok(
        json!({"queries_verified":plans.len(),"count_supported":supported.is_some(),"count":supported,
               "count_terminal_response":true,"count_elapsed_secs":count_started.elapsed().as_secs_f64(),
               "measurement_starts_after_count":true}),
    )
}

async fn postcheck(url: &str, events: &[Value], rows: &[WriteRecord]) -> Result<Value> {
    let mut socket = connect_retry(url).await?;
    let mut missing = 0;
    let mut changed = 0;
    let mut refused_stored = 0;
    let mut stored = 0;
    let mut unanswered_stored = 0;
    for (chunk, values) in events.chunks(100).enumerate() {
        if chunk % 100 == 0 {
            eprintln!("postcheck IDs {} / {}", chunk * 100, events.len());
        }
        let ids: Vec<_> = values.iter().map(|v| v["id"].clone()).collect();
        let sid = format!("post{chunk}");
        socket
            .send(Message::Text(
                json!(["REQ",sid,{"ids":ids,"limit":100}])
                    .to_string()
                    .into(),
            ))
            .await?;
        let actual = read_history(&mut socket, &sid).await?;
        let wanted: HashMap<_, _> = values
            .iter()
            .map(|v| (v["id"].as_str().unwrap(), v))
            .collect();
        let mut seen = HashSet::new();
        for value in &actual {
            let id = value["id"].as_str().unwrap_or_default();
            if !seen.insert(id.to_owned())
                || wanted.get(id).is_none_or(|expected| **expected != *value)
            {
                changed += 1;
            }
        }
        for (offset, value) in values.iter().enumerate() {
            let row = &rows[chunk * 100 + offset];
            let exists = seen.contains(value["id"].as_str().unwrap());
            if exists {
                stored += 1;
            }
            match (row.accepted, exists) {
                (Some(true), false) => missing += 1,
                (Some(false), true) => refused_stored += 1,
                (None, true) => unanswered_stored += 1,
                _ => {}
            }
        }
        socket
            .send(Message::Text(json!(["CLOSE", sid]).to_string().into()))
            .await?;
    }
    let _ = socket.close(None).await;
    Ok(
        json!({"queried":events.len(),"stored":stored,"acked_missing":missing,"changed_or_unexpected":changed,
        "refused_stored":refused_stored,"unanswered_stored":unanswered_stored,"mismatches":missing+changed+refused_stored}),
    )
}

async fn run(args: &Args, corpus: &corpus::Corpus, path: &Path) -> Result<()> {
    let url = args
        .target_url
        .as_deref()
        .context("matched_network requires --target-url")?;
    let n = args.events.unwrap_or(80_000);
    ensure!(
        n > 0
            && args.send_rate.is_finite()
            && args.send_rate > 0.0
            && args.read_rate > 0
            && args.read_connections > 0
            && args.publish_connections > 0,
        "positive rates/counts required"
    );
    ensure!(
        args.matched_writer_authors == WriterAuthors::Disjoint || n >= POOL as u64,
        "queried writer mode requires at least 64 writes to exercise every selected author"
    );
    let (cutoff, filters) = corpus.matched_filters(POOL)?;
    ensure!(
        cutoff < unix_timestamp()?,
        "seed cutoff leaves no non-future timestamp for timed writes"
    );
    let plans: Arc<Vec<_>> = Arc::new(
        filters
            .iter()
            .map(|(shape, filter)| Plan {
                shape,
                filter: filter.clone(),
                wire_filter: filter.to_string(),
                expected: corpus.expected(filter).owned(),
            })
            .collect(),
    );
    let plan_hash = hex::encode(Sha256::digest(serde_json::to_vec(&filters)?));
    let keyring = writer_keys(args.matched_writer_authors, args.seed, &filters)?;
    let events = Arc::new(
        (0..n)
            .map(|seq| signed(seq, n, cutoff + 1, args.seed, &keyring, true))
            .collect::<Vec<_>>(),
    );
    write_jsonl(&args.out.join("timedwrites.jsonl"), &events)?;
    eprintln!("verifying256 historical pool queries and optional COUNT");
    let preflight = verify_pool(url, &plans, corpus.retained(), cutoff).await?;
    let horizon = due(n, args.send_rate);
    let read_count = (horizon.as_secs_f64() * args.read_rate as f64).floor() as u64;
    ensure!(read_count > 0, "empty read offer horizon");
    let mut publisher_sockets = Vec::new();
    let mut reader_sockets = Vec::new();
    for _ in 0..args.publish_connections {
        let ClientConnection::WebSocket(socket) = connect_retry(url).await? else {
            anyhow::bail!("requires WebSocket")
        };
        publisher_sockets.push(*socket);
    }
    for _ in 0..args.read_connections {
        let ClientConnection::WebSocket(socket) = connect_retry(url).await? else {
            anyhow::bail!("requires WebSocket")
        };
        reader_sockets.push(*socket);
    }
    let mut publisher_specs = Vec::new();
    let mut reader_specs = Vec::new();
    let mut write_lanes = Vec::new();
    let mut read_lanes = Vec::new();
    let mut tasks = Vec::new();
    for (conn, socket) in publisher_sockets.into_iter().enumerate() {
        let rows: Shared<_> = Arc::new(Mutex::new(
            (conn as u64..n)
                .step_by(args.publish_connections)
                .map(|seq| WriteRecord {
                    seq,
                    conn,
                    id: events[seq as usize]["id"].as_str().unwrap().into(),
                    due_us: micros(due(seq, args.send_rate)),
                    send_started_us: None,
                    sent_us: None,
                    reply_us: None,
                    accepted: None,
                    message: None,
                })
                .collect(),
        ));
        write_lanes.push(rows.clone());
        let frames = rows
            .lock()
            .unwrap()
            .iter()
            .map(|r| json!(["EVENT", events[r.seq as usize]]).to_string())
            .collect();
        let index = rows
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();
        publisher_specs.push((socket, frames, index, rows));
    }
    for (conn, socket) in reader_sockets.into_iter().enumerate() {
        let rows: Shared<_> = Arc::new(Mutex::new(
            (conn as u64..read_count)
                .step_by(args.read_connections)
                .map(|seq| {
                    let plan = pick(seq, args.read_connections);
                    QueryRecord {
                        seq,
                        conn,
                        plan,
                        shape: plans[plan].shape,
                        due_us: micros(due(seq, args.read_rate as f64)),
                        send_started_us: None,
                        sent_us: None,
                        first_event_us: None,
                        eose_us: None,
                        received: 0,
                        matches: None,
                    }
                })
                .collect(),
        ));
        read_lanes.push(rows.clone());
        let index = rows
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("q{}", r.seq), i))
            .collect();
        reader_specs.push((socket, rows, index));
    }
    eprintln!(
        "matched network start: {n} writes at{}/s, {read_count} queries at{}/s, horizon{:.3}s",
        args.send_rate,
        args.read_rate,
        horizon.as_secs_f64()
    );
    let origin = Clock::now() + Duration::from_millis(200);
    let hard = origin + horizon + Duration::from_secs(args.drain_secs);
    for (socket, frames, index, rows) in publisher_specs {
        tasks.push(tokio::spawn(publisher(
            socket, frames, index, rows, origin, hard,
        )));
    }
    for (socket, rows, index) in reader_specs {
        tasks.push(tokio::spawn(reader(
            socket,
            plans.clone(),
            rows,
            index,
            origin,
            hard,
        )));
    }
    let mut errors = Vec::new();
    let mut notices = 0;
    for task in tasks {
        match task.await {
            Ok(result) => {
                errors.extend(result.errors);
                notices += result.notices;
            }
            Err(e) => errors.push(format!("worker panicked: {e}")),
        }
    }
    let finished = since(origin);
    let censor = micros(horizon + Duration::from_secs(args.drain_secs));
    let mut writes: Vec<_> = write_lanes
        .into_iter()
        .flat_map(|rows| Arc::try_unwrap(rows).ok().unwrap().into_inner().unwrap())
        .collect();
    writes.sort_unstable_by_key(|r| r.seq);
    let mut queries: Vec<_> = read_lanes
        .into_iter()
        .flat_map(|rows| Arc::try_unwrap(rows).ok().unwrap().into_inner().unwrap())
        .collect();
    queries.sort_unstable_by_key(|r| r.seq);
    write_jsonl(&args.out.join("write-outcomes.jsonl"), &writes)?;
    write_jsonl(&args.out.join("query-outcomes.jsonl"), &queries)?;
    eprintln!("network arrivals/drain finished; checking all{n} timed IDs outside measurement");
    let post = match postcheck(url, &events, &writes).await {
        Ok(value) => value,
        Err(e) => {
            errors.push(format!("postcheck failed: {e:#}"));
            json!({"mismatches":1,"error":format!("{e:#}")})
        }
    };
    let accepted = writes.iter().filter(|r| r.accepted == Some(true)).count();
    let rejected = writes.iter().filter(|r| r.accepted == Some(false)).count();
    let sent = writes.iter().filter(|r| r.sent_us.is_some()).count();
    let answered = writes.iter().filter(|r| r.reply_us.is_some()).count();
    let read_sent = queries.iter().filter(|r| r.sent_us.is_some()).count();
    let completed = queries.iter().filter(|r| r.eose_us.is_some()).count();
    let mismatches = queries.iter().filter(|r| r.matches == Some(false)).count();
    let summaries = SHAPES
        .iter()
        .map(|shape| query_summary(&queries, shape, censor))
        .collect::<Result<Vec<_>>>()?;
    let ok = accepted == n as usize
        && sent == n as usize
        && read_sent == read_count as usize
        && completed == read_count as usize
        && mismatches == 0
        && errors.is_empty()
        && post["mismatches"] == 0;
    let mut report = json!({"format":"network-matched-v1","ok":ok,"target_url":url,"target_label":args.target_label,
        "corpus_sha256":sha256_file(path)?,"corpus_events":corpus.lines(),"corpus_retained":corpus.retained(),"history_cutoff":cutoff,
        "query_plan_sha256":plan_hash,"seed":args.seed,"write_rate":args.send_rate,"read_rate":args.read_rate,
        "read_connections":args.read_connections,"publish_connections":args.publish_connections,"drain_secs":args.drain_secs,
        "offer_horizon_secs":horizon.as_secs_f64(),"finished_us":finished,"pending_safety_bound_per_read_lane":PENDING});
    let counts = json!({
        "offered_writes":n,"sent_writes":sent,"accepted_writes":accepted,"rejected_writes":rejected,
        "unanswered_writes":n as usize-answered,"unsent_writes":n as usize-sent,
        "offered_reads":read_count,"sent_reads":read_sent,"completed_reads":completed,"unanswered_reads":read_count as usize-completed,
        "unsent_reads":read_count as usize-read_sent,"query_mismatches":mismatches,"protocol_errors":errors.len(),"errors":errors,"notices":notices});
    let validation = json!({
        "verification_scope":"live relay readback; no restart or power-loss durability proof",
        "preflight":preflight,"postcheck_mismatches":post["mismatches"],"postcheck":post,"reads":summaries,
        "writes":{"censored":n as usize-answered,
            "scheduled_to_ok":histogram(writes.iter().map(|r|r.reply_us.unwrap_or(censor).saturating_sub(r.due_us)))?,
            "wire_to_ok":histogram(writes.iter().filter_map(|r|r.send_started_us.map(|s|r.reply_us.unwrap_or(censor).saturating_sub(s))))?,
            "send_lateness":histogram(writes.iter().filter_map(|r|r.send_started_us.map(|s|s.saturating_sub(r.due_us))))?},
        "method":"Absolute event and REQ schedules, multiplexed historical subscriptions; appends after immutable cutoff; no ACK/EOSE gating. Unanswered/unsent arrivals count and are censored at horizon+drain. Wire latency starts before socket send. Full signed body oracle, post-run all timed IDs fetched independently. Network/protocol/relay scheduling included; cannot force backend write batches. Preflight pool acts as warm-up."});
    report
        .as_object_mut()
        .unwrap()
        .extend(counts.as_object().unwrap().clone());
    report
        .as_object_mut()
        .unwrap()
        .extend(validation.as_object().unwrap().clone());
    annotate_writer_workload(&mut report, args, &filters, &keyring, &events)?;
    std::fs::write(
        args.out.join("network-matched.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    ensure!(
        ok,
        "matched network trial failed correctness/completion gates; inspect network-matched.json"
    );
    Ok(())
}

pub(super) fn dispatch(args: &Args) -> Result<()> {
    if args.scenario.as_deref() == Some("matched_network_generate") {
        return generate(args);
    }
    let path = args
        .corpus
        .as_deref()
        .context("matched_network requires --corpus")?;
    let corpus = corpus::Corpus::load(path)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(run(args, &corpus, path));
    if let Err(error) = &result {
        let report = args.out.join("network-matched.json");
        if !report.exists() {
            let mut failure = json!({"format":"network-matched-v1","ok":false,
                "stage":"preflight_or_setup","target_url":args.target_url,"error":format!("{error:#}")});
            if args.matched_writer_authors == WriterAuthors::Queried {
                failure["matched_writer_authors"] = json!(args.matched_writer_authors);
            }
            std::fs::write(report, serde_json::to_vec_pretty(&failure)?)?;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched_corpus(seed: u64) -> (TempDir, Vec<Value>, corpus::Corpus) {
        let directory = tempfile::tempdir().unwrap();
        let keyring = keys(seed, b"matched-network-corpus-v1", AUTHORS);
        let values: Vec<_> = (0..AUTHORS as u64)
            .map(|seq| signed(seq, AUTHORS as u64, 10_000, seed, &keyring, false))
            .collect();
        let path = directory.path().join("corpus.jsonl");
        write_jsonl(&path, &values).unwrap();
        let corpus = corpus::Corpus::load(&path).unwrap();
        (directory, values, corpus)
    }

    fn overlap_args() -> Args {
        Args::try_parse_from([
            "wok-bench",
            "--scenario",
            "matched_network",
            "--seed",
            "257",
            "--matched-writer-authors",
            "queried",
        ])
        .unwrap()
    }

    fn identity_report(cutoff: u64, filters: &[(&str, Value)]) -> Value {
        json!({"corpus_sha256":"fixture-corpus", "history_cutoff":cutoff,
            "query_plan_sha256":hex::encode(Sha256::digest(serde_json::to_vec(filters).unwrap()))})
    }

    #[test]
    fn queried_writers_cover_every_author_and_feed_plan() {
        let (_, _, corpus) = matched_corpus(257);
        let (cutoff, filters) = corpus.matched_filters(POOL).unwrap();
        let selected = writer_keys(WriterAuthors::Queried, 257, &filters).unwrap();
        assert_eq!(selected.len(), 64);
        let mut report = identity_report(cutoff, &filters);
        let events: Vec<_> = (0..128)
            .map(|seq| signed(seq, 128, cutoff + 1, 257, &selected, true))
            .collect();
        annotate_writer_workload(&mut report, &overlap_args(), &filters, &selected, &events)
            .unwrap();
        let writer = &report["workload"]["writer_authors"];
        assert_eq!(writer["author_count"], 64);
        for shape in ["author", "feed500"] {
            let overlap = &writer["query_shape_overlap"][shape];
            assert_eq!(overlap["plans"], 64);
            assert_eq!(overlap["plans_with_writer_authors"], 64);
            assert!(overlap["minimum_writer_authors"].as_u64().unwrap() > 0);
        }
        for shape in ["tag", "id"] {
            assert_eq!(
                writer["query_shape_overlap"][shape]["author_filter_plans"],
                0
            );
            assert!(writer["query_shape_overlap"][shape]["minimum_writer_authors"].is_null());
        }
        assert!(writer.get("pubkeys").is_none());
    }

    #[test]
    fn overlapping_appends_do_not_change_fixed_cutoff_order_or_body_oracle() {
        let (_, history, corpus) = matched_corpus(257);
        let (cutoff, filters) = corpus.matched_filters(POOL).unwrap();
        let selected = writer_keys(WriterAuthors::Queried, 257, &filters).unwrap();
        let appends: Vec<_> = (0..128)
            .map(|seq| signed(seq, 128, cutoff + 1, 257, &selected, true))
            .collect();
        assert!(appends
            .iter()
            .all(|event| event["created_at"] == cutoff + 1));
        let mut combined = history.clone();
        combined.extend(appends.iter().cloned());
        for (_, filter) in &filters {
            let expected = expected_history(&history, filter);
            assert_eq!(expected_history(&combined, filter), expected);
            assert!(history_matches(&corpus.expected(filter).owned(), &expected));
            assert!(appends.iter().all(|event| !matches_filter(event, filter)));
        }
        let mut widened = filters[0].1.clone();
        widened["until"] = json!(cutoff + 1);
        assert!(expected_history(&combined, &widened)
            .iter()
            .any(|event| event["id"] == appends[0]["id"]));
        let mut corrupted = expected_history(&history, &filters[0].1);
        corrupted[0]["content"] = json!("changed stored body");
        assert!(!history_matches(
            &corpus.expected(&filters[0].1).owned(),
            &corrupted
        ));
    }

    #[test]
    fn queried_writer_mode_rejects_unexercised_authors_before_output_or_connections() {
        let (directory, _, corpus) = matched_corpus(257);
        let mut args = overlap_args();
        args.events = Some(63);
        args.target_url = Some("ws://127.0.0.1:1".into());
        args.out = directory.path().join("must-not-be-created");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(run(&args, &corpus, &args.out.join("network-matched.json")))
            .unwrap_err();
        assert!(error.to_string().contains("at least 64 writes"));
        assert!(!args.out.exists());
    }

    #[test]
    fn queried_writer_mode_rejects_a_mismatched_corpus_seed() {
        let (_, _, corpus) = matched_corpus(257);
        let (_, filters) = corpus.matched_filters(POOL).unwrap();
        assert!(writer_keys(WriterAuthors::Queried, 258, &filters)
            .unwrap_err()
            .to_string()
            .contains("does not belong"));
    }

    #[test]
    fn default_writers_preserve_legacy_jsonl_and_report_bytes() {
        let args = Args::try_parse_from(["wok-bench"]).unwrap();
        assert_eq!(args.matched_writer_authors, WriterAuthors::Disjoint);
        let legacy = keys(257, b"matched-network-timed-v1", 32);
        let selected = writer_keys(WriterAuthors::Disjoint, 257, &[]).unwrap();
        assert_eq!(selected.len(), 32);
        let original: Vec<_> = (0..128)
            .map(|seq| signed(seq, 128, 10_000, 257, &legacy, true))
            .collect();
        let current: Vec<_> = (0..128)
            .map(|seq| signed(seq, 128, 10_000, 257, &selected, true))
            .collect();
        let directory = tempfile::tempdir().unwrap();
        let before = directory.path().join("before.jsonl");
        let after = directory.path().join("after.jsonl");
        write_jsonl(&before, &original).unwrap();
        write_jsonl(&after, &current).unwrap();
        assert_eq!(
            std::fs::read(&before).unwrap(),
            std::fs::read(&after).unwrap()
        );
        assert_eq!(sha256_file(&before).unwrap(), sha256_file(&after).unwrap());
        let mut report = json!({"format":"network-matched-v1","ok":true});
        let bytes = serde_json::to_vec_pretty(&report).unwrap();
        annotate_writer_workload(&mut report, &args, &[], &selected, &current).unwrap();
        assert_eq!(serde_json::to_vec_pretty(&report).unwrap(), bytes);
    }

    #[test]
    fn queried_writer_ids_and_workload_hash_are_deterministic_and_bind_rates() {
        let (_, _, corpus) = matched_corpus(257);
        let (cutoff, filters) = corpus.matched_filters(POOL).unwrap();
        let selected = writer_keys(WriterAuthors::Queried, 257, &filters).unwrap();
        let again = writer_keys(WriterAuthors::Queried, 257, &filters).unwrap();
        let events: Vec<_> = (0..128)
            .map(|seq| signed(seq, 128, cutoff + 1, 257, &selected, true))
            .collect();
        let repeated: Vec<_> = (0..128)
            .map(|seq| signed(seq, 128, cutoff + 1, 257, &again, true))
            .collect();
        assert_eq!(events, repeated);
        let mut args = overlap_args();
        let mut first = identity_report(cutoff, &filters);
        let mut second = first.clone();
        annotate_writer_workload(&mut first, &args, &filters, &selected, &events).unwrap();
        annotate_writer_workload(&mut second, &args, &filters, &again, &repeated).unwrap();
        assert_eq!(first, second);
        // The offline controller guard consumes these exact Rust-rendered bytes.
        println!("WOK_MATCHED_WRITER_WORKLOAD_FIXTURE={first}");
        args.send_rate = 4_000.0;
        let mut changed = identity_report(cutoff, &filters);
        annotate_writer_workload(&mut changed, &args, &filters, &selected, &events).unwrap();
        assert_ne!(first["workload_sha256"], changed["workload_sha256"]);
        assert_eq!(
            first["workload"]["writer_authors"],
            changed["workload"]["writer_authors"]
        );
    }
    #[test]
    fn matched_preflight_waits_for_count_past_old_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let request = socket.next().await.unwrap().unwrap();
                assert!(request.to_text().unwrap().contains("pre-count"));
                tokio::time::sleep(Duration::from_millis(2100)).await;
                socket
                    .send(Message::Text(
                        json!(["COUNT","pre-count",{"count":15000000}])
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                let _ = socket.next().await;
            });
            let result = verify_pool(&url, &[], 15000000, 100).await.unwrap();
            assert_eq!(result["count"], 15000000);
            assert_eq!(result["measurement_starts_after_count"], true);
            assert!(result["count_elapsed_secs"].as_f64().unwrap() >= 2.1);
            server.await.unwrap();
        });
    }
    #[test]
    fn matched_preflight_rejects_limited_count_even_when_value_matches() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let _ = socket.next().await;
                socket
                    .send(Message::Text(
                        json!(["COUNT","pre-count",{"count":15000000,"limited":true}])
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            });
            assert!(verify_pool(&url, &[], 15000000, 100)
                .await
                .unwrap_err()
                .to_string()
                .contains("limited"));
            server.await.unwrap();
        });
    }
    #[test]
    fn matched_history_rejects_reversed_order_but_allows_ties() {
        assert!(history_ordered(&[
            json!({"created_at":2}),
            json!({"created_at":2}),
            json!({"created_at":1})
        ]));
        assert!(!history_ordered(&[
            json!({"created_at":1}),
            json!({"created_at":2})
        ]));
    }
    #[test]
    fn fixed_arrival_does_not_follow_completion() {
        assert_eq!(due(100, 250.0), Duration::from_millis(400));
        assert_eq!(due(101, 250.0), Duration::from_millis(404));
        assert!(Duration::from_secs(1) > due(101, 250.0));
    }
    #[test]
    fn both_reader_lanes_rotate_all_shapes() {
        for worker in 0..2 {
            let seen: HashSet<_> = (worker..128)
                .step_by(2)
                .map(|seq| pick(seq, 2) % 4)
                .collect();
            assert_eq!(seen.len(), 4);
        }
    }
    #[test]
    fn public_events_are_unique_and_time_partitioned() {
        let keyring = keys(7, b"test", AUTHORS);
        let values: Vec<_> = (0..AUTHORS as u64)
            .map(|seq| signed(seq, AUTHORS as u64, 10000, 7, &keyring, false))
            .collect();
        let ids: HashSet<_> = values.iter().map(|v| v["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), AUTHORS);
        assert!(values
            .iter()
            .all(|v| v["created_at"].as_u64().unwrap() < 10000));
        let timed = signed(0, 1, 10000, 7, &keyring, true);
        assert_eq!(timed["created_at"], 10000);
    }
}
