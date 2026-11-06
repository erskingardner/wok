//! Load driver for scripts/reliability-soak.py. The relay runs in a separate
//! process; every receipt, live delivery and stored/synchronized set is checked.
#[path = "../tests/support/wire.rs"]
mod wire;
use anyhow::{ensure, Context, Result};
use futures_util::future::join_all;
use hdrhistogram::Histogram;
use rand::{rngs::StdRng, SeedableRng};
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wire::Wire;

/// NIP-09 gives a deletion request against a deletion request no effect, so
/// every kind 5 stays stored. Notes past the retained window are deleted in
/// one request per author every this many rounds. For the longest soak
/// (21600 one-second rounds) that keeps at most 5760 ordinary deletion
/// requests, 2880 feed deletion requests, and bounded notes/replacements,
/// so even with 20498 initial notes the model stays below the configured
/// 30000-event history limit.
const DELETE_EVERY_ROUNDS: u64 = 15;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn event(key: &Keypair, kind: u64, tags: Value, content: String) -> Value {
    wok_compat::sign_event_with_key(
        json!({"created_at":now(),"kind":kind,"tags":tags,"content":content}),
        key,
    )
}
fn feed_event(key: &Keypair, created_at: u64, content: String) -> Value {
    wok_compat::sign_event_with_key(
        json!({"created_at":created_at,"kind":1,"tags":[["t","soak"]],"content":content}),
        key,
    )
}
async fn publish(wires: &mut [Wire], events: &[Value], hist: &mut Histogram<u64>) -> Result<()> {
    for chunk in events.chunks(wires.len()) {
        for result in join_all(wires.iter_mut().zip(chunk).map(|(wire, e)| async move {
            let start = Instant::now();
            wire.send(json!(["EVENT", e])).await?;
            let ack = wire.recv().await?;
            ensure!(
                ack[0] == "OK" && ack[1] == e["id"] && ack[2] == true,
                "wrong receipt: {ack}"
            );
            Ok::<_, anyhow::Error>(start.elapsed().as_micros().max(1) as u64)
        }))
        .await
        {
            hist.record(result?)?;
        }
    }
    Ok(())
}
async fn subscribe(endpoint: &str, tag: &str) -> Result<Wire> {
    let mut w = Wire::connect(endpoint).await?;
    w.send(json!(["REQ","live",{"#t":[tag],"limit":0}])).await?;
    ensure!(w.recv().await? == json!(["EOSE", "live"]), "live setup");
    Ok(w)
}
async fn subscribe_feed(endpoint: &str, authors: &[String]) -> Result<Wire> {
    let mut wire = Wire::connect(endpoint).await?;
    wire.send(json!(["REQ","live",{"authors":authors,"kinds":[1],"limit":0}]))
        .await?;
    ensure!(wire.recv().await? == json!(["EOSE", "live"]), "feed setup");
    Ok(wire)
}

async fn author_feed(
    endpoint: &str,
    authors: &[String],
    model: &BTreeMap<String, Value>,
    hist: &mut Histogram<u64>,
) -> Result<()> {
    let selected: BTreeSet<_> = authors.iter().map(String::as_str).collect();
    let mut expected: Vec<_> = model
        .values()
        .filter(|e| e["kind"] == 1 && selected.contains(e["pubkey"].as_str().unwrap()))
        .cloned()
        .collect();
    expected.sort_unstable_by_key(|e| std::cmp::Reverse(e["created_at"].as_u64().unwrap()));
    ensure!(
        expected
            .windows(2)
            .all(|w| w[0]["created_at"] != w[1]["created_at"]),
        "feed fixture must avoid ambiguous timestamp ties"
    );
    let total = expected.len();
    expected.truncate(50);
    let start = Instant::now();
    let mut wire = Wire::connect(endpoint).await?;
    wire.send(json!(["REQ","feed",{"authors":authors,"kinds":[1],"limit":50}]))
        .await?;
    let mut actual = Vec::new();
    loop {
        let frame = wire.recv().await?;
        ensure!(frame[1] == "feed", "unexpected feed subscription: {frame}");
        if frame[0] == "EOSE" {
            break;
        }
        ensure!(frame[0] == "EVENT", "feed frame: {frame}");
        actual.push(frame[2].clone());
        ensure!(actual.len() <= 50, "feed limit exceeded");
    }
    ensure!(
        actual == expected,
        "500-author feed changed order, IDs or full bodies"
    );
    hist.record(start.elapsed().as_micros().max(1) as u64)?;
    wire.send(json!(["COUNT","feed-count",{"authors":authors,"kinds":[1]}]))
        .await?;
    let count = wire.recv().await?;
    ensure!(
        count[0] == "COUNT" && count[1] == "feed-count" && count[2]["count"] == total,
        "feed COUNT mismatch: {count}"
    );
    Ok(())
}

struct Connections {
    writers: Vec<Wire>,
    readers: Vec<Wire>,
    feed_readers: Vec<Wire>,
    slow: Vec<Wire>,
}
impl Connections {
    async fn connect(endpoints: &[&str; 2], authors: &[String]) -> Result<Self> {
        let mut result = Self {
            writers: Vec::new(),
            readers: Vec::new(),
            feed_readers: Vec::new(),
            slow: Vec::new(),
        };
        for i in 0..8 {
            result.writers.push(Wire::connect(endpoints[i % 2]).await?);
        }
        for i in 0..4 {
            result
                .readers
                .push(subscribe(endpoints[i % 2], "soak").await?);
        }
        for endpoint in endpoints {
            result
                .feed_readers
                .push(subscribe_feed(endpoint, authors).await?);
            result.slow.push(subscribe(endpoint, "soak-slow").await?);
        }
        Ok(result)
    }
    fn clear(&mut self) {
        self.writers.clear();
        self.readers.clear();
        self.feed_readers.clear();
        self.slow.clear();
    }
}

async fn recover(
    phase: &str,
    output: &Path,
    endpoints: &[&str; 2],
    authors: &[String],
    model: &BTreeMap<String, Value>,
    hist: &mut Histogram<u64>,
) -> Result<Connections> {
    std::fs::write(output.join(format!("{phase}.request")), b"ready")?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !output.join(format!("{phase}.ready")).exists() {
        ensure!(Instant::now() < deadline, "{phase} deadline");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for endpoint in endpoints {
        history(endpoint, model, hist).await?;
        author_feed(endpoint, authors, model, hist).await?;
    }
    Connections::connect(endpoints, authors).await
}
async fn live(w: &mut Wire, events: &[Value]) -> Result<()> {
    let mut expected: BTreeMap<_, _> = events
        .iter()
        .map(|e| (e["id"].as_str().unwrap().to_string(), e))
        .collect();
    for _ in 0..events.len() {
        let reply = w.recv().await?;
        ensure!(
            reply[0] == "EVENT" && reply[1] == "live",
            "unexpected live frame: {reply}"
        );
        let id = reply[2]["id"].as_str().context("live ID")?;
        ensure!(
            expected.remove(id) == Some(&reply[2]),
            "missing, duplicate or altered live event {id}"
        );
    }
    ensure!(expected.is_empty(), "missing live events");
    Ok(())
}
async fn history(
    endpoint: &str,
    model: &BTreeMap<String, Value>,
    query_hist: &mut Histogram<u64>,
) -> Result<()> {
    let mut wire = Wire::connect(endpoint).await?;
    let start = Instant::now();
    wire.send(json!(["REQ","snapshot",{"kinds":[1,5,30000],"limit":30000}]))
        .await?;
    let mut got = BTreeMap::new();
    loop {
        let reply = wire.recv().await?;
        ensure!(reply[1] == "snapshot", "wrong subscription: {reply}");
        if reply[0] == "EOSE" {
            break;
        }
        ensure!(reply[0] == "EVENT", "unexpected snapshot: {reply}");
        let e = reply[2].clone();
        ensure!(
            got.insert(e["id"].as_str().context("snapshot ID")?.into(), e)
                .is_none(),
            "duplicate history"
        );
    }
    ensure!(
        &got == model,
        "history mismatch: got {} expected {}",
        got.len(),
        model.len()
    );
    query_hist.record(start.elapsed().as_micros().max(1) as u64)?;
    wire.send(json!(["COUNT","count",{"kinds":[1,5,30000]}]))
        .await?;
    let reply = wire.recv().await?;
    ensure!(
        reply[0] == "COUNT" && reply[2]["count"] == model.len(),
        "COUNT mismatch: {reply}"
    );
    Ok(())
}
async fn sync(endpoint: &str, model: &BTreeMap<String, Value>) -> Result<u64> {
    let mut wire = Wire::connect(endpoint).await?;
    let mut vector = wok_negentropy::Vector::new();
    vector.seal()?;
    let mut peer = wok_negentropy::Negentropy::new(vector, 4096)?;
    wire.send(json!(["NEG-OPEN","sync",{"kinds":[1,5,30000]},hex::encode(peer.initiate()?)]))
        .await?;
    let mut got = BTreeSet::new();
    for round in 1..=1000 {
        let reply = wire.recv().await?;
        ensure!(reply[0] == "NEG-MSG", "sync response: {reply}");
        let mut have = Vec::new();
        let mut need = Vec::new();
        let next = peer.reconcile_with_ids(
            &hex::decode(reply[2].as_str().context("sync payload")?)?,
            &mut have,
            &mut need,
        )?;
        ensure!(have.is_empty(), "unexpected upload IDs");
        for id in need {
            ensure!(got.insert(hex::encode(id)), "duplicate sync ID");
        }
        if let Some(next) = next {
            wire.send(json!(["NEG-MSG", "sync", hex::encode(next)]))
                .await?;
        } else {
            ensure!(got == model.keys().cloned().collect(), "sync set mismatch");
            return Ok(round);
        }
    }
    anyhow::bail!("sync exceeded round budget")
}
async fn slow_closed(wire: &mut Wire) -> bool {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if wire.recv().await.is_err() {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "usage: reliability_soak WS_URL UNIX_URL SECONDS OUTPUT SEED"
    );
    let endpoints = [args[1].as_str(), args[2].as_str()];
    let duration = Duration::from_secs(args[3].parse()?);
    let output = Path::new(&args[4]);
    let seed: u64 = args[5].parse()?;
    let mut rng = StdRng::seed_from_u64(seed);
    let keys: Vec<_> = (0..4).map(|_| Keypair::new(SECP256K1, &mut rng)).collect();
    let feed_keys: Vec<_> = (0..2).map(|_| Keypair::new(SECP256K1, &mut rng)).collect();
    let seeded_feed_keys: Vec<_> = (0..498)
        .map(|_| Keypair::new(SECP256K1, &mut rng))
        .collect();
    let mut feed_authors: Vec<_> = feed_keys
        .iter()
        .map(|key| hex::encode(key.x_only_public_key().0.serialize()))
        .collect();
    feed_authors.extend(
        seeded_feed_keys
            .iter()
            .map(|key| hex::encode(key.x_only_public_key().0.serialize())),
    );
    feed_authors.sort_unstable();
    feed_authors.dedup();
    ensure!(feed_authors.len() == 500, "500 distinct feed authors");
    // Unique, already-past timestamps make the exact newest50 deterministic.
    let feed_epoch = now().saturating_sub(50_000);
    let mut writers = Vec::new();
    for i in 0..8 {
        writers.push(Wire::connect(endpoints[i % 2]).await?);
    }
    let mut model = BTreeMap::new();
    let mut ack_hist = Histogram::<u64>::new(3)?;
    let mut query_hist = Histogram::<u64>::new(3)?;
    let mut corpus = String::new();
    for batch in 0..200 {
        let events: Vec<_> = (0..100)
            .map(|i| {
                event(
                    &keys[i % 4],
                    1,
                    json!([["t", "soak-seed"]]),
                    format!("seed {seed} {batch} {i} {}", "x".repeat(256)),
                )
            })
            .collect();
        publish(&mut writers, &events, &mut ack_hist).await?;
        for e in events {
            corpus.push_str(&wok_event::json::to_tao_string(&e));
            corpus.push('\n');
            model.insert(e["id"].as_str().unwrap().into(), e);
        }
    }
    // Populate every inactive feed range before the two active authors append.
    // All 498 timestamps are unique and older than every active feed note.
    let seeded_feed: Vec<_> = seeded_feed_keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            feed_event(
                key,
                feed_epoch - seeded_feed_keys.len() as u64 + i as u64,
                format!("feed seed {seed}/{i}"),
            )
        })
        .collect();
    publish(&mut writers, &seeded_feed, &mut ack_hist).await?;
    for e in seeded_feed {
        corpus.push_str(&wok_event::json::to_tao_string(&e));
        corpus.push('\n');
        model.insert(e["id"].as_str().unwrap().into(), e);
    }
    std::fs::write(output.join("corpus.jsonl"), corpus)?;
    history(endpoints[0], &model, &mut query_hist).await?;
    sync(endpoints[1], &model).await?;
    ack_hist.reset();
    query_hist.reset();
    drop(writers);
    let mut connections = Connections::connect(&endpoints, &feed_authors).await?;
    let mut notes: VecDeque<(usize, String)> = VecDeque::new();
    let mut feed_notes: VecDeque<(usize, String)> = VecDeque::new();
    let mut replacements: BTreeMap<(usize, u64), String> = BTreeMap::new();
    let start = Instant::now();
    let mut round = 0u64;
    let mut receipts = 0u64;
    let mut pressure_receipts = 0u64;
    let mut sync_rounds = 0;
    let mut slow_closes = 0;
    let mut restarted = false;
    let mut restart_round = None;
    let mut crash_recovered = false;
    let mut feed_checks = 0u64;
    let mut author_live_deliveries = 0u64;
    while start.elapsed() < duration || !crash_recovered {
        let tick = Instant::now();
        if round.is_multiple_of(60) {
            // Dedicated ephemeral pressure frames must never appear in the
            // durable model or on the unrelated fast subscription.
            let pressure: Vec<_> = (0..64)
                .map(|i| {
                    event(
                        &keys[i % 4],
                        20001,
                        json!([["t", "soak-slow"]]),
                        format!("pressure {round}/{i} {}", "x".repeat(512 * 1024)),
                    )
                })
                .collect();
            publish(&mut connections.writers, &pressure, &mut ack_hist).await?;
            pressure_receipts += pressure.len() as u64;
        }
        let mut batch = Vec::new();
        for i in 0..32 {
            let actor = i % 4;
            let e = event(
                &keys[actor],
                1,
                json!([["t", "soak"]]),
                format!("round {round}/{i} {}", "x".repeat(2048)),
            );
            let id = e["id"].as_str().unwrap().to_string();
            notes.push_back((actor, id.clone()));
            model.insert(id, e.clone());
            batch.push(e);
        }
        for (actor, key) in keys.iter().enumerate() {
            let slot = round % 16;
            let e = event(
                key,
                30000,
                json!([["d", slot.to_string()], ["t", "soak"]]),
                format!("replace {round}/{actor}"),
            );
            let id = e["id"].as_str().unwrap().to_string();
            if let Some(old) = replacements.insert((actor, slot), id.clone()) {
                model.remove(&old);
            }
            model.insert(id, e.clone());
            batch.push(e);
        }
        let mut removed: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        while round.is_multiple_of(DELETE_EVERY_ROUNDS) && notes.len() > 256 {
            let (actor, id) = notes.pop_front().unwrap();
            model.remove(&id);
            removed.entry(actor).or_default().push(id);
        }
        for (actor, ids) in removed {
            let mut tags = vec![json!(["t", "soak"])];
            tags.extend(ids.into_iter().map(|id| json!(["e", id])));
            let e = event(
                &keys[actor],
                5,
                json!(tags),
                format!("delete {round}/{actor}"),
            );
            model.insert(e["id"].as_str().unwrap().to_string(), e.clone());
            batch.push(e);
        }
        let mut feed_batch = Vec::new();
        for (actor, key) in feed_keys.iter().enumerate() {
            let e = feed_event(
                key,
                feed_epoch + round * 2 + actor as u64,
                format!("same-author feed {round}/{actor}"),
            );
            let id = e["id"].as_str().unwrap().to_owned();
            model.insert(id.clone(), e.clone());
            feed_notes.push_back((actor, id));
            feed_batch.push(e.clone());
            batch.push(e);
        }
        let mut removed_feed: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        while round.is_multiple_of(DELETE_EVERY_ROUNDS) && feed_notes.len() > 64 {
            let (actor, id) = feed_notes.pop_front().unwrap();
            model.remove(&id);
            removed_feed.entry(actor).or_default().push(id);
        }
        for (actor, ids) in removed_feed {
            let mut tags = vec![json!(["t", "soak"])];
            tags.extend(ids.into_iter().map(|id| json!(["e", id])));
            let e = event(
                &feed_keys[actor],
                5,
                json!(tags),
                format!("delete feed {round}/{actor}"),
            );
            model.insert(e["id"].as_str().unwrap().into(), e.clone());
            batch.push(e);
        }
        publish(&mut connections.writers, &batch, &mut ack_hist).await?;
        for reader in &mut connections.readers {
            live(reader, &batch).await?;
        }
        for reader in &mut connections.feed_readers {
            live(reader, &feed_batch).await?;
        }
        author_live_deliveries += (feed_batch.len() * connections.feed_readers.len()) as u64;
        receipts += batch.len() as u64;
        if round.is_multiple_of(15) {
            for endpoint in endpoints {
                history(endpoint, &model, &mut query_hist).await?;
                author_feed(endpoint, &feed_authors, &model, &mut query_hist).await?;
                feed_checks += 1;
            }
            sync_rounds += sync(endpoints[(round / 15) as usize % 2], &model).await?;
        }
        if round > 0 && round.is_multiple_of(60) {
            connections.readers[0] = subscribe(endpoints[0], "soak").await?;
            connections.readers[1] = subscribe(endpoints[1], "soak").await?;
            for (i, wire) in connections.slow.iter_mut().enumerate() {
                if slow_closed(wire).await {
                    slow_closes += 1;
                }
                *wire = subscribe(endpoints[i], "soak-slow").await?;
            }
        }
        if !restarted && start.elapsed() > duration / 2 {
            connections.clear();
            connections = recover(
                "restart",
                output,
                &endpoints,
                &feed_authors,
                &model,
                &mut query_hist,
            )
            .await?;
            feed_checks += 2;
            sync_rounds += sync(endpoints[0], &model).await?;
            restarted = true;
            restart_round = Some(round);
        }
        if restarted
            && !crash_recovered
            && restart_round != Some(round)
            && start.elapsed() > duration * 3 / 4
        {
            connections.clear();
            connections = recover(
                "crash",
                output,
                &endpoints,
                &feed_authors,
                &model,
                &mut query_hist,
            )
            .await?;
            feed_checks += 2;
            sync_rounds += sync(endpoints[1], &model).await?;
            crash_recovered = true;
        }
        round += 1;
        if round.is_multiple_of(10) {
            println!(
                "{}",
                json!({"phase":"mixed","seconds":start.elapsed().as_secs_f64(),"rounds":round,"receipts":receipts,"pressure_receipts":pressure_receipts,"stored":model.len(),"ack_p99_ms":ack_hist.value_at_quantile(0.99) as f64/1000.0,"ack_max_ms":ack_hist.max() as f64/1000.0,"query_p99_ms":query_hist.value_at_quantile(0.99) as f64/1000.0,"sync_rounds":sync_rounds,"slow_closes":slow_closes,"restarted":restarted,"crash_recovered":crash_recovered,"author_feed_checks":feed_checks})
            );
        }
        if let Some(remaining) = Duration::from_secs(1).checked_sub(tick.elapsed()) {
            tokio::time::sleep(remaining).await;
        }
    }
    for endpoint in endpoints {
        history(endpoint, &model, &mut query_hist).await?;
        author_feed(endpoint, &feed_authors, &model, &mut query_hist).await?;
        feed_checks += 1;
    }
    sync_rounds += sync(endpoints[0], &model).await?;
    ensure!(restarted, "restart phase did not run");
    ensure!(crash_recovered, "crash recovery phase did not run");
    if duration.as_secs() >= 180 {
        ensure!(slow_closes > 0, "slow clients never observed closing");
    }
    let result = json!({"ok":true,"seconds":start.elapsed().as_secs_f64(),"seed":seed,"rounds":round,"receipts":receipts,"pressure_receipts":pressure_receipts,"live_deliveries":receipts*4,"author_live_deliveries":author_live_deliveries,"author_feed_checks":feed_checks,"feed_author_count":feed_authors.len(),"stored":model.len(),"sync_rounds":sync_rounds,"slow_closes":slow_closes,"restart_verified":restarted,"crash_recovery_verified":crash_recovered,"crash_scope":"SIGKILL after fully acknowledged batch; no in-flight/power-loss claim","ack_p50_ms":ack_hist.value_at_quantile(0.5) as f64/1000.0,"ack_p99_ms":ack_hist.value_at_quantile(0.99) as f64/1000.0,"ack_max_ms":ack_hist.max() as f64/1000.0,"query_p99_ms":query_hist.value_at_quantile(0.99) as f64/1000.0,"query_max_ms":query_hist.max() as f64/1000.0});
    std::fs::write(
        output.join("driver-result.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{result}");
    Ok(())
}
