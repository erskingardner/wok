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
    std::fs::write(output.join("corpus.jsonl"), corpus)?;
    history(endpoints[0], &model, &mut query_hist).await?;
    sync(endpoints[1], &model).await?;
    ack_hist.reset();
    query_hist.reset();
    let mut readers = Vec::new();
    for i in 0..4 {
        readers.push(subscribe(endpoints[i % 2], "soak").await?);
    }
    let mut slow = vec![
        subscribe(endpoints[0], "soak-slow").await?,
        subscribe(endpoints[1], "soak-slow").await?,
    ];
    let mut notes: VecDeque<(usize, String)> = VecDeque::new();
    let mut replacements: BTreeMap<(usize, u64), String> = BTreeMap::new();
    let mut deletions: BTreeMap<usize, String> = BTreeMap::new();
    let start = Instant::now();
    let mut round = 0u64;
    let mut receipts = 0u64;
    let mut pressure_receipts = 0u64;
    let mut sync_rounds = 0;
    let mut slow_closes = 0;
    let mut restarted = false;
    while start.elapsed() < duration {
        let tick = Instant::now();
        if round % 60 == 0 {
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
            publish(&mut writers, &pressure, &mut ack_hist).await?;
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
        while notes.len() > 256 {
            let (actor, id) = notes.pop_front().unwrap();
            model.remove(&id);
            removed.entry(actor).or_default().push(id);
        }
        for (actor, mut ids) in removed {
            if let Some(old) = deletions.remove(&actor) {
                model.remove(&old);
                ids.push(old);
            }
            let mut tags = vec![json!(["t", "soak"])];
            tags.extend(ids.into_iter().map(|id| json!(["e", id])));
            let e = event(
                &keys[actor],
                5,
                json!(tags),
                format!("delete {round}/{actor}"),
            );
            let id = e["id"].as_str().unwrap().to_string();
            deletions.insert(actor, id.clone());
            model.insert(id, e.clone());
            batch.push(e);
        }
        publish(&mut writers, &batch, &mut ack_hist).await?;
        for reader in &mut readers {
            live(reader, &batch).await?;
        }
        receipts += batch.len() as u64;
        if round % 15 == 0 {
            for endpoint in endpoints {
                history(endpoint, &model, &mut query_hist).await?;
            }
            sync_rounds += sync(endpoints[(round / 15) as usize % 2], &model).await?;
        }
        if round > 0 && round % 60 == 0 {
            readers[0] = subscribe(endpoints[0], "soak").await?;
            readers[1] = subscribe(endpoints[1], "soak").await?;
            for (i, wire) in slow.iter_mut().enumerate() {
                if slow_closed(wire).await {
                    slow_closes += 1;
                }
                *wire = subscribe(endpoints[i], "soak-slow").await?;
            }
        }
        if !restarted && start.elapsed() > duration / 2 {
            writers.clear();
            readers.clear();
            slow.clear();
            std::fs::write(output.join("restart.request"), b"ready")?;
            let deadline = Instant::now() + Duration::from_secs(60);
            while !output.join("restart.ready").exists() {
                ensure!(Instant::now() < deadline, "restart deadline");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            for endpoint in endpoints {
                history(endpoint, &model, &mut query_hist).await?;
            }
            for i in 0..8 {
                writers.push(Wire::connect(endpoints[i % 2]).await?);
            }
            for i in 0..4 {
                readers.push(subscribe(endpoints[i % 2], "soak").await?);
            }
            slow = vec![
                subscribe(endpoints[0], "soak-slow").await?,
                subscribe(endpoints[1], "soak-slow").await?,
            ];
            restarted = true;
        }
        round += 1;
        if round % 10 == 0 {
            println!(
                "{}",
                json!({"phase":"mixed","seconds":start.elapsed().as_secs_f64(),"rounds":round,"receipts":receipts,"pressure_receipts":pressure_receipts,"stored":model.len(),"ack_p99_ms":ack_hist.value_at_quantile(0.99) as f64/1000.0,"ack_max_ms":ack_hist.max() as f64/1000.0,"query_p99_ms":query_hist.value_at_quantile(0.99) as f64/1000.0,"sync_rounds":sync_rounds,"slow_closes":slow_closes,"restarted":restarted})
            );
        }
        if let Some(remaining) = Duration::from_secs(1).checked_sub(tick.elapsed()) {
            tokio::time::sleep(remaining).await;
        }
    }
    for endpoint in endpoints {
        history(endpoint, &model, &mut query_hist).await?;
    }
    sync_rounds += sync(endpoints[0], &model).await?;
    ensure!(restarted, "restart phase did not run");
    if duration.as_secs() >= 180 {
        ensure!(slow_closes > 0, "slow clients never observed closing");
    }
    let result = json!({"ok":true,"seconds":start.elapsed().as_secs_f64(),"seed":seed,"rounds":round,"receipts":receipts,"pressure_receipts":pressure_receipts,"live_deliveries":receipts*4,"stored":model.len(),"sync_rounds":sync_rounds,"slow_closes":slow_closes,"restart_verified":restarted,"ack_p50_ms":ack_hist.value_at_quantile(0.5) as f64/1000.0,"ack_p99_ms":ack_hist.value_at_quantile(0.99) as f64/1000.0,"ack_max_ms":ack_hist.max() as f64/1000.0,"query_p99_ms":query_hist.value_at_quantile(0.99) as f64/1000.0,"query_max_ms":query_hist.max() as f64/1000.0});
    std::fs::write(
        output.join("driver-result.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{result}");
    Ok(())
}
