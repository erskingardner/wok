//! `--scenario db_write`: what storing events costs, without a relay or the
//! network. The writer thread's storage path runs in process: one write
//! transaction per batch through `write_events_with_quota`, the negentropy
//! tree flush, and a durable commit, as `run_writer` does.
//!
//! The corpus is loaded into a fresh database in large untimed batches,
//! except its last events. Those are written in timed steps, one per
//! `--db-batches` size, each its own slice of the held-back events in corpus
//! order, so every step writes new events on top of the preloaded history.
//! A step writes at least `--db-step-events` events and at least
//! [`MIN_COMMITS`] transactions.
//!
//! Per step it reports transaction and commit times, and on Linux the bytes
//! the process wrote (`write_bytes` of `/proc/self/io`, which counts each page
//! dirtied once per commit). The relay writer's checks before its write
//! transaction (duplicates, policy, quotas) are not part of the time.
//!
//! Each event ends as the writer leaves it. Stored events were inserted; a
//! duplicate, an older version of a replaceable event, or a deleted event
//! is settled without a row of its own, as on a relay (a social corpus has
//! many). Rates and costs are per stored event. An event the writer left
//! pending or over a quota fails the step.
//!
//! The database lives under `--dataset-dir`, not the system temp directory,
//! which is a tmpfs on many Linux hosts and would hide the disk's cost.

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::Value;
use std::io::BufRead;
use std::path::PathBuf;
use std::time::Instant;

/// Events per untimed preload transaction, small enough to stay clear of
/// LMDB's dirty-page limit with heavily tagged events.
const PRELOAD_BATCH: usize = 1_000;
/// Fewest transactions a step commits, so its percentiles mean something.
pub const MIN_COMMITS: u64 = 20;
/// Events preloaded before the steps when the scenario generates its corpus.
const DEFAULT_PRELOAD: u64 = 20_000;
const PAGE_BYTES: f64 = 4_096.0;

pub struct Options {
    pub corpus: PathBuf,
    /// Parent of the trial's database directory.
    pub dir: PathBuf,
    pub batches: Vec<usize>,
    pub step_events: u64,
    pub max_tags_per_filter: usize,
}

#[derive(Serialize, Clone)]
pub struct Report {
    pub corpus_events: u64,
    /// Corpus events written before the steps, and those of them stored.
    pub preloaded: u64,
    pub preload_stored: u64,
    pub preload_secs: f64,
    /// Whether `/proc/self/io` was readable, so the byte columns are filled.
    pub io_counted: bool,
    pub steps: Vec<Step>,
}

#[derive(Serialize, Clone)]
pub struct Step {
    pub batch: usize,
    pub events: u64,
    /// Inserted as rows.
    pub stored: u64,
    /// Duplicates, superseded replaceable events and deleted events.
    pub settled: u64,
    /// Left pending or over a quota: a failure.
    pub unfinished: u64,
    pub commits: u64,
    pub secs: f64,
    pub stored_per_s: f64,
    pub us_per_stored: f64,
    pub txn_p50_us: u64,
    pub txn_p99_us: u64,
    pub txn_max_us: u64,
    pub commit_p50_us: u64,
    pub commit_p99_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_per_stored: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages_per_commit: Option<f64>,
    /// Growth of `data.mdb` over the step.
    pub file_growth_bytes: u64,
    /// Transaction times in µs, kept for the trial's latency columns.
    #[serde(skip)]
    pub txn_us: Vec<u64>,
}

impl Report {
    /// The step with the smallest batch.
    pub fn smallest_batch(&self) -> Option<&Step> {
        self.steps.iter().min_by_key(|step| step.batch)
    }

    /// The highest stored events per second over the steps.
    pub fn best_rate(&self) -> f64 {
        self.steps
            .iter()
            .map(|step| step.stored_per_s)
            .fold(0.0, f64::max)
    }

    /// Steps with an event the writer did not finish.
    pub fn failed_steps(&self) -> u64 {
        self.steps.iter().filter(|step| step.unfinished > 0).count() as u64
    }
}

/// Events each step writes: at least `step_events`, and enough for
/// [`MIN_COMMITS`] transactions of its batch size.
fn step_sizes(batches: &[usize], step_events: u64) -> Vec<u64> {
    batches
        .iter()
        .map(|&batch| step_events.max(batch as u64 * MIN_COMMITS))
        .collect()
}

/// Events a corpus generated for this scenario holds: the steps' events
/// plus a preloaded history of [`DEFAULT_PRELOAD`].
pub fn default_corpus_events(batches: &[usize], step_events: u64) -> u64 {
    step_sizes(batches, step_events).iter().sum::<u64>() + DEFAULT_PRELOAD
}

/// What a batch of events came to.
#[derive(Default)]
struct Outcomes {
    stored: u64,
    settled: u64,
    unfinished: u64,
}

impl Outcomes {
    fn add(&mut self, events: &[wok_db::EventToWrite]) {
        use wok_db::EventWriteStatus as Status;
        for event in events {
            match event.status {
                Status::Written => self.stored += 1,
                Status::Duplicate | Status::Replaced | Status::Deleted => self.settled += 1,
                Status::Pending | Status::QuotaExceeded => self.unfinished += 1,
            }
        }
    }
}

pub fn run(opts: &Options) -> Result<Report> {
    anyhow::ensure!(
        !opts.batches.is_empty() && opts.batches.iter().all(|&batch| batch > 0),
        "--db-batches needs at least one batch size above 0"
    );
    let corpus_events = crate::count_jsonl_events(&opts.corpus)?;
    let sizes = step_sizes(&opts.batches, opts.step_events);
    let held: u64 = sizes.iter().sum();
    anyhow::ensure!(
        corpus_events > held,
        "--scenario db_write holds back {held} events for its steps, but the corpus has {corpus_events}; pass a larger corpus or a smaller --db-step-events"
    );
    std::fs::create_dir_all(&opts.dir)?;
    let dir = tempfile::Builder::new()
        .prefix("db_write-")
        .tempdir_in(&opts.dir)
        .with_context(|| format!("create a database under {}", opts.dir.display()))?;
    let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::default())?;
    env.ensure_initialized()?;
    let mut trees = wok_negentropy::NegentropyFilterCache::new(opts.max_tags_per_filter);
    let mut lines = std::io::BufReader::new(std::fs::File::open(&opts.corpus)?)
        .lines()
        .filter(|line| !matches!(line, Ok(line) if line.trim().is_empty()));
    let mut next = || -> Result<wok_db::EventToWrite> {
        let line = lines.next().context("corpus ended early")??;
        parse(&line)
    };

    let preloaded = corpus_events - held;
    let started = Instant::now();
    let mut batch = Vec::with_capacity(PRELOAD_BATCH);
    let mut preload = Outcomes::default();
    for i in 0..preloaded {
        batch.push(next()?);
        if batch.len() == PRELOAD_BATCH || i + 1 == preloaded {
            write_batch(&env, &mut trees, &mut batch)?;
            preload.add(&batch);
            batch.clear();
        }
    }
    let preload_secs = started.elapsed().as_secs_f64();
    anyhow::ensure!(
        preload.unfinished == 0,
        "{} preloaded events were left pending",
        preload.unfinished
    );

    let data = dir.path().join("data.mdb");
    let mut io_counted = true;
    let mut steps = Vec::new();
    for (&batch_size, &events) in opts.batches.iter().zip(&sizes) {
        let mut pending = (0..events).map(|_| next()).collect::<Result<Vec<_>>>()?;
        let size_before = std::fs::metadata(&data)?.len();
        let io_before = process_write_bytes();
        let mut txn_us = Vec::new();
        let mut commit_hist = Histogram::<u64>::new(3)?;
        let mut outcomes = Outcomes::default();
        let started = Instant::now();
        for chunk in pending.chunks_mut(batch_size) {
            let times = write_batch(&env, &mut trees, chunk)?;
            txn_us.push(times.txn_us);
            commit_hist.record(times.commit_us.max(1))?;
            outcomes.add(chunk);
        }
        let secs = started.elapsed().as_secs_f64();
        let bytes_written = match (io_before, process_write_bytes()) {
            (Some(before), Some(after)) => Some(after.saturating_sub(before)),
            _ => {
                io_counted = false;
                None
            }
        };
        let commits = txn_us.len() as u64;
        let mut txn_hist = Histogram::<u64>::new(3)?;
        for &us in &txn_us {
            txn_hist.record(us.max(1))?;
        }
        let stored = outcomes.stored.max(1) as f64;
        steps.push(Step {
            batch: batch_size,
            events,
            stored: outcomes.stored,
            settled: outcomes.settled,
            unfinished: outcomes.unfinished,
            commits,
            secs,
            stored_per_s: outcomes.stored as f64 / secs.max(f64::MIN_POSITIVE),
            us_per_stored: secs * 1e6 / stored,
            txn_p50_us: txn_hist.value_at_quantile(0.50),
            txn_p99_us: txn_hist.value_at_quantile(0.99),
            txn_max_us: txn_hist.max(),
            commit_p50_us: commit_hist.value_at_quantile(0.50),
            commit_p99_us: commit_hist.value_at_quantile(0.99),
            bytes_written,
            bytes_per_stored: bytes_written.map(|bytes| bytes as f64 / stored),
            pages_per_commit: bytes_written.map(|bytes| bytes as f64 / PAGE_BYTES / commits as f64),
            file_growth_bytes: std::fs::metadata(&data)?.len().saturating_sub(size_before),
            txn_us,
        });
        pending.clear();
    }
    Ok(Report {
        corpus_events,
        preloaded,
        preload_stored: preload.stored,
        preload_secs,
        io_counted,
        steps,
    })
}

fn parse(line: &str) -> Result<wok_db::EventToWrite> {
    let value: Value = serde_json::from_str(line)?;
    // The corpus is signed by its generator; the relay's limits are raised
    // to what a corpus needs, so none apply here.
    let limits = wok_event::EventLimits {
        max_event_size: usize::MAX,
        max_num_tags: usize::MAX,
        max_tag_val_size: usize::MAX,
    };
    let parsed = wok_event::parse_and_verify_event(&value, &limits, None, false, false)
        .map_err(|error| anyhow::anyhow!("corpus event: {error}"))?;
    Ok(wok_db::EventToWrite::new(
        parsed.packed.into_bytes(),
        parsed.json,
    ))
}

struct BatchTimes {
    txn_us: u64,
    commit_us: u64,
}

/// One writer batch: the storage calls `run_writer` makes, in its order.
fn write_batch(
    env: &wok_db::Env,
    trees: &mut wok_negentropy::NegentropyFilterCache,
    events: &mut [wok_db::EventToWrite],
) -> Result<BatchTimes> {
    let started = Instant::now();
    let mut txn = env.begin_rw()?;
    let mut tree_batch = trees.batch();
    wok_db::write::write_events_with_quota(
        &mut txn,
        &mut tree_batch,
        events,
        &wok_db::VanishPolicy::disabled(),
        0,
    )?;
    tree_batch
        .flush(&mut txn)
        .map_err(|error| anyhow::anyhow!("negentropy flush: {error}"))?;
    let commit_started = Instant::now();
    txn.commit()?;
    Ok(BatchTimes {
        txn_us: started.elapsed().as_micros() as u64,
        commit_us: commit_started.elapsed().as_micros() as u64,
    })
}

/// Bytes this process has caused to be written to storage, on Linux.
fn process_write_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/io").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("write_bytes:"))?
        .trim()
        .parse()
        .ok()
}

pub fn render_markdown(report: &Report) -> String {
    let mut s = format!(
        "\n## db_write: {} events preloaded ({} stored) in {:.1} s\n\nEach step writes its own slice of the corpus's last events in transactions of `batch` events, each committed durably, as the relay writer does. Stored events were inserted; settled ones are duplicates, older versions of replaceable events, or deleted, with no row of their own. Rates, times and bytes per event count stored events. Transaction time runs from `begin_rw` to the end of the commit. Bytes are what the process wrote, from `/proc/self/io`; a page counts once per commit that dirties it. With few commits, p99 is close to the step's maximum.\n\n| batch | events | stored | settled | unfinished | commits | stored/s | µs/stored | txn p50 µs | txn p99 µs | txn max µs | commit p50 µs | commit p99 µs | bytes/stored | pages/commit | file growth MB |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        report.preloaded, report.preload_stored, report.preload_secs
    );
    let optional = |value: Option<f64>| value.map_or_else(|| "n/a".into(), |v| format!("{v:.0}"));
    for step in &report.steps {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.0} | {:.1} | {} | {} | {} | {} | {} | {} | {} | {:.1} |\n",
            step.batch,
            step.events,
            step.stored,
            step.settled,
            step.unfinished,
            step.commits,
            step.stored_per_s,
            step.us_per_stored,
            step.txn_p50_us,
            step.txn_p99_us,
            step.txn_max_us,
            step.commit_p50_us,
            step.commit_p99_us,
            optional(step.bytes_per_stored),
            optional(step.pages_per_commit),
            step.file_growth_bytes as f64 / 1e6,
        ));
    }
    if !report.io_counted {
        s.push_str("\n`/proc/self/io` is not available on this host, so bytes are not reported.\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_hold_enough_events_for_their_commits() {
        assert_eq!(step_sizes(&[1, 8, 512], 100), vec![100, 160, 10_240]);
    }

    #[test]
    fn steps_write_the_held_back_events_on_a_preloaded_database() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("corpus.jsonl");
        crate::generate_events(&corpus, 300, 7, 1_700_000_000, crate::EventMix::Kind1).unwrap();
        let report = run(&Options {
            corpus,
            dir: dir.path().join("db"),
            batches: vec![1, 4],
            step_events: 40,
            max_tags_per_filter: 8,
        })
        .unwrap();
        assert_eq!(report.corpus_events, 300);
        assert_eq!(report.preloaded, 180);
        let shape: Vec<_> = report
            .steps
            .iter()
            .map(|step| (step.batch, step.events, step.stored, step.commits))
            .collect();
        assert_eq!(shape, vec![(1, 40, 40, 40), (4, 80, 80, 20)]);
        assert_eq!(report.preload_stored, 180);
        assert_eq!(report.failed_steps(), 0);
        assert!(report
            .steps
            .iter()
            .all(|step| step.txn_us.len() as u64 == step.commits));
        if cfg!(target_os = "linux") {
            assert!(report.io_counted);
        }
        // The trial's database is removed with its directory.
        assert_eq!(std::fs::read_dir(dir.path().join("db")).unwrap().count(), 0);
    }

    #[test]
    fn superseded_and_duplicate_events_are_settled_not_failed() {
        use secp256k1::{Keypair, SECP256K1};
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("corpus.jsonl");
        crate::generate_events(&corpus, 178, 7, 1_700_000_000, crate::EventMix::Kind1).unwrap();
        let notes: Vec<String> = std::fs::read_to_string(&corpus)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let keys = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let profile = |created_at, name: &str| {
            let event = crate::clients::signed(
                &keys,
                created_at,
                0,
                vec![],
                format!(r#"{{"name":"{name}"}}"#),
            );
            wok_event::json::to_tao_string(&event)
        };
        // The preload ends with a profile; the timed slice starts with an
        // older version of it and a note already stored.
        let mut lines = notes[..100].to_vec();
        lines.push(profile(1_700_000_100, "new"));
        lines.push(profile(1_700_000_050, "old"));
        lines.push(notes[0].clone());
        lines.extend_from_slice(&notes[100..]);
        std::fs::write(&corpus, lines.join("\n")).unwrap();

        let report = run(&Options {
            corpus,
            dir: dir.path().join("db"),
            batches: vec![4],
            step_events: 80,
            max_tags_per_filter: 8,
        })
        .unwrap();
        assert_eq!((report.preloaded, report.preload_stored), (101, 101));
        let step = &report.steps[0];
        assert_eq!(
            (step.events, step.stored, step.settled, step.unfinished),
            (80, 78, 2, 0)
        );
        assert_eq!(report.failed_steps(), 0);
    }

    #[test]
    fn the_default_corpus_holds_the_default_steps_and_a_history() {
        assert_eq!(
            default_corpus_events(&[1, 8, 64, 512], 2_000),
            16_240 + DEFAULT_PRELOAD
        );
    }

    #[test]
    fn a_corpus_smaller_than_the_steps_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("corpus.jsonl");
        crate::generate_events(&corpus, 50, 7, 1_700_000_000, crate::EventMix::Kind1).unwrap();
        let error = run(&Options {
            corpus,
            dir: dir.path().join("db"),
            batches: vec![1],
            step_events: 50,
            max_tags_per_filter: 8,
        })
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("holds back 50 events"),
            "{error}"
        );
    }
}
