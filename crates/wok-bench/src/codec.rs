//! `--scenario codec_cpu`: CPU per message of each step a publication and a
//! delivery pass through, in process on one thread. Inbound: the client's
//! `["EVENT", …]` message parsed as the relay parses it, the event packed and
//! its stored JSON normalized, its id hashed, its signature verified, and the
//! client's WebSocket frame decoded, with and without permessage-deflate.
//! Outbound: the event's `["EVENT", sub, …]` frame encoded, with and without
//! deflate. Deflate runs with context takeover and the relay's level.
//!
//! Each step runs over every corpus event twice: once timing each call, for
//! the percentiles, and once untimed, for the rate, so the clock's own cost
//! (tens of ns a call) does not bias the mean of the shortest steps. Only the
//! codec call is timed; its output is checked after the clock stops, on the
//! timed pass, and kept from the optimizer on both. An id or signature that
//! does not verify, an inbound frame that decodes to other bytes, or an
//! outbound frame a client would not decode back to the delivery is a
//! mismatch.

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::Value;
use std::hint::black_box;
use std::io::BufRead;
use std::path::Path;
use std::time::Instant;
use wok_ws::frame::{
    DeflateCtx, InflateCtx, MessageKind, Role, WsEncoder, WsEvent, WsParser, DEFAULT_LEVEL,
};

const MAX_MESSAGE: usize = 16 << 20;
const SUB_ID: &str = "feed";

#[derive(Serialize, Clone)]
pub struct Report {
    pub events: u64,
    pub mean_event_bytes: f64,
    pub deflate_level: u32,
    pub steps: Vec<Step>,
    pub mismatches: u64,
}

#[derive(Serialize, Clone)]
pub struct Step {
    pub name: String,
    /// Calls whose output checked out.
    pub ops: u64,
    /// Mean of the untimed pass.
    pub mean_ns: f64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub ops_per_s: f64,
    /// Message bytes per second of the untimed pass: the event JSON, or the
    /// whole message for the WebSocket steps.
    pub mb_per_s: f64,
    /// Compressed over uncompressed bytes, for the steps that compress.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_ratio: Option<f64>,
}

impl Report {
    /// Publications per second one core could take through every inbound
    /// step without deflate.
    pub fn inbound_rate(&self) -> f64 {
        let ns: f64 = self
            .steps
            .iter()
            .filter(|step| INBOUND.contains(&step.name.as_str()))
            .map(|step| step.mean_ns)
            .sum();
        1e9 / ns.max(f64::MIN_POSITIVE)
    }
}

/// The inbound steps a plain (uncompressed) publication pays for.
const INBOUND: [&str; 5] = [
    "ws decode",
    "EVENT message parse",
    "event pack",
    "id hash",
    "signature verify",
];

/// One corpus event and the inputs each step takes, built before timing.
struct Sample {
    message: String,
    value: Value,
    id: [u8; 32],
    pubkey: [u8; 32],
    sig: [u8; 64],
    delivery: String,
    client_frame: Vec<u8>,
}

impl Sample {
    fn value_len(&self) -> usize {
        // The message is `["EVENT",` + the event + `]`.
        self.message.len() - 10
    }
}

pub fn run(corpus: &Path) -> Result<Report> {
    let mut samples = Vec::new();
    for line in std::io::BufReader::new(std::fs::File::open(corpus)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        samples.push(sample(&line)?);
    }
    anyhow::ensure!(!samples.is_empty(), "--scenario codec_cpu needs a corpus");
    let events = samples.len() as u64;
    let event_bytes: usize = samples.iter().map(Sample::value_len).sum();
    let message_bytes: usize = samples.iter().map(|s| s.message.len()).sum();
    let delivery_bytes: usize = samples.iter().map(|s| s.delivery.len()).sum();
    let limits = wok_event::EventLimits {
        max_event_size: usize::MAX,
        max_num_tags: usize::MAX,
        max_tag_val_size: usize::MAX,
    };
    let mut steps = Vec::new();

    // A connection's parser and encoder live across its messages, and with
    // deflate's context takeover so does their history, so each pass keeps
    // one of each, as one connection does.
    steps.push(measure(
        "ws decode",
        &samples,
        |s| s.message.len(),
        || WsParser::new(MAX_MESSAGE, None),
        |parser, s| parser.feed(&s.client_frame),
        |s, events| text_of(events) == Some(s.message.as_bytes()),
    ));
    steps.push(measure(
        "EVENT message parse",
        &samples,
        |s| s.message.len(),
        || (),
        |_, s| wok_relay::protocol::ClientCommand::parse(&s.message),
        |_, command| matches!(command, Ok(wok_relay::protocol::ClientCommand::Event(_))),
    ));
    steps.push(measure(
        "event pack",
        &samples,
        Sample::value_len,
        || (),
        |_, s| {
            let parsed = wok_event::parse_and_verify_event(&s.value, &limits, None, false, false);
            // The stored JSON and packed bytes are the step's output; keep
            // them, or the optimizer may drop the work that builds them.
            if let Ok(parsed) = &parsed {
                black_box(parsed.json.as_bytes());
                black_box(parsed.packed.as_bytes());
            }
            parsed
        },
        |_, parsed| parsed.is_ok(),
    ));
    steps.push(measure(
        "id hash",
        &samples,
        Sample::value_len,
        || (),
        |_, s| wok_event::verify_id(&s.value, &s.id),
        |_, verified| verified.is_ok(),
    ));
    steps.push(measure(
        "signature verify",
        &samples,
        |_| 64,
        || (),
        |_, s| wok_event::verify_sig(&s.sig, &s.id, &s.pubkey),
        |_, verified| matches!(verified, Ok(true)),
    ));

    let compressed = {
        let mut client = WsEncoder::with_role(Some(DeflateCtx::new(true)), Role::Client);
        samples
            .iter()
            .map(|s| client.encode_message(MessageKind::Text, s.message.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut step = measure(
        "ws decode + inflate",
        &samples,
        |s| s.message.len(),
        || {
            (
                WsParser::new(MAX_MESSAGE, Some(InflateCtx::new(true))),
                compressed.iter(),
            )
        },
        |(parser, frames), _| parser.feed(frames.next().expect("one frame per sample")),
        |s, events| text_of(events) == Some(s.message.as_bytes()),
    );
    step.size_ratio =
        Some(compressed.iter().map(Vec::len).sum::<usize>() as f64 / message_bytes as f64);
    steps.push(step);

    // Outbound frames are checked as a client reads them.
    let mut client = WsParser::with_role(MAX_MESSAGE, None, Role::Client);
    steps.push(measure(
        "ws encode",
        &samples,
        |s| s.delivery.len(),
        || WsEncoder::new(None),
        |encoder, s| encoder.encode_message(MessageKind::Text, s.delivery.as_bytes()),
        |s, frame| {
            frame
                .as_ref()
                .is_ok_and(|frame| decodes_to(&mut client, frame, s.delivery.as_bytes()))
        },
    ));
    let mut client = WsParser::with_role(MAX_MESSAGE, Some(InflateCtx::new(true)), Role::Client);
    let mut sent = 0usize;
    let mut step = measure(
        "ws encode + deflate",
        &samples,
        |s| s.delivery.len(),
        || WsEncoder::new(Some(DeflateCtx::new(true))),
        |encoder, s| encoder.encode_message(MessageKind::Text, s.delivery.as_bytes()),
        |s, frame| {
            frame.as_ref().is_ok_and(|frame| {
                sent += frame.len();
                decodes_to(&mut client, frame, s.delivery.as_bytes())
            })
        },
    );
    step.size_ratio = Some(sent as f64 / delivery_bytes as f64);
    steps.push(step);

    let mismatches = steps.iter().map(|step| events - step.ops).sum();
    Ok(Report {
        events,
        mean_event_bytes: event_bytes as f64 / events as f64,
        deflate_level: DEFAULT_LEVEL,
        steps,
        mismatches,
    })
}

fn sample(line: &str) -> Result<Sample> {
    let value: Value = serde_json::from_str(line)?;
    let hex = |field: &str| -> Result<Vec<u8>> {
        let text = value[field]
            .as_str()
            .with_context(|| format!("event {field}"))?;
        Ok(hex::decode(text)?)
    };
    let id: [u8; 32] = hex("id")?.try_into().ok().context("event id size")?;
    let pubkey: [u8; 32] = hex("pubkey")?.try_into().ok().context("pubkey size")?;
    let sig: [u8; 64] = hex("sig")?.try_into().ok().context("sig size")?;
    let event = wok_event::json::to_tao_string(&value);
    let message = format!("[\"EVENT\",{event}]");
    let delivery = format!("[\"EVENT\",\"{SUB_ID}\",{event}]");
    let client_frame = WsEncoder::with_role(None, Role::Client)
        .encode_message(MessageKind::Text, message.as_bytes())?;
    Ok(Sample {
        message,
        value,
        id,
        pubkey,
        sig,
        delivery,
        client_frame,
    })
}

/// The one text message a parser's output holds.
fn text_of(events: &Result<Vec<WsEvent>, wok_ws::frame::WsError>) -> Option<&[u8]> {
    match events.as_ref().ok()?.as_slice() {
        [WsEvent::Message(MessageKind::Text, bytes)] => Some(bytes),
        _ => None,
    }
}

/// Whether `parser` reads `frame` as exactly one text message, `expected`.
fn decodes_to(parser: &mut WsParser, frame: &[u8], expected: &[u8]) -> bool {
    text_of(&parser.feed(frame)) == Some(expected)
}

/// Times `op` on every sample, with state from `new_state` that lasts one
/// pass. On the timed pass, `check` judges each output after the clock
/// stops; `ops` counts those that pass. The untimed pass gives the mean.
fn measure<'a, S, O>(
    name: &str,
    samples: &'a [Sample],
    bytes: impl Fn(&Sample) -> usize,
    mut new_state: impl FnMut() -> S,
    mut op: impl FnMut(&mut S, &'a Sample) -> O,
    mut check: impl FnMut(&Sample, &O) -> bool,
) -> Step {
    let mut hist = Histogram::<u64>::new(3).expect("histogram bounds");
    let mut ops = 0u64;
    let mut state = new_state();
    for s in samples {
        let started = Instant::now();
        let output = black_box(op(&mut state, black_box(s)));
        let ns = started.elapsed().as_nanos() as u64;
        hist.record(ns.max(1)).expect("histogram range");
        ops += u64::from(check(s, &output));
    }
    let mut state = new_state();
    let started = Instant::now();
    for s in samples {
        black_box(op(&mut state, black_box(s)));
    }
    let secs = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    let n = samples.len() as f64;
    let total: usize = samples.iter().map(&bytes).sum();
    Step {
        name: name.into(),
        ops,
        mean_ns: secs * 1e9 / n,
        p50_ns: hist.value_at_quantile(0.50),
        p99_ns: hist.value_at_quantile(0.99),
        max_ns: hist.max(),
        ops_per_s: n / secs,
        mb_per_s: total as f64 / secs / 1e6,
        size_ratio: None,
    }
}

pub fn render_markdown(report: &Report) -> String {
    let mut s = format!(
        "\n## codec_cpu: {} events, {:.0} bytes on average\n\nCPU per message on one thread. The mean and rate come from an untimed pass, the percentiles from timing each call; checks run outside the clock. Deflate is level {} with context takeover; its ratio is compressed over uncompressed bytes. One core takes about {:.0} uncompressed publications per second through the inbound steps (`ws decode` to `signature verify`).\n\n| step | mean ns | p50 ns | p99 ns | max ns | ops/s | MB/s | ratio | checked |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        report.events,
        report.mean_event_bytes,
        report.deflate_level,
        report.inbound_rate(),
    );
    for step in &report.steps {
        s.push_str(&format!(
            "| {} | {:.0} | {} | {} | {} | {:.0} | {:.1} | {} | {}/{} |\n",
            step.name,
            step.mean_ns,
            step.p50_ns,
            step.p99_ns,
            step.max_ns,
            step.ops_per_s,
            step.mb_per_s,
            step.size_ratio
                .map_or_else(String::new, |ratio| format!("{ratio:.2}")),
            step.ops,
            report.events,
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_checks_out_on_a_generated_corpus() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("corpus.jsonl");
        crate::generate_events(&corpus, 60, 3, 1_700_000_000, crate::EventMix::Realistic).unwrap();
        let report = run(&corpus).unwrap();
        assert_eq!(report.events, 60);
        assert_eq!(report.mismatches, 0);
        let names: Vec<_> = report.steps.iter().map(|step| step.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "ws decode",
                "EVENT message parse",
                "event pack",
                "id hash",
                "signature verify",
                "ws decode + inflate",
                "ws encode",
                "ws encode + deflate",
            ]
        );
        assert!(report.steps.iter().all(|step| step.ops == 60));
        let ratio = |name: &str| {
            report
                .steps
                .iter()
                .find(|step| step.name == name)
                .and_then(|step| step.size_ratio)
                .unwrap()
        };
        assert!(ratio("ws decode + inflate") < 1.0);
        assert!(ratio("ws encode + deflate") < 1.0);
        assert!(report.inbound_rate() > 0.0);
    }

    #[test]
    fn a_bad_signature_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("corpus.jsonl");
        crate::generate_events(&corpus, 2, 3, 1_700_000_000, crate::EventMix::Kind1).unwrap();
        let text = std::fs::read_to_string(&corpus).unwrap();
        let mut lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let sig = lines[0]["sig"].as_str().unwrap().to_owned();
        let flipped = if sig.starts_with('0') { "1" } else { "0" };
        lines[0]["sig"] = Value::String(format!("{flipped}{}", &sig[1..]));
        let rewritten: Vec<String> = lines.iter().map(wok_event::json::to_tao_string).collect();
        std::fs::write(&corpus, rewritten.join("\n")).unwrap();
        let report = run(&corpus).unwrap();
        let verify = report
            .steps
            .iter()
            .find(|step| step.name == "signature verify")
            .unwrap();
        assert_eq!(verify.ops, 1);
        assert_eq!(report.mismatches, 1);
    }

    #[test]
    fn outbound_frames_check_only_when_a_client_reads_the_delivery() {
        let delivery = br#"["EVENT","feed",{"content":"hello hello hello"}]"#;
        let client = || WsParser::with_role(MAX_MESSAGE, Some(InflateCtx::new(true)), Role::Client);
        let mut server = WsEncoder::new(Some(DeflateCtx::new(true)));
        let frame = server.encode_message(MessageKind::Text, delivery).unwrap();
        assert!(decodes_to(&mut client(), &frame, delivery));
        // Another message, a corrupt payload, and a cut frame do not.
        assert!(!decodes_to(
            &mut client(),
            &frame,
            b"[\"EVENT\",\"feed\",{}]"
        ));
        let mut corrupt = frame.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        assert!(!decodes_to(&mut client(), &corrupt, delivery));
        assert!(!decodes_to(
            &mut client(),
            &frame[..frame.len() - 1],
            delivery
        ));
        // A server reads only masked frames, so an unmasked one is refused.
        let plain = WsEncoder::new(None)
            .encode_message(MessageKind::Text, delivery)
            .unwrap();
        assert!(!decodes_to(
            &mut WsParser::new(MAX_MESSAGE, None),
            &plain,
            delivery
        ));
    }
}
