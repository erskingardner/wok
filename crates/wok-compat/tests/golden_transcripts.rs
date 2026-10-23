//! Golden transcripts: one fixed script of client messages and HTTP requests,
//! sent to a relay of every profile in `tests/profiles/`, with what the relay
//! answers saved in `tests/transcripts/<profile>.txt`. A change that alters
//! what a client sees, such as refusing a request at an earlier check, shows
//! up as a diff of those files. Rewrite them with `WOK_BLESS_TRANSCRIPTS=1`
//! and review the diff in the pull request.

use std::path::PathBuf;

#[path = "support/surface.rs"]
mod surface;
#[path = "support/transcript.rs"]
mod transcript;
use surface::*;
use transcript::record;

const BLESS: &str = "WOK_BLESS_TRANSCRIPTS";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_profile_answers_as_its_transcript_says() {
    let bless = std::env::var_os(BLESS).is_some();
    let names = profile_names();
    let mut problems = Vec::new();
    for name in &names {
        let cfg = load_profile(name);
        let relay = Relay::start(cfg.clone()).await;
        let transcript = record(name, &relay, &cfg).await;
        relay.stop().await;
        let path = transcripts_dir().join(format!("{name}.txt"));
        if bless {
            std::fs::write(&path, &transcript).unwrap();
            continue;
        }
        let golden = std::fs::read_to_string(&path).unwrap_or_default();
        if golden != transcript {
            problems.push(first_difference(name, &golden, &transcript));
        }
    }
    for file in std::fs::read_dir(transcripts_dir()).unwrap() {
        let file = file.unwrap().path();
        let stem = file.file_stem().unwrap().to_string_lossy().into_owned();
        if !names.contains(&stem) {
            problems.push(format!("{} has no profile", file.display()));
        }
    }
    assert!(
        problems.is_empty(),
        "the relay's answers differ from tests/transcripts/:\n{}\n\nIf the change is intended, \
         rerun with {BLESS}=1 and review the diff of tests/transcripts/ in the pull request.",
        problems.join("\n")
    );
}

fn transcripts_dir() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/transcripts")
}

fn first_difference(name: &str, golden: &str, now: &str) -> String {
    let (golden, now): (Vec<&str>, Vec<&str>) = (golden.lines().collect(), now.lines().collect());
    let at = golden
        .iter()
        .zip(&now)
        .position(|(a, b)| a != b)
        .unwrap_or(golden.len().min(now.len()));
    let context =
        |lines: &[&str]| lines[at.saturating_sub(2)..(at + 3).min(lines.len())].join("\n  ");
    format!(
        "{name}.txt, line {}:\n  golden:\n  {}\n  now:\n  {}",
        at + 1,
        context(&golden),
        context(&now)
    )
}
