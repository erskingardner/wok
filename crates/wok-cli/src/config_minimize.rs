//! `wok config minimize`: remove the keys that repeat the preset's values, so
//! the file keeps only deliberate choices and the relay follows the preset
//! when a default changes.

use anyhow::{anyhow, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use wok_relay::Config;

/// Lines of unchanged context around each change in `--dry-run` output.
const CONTEXT: usize = 3;

/// Minimize the config file at `path`. With `dry_run`, return the change as
/// a unified diff and leave the file alone; otherwise keep the original as a
/// backup beside it and replace the file.
pub fn run(path: &Path, dry_run: bool) -> Result<String> {
    let label = path.display();
    let text = std::fs::read_to_string(path).map_err(|error| anyhow!("{label}: {error}"))?;
    let preset = Config::parse_toml(&text)
        .map_err(|error| anyhow!("{label}: {error}"))?
        .preset;
    let minimized = Config::minimize_toml(&text).map_err(|error| anyhow!("{label}: {error}"))?;
    let removed = &minimized.removed;
    if removed.is_empty() {
        return Ok(format!(
            "{label} sets no key to preset {preset}'s value; nothing to remove\n"
        ));
    }
    if dry_run {
        let name = label.to_string();
        return Ok(unified_diff(&text, &minimized.text, &name, &name));
    }
    let backup = write_backup(path, &text)?;
    wok_relay::config::write_file(path, minimized.text.as_bytes())
        .map_err(|error| anyhow!("{label}: {error}"))?;
    let mut out = format!(
        "Removed {} {} that repeated preset {preset}'s values from {label}; the original is {}\n",
        removed.len(),
        if removed.len() == 1 { "key" } else { "keys" },
        backup.display()
    );
    for key in removed {
        out.push_str(&format!("  {key}\n"));
    }
    Ok(out)
}

/// Copy `text`, the file's contents, to the first free `<file>.bak`,
/// `<file>.bak.1`, … beside it, with the file's permissions.
fn write_backup(path: &Path, text: &str) -> Result<PathBuf> {
    let permissions = std::fs::metadata(path)?.permissions();
    let mut name = path.as_os_str().to_owned();
    name.push(".bak");
    let first = PathBuf::from(name);
    for attempt in 0.. {
        let candidate = if attempt == 0 {
            first.clone()
        } else {
            PathBuf::from(format!("{}.{attempt}", first.display()))
        };
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(anyhow!("{}: {error}", candidate.display())),
        };
        file.set_permissions(permissions)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        return Ok(candidate);
    }
    unreachable!("the backup suffixes are unbounded")
}

/// A unified diff of two texts, line by line, from their longest common
/// subsequence.
fn unified_diff(old: &str, new: &str, old_name: &str, new_name: &str) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum Op {
        Keep,
        Remove,
        Add,
    }
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    let mut common = vec![vec![0usize; new.len() + 1]; old.len() + 1];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            common[i][j] = if old[i] == new[j] {
                common[i + 1][j + 1] + 1
            } else {
                common[i + 1][j].max(common[i][j + 1])
            };
        }
    }
    // Each step with the old and new line indexes it starts from.
    let mut steps = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < old.len() || j < new.len() {
        let op = if i < old.len() && j < new.len() && old[i] == new[j] {
            Op::Keep
        } else if i < old.len() && (j == new.len() || common[i + 1][j] >= common[i][j + 1]) {
            Op::Remove
        } else {
            Op::Add
        };
        steps.push((op, i, j));
        match op {
            Op::Keep => (i, j) = (i + 1, j + 1),
            Op::Remove => i += 1,
            Op::Add => j += 1,
        }
    }

    let mut out = format!("--- {old_name}\n+++ {new_name} (minimized)\n");
    let changes: Vec<usize> = (0..steps.len())
        .filter(|&index| steps[index].0 != Op::Keep)
        .collect();
    let mut next = 0;
    while next < changes.len() {
        // Extend the hunk while the next change is within two contexts.
        let start = changes[next].saturating_sub(CONTEXT);
        let mut last = changes[next];
        next += 1;
        while next < changes.len() && changes[next] - last <= 2 * CONTEXT {
            last = changes[next];
            next += 1;
        }
        let end = (last + CONTEXT + 1).min(steps.len());
        let hunk = &steps[start..end];
        let old_count = hunk.iter().filter(|step| step.0 != Op::Add).count();
        let new_count = hunk.iter().filter(|step| step.0 != Op::Remove).count();
        // An empty range is named by the line before it.
        let (_, old_start, new_start) = hunk[0];
        out.push_str(&format!(
            "@@ -{},{old_count} +{},{new_count} @@\n",
            old_start + usize::from(old_count > 0),
            new_start + usize::from(new_count > 0),
        ));
        for &(op, i, j) in hunk {
            match op {
                Op::Keep => out.push_str(&format!(" {}\n", old[i])),
                Op::Remove => out.push_str(&format!("-{}\n", old[i])),
                Op::Add => out.push_str(&format!("+{}\n", new[j])),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# Example relay.\n\
                        preset = \"public\"\n\
                        \n\
                        [relay]\n\
                        # Behind nginx.\n\
                        bind = \"127.0.0.1\"\n\
                        real_ip_header = \"x-real-ip\"\n\
                        \n\
                        [relay.abuse]\n\
                        event_burst = 100\n";

    #[test]
    fn dry_run_prints_a_diff_and_leaves_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(&path, FILE).unwrap();
        let name = path.display().to_string();
        let diff = run(&path, true).unwrap();
        assert_eq!(
            diff,
            format!(
                "--- {name}\n\
                 +++ {name} (minimized)\n\
                 @@ -2,9 +2,4 @@\n \
                 preset = \"public\"\n \
                 \n \
                 [relay]\n\
                 -# Behind nginx.\n\
                 -bind = \"127.0.0.1\"\n \
                 real_ip_header = \"x-real-ip\"\n\
                 -\n\
                 -[relay.abuse]\n\
                 -event_burst = 100\n"
            )
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), FILE);
        assert!(!directory.path().join("wok.toml.bak").exists());
    }

    #[test]
    fn minimize_writes_the_file_and_keeps_a_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(&path, FILE).unwrap();
        std::fs::write(directory.path().join("wok.toml.bak"), "older backup").unwrap();

        let report = run(&path, false).unwrap();
        let backup = directory.path().join("wok.toml.bak.1");
        assert!(
            report.starts_with("Removed 2 keys that repeated preset public's values"),
            "{report}"
        );
        assert!(
            report.ends_with("  relay.abuse.event_burst\n  relay.bind\n"),
            "{report}"
        );
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), FILE);
        assert_eq!(
            std::fs::read_to_string(directory.path().join("wok.toml.bak")).unwrap(),
            "older backup"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# Example relay.\n\
             preset = \"public\"\n\
             \n\
             [relay]\n\
             real_ip_header = \"x-real-ip\"\n"
        );

        // Nothing is left to remove, so nothing is written.
        let report = run(&path, false).unwrap();
        assert!(report.ends_with("nothing to remove\n"), "{report}");
        assert!(!directory.path().join("wok.toml.bak.2").exists());
    }

    #[test]
    fn diff_separates_distant_changes_into_hunks() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n";
        let new = "b\nc\nd\ne\nf\ng\nh\ni\nj\nk\n";
        assert_eq!(
            unified_diff(old, new, "x", "x"),
            "--- x\n+++ x (minimized)\n\
             @@ -1,4 +1,3 @@\n-a\n b\n c\n d\n\
             @@ -8,3 +7,4 @@\n h\n i\n j\n+k\n"
        );
    }
}
