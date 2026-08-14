use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn git_path(repo: &Path, name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(git(repo, &["rev-parse", "--git-path", name])?);
    Some(if path.is_absolute() {
        path
    } else {
        repo.join(path)
    })
}

fn main() {
    println!("cargo:rerun-if-env-changed=WOK_GIT_HASH");
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo = manifest
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| manifest.join("../.."));

    if let Some(head) = git_path(&repo, "HEAD") {
        println!("cargo:rerun-if-changed={}", head.display());
    }
    if let Some(reference) = git(&repo, &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git_path(&repo, &reference) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if let Some(path) = git_path(&repo, "packed-refs") {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let hash = std::env::var("WOK_GIT_HASH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| git(&repo, &["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=WOK_GIT_HASH={hash}");
}
