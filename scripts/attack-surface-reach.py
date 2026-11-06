#!/usr/bin/env python3
"""Measure which relay functions each kind of caller reaches, per profile.

Builds the `reachability` probe in `crates/wok-compat/tests/` once with
coverage instrumentation, then runs each of its phases (startup, anonymous,
authenticated, admin, local) against a relay of each profile in
`crates/wok-compat/tests/profiles/`, in a process of its own. From each run it
keeps the functions of the relay crates that ran at least once, and writes,
per profile:

- anonymous: what an unauthenticated client reaches beyond startup;
- authenticated: what NIP-42 AUTH adds to that;
- admin: what an admin's NIP-98 requests add to that;
- local: what a peer the Unix socket admits adds to that.

Closures are named by the function that holds them, without their number,
so adding a closure to a function already reached changes nothing.

    scripts/attack-surface-reach.py            # print the report
    scripts/attack-surface-reach.py --check    # fail on functions newly reached
    scripts/attack-surface-reach.py --bless    # rewrite the baseline

The baseline is `crates/wok-compat/tests/reachability/<profile>.txt`. `--check`
fails when a phase reaches a function its baseline does not list, so code that
becomes reachable before authentication is reviewed before it lands, and when a
phase that reached functions reaches none, so a broken phase is not mistaken for
a smaller surface; a function no longer reached is reported but does not fail. Needs `cargo-llvm-cov`,
`rustfilt` and the `llvm-tools-preview` rustup component.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILES = ROOT / "crates/wok-compat/tests/profiles"
BASELINE = ROOT / "crates/wok-compat/tests/reachability"
TARGET = ROOT / "target/reachability"
RELAY_CRATES = re.compile(r"crates/wok-(relay|ws|unix|event|query|negentropy|db)/src/")
PHASES = ["startup", "anonymous", "authenticated", "admin", "local"]
# Background code that timers and file watchers run whenever they fire, not
# because of anything a client sent; whether it lands in a phase is timing.
# The maintenance timer is off in the probe instead: requests also run the
# code it runs, such as deleting an event, so dropping that by name would
# hide what they reach.
BACKGROUND = re.compile(r"::run_db_watch\b")
HASH = re.compile(r"::h[0-9a-f]{16}$")
CLOSURE = re.compile(r"\{closure#\d+\}")


def run(cmd, **kwargs):
    try:
        return subprocess.run(cmd, check=True, cwd=ROOT, **kwargs)
    except subprocess.CalledProcessError as failed:
        # Captured output is otherwise lost, and with it why the command failed:
        # cargo writes its errors to stderr, libtest a failing test's to stdout.
        for captured in (failed.stdout, failed.stderr):
            if captured:
                text = captured if isinstance(captured, str) else captured.decode(errors="replace")
                sys.stderr.write(text)
        raise


def llvm_tool(name):
    sysroot = run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip()
    host = re.search(r"host: (\S+)", run(["rustc", "-vV"], capture_output=True, text=True).stdout).group(1)
    tool = Path(sysroot) / "lib/rustlib" / host / "bin" / name
    if not tool.exists():
        sys.exit(f"{tool} is missing: rustup component add llvm-tools-preview")
    return tool


def build_probe():
    env = dict(os.environ)
    shown = run(["cargo", "llvm-cov", "show-env", "--export-prefix"], capture_output=True, text=True).stdout
    for line in shown.splitlines():
        key, _, value = line.removeprefix("export ").partition("=")
        env[key] = value.strip("'")
    env["CARGO_TARGET_DIR"] = str(TARGET)
    out = run(
        ["cargo", "test", "-p", "wok-compat", "--test", "reachability", "--no-run", "--locked",
         "--message-format=json"],
        capture_output=True, text=True, env=env,
    ).stdout
    for line in out.splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact" and message.get("executable") \
                and message["target"]["name"] == "reachability":
            return Path(message["executable"])
    sys.exit("could not find the reachability probe binary")


def reached(binary, profile, phase, work, profdata, cov, demangled):
    """The relay functions one phase of one profile ran at least once."""
    raw = work / f"{profile}-{phase}.profraw"
    env = dict(os.environ, WOK_REACH_PROFILE=profile, LLVM_PROFILE_FILE=str(raw))
    run([str(binary), "--ignored", "--exact", f"reach_{phase}", "--test-threads=1"],
        env=env, capture_output=True)
    merged = work / f"{profile}-{phase}.profdata"
    run([str(profdata), "merge", "-sparse", str(raw), "-o", str(merged)])
    export = run(
        [str(cov), "export", "-format=text", f"-instr-profile={merged}", str(binary),
         "-ignore-filename-regex=/(\\.cargo|\\.rustup|rustc|wok-compat|wok-bench|wok-cli)/"],
        capture_output=True, text=True,
    ).stdout
    names = set()
    for function in json.loads(export)["data"][0]["functions"]:
        if function["count"] > 0 and any(RELAY_CRATES.search(f) for f in function["filenames"]):
            names.add(function["name"])
    demangled.batch(sorted(names))
    return {plain for plain in map(demangled, names) if not BACKGROUND.search(plain)}


def demangler():
    # cargo-llvm-cov 0.7 dropped its `demangle` subcommand; rustfilt is the
    # demangler the rustc book names for coverage reports.
    rustfilt = shutil.which("rustfilt")
    if not rustfilt:
        sys.exit("rustfilt is missing: cargo install rustfilt")
    cache = {}

    def demangle(name):
        if name not in cache:
            out = run([rustfilt], input=name + "\n",
                      capture_output=True, text=True).stdout.strip()
            cache[name] = CLOSURE.sub("{closure}", HASH.sub("", out or name))
        return cache[name]

    def batch(names):
        missing = [n for n in names if n not in cache]
        if missing:
            out = run([rustfilt], input="\n".join(missing) + "\n",
                      capture_output=True, text=True).stdout.splitlines()
            for name, plain in zip(missing, out):
                cache[name] = CLOSURE.sub("{closure}", HASH.sub("", plain.strip() or name))

    demangle.batch = batch
    return demangle


def measure(profiles, runs):
    """Each profile's phase sets, the union over `runs` runs: a function some
    runs reach and others miss, such as one behind a timing-dependent branch,
    is in the baseline either way."""
    binary = build_probe()
    profdata, cov = llvm_tool("llvm-profdata"), llvm_tool("llvm-cov")
    demangle = demangler()
    results = {}
    with tempfile.TemporaryDirectory(prefix="wok-reach-") as tmp:
        work = Path(tmp)
        for profile in profiles:
            sets = {phase: set() for phase in PHASES[1:]}
            for _ in range(runs):
                ran = {phase: reached(binary, profile, phase, work, profdata, cov, demangle)
                       for phase in PHASES}
                seen = ran["startup"]
                for phase in PHASES[1:]:
                    sets[phase] |= ran[phase] - seen
                    if phase == "anonymous":
                        seen = seen | ran[phase]
            results[profile] = {phase: sorted(names) for phase, names in sets.items()}
    return results


def render(profile, sets):
    lines = [f"# Relay functions reached in the `{profile}` profile, beyond startup.",
             "# Written by scripts/attack-surface-reach.py --bless; see docs/attack-surface.md."]
    for phase in PHASES[1:]:
        lines.append(f"\n## {phase}: {len(sets[phase])}")
        lines.extend(sets[phase])
    return "\n".join(lines) + "\n"


def parse(text):
    sets, phase = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            phase = line[3:].split(":")[0]
            sets[phase] = set()
        elif phase and line and not line.startswith("#"):
            sets[phase].add(line)
    return sets


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail on functions newly reached")
    mode.add_argument("--bless", action="store_true", help="rewrite the baseline")
    parser.add_argument("--runs", type=int, help="runs to union (default: 3 with --bless, else 1)")
    parser.add_argument("profiles", nargs="*", help="profiles to measure (default: all)")
    args = parser.parse_args()
    profiles = args.profiles or sorted(p.stem for p in PROFILES.glob("*.toml"))
    results = measure(profiles, args.runs or (3 if args.bless else 1))

    new_reach = False
    for profile, sets in results.items():
        counts = ", ".join(f"{phase} {len(sets[phase])}" for phase in PHASES[1:])
        print(f"{profile}: {counts}")
        path = BASELINE / f"{profile}.txt"
        if args.bless:
            BASELINE.mkdir(exist_ok=True)
            path.write_text(render(profile, sets))
            continue
        if not path.exists():
            if args.check:
                print(f"  no baseline at {path.relative_to(ROOT)}")
                new_reach = True
            continue
        baseline = parse(path.read_text())
        for phase in PHASES[1:]:
            now, then = set(sets[phase]), baseline.get(phase, set())
            if then and not now:
                print(f"  {phase}: reached nothing; its baseline lists {len(then)}")
                new_reach = True
                continue
            for name in sorted(now - then):
                print(f"  + {phase}: {name}")
                new_reach = True
            for name in sorted(then - now):
                print(f"  - {phase}: {name}")
    if args.check and new_reach:
        sys.exit("\nNewly reached functions are listed with +, and phases that reached nothing are "
                 "named. If that is intended, review them and rerun with --bless.")


if __name__ == "__main__":
    main()
