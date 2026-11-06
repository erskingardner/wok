#!/usr/bin/env python3
"""Private-VM matched-network comparison; preserve seeds and failed evidence.

Qualification gates the full unique-event campaign. Each measured cell starts
from a closed pristine seed copy. Only marker-owned successful clones are
removed. Stock fastr acknowledgements do not promise fsync durability.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ARMS = ("wok", "fastr", "strfry")
GIB = 1 << 30
CAPS = {"AllowedCPUs": "0-15", "CPUQuota": "1600%", "MemoryMax": "64G", "LimitNOFILE": "65536"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def cgroup_stats():
    relative = Path("/proc/self/cgroup").read_text().strip().split("::")[-1]
    root = Path("/sys/fs/cgroup") / relative.lstrip("/")
    stats = {name: (root / name).read_text() for name in
             ["cpu.stat", "memory.peak", "memory.events", "io.stat", "cpuset.cpus.effective", "cpu.max", "memory.max", "memory.swap.max"]
             if (root / name).exists()}
    stats["cgroup_path"] = relative
    stats["ancestor_envelopes"] = {str(parent): {name: (parent / name).read_text() for name in
        ["cpu.max", "cpuset.cpus.effective", "memory.max", "memory.swap.max"] if (parent / name).exists()}
        for parent in root.parents if parent != Path("/sys/fs/cgroup") and str(parent).startswith("/sys/fs/cgroup/")}
    return stats


def limits():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    return {"nofile": {"soft": soft, "hard": hard}}


def check_caps(memory_gib, *, allow_process_affinity=False):
    stats = cgroup_stats()
    if "cpuset.cpus.effective" in stats:
        assert stats["cpuset.cpus.effective"].strip() == "0-15", "requires effective CPUs0-15"
    else:
        assert allow_process_affinity, "cgroup cpuset is unavailable; relay-side checks require delegation"
        affinity = sorted(os.sched_getaffinity(0))
        assert affinity == list(range(16)), "load process affinity must be exactly CPUs0-15"
        stats["cpu_affinity_verification"] = {"method": "process sched_getaffinity fallback",
            "actual_cpus": affinity, "missing_cgroup_file": "cpuset.cpus.effective",
            "note": "user cgroup has no delegated cpuset file; this records the real process affinity, not an assumed cgroup cpuset"}
    assert stats["memory.max"].strip() == str(memory_gib * GIB), "wrong memory cap"
    assert stats["cpu.max"].split() == ["1600000", "100000"], "wrong CPU quota"
    assert limits()["nofile"]["soft"] >= 65536, "open-file limit too low"
    return stats


def validate_predecessor_identity(old, current, *, rerun_network, rerun_arms):
    """Only explicitly invalidated arms may change while valid cells are reused."""
    rerun_arms = set(rerun_arms)
    resume = current["options"].get("resume_measured",False)
    if resume:
        assert rerun_network and not rerun_arms, "measurement resume cannot invalidate an arm"
        assert old["binaries"] == current["binaries"], "measurement resume requires identical relay binaries"
        assert old["bench_binary_sha256"] == current["bench_binary_sha256"], "measurement resume requires identical driver"
    assert set(old["binaries"]) <= set(current["binaries"]), "predecessor arm missing"
    assert rerun_arms <= set(old["binaries"]) & set(current["binaries"]), "unknown recovery arm"
    assert not rerun_arms or rerun_network, "recovery requires corrected COUNT validation"
    for arm, value in old["binaries"].items():
        if arm not in rerun_arms:
            assert value == current["binaries"][arm], "predecessor relay binaries differ"
    if not rerun_network or rerun_arms:
        assert old["bench_binary_sha256"] == current["bench_binary_sha256"], "predecessor benchmark binary differs"
    ignored = {"root", "load_root", "source_manifest", "strfry_config_template", "predecessor",
               "rerun_network", "rerun_arms", "rocksdb_binary", "ssh_identity", "unit_prefix",
               "allow_read_ingress_overload", "retain_overload_on_load", "copy_headroom_gib", "resume_measured"}
    if current["options"].get("allow_read_ingress_overload"):
        assert rerun_network and (rerun_arms == {"rocksdb"} or resume), "overload policy is restricted to explicit Rocks recovery"
        ignored.add("minimum_free_gib")  # Disk copy guard only, outside measured workload/caps.
    if rerun_network and not rerun_arms:
        ignored |= {"bench_binary", "load_bench_binary"}
    assert {k:v for k,v in old["options"].items() if k not in ignored} == {k:v for k,v in current["options"].items() if k not in ignored}, "predecessor workload/options differ"
    assert old["wok_template_sha256"] == current["wok_template_sha256"] and old["fastr_environment"] == current["fastr_environment"], "predecessor configuration differs"


def matrix(rates, repetitions, arms=ARMS):
    result = []
    for repetition in range(1, repetitions + 1):
        for rate in rates if repetition % 2 else list(reversed(rates)):
            index = rates.index(rate) % len(arms)
            order = list(arms[index:]) + list(arms[:index])
            if repetition % 2 == 0:
                order.reverse()  # At each fixed rate, every arm pair flips order.
            for arm in order:
                result.append({"name": f"r{repetition}-w{rate}-{arm}", "arm": arm,
                               "write_rate": rate, "repetition": repetition})
    return result


def inventory(root, content):
    root = Path(root)
    assert root.is_dir() and not root.is_symlink(), root
    result = []
    for path in sorted(root.rglob("*")):
        assert not path.is_symlink(), f"unexpected seed symlink: {path}"
        if path.is_file():
            stat = path.stat()
            row = {"path": str(path.relative_to(root)), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
            if content:
                row["sha256"] = sha(path)
            result.append(row)
    assert result, "empty seed"
    return result


def metadata(rows):
    return [{key: value for key, value in row.items() if key != "sha256"} for row in rows]


def artifact_hashes(root, names):
    return {name: sha(Path(root) / name) for name in names}


def verify_artifacts(root, values):
    for name, digest in values.items():
        path = Path(root) / name
        assert not Path(name).is_absolute() and ".." not in Path(name).parts, "artifact path escapes evidence directory"
        assert sha(path) == digest, f"evidence changed: {path}"


def corpus_source(corpus):
    """Resolve imported corpus evidence to its immutable original bytes."""
    seen = set()
    corpus = Path(corpus)
    while True:
        assert corpus not in seen, "corpus source cycle"
        seen.add(corpus)
        marker = read(corpus / "complete.json")
        imported = marker.get("imported_corpus_path")
        if not imported:
            source = corpus / "corpus.jsonl"
            manifest = read(corpus / "corpus-manifest.json")
            assert sha(source) == manifest["sha256"], "source corpus changed"
            return source
        corpus = Path(imported)


def parse_rocksdb_audit(text, events):
    # stderr final counters and stdout JSON can be interleaved at process exit.
    # Select the complete audit object, not an unrelated stats/config object.
    reports = []
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and {"verified_signatures_and_bodies", "covering_records_verified", "events", "ok", "table_counts", "layout"} <= value.keys():
            reports.append(value)
    assert len(reports) == 1, "missing or duplicate RocksDB physical audit report"
    audit = reports[0]
    assert audit["ok"] and audit["events"] == audit["verified_signatures_and_bodies"] == audit["covering_records_verified"] == events
    return audit


def parse_import(arm, text, events):
    if arm in ("wok", "rocksdb"):
        matches = re.findall(r"Processed (\d+) lines\. (\d+) added, (\d+) rejected, (\d+) dups", text)
        assert matches, "missing Wok import summary"
        processed, accepted, rejected, duplicates = map(int, matches[-1])
        assert (processed, accepted, rejected, duplicates) == (events, events, 0, 0), matches[-1]
        return {"processed": processed, "accepted": accepted, "rejected": rejected, "duplicates": duplicates}
    if arm == "fastr":
        matches = re.findall(r"imported:\s*(\d+)\s+duplicates:\s*(\d+)\s+failures:\s*(\d+)", text)
        assert matches, "missing fastr import summary; exit0 is insufficient"
        accepted, duplicates, rejected = map(int, matches[-1])
        assert (accepted, duplicates, rejected) == (events, 0, 0), matches[-1]
        return {"accepted": accepted, "duplicates": duplicates, "parse_failures": rejected}
    # strfry's verified import is followed by an exact CLI database count.
    assert arm == "strfry"
    assert not re.search(r"(?:invalid|rejected|failed)\s*(?:events?)?\s*[:=]\s*[1-9]", text, re.I), "strfry import reported failures"
    return {"verification": "default verified import; exact database count checked separately"}


def known_read_disconnect_error(error):
    """Exact driver variants after a proven read socket closes; never publishers."""
    bodies = ["AlreadyClosed", "ConnectionClosed",
              'Io(Os { code: 104, kind: ConnectionReset, message: "Connection reset by peer" })',
              'Io(Os { code: 32, kind: BrokenPipe, message: "Broken pipe" })']
    sends = {f"{operation} send failed: Ok(Err({body}))" for operation in ["REQ","CLOSE"] for body in bodies}
    receives = {f"query receive ended: Ok(Some(Err({body})))" for body in bodies}
    receives.add("query receive ended: Ok(Some(Err(Protocol(ResetWithoutClosingHandshake))))")
    receives.add("query disconnected")
    return error in sends | receives


def matched_writer_arguments(mode):
    assert mode in {"disjoint", "queried"}, "unknown matched writer author mode"
    return [] if mode == "disjoint" else ["--matched-writer-authors", mode]


def validate_writer_workload(report, expected_mode):
    assert report.get("matched_writer_authors", "disjoint") == expected_mode, "writer author mode differs"
    if expected_mode == "disjoint":
        return
    assert expected_mode == "queried", "unknown matched writer author mode"
    workload = report["workload"]
    assert workload["format"] == "network-matched-queried-authors-v1"
    assert workload["matched_writer_authors"] == "queried"
    canonical = json.dumps(workload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert hashlib.sha256(canonical).hexdigest() == report["workload_sha256"], "workload identity digest differs"
    for key in ["corpus_sha256", "query_plan_sha256", "history_cutoff", "seed", "offered_writes",
                "write_rate", "read_rate", "read_connections", "publish_connections", "drain_secs"]:
        assert workload[key] == report[key], f"workload identity differs at {key}"
    writer = workload["writer_authors"]
    assert writer["mode"] == "queried" and writer["author_count"] == 64
    for key in ["pubkey_set_sha256", "timed_event_ids_sha256"]:
        assert re.fullmatch(r"[0-9a-f]{64}", writer[key]), f"missing writer digest {key}"
    overlap = writer["query_shape_overlap"]
    assert set(overlap) == {"author", "feed500", "tag", "id"}
    for shape, value in overlap.items():
        assert value["plans"] == 64
        if shape in {"author", "feed500"}:
            assert value["author_filter_plans"] == value["plans_with_writer_authors"] == 64
            assert 1 <= value["minimum_writer_authors"] <= value["maximum_writer_authors"] <= 64
        else:
            assert value["author_filter_plans"] == value["plans_with_writer_authors"] == 0
            assert value["minimum_writer_authors"] is None and value["maximum_writer_authors"] is None


def validate_network(report, events, write_rate, read_rate, corpus_hash, query_hash, *, corpus_events=None, seed=None, drain_secs=None, allow_censored=False, require_count_settled=False, verified_read_ingress_overload=False, matched_writer_authors="disjoint"):
    assert report["format"] == "network-matched-v1", "wrong network report format"
    assert report.get("stage") != "preflight_or_setup", f"network preflight/setup failed: {report.get('error', 'missing diagnostic')}"
    assert report["ok"] is True or allow_censored, "network trial failed"
    validate_writer_workload(report, matched_writer_authors)
    if require_count_settled:
        preflight = report.get("preflight", {})
        assert preflight.get("count_terminal_response") is True and preflight.get("measurement_starts_after_count") is True, "preflight COUNT was not proven complete before measurement"
    assert report["corpus_sha256"] == corpus_hash, "wrong corpus"
    assert report["write_rate"] == write_rate and report["read_rate"] == read_rate, "wrong offered rates"
    assert report["read_connections"] == 2 and report["publish_connections"] == 32, "wrong client connection counts"
    if corpus_events is not None:
        assert report["corpus_events"] == report["corpus_retained"] == corpus_events, "corpus count/identity mismatch"
    if seed is not None:
        assert report["seed"] == seed, "wrong event/query random seed"
    if drain_secs is not None:
        assert report["drain_secs"] == drain_secs, "wrong common drain horizon"
    reads = events * read_rate // write_rate
    assert report["offered_writes"] == events and report["offered_reads"] == reads, "wrong offered arrivals"
    for key in ["rejected_writes", "query_mismatches", "postcheck_mismatches"]:
        assert report[key] == 0, f"nonzero correctness/rejection counter {key}"
    if report["ok"] is True:
        assert report["sent_writes"] == report["accepted_writes"] == events, "missing write arrivals/OKs"
        assert report["sent_reads"] == report["completed_reads"] == reads, "missing read arrivals/EOSEs"
        for key in ["unanswered_writes", "unsent_writes", "unanswered_reads", "unsent_reads", "protocol_errors"]:
            assert report[key] == 0, f"nonzero {key}"
    else:
        assert allow_censored
        assert 0 <= report["accepted_writes"] <= report["sent_writes"] <= events
        assert 0 <= report["completed_reads"] <= report["sent_reads"] <= reads
        assert report["unanswered_writes"] == events - report["accepted_writes"]
        assert report["unsent_writes"] == events - report["sent_writes"]
        assert report["unanswered_reads"] == reads - report["completed_reads"]
        assert report["unsent_reads"] == reads - report["sent_reads"]
        errors = report["errors"]
        assert report["protocol_errors"] == len(errors)
        patterns = [r"(?:query|publisher) receive ended: Err\(Elapsed\(\(\)\)\)",
                    r"(?:publication|REQ|CLOSE) send failed: Err\(Elapsed\(\(\)\)\)",
                    r"CLOSE send timed out", r"query pending safety bound \d+ exceeded; trial invalid"]
        assert all((verified_read_ingress_overload and known_read_disconnect_error(error))
                   or any(re.fullmatch(pattern,error) for pattern in patterns)
                   for error in errors), "real protocol/preflight failure cannot be classified as overload"
        assert errors or report["unanswered_writes"] or report["unanswered_reads"], "unexplained failed report"
    assert report["query_plan_sha256"], "missing deterministic query plan digest"
    if query_hash is not None:
        assert report["query_plan_sha256"] == query_hash, "query plan differs across engines/rates"
    return report["query_plan_sha256"]


def read_ingress_overload_proof(report, folder, events):
    """User-authorized read overload; retain errors and require relay-side cause."""
    assert report["ok"] is False and report["unanswered_reads"] > 0
    assert report["accepted_writes"] == report["sent_writes"] == report["offered_writes"] == events
    for key in ["rejected_writes", "unanswered_writes", "unsent_writes", "query_mismatches", "postcheck_mismatches", "notices"]:
        assert report[key] == 0, "read-overload classification cannot hide correctness/write errors"
    post = report["postcheck"]
    assert post["queried"] == post["stored"] == events
    for key in ["acked_missing", "changed_or_unexpected", "mismatches", "refused_stored", "unanswered_stored"]:
        assert post[key] == 0, "read-overload postcheck failed"
    assert any(known_read_disconnect_error(error) for error in report["errors"])
    text = re.sub(r"\x1b\[[0-9;]*m", "", (folder / "relay.log").read_text())
    terminations = [line for line in text.splitlines() if "client terminated" in line]
    assert terminations, "missing relay overload evidence"
    ids = []
    for line in terminations:
        assert 'reason="ingress_paused_overflow"' in line, "different relay termination cause"
        found = re.search(r"conn_id=(\d+)(?: |$)", line)
        assert found, "missing terminated connection identity"
        ids.append(int(found[1]))
    # One preflight socket, 32 publish sockets, then exactly two read sockets.
    # Each fresh relay starts IDs at1; the driver opens these in fixed order.
    expected_ids = {34,35}
    assert set(ids) <= expected_ids and len(ids) == len(set(ids)), "overflow was outside known read sockets"
    connected = [int(value) for value in re.findall(r"client connected conn_id=(\d+) ",text)]
    assert connected[:35] == list(range(1,36)), "unexpected socket setup; cannot map overload to reads"
    final = read(folder / "backend-final-stats.json")
    assert all(v["rocksdb.background-errors"] == 0 for v in final["column_families"].values())
    resources = read(folder / "relay.resources.json")
    assert resources["exit_code"] in [0,-15]
    for key in ["cgroup_before","cgroup_after"]:
        counters = dict(line.split() for line in resources[key]["memory.events"].splitlines())
        assert int(counters["oom"]) == int(counters["oom_kill"]) == 0
    return {"classification":"relay_read_ingress_overload", "terminated_read_connection_ids":ids,
            "relay_termination_evidence":terminations, "relay_log_sha256":sha(folder / "relay.log"),
            "report_sha256":sha(folder / "load/network-matched.json"),
            "backend_final_stats_sha256":sha(folder / "backend-final-stats.json"),
            "resources_sha256":sha(folder / "relay.resources.json"),
            "protocol_errors_retained":report["protocol_errors"],
            "eligible_for_uncensored_latency_winner":False,
            "note":"User explicitly chose fixed workload and recorded read overload; connection errors and all offered/sent/completed/missing counts retained. Missing scheduled arrivals are censored, not successful latency observations; no valid read-latency winner or combined mixed-load capacity pass."}


def record_command(argv):
    """Executed inside the exact benchmark systemd unit on either VM."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--meta", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--stdin", type=Path)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--memory-gib", type=int, default=64)
    parser.add_argument("--allow-process-affinity", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert command
    before = check_caps(args.memory_gib, allow_process_affinity=args.allow_process_affinity)
    started = time.monotonic()
    environment = os.environ.copy()
    if args.env:
        environment.update({key: str(value) for key, value in read(args.env).items()})
    record = {"started": now(), "command": command, "environment_overrides": read(args.env) if args.env else {},
              "host": platform.uname()._asdict(), "resource_limits": limits(), "cgroup_before": before,
              "state": "running"}
    save(args.meta, record)
    stop = threading.Event()
    samples = args.meta.with_suffix(".samples.jsonl")
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w") as output:
        input_stream = args.stdin.open("rb") if args.stdin else subprocess.DEVNULL
        try:
            child = subprocess.Popen(command, stdin=input_stream, stdout=output, stderr=subprocess.STDOUT, env=environment)
            def terminate(_signal, _frame):
                if child.poll() is None:
                    child.terminate()
            signal.signal(signal.SIGTERM, terminate)
            signal.signal(signal.SIGINT, terminate)
            def sample():
                with samples.open("a") as stream:
                    while not stop.is_set():
                        item = {"time": now(), "elapsed_secs": time.monotonic() - started, "pid": child.pid,
                                "cgroup": cgroup_stats()}
                        for name in ["io", "status"]:
                            path = Path(f"/proc/{child.pid}/{name}")
                            try:
                                item["process_" + name] = path.read_text()
                            except FileNotFoundError:
                                pass
                        stream.write(json.dumps(item) + "\n")
                        stream.flush()
                        stop.wait(5)
            sampler = threading.Thread(target=sample, daemon=True)
            sampler.start()
            code = child.wait()
            stop.set()
            sampler.join(timeout=10)
        finally:
            if args.stdin:
                input_stream.close()
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    record.update(state="exited", finished=now(), exit_code=code, elapsed_secs=time.monotonic() - started,
                  user_cpu_secs=usage.ru_utime, system_cpu_secs=usage.ru_stime,
                  max_rss_kib=usage.ru_maxrss,
                  final_child_io={"input_blocks": usage.ru_inblock, "output_blocks": usage.ru_oublock,
                      "linux_accounting_block_bytes": 512,
                      "accounted_read_bytes": usage.ru_inblock * 512,
                      "accounted_write_bytes": usage.ru_oublock * 512,
                      "scope": "RUSAGE_CHILDREN after wait; one recorded child per wrapper, includes child shutdown and reaped descendants; Linux block accounting, not device amplification or durability"},
                  cgroup_after=cgroup_stats())
    save(args.meta, record)
    return code


class Campaign:
    def __init__(self, args):
        self.args = args
        self.root = args.root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-i", str(args.ssh_identity), args.load_host]
        self.remote_root = args.load_root
        self.remote_helper = self.remote_root / "run-campaign.py"
        self.template = {arm: path.read_text() for arm, path in
                         [("wok", args.wok_config_template), ("strfry", args.strfry_config_template)]}
        self.binary = {"wok": args.wok_binary.resolve(), "fastr": args.fastr_binary.resolve(), "strfry": args.strfry_binary.resolve()}
        if getattr(args, "rocksdb_binary", None):
            self.binary["rocksdb"] = args.rocksdb_binary.resolve()
            self.template["rocksdb"] = self.template["wok"]
        self.arms = tuple(self.binary)
        self.environment = read(args.fastr_environment)
        self.units = set()
        self.query_hashes = {}
        self.pinned_binaries = {}
        self.corpus_remote = {}

    def predecessor_marker(self, relative):
        if not getattr(self.args, "predecessor", None):
            return None
        path = self.args.predecessor.resolve() / relative
        if not path.is_file():
            return None
        saved = read(path)
        verify_artifacts(path.parent, saved["artifacts"])
        return path, saved

    def import_marker(self, source, destination, *, seed_path=None, corpus_path=None, validation=None):
        path, saved = source
        assert not destination.exists(), f"destination already exists: {destination}"
        destination.mkdir(parents=True)
        # Copy only marker-listed evidence, never scratch databases or corpus bytes.
        for name in saved["artifacts"]:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path.parent / name, target)
        parent = destination / "imports" / sha(path)[:16]
        parent.mkdir(parents=True)
        shutil.copy2(path, parent / "complete.json")
        save(parent / "provenance.json", {"imported": now(), "original_marker": str(path), "artifact_root": "../..",
             "original_marker_sha256": sha(path), "original_manifest_sha256": sha(self.args.predecessor / "manifest.json"),
             "seed_path": str(seed_path) if seed_path else None, "corpus_path": str(corpus_path) if corpus_path else None})
        if validation is not None:
            save(parent / "unchanged-arm-validation.json", validation)
        names = [str(p.relative_to(destination)) for p in sorted(destination.rglob("*")) if p.is_file()]
        save(destination / "complete.json", {**saved, "artifacts": artifact_hashes(destination, names),
             "predecessor_marker": str((parent / "complete.json").relative_to(destination)),
             "imported_seed_path": str(seed_path) if seed_path else None,
             "imported_corpus_path": str(corpus_path) if corpus_path else None})

    def update(self, **value):
        value = {"time": now(), **value}
        save(self.root / "status.json", value)
        with (self.root / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(value) + "\n")
        print(json.dumps(value), flush=True)

    def remote(self, command, **kwargs):
        return subprocess.run([*self.ssh, shlex.join([str(value) for value in command])], check=True, **kwargs)

    def transfer(self, source, destination, pull=False):
        transport = shlex.join(self.ssh[:-1])
        remote = f"{self.args.load_host}:{source if pull else destination}"
        command = ["rsync", "-a", "-e", transport, remote, str(destination)] if pull else ["rsync", "-a", "-e", transport, str(source), remote]
        subprocess.run(command, check=True)

    def unit(self, unit, command, meta, log, *, remote=False, wait=True, stdin=None, env=None):
        assert unit.startswith(self.args.unit_prefix + "-"), "unit is outside benchmark namespace"
        active_command = ["systemctl", *(["--user"] if remote else []), "is-active", "--quiet", unit]
        if remote:
            active = subprocess.run([*self.ssh, shlex.join(["env", f"XDG_RUNTIME_DIR=/run/user/{self.args.load_uid}", *active_command])], check=False).returncode
        else:
            active = subprocess.run(active_command, check=False).returncode
        assert active != 0, f"benchmark unit already active: {unit}; inspect before retry"
        self.units.add((remote, unit))
        memory = self.args.load_memory_gib if remote else 64
        helper = self.remote_helper if remote else Path(__file__).resolve()
        record = ["/usr/bin/python3", str(helper), "_record", "--meta", str(meta), "--log", str(log), "--memory-gib", str(memory)]
        if remote:
            record += ["--allow-process-affinity"]
        if stdin:
            record += ["--stdin", str(stdin)]
        if env:
            record += ["--env", str(env)]
        launch = ["systemd-run", *(["--user"] if remote else []), "--unit", unit, "--collect"]
        for key, value in {**CAPS, "MemoryMax": str(memory) + "G", "KillMode": "mixed", "TimeoutStopSec": "120s"}.items():
            launch += ["--property", f"{key}={value}"]
        if not remote:
            launch += ["--slice", self.args.relay_slice]
        if wait:
            launch += ["--wait", "--pipe"]
        launch += [*record, "--", *map(str, command)]
        if remote:
            launch = ["env", f"XDG_RUNTIME_DIR=/run/user/{self.args.load_uid}", *launch]
            self.remote(launch)
        else:
            subprocess.run(launch, check=True)

    def active(self, unit, remote=False):
        command = ["systemctl", *(["--user"] if remote else []), "is-active", "--quiet", unit]
        if remote:
            command = [*self.ssh, shlex.join(["env", f"XDG_RUNTIME_DIR=/run/user/{self.args.load_uid}", *command])]
        return subprocess.run(command, check=False).returncode == 0

    def stop_owned_active(self):
        outcomes = []
        for remote, unit in self.units:
            try:
                if self.active(unit, remote):
                    self.stop(unit, remote)
                    outcomes.append({"unit": unit, "remote": remote, "stopped": True})
            except Exception as error:
                outcomes.append({"unit": unit, "remote": remote, "stop_error": repr(error)})
        return outcomes

    def stop(self, unit, remote=False):
        assert (remote, unit) in self.units and unit.startswith(self.args.unit_prefix + "-")
        command = ["systemctl", *(["--user"] if remote else []), "stop", unit]
        if remote:
            self.remote(["env", f"XDG_RUNTIME_DIR=/run/user/{self.args.load_uid}", *command])
        else:
            subprocess.run(command, check=True)

    def own(self, path, kind):
        path = Path(path)
        assert path.parent.name == kind and path.parent.parent.parent == self.root, "scratch path outside stage"
        marker = path.with_suffix(".owned.json")
        assert not path.exists() and not marker.exists(), f"incomplete path retained: {path}; inspect before retry"
        save(marker, {"campaign": str(self.root), "path": str(path), "created": now()})

    def cleanup(self, path):
        marker = path.with_suffix(".owned.json")
        assert path.parent.name == "databases" and path.parent.parent.parent == self.root and not path.is_symlink()
        assert read(marker)["campaign"] == str(self.root) and read(marker)["path"] == str(path)
        shutil.rmtree(path)
        marker.unlink()

    def config(self, arm, database, output):
        output.parent.mkdir(parents=True, exist_ok=True)
        if arm == "fastr":
            environment = {**self.environment, "FASTR_ADDR": self.args.relay_address, "FASTR_PORT": str(self.args.port), "FASTR_DATA_DIR": str(database)}
            save(output, {key: str(value) for key, value in environment.items()})
        else:
            text = self.template[arm].replace("@DATABASE@", str(database)).replace("@ADDRESS@", self.args.relay_address).replace("@PORT@", str(self.args.port))
            assert "@DATABASE@" in self.template[arm], "template must set the scratch database"
            output.write_text(text)
        return output

    def space(self, needed=0):
        assert shutil.disk_usage(self.root).free >= max(self.args.minimum_free_gib * GIB, needed + getattr(self.args,"copy_headroom_gib",20) * GIB), "insufficient scratch disk; preserve evidence and inspect"

    def generate(self, stage, events):
        destination = stage / "corpus"
        marker = destination / "complete.json"
        remote = self.remote_root / stage.name / "corpus"
        imported = self.predecessor_marker(Path(stage.name) / "corpus" / "complete.json") if not marker.exists() else None
        if imported:
            evidence_source = imported[0].parent
            original = evidence_source
            chain = []
            while True:
                source_marker = original / "complete.json"
                source_saved = read(source_marker)
                verify_artifacts(original, source_saved["artifacts"])
                assert str(source_marker) not in [item["marker"] for item in chain], "corpus provenance cycle"
                chain.append({"marker": str(source_marker), "sha256": sha(source_marker)})
                if not source_saved.get("imported_corpus_path"):
                    break
                original = Path(source_saved["imported_corpus_path"])
            original_manifest = read(original / "corpus-manifest.json")
            assert original_manifest["events"] == events and original_manifest["seed"] == self.args.seed
            assert original_manifest["base_timestamp"] == self.args.base_timestamp
            # The raw corpus is retained in place; only its small evidence files are imported.
            saved = imported[1]
            evidence = {name: digest for name, digest in saved["artifacts"].items() if name != "corpus.jsonl"}
            destination.mkdir(parents=True)
            for name in evidence:
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(evidence_source / name, target)
            parent = destination / "imports" / sha(imported[0])[:16]
            parent.mkdir(parents=True)
            shutil.copy2(imported[0], parent / "complete.json")
            save(parent / "provenance.json", {"original_marker": str(imported[0]), "artifact_root": "../..",
                 "original_marker_sha256": sha(imported[0]), "raw_corpus_sha256": original_manifest["sha256"], "chain": chain})
            names = [str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file()]
            save(marker, {"completed": now(), "artifacts": artifact_hashes(destination, names), "imported_corpus_path": str(original)})
        if marker.exists():
            saved = read(marker)
            verify_artifacts(destination, saved["artifacts"])
            if saved.get("imported_corpus_path"):
                original = Path(saved["imported_corpus_path"])
                assert sha(original / "corpus.jsonl") == read(original / "corpus-manifest.json")["sha256"]
                predecessor_options = read(original.parent.parent / "manifest.json")["identity"]["options"]
                self.corpus_remote[stage.name] = Path(predecessor_options["load_root"]) / stage.name / "corpus" / "corpus.jsonl"
                return original
            self.corpus_remote[stage.name] = remote / "corpus.jsonl"
            return destination
        assert not destination.exists(), f"incomplete corpus retained: {destination}"
        destination.mkdir(parents=True)
        self.remote(["mkdir", "-p", str(remote)])
        self.update(state="generating_corpus", stage=stage.name, events=events, remote_output=str(remote))
        command = [str(self.args.load_bench_binary), "--scenario", "matched_network_generate", "--events", str(events),
                   "--seed", str(self.args.seed), "--base-timestamp", str(self.args.base_timestamp), "--out", str(remote)]
        self.unit(self.args.unit_prefix + "-" + stage.name + "-generate", command,
                  remote / "generate.resources.json", remote / "generate.log", remote=True)
        self.transfer(str(remote) + "/", destination, pull=True)
        report = read(destination / "corpus-manifest.json")
        assert report["events"] == events and report["authors"] == 2048 and report["seed"] == self.args.seed
        assert report["base_timestamp"] == self.args.base_timestamp
        assert sha(destination / "corpus.jsonl") == report["sha256"], "corpus transfer/hash mismatch"
        save(marker, {"completed": now(), "artifacts": artifact_hashes(destination, [str(p.relative_to(destination)) for p in sorted(destination.rglob("*")) if p.is_file()])})
        self.corpus_remote[stage.name] = remote / "corpus.jsonl"
        return destination

    def prepare(self, stage, corpus, arm, events):
        seeds = stage / "seeds"
        evidence = stage / "reports" / ("seed-" + arm)
        evidence.mkdir(parents=True, exist_ok=True)
        seed = seeds / arm
        complete = evidence / "complete.json"
        imported = self.predecessor_marker(Path(stage.name) / "reports" / ("seed-" + arm) / "complete.json") if not complete.exists() else None
        if imported:
            original_seed = Path(imported[1].get("imported_seed_path") or self.args.predecessor.resolve() / stage.name / "seeds" / arm)
            assert read(original_seed.with_suffix(".owned.json"))["campaign"] == str(original_seed.parent.parent.parent)
            assert inventory(original_seed, True) == read(imported[0].parent / "inventory.json"), "predecessor seed changed"
            # evidence was created above, but import_marker requires an empty new destination.
            evidence.rmdir()
            self.import_marker(imported, evidence, seed_path=original_seed)
        if complete.exists():
            saved = read(complete)
            verify_artifacts(evidence, saved["artifacts"])
            if saved.get("imported_seed_path"):
                seed = Path(saved["imported_seed_path"])
                predecessor_seed = read(self.args.predecessor / stage.name / "reports" / ("seed-" + arm) / "complete.json")
                assert seed == Path(predecessor_seed.get("imported_seed_path") or self.args.predecessor.resolve() / stage.name / "seeds" / arm)
                assert inventory(seed, True) == read(evidence / "inventory.json"), "imported seed changed"
                return seed
            assert read(seed.with_suffix(".owned.json"))["campaign"] == str(self.root)
            assert inventory(seed, True) == read(evidence / "inventory.json"), "seed changed"
            return seed
        self.space()
        assert sha(self.binary[arm]) == self.pinned_binaries[arm], "relay binary changed after manifest freeze"
        self.own(seed, "seeds")
        if arm == "strfry":
            # strfry opens LMDB in an existing directory; keep ownership
            # creation before mkdir so interrupted imports remain explicit.
            seed.mkdir()
        config = self.config(arm, seed, evidence / ("environment.json" if arm == "fastr" else "config.conf"))
        source = corpus_source(corpus)
        command = ([str(self.binary[arm]), "import", str(seed), str(source)] if arm == "fastr" else
                   [str(self.binary[arm]), "--config", str(config), "import"])
        self.update(state="importing_seed", stage=stage.name, arm=arm, log=str(evidence / "import.log"), expected_events=events)
        self.unit(self.args.unit_prefix + "-" + stage.name + "-import-" + arm, command,
                  evidence / "import.resources.json", evidence / "import.log",
                  stdin=source if arm != "fastr" else None, env=config if arm == "fastr" else None)
        parsed = parse_import(arm, (evidence / "import.log").read_text(), events)
        sync_started = time.monotonic()
        subprocess.run(["sync", "-f", str(seed)], check=True)
        save(evidence / "post_import_sync.json", {"elapsed_secs": time.monotonic() - sync_started, "method": "sync -f seed before inventory"})
        if arm == "strfry":
            result = subprocess.run([str(self.binary[arm]), "--config", str(config), "scan", "{}", "--count"], check=True, capture_output=True, text=True)
            (evidence / "count.log").write_text(result.stdout + result.stderr)
            values = re.findall(r"(?m)^\s*(\d+)\s*$", result.stdout)
            assert values and int(values[-1]) == events, "strfry imported count mismatch"
            parsed["database_events"] = int(values[-1])
        if arm == "rocksdb":
            # A read-only stream verifies every primary/signature, both author
            # index representations, and independent table counts before freezing.
            self.update(state="verifying_optimized_schema", stage=stage.name, arm=arm)
            self.unit(self.args.unit_prefix + "-" + stage.name + "-audit-" + arm,
                      [str(self.binary[arm]), "--config", str(config), "rocksdb-check"],
                      evidence / "audit.resources.json", evidence / "audit.log")
            text = (evidence / "audit.log").read_text()
            audit = parse_rocksdb_audit(text, events)
            save(evidence / "schema-validation.json", audit)
        save(evidence / "import-validation.json", parsed)
        self.update(state="hashing_seed", stage=stage.name, arm=arm)
        save(evidence / "inventory.json", inventory(seed, True))
        save(complete, {"completed": now(), "artifacts": artifact_hashes(evidence, [str(p.relative_to(evidence)) for p in sorted(evidence.rglob("*")) if p.is_file()])})
        return seed

    def classify_read_overload(self, stage, arm, evidence, result, events):
        proof = None
        if (stage.name == "main" and arm == "rocksdb"
                and getattr(self.args, "allow_read_ingress_overload", False)
                and any(known_read_disconnect_error(error) for error in result.get("errors",[]))):
            proof = read_ingress_overload_proof(result,evidence,events)
            path = evidence / "relay-ingress-overload.json"
            if path.exists():
                assert read(path) == proof, "overload proof changed"
            else:
                save(path,proof)
        return proof

    def retain_overload(self, database, evidence, unit):
        # Preserve closed new trial DBs on the load VM. No historical path is
        # touched, and removal of this relay copy is only after full hash proof.
        assert database.parent.name == "databases" and database.parent.parent.parent == self.root
        assert read(database.with_suffix(".owned.json"))["campaign"] == str(self.root)
        remote = self.remote_root / "retained-databases" / database.parent.parent.name / database.name
        self.remote(["test", "!", "-e", str(remote)])
        expected = inventory(database,True)
        save(evidence / "retained-source-inventory.json",expected)
        needed = sum(row["size"] for row in expected)
        self.remote(["python3","-c","import shutil,sys;assert shutil.disk_usage(sys.argv[1]).free > int(sys.argv[2]) + 20*(1<<30)",str(self.remote_root),str(needed)])
        self.remote(["mkdir","-p",str(remote)])
        self.transfer(str(database)+"/",str(remote)+"/")
        output = self.remote_root / "retention-evidence" / database.parent.parent.name / (database.name + ".inventory.json")
        self.unit(unit+"-retention",["python3",str(self.remote_helper),"_inventory",str(remote),str(output)],
                  str(output)+".resources.json",str(output)+".log",remote=True)
        self.transfer(str(output),evidence / "retained-load-inventory.json",pull=True)
        actual = read(evidence / "retained-load-inventory.json")
        assert actual == expected, "retained database copy changed bytes or metadata"
        save(evidence / "retained-database.json",{"host":self.args.load_host,"path":str(remote),
             "source_path":str(database),"source_inventory_sha256":sha(evidence / "retained-source-inventory.json"),
             "load_inventory_sha256":sha(evidence / "retained-load-inventory.json"),
             "all_files_full_sha256_verified":True,"files":len(actual),"bytes":needed,
             "method":"closed DB rsync copy, full remote SHA256 inventory equality before deleting only this campaign-owned relay copy; never downloaded locally"})
        return remote

    def cell(self, stage, corpus, seeds, job, events, read_rate, position, total):
        arm, name, rate = job["arm"], job["name"], job["write_rate"]
        evidence = stage / "reports" / name
        complete = evidence / "complete.json"
        database = stage / "databases" / name
        self.query_hashes.setdefault(stage.name, None)
        corpus_manifest = read(corpus / "corpus-manifest.json")
        corpus_hash = corpus_manifest["sha256"]
        resume = getattr(self.args,"resume_measured",False)
        recovery = bool(getattr(self.args, "rerun_arms", [])) or resume
        may_import = resume or not self.args.rerun_network or (recovery and arm not in self.args.rerun_arms)
        if recovery:
            assert self.recovery_verified, "recovery identity was not verified"
        imported = self.predecessor_marker(Path(stage.name) / "reports" / name / "complete.json") if not complete.exists() and may_import else None
        if imported:
            assert imported[1]["job"] == job and (imported[1]["outcome"] == "completed" or (resume and imported[1]["outcome"] == "relay_read_ingress_overload"))
            validation = None
            if recovery:
                validation = {"arm": arm, "binary_sha256": self.pinned_binaries[arm],
                    "unchanged_binary_driver_workload_and_configuration": True,
                    "invalidated_arms": self.args.rerun_arms,
                    "predecessor_manifest_sha256": sha(self.args.predecessor / "manifest.json"),
                    "current_manifest_sha256": sha(self.root / "manifest.json")}
            self.import_marker(imported, evidence, validation=validation)
        if complete.exists():
            saved = read(complete)
            assert saved["job"] == job
            verify_artifacts(evidence, saved["artifacts"])
        else:
            assert not evidence.exists(), f"incomplete trial evidence retained: {evidence}; inspect before retry"
            evidence.mkdir(parents=True)
            seed = seeds[arm]
            expected = read(stage / "reports" / ("seed-" + arm) / "inventory.json")
            assert inventory(seed, False) == metadata(expected), "seed metadata changed"
            self.space(sum(row["size"] for row in expected))
            self.own(database, "databases")
            self.update(state="copying_seed", stage=stage.name, job=position, jobs=total, name=name)
            started = time.monotonic()
            subprocess.run(["cp", "--reflink=auto", "--preserve=all", "-R", str(seed), str(database)], check=True)
            assert inventory(seed, False) == metadata(expected), "seed changed during copy"
            copy_secs = time.monotonic() - started
            sync_started = time.monotonic()
            subprocess.run(["sync", "-f", str(database)], check=True)
            save(evidence / "copy.json", {"secs": copy_secs, "sync_secs": time.monotonic() - sync_started,
                 "seed_inventory_sha256": sha(stage / "reports" / ("seed-" + arm) / "inventory.json"),
                 "method": "cp --reflink=auto --preserve=all -R; no hardlinks"})
            assert sha(self.binary[arm]) == self.pinned_binaries[arm], "relay binary changed after manifest freeze"
            config = self.config(arm, database, evidence / ("environment.json" if arm == "fastr" else "config.conf"))
            with socket.socket() as probe:
                assert probe.connect_ex((self.args.relay_address, self.args.port)) != 0, "benchmark port is already in use"
            unit = self.args.unit_prefix + "-" + stage.name + "-" + name
            command = [str(self.binary[arm])] if arm == "fastr" else [str(self.binary[arm]), "--config", str(config), "relay"]
            self.unit(unit, command, evidence / "relay.resources.json", evidence / "relay.log", wait=False, env=config if arm == "fastr" else None)
            self.update(state="starting_relay", stage=stage.name, name=name, unit=unit)
            startup = time.monotonic()
            deadline = startup + 600
            while True:
                assert self.active(unit), "relay exited during startup; inspect retained log/unit"
                try:
                    request = urllib.request.Request(f"http://{self.args.relay_address}:{self.args.port}/", headers={"Accept": "application/nostr+json", "Connection": "close"})
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(request, timeout=2) as response:
                        info = json.load(response)
                        assert response.status == 200 and isinstance(info, dict), "invalid relay-information response"
                    break
                except (OSError, ValueError, urllib.error.URLError):
                    assert time.monotonic() < deadline, "relay application did not become ready; inspect retained log/unit"
                    time.sleep(1)
            save(evidence / "startup.json", {"elapsed_secs": time.monotonic() - startup, "readiness": "successful complete HTTP NIP11 JSON response, not just bound port", "relay_info": info})
            remote = self.remote_root / stage.name / name
            self.remote(["mkdir", "-p", str(remote)])
            network = [str(self.args.load_bench_binary), "--scenario", "matched_network", "--target-url", f"ws://{self.args.relay_address}:{self.args.port}",
                       "--corpus", str(self.corpus_remote[stage.name]), "--events", str(events), "--send-rate", str(rate),
                       "--read-rate", str(read_rate), "--read-connections", "2", "--publish-connections", "32", "--drain-secs", str(self.args.drain_secs),
                       "--seed", str(self.args.seed), "--out", str(remote)]
            network += matched_writer_arguments(getattr(self.args, "matched_writer_authors", "disjoint"))
            save(evidence / "commands.json", {"relay": command, "network": network, "relay_unit": unit})
            self.update(state="running", stage=stage.name, job=position, jobs=total, name=name, arm=arm, write_rate=rate, read_rate=read_rate,
                        unit=unit, relay_log=str(evidence / "relay.log"), load_output=str(remote))
            load_error = None
            try:
                self.unit(unit + "-load", network, remote / "load.resources.json", remote / "load.log", remote=True)
                self.update(state="settling", stage=stage.name, name=name, idle_secs=self.args.settle_secs)
                time.sleep(self.args.settle_secs)
                assert self.active(unit), "relay exited before expected benchmark shutdown"
            except subprocess.CalledProcessError as error:
                load_error = error
                save(evidence / "load-exit.json", {"time": now(), "error": repr(error), "note": "nonzero load exit still requires strict report classification"})
                if stage.name == "main":
                    assert self.active(unit), "relay crashed during an incomplete network trial"
                    self.update(state="settling_incomplete_trial", stage=stage.name, name=name, idle_secs=self.args.settle_secs)
                    time.sleep(self.args.settle_secs)
                    assert self.active(unit), "relay exited before expected incomplete-trial shutdown"
            except BaseException as error:
                save(evidence / "failure.json", {"time": now(), "error": repr(error)})
                raise
            finally:
                self.stop(unit)
                self.transfer(str(remote) + "/", evidence / "load", pull=True)
            sync_started = time.monotonic()
            subprocess.run(["sync", "-f", str(database)], check=True)
            save(evidence / "post_stop_sync.json", {"elapsed_secs": time.monotonic() - sync_started, "note": "writeback before successful clone cleanup; does not create a per-OK durability guarantee"})
            if load_error is not None and stage.name != "main":
                raise load_error
            if arm == "rocksdb":
                lines = (evidence / "relay.log").read_text().splitlines()
                final = [json.loads(line.split("WOK_ROCKSDB_FINAL_STATS ",1)[1]) for line in lines if line.startswith("WOK_ROCKSDB_FINAL_STATS ")]
                assert len(final)==1, "missing or duplicate RocksDB final storage statistics"
                assert all(value["rocksdb.background-errors"] == 0 for value in final[0]["column_families"].values()), "RocksDB background error"
                save(evidence / "backend-final-stats.json", final[0])
            result = read(evidence / "load" / "network-matched.json")
            overload = self.classify_read_overload(stage,arm,evidence,result,events)
            self.query_hashes[stage.name] = validate_network(result, events, rate, read_rate, corpus_hash, self.query_hashes[stage.name], corpus_events=corpus_manifest["events"], seed=self.args.seed, drain_secs=self.args.drain_secs, allow_censored=stage.name == "main", require_count_settled=self.args.rerun_network, verified_read_ingress_overload=overload is not None, matched_writer_authors=getattr(self.args, "matched_writer_authors", "disjoint"))
            outcome = "completed" if result["ok"] else ("relay_read_ingress_overload" if overload else ("harness_bound" if any("pending safety bound" in error for error in result["errors"]) else "completed_with_censored_overload"))
            if overload and self.args.retain_overload_on_load:
                self.update(state="retaining_overloaded_database",stage=stage.name,name=name)
                self.retain_overload(database,evidence,unit)
            save(complete, {"completed": now(), "job": job, "outcome": outcome, "eligible_for_uncensored_latency_winner": outcome == "completed",
                 "artifacts": artifact_hashes(evidence, [str(p.relative_to(evidence)) for p in sorted(evidence.rglob("*")) if p.is_file()]),
                 "durability": "fastr stock OK has no fsync guarantee" if arm == "fastr" else "relay default verified/durable write policy"})
        result = read(evidence / "load" / "network-matched.json")
        overload = self.classify_read_overload(stage,arm,evidence,result,events)
        self.query_hashes[stage.name] = validate_network(result, events, rate, read_rate, corpus_hash, self.query_hashes[stage.name], corpus_events=corpus_manifest["events"], seed=self.args.seed, drain_secs=self.args.drain_secs, allow_censored=stage.name == "main", require_count_settled=self.args.rerun_network, verified_read_ingress_overload=overload is not None, matched_writer_authors=getattr(self.args, "matched_writer_authors", "disjoint"))
        outcome = read(complete)["outcome"]
        if database.exists() and outcome == "completed":
            self.cleanup(database)
        retained = str(database) if database.exists() else None
        if outcome == "relay_read_ingress_overload" and self.args.retain_overload_on_load:
            preserved = read(evidence / "retained-database.json")
            assert preserved["all_files_full_sha256_verified"]
            if database.exists():self.cleanup(database)
            retained = preserved["host"] + ":" + preserved["path"]
        self.update(state="completed_job", stage=stage.name, job=position, jobs=total, name=name, outcome=outcome,
                    retained_database=retained)

    def run(self):
        args = self.args
        assert 0 < args.port < 65536 and args.events > 0 and args.qualification_events > 0
        assert args.corpus_events >= 2048 and args.qualification_corpus_events >= 2048
        assert args.load_memory_gib > 0 and args.minimum_free_gib > 0 and args.drain_secs > 0 and args.settle_secs >= 0
        assert args.copy_headroom_gib >= 12
        assert not args.retain_overload_on_load or args.allow_read_ingress_overload
        controller_caps = check_caps(64)
        assert args.relay_slice in Path(controller_caps["cgroup_path"]).parts, "controller must share the relay benchmark slice"
        envelopes = controller_caps["ancestor_envelopes"]
        envelope = next((value for path, value in envelopes.items() if Path(path).name == args.relay_slice), None)
        assert envelope and envelope["memory.max"].strip() == str(64 * GIB) and envelope["cpu.max"].split() == ["1600000", "100000"], "shared slice resource envelope differs"
        self.space()
        assert args.unit_prefix.startswith("wok-fastr-bench-"), "use a private benchmark unit namespace"
        self.remote(["mkdir", "-p", str(self.remote_root)])
        self.transfer(Path(__file__).resolve(), self.remote_helper)
        helper_hash = self.remote(["sha256sum", str(self.remote_helper)], capture_output=True, text=True).stdout.split()[0]
        assert helper_hash == sha(__file__), "load resource-wrapper transfer mismatch"
        remote_hash = self.remote(["sha256sum", str(args.load_bench_binary)], capture_output=True, text=True).stdout.split()[0]
        identity = {"options": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                                if k != "matched_writer_authors" or v != "disjoint"},
                    "controller_sha256": sha(__file__), "source_manifest": read(args.source_manifest),
                    "source_manifest_sha256": sha(args.source_manifest), "binaries": {arm: sha(path) for arm, path in self.binary.items()},
                    "bench_binary_sha256": remote_hash, "wok_template_sha256": sha(args.wok_config_template),
                    "strfry_template_sha256": sha(args.strfry_config_template), "fastr_environment": self.environment,
                    "durability_note": "stock fastr OK is async/non-fsync; Wok LMDB, optimized RocksDB and strfry use synchronous commits. No equivalent-durability claim for fastr.",
                    "network_note": "private benchmark relay/load pair; no production code, production services or peers"}
        self.pinned_binaries = identity["binaries"]
        assert not (args.rerun_arms or args.resume_measured) or args.predecessor, "recovery requires predecessor evidence"
        if args.predecessor:
            old = read(args.predecessor / "manifest.json")["identity"]
            validate_predecessor_identity(old, identity, rerun_network=args.rerun_network,
                                          rerun_arms=args.rerun_arms)
            self.recovery_verified = True
            old_strfry = Path(old["options"]["strfry_config_template"]).read_text()
            expected_strfry = old_strfry if args.rerun_network else old_strfry.replace("    maxFilterLimit = 500\n", "    maxFilterLimit = 500\n    maxFilterLimitCount = 20000000\n")
            assert args.strfry_config_template.read_text() == expected_strfry, "unexpected strfry configuration difference"
            identity["predecessor_manifest_sha256"] = sha(args.predecessor / "manifest.json")
        if args.bench_binary:
            assert remote_hash == sha(args.bench_binary), "load generator binary differs from pinned local binary"
        manifest = self.root / "manifest.json"
        if manifest.exists():
            assert read(manifest)["identity"] == identity, "campaign inputs changed; use a new campaign directory"
        else:
            save(manifest, {"started": now(), "identity": identity, "host": platform.uname()._asdict(), "resource_limits": limits(), "cgroup": cgroup_stats(),
                            "method": "unique signed corpus; fixed write/read schedules; pristine closed seed copies; rate/arm order reversed in second repetition",
                            "scope": "qualification gates main; seeds/failed clones retained; only successful marker-owned trial clones deleted"})
        for name, corpus_events, timed_events, rates, read_rate, repetitions in [
            ("qualification", args.qualification_corpus_events, args.qualification_events, [100, 250], 100, 1),
            ("main", args.corpus_events, args.events, [100, 250, 500, 1000], 1000, 2)]:
            stage = self.root / name
            stage.mkdir(exist_ok=True)
            for directory in ["seeds", "databases", "reports"]:
                (stage / directory).mkdir(exist_ok=True)
            corpus = self.generate(stage, corpus_events)
            seeds = {arm: self.prepare(stage, corpus, arm, corpus_events) for arm in self.arms}
            jobs = matrix(rates, repetitions, self.arms)
            save(stage / "jobs.json", jobs)
            for position, job in enumerate(jobs, 1):
                self.cell(stage, corpus, seeds, job, timed_events, read_rate, position, len(jobs))
            save(stage / "complete.json", {"completed": now(), "jobs": len(jobs), "query_plan_sha256": self.query_hashes[name],
                 "outcomes": {job["name"]: read(stage / "reports" / job["name"] / "complete.json")["outcome"] for job in jobs},
                 "completion_markers": {job["name"]: sha(stage / "reports" / job["name"] / "complete.json") for job in jobs}})
            self.update(state="stage_complete", stage=name, jobs=len(jobs))
        self.update(state="complete", qualification_jobs=len(self.arms) * 2, main_jobs=len(self.arms) * 8)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_record":
        return record_command(sys.argv[2:])
    if len(sys.argv) == 4 and sys.argv[1] == "_inventory":
        save(Path(sys.argv[3]),inventory(Path(sys.argv[2]),True))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--load-root", type=Path, required=True)
    parser.add_argument("--load-host", default="relaybench-fastr@10.77.1.1")
    parser.add_argument("--load-uid", type=int, default=1000)
    parser.add_argument("--ssh-identity", type=Path, required=True)
    parser.add_argument("--wok-binary", type=Path, required=True)
    parser.add_argument("--rocksdb-binary", type=Path, help="Add opt-in optimized RocksDB Wok as a fourth arm; reuse Wok config/workload")
    parser.add_argument("--fastr-binary", type=Path, required=True)
    parser.add_argument("--strfry-binary", type=Path, required=True)
    parser.add_argument("--bench-binary", type=Path)
    parser.add_argument("--load-bench-binary", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--predecessor", type=Path, help="Import verified completed evidence and closed seed references from the COUNT-cap predecessor")
    parser.add_argument("--rerun-network", action="store_true", help="Reuse verified seeds/corpora only; rerun all cells with a corrected preflight benchmark binary")
    parser.add_argument("--rerun-arms", nargs="+", choices=[*ARMS, "rocksdb"], default=[],
                        help="Explicit recovery: invalidate these arms, preserve verified completed cells of unchanged arms; requires --rerun-network")
    parser.add_argument("--wok-config-template", type=Path, required=True)
    parser.add_argument("--strfry-config-template", type=Path, required=True)
    parser.add_argument("--fastr-environment", type=Path, required=True)
    parser.add_argument("--relay-address", default="10.77.1.2")
    parser.add_argument("--port", type=int, default=29990)
    parser.add_argument("--unit-prefix", default="wok-fastr-bench-20261103")
    parser.add_argument("--relay-slice", default="wokfastrbench20261103.slice")
    parser.add_argument("--base-timestamp", type=int, required=True)
    parser.add_argument("--seed", type=int, default=257)
    parser.add_argument("--corpus-events", type=int, default=15000000)
    parser.add_argument("--events", type=int, default=80000)
    parser.add_argument("--matched-writer-authors", choices=["disjoint", "queried"], default="disjoint",
                        help="Legacy independent32authors, or64actualhistoricalauthor-plan keys; queried requires same matched-corpus seed and new evidence")
    parser.add_argument("--qualification-corpus-events", type=int, default=12000)
    parser.add_argument("--qualification-events", type=int, default=1000)
    parser.add_argument("--load-memory-gib", type=int, default=56)
    parser.add_argument("--minimum-free-gib", type=int, default=80)
    parser.add_argument("--copy-headroom-gib", type=int, default=20, help="Untimed disk-copy safety guard")
    parser.add_argument("--resume-measured", action="store_true", help="Controller-only recovery: preserve verified measured cells, including externally proven read overload; all relay/driver binaries must be identical")
    parser.add_argument("--allow-read-ingress-overload", action="store_true", help="Explicit user-authorized Rocks main read-queue overflow classification with external relay log/correctness proof; retain protocol counters")
    parser.add_argument("--retain-overload-on-load", action="store_true", help="Preserve closed overloaded trial DB on load VM with full hash proof before relay clone cleanup")
    parser.add_argument("--settle-secs", type=int, default=30)
    parser.add_argument("--drain-secs", type=int, default=120)
    args = parser.parse_args()
    campaign = Campaign(args)
    def cancelled(_signal, _frame):
        raise RuntimeError("benchmark controller received termination; preserving evidence")
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    try:
        campaign.run()
    except BaseException as error:
        stopped = campaign.stop_owned_active()
        campaign.update(state="failed", error=repr(error), stopped_owned_units=stopped, cgroup=cgroup_stats())
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
