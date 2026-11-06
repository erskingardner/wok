#!/usr/bin/env python3
"""Bounded Linux relay soak. Uses disposable storage and preserves all evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import stat
import subprocess
import sys
import time
import urllib.request

STORAGE_BACKEND = "rocksdb-author-heads-experimental"
SMALL_ROCKSDB_OPTIONS = {
    "block_cache_bytes": 16 * 1024 * 1024,
    "row_cache_bytes": 0,
    "total_memtable_bytes": 16 * 1024 * 1024,
    "max_total_wal_bytes": 32 * 1024 * 1024,
}


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def stop(child):
    if child is None:
        return
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            raise RuntimeError("relay did not stop gracefully")
    if child.returncode != 0:
        raise RuntimeError(f"relay exited {child.returncode}")


def database_footprint(path):
    """Sample logical backend files; compaction may unlink a listed SST."""
    sizes = {"wal": 0, "sst": 0, "other": 0}
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"expected a plain database directory: {path}")
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            entry = Path(parent) / name
            try:
                info = entry.lstat()
            except FileNotFoundError:
                # RocksDB can retire a compacted SST after os.walk listed it.
                # This is a sample rather than an atomic storage snapshot.
                continue
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError(f"database symlink outside bounded scratch: {entry}")
            if stat.S_ISREG(info.st_mode):
                kind = "wal" if entry.suffix == ".log" else "sst" if entry.suffix == ".sst" else "other"
                sizes[kind] += info.st_size
    return sizes


def database_bytes(path):
    return sum(database_footprint(path).values())


def verify_backend(wok):
    actual = subprocess.run([str(wok.resolve()), "storage-backend"], capture_output=True,
                            text=True, check=True, timeout=15).stdout.strip()
    if actual != STORAGE_BACKEND:
        raise RuntimeError(f"binary reports {actual!r}; expected {STORAGE_BACKEND!r}")
    return actual


def validate_driver_result(result):
    if not (result.get("ok") is True and result.get("restart_verified") is True
            and result.get("crash_recovery_verified") is True
            and result.get("feed_author_count") == 500 and result.get("author_feed_checks", 0) >= 6
            and result.get("author_live_deliveries", 0) > 0):
        raise RuntimeError("driver did not verify both recovery phases and the active 500-author feed")


def crash(child, evidence):
    """Record the one deliberate owned-process crash without treating it as exit0."""
    if child.poll() is not None:
        raise RuntimeError(f"relay exited before controlled crash: {child.returncode}")
    child.kill()
    code = child.wait(timeout=15)
    evidence.write_text(json.dumps({"intentional": True, "actual_returncode": code,
                        "signal": "SIGKILL", "scope": "acknowledged data; not power loss"}))
    if code != -signal.SIGKILL:
        raise RuntimeError(f"controlled crash exited {code}")


def ready(child, url):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f"relay exited during startup: {child.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("relay startup deadline")


def sample(pid, root, started):
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    footprint = database_footprint(root / "db")
    return {"seconds": time.monotonic() - started, "observed_unix_millis": int(time.time() * 1000), "pid": pid,
            "rss_kib": int(status.get("VmRSS", "0 kB").split()[0]),
            "anonymous_kib": int(status.get("RssAnon", "0 kB").split()[0]),
            "cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
            "threads": int(status["Threads"]), "db_bytes": sum(footprint.values()), "db_file_bytes": footprint}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wok", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--port", type=int, default=17777)
    parser.add_argument("--max-db-mib", type=int, default=512,
                        help="whole database allowance, including WAL (default: 512 MiB)")
    parser.add_argument("--rocksdb-profile", choices=["small", "native-defaults"], default="small",
                        help="startup resource targets (default: small); native-defaults applies no overrides")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or not 10 <= args.seconds <= 21600:
        parser.error("requires Linux and a duration between 10 and 21600 seconds")
    if not 64 <= args.max_db_mib <= 16384:
        parser.error("--max-db-mib must be between 64 and 16384")
    return args


def rocksdb_overrides(profile):
    return SMALL_ROCKSDB_OPTIONS.copy() if profile == "small" else {}


def config_text(args, root, unix):
    overrides = rocksdb_overrides(args.rocksdb_profile)
    native = ""
    if overrides:
        native = "[database.rocksdb]\n" + "".join(f"{key} = {value}\n" for key, value in overrides.items())
    return f'''[database]
path = {json.dumps(str(root / "db"))}
map_size = 1073741824
min_free_disk_bytes = 0
{native}[relay]
bind = "127.0.0.1"
port = {args.port}
# Retain the runner's inherited limit; this bounded workload uses few sockets.
nofiles = 0
max_filter_limit = 30000
max_total_events_per_req = 30000
max_pending_outbound_bytes = 16777216
[relay.abuse]
enabled = false
[observability]
# Readiness and the resource samples read /metrics.
metrics_enabled = true
[relay.unix]
enabled = true
path = {json.dumps(str(unix))}
max_pending_outbound_bytes = 16777216
'''


def main():
    args = parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    # Short socket path avoids AF_UNIX's small sun_path even for deep artifact roots.
    import tempfile
    socket_dir = tempfile.TemporaryDirectory(prefix="wok-soak-")
    unix = Path(socket_dir.name) / "relay.sock"
    cfg = root / "wok.toml"
    cfg.write_text(config_text(args, root, unix))
    metadata = {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                "nofile_limits": resource.getrlimit(resource.RLIMIT_NOFILE),
                "seconds_requested": args.seconds, "seed": args.seed, "wok_sha256": digest(args.wok),
                "driver_sha256": digest(args.driver), "config_sha256": digest(cfg),
                "backend": "rocksdb",
                "durability": "synchronous RocksDB WAL batches",
                "db_size_scope": "all regular database files, including WAL/SST/metadata; logical bytes",
                "database_policy": {"max_mib": args.max_db_mib},
                "rocksdb_profile": args.rocksdb_profile,
                "rocksdb_overrides": rocksdb_overrides(args.rocksdb_profile),
                "crash_scope": "one intentional SIGKILL after an acknowledged batch; not in-flight writes or power loss",
                "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "memory_policy": {"rss_max_mib": 768, "anonymous_growth_max_mib_after_120s_warmup": 64}}
    for name in ["cpu.max", "memory.max", "memory.swap.max"]:
        path = Path("/sys/fs/cgroup") / name
        metadata[name] = path.read_text().strip() if path.exists() else "unavailable"
    (root / "host-meminfo.txt").write_text(Path("/proc/meminfo").read_text())
    (root / "host-cpuinfo.txt").write_text(Path("/proc/cpuinfo").read_text())
    (root / "manifest.json").write_text(json.dumps(metadata, indent=2))
    relay = load = None
    samples = []
    started = time.monotonic()
    url = f"http://127.0.0.1:{args.port}/metrics"
    relay_log = open(root / "relay.log", "w")
    driver_log = open(root / "driver.jsonl", "w")
    driver_err = open(root / "driver.stderr", "w")

    def launch():
        child = subprocess.Popen([str(args.wok.resolve()), "--config", str(cfg), "relay"], stdout=relay_log, stderr=relay_log)
        try:
            ready(child, url)
        except BaseException:
            if child.poll() is None:
                child.kill()
            child.wait()
            raise
        return child

    def integrity(name):
        with open(root / name, "w") as log:
            subprocess.run([str(args.wok.resolve()), "--config", str(cfg), "integrity"], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
        path = root / name.replace("-integrity.txt", "-rocksdb-audit.json")
        with path.open("x") as log:
            subprocess.run([str(args.wok.resolve()), "--config", str(cfg), "rocksdb-check"],
                           stdout=log, stderr=relay_log, check=True, timeout=120)
        audit = json.loads(path.read_text())
        if not (audit.get("ok") is True and audit.get("author_head_records_verified", 0) > 0
                and audit.get("author_frontier_positions_verified", 0) > 0):
            raise RuntimeError("RocksDB primary/index/author-frontier audit failed")
        return audit

    try:
        metadata["binary_storage_backend"] = verify_backend(args.wok)
        (root / "manifest.json").write_text(json.dumps(metadata, indent=2))
        relay = launch()
        load = subprocess.Popen([str(args.driver.resolve()), f"ws://127.0.0.1:{args.port}", f"unix://{unix}", str(args.seconds), str(root), str(args.seed)], stdout=driver_log, stderr=driver_err)
        next_sample = 0
        with open(root / "samples.jsonl", "w") as log, open(root / "metrics.jsonl", "w") as metrics:
            deadline = started + args.seconds + 300
            while load.poll() is None:
                if time.monotonic() > deadline:
                    raise RuntimeError("soak exceeded its wall-clock budget")
                if relay.poll() is not None:
                    raise RuntimeError(f"relay unexpectedly exited {relay.returncode}")
                if (root / "restart.request").exists() and not (root / "restart.ready").exists():
                    stop(relay)
                    relay = None
                    integrity("restart-integrity.txt")
                    relay = launch()
                    (root / "restart.ready").write_text("ready")
                if (root / "crash.request").exists() and not (root / "crash.ready").exists():
                    # All receipts and live payloads were checked before this request.
                    # Only this owned relay is killed; its scratch DB and logs remain.
                    crash(relay, root / "crash-exit.json")
                    relay = None
                    integrity("crash-integrity.txt")
                    relay = launch()
                    (root / "crash.ready").write_text("ready")
                if time.monotonic() >= next_sample:
                    row = sample(relay.pid, root, started)
                    samples.append(row)
                    log.write(json.dumps(row) + "\n")
                    log.flush()
                    if row["rss_kib"] > 768 * 1024:
                        raise RuntimeError("relay exceeded the 768 MiB RSS budget")
                    if row["db_bytes"] > args.max_db_mib * 1024 * 1024:
                        raise RuntimeError(f"bounded dataset exceeded {args.max_db_mib} MiB database budget")
                    with urllib.request.urlopen(url, timeout=3) as response:
                        metrics.write(json.dumps({"seconds": row["seconds"], "text": response.read().decode()}) + "\n")
                        metrics.flush()
                    next_sample = time.monotonic() + 5
                time.sleep(0.1)
        if load.returncode != 0:
            raise RuntimeError(f"load driver failed ({load.returncode}); see driver.stderr")
        stop(relay)
        relay = None
        final_audit = integrity("final-integrity.txt")
        growth = []
        for pid in sorted({s["pid"] for s in samples}):
            rows = [s for s in samples if s["pid"] == pid]
            warm = [s for s in rows if s["seconds"] - rows[0]["seconds"] >= 120]
            if len(warm) >= 12:
                change = max(s["anonymous_kib"] for s in warm[-6:]) - max(s["anonymous_kib"] for s in warm[:6])
                growth.append({"pid": pid, "anonymous_growth_kib": change})
        (root / "memory-analysis.json").write_text(json.dumps({
            "policy": metadata["memory_policy"], "segments": growth,
            "ok": all(segment["anonymous_growth_kib"] <= 64 * 1024 for segment in growth),
        }, indent=2))
        for segment in growth:
            if segment["anonymous_growth_kib"] > 64 * 1024:
                raise RuntimeError(f"anonymous memory grew by {segment['anonymous_growth_kib']} KiB after warmup")
        driver = json.loads((root / "driver-result.json").read_text())
        validate_driver_result(driver)
        if final_audit["events"] != driver["stored"]:
            raise RuntimeError("offline RocksDB primary count differs from the exact driver model")
        result = {"ok": True, "driver": driver, "peak_rss_kib": max(s["rss_kib"] for s in samples),
                  "backend": "rocksdb", "binary_storage_backend": metadata["binary_storage_backend"],
                  "peak_anonymous_kib": max(s["anonymous_kib"] for s in samples), "memory_segments": growth,
                  "final_db_bytes": database_bytes(root / "db"), "samples": len(samples), "corpus_sha256": digest(root / "corpus.jsonl")}
        (root / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
    except BaseException as error:
        (root / "failure.json").write_text(json.dumps({"ok": False, "error": str(error)}, indent=2))
        raise
    finally:
        if load is not None and load.poll() is None:
            load.terminate()
            try:
                load.wait(timeout=10)
            except subprocess.TimeoutExpired:
                load.kill()
                load.wait()
        primary_error = sys.exc_info()[0] is not None
        try:
            stop(relay)
        except Exception as error:
            (root / "cleanup-failure.json").write_text(json.dumps({"error": str(error)}))
            if not primary_error:
                raise
        finally:
            socket_dir.cleanup()
            relay_log.close()
            driver_log.close()
            driver_err.close()


if __name__ == "__main__":
    main()
