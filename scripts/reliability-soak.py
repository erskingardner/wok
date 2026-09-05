#!/usr/bin/env python3
"""Bounded Linux relay soak. Uses disposable storage and preserves all evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import urllib.request


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def stop(child):
    if child is not None and child.poll() is None:
        child.send_signal(signal.SIGTERM)
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            raise RuntimeError("relay did not stop gracefully")
        if child.returncode != 0:
            raise RuntimeError(f"relay exited {child.returncode}")


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
    return {"seconds": time.monotonic() - started, "pid": pid,
            "rss_kib": int(status.get("VmRSS", "0 kB").split()[0]),
            "anonymous_kib": int(status.get("RssAnon", "0 kB").split()[0]),
            "cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
            "threads": int(status["Threads"]), "db_bytes": (root / "db/data.mdb").stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wok", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--port", type=int, default=17777)
    args = parser.parse_args()
    if sys.platform != "linux" or not 10 <= args.seconds <= 21600:
        parser.error("requires Linux and a duration between 10 and 21600 seconds")
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    # Short socket path avoids AF_UNIX's small sun_path even for deep artifact roots.
    import tempfile
    socket_dir = tempfile.TemporaryDirectory(prefix="wok-soak-")
    unix = Path(socket_dir.name) / "relay.sock"
    cfg = root / "wok.toml"
    cfg.write_text(f'''[database]
path = {json.dumps(str(root / "db"))}
map_size = 1073741824
min_free_disk_bytes = 0
[relay]
bind = "127.0.0.1"
port = {args.port}
max_filter_limit = 30000
max_total_events_per_req = 30000
max_pending_outbound_bytes = 16777216
[relay.abuse]
enabled = false
[relay.unix]
enabled = true
path = {json.dumps(str(unix))}
max_pending_outbound_bytes = 16777216
''')
    metadata = {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                "seconds_requested": args.seconds, "seed": args.seed, "wok_sha256": digest(args.wok),
                "driver_sha256": digest(args.driver), "config_sha256": digest(cfg),
                "durability": "normal LMDB synchronous commits", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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

    try:
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
                    integrity("restart-integrity.txt")
                    relay = launch()
                    (root / "restart.ready").write_text("ready")
                if time.monotonic() >= next_sample:
                    row = sample(relay.pid, root, started)
                    samples.append(row)
                    log.write(json.dumps(row) + "\n")
                    log.flush()
                    if row["rss_kib"] > 768 * 1024:
                        raise RuntimeError("relay exceeded the 768 MiB RSS budget")
                    if row["db_bytes"] > 512 * 1024 * 1024:
                        raise RuntimeError("bounded dataset exceeded 512 MiB database budget")
                    with urllib.request.urlopen(url, timeout=3) as response:
                        metrics.write(json.dumps({"seconds": row["seconds"], "text": response.read().decode()}) + "\n")
                        metrics.flush()
                    next_sample = time.monotonic() + 5
                time.sleep(0.1)
        if load.returncode != 0:
            raise RuntimeError(f"load driver failed ({load.returncode}); see driver.stderr")
        stop(relay)
        integrity("final-integrity.txt")
        growth = []
        for pid in sorted({s["pid"] for s in samples}):
            rows = [s for s in samples if s["pid"] == pid]
            warm = [s for s in rows if s["seconds"] - rows[0]["seconds"] >= 120]
            if len(warm) >= 12:
                change = max(s["anonymous_kib"] for s in warm[-6:]) - max(s["anonymous_kib"] for s in warm[:6])
                growth.append({"pid": pid, "anonymous_growth_kib": change})
                if change > 64 * 1024:
                    raise RuntimeError(f"anonymous memory grew by {change} KiB after warmup")
        driver = json.loads((root / "driver-result.json").read_text())
        result = {"ok": True, "driver": driver, "peak_rss_kib": max(s["rss_kib"] for s in samples),
                  "peak_anonymous_kib": max(s["anonymous_kib"] for s in samples), "memory_segments": growth,
                  "final_db_bytes": samples[-1]["db_bytes"], "samples": len(samples), "corpus_sha256": digest(root / "corpus.jsonl")}
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


if __name__ == "__main__":
    main()
