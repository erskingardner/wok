#!/usr/bin/env python3
"""Run bounded remote benchmarks and reject incomplete/incorrect result sets."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time


def positive(name, default):
    value = int(os.environ.get(name) or default)
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def validate_results(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    expected = {"ws_publish_scaled", "live_fanout", "idle_connections"}
    if len(rows) != 3 or {row.get("scenario") for row in rows} != expected:
        raise RuntimeError("missing or duplicate benchmark scenarios")
    if any(row.get("ok") is not True or row.get("errors") != 0 or row.get("mismatches") != 0 for row in rows):
        raise RuntimeError("benchmark correctness gate failed; see results.jsonl")
    return rows


def main():
    root = Path('/results/run')
    root.mkdir(exist_ok=False)
    started = time.monotonic()
    target = os.environ.get('LAB_TARGET', 'ws://relay:7777')
    seed = positive('LAB_SEED', 4242)
    rounds = positive('LAB_ROUNDS', 1)
    deadline = positive('LAB_DEADLINE_SECONDS', 900)
    timestamp = positive('LAB_BASE_TIMESTAMP', int(time.time()))
    knobs = {'events': positive('LAB_EVENTS', 2000), 'publish-connections': positive('LAB_PUBLISHERS', 8),
             'fanout-subscribers': positive('LAB_SUBSCRIBERS', 8), 'fanout-events': positive('LAB_FANOUT_EVENTS', 100),
             'connections': positive('LAB_CONNECTIONS', 64), 'hold-seconds': positive('LAB_HOLD_SECONDS', 2)}
    with open('/usr/local/bin/wok-bench', 'rb') as binary:
        digest = hashlib.file_digest(binary, 'sha256').hexdigest()
    (root/'manifest.json').write_text(json.dumps({'target': target, 'seed': seed, 'rounds': rounds,
        'base_timestamp': timestamp, 'deadline_seconds': deadline, 'knobs': knobs,
        'generator_sha256': digest, 'platform': platform.platform()}, indent=2))
    all_rows = []
    try:
        for i in range(rounds):
            output = root/f'round-{i+1}'
            args = ['wok-bench', '--profile', 'load', '--target-url', target, '--target-label', 'lab',
                    '--event-mix', 'realistic', '--seed', str(seed+i), '--base-timestamp', str(timestamp),
                    '--out', str(output)]
            for name, value in knobs.items():
                args += ['--'+name, str(value)]
            remaining = deadline - (time.monotonic()-started)
            if remaining <= 0:
                raise TimeoutError('campaign deadline exceeded')
            with (root/f'round-{i+1}.log').open('w') as log:
                subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=remaining)
            all_rows.extend(validate_results(output/'results.jsonl'))
        (root/'result.json').write_text(json.dumps({'ok': True, 'seconds': time.monotonic()-started,
                                                    'trials': len(all_rows)}, indent=2))
    except BaseException as error:
        (root/'failure.json').write_text(json.dumps({'ok': False, 'error': str(error)}, indent=2))
        raise


if __name__ == '__main__':
    main()
