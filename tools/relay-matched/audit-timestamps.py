#!/usr/bin/env python3
"""Verify frozen matched-network ledgers and report exact latency/tail windows.

Run this where the reports live; the output contains aggregate measurements,
not event bodies. Missing operations retain the driver's fixed censor deadline.
Wire latency starts at send_started_us, before the socket send completes.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import json
from math import ceil
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def quantiles(values):
    counts = Counter(values)
    size = counts.total()
    result = {'count': size}
    ordered = sorted(counts.items())
    for label, percentile in [('p50', .5), ('p90', .9), ('p99', .99), ('p999', .999)]:
        rank, seen = ceil(size * percentile), 0
        for value, count in ordered:
            seen += count
            if seen >= rank:
                result[label + '_us'] = value
                break
    if ordered:
        result['max_us'] = ordered[-1][0]
    return result


def compare_histogram(exact, reported):
    assert exact['count'] == reported['count'], 'histogram count differs from raw timestamps'
    for key in ['p50_us', 'p90_us', 'p99_us', 'max_us']:
        if key in exact:
            # The driver uses an HDR upper bucket edge with three significant digits.
            assert 0 <= reported[key] - exact[key] <= max(2, exact[key] * .0011 + 1), (
                'reported histogram differs from raw timestamps', key, exact[key], reported[key])


def latency(rows, end, censor):
    return {
        'scheduled': quantiles(max(0, (r[end] if r[end] is not None else censor) - r['due_us']) for r in rows),
        'wire': quantiles(max(0, (r[end] if r[end] is not None else censor) - r['send_started_us'])
                          for r in rows if r['send_started_us'] is not None),
        'send_lateness': quantiles(max(0, r['send_started_us'] - r['due_us'])
                                   for r in rows if r['send_started_us'] is not None),
        'censored': sum(r[end] is None for r in rows),
        'unsent': sum(r['sent_us'] is None for r in rows),
    }


def debt(rows, end, at):
    offered = sum(r['due_us'] < at for r in rows)
    sent = sum(r['sent_us'] is not None and r['sent_us'] <= at for r in rows)
    completed = sum(r[end] is not None and r[end] <= at for r in rows)
    return {'offered': offered, 'completed': completed, 'unanswered': offered - completed,
            'not_yet_sent': offered - sent, 'sent_pending': sent - completed}


def outstanding(rows, end):
    changes = []
    for row in rows:
        if row['send_started_us'] is not None:
            changes.append((row['send_started_us'], 1))
            if row[end] is not None:
                changes.append((row[end], -1))
    value = peak = 0
    # Treat coincident starts before completions: a conservative timestamp bound.
    for _, delta in sorted(changes, key=lambda pair: (pair[0], -pair[1])):
        value += delta
        peak = max(peak, value)
    return {'peak_attempts': peak, 'unfinished_attempts': value}


def verify_rows(rows, *, rate, end):
    for seq, row in enumerate(rows):
        assert row['seq'] == seq, 'missing, duplicate, or out-of-order ledger sequence'
        assert abs(row['due_us'] - int(seq * 1_000_000 / rate)) <= 1, 'offered arrival schedule changed'
        for key in ['due_us', 'send_started_us', 'sent_us', end]:
            value = row[key]
            assert value is None or (type(value) is int and value >= 0), 'invalid timestamp'
        start = row['send_started_us']
        assert row['sent_us'] is None or (start is not None and row['sent_us'] >= start), 'sent without a send attempt'
        assert row[end] is None or (start is not None and row[end] >= start), 'completion precedes send attempt'


def resources(folder):
    result = {}
    for label, relative, memory in [('relay', 'relay.resources.json', 64), ('load', 'load/load.resources.json', 56)]:
        meta = read(folder / relative)
        assert meta['resource_limits']['nofile']['soft'] >= 65536, 'file limit changed'
        for key in ['cgroup_before', 'cgroup_after']:
            group = meta[key]
            assert group['cpu.max'].split() == ['1600000', '100000'], 'CPU quota changed'
            assert int(group['memory.max']) == memory << 30, 'memory cap changed'
            if 'cpuset.cpus.effective' in group:
                assert group['cpuset.cpus.effective'].strip() == '0-15', 'CPU set changed'
            else:
                assert label == 'load' and meta['cgroup_before']['cpu_affinity_verification']['actual_cpus'] == list(range(16)), 'missing real CPU affinity proof'
        events = dict(line.split() for line in meta['cgroup_after']['memory.events'].splitlines())
        result[label] = {
            'started': meta.get('started'), 'finished': meta.get('finished'),
            'exit_code': meta['exit_code'], 'elapsed_secs': meta['elapsed_secs'],
            'user_cpu_secs': meta['user_cpu_secs'], 'system_cpu_secs': meta['system_cpu_secs'],
            'max_rss_kib': meta['max_rss_kib'], 'cgroup_peak_bytes': int(meta['cgroup_after']['memory.peak']),
            'oom': int(events.get('oom', 0)), 'oom_kill': int(events.get('oom_kill', 0)),
            'final_child_io': meta.get('final_child_io'),
        }
    return result


def backend_activity(folder, artifacts, started, finished):
    paths = sorted(folder.glob('backend-logs/LOG*'))
    if not paths:
        return None
    assert started and finished, 'backend activity requires recorded process time bounds'
    start = round(datetime.datetime.fromisoformat(started).timestamp() * 1_000_000)
    end = round(datetime.datetime.fromisoformat(finished).timestamp() * 1_000_000)
    events = []
    for path in paths:
        assert str(path.relative_to(folder)) in artifacts, 'unhashed backend activity log'
        with path.open() as stream:
            for line in stream:
                if 'EVENT_LOG_v1 ' in line:
                    event = json.loads(line.split('EVENT_LOG_v1 ', 1)[1])
                    if start <= event['time_micros'] <= end:
                        events.append(event)
    return {
        'event_counts': dict(Counter(e['event'] for e in events)),
        'compaction_output_bytes': sum(e.get('total_output_size', 0) for e in events if e['event'] == 'compaction_finished'),
        'compaction_elapsed_us_sum': sum(e.get('compaction_time_micros', 0) for e in events if e['event'] == 'compaction_finished'),
        'flush_input_bytes': sum(e.get('total_data_size', 0) for e in events if e['event'] == 'flush_started'),
        'events': events,
        'scope': 'Native RocksDB event-log observations during the recorded relay process lifetime. Inherited seed log history is excluded by wall-clock bounds. Includes startup, preflight, postcheck and idle settlement; the frozen driver does not record an exact wall-clock origin for relative query timestamps.',
    }


def audit_trial(folder, window_seconds=5):
    folder = Path(folder)
    marker = read(folder / 'complete.json')
    assert marker['artifacts'], 'empty artifact manifest'
    required = {'load/network-matched.json', 'load/query-outcomes.jsonl', 'load/write-outcomes.jsonl',
                'load/timedwrites.jsonl', 'relay.resources.json', 'load/load.resources.json'}
    assert required <= marker['artifacts'].keys(), 'critical evidence missing from artifact manifest'
    for name, expected in marker['artifacts'].items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts, 'artifact path escapes report directory'
        assert sha(folder / path) == expected, 'artifact changed: ' + name
    report = read(folder / 'load/network-matched.json')
    assert report['format'] == 'network-matched-v1'
    streams = []
    for name in ['query-outcomes.jsonl', 'write-outcomes.jsonl']:
        with (folder / 'load' / name).open() as stream:
            streams.append([json.loads(line) for line in stream])
    queries, writes = streams
    verify_rows(queries, rate=report['read_rate'], end='eose_us')
    verify_rows(writes, rate=report['write_rate'], end='reply_us')
    assert report['offered_reads'] == len(queries)
    assert report['offered_writes'] == len(writes)
    assert report['offered_reads'] == int(report['offer_horizon_secs'] * report['read_rate'])
    assert abs(report['offer_horizon_secs'] * report['write_rate'] - len(writes)) < .001
    for rows, label, end in [(queries, 'reads', 'eose_us'), (writes, 'writes', 'reply_us')]:
        assert report['sent_' + label] == sum(r['sent_us'] is not None for r in rows)
        assert report['unsent_' + label] == sum(r['sent_us'] is None for r in rows)
        assert report['unanswered_' + label] == sum(r[end] is None for r in rows)
    assert report['completed_reads'] == sum(r['eose_us'] is not None for r in queries)
    assert report['accepted_writes'] == sum(r['accepted'] is True for r in writes)
    assert report['rejected_writes'] == sum(r['accepted'] is False for r in writes)
    assert report['query_mismatches'] == sum(r['matches'] is False for r in queries)
    assert report['protocol_errors'] == len(report['errors']), 'protocol error count disagrees with retained errors'
    assert all((r['reply_us'] is None) == (r['accepted'] is None) for r in writes), 'write reply/status disagreement'
    assert all(r['eose_us'] is None or r['matches'] is not None for r in queries), 'completed read lacks body/oracle result'
    assert report['read_connections'] == 2 and report['publish_connections'] == 32, 'socket counts changed'
    for row in queries:
        first = row['first_event_us']
        assert first is None or (type(first) is int and row['send_started_us'] is not None
                                 and first >= row['send_started_us']), 'invalid first event timestamp'
        assert first is None or row['eose_us'] is None or first <= row['eose_us'], 'first event follows EOSE'
    assert report['preflight']['count_terminal_response'] is True
    assert report['preflight']['measurement_starts_after_count'] is True
    horizon = round(report['offer_horizon_secs'] * 1_000_000)
    censor = horizon + report['drain_secs'] * 1_000_000
    by_shape = {}
    for shape in sorted({r['shape'] for r in queries}):
        selected = [r for r in queries if r['shape'] == shape]
        stats = latency(selected, 'eose_us', censor)
        first = latency(selected, 'first_event_us', censor)
        by_shape[shape] = {'eose': stats, 'first_event': first}
        reported = next(item for item in report['reads'] if item['shape'] == shape)
        for key, hist in [('scheduled', 'scheduled_to_eose'), ('wire', 'wire_to_eose'), ('send_lateness', 'send_lateness')]:
            compare_histogram(stats[key], reported[hist])
        for key, hist in [('scheduled', 'scheduled_to_first_event'), ('wire', 'wire_to_first_event')]:
            compare_histogram(first[key], reported[hist])
    write_stats = latency(writes, 'reply_us', censor)
    for key, hist in [('scheduled', 'scheduled_to_ok'), ('wire', 'wire_to_ok'), ('send_lateness', 'send_lateness')]:
        compare_histogram(write_stats[key], report['writes'][hist])
    resource = resources(folder)
    correctness = (report['query_mismatches'] == report['postcheck_mismatches'] == report['rejected_writes'] == 0
                   and report['postcheck']['mismatches'] == 0)
    complete = (report['completed_reads'] == len(queries) and report['accepted_writes'] == len(writes)
                and report['sent_reads'] == len(queries) and report['sent_writes'] == len(writes))
    if report['ok']:
        assert complete and correctness and not report['errors'], 'false success claim'
        assert report['postcheck']['queried'] == report['postcheck']['stored'] == len(writes), 'incomplete full-write readback'
    background_errors = None
    backend = folder / 'backend-final-stats.json'
    if marker['job']['arm'] == 'rocksdb':
        assert backend.exists(), 'missing RocksDB background-error evidence'
    if backend.exists():
        assert 'backend-final-stats.json' in marker['artifacts'], 'unhashed backend statistics'
        background_errors = sum(v['rocksdb.background-errors'] for v in read(backend)['column_families'].values())
    eligible = (report['ok'] and marker['outcome'] == 'completed' and complete and correctness
                and background_errors in [None, 0]
                and all(r['oom'] == r['oom_kill'] == 0 for r in resource.values())
                and resource['load']['exit_code'] == 0 and resource['relay']['exit_code'] in [0, -15])
    windows = []
    width = round(window_seconds * 1_000_000)
    assert width > 0
    for start in range(0, horizon, width):
        end = min(horizon, start + width)
        q = [r for r in queries if start <= r['due_us'] < end]
        w = [r for r in writes if start <= r['due_us'] < end]
        windows.append({'start_us': start, 'end_us': end,
                        'reads': {s: latency([r for r in q if r['shape'] == s], 'eose_us', censor) for s in by_shape},
                        'writes': latency(w, 'reply_us', censor),
                        'read_debt_at_end': debt(queries, 'eose_us', end),
                        'write_debt_at_end': debt(writes, 'reply_us', end)})
    return {
        'evidence': str(folder), 'job': marker['job'], 'outcome': marker['outcome'],
        'eligible_for_read_and_write_mixed_load_latency': eligible,
        'artifact_hashes_verified': len(marker['artifacts']),
        'report_sha256': sha(folder / 'load/network-matched.json'), 'completion_marker_sha256': sha(folder / 'complete.json'),
        'corpus_sha256': report['corpus_sha256'], 'query_plan_sha256': report['query_plan_sha256'],
        'timed_writes_sha256': sha(folder / 'load/timedwrites.jsonl'),
        'corpus_events': report['corpus_events'], 'corpus_retained': report['corpus_retained'],
        'write_rate': report['write_rate'], 'read_rate': report['read_rate'],
        'window_seconds': report['offer_horizon_secs'], 'drain_seconds': report['drain_secs'],
        'reads': {k: report[k] for k in ['offered_reads', 'sent_reads', 'completed_reads', 'unsent_reads', 'unanswered_reads']},
        'writes': {k: report[k] for k in ['offered_writes', 'sent_writes', 'accepted_writes', 'unsent_writes', 'unanswered_writes']},
        'read_latency': by_shape, 'write_latency': write_stats,
        'read_debt_at_offer_end': debt(queries, 'eose_us', horizon),
        'write_debt_at_offer_end': debt(writes, 'reply_us', horizon),
        'read_outstanding': outstanding(queries, 'eose_us'), 'write_outstanding': outstanding(writes, 'reply_us'),
        'last_observed_read_drain_us': max(0, max((r['eose_us'] or 0 for r in queries), default=0) - horizon),
        'last_observed_write_drain_us': max(0, max((r['reply_us'] or 0 for r in writes), default=0) - horizon),
        'finished_us': report['finished_us'], 'errors': report['errors'], 'postcheck': report['postcheck'],
        'correctness_passed': correctness, 'background_errors': background_errors,
        'backend_activity': backend_activity(folder, marker['artifacts'], resource['relay']['started'], resource['relay']['finished']),
        'resources': resource, 'arrival_windows': windows,
        'interpretation': 'Exact nearest-rank microseconds. Incomplete latencies include the fixed censor deadline; they cannot win either mixed-load latency comparison. Windows group by scheduled arrival. Outstanding/debt measures client timestamps, not internal relay queue length. Drain reports only observed completions and does not clear unanswered debt.',
    }


def audit_many(folders, window_seconds=5):
    rows = [audit_trial(folder, window_seconds) for folder in folders]
    assert len({r['corpus_sha256'] for r in rows}) <= 1, 'compared corpus identities differ'
    assert len({r['query_plan_sha256'] for r in rows}) <= 1, 'compared query plans differ'
    groups = {}
    for row in rows:
        key = (row['write_rate'], row['read_rate'], row['writes']['offered_writes'])
        groups.setdefault(key, set()).add(row['timed_writes_sha256'])
    assert all(len(hashes) == 1 for hashes in groups.values()), 'matched timed-write identities differ'
    return {'format': 'matched-network-raw-audit-v1', 'auditor_sha256': sha(Path(__file__)), 'rows': rows,
            'all_artifact_hashes_and_raw_timestamp_ledgers_verified': True,
            'same_corpus_query_plans_and_grouped_timed_writes': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='+', type=Path, help='Trial directories containing complete.json and load/*.jsonl')
    parser.add_argument('--window-seconds', type=float, default=5)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    result = json.dumps(audit_many(args.reports, args.window_seconds), indent=2) + '\n'
    if args.out:
        assert not args.out.exists(), 'Audit output already exists; use a new identity.'
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(result)
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
