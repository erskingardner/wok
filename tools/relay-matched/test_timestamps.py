"""Raw-ledger audit regressions; no VM jobs or network access."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('audit-timestamps.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def histogram(count, value):
    return {'count': count, 'p50_us': value, 'p90_us': value, 'p99_us': value, 'max_us': value}


class TimestampTests(unittest.TestCase):
    def fixture(self, root):
        folder = root / 'trial'
        (folder / 'load').mkdir(parents=True)
        queries = [
            {'seq': seq, 'shape': shape, 'due_us': seq * 250_000,
             'send_started_us': seq * 250_000 + 10, 'sent_us': seq * 250_000 + 20,
             'first_event_us': seq * 250_000 + 40, 'eose_us': seq * 250_000 + 100,
             'received': 1, 'matches': True}
            for seq, shape in enumerate(['author', 'feed500', 'tag', 'id'])
        ]
        writes = [{'seq': seq, 'due_us': seq * 500_000, 'send_started_us': seq * 500_000 + 10,
                   'sent_us': seq * 500_000 + 20, 'reply_us': seq * 500_000 + 100, 'accepted': True}
                  for seq in range(2)]
        report = {
            'format': 'network-matched-v1', 'ok': True, 'write_rate': 2, 'read_rate': 4,
            'read_connections': 2, 'publish_connections': 32, 'offer_horizon_secs': 1, 'drain_secs': 120,
            'offered_reads': 4, 'sent_reads': 4, 'completed_reads': 4, 'unsent_reads': 0, 'unanswered_reads': 0,
            'offered_writes': 2, 'sent_writes': 2, 'accepted_writes': 2, 'rejected_writes': 0,
            'unsent_writes': 0, 'unanswered_writes': 0, 'query_mismatches': 0, 'postcheck_mismatches': 0,
            'protocol_errors': 0,
            'preflight': {'count_terminal_response': True, 'measurement_starts_after_count': True},
            'postcheck': {'queried': 2, 'stored': 2, 'mismatches': 0}, 'finished_us': 1_300_000, 'errors': [],
            'corpus_sha256': 'corpus', 'query_plan_sha256': 'queries', 'corpus_events': 15_000_000,
            'corpus_retained': 15_000_000,
            'reads': [{'shape': row['shape'], 'scheduled_to_eose': histogram(1, 100),
                       'wire_to_eose': histogram(1, 90), 'send_lateness': histogram(1, 10),
                       'scheduled_to_first_event': histogram(1, 40), 'wire_to_first_event': histogram(1, 30)}
                      for row in queries],
            'writes': {'scheduled_to_ok': histogram(2, 100), 'wire_to_ok': histogram(2, 90),
                       'send_lateness': histogram(2, 10)},
        }
        (folder / 'load/timedwrites.jsonl').write_text('signed fixture, no real body\n')
        self.save(folder / 'backend-final-stats.json', {'column_families': {'default': {'rocksdb.background-errors': 0}}})
        for label, relative, memory in [('relay', 'relay.resources.json', 64), ('load', 'load/load.resources.json', 56)]:
            group = {'cpu.max': '1600000 100000\n', 'memory.max': str(memory << 30),
                     'cpuset.cpus.effective': '0-15\n', 'memory.events': 'oom 0\noom_kill 0\n', 'memory.peak': '1024'}
            self.save(folder / relative, {'resource_limits': {'nofile': {'soft': 65536}},
                      'cgroup_before': group, 'cgroup_after': group, 'exit_code': 0, 'elapsed_secs': 2,
                      'user_cpu_secs': 1, 'system_cpu_secs': .1, 'max_rss_kib': 1})
        self.write_trial(folder, report, queries, writes)
        return folder, report, queries, writes

    def save(self, path, value):
        path.write_text(json.dumps(value) + '\n')

    def freeze(self, folder):
        self.save(folder / 'complete.json', {
            'job': {'arm': 'rocksdb', 'write_rate': 2, 'repetition': 1}, 'outcome': 'completed',
            'artifacts': {str(p.relative_to(folder)): M.sha(p) for p in folder.rglob('*')
                          if p.is_file() and p.name != 'complete.json'},
        })

    def write_trial(self, folder, report, queries, writes):
        self.save(folder / 'load/network-matched.json', report)
        for name, rows in [('query-outcomes.jsonl', queries), ('write-outcomes.jsonl', writes)]:
            (folder / 'load' / name).write_text(''.join(json.dumps(r) + '\n' for r in rows))
        self.freeze(folder)

    def test_nearest_rank_uses_raw_values_and_distinguishes_wire_start(self):
        self.assertEqual(M.quantiles([7, 9, 11, 13])['p50_us'], 9)
        self.assertEqual(M.quantiles([7, 9, 11, 13])['p99_us'], 13)
        with tempfile.TemporaryDirectory() as d:
            folder, _, _, _ = self.fixture(Path(d))
            result = M.audit_trial(folder, .5)
            self.assertTrue(result['eligible_for_read_and_write_mixed_load_latency'])
            self.assertEqual(result['read_latency']['author']['eose']['scheduled']['p99_us'], 100)
            self.assertEqual(result['read_latency']['author']['eose']['wire']['p99_us'], 90)
            self.assertEqual(result['read_latency']['author']['eose']['send_lateness']['p99_us'], 10)
            self.assertEqual(result['arrival_windows'][0]['read_debt_at_end']['unanswered'], 0)

    def test_artifact_tampering_and_unhashed_critical_ledger_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder, _, _, _ = self.fixture(Path(d))
            path = folder / 'load/query-outcomes.jsonl'
            original = path.read_text()
            path.write_text(original + '\n')
            with self.assertRaisesRegex(AssertionError, 'artifact changed'):
                M.audit_trial(folder)
            path.write_text(original)
            marker = M.read(folder / 'complete.json')
            del marker['artifacts']['load/query-outcomes.jsonl']
            self.save(folder / 'complete.json', marker)
            with self.assertRaisesRegex(AssertionError, 'critical evidence missing'):
                M.audit_trial(folder)

    def test_missing_read_keeps_censor_and_debt_and_disqualifies_writes(self):
        with tempfile.TemporaryDirectory() as d:
            folder, report, queries, writes = self.fixture(Path(d))
            last = queries[-1]
            last.update(eose_us=None, matches=None)
            report.update(ok=False, completed_reads=3, unanswered_reads=1, protocol_errors=1, errors=['read idle timeout'])
            report['reads'][-1]['scheduled_to_eose'] = histogram(1, 120_250_000)
            report['reads'][-1]['wire_to_eose'] = histogram(1, 120_249_990)
            self.write_trial(folder, report, queries, writes)
            result = M.audit_trial(folder)
            self.assertFalse(result['eligible_for_read_and_write_mixed_load_latency'])
            self.assertEqual(result['read_debt_at_offer_end']['unanswered'], 1)
            self.assertEqual(result['read_outstanding']['unfinished_attempts'], 1)
            self.assertEqual(result['read_latency']['id']['eose']['censored'], 1)
            self.assertEqual(result['read_latency']['id']['eose']['scheduled']['p99_us'], 120_250_000)

    def test_schedule_gap_and_shifted_timing_origin_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder, report, queries, writes = self.fixture(Path(d))
            queries[1]['seq'] = 0
            self.write_trial(folder, report, queries, writes)
            with self.assertRaisesRegex(AssertionError, 'ledger sequence'):
                M.audit_trial(folder)
            queries[1]['seq'] = 1
            report['reads'][0]['scheduled_to_eose'] = histogram(1, 90)
            self.write_trial(folder, report, queries, writes)
            with self.assertRaisesRegex(AssertionError, 'differs from raw timestamps'):
                M.audit_trial(folder)

    def test_false_success_and_changed_socket_caps_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder, report, queries, writes = self.fixture(Path(d))
            report['errors'] = ['connection closed']
            report['protocol_errors'] = 1
            self.write_trial(folder, report, queries, writes)
            with self.assertRaisesRegex(AssertionError, 'false success'):
                M.audit_trial(folder)
            report['errors'] = []
            report['protocol_errors'] = 0
            report['read_connections'] = 3
            self.write_trial(folder, report, queries, writes)
            with self.assertRaisesRegex(AssertionError, 'socket counts changed'):
                M.audit_trial(folder)

    def test_oom_cannot_be_an_eligible_latency_winner(self):
        with tempfile.TemporaryDirectory() as d:
            folder, _, _, _ = self.fixture(Path(d))
            path = folder / 'relay.resources.json'
            meta = M.read(path)
            meta['cgroup_after']['memory.events'] = 'oom 1\noom_kill 0\n'
            self.save(path, meta)
            self.freeze(folder)
            self.assertFalse(M.audit_trial(folder)['eligible_for_read_and_write_mixed_load_latency'])

    def test_inherited_seed_compactions_are_excluded_from_trial_activity(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / 'backend-logs').mkdir()
            path = folder / 'backend-logs/LOG.old'
            rows = [{'event': 'compaction_finished', 'time_micros': 500_000, 'total_output_size': 9000},
                    {'event': 'compaction_finished', 'time_micros': 2_000_000, 'total_output_size': 17},
                    {'event': 'flush_started', 'time_micros': 3_000_000, 'total_data_size': 42}]
            path.write_text(''.join('native prefix EVENT_LOG_v1 ' + json.dumps(r) + '\n' for r in rows))
            result = M.backend_activity(folder, {'backend-logs/LOG.old': M.sha(path)},
                                        '1970-01-01T00:00:01+00:00', '1970-01-01T00:00:04+00:00')
            self.assertEqual(result['event_counts'], {'compaction_finished': 1, 'flush_started': 1})
            self.assertEqual(result['compaction_output_bytes'], 17)
            self.assertEqual(result['flush_input_bytes'], 42)


if __name__ == '__main__':
    unittest.main()
