import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
QUALIFY = ROOT/'scripts/benchmark-qualify.sh'
SETTINGS = dict(RELAY_SSH='root@relay', LOAD_SSH='root@load', RELAY_HOST='10.0.0.2')

MPSTAT = '''Linux 6.12.107 (relay) \t2026-10-26 \t_x86_64_\t(2 CPU)

10:57:01     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
10:57:02     all   98.00    0.00    0.50    0.00    0.00    0.50    1.00    0.00    0.00    0.00
10:57:02       0   99.00    0.00    0.00    0.00    0.00    1.00    0.00    0.00    0.00    0.00
10:57:02       1   97.00    0.00    1.00    0.00    0.00    0.00    2.00    0.00    0.00    0.00

10:57:02     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
10:57:03     all   99.00    0.00    0.00    0.00    0.00    0.00    1.00    0.00    0.00    0.00
10:57:03       0   99.50    0.00    0.00    0.00    0.00    0.00    0.50    0.00    0.00    0.00
10:57:03       1   97.50    0.00    0.00    0.00    0.00    0.00    2.50    0.00    0.00    0.00

Average:     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
Average:     all   98.50    0.00    0.25    0.00    0.00    0.25    1.00    0.00    0.00    0.00
Average:       0   99.25    0.00    0.00    0.00    0.00    0.50    0.25    0.00    0.00    0.00
Average:       1   97.25    0.00    0.50    0.00    0.00    0.00    2.25    0.00    0.00    0.00
'''


def qualify(body, *args, **env):
    """Sources the script without running its main, then runs body."""
    return subprocess.run(
        ['bash', '-c', f'source "$1"; shift; {body}', 'bash', str(QUALIFY), *args],
        capture_output=True, text=True, env={**os.environ, **SETTINGS, **env})


class Settings(unittest.TestCase):
    def test_accepts_complete_settings(self):
        result = qualify('validate_settings')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_incomplete_or_invalid_settings(self):
        cases = {
            'relay ssh': dict(RELAY_SSH=''),
            'load ssh': dict(LOAD_SSH=''),
            'relay host': dict(RELAY_HOST=''),
            'fio seconds': dict(FIO_SECONDS='0'),
            'iperf seconds': dict(IPERF_SECONDS='x'),
            'steal seconds': dict(STEAL_SECONDS='-1'),
            'relative disk dir': dict(DISK_DIR='var/lib/q'),
            'disk dir with ..': dict(DISK_DIR='/var/lib/../q'),
            'baseline without fio output': dict(BASELINE='/nonexistent'),
            'steal limit': dict(STEAL_LIMIT='1%'),
        }
        for case, env in cases.items():
            with self.subTest(case=case):
                result = qualify('validate_settings', **env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('benchmark-qualify:', result.stderr)

    def test_refuses_to_contact_hosts_without_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp)/'calls'
            fake = Path(tmp)/'ssh'
            fake.write_text(f'#!/bin/sh\necho ssh >> "{calls}"\nexit 1\n')
            fake.chmod(0o755)
            env = {**os.environ, **SETTINGS, 'RELAY_SSH': '', 'OUT': f'{tmp}/out',
                   'PATH': f'{tmp}:{os.environ["PATH"]}'}
            result = subprocess.run(['bash', str(QUALIFY)], capture_output=True, text=True,
                                    env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('RELAY_SSH is required', result.stderr)
            self.assertFalse(calls.exists())


class Scratch(unittest.TestCase):
    # The relay host's commands run on this machine.
    LOCAL = 'remote() { shift; bash -c "$1"; }; ssh() { :; }; '

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)/'relay-bench'
        self.parent.mkdir()
        self.unrelated = self.parent/'wok-master/db/data.mdb'
        self.unrelated.parent.mkdir(parents=True)
        self.unrelated.write_text('database')

    def tearDown(self):
        self.tmp.cleanup()

    def test_disk_checks_remove_only_their_own_directory(self):
        result = qualify(self.LOCAL + 'create_scratch; touch "$SCRATCH/fio-file"; '
                         'echo "$SCRATCH"; cleanup', DISK_DIR=f'{self.parent}/')
        self.assertEqual(result.returncode, 0, result.stderr)
        scratch = Path(result.stdout.strip())
        self.assertEqual(scratch.parent, self.parent)
        self.assertTrue(scratch.name.startswith('qualify.'))
        self.assertFalse(scratch.exists())
        self.assertTrue(self.unrelated.exists())

    def test_early_failure_leaves_the_disk_alone(self):
        fail_host_facts = ('remote() { shift; [[ $1 == *"missing tool"* ]] && return 1; '
                           'bash -c "$1"; }; ssh() { :; }; ')
        result = qualify(fail_host_facts + 'main', DISK_DIR=str(self.parent),
                         OUT=f'{self.tmp.name}/out')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sorted(path.name for path in self.parent.iterdir()), ['wok-master'])
        self.assertTrue(self.unrelated.exists())


class Gates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def steal(self, relay, load=MPSTAT, **env):
        (self.out/'mpstat-steal-relay.txt').write_text(relay)
        (self.out/'mpstat-steal-load.txt').write_text(load)
        return qualify('check_steal', OUT=str(self.out), **env)

    def test_steal_within_the_limit_passes(self):
        result = self.steal(MPSTAT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_steal_above_the_limit_fails(self):
        result = self.steal(MPSTAT, STEAL_LIMIT='0.5')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('average steal on the relay host is 1.00%', result.stderr)

    def test_missing_steal_fails(self):
        # What mpstat leaves when it fails: the stress ran, nothing was sampled.
        result = self.steal('', load=MPSTAT)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no %steal in', result.stderr)

    def test_baseline_allows_up_to_twice_either_way(self):
        def fio(directory, p99):
            directory.mkdir(exist_ok=True)
            (directory/'fio-fdatasync.json').write_text(json.dumps(
                {'jobs': [{'sync': {'lat_ns': {'percentile': {'99.000000': p99}}}}]}))
        before = self.out/'before'
        fio(before, 1_000_000)
        for p99, passes in [(2_000_000, True), (500_000, True), (2_000_001, False),
                            (499_999, False)]:
            with self.subTest(p99=p99):
                fio(self.out, p99)
                result = qualify('check_baseline', OUT=str(self.out), BASELINE=str(before))
                self.assertEqual(result.returncode == 0, passes, result.stderr)
                if not passes:
                    self.assertIn('moved by more than 2x', result.stderr)


class Summaries(unittest.TestCase):
    def test_steal_reads_the_steal_column(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt') as mpstat:
            mpstat.write(MPSTAT)
            mpstat.flush()
            result = qualify('steal_summary "$1"', mpstat.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'average 1.00%, worst CPU-second 2.5%')

    def test_fio_and_iperf_lines(self):
        fio = {'jobs': [{'sync': {'lat_ns': {'percentile': {
            '50.000000': 765952, '99.000000': 1417216, '99.900000': 3358720}}}}]}
        iperf = {'end': {'sum_received': {'bits_per_second': 7.434e9},
                         'sum_sent': {'retransmits': 2139}}}
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'fio.json').write_text(json.dumps(fio))
            (Path(tmp)/'iperf.json').write_text(json.dumps(iperf))
            result = qualify(
                'percentile_ms ".jobs[0].sync.lat_ns.percentile" "$1/fio.json"; '
                'iperf_line "$1/iperf.json"', tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            '0.765952 ms p50, 1.417216 ms p99, 3.35872 ms p99.9',
            '7.43 Gbit/s, 2139 retransmits',
        ])

    def test_cpu_stress_lasts_as_long_as_the_sampling(self):
        # openssl speed spends -seconds on each buffer size it tries.
        with tempfile.TemporaryDirectory() as tmp:
            result = qualify('remote() { printf "%s" "$2"; }; steal_check root@load load',
                             OUT=tmp, STEAL_SECONDS='45')
            self.assertEqual(result.returncode, 0, result.stderr)
            sent = (Path(tmp)/'mpstat-steal-load.txt').read_text()
        self.assertIn('-seconds 45 -bytes 16384 sha256', sent)
        self.assertIn('mpstat -P ALL 1 45', sent)

    def test_stopping_iperf3_spares_the_shell_that_stops_it(self):
        # Linux pkill -f matches each process's whole command line, and the
        # remote shell's holds the pattern too: unanchored, it ended that
        # shell and failed the run.
        patterns = re.findall(r"pkill -f '([^']*)'", QUALIFY.read_text())
        self.assertEqual(len(patterns), 2)
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertRegex('iperf3 -s -p 5299 -B 10.0.0.2 -D', pattern)
                self.assertNotRegex(f"bash -c pkill -f '{pattern}' || true", pattern)

if __name__ == '__main__':
    unittest.main()
