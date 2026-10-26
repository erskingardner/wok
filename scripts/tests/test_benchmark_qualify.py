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
            'disk dir at the root': dict(DISK_DIR='/q'),
            'disk dir with ..': dict(DISK_DIR='/var/lib/../q'),
            'baseline without fio output': dict(BASELINE='/nonexistent'),
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

    def test_stopping_iperf3_spares_the_shell_that_stops_it(self):
        # Linux pkill -f matches each process's whole command line, and the
        # remote shell's holds the pattern too: unanchored, it ended that
        # shell and failed the run.
        patterns = re.findall(r"pkill -f '([^']*)'", QUALIFY.read_text())
        self.assertEqual(len(patterns), 2)
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertRegex('iperf3 -s -p 5299 -D', pattern)
                self.assertNotRegex(f"bash -c pkill -f '{pattern}' || true", pattern)

if __name__ == '__main__':
    unittest.main()
