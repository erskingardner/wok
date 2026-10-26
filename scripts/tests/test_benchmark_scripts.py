import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT/'scripts/benchmark-relay-control.sh'
CAMPAIGN = ROOT/'scripts/benchmark-campaign.sh'


def bash(script, body, *args, env=None):
    """Sources a script without running its main, then runs body."""
    return subprocess.run(
        ['bash', '-c', f'source "$1"; shift; {body}', 'bash', str(script), *args],
        capture_output=True, text=True, env={**os.environ, **(env or {})})


class RelayTargets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.prefix = Path(self.tmp.name)
        self.targets = self.prefix/'etc/relay-bench/targets'
        self.targets.mkdir(parents=True)
        self.binary = self.prefix/'opt/relay-bench/bin/wok'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text('#!/bin/sh\n')
        self.binary.chmod(0o755)
        self.config = self.prefix/'etc/relay-bench/wok-master.toml'
        self.config.write_text('[database]\n')

    def tearDown(self):
        self.tmp.cleanup()

    def control(self, body, *args):
        return bash(CONTROL, body, *args, env={'RELAY_BENCH_PREFIX': str(self.prefix)})

    def write_target(self, name, text):
        (self.targets/f'{name}.env').write_text(text)

    def valid(self, **overrides):
        keys = dict(KIND='wok', BINARY=str(self.binary), CONFIG=str(self.config), PORT='7777')
        keys.update(overrides)
        return ''.join(f'{key}={value}\n' for key, value in keys.items() if value is not None)

    def test_reads_keys_comments_and_quotes(self):
        self.write_target('wok-0.7.0', f'''# Wok 0.7.0
KIND="wok"
BINARY='{self.binary}'

CONFIG={self.config}
PORT=7777
USER=wokbench
METRICS_URL=http://10.0.0.2:7777/metrics
''')
        result = self.control(
            'load_target wok-0.7.0; printf "%s\\n" "$KIND" "$BINARY" "$PORT" "$SERVICE_USER" '
            '"$METRICS_URL" "$DB_ROOT" "$UNIT"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            'wok', str(self.binary), '7777', 'wokbench', 'http://10.0.0.2:7777/metrics',
            f'{self.prefix}/var/lib/relay-bench/wok-0.7.0',
            'relay-bench-target-wok-0.7.0.service'])

    def test_service_user_defaults(self):
        self.write_target('strfry', self.valid(KIND='strfry'))
        result = self.control('load_target strfry; echo "$KIND $SERVICE_USER"')
        self.assertEqual(result.stdout.strip(), 'strfry relay-bench', result.stderr)

    def test_rejects_invalid_target_files(self):
        cases = {
            'unknown key': self.valid() + 'EXTRA=1\n',
            'not KEY=VALUE': self.valid() + 'export KIND=wok\n',
            'kind': self.valid(KIND='khatru'),
            'relative binary': self.valid(BINARY='bin/wok'),
            'missing binary': self.valid(BINARY=str(self.prefix/'missing')),
            'missing config': self.valid(CONFIG=str(self.prefix/'missing.toml')),
            'port zero': self.valid(PORT='0'),
            'port too large': self.valid(PORT='70000'),
            'no port': self.valid(PORT=None),
            'user': self.valid(USER='Root;rm'),
        }
        for case, text in cases.items():
            with self.subTest(case=case):
                self.write_target('target', text)
                result = self.control('load_target target')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('benchmark-relay-control:', result.stderr)

    def test_rejects_target_names(self):
        for name in ['', 'Wok', '.hidden', '-wok', 'a/b', 'snapshots', 'x' * 64]:
            with self.subTest(name=name):
                result = self.control('validate_target_name "$1"', name)
                self.assertNotEqual(result.returncode, 0)
        for name in ['wok', 'wok-0.7.0', 'strfry-1.1.3', 'wok_master', 'x' * 63]:
            with self.subTest(name=name):
                self.assertEqual(self.control('validate_target_name "$1"', name).returncode, 0)

    def test_run_options(self):
        good = self.control(
            'parse_run_options "cache cpus memory nofile" --cpus 0-7,24-31 --memory 64G '
            '--cache warm --nofile 1024; echo "$RUN_CPUS $RUN_MEMORY $RUN_CACHE $RUN_NOFILE"')
        self.assertEqual(good.stdout.strip(), '0-7,24-31 64G warm 1024', good.stderr)
        defaults = self.control(
            'parse_run_options "cache snapshot"; echo "$RUN_CACHE $SNAPSHOT_POLICY ${RUN_CPUS:-none}"')
        self.assertEqual(defaults.stdout.strip(), 'cold none none')
        for args in [['--snapshot', 'keep'], ['--cpus', '0-'], ['--cpus', 'all'],
                     ['--memory', '64GB'], ['--memory', '0'], ['--cache', 'hot'],
                     ['--nofile', '-1'], ['--cpus']]:
            with self.subTest(args=args):
                result = self.control('parse_run_options "cache cpus memory nofile" "$@"', *args)
                self.assertNotEqual(result.returncode, 0)

    def test_artifact_paths(self):
        opt = f'{self.prefix}/opt/relay-bench'
        for path in [f'{opt}/campaigns/c1/runs/r1', f'{opt}/results/c1']:
            with self.subTest(path=path):
                self.assertEqual(self.control('assert_benchmark_path "$1"', path).returncode, 0)
        for path in [f'{opt}/campaigns/', f'{opt}/campaigns/../../etc', f'{opt}/campaigns/./x',
                     f'{opt}/other/x', '/etc/passwd', f'{opt}/campaigns/c1/..']:
            with self.subTest(path=path):
                self.assertNotEqual(self.control('assert_benchmark_path "$1"', path).returncode, 0)

    def test_cpu_lists_compare_by_members(self):
        for given, expected in [('0-3,8', '0 1 2 3 8'), ('3,1-2', '1 2 3'), ('0,0-1', '0 1'),
                                ('5', '5')]:
            with self.subTest(given=given):
                self.assertEqual(self.control('expand_cpu_list "$1"', given).stdout.strip(), expected)

    def test_snapshot_used_only_for_the_same_identity(self):
        self.write_target('wok', self.valid())
        snapshot = self.prefix/'var/lib/relay-bench/snapshots/wok'
        check = 'load_target wok; snapshot_matches "$1" && echo match || echo stale'
        self.assertEqual(self.control(check, 'kind=wok').stdout.strip(), 'stale')
        (snapshot/'db').mkdir(parents=True)
        (snapshot/'identity').write_text('kind=wok\nevents=10\n')
        (snapshot/'retained').write_text('10\n')
        self.assertEqual(self.control(check, 'kind=wok\nevents=10').stdout.strip(), 'match')
        self.assertEqual(self.control(check, 'kind=wok\nevents=11').stdout.strip(), 'stale')
        (snapshot/'retained').unlink()
        self.assertEqual(self.control(check, 'kind=wok\nevents=10').stdout.strip(), 'stale')


class CampaignSettings(unittest.TestCase):
    REQUIRED = dict(RELAY_SSH='root@relay', LOAD_SSH='root@load', RELAY_HOST='10.0.0.2',
                    TARGETS='strfry-1.1.3 wok-0.7.0 wok-master')

    def campaign(self, body, **env):
        return bash(CAMPAIGN, body, env={**self.REQUIRED, **env})

    def test_rotation_puts_each_target_in_each_position(self):
        orders = [self.campaign(f'rotation {n}').stdout.split() for n in range(1, 5)]
        self.assertEqual(orders, [
            ['strfry-1.1.3', 'wok-0.7.0', 'wok-master'],
            ['wok-0.7.0', 'wok-master', 'strfry-1.1.3'],
            ['wok-master', 'strfry-1.1.3', 'wok-0.7.0'],
            ['strfry-1.1.3', 'wok-0.7.0', 'wok-master'],
        ])
        two = [self.campaign(f'rotation {n}', TARGETS='wok strfry').stdout.split()
               for n in (1, 2)]
        self.assertEqual(two, [['wok', 'strfry'], ['strfry', 'wok']])

    def test_accepts_complete_settings(self):
        result = self.campaign('validate_settings')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_incomplete_or_invalid_settings(self):
        cases = {
            'relay ssh': dict(RELAY_SSH=''),
            'load ssh': dict(LOAD_SSH=''),
            'relay host': dict(RELAY_HOST=''),
            'targets': dict(TARGETS=''),
            'duplicate target': dict(TARGETS='wok strfry wok'),
            'events': dict(EVENTS='0'),
            'repetitions': dict(REPETITIONS='x'),
            'campaign id': dict(CAMPAIGN_ID='../x'),
            'cache': dict(CACHE='hot'),
            'snapshots': dict(SNAPSHOTS='yes'),
        }
        for case, env in cases.items():
            with self.subTest(case=case):
                result = self.campaign('validate_settings', **env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('benchmark-campaign:', result.stderr)

    def test_refuses_to_contact_hosts_without_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp)/'calls'
            for tool in ['ssh', 'scp']:
                fake = Path(tmp)/tool
                fake.write_text(f'#!/bin/sh\necho {tool} >> "{calls}"\nexit 1\n')
                fake.chmod(0o755)
            env = {key: '' for key in self.REQUIRED}
            env['PATH'] = f'{tmp}:{os.environ["PATH"]}'
            result = subprocess.run(['bash', str(CAMPAIGN)], capture_output=True, text=True,
                                    env={**os.environ, **env})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('RELAY_SSH is required', result.stderr)
            self.assertFalse(calls.exists())


if __name__ == '__main__':
    unittest.main()
