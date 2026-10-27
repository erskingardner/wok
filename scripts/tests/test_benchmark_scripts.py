import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT/'scripts/benchmark-relay-control.sh'
CAMPAIGN = ROOT/'scripts/benchmark-campaign.sh'
TRANSPORTS = ROOT/'scripts/benchmark-transports.sh'


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
            'inline comment': self.valid(KIND='wok   # wok or strfry'),
        }
        for case, text in cases.items():
            with self.subTest(case=case):
                self.write_target('target', text)
                result = self.control('load_target target')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('benchmark-relay-control:', result.stderr)

    def documented_examples(self):
        docs = (ROOT/'docs/benchmarks.md').read_text()
        block = re.search(r'Each target is a file on the relay host,.*?```sh\n(.*?)```', docs, re.S)
        header = re.search(r'# Each relay under test.*?\n#\n(.*?)\n#\n', CONTROL.read_text(), re.S)
        lines = [line.removeprefix('#   ') for line in header.group(1).splitlines()]
        return {'docs': block.group(1), 'script header': '\n'.join(lines) + '\n'}

    def test_documented_target_files_parse(self):
        for source, text in self.documented_examples().items():
            with self.subTest(source=source):
                text = re.sub(r'(?m)^BINARY=.*$', f'BINARY={self.binary}', text)
                text = re.sub(r'(?m)^CONFIG=.*$', f'CONFIG={self.config}', text)
                self.write_target('wok-master', text)
                result = self.control(
                    'load_target wok-master; printf "%s\\n" "$KIND" "$PORT" "$METRICS_URL" '
                    '"$SOURCE_CHECKOUT" "$SERVICE_USER"')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [
                    'wok', '7777', 'http://10.0.0.2:7777/metrics',
                    '/opt/relay-bench/src/wok-master', 'relay-bench'])

    def test_database_setting_is_read_from_the_config(self):
        db = f'{self.prefix}/var/lib/relay-bench/wok/db'
        other = f'{self.prefix}/var/lib/relay-bench/other/db'
        wok = {
            'table': (f'[database]\npath = "{db}"\n', True),
            'trailing slash and comment': (f'[ database ]\npath = "{db}/"  # here\n', True),
            'root dotted key': (f"database.path = '{db}'\n", True),
            'socket path in a later table': (
                f'[database]\npath = "{db}"\n\n[relay.unix]\npath = "{db}/../wok.sock"\n', True),
            'expected path only in a comment': (
                f'# path = "{db}"\n[database]\npath = "{other}"\n', False),
            'commented out': (f'[database]\n# path = "{db}"\n', False),
            'path in another table': (f'[relay.unix]\npath = "{db}"\n', False),
            'relative': ('[database]\npath = "./db"\n', False),
        }
        strfry = {
            'top level': (f'db = "{db}/"\nrelay {{\n    port = 7777\n}}\n', True),
            'only in a block': (f'db = "./strfry-db/"\nrelay {{\n    db = "{db}"\n}}\n', False),
            'commented out': (f'# db = "{db}/"\ndb = "{other}/"\n', False),
        }
        for kind, cases in [('wok', wok), ('strfry', strfry)]:
            for case, (config, ok) in cases.items():
                with self.subTest(kind=kind, case=case):
                    self.config.write_text(config)
                    self.write_target('wok', self.valid(KIND=kind))
                    result = self.control('load_target wok; assert_db_config')
                    self.assertEqual(result.returncode == 0, ok, result.stderr)

    def test_memory_sizes_and_effective_cap(self):
        for size, expected in [('64G', 68719476736), ('512M', 536870912), ('1T', 1 << 40),
                               ('2K', 2048), ('4096', 4096)]:
            with self.subTest(size=size):
                self.assertEqual(self.control('memory_bytes "$1"', size).stdout.strip(),
                                 str(expected))
        cgroups = self.prefix/'cgroup'
        unit = cgroups/'relay.slice/relay-bench.slice/relay-bench-target-wok.service'
        unit.mkdir(parents=True)
        (cgroups/'memory.max').write_text('1\n')
        effective = 'effective_memory_max "$1" "$2"'
        self.assertEqual(self.control(effective, unit, cgroups).stdout.strip(), 'max')
        (unit/'memory.max').write_text('68719476736\n')
        (unit.parent/'memory.max').write_text('max\n')
        self.assertEqual(self.control(effective, unit, cgroups).stdout.strip(), '68719476736')
        (unit.parent.parent/'memory.max').write_text('8589934592\n')
        self.assertEqual(self.control(effective, unit, cgroups).stdout.strip(), '8589934592')

    def test_warm_needs_every_database_page_cached(self):
        listing = self.prefix/'residency'
        db = '/var/lib/relay-bench/wok/db'
        cases = {
            # Whole pages reach past an unaligned size.
            'all cached': (f'{db}/data.mdb 8089600 8089600\n{db}/lock.mdb 16576 20480\n', ''),
            'one page missing': (f'{db}/data.mdb 8089600 8085504\n{db}/lock.mdb 16576 20480\n',
                                 f'{db}/data.mdb'),
            'unaligned tail missing': (f'{db}/data.mdb 8089600 8089600\n{db}/lock.mdb 16576 16384\n',
                                       f'{db}/lock.mdb'),
        }
        for case, (text, expected) in cases.items():
            with self.subTest(case=case):
                listing.write_text(text)
                result = self.control('uncached_database_files "$1"', listing)
                self.assertEqual(result.stdout.strip(), expected, result.stderr)

    def test_import_and_export_run_under_the_requested_file_limit(self):
        self.write_target('strfry-1.1.3', self.valid(KIND='strfry'))
        calls = self.prefix/'calls'
        result = self.control(
            f'systemd-run() {{ printf "%s\\n" "$*" >>"{calls}"; }}; systemctl() {{ :; }}; '
            'load_target strfry-1.1.3; parse_run_options nofile --nofile 1048576; '
            'mkdir -p "$DB_ROOT/db"; echo x >"$DB_ROOT/db/data.mdb"; '
            'import_corpus /dev/null "$1"; count_retained', str(self.prefix))
        self.assertEqual(result.returncode, 0, result.stderr)
        units = calls.read_text().splitlines()
        self.assertEqual(len(units), 2, units)
        self.assertIn('--unit=relay-bench-import-strfry-1.1.3.service', units[0])
        self.assertIn('--unit=relay-bench-export-strfry-1.1.3.service', units[1])
        for unit in units:
            self.assertIn('-p LimitNOFILE=1048576', unit)

    def test_reconcile_exports_once_and_reconciles_every_step(self):
        self.write_target('wok', self.valid())
        (self.prefix/'var/lib/relay-bench/wok').mkdir(parents=True)
        steps = self.prefix/'opt/relay-bench/campaigns/c1/runs/r1-wok/rate'
        for rate in ['1000', '2000']:
            (steps/f'rate-{rate}').mkdir(parents=True)
            (steps/f'rate-{rate}/outcomes.jsonl').write_text(f'{rate}\n')
        # Called as: --reconcile LOG --relay-export EXPORT --out DIR. The
        # 2000 step lost a write.
        bench = self.prefix/'opt/relay-bench/bin/wok-bench'
        bench.write_text('#!/bin/sh\n'
                         'cat "$4" >"$6/export-seen"\n'
                         'echo "{}" >"$6/reconciliation.json"\n'
                         'grep -q 2000 "$2" && exit 1\n'
                         'exit 0\n')
        bench.chmod(0o755)
        calls = self.prefix/'calls'
        reconcile = (f'systemd-run() {{ printf "%s\\n" "$*" >>"{calls}"; echo exported; }}; '
                     'reconcile_steps wok "$1" "$2" --nofile 1024')
        result = self.control('systemctl() { echo inactive; }; ' + reconcile,
                              str(bench), str(steps))
        self.assertNotEqual(result.returncode, 0)
        exports = calls.read_text().splitlines()
        self.assertEqual(len(exports), 1, exports)
        self.assertIn('--unit=relay-bench-export-wok.service', exports[0])
        self.assertIn('-p LimitNOFILE=1024', exports[0])
        for rate in ['1000', '2000']:
            self.assertEqual((steps/f'rate-{rate}/export-seen').read_text(), 'exported\n')
            self.assertTrue((steps/f'rate-{rate}/reconciliation.json').exists())
        self.assertFalse((self.prefix/'var/lib/relay-bench/wok/reconcile-export.jsonl').exists())

        (steps/'rate-2000/outcomes.jsonl').write_text('kept\n')
        result = self.control('systemctl() { echo inactive; }; ' + reconcile,
                              str(bench), str(steps))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.control('systemctl() { echo active; }; ' + reconcile,
                              str(bench), str(steps))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('stop wok before reconciling', result.stderr)

    def test_io_marks_keep_metrics_that_give_each_phases_writer_batches(self):
        self.write_target('wok', self.valid(METRICS_URL='http://127.0.0.1:9784/metrics'))
        artifacts = self.prefix/'opt/relay-bench/campaigns/c1/runs/r1-wok/server'
        artifacts.mkdir(parents=True)
        (artifacts/'main.pid').write_text('4242\n')
        io = self.prefix/'proc/4242/io'
        io.parent.mkdir(parents=True)
        io.write_text('read_bytes: 0\nwrite_bytes: 0\n')
        scrape = self.prefix/'metrics.prom'

        def mark(label, commits, events, commit_seconds, stored_bytes):
            if commits is None:
                scrape.unlink(missing_ok=True)
            else:
                scrape.write_text(
                    '# HELP wok_writer_commit_events Events each writer commit stored\n'
                    f'wok_writer_commit_events_bucket{{le="+Inf"}} {commits}\n'
                    f'wok_writer_commit_events_sum {events}\n'
                    f'wok_writer_commit_events_count {commits}\n'
                    f'wok_writer_queue_depth_sum {2 * events}\n'
                    f'wok_writer_queue_depth_count {commits}\n'
                    f'wok_writer_commit_seconds_sum {commit_seconds}\n'
                    f'wok_writer_commit_seconds_count {commits}\n'
                    f'wok_writer_storage_bytes_total {stored_bytes}\n'
                    'wok_connections 3\n')
            # A scrape that fails leaves no snapshot, like curl --fail.
            return self.control(f'curl() {{ cat "{scrape}"; }}; io_mark wok "$1" "$2"',
                                str(artifacts), label)

        for label, *metrics in [('query-start', 10, 100, 0.5, 1000),
                                ('query-end', 10, 100, 0.5, 1000),
                                ('rate-1000-start', 10, 100, 0.5, 1000),
                                ('rate-1000-end', 30, 2100, 1.5, 401000),
                                ('rate-2000-start', None, 0, 0, 0),
                                ('rate-2000-end', 40, 4100, 2.0, 801000)]:
            result = mark(label, *metrics)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((artifacts/'metrics-marks/rate-2000-start.prom').exists())

        result = self.control('writer_phases "$1"', str(artifacts))
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split('\t') for line in
                (artifacts/'writer-phases.tsv').read_text().splitlines()]
        self.assertEqual(rows[0], ['phase', 'commits', 'events', 'events_per_commit',
                                   'queue_depth', 'prepare_ms', 'write_ms', 'commit_ms',
                                   'reply_ms', 'storage_bytes_per_event'])
        # No commits, no means. A phase missing a snapshot is left out.
        self.assertEqual(rows[1:], [
            ['query', '0', '0', '', '', '', '', '', '', ''],
            ['rate-1000', '20', '2000', '100.00', '200.00', '0.00', '0.00', '50.00',
             '0.00', '200'],
        ])

        # Without METRICS_URL, as for strfry, marks keep no snapshots and the
        # summary is its header.
        self.write_target('wok', self.valid())
        result = self.control('rm -r "$1/metrics-marks"; io_mark wok "$1" query-start'
                              ' && io_mark wok "$1" query-end && writer_phases "$1"',
                              str(artifacts))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((artifacts/'metrics-marks').exists())
        self.assertEqual(len((artifacts/'writer-phases.tsv').read_text().splitlines()), 1)

    def test_io_marks_bracket_phases_in_the_relays_io(self):
        self.write_target('wok', self.valid())
        artifacts = self.prefix/'opt/relay-bench/campaigns/c1/runs/r1-wok/server'
        artifacts.mkdir(parents=True)
        (artifacts/'main.pid').write_text('4242\n')
        io = self.prefix/'proc/4242/io'
        io.parent.mkdir(parents=True)

        def mark(label, read, written):
            io.write_text(f'rchar: 1\nwchar: 2\nread_bytes: {read}\nwrite_bytes: {written}\n'
                          'cancelled_write_bytes: 0\n')
            return self.control('io_mark wok "$1" "$2"', str(artifacts), label)

        for label, read, written in [('query-start', 100, 1000), ('query-end', 900, 1500),
                                     ('rate-1000-start', 900, 1500),
                                     ('rate-1000-end', 950, 801500),
                                     ('rate-2000-start', 950, 801500)]:
            result = mark(label, read, written)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(mark('bad label', 0, 0).returncode, 0)
        marks = (artifacts/'io-marks.tsv').read_text().splitlines()
        self.assertEqual([line.split('\t')[0] for line in marks],
                         ['query-start', 'query-end', 'rate-1000-start', 'rate-1000-end',
                          'rate-2000-start'])

        result = self.control('io_phases "$1"', str(artifacts))
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split('\t') for line in
                (artifacts/'io-phases.tsv').read_text().splitlines()]
        self.assertEqual(rows[0], ['phase', 'secs', 'read_bytes', 'write_bytes'])
        # A phase without its end mark (the relay died) is left out.
        self.assertEqual([(row[0], row[2], row[3]) for row in rows[1:]],
                         [('query', '800', '500'), ('rate-1000', '50', '800000')])

        # A phase started again without an end loses its earlier interval.
        self.assertEqual(mark('query-start', 2000, 2000).returncode, 0)
        result = self.control('io_phases "$1"', str(artifacts))
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = (artifacts/'io-phases.tsv').read_text().splitlines()
        self.assertEqual([row.split('\t')[0] for row in rows[1:]], ['rate-1000'])

        # With no marks, the summary is only its header, replacing any copy
        # an earlier run left.
        (artifacts/'io-marks.tsv').unlink()
        result = self.control('io_phases "$1"', str(artifacts))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((artifacts/'io-phases.tsv').read_text(),
                         'phase\tsecs\tread_bytes\twrite_bytes\n')

        (artifacts/'main.pid').unlink()
        result = mark('lifecycle-start', 0, 0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no recorded main PID', result.stderr)

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
        result = self.campaign('validate_settings', CORPUS_MIX='social',
                               RATE_STEPS='1000 2000  5000')
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(
        Path('/bin/bash').exists() and subprocess.run(
            ['/bin/bash', '-c', 'echo ${BASH_VERSINFO[0]}'],
            capture_output=True, text=True).stdout.strip() == '3',
        'needs Bash 3.2 at /bin/bash, as on macOS')
    def test_settings_validate_under_bash_3_without_rate_steps(self):
        # The operator host may be a Mac, whose system Bash is 3.2.
        env = {**os.environ, **self.REQUIRED}
        env.pop('RATE_STEPS', None)
        result = subprocess.run(
            ['/bin/bash', '-c', 'source "$1"; validate_settings', 'bash', str(CAMPAIGN)],
            capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)

    # Commands sent to either host run here instead.
    LOCAL_HOSTS = 'remote_command() { shift; "$@"; }; '

    def write_rate_results(self, load, rate, **changes):
        trial = dict(ok=True, errors=0, mismatches=0, latency_p99_ms=40.0,
                     publish_rate=dict(unsent=0, no_reply=0, refused={}))
        for key, value in changes.items():
            if key in ('unsent', 'no_reply', 'refused'):
                trial['publish_rate'][key] = value
            else:
                trial[key] = value
        phase = load/f'rate-{rate}'
        phase.mkdir(parents=True, exist_ok=True)
        (phase/'results.jsonl').write_text(json.dumps(trial) + '\n')

    def rate_sweep(self, root, steps='1000 2000 4000 8000'):
        return self.campaign(
            self.LOCAL_HOSTS + f'launch_bench() {{ echo "$4 $5" >>"{root}/launched"; }}; '
            f'LOAD_ROOT={root}; rate_sweep wok 1 ws://10.0.0.2:7777; '
            'echo "${RATE_LAUNCHED[*]}"', RATE_STEPS=steps)

    def test_rate_sweep_stops_at_the_first_missed_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            load = root/'runs/r1-wok/load'
            self.write_rate_results(load, 1000)
            self.write_rate_results(load, 2000)
            self.write_rate_results(load, 4000, latency_p99_ms=250.5)
            self.write_rate_results(load, 8000)
            result = self.rate_sweep(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Each step signs its events from its own seed.
            self.assertEqual((root/'launched').read_text().splitlines(),
                             ['rate-1000 4243', 'rate-2000 4244', 'rate-4000 4245'])
            self.assertEqual(result.stdout.strip(), '1000 2000 4000')
            self.assertEqual((load/'rate-capacity.txt').read_text(),
                             'capacity=2000\nfirst_missed=4000\n')

    def test_rate_step_misses_unless_the_relay_kept_up(self):
        misses = {
            'rate not held': dict(ok=False),
            'connection failed': dict(errors=1),
            'refused': dict(refused={'rate-limited': 3}),
            'unanswered': dict(no_reply=1),
            'never sent': dict(unsent=5),
        }
        for case, changes in misses.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                load = root/'runs/r1-wok/load'
                self.write_rate_results(load, 1000)
                self.write_rate_results(load, 2000, **changes)
                result = self.rate_sweep(root, steps='1000 2000')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((load/'rate-capacity.txt').read_text(),
                                 'capacity=1000\nfirst_missed=2000\n')

    def test_rate_sweep_fails_without_a_report_or_on_a_misrouted_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            load = root/'runs/r1-wok/load'
            self.write_rate_results(load, 1000)
            self.write_rate_results(load, 2000, ok=False, mismatches=1)
            # A trial that failed before its outcome log was complete has no
            # fixed-rate report: no evidence, not a capacity.
            self.write_rate_results(load, 3000, ok=False, errors=1, publish_rate=None)
            for steps in ['1000 2000', '1000 3000', '1000 5000']:
                with self.subTest(steps=steps):
                    result = self.rate_sweep(root, steps=steps)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('left no fixed-rate report', result.stderr)
            self.assertFalse((load/'rate-capacity.txt').exists())

    def reconcile(self, root, launched, log_lines, fail_copy=''):
        """Runs reconcile_rate_steps for repetition 2 of target wok, with
        the steps in launched started and each step's outcome log holding
        log_lines[rate] of its 10 planned events (none when absent). Copying
        step fail_copy's log to the relay host fails."""
        load = root/'l/runs/r2-wok/load'
        for rate in launched:
            self.write_rate_results(load, rate)
            trial = json.loads((load/f'rate-{rate}/results.jsonl').read_text())
            trial['publish_rate']['events'] = 10
            (load/f'rate-{rate}/results.jsonl').write_text(json.dumps(trial) + '\n')
            if rate in log_lines:
                (load/f'rate-{rate}/outcomes-wok-r2-r1.jsonl').write_text('{}\n' * log_lines[rate])
        calls = root/'calls'
        # The control helper's reconcile counts each copied log's events, as
        # wok-bench --reconcile does.
        body = ('remote_command() { shift; if [[ $1 == "$CONTROL_REMOTE" ]]; then '
                f'echo "control ${{*:2}}" >>"{calls}"; local d; '
                'for d in "$5"/rate-*; do '
                'echo "{\\"events\\":$(wc -l <"$d/outcomes.jsonl")}" >"$d/reconciliation.json"; '
                'done; else "$@"; fi; }; '
                'scp() { local from=${*: -2:1} to=${*: -1}; '
                f'[[ $from == *"/rate-{fail_copy}/outcomes"* ]] && return 1; '
                f'echo "scp $from $to" >>"{calls}"; cp "${{from#*:}}" "${{to#*:}}"; }}; '
                f'LOAD_ROOT={root}/l RELAY_ROOT={root}/r; '
                f'RATE_LAUNCHED=({" ".join(map(str, launched))}); reconcile_rate_steps wok 2')
        result = self.campaign(body, RATE_STEPS='1000 2000 4000')
        sent = calls.read_text().splitlines() if calls.exists() else []
        return result, sent, load, f'{root}/r/runs/r2-wok/rate'

    def test_reconciles_the_steps_that_ran_after_the_relay_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, sent, load, relay = self.reconcile(
                Path(tmp), [1000, 2000], {1000: 10, 2000: 10})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sent, [
                f'scp root@load:{load}/rate-1000/outcomes-wok-r2-r1.jsonl '
                f'root@relay:{relay}/rate-1000/outcomes.jsonl',
                f'scp root@load:{load}/rate-2000/outcomes-wok-r2-r1.jsonl '
                f'root@relay:{relay}/rate-2000/outcomes.jsonl',
                f'control reconcile wok /opt/relay-bench/bin/wok-bench/wok-bench {relay} '
                '--nofile 524288',
                f'scp root@relay:{relay}/rate-1000/reconciliation.json '
                f'root@load:{load}/rate-1000/reconciliation.json',
                f'scp root@relay:{relay}/rate-2000/reconciliation.json '
                f'root@load:{load}/rate-2000/reconciliation.json',
            ])
        with tempfile.TemporaryDirectory() as tmp:
            result, sent, _, _ = self.reconcile(Path(tmp), [], {})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sent, [])

    def test_reconciliation_fails_without_every_started_steps_whole_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The 2000 step ran but wrote no log; the 1000 step is still
            # reconciled.
            result, sent, load, _ = self.reconcile(Path(tmp), [1000, 2000], {1000: 10})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('step 2000 ran but its outcome log', result.stderr)
            self.assertTrue((load/'rate-1000/reconciliation.json').exists())
            self.assertTrue(any(line.startswith('control reconcile') for line in sent))
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _, _ = self.reconcile(Path(tmp), [1000, 2000], {1000: 10, 2000: 6})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('step 2000: the outcome log does not hold every planned event',
                          result.stderr)

    def test_reconciliation_uses_only_this_runs_copied_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Logs left on the relay host by an earlier run with this
            # campaign ID, one for a step this run never reached.
            stale = root/'r/runs/r2-wok/rate'
            for rate in [2000, 4000]:
                (stale/f'rate-{rate}').mkdir(parents=True)
                (stale/f'rate-{rate}/outcomes.jsonl').write_text('{}\n' * 10)
            result, sent, load, relay = self.reconcile(
                root, [1000, 2000], {1000: 10, 2000: 10}, fail_copy='2000')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('step 2000: could not copy its outcome log', result.stderr)
            self.assertEqual(sorted(path.name for path in stale.iterdir()), ['rate-1000'])
            self.assertTrue((load/'rate-1000/reconciliation.json').exists())
            self.assertFalse((load/'rate-2000/reconciliation.json').exists())
            self.assertTrue(any(line.startswith('control reconcile') for line in sent))

    def test_campaign_reads_its_corpus_mix_and_expects_the_retained_count(self):
        reads = ['query', 'deep-history', 'mixed-read-write']
        for mix in ['realistic', 'social']:
            with self.subTest(mix=mix), tempfile.TemporaryDirectory() as tmp:
                calls = Path(tmp)/'calls'
                result = self.campaign(
                    f'remote_command() {{ printf "%s\\n" "$*" >>"{calls}"; echo 7777; }}; '
                    f'run_bench() {{ echo "phase $4 ${{*: -2:1}} ${{*: -1}}" >>"{calls}"; }}; '
                    f'rate_sweep() {{ echo sweep >>"{calls}"; }}; '
                    f'reconcile_rate_steps() {{ echo reconcile >>"{calls}"; }}; scp() {{ :; }}; '
                    'LOAD_ROOT=/l RELAY_ROOT=/r RELAY_CORPUS=/r/c LOAD_CORPUS=/l/c CAP_ARGS=() '
                    'RETAINED=933179; run_target wok-master 1',
                    CORPUS_MIX=mix, RATE_STEPS='1000')
                self.assertEqual(result.returncode, 0, result.stderr)
                sent = calls.read_text().splitlines()
                phases = [line.split()[1:] for line in sent if line.startswith('phase ')]
                self.assertEqual([phase[0] for phase in phases], reads + ['load', 'lifecycle'])
                for phase in phases[:3]:
                    self.assertEqual(phase[1:], ['--event-mix', mix])
                prepare = next(i for i, line in enumerate(sent) if ' prepare ' in line)
                self.assertIn(' /r/c 933179 ', sent[prepare])
                stop = next(i for i, line in enumerate(sent) if ' collect-stop ' in line)
                self.assertLess(prepare, sent.index('sweep'))
                self.assertLess(sent.index('sweep'), stop)
                self.assertLess(stop, sent.index('reconcile'))

    def test_retained_count_comes_from_the_social_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = self.LOCAL_HOSTS + f'LOAD_CORPUS_DIR={tmp}; retained_events'
            self.assertEqual(self.campaign(body, EVENTS='1000').stdout.strip(), '1000')
            social = self.campaign(body, EVENTS='1000', CORPUS_MIX='social')
            self.assertNotEqual(social.returncode, 0)
            self.assertIn('no retained count', social.stderr)
            Path(tmp, 'manifest.json').write_text(
                json.dumps({'corpus': {'social': {'retained': 933}}}))
            social = self.campaign(body, EVENTS='1000', CORPUS_MIX='social')
            self.assertEqual(social.stdout.strip(), '933', social.stderr)

    def test_generator_runs_as_a_named_unit_that_cleanup_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp)/'calls'
            fake_ssh = (f'ssh() {{ printf "%s\\n---\\n" "$*" >>"{calls}"; }}; '
                        'LOAD_ROOT=/opt/wok-load/results/c1 '
                        'RELAY_ROOT=/opt/relay-bench/campaigns/c1; ')
            for cpus, pinned in [('', False), ('16-47', True)]:
                with self.subTest(load_cpus=cpus):
                    calls.unlink(missing_ok=True)
                    result = self.campaign(
                        fake_ssh + 'run_bench wok-master 1 ws://10.0.0.2:7777 query '
                        '--scenario ws_query_latency; cleanup',
                        CAMPAIGN_ID='c1', LOAD_CPUS=cpus)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    sent = calls.read_text().split('\n---\n')
                    bench = next(command for command in sent if 'ws_query_latency' in command)
                    self.assertIn('systemd-run --quiet --wait --pipe --collect '
                                  '--unit=relay-bench-load-c1 -p LimitNOFILE=524288', bench)
                    self.assertIn('--unit=relay-bench-load-c1-mpstat', bench)
                    self.assertIn('systemctl stop relay-bench-load-c1-mpstat.service', bench)
                    self.assertEqual('AllowedCPUs=16-47' in bench, pinned)
                    stop = "root@load systemctl stop 'relay-bench-load-*.service'"
                    self.assertTrue(any(stop in command for command in sent), sent)

    def test_phases_mark_the_relays_io_and_keep_their_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp)/'calls'
            for bench_status in [0, 3]:
                with self.subTest(bench_status=bench_status):
                    calls.unlink(missing_ok=True)
                    result = self.campaign(
                        f'remote_command() {{ printf "%s\\n" "$*" >>"{calls}"; }}; '
                        f'ssh() {{ echo bench >>"{calls}"; return {bench_status}; }}; '
                        'LOAD_ROOT=/l RELAY_ROOT=/r; '
                        'status=0; launch_bench wok 2 ws://10.0.0.2:7777 rate-1000 7 '
                        '--scenario x || status=$?; '
                        'echo "status=$status phases=${PHASES_LAUNCHED[*]}"',
                        CAMPAIGN_ID='c1')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f'status={bench_status} phases=rate-1000', result.stdout)
                    sent = calls.read_text().splitlines()
                    marks = [i for i, line in enumerate(sent) if ' io-mark ' in line]
                    bench = sent.index('bench')
                    self.assertEqual(len(marks), 2, sent)
                    self.assertLess(marks[0], bench)
                    self.assertGreater(marks[1], bench)
                    self.assertTrue(sent[marks[0]].endswith(
                        'io-mark wok /r/runs/r2-wok/server rate-1000-start'), sent)
                    self.assertTrue(sent[marks[1]].endswith(
                        'io-mark wok /r/runs/r2-wok/server rate-1000-end'), sent)

    def test_a_rerun_starts_each_phase_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            phase = root/'runs/r1-wok/load/rate-1000'
            phase.mkdir(parents=True)
            (phase/'relay-io.json').write_text('{"phase": "rate-1000"}\n')
            (phase/'results.jsonl').write_text('{}\n')
            result = self.campaign(
                'remote_command() { [[ $1 == "$LOAD_SSH" ]] || return 0; shift; "$@"; }; '
                f'ssh() {{ :; }}; LOAD_ROOT={root} RELAY_ROOT=/r; '
                'launch_bench wok 1 ws://10.0.0.2:7777 rate-1000 7 --scenario x',
                CAMPAIGN_ID='c1')
            self.assertEqual(result.returncode, 0, result.stderr)
            # The bench (faked) wrote nothing, so nothing is left to read.
            self.assertTrue(phase.is_dir())
            self.assertEqual(list(phase.iterdir()), [])

    def test_phase_io_gives_bytes_per_stored_event_for_rate_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root/'runs/r1-wok'
            (run/'server').mkdir(parents=True)
            (run/'server/io-phases.tsv').write_text(
                'phase\tsecs\tread_bytes\twrite_bytes\n'
                'query\t12.5\t800\t500\n'
                'rate-1000\t190.0\t50\t800000\n')
            for phase, results in [
                    ('query', {'ok': True}),
                    ('rate-1000', {'publish_rate': {'accepted': 1000, 'duplicates': 200}}),
                    ('lifecycle', {'ok': True})]:
                (run/f'load/{phase}').mkdir(parents=True)
                (run/f'load/{phase}/results.jsonl').write_text(json.dumps(results) + '\n')
            result = self.campaign(
                'remote_command() { shift; "$@"; }; '
                f'LOAD_ROOT={root}; PHASES_LAUNCHED=(query rate-1000 lifecycle); '
                'phase_io wok 1')
            self.assertEqual(result.returncode, 0, result.stderr)
            query = json.loads((run/'load/query/relay-io.json').read_text())
            self.assertEqual(query, {'phase': 'query', 'secs': 12.5, 'read_bytes': 800,
                                     'write_bytes': 500})
            rate = json.loads((run/'load/rate-1000/relay-io.json').read_text())
            self.assertEqual(rate['stored_events'], 800)
            self.assertEqual(rate['write_bytes_per_stored_event'], 1000)
            # No marks for lifecycle (the relay died): no summary, no file.
            self.assertFalse((run/'load/lifecycle/relay-io.json').exists())
            self.assertFalse((run/'load/lifecycle/relay-io.json.tmp').exists())

    def test_file_limit_reaches_import_and_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp)/'calls'
            result = self.campaign(
                f'remote_command() {{ printf "%s\\n" "$*" >>"{calls}"; echo 7777; }}; '
                'run_bench() { return 1; }; scp() { :; }; '
                'LOAD_ROOT=/l RELAY_ROOT=/r RELAY_CORPUS=/r/c LOAD_CORPUS=/l/c CAP_ARGS=() '
                'RETAINED=10; run_target strfry-1.1.3 1 || true', NOFILE_LIMIT='1048576')
            self.assertEqual(result.returncode, 0, result.stderr)
            sent = calls.read_text().splitlines()
            for command in ['prepare', 'start']:
                line = next(line for line in sent if f'control {command} ' in line)
                self.assertIn('--nofile 1048576', line)
            # An earlier run's I/O summary is gone before this run starts.
            clear = sent.index('root@load rm -f -- /l/runs/r1-strfry-1.1.3/server/io-phases.tsv'
                               ' /l/runs/r1-strfry-1.1.3/server/writer-phases.tsv')
            self.assertLess(clear, next(i for i, line in enumerate(sent)
                                        if 'control start ' in line))

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
            'corpus mix': dict(CORPUS_MIX='kind1'),
            'social authors': dict(SOCIAL_AUTHORS='0'),
            'rate step': dict(RATE_STEPS='1000 2k'),
            'rate steps fall': dict(RATE_STEPS='2000 1000'),
            'rate steps repeat': dict(RATE_STEPS='1000 1000'),
            'rate seconds': dict(RATE_SECS='0'),
            'rate drain': dict(RATE_DRAIN_SECS='x'),
            'rate connections': dict(RATE_CONNECTIONS='-1'),
            'rate p99': dict(RATE_P99_MS='2.5'),
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


class TransportSettings(unittest.TestCase):
    def test_refuses_to_contact_hosts_without_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp)/'calls'
            for tool in ['ssh', 'scp']:
                fake = Path(tmp)/tool
                fake.write_text(f'#!/bin/sh\necho {tool} >> "{calls}"\nexit 1\n')
                fake.chmod(0o755)
            env = {**os.environ, 'RELAY_SSH': 'root@relay', 'LOAD_SSH': 'root@load',
                   'WS_URL': '', 'PATH': f'{tmp}:{os.environ["PATH"]}'}
            result = subprocess.run(['bash', str(TRANSPORTS)], capture_output=True, text=True,
                                    env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('WS_URL is required', result.stderr)
            self.assertFalse(calls.exists())


if __name__ == '__main__':
    unittest.main()
