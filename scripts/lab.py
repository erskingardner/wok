#!/usr/bin/env python3
"""Disposable local or two-VM Wok campaigns; preserve evidence and named volumes."""
import argparse
import hashlib
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FILES = ['-f', 'contrib/lab/relay.compose.yml', '-f', 'contrib/lab/load.compose.yml']
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3']


class Host:
    def __init__(self, ssh, cwd, env, project):
        if ssh and (ssh.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.@-]+', ssh)):
            raise ValueError('SSH destination must be user@hostname or an SSH config alias')
        self.ssh, self.cwd, self.env, self.project = ssh, str(cwd), env, project

    def command(self, args):
        if self.ssh:
            # Relative remote staging path is resolved by the login shell.
            return SSH + [self.ssh, 'cd ' + shlex.quote(self.cwd) + ' && ' +
                          shlex.join(['env'] + [f'{k}={v}' for k, v in self.env.items()] + list(args))]
        return list(args)

    def run(self, args, *, check=True, timeout=120, **kwargs):
        return subprocess.run(self.command(args), cwd=ROOT, env={**os.environ, **self.env},
                              check=check, timeout=timeout, **kwargs)

    def compose(self, *args, **kwargs):
        return self.run(['docker', 'compose', '-p', self.project] + FILES + list(args), **kwargs)

    def save(self, path, args, *, check=False):
        with path.open('w') as log:
            return self.run(args, stdout=log, stderr=subprocess.STDOUT, check=check)

    def copy(self, container, out):
        out.mkdir()
        if not self.ssh:
            self.run(['docker', 'cp', container + ':/results/.', str(out)])
        else:
            # Docker emits its own archive; no remote path interpolation or scp needed.
            with tempfile.TemporaryFile() as archive:
                self.run(['docker', 'cp', container + ':/results/.', '-'], stdout=archive)
                archive.seek(0)
                extract_results(archive, out)


def extract_results(archive, out):
    # Validate the entire untrusted archive before extracting any member.
    import tarfile
    with tarfile.open(fileobj=archive) as tar:
        for member in tar.getmembers():
            p = Path(member.name)
            if p.is_absolute() or '..' in p.parts or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe result archive member')
        tar.extractall(out, filter='data')


def stage(host, archive):
    command = 'mkdir -p wok-lab && mkdir ' + shlex.quote(host.cwd) + ' && tar -xf - -C ' + shlex.quote(host.cwd)
    with archive.open('rb') as stream:
        subprocess.run(SSH + [host.ssh, command], stdin=stream, check=True, timeout=120)


def sample(hosts, output, stopped):
    with output.open('w') as log:
        while not stopped.is_set():
            for role, host, container in hosts:
                try:
                    result = host.run(['docker', 'stats', '--no-stream', '--format', '{{json .}}', container],
                                      capture_output=True, text=True, check=True, timeout=20)
                    row = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           'role': role, 'stats': json.loads(result.stdout)}
                except Exception as error:
                    row = {'role': role, 'error': str(error)}
                log.write(json.dumps(row) + '\n')
                log.flush()
            stopped.wait(5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['local', 'remote'])
    parser.add_argument('--relay-ssh')
    parser.add_argument('--load-ssh')
    parser.add_argument('--relay-bind', default='127.0.0.1', help='Host interface on which Docker publishes port 7777')
    parser.add_argument('--target-url', help='Relay WebSocket address reachable from the load VM')
    parser.add_argument('--run-id', default=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S').lower()+'-'+uuid.uuid4().hex[:6])
    parser.add_argument('--bootstrap-debian', action='store_true', help='Explicitly install Docker on clean Debian 12/13 hosts via root SSH')
    parser.add_argument('--skip-build', action='store_true', help='Use existing wok-lab:local image for local development')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', args.run_id):
        parser.error('run-id must be 1-56 lowercase letters, digits or hyphens')
    remote = args.mode == 'remote'
    if remote and sys.version_info < (3, 12):
        parser.error('remote artifact extraction requires operator Python 3.12+')
    if remote and (not args.relay_ssh or not args.load_ssh or not args.target_url or args.relay_bind == '127.0.0.1'):
        parser.error('remote requires --relay-ssh, --load-ssh, --target-url and --relay-bind (use an isolated private interface)')
    if remote and (args.relay_ssh == args.load_ssh or args.skip_build):
        parser.error('remote requires distinct hosts and builds the supplied source on each')
    if not remote and (args.relay_ssh or args.load_ssh or args.bootstrap_debian):
        parser.error('SSH and bootstrap options require remote mode')
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if remote and status:
        parser.error('remote deploy requires a clean committed checkout so both hosts receive identical source')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    project = 'wok-lab-' + args.run_id
    out = ROOT/'bench-results/lab'/args.run_id
    out.mkdir(parents=True, exist_ok=False)
    knobs = ['EVENTS', 'PUBLISHERS', 'SUBSCRIBERS', 'FANOUT_EVENTS', 'CONNECTIONS', 'HOLD_SECONDS',
             'ROUNDS', 'SEED', 'BASE_TIMESTAMP', 'DEADLINE_SECONDS', 'RELAY_PORT',
             'RELAY_CPUS', 'RELAY_MEMORY', 'LOAD_CPUS', 'LOAD_MEMORY']
    env = {'LAB_'+k: os.environ['LAB_'+k] for k in knobs if 'LAB_'+k in os.environ}
    env.update(LAB_IMAGE_TAG='local' if args.skip_build else args.run_id,
               LAB_SOURCE_REVISION=revision + ('-dirty' if status else ''), LAB_RELAY_BIND=args.relay_bind,
               LAB_TARGET=args.target_url or 'ws://relay:7777')
    # One timestamp for every round, recorded even when the two hosts have clock skew.
    env.setdefault('LAB_BASE_TIMESTAMP', str(int(time.time())))
    cwd = 'wok-lab/' + args.run_id if remote else ROOT
    relay = Host(args.relay_ssh if remote else None, cwd, env, project)
    load = Host(args.load_ssh if remote else None, cwd, env, project)
    (out/'campaign.json').write_text(json.dumps({'source_revision': revision, 'dirty': bool(status),
        'mode': args.mode, 'relay_host': relay.ssh or 'local', 'load_host': load.ssh or 'local',
        'project': project, 'environment': env, 'compose_files': FILES, 'volumes_preserved': True}, indent=2))
    source_files = [ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'rust-toolchain.toml', ROOT/'.dockerignore']
    source_files += [p for folder in ['crates', 'contrib/lab'] for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and 'target' not in p.parts]
    (out/'source-hashes.json').write_text(json.dumps({str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}, indent=2))
    hosts = [('relay', relay), ('load', load)] if remote else [('local', relay)]
    claimed = []
    started_relay = False
    container = ''
    load_attempted = False
    load_name = project+'-load'
    stopped = threading.Event()
    sampler = None
    success = False
    try:
        if remote:
            archive = out/'source.tar'
            with archive.open('wb') as f:
                subprocess.run(['git', 'archive', 'HEAD'], cwd=ROOT, stdout=f, check=True)
            for _, host in hosts:
                stage(host, archive)
                if args.bootstrap_debian:
                    host.run(['bash', 'scripts/lab-bootstrap-debian.sh'], timeout=900)
        for role, host in hosts:
            host.save(out/f'{role}-docker.json', ['docker', 'info', '--format', '{{json .}}'], check=True)
            if json.loads((out/f'{role}-docker.json').read_text()).get('OSType') != 'linux':
                raise RuntimeError('lab requires a Linux Docker engine')
            for kind in ['container', 'volume', 'network']:
                existing = host.run(['docker', kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project='+project], capture_output=True, text=True).stdout.strip()
                if existing:
                    raise RuntimeError(f'{role}: project already has {kind}s; choose a new run-id')
            # Compose may reuse an unlabelled volume with its default name.
            for suffix in ['relay-data', 'load-results']:
                name = project + '_' + suffix
                probe = host.run(['docker', 'volume', 'inspect', name], capture_output=True, check=False)
                if probe.returncode == 0:
                    raise RuntimeError(f'{role}: volume {name} already exists; choose a new run-id')
            claimed.append((role, host))
            host.save(out/f'{role}-compose.yml', ['docker', 'compose', '-p', project]+FILES+['config'], check=True)
        if remote:
            ids = [json.loads((out/f'{role}-docker.json').read_text())['ID'] for role, _ in hosts]
            if ids[0] == ids[1]:
                raise RuntimeError('both SSH destinations point to the same Docker daemon')
        for role, host in [('relay', relay), ('load', load)] if remote else [('relay', relay)]:
            if not args.skip_build:
                with (out/f'{role}-build.log').open('w') as log:
                    host.compose('build', role, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
            host.save(out/f'{role}-image.json', ['docker', 'image', 'inspect', 'wok-lab:'+env['LAB_IMAGE_TAG']], check=True)
            host.save(out/f'{role}-hardware.txt', ['docker', 'run', '--rm', '--entrypoint', 'sh',
                      'wok-lab:'+env['LAB_IMAGE_TAG'], '-c', 'cat /proc/cpuinfo /proc/meminfo'], check=True)
        started_relay = True  # Capture even partial startup failures.
        relay.compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '90', 'relay', timeout=120)
        container = relay.compose('ps', '-q', 'relay', capture_output=True, text=True).stdout.strip()
        relay.save(out/'relay-config.toml', ['docker', 'exec', container, 'cat', '/etc/wok/lab.toml'], check=True)
        sampler = threading.Thread(target=sample, args=([('relay', relay, container), ('load', load, load_name)], out/'stats.jsonl', stopped), daemon=True)
        sampler.start()
        load_attempted = True
        with (out/'load-console.log').open('w') as log:
            result = load.compose('run', '--no-deps', '--name', load_name, 'load', check=False,
                                  stdout=log, stderr=subprocess.STDOUT,
                                  timeout=int(env.get('LAB_DEADLINE_SECONDS', '900'))+120)
        load.copy(load_name, out/'load')
        if result.returncode:
            raise RuntimeError(f'load failed ({result.returncode}); see load artifacts')
        # Copy success is not proof of a valid workload: verify the explicit completion marker.
        completed = json.loads((out/'load/run/result.json').read_text())
        if completed.get('ok') is not True:
            raise RuntimeError('load completion marker failed')
        success = True
    finally:
        primary_error = sys.exception()
        stopped.set()
        if sampler:
            sampler.join(timeout=45)
        cleanup_errors = []
        if load_attempted and not (out/'load').exists():
            try:
                load.copy(load_name, out/'load')
            except Exception as error:
                cleanup_errors.append(f'load artifact collection: {error}')
        if started_relay:
            for name, cmd in [('relay-metrics.txt', ['exec', '-T', 'relay', 'curl', '-fsS', '--max-time', '3', 'http://127.0.0.1:7777/metrics']),
                              ('relay-stop.txt', ['stop', 'relay']),
                              ('relay-log.txt', ['logs', '--no-color', 'relay']),
                              ('integrity.txt', ['run', '--rm', '--no-deps', 'relay', '--config', '/etc/wok/lab.toml', 'integrity'])]:
                try:
                    with (out/name).open('w') as log:
                        r = relay.compose(*cmd, check=False, stdout=log, stderr=subprocess.STDOUT)
                    if r.returncode:
                        cleanup_errors.append(name)
                except Exception as error:
                    cleanup_errors.append(f'{name}: {error}')
        if container:
            try:
                state = json.loads(relay.run(['docker', 'inspect', container], capture_output=True, text=True).stdout)
                (out/'relay-inspect.json').write_text(json.dumps(state, indent=2))
                if state[0]['State']['ExitCode'] != 0 or state[0]['State']['OOMKilled']:
                    cleanup_errors.append('relay did not exit cleanly')
            except Exception as error:
                cleanup_errors.append(f'relay exit verification: {error}')
        for role, host in claimed:
            try:
                host.compose('down', '--remove-orphans')  # Never remove volumes.
            except Exception as error:
                cleanup_errors.append(f'{role}: {error}')
        (out/'result.json').write_text(json.dumps({'ok': success and not cleanup_errors,
            'error': str(primary_error) if primary_error else None,
            'cleanup_errors': cleanup_errors, 'volumes_preserved': True}, indent=2))
        print(f'Artifacts: {out}\nRetained volume project: {project}', flush=True)
        if cleanup_errors:
            raise RuntimeError(f'cleanup/integrity failed: {cleanup_errors}')
    if not success:
        raise RuntimeError('campaign failed')


if __name__ == '__main__':
    main()
