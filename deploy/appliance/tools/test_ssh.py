#!/usr/bin/env python3
"""Bounded isolated native guacd/OpenSSH/tmux fixture, not browser acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

import terminal_launcher

HERE = Path(__file__).resolve().parent
LABEL = 'guacamole.ssh-fixture'


class InnerFailure(RuntimeError):
    def __init__(self, category, phase):
        self.category = category
        self.phase = phase
        super().__init__('Synthetic inner operation failed')


def exact_image(value):
    if not isinstance(value, str) or re.fullmatch(r'(sha256:)?[a-f0-9]{64}', value) is None:
        raise ValueError('Exact local image SHA256 required')
    return 'sha256:'+value.removeprefix('sha256:')


def owned(info, *, cid, image, token, name):
    observed = info.get('Image', '')
    return (info.get('Id') == cid and isinstance(observed, str)
            and re.fullmatch(r'(sha256:)?[a-f0-9]{64}', observed) is not None
            and exact_image(observed) == image
            and info.get('Name', '').lstrip('/') == name
            and info.get('Config', {}).get('Labels', {}).get(LABEL) == token)


def engine(*args, data=None, timeout=20, check=True):
    result = subprocess.run(['podman', *args], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Fixture engine operation failed')
    return result


def inner(cid, request, native=False):
    source = (HERE/'ssh_fixture.py').read_text()
    if native:
        # Reuse only the bounded wire codec. The RDP credential helper is not run.
        codec = (HERE/'probe_login.py').read_text().split('\ndef parameters(')[0]
        source = ('import types,sys\nm=types.ModuleType("probe_login")\n'
                  'exec('+repr(codec)+',m.__dict__)\nsys.modules["probe_login"]=m\n')+source
    result = engine('exec', '-i', cid, 'python3', '-B', '-c', source,
                    data=json.dumps(request).encode(), timeout=25, check=False)
    if len(result.stdout) > 32768:
        raise RuntimeError('Oversized fixture result')
    value = json.loads(result.stdout)
    if result.returncode:
        allowed = {'TimeoutError', 'EOFError', 'ProtocolError', 'ValueError',
                   'FileNotFoundError', 'PermissionError', 'CalledProcessError', 'OtherError'}
        category = value.get('fixture_error_type') if isinstance(value, dict) else None
        phase = value.get('fixture_phase') if isinstance(value, dict) else None
        raise InnerFailure(category if category in allowed else 'OtherError',
                           phase if phase in ('select', 'connect', 'observe', 'operation') else 'unknown')
    return value


def native_result(value):
    keys = {'status', 'display_instructions', 'syncs', 'injected', 'outcome'}
    if (not isinstance(value, dict) or set(value) != keys
            or value['outcome'] not in ('display_activity', 'guacd_error', 'incomplete')
            or type(value['injected']) is not bool
            or any(type(value[k]) is not int or not 0 <= value[k] <= 10000
                   for k in ('display_instructions', 'syncs'))
            or (value['status'] is not None and
                (type(value['status']) is not int or not 0 <= value['status'] <= 65535))):
        raise ValueError('Invalid sanitized native result')
    return dict(value)


def metadata_result(value):
    if not isinstance(value, dict) or not {'sentinel'} <= set(value) <= {'sentinel', 'process'}:
        raise ValueError('Invalid process metadata')
    for name, item in value.items():
        keys = {'pid', 'start', 'counter'} if name == 'process' else {'pid', 'start'}
        if (not isinstance(item, dict) or set(item) != keys
                or any(type(v) is not int or not 0 <= v <= 2**63-1 for v in item.values())):
            raise ValueError('Invalid numeric process metadata')
    return {name: dict(item) for name, item in value.items()}


def persisted(before, after):
    a, b = before.get('process', {}), after.get('process', {})
    return (before['sentinel'] == after['sentinel'] and bool(a) and bool(b)
            and a['pid'] == b['pid'] and a['start'] == b['start']
            and b['counter'] > a['counter'])


def cleanup_owned(item, token):
    found = engine('container', 'exists', item['name'], check=False, timeout=5).returncode
    if found == 1:
        return
    if found != 0:
        raise RuntimeError('Unable to verify container absence')
    info = json.loads(engine('inspect', item['name'], timeout=5).stdout)[0]
    cid = item['cid'] or info['Id']
    if (re.fullmatch('[a-f0-9]{64}', cid) is None or
            not owned(info, cid=cid, image=item['image'], token=token, name=item['name'])):
        raise RuntimeError('Cleanup ownership mismatch')
    engine('rm', '-f', '--time=2', cid, timeout=15)
    if (engine('container', 'exists', cid, check=False, timeout=5).returncode != 1 or
            engine('container', 'exists', item['name'], check=False, timeout=5).returncode != 1):
        raise RuntimeError('Owned fixture container survived')


def fixture(image, endpoint_image, directory):
    image, endpoint_image = exact_image(image), exact_image(endpoint_image)
    if os.geteuid() != 0:
        raise ValueError('Rootful isolated fixture required')
    if not directory.is_absolute() or directory.exists() or directory.is_symlink():
        raise ValueError('New absolute private case required')
    directory.mkdir(mode=0o700)
    token = uuid.uuid4().hex
    sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
               [Path(__file__), HERE/'ssh_fixture.py', HERE/'probe_login.py',
                HERE/'terminal_launcher.py', HERE/'ssh-endpoint.Containerfile']}
    status = {'schema': 1, 'scope': 'synthetic native SSH; not browser or JDBC acceptance',
              'passed': False, 'cleanup_verified': False, 'image': image,
              'endpoint_image': endpoint_image, 'run_id': token,
              'sources': sources, 'checks': {}, 'phase': 'validate'}
    (directory/'intent.json').write_text(json.dumps(status, sort_keys=True)+'\n')
    with (directory/'intent.json').open('rb') as intent:
        os.fsync(intent.fileno())
    containers = []
    primary = None
    cleanup_errors = []
    def start(role, selected, network, entrypoint, command, readonly=False):
        name = 'portal-ssh-'+token+'-'+role
        # Track the fresh name before dispatch, including a failed engine response.
        item = dict(name=name, image=selected, cid=None)
        containers.append(item)
        args = ['run', '-d', '--pull=never', '--name', name, '--label', LABEL+'='+token,
                '--env', 'PORTAL_SSH_FIXTURE='+token,
                '--network', network, '--cpus=1', '--memory=384m', '--pids-limit=128',
                '--security-opt=no-new-privileges', '--tmpfs', '/run:rw,nosuid,nodev,size=32m',
                '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777,size=32m', '--entrypoint', entrypoint]
        if readonly:
            args += ['--read-only', '--cap-drop=ALL', '--user=2002:2002']
        raw = engine(*args, selected, *command).stdout.decode().strip()
        if re.fullmatch('[a-f0-9]{64}', raw) is None:
            raise RuntimeError('Invalid owned container ID')
        item['cid'] = raw
        info = json.loads(engine('inspect', raw).stdout)[0]
        if not owned(info, cid=raw, image=selected, token=token, name=name):
            raise RuntimeError('Fixture container ownership mismatch')
        return raw
    try:
        for selected in (image, endpoint_image):
            info = json.loads(engine('image', 'inspect', selected).stdout)[0]
            if exact_image(info['Id']) != selected:
                raise RuntimeError('Image identity mismatch')
            if selected == endpoint_image and info.get('Labels', {}).get('guacamole.ssh-fixture.endpoint') != '1':
                raise RuntimeError('Dedicated endpoint image required')
            if (selected == endpoint_image and info.get('Labels', {}).get(
                    'guacamole.ssh-fixture.source-sha256') != sources['ssh-endpoint.Containerfile']):
                raise RuntimeError('Endpoint source binding mismatch')
        status['phase'] = 'start'
        candidate = start('guacd', image, 'none', '/usr/bin/timeout',
                          ['--kill-after=5', '210', '/opt/guacamole/sbin/guacd',
                           '-f', '-b', '127.0.0.1', '-l', '4822', '-L', 'error'], True)
        status['phase'] = 'ssh_linkage'
        if inner(candidate, {'mode': 'linkage'}) != {'ssh_plugin_loadable': True}:
            raise RuntimeError('SSH plugin cannot load')
        status['checks']['ssh_plugin_loadable'] = True
        endpoint = start('endpoint', endpoint_image, 'container:'+candidate, 'sleep', ['220'])
        status['containers'] = {'candidate': candidate, 'endpoint': endpoint}
        launcher = terminal_launcher.render(launcher='/run/fixture/launcher',
                    socket='/run/fixture/home/portal.sock', config='/run/fixture/tmux.conf',
                    home='/run/fixture/home', username='fixture')
        status['phase'] = 'initialize'
        if inner(endpoint, {'mode': 'initialize', 'launcher': launcher}) != {'initialized': True}:
            raise RuntimeError('Endpoint initialization failed')
        baseline = metadata_result(inner(endpoint, {'mode': 'metadata'}))
        keys = inner(endpoint, {'mode': 'export'})
        if (set(keys) != {'host-key', 'private-key', 'wrong-key'}
                or any(not isinstance(v, str) or len(v) > 16384 for v in keys.values())):
            raise RuntimeError('Invalid ephemeral keys')
        manifest = engine('exec', endpoint, 'cat', '/fixture-packages.tsv').stdout
        if len(manifest) > 65536:
            raise RuntimeError('Oversized package manifest')
        (directory/'endpoint-packages.tsv').write_bytes(manifest)
        status['endpoint_packages_sha256'] = hashlib.sha256(manifest).hexdigest()
        params = {'hostname': '127.0.0.1', 'port': '2222', 'username': 'fixture',
                  'command': '/run/fixture/launcher', 'host-key': keys['host-key'],
                  'private-key': keys['private-key']}
        for kind in ('none', 'command'):
            status['phase'] = 'deny_'+kind
            value = inner(endpoint, {'mode': 'denied', 'kind': kind})
            expected_exit = 255 if kind == 'none' else 126
            if (set(value) != {'denied', 'exit'} or value['denied'] is not True
                    or type(value['exit']) is not int or value['exit'] != expected_exit):
                raise RuntimeError('Negative SSH gate failed')
            status['checks'][kind+'_denied'] = True
        # Wrong pin is a valid, different public key entry, not malformed data.
        wrong_pub = engine('exec', endpoint, 'cat', '/run/fixture/wrong.pub').stdout.decode().split()
        wrong_pin = '[127.0.0.1]:2222 '+' '.join(wrong_pub[:2])
        for kind, changes in [('wrong_pin', {'host-key': wrong_pin}),
                              ('wrong_appkey', {'private-key': keys['wrong-key']})]:
            status['phase'] = kind
            value = native_result(inner(candidate, {'mode': 'native', 'params': dict(params, **changes)}, True))
            status['checks'][kind] = value
            if value['outcome'] != 'guacd_error' or value['status'] == 0:
                raise RuntimeError('Native SSH denial missing')
        status['phase'] = 'first_connect'
        first = native_result(inner(candidate, {'mode': 'native', 'params': params, 'inject': True}, True))
        status['checks']['first_connect'] = first
        if first['outcome'] != 'display_activity' or not first['injected']:
            raise RuntimeError('Native SSH display missing')
        before = metadata_result(inner(endpoint, {'mode': 'metadata'}))
        if 'process' not in before or baseline['sentinel'] != before['sentinel']:
            raise RuntimeError('Controlled pane missing or sentinel changed')
        status['phase'] = 'reconnect'
        second = native_result(inner(candidate, {'mode': 'native', 'params': params}, True))
        status['checks']['reconnect'] = second
        after = metadata_result(inner(endpoint, {'mode': 'metadata'}))
        status['process_before'], status['process_after'] = before, after
        if second['outcome'] != 'display_activity' or not persisted(before, after):
            raise RuntimeError('Controlled pane did not persist')
        status['checks']['same_process_counter_progress_sentinel_unchanged'] = True
        keys.clear(); params.clear()
        if sources != {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                       [Path(__file__), HERE/'ssh_fixture.py', HERE/'probe_login.py',
                        HERE/'terminal_launcher.py', HERE/'ssh-endpoint.Containerfile']}:
            raise RuntimeError('Fixture sources changed')
        status['passed'] = True
        status['phase'] = 'complete'
    except Exception as error:
        primary = error
        status['error_type'] = type(error).__name__
        if isinstance(error, InnerFailure):
            status['inner_error_type'] = error.category
            status['inner_phase'] = error.phase
    finally:
        for item in reversed(containers):
            try:
                cleanup_owned(item, token)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        status['cleanup_verified'] = not cleanup_errors
        if cleanup_errors:
            status['cleanup_error_types'] = cleanup_errors
        (directory/'result.json').write_text(json.dumps(status, sort_keys=True, indent=2)+'\n')
    print(json.dumps(status, sort_keys=True))
    return 0 if status['passed'] and status['cleanup_verified'] and primary is None else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--endpoint-image', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(180)
    return fixture(args.image, args.endpoint_image, args.directory)


if __name__ == '__main__':
    raise SystemExit(main())
