#!/usr/bin/env python3
"""Root host supervisor for one admitted appliance. No installation or migration."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import catalog
import network

ROOT = Path('/opt/guacamole-portal')
CONFIG = Path('/etc/guacamole-portal/config.json')
NETWORK = Path('/etc/guacamole-portal/network.json')
RELEASE = Path('/etc/guacamole-portal/release.json')
PERSIST = Path('/var/lib/guacamole-portal')
STATE = PERSIST / 'host'
PUBLIC = Path('/run/guacamole-portal')
NAME = 'guacamole-portal'
LABEL = 'guacamole.portal'
RUNTIME = '/opt/homelab-web-rdp/runtime.py'
PODMAN = '/usr/bin/podman'
COMPONENTS = ('database_ready', 'web_ready', 'enrolled')
STOP = False
DEADLINE = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identifier(value, length=64):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{%d}' % length, value):
        raise ValueError('Exact immutable identity required')
    return value


def image_id(value):
    if not isinstance(value, str) or not value.startswith('sha256:'):
        raise ValueError('Exact sha256 image ID required')
    identifier(value[7:])
    return value


def inspected_image(value):
    """Podman inspect accepts either spelling of the same full immutable ID."""
    if not isinstance(value, str): raise ValueError('Inspected image ID required')
    return 'sha256:' + identifier(value.removeprefix('sha256:'))


def parse_release(value):
    required = {'schema', 'image_id', 'config_sha256', 'network_sha256',
                'acceptance_evidence_path', 'acceptance_evidence_sha256',
                'backend_loopback_port', 'podman_network', 'apparmor_profile',
                'apparmor_profile_path', 'apparmor_profile_sha256'}
    catalog.fields(value, required)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Release schema 1 required')
    image_id(value['image_id'])
    for key in ('config_sha256', 'network_sha256', 'acceptance_evidence_sha256',
                'apparmor_profile_sha256'):
        identifier(value[key])
    catalog.port(value['backend_loopback_port'])
    for key in ('podman_network', 'apparmor_profile'):
        if (not isinstance(value[key], str) or not re.fullmatch('[a-z][a-z0-9_.-]{0,95}', value[key])
                or value[key] in ('host', 'none', 'bridge', 'unconfined')):
            raise ValueError('Literal dedicated network/profile required')
    for key in ('acceptance_evidence_path', 'apparmor_profile_path'):
        catalog.text(value[key], 4096)
        path = Path(value[key])
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('Absolute protected release input required')
    if Path(value['apparmor_profile_path']).parent != Path('/etc/apparmor.d'):
        raise ValueError('Pinned AppArmor source in /etc/apparmor.d required')
    return dict(value)


def read_json(path):
    return json.loads(network.protected_read(path), object_pairs_hook=catalog.unique_object)


def directory(path, *, mode=None, uid=0, gid=None, create=False):
    """Validate complete ancestry without following any directory symlink."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for i, part in enumerate(path.parts[1:]):
            final = i == len(path.parts) - 2
            created = False
            if final and create:
                try:
                    os.mkdir(part, mode or 0o700, dir_fd=fd)
                    created = True
                except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            if created: os.fchmod(fd, mode or 0o700)
            info = os.fstat(fd)
            if info.st_uid != (uid if final else 0) or info.st_mode & 0o022:
                raise RuntimeError('Unsafe directory ownership or permissions')
            if final and ((mode is not None and stat.S_IMODE(info.st_mode) != mode)
                          or (gid is not None and info.st_gid != gid)):
                raise RuntimeError('Exact directory mode/owner required')
        return (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def private_json(path):
    directory(path.parent, mode=0o700)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise RuntimeError('Private root regular state file required')
    return read_json(path)


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def write(path, value):
    """Private atomic replacement, durable before the caller continues."""
    directory(path.parent, mode=0o700)
    if os.path.lexists(path): private_json(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); sync_directory(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def command(args, timeout=5, check=True):
    if DEADLINE is not None:
        remaining = DEADLINE - time.monotonic()
        if remaining <= 0: raise RuntimeError('Startup deadline exceeded')
        timeout = min(timeout, remaining)
    # Engine output never enters logs. A file avoids unbounded RAM capture.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(list(map(str, args)), stdout=out, stderr=err,
                                timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                      'LANG': 'C', 'HOME': '/root'})
        if out.tell() > 131072 or err.tell() > 131072:
            raise RuntimeError('Command output exceeds bound')
        out.seek(0); err.seek(0)
        result.stdout = out.read(); result.stderr = err.read()
    if check and result.returncode: raise RuntimeError('Host command failed')
    return result


def engine(*args, **kwargs):
    return command([PODMAN, *args], **kwargs)


def one(raw):
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeError('Exactly one inspected object required')
    return value[0]


def authentication_fields(registry):
    fields = [{'name': 'username', 'type': 'USERNAME'}]
    if registry.publish_target_labels:
        fields.append({'name': 'wrdp-target', 'type': 'ENUM',
                       'options': [target.alias for target in registry.targets]})
    return fields


def image_backend_port(cfg):
    if type(cfg.host_backend_port) is not int or cfg.host_backend_port != 8080:
        raise ValueError('Immutable application requires internal HTTP port 8080')
    return cfg.host_backend_port


def validate_secret_metadata(root, limits):
    """Metadata only: values remain inside the read-only image secret mount."""
    for name, limit in limits.items():
        info = (root / name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                or info.st_nlink != 1 or not 0 < info.st_size <= limit):
            raise RuntimeError('Root-private literal secret mount required')


def selection():
    raw = network.protected_read(RELEASE)
    release = parse_release(json.loads(raw, object_pairs_hook=catalog.unique_object))
    config_raw, network_raw = network.protected_read(CONFIG), network.protected_read(NETWORK)
    if sha(config_raw) != release['config_sha256'] or sha(network_raw) != release['network_sha256']:
        raise RuntimeError('Admitted configuration changed')
    targets = catalog.parse(json.loads(config_raw, object_pairs_hook=catalog.unique_object))
    cfg = network.parse_config(json.loads(network_raw, object_pairs_hook=catalog.unique_object))
    image_backend_port(cfg)
    network.policy(cfg, targets)
    for key in ('acceptance_evidence', 'apparmor_profile'):
        if sha(network.protected_read(Path(release[key + '_path']))) != release[key + '_sha256']:
            raise RuntimeError('Reviewed release input changed')
    data = directory(PERSIST / 'data', uid=2000, gid=2000, mode=0o700)
    directory(PERSIST / 'secrets', mode=0o700)
    # Runtime validates individual secret contents. Host never reads credentials.
    limits = {'db-password': 4096}
    for target in targets.targets:
        if target.secret_file in limits and limits[target.secret_file] != target.secret_limit:
            raise RuntimeError('Secret filename has conflicting roles')
        limits[target.secret_file] = target.secret_limit
    validate_secret_metadata(PERSIST / 'secrets', limits)
    prepared = PERSIST / 'data/prepared.json'
    fd = os.open(prepared, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192):
            raise RuntimeError('Prepared data receipt required')
        prepared_raw = stream.read(8193)
    return release, cfg, (sha(raw), data, sha(prepared_raw), directory(PERSIST / 'secrets', mode=0o700),
                          authentication_fields(targets))


def guards(release, cfg, *, empty=False):
    profiles = Path('/sys/kernel/security/apparmor/profiles').read_text()
    if release['apparmor_profile'] + ' (enforce)' not in profiles.splitlines():
        raise RuntimeError('Pinned enforcing AppArmor profile required')
    value = one(engine('network', 'inspect', release['podman_network']).stdout)
    if (value.get('name') != release['podman_network'] or value.get('driver') != 'bridge'
            or value.get('network_interface') != cfg.bridge
            or value.get('labels', {}).get(LABEL) != '1'
            or value.get('subnets') != [{'subnet': cfg.subnet_ipv4, 'gateway': cfg.gateway_ipv4}]
            or value.get('ipv6_enabled') is not False or value.get('internal') is not False
            or value.get('dns_enabled') is not False):
        raise RuntimeError('Exact owned bridge required')
    members = engine('ps', '--all', '--no-trunc', '--filter=network=' + release['podman_network'],
                     '--format={{.ID}}').stdout.decode().splitlines()
    if empty and members: raise RuntimeError('Dedicated bridge is already consumed')
    return members


def network_command(action):
    command(['/usr/bin/python3', '-B', ROOT / 'network.py', action,
             '--config', NETWORK, '--catalog', CONFIG], timeout=60)


def network_bootstrap():
    # Netavark may remove the kernel bridge when the last consumer is removed.
    # Only the bootstrap module may reconcile its already admitted ownership.
    command(['/usr/bin/python3', '-B', ROOT / 'network_service.py', 'boot'], timeout=90)


def container_args(release, cfg, run_id):
    identifier(run_id, 32)
    internal_port = image_backend_port(cfg)
    logs = STATE / ('logs-' + run_id)
    engine_logs = STATE / ('engine-logs-' + run_id)
    return [PODMAN, 'run', '--detach', '--name=' + NAME, '--pull=never', '--restart=no',
            '--label=' + LABEL + '=1', '--label=' + LABEL + '.run=' + run_id,
            '--read-only', '--memory=2g', '--memory-swap=2g', '--cpus=2', '--pids-limit=384',
            '--cap-drop=all', *['--cap-add=' + cap for cap in
                ('SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'KILL')],
            '--security-opt=no-new-privileges', '--security-opt=apparmor=' + release['apparmor_profile'],
            '--tmpfs=/tmp:rw,nosuid,nodev,size=128m,mode=1777',
            '--tmpfs=/run:rw,nosuid,nodev,size=64m,mode=755',
            '--tmpfs=/run/web-rdp:rw,nosuid,nodev,size=64m,mode=755',
            '--log-driver=k8s-file', '--log-opt=max-size=64k', '--log-opt=path=' + str(engine_logs / 'entrypoint.log'),
            '--volume=' + str(logs) + ':/run/web-rdp/diagnostics:rw',
            '--volume=' + str(PERSIST / 'data') + ':/data:rw',
            '--volume=' + str(CONFIG.parent) + ':/config:ro',
            '--volume=' + str(PERSIST / 'secrets') + ':/secrets:ro',
            '--network=' + release['podman_network'], '--ip=' + cfg.source_ipv4,
            '--publish=127.0.0.1:%d:%d' % (release['backend_loopback_port'], internal_port),
            '--env=WEB_RDP_PRODUCTION=1', release['image_id'], 'serve']


def owned(record, cid):
    identifier(cid); identifier(record['run_id'], 32)
    result = engine('inspect', '--type=container', cid, check=False)
    if result.returncode:
        if engine('container', 'exists', cid, check=False).returncode == 1: return None
        raise RuntimeError('Container identity is unknown')
    value = one(result.stdout)
    labels = value.get('Config', {}).get('Labels', {})
    if (value.get('Id') != cid or inspected_image(value.get('Image')) != record['image_id']
            or value.get('Name', '').lstrip('/') != NAME
            or labels.get(LABEL) != '1' or labels.get(LABEL + '.run') != record['run_id']):
        raise RuntimeError('Foreign container identity')
    return value


def reconcile(record):
    """Resolve uncertain creation using a fresh query, never another run command."""
    identifier(record['run_id'], 32); image_id(record['image_id'])
    lines = engine('ps', '--all', '--no-trunc', '--filter=label=' + LABEL + '=1',
                   '--filter=label=' + LABEL + '.run=' + record['run_id'], '--format={{.ID}}').stdout.decode().splitlines()
    if len(lines) > 1: raise RuntimeError('Ambiguous owned creation; review required')
    if record.get('container_id'):
        cid = identifier(record['container_id'])
        if lines and lines != [cid]: raise RuntimeError('Recorded container differs from fresh ownership query')
        value = owned(record, cid)
        if value is not None and lines != [cid]: raise RuntimeError('Ownership query inconsistent')
        return cid if value is not None else None
    if not lines: return None
    cid = identifier(lines[0]); owned(record, cid)
    record['container_id'] = cid; write(STATE / 'current.json', record)
    return cid


def marker(run_id):
    return ('guacamole-portal:' + identifier(run_id, 32) + '\n').encode()


def ready_owned(run_id):
    path = PUBLIC / 'ready'
    directory(PUBLIC, mode=0o755)
    if not os.path.lexists(path): return False
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or network.protected_read(path) != marker(run_id)):
        raise RuntimeError('Foreign readiness marker')
    return True


def unpublish(run_id):
    if not ready_owned(run_id): return
    path = PUBLIC / 'ready'
    path.unlink(); sync_directory(PUBLIC)


def publish(run_id):
    directory(PUBLIC, mode=0o755)
    fd = os.open(PUBLIC / 'ready', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(marker(run_id)); stream.flush(); os.fsync(stream.fileno())
    sync_directory(PUBLIC)


def cutoff(record):
    marker_error = None
    try: unpublish(record['run_id'])
    except (OSError, RuntimeError, ValueError) as error: marker_error = error
    record['phase'] = 'stop_intent'; write(STATE / 'current.json', record)
    cid = reconcile(record)
    if cid is None and record.get('creation_uncertain') and not record.get('container_id'):
        record['phase'] = 'unresolved_creation'; write(STATE / 'current.json', record)
        raise RuntimeError('Uncertain creation remains absent; operator review required')
    if cid is not None:
        value = owned(record, cid)
        if value and value.get('State', {}).get('Running'):
            try: engine('stop', '--time=10', cid, timeout=14, check=False)
            except (OSError, RuntimeError, subprocess.TimeoutExpired): pass
            value = owned(record, cid)
            if value and value.get('State', {}).get('Running'):
                engine('kill', '--signal=KILL', cid, check=False)
        value = owned(record, cid)
        if value and value.get('State', {}).get('Running'):
            raise RuntimeError('Owned container shutdown unconfirmed')
        if value: engine('rm', cid)
        if owned(record, cid) is not None: raise RuntimeError('Owned removal unconfirmed')
    record['phase'] = 'stopped'; record['stopped_at'] = time.time()
    write(STATE / 'current.json', record)
    write(STATE / ('result-' + record['run_id'] + '.json'), record)
    if marker_error: raise marker_error


def health(cid):
    report = {'at': time.time(), 'components': {name: None for name in COMPONENTS}}
    try:
        result = engine('exec', cid, 'python3', '-B', RUNTIME, 'health', timeout=4, check=False)
        report['returncode'] = result.returncode
        if result.returncode or len(result.stdout) > 4096: raise ValueError('Native health failed')
        value = json.loads(result.stdout, object_pairs_hook=catalog.unique_object)
        report['components'] = {name: value.get(name) if type(value.get(name)) is bool else None
                                for name in COMPONENTS}
    except (OSError, RuntimeError, ValueError, AttributeError, subprocess.TimeoutExpired) as error:
        report['error_type'] = type(error).__name__
    report['healthy'] = all(v is True for v in report['components'].values())
    write(STATE / 'health-last.json', report)
    return report['healthy']


def authentication_ready(port, expected_fields):
    request = urllib.request.Request('http://127.0.0.1:%d/guacamole/api/tokens' % port,
        data=b'', method='POST', headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        # Local loopback only; ignore proxy environment and refuse redirects.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=2) as response: response.read(8193)
        return False
    except urllib.error.HTTPError as response:
        with response: raw = response.read(8193)
        if response.code != 403 or len(raw) > 8192: return False
        try: value = json.loads(raw, object_pairs_hook=catalog.unique_object)
        except ValueError: return False
        expected = value.get('expected') if isinstance(value, dict) else None
        return expected == expected_fields
    except (OSError, ValueError): return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def notify_ready():
    target = os.environ.get('NOTIFY_SOCKET')
    if target:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
            channel.connect('\0' + target[1:] if target.startswith('@') else target)
            channel.sendall(b'READY=1')


def run():
    global DEADLINE
    started = time.monotonic(); DEADLINE = started + 120
    previous_path = STATE / 'current.json'
    if previous_path.exists():
        previous = private_json(previous_path)
        if previous.get('phase') != 'stopped': cutoff(previous)
    if os.path.lexists(PUBLIC / 'ready'): raise RuntimeError('Existing readiness marker collision')
    release, cfg, binding = selection()
    network_bootstrap()
    guards(release, cfg, empty=True)
    network_command('apply'); network_command('check')
    value = one(engine('image', 'inspect', release['image_id']).stdout)
    if inspected_image(value.get('Id')) != release['image_id'] or value.get('Architecture') != 'amd64':
        raise RuntimeError('Immutable image differs')
    if engine('container', 'exists', NAME, check=False).returncode != 1:
        raise RuntimeError('Existing container name collision')
    with socket.socket() as probe: probe.bind(('127.0.0.1', release['backend_loopback_port']))
    if STOP: return
    run_id = secrets.token_hex(16)
    directory(STATE / ('logs-' + run_id), mode=0o700, create=True)
    # Conmon rotates files as host root. Its directory must never be writable
    # through any container mount, even by a compromised in-container root.
    directory(STATE / ('engine-logs-' + run_id), mode=0o700, create=True)
    record = {'schema': 1, 'run_id': run_id, 'image_id': release['image_id'],
              'release_sha256': binding[0], 'phase': 'start_intent', 'at': time.time(),
              'creation_uncertain': True}
    write(STATE / 'current.json', record)
    try:
        result = command(container_args(release, cfg, run_id), timeout=15)
        cid = identifier(result.stdout.decode().strip())
        owned(record, cid)
        container_started = time.monotonic()
        record['container_id'] = cid; record['creation_uncertain'] = False
        record['phase'] = 'starting'; write(STATE / 'current.json', record)
        published = False
        while not STOP:
            if published and not ready_owned(run_id): raise RuntimeError('Readiness marker lost')
            current_release, current_cfg, current_binding = selection()
            if (current_release, current_cfg, current_binding) != (release, cfg, binding):
                raise RuntimeError('Admitted mount/release binding changed')
            members = guards(release, cfg)
            if members != [cid]: raise RuntimeError('Dedicated bridge membership changed')
            network_command('check')
            value = owned(record, cid)
            if not value or not value.get('State', {}).get('Running'):
                raise RuntimeError('Owned container exited')
            good = health(cid)
            if published and not good: raise RuntimeError('Required component health lost')
            if not published:
                if time.monotonic() >= started + 120: raise RuntimeError('Startup deadline exceeded')
                if good and time.monotonic() >= container_started + 65 and authentication_ready(release['backend_loopback_port'], binding[4]):
                    publish(run_id); published = True; DEADLINE = None
                    record['phase'] = 'ready'; record['ready_at'] = time.time()
                    write(STATE / 'current.json', record); notify_ready()
            time.sleep(1)
    except BaseException as error:
        record['error_type'] = type(error).__name__
        raise
    finally:
        DEADLINE = None
        cutoff(record)


@contextlib.contextmanager
def locked():
    path = STATE / 'lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('Private root lock required')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('run', 'cutoff'))
    args = parser.parse_args()
    if os.geteuid() != 0: raise RuntimeError('Root required')
    directory(PERSIST, mode=0o700)
    directory(STATE, mode=0o700, create=True)
    directory(PUBLIC, mode=0o755, create=True)
    def stop(signum, frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    with locked():
        if args.command == 'run': run()
        elif (STATE / 'current.json').exists(): cutoff(private_json(STATE / 'current.json'))


if __name__ == '__main__':
    try: main()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        # No command output, paths, configuration values or credential bytes.
        print('Host supervisor failed: ' + type(error).__name__, flush=True)
        raise SystemExit(1)
