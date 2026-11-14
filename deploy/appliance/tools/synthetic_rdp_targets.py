#!/usr/bin/env python3
"""Bounded synthetic two-listener XRDP fixture on an explicitly pinned guest."""
import argparse
import configparser
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import secrets
import shutil
import socket
import subprocess
import time


def run(*args, check=True, timeout=20, **kw):
    return subprocess.run(list(map(str, args)), check=check, timeout=timeout,
                          capture_output=True, **kw)


def save(path, value):
    with path.open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(value, f, indent=2)
        f.flush()
        os.fsync(f.fileno())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(directory):
    if directory.is_symlink() or directory.stat().st_uid != 0 or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise RuntimeError('Unsafe fixture directory')
    statefile = directory / 'state.json'
    if statefile.is_symlink() or statefile.stat().st_uid != 0 or stat.S_IMODE(statefile.stat().st_mode) != 0o600:
        raise RuntimeError('Unsafe fixture state')
    state = json.loads((directory / 'state.json').read_text())
    if socket.gethostname() != state['hostname'] or Path(
            '/sys/class/dmi/id/product_uuid').read_text().strip().lower() != state['uuid']:
        raise RuntimeError('Guest identity mismatch')
    return state


def properties(unit):
    result = run('systemctl', 'show', unit, '--property=InvocationID,ActiveState,MainPID', check=False)
    return dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)


def baseline():
    return {'pidfile': Path('/run/xrdp/xrdp.pid').read_text(),
            'config_sha256': digest('/etc/xrdp/xrdp.ini'),
            'main_pid': properties('xrdp.service').get('MainPID')}


def assert_baseline(state):
    if baseline() != state['baseline']:
        raise RuntimeError('Original XRDP identity/config changed; preserve evidence')


def prepare(args):
    if socket.gethostname() != args.hostname or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.uuid.lower():
        raise RuntimeError('Explicit pinned guest required')
    address = str(ipaddress.IPv4Address(args.address))
    if args.beta_port == 3389 or not 1024 <= args.beta_port <= 65535:
        raise RuntimeError('Independent nonprivileged beta port required')
    run('systemctl', 'is-active', 'xrdp.service', 'xrdp-sesman.service')
    with socket.socket() as probe:
        probe.bind((address, args.beta_port))
    directory = args.directory
    directory.mkdir(mode=0o700)
    token = secrets.token_hex(5)
    runtime = Path('/run') / ('portal-synthetic-' + token)
    state = {'hostname': args.hostname, 'uuid': args.uuid.lower(), 'address': address,
             'beta_port': args.beta_port, 'runtime': str(runtime),
             'beta_unit': 'portal-synthetic-beta-' + token + '.service',
             'watchdog_unit': 'portal-synthetic-watch-' + token + '.service',
             'source_sha256': digest(__file__), 'baseline': baseline(),
             'desktop_startup': 'openbox-startup-after-wm',
             'users': ['pa' + token, 'pb' + token], 'prepared_at': time.time()}
    save(directory / 'state.json', state)
    shutil.copyfile(__file__, directory / 'controller.py')
    os.chmod(directory / 'controller.py', 0o600)
    credentials = {'targets': []}
    desktop_scripts = {}
    for label, user, port in zip(('alpha', 'beta'), state['users'], (3389, args.beta_port)):
        if run('getent', 'passwd', user, check=False).returncode == 0:
            raise RuntimeError('Generated account collision')
        # New accounts remain locked until the independently bounded watchdog exists.
        run('useradd', '--create-home', '--shell', '/bin/bash', '--comment', 'Synthetic portal fixture', user)
        info = pwd.getpwnam(user)
        home = Path(info.pw_dir)
        marker = home / 'portal-marker.sh'
        marker.write_text('#!/bin/sh\nexec /usr/bin/xterm -geometry 80x20+30+30 -bg ' +
                          ('darkgreen' if label == 'alpha' else 'navy') +
                          ' -fg white -title SYNTHETIC-' + label.upper() +
                          ' -e /bin/sh -c \'printf "SYNTHETIC TARGET ' + label.upper() +
                          '\\n"; exec sleep 600\'\n')
        script = home / 'startwm.sh'
        # Openbox starts the marker only after initializing the window manager.
        # Starting xterm in parallel before the WM can leave an unmapped shell.
        script.write_text('#!/bin/sh\nexec /usr/bin/openbox --startup ' + str(marker) + '\n')
        for path in (script, marker):
            os.chmod(path, 0o700)
            os.chown(path, info.pw_uid, info.pw_gid)
            run('/bin/sh', '-n', path)
        desktop_scripts[label] = {path.name: digest(path) for path in (script, marker)}
        credentials['targets'].append({'alias': label, 'username': user,
            'password': secrets.token_urlsafe(32), 'address': address, 'port': port})
    save(directory / 'credentials.json', credentials)
    runtime.mkdir(mode=0o700)
    xrdp = pwd.getpwnam('xrdp')
    os.chown(runtime, xrdp.pw_uid, xrdp.pw_gid)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=synthetic-beta', '-keyout', runtime / 'key.pem', '-out', runtime / 'cert.pem')
    cfg = configparser.ConfigParser(strict=False, interpolation=None)
    cfg.optionxform = str
    cfg.read('/etc/xrdp/xrdp.ini')
    cfg['Globals']['port'] = 'tcp://' + address + ':' + str(args.beta_port)
    cfg['Globals']['certificate'] = str(runtime / 'cert.pem')
    cfg['Globals']['key_file'] = str(runtime / 'key.pem')
    cfg['Globals']['security_layer'] = 'tls'
    cfg['Logging']['LogFile'] = str(runtime / 'xrdp.log')
    cfg['Logging']['EnableSyslog'] = 'false'
    with (runtime / 'xrdp.ini').open('w') as stream:
        cfg.write(stream)
    (runtime / 'pidroot').mkdir(mode=0o700)
    (runtime / 'pidroot' / 'sockdir').mkdir(mode=0o700)
    for path in runtime.iterdir():
        os.chown(path, xrdp.pw_uid, xrdp.pw_gid)
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    os.chown(runtime / 'pidroot' / 'sockdir', xrdp.pw_uid, xrdp.pw_gid)
    certs = [Path('/etc/xrdp/synthetic-fixture.crt'), runtime / 'cert.pem']
    for target, cert in zip(credentials['targets'], certs):
        target['certificate_sha256'] = hashlib.sha256(run('openssl', 'x509', '-in', cert,
            '-outform', 'DER').stdout).hexdigest()
    # Credentials file is replaced only before any consumer/start intent exists.
    (directory / 'credentials.json').write_text(json.dumps(credentials, indent=2))
    assert_baseline(state)
    save(directory / 'prepared.json', {'prepared': True, 'source_sha256': digest(__file__),
                                      'accounts_locked': True, 'baseline': baseline(),
                                      'desktop_startup': state['desktop_startup'],
                                      'desktop_scripts_sha256': desktop_scripts})


def start(directory, seconds):
    state = load(directory)
    if digest(directory / 'controller.py') != state['source_sha256']:
        raise RuntimeError('Controller source mismatch')
    assert_baseline(state)
    save(directory / 'start.intent.json', {'seconds': seconds, 'at': time.time()})
    # The independent root watchdog expires access even if this controller fails.
    run('systemd-run', '--unit=' + state['watchdog_unit'], '--property=Type=exec',
        '--property=RuntimeMaxSec=' + str(seconds), '--property=TimeoutStopSec=20',
        '--property=ExecStopPost=/usr/bin/python3 ' + str(directory / 'controller.py') +
        ' expire --directory ' + str(directory), '/usr/bin/sleep', str(seconds))
    watchdog = properties(state['watchdog_unit'])
    save(directory / 'watchdog.json', watchdog)
    if watchdog.get('ActiveState') != 'active' or not watchdog.get('InvocationID'):
        raise RuntimeError('Independent watchdog not active; accounts remain locked')
    creds = json.loads((directory / 'credentials.json').read_text())
    for target in creds['targets']:
        run('chpasswd', input=(target['username'] + ':' + target['password'] + '\n').encode())
    runtime = Path(state['runtime'])
    # XRDP0.9 refuses even an empty existing PID file. Bind an empty private
    # run directory, then retain only the shared sesman socket directory.
    # systemd resolves bind sources against the host filesystem.
    run('systemd-run', '--unit=' + state['beta_unit'], '--property=Type=exec',
        '--property=User=xrdp', '--property=Group=xrdp',
        '--property=RuntimeMaxSec=' + str(seconds), '--property=KillMode=control-group',
        '--property=TimeoutStopSec=10', '--property=PrivateMounts=yes',
        '--property=BindPaths=' + str(runtime / 'pidroot') + ':/run/xrdp /run/xrdp/sockdir:/run/xrdp/sockdir',
        '/usr/sbin/xrdp', '--nodaemon', '--config', runtime / 'xrdp.ini')
    save(directory / 'beta.json', properties(state['beta_unit']))
    time.sleep(1)
    assert_baseline(state)
    if properties(state['beta_unit']).get('ActiveState') != 'active':
        raise RuntimeError('Beta failed; watchdog still expires synthetic accounts')
    pid = properties(state['beta_unit'])['MainPID']
    childrun = Path('/proc') / pid / 'root/run/xrdp'
    identity = lambda path: [path.stat().st_dev, path.stat().st_ino]
    mount_check = {'host_run': identity(Path('/run/xrdp')),
                   'child_run': identity(childrun),
                   'host_sockdir': identity(Path('/run/xrdp/sockdir')),
                   'child_sockdir': identity(childrun / 'sockdir'),
                   'child_pidfile': (childrun / 'xrdp.pid').read_text() if (childrun / 'xrdp.pid').exists() else None}
    save(directory / 'mount-check.json', mount_check)
    if (mount_check['host_run'] == mount_check['child_run']
            or mount_check['host_sockdir'] != mount_check['child_sockdir']
            or mount_check['child_pidfile'] == state['baseline']['pidfile']):
        raise RuntimeError('Private run/socket/PID namespace proof failed; expire fixture')
    save(directory / 'started.json', {'started': True, 'seconds': seconds,
                                     'baseline_unchanged': True, 'at': time.time(),
                                     'beta_properties': properties(state['beta_unit']),
                                     'beta_mount_namespace': os.readlink('/proc/' + properties(state['beta_unit'])['MainPID'] + '/ns/mnt'),
                                     'original_mount_namespace': os.readlink('/proc/' + state['baseline']['main_pid'] + '/ns/mnt')})


def stop_beta(directory, state):
    record = directory / 'beta.json'
    current = properties(state['beta_unit'])
    if current.get('ActiveState') in ('active', 'activating', 'deactivating'):
        if not record.exists() or current.get('InvocationID') != json.loads(record.read_text()).get('InvocationID'):
            raise RuntimeError('Beta invocation mismatch; refuse foreign stop')
        run('systemctl', 'stop', state['beta_unit'])


def expire(directory):
    state = load(directory)
    # Lock first, including after partial account creation; never remove accounts.
    for user in state['users']:
        try:
            info = pwd.getpwnam(user)
        except KeyError:
            continue
        if info.pw_dir != '/home/' + user or info.pw_gecos != 'Synthetic portal fixture':
            raise RuntimeError('Synthetic account ownership mismatch')
        run('usermod', '--lock', user)
        run('usermod', '--expiredate', '1970-01-02', user)
        run('loginctl', 'terminate-user', str(info.pw_uid), check=False)
        run('pkill', '-TERM', '-u', str(info.pw_uid), check=False)
    stop_beta(directory, state)
    assert_baseline(state)
    # Preserve original intent and result; repeated expiry is safe and explicit.
    save(directory / ('expired-' + secrets.token_hex(4) + '.json'),
         {'expired': True, 'accounts_locked': True, 'original_listener_unchanged': True,
          'at': time.time()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'start', 'status', 'stop-beta', 'expire'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--hostname')
    parser.add_argument('--uuid')
    parser.add_argument('--address')
    parser.add_argument('--beta-port', type=int, default=3390)
    parser.add_argument('--seconds', type=int, default=600)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(args.directory))
            or '..' in args.directory.parts or args.directory.parent != Path('/var/lib')
            or not args.directory.name.startswith('portal-synthetic-')
            or len(args.directory.name) < 20):
        parser.error('Root and an absolute whitespace-free private directory required')
    if not 1 <= args.seconds <= 600:
        parser.error('Duration must be 1..600 seconds')
    os.umask(0o077)
    if args.action == 'prepare':
        if not all((args.hostname, args.uuid, args.address)):
            parser.error('Prepare requires explicit hostname, UUID and address')
        prepare(args)
    elif args.action == 'start':
        start(args.directory, args.seconds)
    elif args.action == 'expire':
        expire(args.directory)
    else:
        state = load(args.directory)
        if args.action == 'stop-beta':
            stop_beta(args.directory, state)
            assert_baseline(state)
        print(json.dumps({'beta': properties(state['beta_unit']),
                          'watchdog': properties(state['watchdog_unit']),
                          'baseline_unchanged': baseline() == state['baseline']}))


if __name__ == '__main__':
    main()
