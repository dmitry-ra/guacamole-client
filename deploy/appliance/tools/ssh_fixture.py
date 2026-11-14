#!/usr/bin/env python3
"""Synthetic-only inner operations for test_ssh; never reads product secrets."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path('/run/fixture')
USER = 'fixture'
COMMAND = '/run/fixture/launcher'
CONTROL = 'exec python3 /run/fixture/control.py\r'
PHASE = 'operation'


def command(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=10, **kwargs).stdout


def write(path, value, mode=0o600, uid=0):
    path.write_text(value, encoding='ascii')
    path.chmod(mode)
    os.chown(path, uid, uid)


def initialize(launcher):
    Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
    ROOT.mkdir(mode=0o755)
    command(['useradd', '--uid', '2100', '--home-dir', str(ROOT/'home'),
             '--shell', '/bin/bash', '--password', 'x', USER])
    (ROOT/'home').mkdir(mode=0o700)
    os.chown(ROOT/'home', 2100, 2100)
    for name, kind in [('host', 'ecdsa'), ('app', 'ed25519'), ('wrong', 'ed25519')]:
        command(['ssh-keygen', '-q', '-t', kind, '-N', '', '-f', str(ROOT/name)])
    write(ROOT/'authorized_keys', 'restrict,pty,command="'+COMMAND+'" '+
          (ROOT/'app.pub').read_text(), 0o644)
    write(ROOT/'launcher', launcher, 0o755)
    # Empty root-owned tmux configuration; path is passed to the shared renderer.
    write(ROOT/'tmux.conf', '', 0o644)
    write(ROOT/'control.py', '''import json,os,time
from pathlib import Path
p=Path('/run/fixture/home/state.json')
pid=os.getpid(); start=int(Path('/proc/self/stat').read_text().split(') ')[1].split()[19])
for counter in range(300):
    temp=p.with_suffix('.next')
    temp.write_text(json.dumps(dict(pid=pid,start=start,counter=counter)))
    temp.replace(p)
    print('synthetic counter',counter,flush=True)
    time.sleep(0.2)
''', 0o644)
    write(ROOT/'sshd.conf', '''Port 2222
ListenAddress 127.0.0.1
HostKey /run/fixture/host
PidFile /run/fixture/sshd.pid
AuthorizedKeysFile /run/fixture/authorized_keys
StrictModes yes
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers fixture
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitUserRC no
LogLevel QUIET
''')
    command(['/usr/sbin/sshd', '-t', '-f', str(ROOT/'sshd.conf')])
    command(['/usr/sbin/sshd', '-f', str(ROOT/'sshd.conf')])
    # A synthetic default server is a sentinel, inside this disposable container.
    command(['runuser', '-u', USER, '--', 'tmux', '-f', '/dev/null',
             'new-session', '-d', '-s', 'sentinel', 'sleep 300'])
    return {'initialized': True}


def export():
    pub = (ROOT/'host.pub').read_text().split()
    return {'host-key': '[127.0.0.1]:2222 '+pub[0]+' '+pub[1],
            'private-key': (ROOT/'app').read_text(),
            'wrong-key': (ROOT/'wrong').read_text()}


def metadata():
    pid = int(command(['runuser', '-u', USER, '--', 'tmux', 'display-message',
                       '-p', '-t', 'sentinel', '#{pane_pid}']).strip())
    fields = Path('/proc/'+str(pid)+'/stat').read_text().split(') ')[1].split()
    result = {'sentinel': {'pid': pid, 'start': int(fields[19])}}
    state = ROOT/'home/state.json'
    if state.exists():
        value = json.loads(state.read_text())
        if set(value) != {'pid', 'start', 'counter'} or any(type(v) is not int or v < 0 for v in value.values()):
            raise ValueError('Invalid numeric state')
        fields = Path('/proc/'+str(value['pid'])+'/stat').read_text().split(') ')[1].split()
        if int(fields[19]) != value['start']:
            raise ValueError('Process identity changed')
        result['process'] = value
    return result


def denied(kind):
    public = (ROOT/'host.pub').read_text().split()
    write(ROOT/'known_hosts', '[127.0.0.1]:2222 '+' '.join(public[:2])+'\n')
    args = ['ssh', '-F', '/dev/null', '-oBatchMode=yes', '-oConnectTimeout=5',
            '-oStrictHostKeyChecking=yes', '-oUserKnownHostsFile='+str(ROOT/'known_hosts'),
            '-oControlMaster=no', '-oControlPath=none', '-oControlPersist=no',
            '-oIdentitiesOnly=yes', '-p', '2222']
    if kind == 'none':
        args += ['-oPreferredAuthentications=none', '-oPubkeyAuthentication=no']
    elif kind == 'command':
        args += ['-i', str(ROOT/'app'), '-oPreferredAuthentications=publickey']
    else:
        raise ValueError('Unknown negative gate')
    code = subprocess.run(args+['fixture@127.0.0.1', '/unapproved'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8).returncode
    return {'denied': code != 0, 'exit': code}


def native(params, inject=False, seconds=3):
    global PHASE
    from probe_login import Protocol, ProtocolError, PAINT
    required = {'hostname', 'port', 'username', 'host-key', 'private-key', 'command'}
    if (set(params) != required or params['hostname'] != '127.0.0.1'
            or params['port'] != '2222' or params['username'] != USER
            or params['command'] != COMMAND or not 1 <= seconds <= 8
            or any(not isinstance(v, str) or len(v) > 16384 for v in params.values())):
        raise ValueError('Synthetic scope required')
    deadline = time.monotonic()+12
    result = {'status': None, 'display_instructions': 0, 'syncs': 0,
              'injected': False, 'outcome': 'incomplete'}
    with socket.create_connection(('127.0.0.1', 4822), timeout=3) as sock:
        p = Protocol(sock, deadline)
        PHASE = 'select'
        p.send('select', 'ssh')
        args = p.read()
        if (not args or args[0] != 'args' or len(set(args[1:])) != len(args[1:])
                or not required.issubset(args[1:])):
            raise ProtocolError()
        p.send('size', '800', '600', '96'); p.send('audio'); p.send('video'); p.send('image', 'image/png')
        values = []
        for name in args[1:]:
            if name.startswith('VERSION_'):
                if not re.fullmatch(r'VERSION_[0-9]+_[0-9]+_[0-9]+', name):
                    raise ProtocolError()
                values.append(name)
            else:
                values.append(params.get(name, ''))
        PHASE = 'connect'
        p.send('connect', *values)
        values.clear()
        painted = None
        PHASE = 'observe'
        for _ in range(10000):
            message = p.read()
            if message[0] == 'error':
                if len(message) != 3 or not re.fullmatch('[0-9]{1,5}', message[2]):
                    raise ProtocolError()
                result.update(status=int(message[2]), outcome='guacd_error')
                return result
            if message[0] in PAINT:
                result['display_instructions'] += 1
            if message[0] == 'blob':
                if len(message) != 3 or not message[1].isdigit():
                    raise ProtocolError()
                p.send('ack', message[1], 'OK', '0')
            if message[0] == 'sync':
                if len(message) < 2 or not message[1].isdigit():
                    raise ProtocolError()
                result['syncs'] += 1
                p.send('sync', message[1])
                if result['display_instructions'] and painted is None:
                    painted = time.monotonic()
                # Let the native shell finish startup before sending one fixed command.
                if inject and not result['injected'] and painted and time.monotonic()-painted >= .5:
                    for character in CONTROL:
                        key = 0xff0d if character == '\r' else ord(character)
                        p.send('key', str(key), '1'); p.send('key', str(key), '0')
                    result['injected'] = True
                if painted and time.monotonic()-painted >= seconds:
                    result['outcome'] = 'display_activity'
                    p.send('disconnect')
                    return result
        raise ProtocolError()


def main():
    if (not re.fullmatch('[a-f0-9]{32}', os.environ.get('PORTAL_SSH_FIXTURE', ''))
            or not Path('/run/.containerenv').is_file()):
        raise ValueError('Owned disposable container required')
    request = json.loads(sys.stdin.buffer.read(65537))
    mode = request['mode']
    if mode == 'linkage':
        import ctypes
        try:
            ctypes.CDLL('/opt/guacamole/lib/libguac-client-ssh.so')
            result = {'ssh_plugin_loadable': True}
        except OSError:
            result = {'ssh_plugin_loadable': False}
    elif mode == 'initialize': result = initialize(request['launcher'])
    elif mode == 'export': result = export()
    elif mode == 'metadata': result = metadata()
    elif mode == 'denied': result = denied(request['kind'])
    elif mode == 'native': result = native(request['params'], request.get('inject', False))
    else: raise ValueError('Unknown operation')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        allowed = {'TimeoutError', 'EOFError', 'ProtocolError', 'ValueError',
                   'FileNotFoundError', 'PermissionError', 'CalledProcessError'}
        name = type(error).__name__
        print(json.dumps({'fixture_error_type': name if name in allowed else 'OtherError', 'fixture_phase': PHASE}))
        raise SystemExit(1)
