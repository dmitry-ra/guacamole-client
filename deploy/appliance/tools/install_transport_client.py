#!/usr/bin/env python3
"""Stage restricted transport config beside its existing private client key."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import render_transport

ROOT = Path('/etc/portal-rdp-transport')
UNIT = Path('/etc/systemd/system/portal-rdp-transport.service')


def write(path, value, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as out:
        out.write(value); out.flush(); os.fsync(out.fileno())


def install(config):
    if os.geteuid() != 0:
        raise RuntimeError('Root client required')
    os.umask(0o077)
    rendered = render_transport.render(config)
    info = ROOT.lstat()
    key = (ROOT/'identity').lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
            or not stat.S_ISREG(key.st_mode) or key.st_uid != 0 or stat.S_IMODE(key.st_mode) != 0o600):
        raise RuntimeError('Existing private client identity required')
    if ' '.join((ROOT/'identity.pub').read_text().split()[:2]) != config['public_key']:
        raise RuntimeError('Public client identity mismatch')
    addresses = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', '-4', 'address'], timeout=5))
    if config['client_address'] not in {a['local'] for interface in addresses for a in interface.get('addr_info', [])}:
        raise RuntimeError('Pinned client address is not local')
    destinations = (ROOT/'client.conf', ROOT/'known_hosts', UNIT,
                    ROOT/'client-install-intent.json', ROOT/'client-install-result.json')
    if any(os.path.lexists(path) for path in destinations):
        raise RuntimeError('Existing client installation; refuse replay')
    unit = rendered['portal-rdp-transport.service'].replace(
        'After=network-online.target',
        'After=network-online.target guacamole-portal-network.service\nRequires=guacamole-portal-network.service')
    write(ROOT/'client-install-intent.json', json.dumps({'schema': 1, 'operation': 'install client',
          'config_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}))
    for name in ('client.conf', 'known_hosts'):
        write(ROOT/name, rendered[name])
    write(UNIT, unit, 0o644)
    os.chmod(UNIT, 0o644)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=20)
    result = {'schema': 1, 'installed': True, 'started': False,
              'unit_sha256': hashlib.sha256(unit.encode()).hexdigest()}
    write(ROOT/'client-install-result.json', json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    # A public-only JSON stream avoids transferring the private key or a file
    # containing credentials. Source code is installed separately before use.
    import sys
    install(json.load(sys.stdin))
