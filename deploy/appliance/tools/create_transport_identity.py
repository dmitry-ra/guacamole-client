#!/usr/bin/env python3
"""Create one root-private client transport identity; refuse every existing path."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path('/etc/portal-rdp-transport')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Root client host required')
    os.umask(0o077)
    for parent in ROOT.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Protected root-owned ancestry required')
    ROOT.mkdir(mode=0o700)
    intent = {'schema': 1, 'phase': 'intent', 'purpose': 'restricted-rdp-peer'}
    with (ROOT/'identity-intent.json').open('x') as out:
        json.dump(intent, out); out.flush(); os.fsync(out.fileno())
    subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                    '-C', 'portal-rdp-peer', '-f', str(ROOT/'identity')],
                   check=True, capture_output=True, timeout=15)
    private = (ROOT/'identity').lstat()
    if private.st_uid != 0 or stat.S_IMODE(private.st_mode) != 0o600:
        raise RuntimeError('Unexpected generated private-key permissions')
    public = ' '.join((ROOT/'identity.pub').read_text().split()[:2])
    result = {'schema': 1, 'phase': 'created', 'public_key': public,
              'public_key_sha256': hashlib.sha256(public.encode()).hexdigest()}
    with (ROOT/'identity-result.json').open('x') as out:
        json.dump(result, out); out.flush(); os.fsync(out.fileno())
    fd = os.open(ROOT, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
