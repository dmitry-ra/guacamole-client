#!/usr/bin/env python3
"""Verify pinned client-key authentication and refusal of SSH shell sessions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Root client required')
    os.umask(0o077)
    args.directory.mkdir(mode=0o700)
    command = ['/usr/bin/ssh', '-v', '-F', '/etc/portal-rdp-transport/client.conf',
               '-oClearAllForwardings=yes', '-oControlMaster=no', '-oControlPath=none',
               '-T', 'portal-rdp-peer', '/bin/true']
    with (args.directory/'intent.json').open('x') as out:
        json.dump({'test': 'restricted public-key authentication, no shell session'}, out)
        out.flush(); os.fsync(out.fileno())
    result = subprocess.run(command, capture_output=True, timeout=20)
    # Verbose SSH diagnostics contain public fingerprints and transport metadata,
    # never private-key bytes or passwords. Keep them private for reconciliation.
    with (args.directory/'ssh.stderr').open('xb') as out:
        out.write(result.stderr)
    authenticated = b'Authenticated to ' in result.stderr and b'using "publickey"' in result.stderr
    # OpenSSH reports MaxSessions0 as SSH_OPEN_CONNECT_FAILED on this server,
    # rather than SSH_OPEN_ADMINISTRATIVELY_PROHIBITED. Both refuse the session.
    denied = (b'channel 0: new session' in result.stderr
              and b'channel 0: open failed:' in result.stderr)
    passed = authenticated and denied and result.returncode == 255 and not result.stdout
    receipt = {'passed': passed, 'authenticated_publickey': authenticated,
               'shell_denied': denied, 'returncode': result.returncode,
               'config_sha256': hashlib.sha256(Path('/etc/portal-rdp-transport/client.conf').read_bytes()).hexdigest()}
    with (args.directory/'receipt.json').open('x') as out:
        json.dump(receipt, out); out.flush(); os.fsync(out.fileno())
    print(json.dumps(receipt))
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
