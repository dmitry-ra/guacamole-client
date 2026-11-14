#!/usr/bin/env python3
"""Run the credential-free probe in one exact existing remote container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

import probe_rdp


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--container', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--endpoint', action='append', nargs=4, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', args.ssh_host):
        raise ValueError('Literal SSH host alias required')
    if not re.fullmatch(r'[a-f0-9]{64}', args.container):
        raise ValueError('Full immutable existing container ID required')
    source = probe_rdp.ipv4(args.source)
    endpoints = [probe_rdp.endpoint(value) for value in args.endpoint]
    if not 1 <= len(endpoints) <= 8 or len({value[0] for value in endpoints}) != len(endpoints):
        raise ValueError('One through eight uniquely labeled endpoints required')
    if not args.directory.is_absolute() or '..' in args.directory.parts:
        raise ValueError('New absolute private evidence directory required')
    args.directory.mkdir(mode=0o700)
    os.chmod(args.directory, 0o700)
    payload = Path(probe_rdp.__file__).read_bytes()
    remote = ['sudo', '-n', '/usr/bin/podman', 'exec', '-i', '--user', '2002',
              args.container, '/usr/bin/python3', '-B', '-', '--source', source]
    for selected in endpoints:
        remote.extend(['--endpoint', *map(str, selected)])
    command = ['/usr/bin/ssh', '-T', '-oBatchMode=yes', '-oConnectTimeout=10',
               '-oControlMaster=no', '-oControlPath=none', '-oControlPersist=no',
               args.ssh_host, shlex.join(remote)]
    receipt = dict(schema=1, phase='intent', container_id=args.container,
                   command=command, source_sha256=hashlib.sha256(payload).hexdigest(),
                   credentials_used=False, started_at=time.time())
    write(args.directory / 'probe-source.py', payload)
    write(args.directory / 'intent.json', json.dumps(receipt, sort_keys=True).encode() + b'\n')
    try:
        result = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=8 * len(endpoints) + 25, check=False)
        write(args.directory / 'stdout.json', result.stdout[:131072])
        write(args.directory / 'stderr.log', result.stderr[:131072])
        receipt.update(returncode=result.returncode,
                       stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                       stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
        if len(result.stdout) > 131072 or len(result.stderr) > 131072:
            raise RuntimeError('Probe command output exceeds bound')
        response = json.loads(result.stdout)
        if (response.get('schema') != 1 or response.get('uid') != 2002
                or response.get('credentials_used') is not False
                or response.get('desktop_authenticated') is not False):
            raise RuntimeError('Unexpected probe identity or credential contract')
        receipt.update(response=response, phase='complete', passed=response['passed'] is True
                       and result.returncode == 0)
    except Exception as error:
        receipt.update(phase='failed', passed=False, error_type=type(error).__name__)
    receipt['finished_at'] = time.time()
    write(args.directory / 'receipt.json', json.dumps(receipt, sort_keys=True).encode() + b'\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
