#!/usr/bin/env python3
"""Root-only stopped-candidate update of one catalog target secret from stdin."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog
import network
import prepare_instance as files

CONFIG = Path('/etc/guacamole-portal/config.json')
SECRETS = Path('/var/lib/guacamole-portal/secrets')
LOCK = Path('/var/lib/guacamole-portal/host/lock')
FORBIDDEN = (Path('/etc/guacamole-portal'), SECRETS, Path('/var/lib/guacamole-portal/data'), Path('/run/guacamole-portal'))


def inactive():
    p = subprocess.run(['/usr/bin/systemctl','show','guacamole-portal.service',
        '--property=LoadState','--property=ActiveState','--property=SubState','--property=MainPID'],
        capture_output=True, check=True, timeout=5)
    fields = dict(line.split('=',1) for line in p.stdout.decode('ascii').splitlines() if '=' in line)
    if fields != {'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0'}:
        raise ValueError('Candidate service must be inactive')
    p = subprocess.run(['/usr/bin/podman','ps','--all','--filter=label=guacamole.portal=1','--format={{.ID}}'],
                       capture_output=True, check=True, timeout=5)
    if p.stdout.strip():
        raise ValueError('Owned candidate container exists')
    p = subprocess.run(['/usr/bin/podman','container','exists','guacamole-portal'],
                       capture_output=True, timeout=5)
    if p.returncode != 1:
        raise ValueError('Candidate container name is not absent')


def target(args):
    raw = network.protected_read(CONFIG)
    meta = CONFIG.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
        raise ValueError('Single-link protected config required')
    if hashlib.sha256(raw).hexdigest() != args.expected_config_sha256:
        raise ValueError('Config changed')
    registry = catalog.parse(json.loads(raw, object_pairs_hook=catalog.unique_object))
    selected = registry.target(args.alias)
    if selected.username != args.expected_username:
        raise ValueError('Target identity changed')
    # A shared filename would mutate another target as well.
    if sum(t.password_file == selected.password_file for t in registry.targets) != 1:
        raise ValueError('Connection-specific secret required')
    return SECRETS / selected.password_file


def stable(meta):
    return tuple(getattr(meta, field) for field in ('st_uid','st_gid','st_mode','st_nlink',
                 'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))


def update(args, incoming, report):
    if os.geteuid() != 0:
        raise ValueError('Root required')
    if not re.fullmatch('[a-f0-9]{64}', args.expected_config_sha256):
        raise ValueError('Exact config digest required')
    case = files.literal(args.directory)
    if any(case == root or root in case.parents or case in root.parents for root in FORBIDDEN):
        raise ValueError('Separate private case required')
    files.protected_directory(LOCK.parent, private=True)
    lock = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(lock)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1
                or stat.S_IMODE(meta.st_mode) != 0o600):
            raise ValueError('Owned host lock required')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inactive()
        destination = target(args)
        files.protected_directory(SECRETS, private=True)
        previous = files.private_bytes(destination, 513)
        original = destination.lstat()
        replacement = files.windows_password(incoming.read(514))
        files.new_directory(case)  # Existing/uncertain cases are never replayed.
        files.json_new(case/'intent.json', dict(report, expected_config_sha256=args.expected_config_sha256))
        report['phase'] = 'backup'
        files.write_new(case/'previous-secret', previous)
        # Recheck safety and stale mapping after the durable backup, before any
        # secret-directory mutation. Holding the supervisor lock excludes start.
        inactive()
        if target(args) != destination or files.private_bytes(destination,513) != previous or stable(destination.lstat()) != stable(original):
            raise ValueError('Secret or mapping changed')
        report['phase'] = 'replace_intent'
        files.json_new(case/'replace-intent.json', report)
        temp = None
        try:
            fd, name = tempfile.mkstemp(prefix='.portal-secret-update-', dir=SECRETS)
            temp = Path(name)
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(), original.st_uid, original.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(original.st_mode))
                stream.write(replacement)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, destination)
            temp = None
            report['phase'] = 'replaced'
            files.fsync_directory(SECRETS)
            if files.private_bytes(destination,513) != replacement:
                raise ValueError('Replacement verification failed')
            report.update(phase='complete', success=True)
            files.json_new(case/'result.json', report)
        finally:
            if temp is not None:
                try:
                    temp.unlink()
                except OSError:
                    pass
    finally:
        os.close(lock)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alias', required=True)
    p.add_argument('--expected-username', required=True)
    p.add_argument('--expected-config-sha256', required=True)
    p.add_argument('--directory', type=Path, required=True)
    args = p.parse_args()
    if not re.fullmatch('[a-z][a-z0-9-]{0,47}', args.alias) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}',args.expected_username):
        raise SystemExit(1)
    report = dict(phase='preconditions', success=False, alias=args.alias, username=args.expected_username)
    def expired(signum, frame):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(30)
    try:
        update(args, sys.stdin.buffer, report)
    except Exception:
        report['success'] = False
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
