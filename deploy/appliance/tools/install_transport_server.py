#!/usr/bin/env python3
"""Install the explicitly configured tunnel-only account on its pinned server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time

import render_transport

ROOT = Path('/etc/portal-rdp-transport')
SSHD = Path('/etc/ssh/sshd_config')
USER = 'portal-rdp-tunnel'


def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True,
                          text=True, timeout=20)


def write(path, value, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as out:
        out.write(value); out.flush(); os.fsync(out.fileno())


def effective(path, user, address):
    return run('/usr/sbin/sshd', '-T', '-f', path, '-C',
               'user='+user+',host=peer.invalid,addr='+address).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--admin-user', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.record.is_absolute():
        raise RuntimeError('Root and absolute new evidence directory required')
    for path in (*SSHD.parents, SSHD, *args.record.parent.parents, args.record.parent):
        meta = path.lstat()
        if (meta.st_uid != 0 or meta.st_mode & 0o022
                or not (stat.S_ISDIR(meta.st_mode) or path == SSHD and stat.S_ISREG(meta.st_mode))):
            raise RuntimeError('Protected root-owned installation ancestry required')
    os.umask(0o077)
    config = json.loads(args.config.read_bytes())
    rendered = render_transport.render(config)
    if args.admin_user == USER:
        raise ValueError('Separate existing administrative user required')
    pwd.getpwnam(args.admin_user)
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise RuntimeError('Account already exists; refuse replay')
    if ROOT.exists() or ROOT.is_symlink():
        raise RuntimeError('Server transport directory already exists')
    host_key = ' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2])
    if host_key != config['host_key']:
        raise RuntimeError('Pinned server host key mismatch')
    addresses = json.loads(run('/usr/sbin/ip', '-j', '-4', 'address').stdout)
    if config['server_address'] not in {a['local'] for interface in addresses for a in interface.get('addr_info', [])}:
        raise RuntimeError('Pinned server address is not local')
    original = SSHD.read_text()
    if any(line.strip().lower().startswith('match ') for line in original.splitlines()
           if not line.lstrip().startswith('#')):
        raise RuntimeError('Existing Match blocks require separate placement review')
    args.record.mkdir(mode=0o700)
    snippet = args.record/'sshd-block.conf'
    write(snippet, rendered['sshd.conf'])
    candidate = args.record/'sshd-candidate.conf'
    write(candidate, original+'\nInclude '+str(snippet)+'\n')
    run('/usr/sbin/sshd', '-t', '-f', candidate)
    before = effective(SSHD, args.admin_user, config['client_address'])
    after = effective(candidate, args.admin_user, config['client_address'])
    if before != after:
        raise RuntimeError('Administrative SSH policy changed')
    policy = dict(line.split(' ', 1) for line in effective(candidate, USER, config['client_address']).splitlines())
    expected = {'maxsessions': '0', 'allowtcpforwarding': 'local',
                'allowstreamlocalforwarding': 'no', 'permitlisten': 'none',
                'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
                'pubkeyauthentication': 'yes', 'usepam': 'yes',
                'authorizedkeyscommand': 'none', 'trustedusercakeys': 'none',
                'disableforwarding': 'no',
                'permitopen': str(config['target_address'])+':'+str(config['target_port'])}
    if any(policy.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Tunnel account policy mismatch')
    if any(key in policy for key in ('allowusers', 'denyusers', 'allowgroups', 'denygroups')):
        raise RuntimeError('Global access lists require separate account admission review')
    original_sha = hashlib.sha256(original.encode()).hexdigest()
    backup = Path(str(SSHD)+'.bak-portal-'+str(time.time_ns()))
    write(args.record/'intent.json', json.dumps({'schema': 1, 'original_sshd_sha256': original_sha,
          'admin_effective_sha256': hashlib.sha256(before.encode()).hexdigest(),
          'server_host_key_verified': True, 'backup': str(backup), 'started_at': time.time()}))
    # Preserve the actual global file before changing it. The account has no
    # usable authentication until its restricted key and SSH block are installed.
    if hashlib.sha256(SSHD.read_bytes()).hexdigest() != original_sha:
        raise RuntimeError('SSH configuration changed during review')
    run('/usr/bin/cp', '--preserve=mode,ownership,timestamps', SSHD, backup)
    run('/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
        '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', USER)
    ROOT.mkdir(mode=0o755)
    write(ROOT/'sshd.conf', rendered['sshd.conf'], 0o644)
    write(ROOT/'authorized_keys', rendered['authorized_keys'], 0o644)
    # umask is private by default; only these public server files are traversed
    # by the unprivileged sshd key reader.
    os.chmod(ROOT, 0o755)
    os.chmod(ROOT/'authorized_keys', 0o644)
    os.chmod(ROOT/'sshd.conf', 0o644)
    installed = original+'\nInclude '+str(ROOT/'sshd.conf')+'\n'
    final = args.record/'sshd-final.conf'
    write(final, installed)
    run('/usr/sbin/sshd', '-t', '-f', final)
    if effective(final, args.admin_user, config['client_address']) != before:
        raise RuntimeError('Installed administrative policy differs')
    temporary = SSHD.with_name('sshd_config.portal-next')
    write(temporary, installed, 0o600)
    os.chmod(temporary, SSHD.stat().st_mode & 0o777)
    if hashlib.sha256(SSHD.read_bytes()).hexdigest() != original_sha:
        raise RuntimeError('SSH configuration changed before replacement')
    os.replace(temporary, SSHD)
    run('/usr/sbin/sshd', '-t')
    run('/usr/bin/systemctl', 'reload', 'ssh.service')
    run('/usr/bin/systemctl', 'is-active', 'ssh.service')
    result = {'schema': 1, 'installed': True, 'account_uid': pwd.getpwnam(USER).pw_uid,
              'backup': str(backup), 'admin_effective_unchanged': True,
              'installed_sshd_sha256': hashlib.sha256(installed.encode()).hexdigest(),
              'at': time.time()}
    write(args.record/'result.json', json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
