#!/usr/bin/env python3
"""Prepare/review/apply an additive transport upgrade; never activate services."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import time

import install_transport_server as server
import prepare_instance as files
import render_transport as renderer

ROOT = Path('/etc/portal-rdp-transport')
SSHD = Path('/etc/ssh/sshd_config')
UNIT = Path('/etc/systemd/system/portal-rdp-transport.service')
HOST_KEY = Path('/etc/ssh/ssh_host_ed25519_key.pub')
USER = 'portal-rdp-tunnel'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(raw):
    return json.loads(raw, object_pairs_hook=files.catalog.unique_object)


def public_file(path, limit=131072):
    """Root-owned public configuration, with the same protected ancestry rule."""
    files.protected_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or info.st_size > limit):
            raise ValueError('Bounded root-owned configuration required')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Configuration exceeds bound')
    return raw, {'sha256': sha(raw), 'uid': info.st_uid, 'gid': info.st_gid,
                 'mode': stat.S_IMODE(info.st_mode), 'device': info.st_dev,
                 'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def extension(old, new):
    before, after = renderer.normalize(old), renderer.normalize(new)
    if new['schema'] != 2:
        raise ValueError('Upgrade destination requires schema2')
    for key in ('client_address', 'server_address', 'server_port', 'public_key', 'host_key'):
        if before[key] != after[key]:
            raise ValueError('Existing transport identity and peer must be retained')
    if (len(after['forwards']) <= len(before['forwards'])
            or any(item not in after['forwards'] for item in before['forwards'])
            or before['forwards'][0]['listen_address'] != after['forwards'][0]['listen_address']):
        raise ValueError('Strict additive upgrade on the existing bridge required')


def client_unit(config):
    return renderer.render(config)['portal-rdp-transport.service'].replace(
        'After=network-online.target',
        'After=network-online.target guacamole-portal-network.service\nRequires=guacamole-portal-network.service')


def account_state():
    account = pwd.getpwnam(USER)
    if account.pw_shell != '/usr/sbin/nologin' or account.pw_dir != '/nonexistent':
        raise ValueError('Existing tunnel-only account required')
    return {'uid': account.pw_uid, 'gid': account.pw_gid,
            'home': account.pw_dir, 'shell': account.pw_shell}


def baseline(role, old):
    rendered = renderer.render(old)
    files.protected_directory(ROOT, private=role == 'client')
    info = ROOT.lstat()
    if stat.S_IMODE(info.st_mode) != (0o700 if role == 'client' else 0o755):
        raise ValueError('Exact existing transport directory mode required')
    expected = ({ROOT/'sshd.conf': rendered['sshd.conf'],
                 ROOT/'authorized_keys': rendered['authorized_keys']} if role == 'server' else
                {ROOT/'client.conf': rendered['client.conf'], ROOT/'known_hosts': rendered['known_hosts'],
                 UNIT: client_unit(old)})
    snapshots = {}
    for path, wanted in expected.items():
        raw, snapshots[str(path)] = public_file(path)
        if raw != wanted.encode('ascii'):
            raise ValueError('Installed transport differs from reviewed original config')
    if role == 'server':
        raw, snapshots[str(SSHD)] = public_file(SSHD)
        include = 'Include ' + str(ROOT/'sshd.conf')
        if raw.decode('ascii').splitlines().count(include) != 1:
            raise ValueError('One exact owned SSH Include required')
        key, snapshots[str(HOST_KEY)] = public_file(HOST_KEY, 4096)
        state = account_state()
    else:
        key, snapshots[str(ROOT/'identity.pub')] = public_file(ROOT/'identity.pub', 4096)
        # Never open/read/hash the private key. Bind its inode/owner/mode only.
        private = (ROOT/'identity').lstat()
        if (not stat.S_ISREG(private.st_mode) or private.st_uid != 0 or private.st_nlink != 1
                or stat.S_IMODE(private.st_mode) != 0o600):
            raise ValueError('Existing root-private identity required')
        state = {'identity': {key: getattr(private, key) for key in
                 ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}}
    if ' '.join(key.decode('ascii').split()[:2]) != old['host_key' if role == 'server' else 'public_key']:
        raise ValueError('Installed public identity differs')
    addresses = load(server.run('/usr/sbin/ip', '-j', '-4', 'address').stdout)
    if old['server_address' if role == 'server' else 'client_address'] not in {
            item['local'] for interface in addresses for item in interface.get('addr_info', [])}:
        raise ValueError('Pinned host address must remain local')
    state['files'] = snapshots
    state['root'] = {'device': info.st_dev, 'inode': info.st_ino,
                     'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}
    return state


def validate_server(candidate, config, admin):
    if admin == USER:
        raise ValueError('Separate administrative user required')
    pwd.getpwnam(admin)
    server.run('/usr/sbin/sshd', '-t', '-f', candidate)
    before = server.effective(SSHD, admin, config['client_address'])
    if server.effective(candidate, admin, config['client_address']) != before:
        raise ValueError('Administrative SSH policy changed')
    policy = dict(line.split(' ', 1) for line in
                  server.effective(candidate, USER, config['client_address']).splitlines())
    normalized = renderer.normalize(config)
    expected = {'maxsessions': '0', 'allowtcpforwarding': 'local',
                'allowstreamlocalforwarding': 'no', 'permitlisten': 'none',
                'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
                'pubkeyauthentication': 'yes', 'authenticationmethods': 'publickey',
                'authorizedkeyscommand': 'none', 'trustedusercakeys': 'none',
                'disableforwarding': 'no', 'permittty': 'no', 'x11forwarding': 'no',
                'allowagentforwarding': 'no', 'permittunnel': 'no',
                'authorizedkeysfile': str(ROOT/'authorized_keys'),
                'permitopen': ' '.join(f"{f['target_address']}:{f['target_port']}" for f in normalized['forwards'])}
    if any(policy.get(key) != value for key, value in expected.items()):
        raise ValueError('Exact restricted tunnel policy required')
    if any(key in policy for key in ('allowusers', 'denyusers', 'allowgroups', 'denygroups')):
        raise ValueError('Global access lists require separate account admission')
    return sha(before.encode())


def prepare(role, directory, old_path, new_path, admin=None):
    old_raw, new_raw = files.private_bytes(old_path, 16384), files.private_bytes(new_path, 16384)
    old, new = load(old_raw), load(new_raw)
    extension(old, new)
    state = baseline(role, old)
    if role == 'server' and not admin:
        raise ValueError('Existing administrative user required')
    files.new_directory(directory)
    files.json_new(directory/'prepare-intent.json', {'schema': 1, 'role': role,
                   'old_config_sha256': sha(old_raw), 'new_config_sha256': sha(new_raw)})
    files.write_new(directory/'old.json', old_raw)
    files.write_new(directory/'new.json', new_raw)
    rendered = renderer.render(new)
    candidates = ({ROOT/'sshd.conf': rendered['sshd.conf'], ROOT/'authorized_keys': rendered['authorized_keys']}
                  if role == 'server' else {ROOT/'client.conf': rendered['client.conf']})
    plan_files = {}
    for index, (path, text) in enumerate(candidates.items()):
        candidate, backup = 'candidate-' + str(index), 'backup-' + str(index)
        raw, metadata = public_file(path)
        if metadata != state['files'][str(path)]:
            raise ValueError('Original changed during preparation')
        files.write_new(directory/backup, raw)
        files.write_new(directory/candidate, text.encode('ascii'))
        plan_files[str(path)] = {'candidate': candidate, 'candidate_sha256': sha(text.encode('ascii')),
                                'backup': backup, 'backup_sha256': sha(raw)}
    admin_digest = None
    if role == 'server':
        original, _ = public_file(SSHD)
        files.write_new(directory/'global-sshd-backup', original)
        candidate = directory/'sshd-candidate.conf'
        files.write_new(candidate, original.replace(
            ('Include '+str(ROOT/'sshd.conf')).encode(),
            ('Include '+str(directory/'candidate-0')).encode()))
        admin_digest = validate_server(candidate, new, admin)
    else:
        # -G parses only; it does not connect or authenticate.
        server.run('/usr/bin/ssh', '-G', '-F', directory/'candidate-0', 'portal-rdp-peer')
    if baseline(role, old) != state:
        raise ValueError('Original host state changed during preparation')
    files.json_new(directory/'plan.json', {'schema': 1, 'role': role, 'phase': 'prepared',
        'old_config_sha256': sha(old_raw), 'new_config_sha256': sha(new_raw),
        'state': state, 'files': plan_files, 'admin_user': admin,
        'admin_effective_sha256': admin_digest, 'prepared_at': time.time(), 'activation': 'external only'})


def validate_review(raw, role, reviewed_sha):
    """Recheck the bound external attestation at each mutation boundary."""
    review = load(raw)
    now = time.time()
    if (not isinstance(review, dict) or set(review) != {'schema', 'role', 'plan_sha256',
            'deployment_reference', 'portal_closed', 'sessions_cleared', 'reviewed_at', 'expires_at'}
            or type(review['schema']) is not int or review['schema'] != 1
            or review['role'] != role or review['plan_sha256'] != reviewed_sha
            or review['portal_closed'] is not True or review['sessions_cleared'] is not True
            or not isinstance(review['deployment_reference'], str)
            or not 1 <= len(review['deployment_reference']) <= 256
            or any(ord(c) < 33 or ord(c) > 126 for c in review['deployment_reference'])
            or type(review['reviewed_at']) not in (float, int)
            or type(review['expires_at']) not in (float, int)
            or not review['reviewed_at'] <= now < review['expires_at']
            or not 0 < review['expires_at'] - review['reviewed_at'] <= 300):
        raise ValueError('Fresh external closed-portal/session-clearance deployment review required')


def apply(role, directory, reviewed_sha, review_path):
    files.protected_directory(directory, private=True)
    raw = files.private_bytes(directory/'plan.json', 65536)
    if sha(raw) != reviewed_sha:
        raise ValueError('Exact independently reviewed plan SHA required')
    plan = load(raw)
    if (not isinstance(plan, dict) or set(plan) != {'schema', 'role', 'phase',
            'old_config_sha256', 'new_config_sha256', 'state', 'files', 'admin_user',
            'admin_effective_sha256', 'prepared_at', 'activation'}
            or type(plan['schema']) is not int or plan['schema'] != 1
            or plan['role'] != role or plan['phase'] != 'prepared'
            or plan['activation'] != 'external only'):
        raise ValueError('Prepared role-bound plan required')
    if any((directory/name).exists() or (directory/name).is_symlink()
           for name in ('apply-intent.json', 'result.json')):
        raise ValueError('Interrupted or completed apply is never replayed')
    old_raw = files.private_bytes(directory/'old.json', 16384)
    new_raw = files.private_bytes(directory/'new.json', 16384)
    if sha(old_raw) != plan['old_config_sha256'] or sha(new_raw) != plan['new_config_sha256']:
        raise ValueError('Prepared config binding changed')
    old, new = load(old_raw), load(new_raw)
    extension(old, new)
    if baseline(role, old) != plan['state']:
        raise ValueError('Original host state changed after review')
    review_raw = files.private_bytes(review_path, 16384)
    validate_review(review_raw, role, reviewed_sha)
    candidates = {}
    rendered = renderer.render(new)
    wanted = ({ROOT/'sshd.conf': rendered['sshd.conf'], ROOT/'authorized_keys': rendered['authorized_keys']}
              if role == 'server' else {ROOT/'client.conf': rendered['client.conf']})
    if set(plan['files']) != set(map(str, wanted)):
        raise ValueError('Exact role-specific replacement paths required')
    for index, (path, text) in enumerate(wanted.items()):
        item = plan['files'][str(path)]
        if item['candidate'] != 'candidate-'+str(index) or item['backup'] != 'backup-'+str(index):
            raise ValueError('Exact prepared artifact names required')
        content = files.private_bytes(directory/item['candidate'], 16384)
        backup = files.private_bytes(directory/item['backup'], 16384)
        if (content != text.encode('ascii') or sha(content) != item['candidate_sha256']
                or sha(backup) != item['backup_sha256']
                or sha(backup) != plan['state']['files'][str(path)]['sha256']):
            raise ValueError('Candidate or backup changed after review')
        candidates[path] = content
        if os.path.lexists(path.with_name(path.name+'.portal-upgrade-next')):
            raise ValueError('Interrupted replacement must be reviewed')
    if role == 'server':
        # Reconstruct from bound original; never trust a mutable candidate Include.
        original, _ = public_file(SSHD)
        candidate = directory/'sshd-apply-check.conf'
        validate_review(review_raw, role, reviewed_sha)
        files.write_new(candidate, original.replace(('Include '+str(ROOT/'sshd.conf')).encode(),
                        ('Include '+str(directory/'candidate-0')).encode()))
        if validate_server(candidate, new, plan['admin_user']) != plan['admin_effective_sha256']:
            raise ValueError('Administrative SSH policy changed after review')
    else:
        server.run('/usr/bin/ssh', '-G', '-F', directory/'candidate-0', 'portal-rdp-peer')
        state = dict(line.split('=', 1) for line in server.run('/usr/bin/systemctl', 'show',
            'portal-rdp-transport.service', '--no-pager', '--property=LoadState,ActiveState,MainPID').stdout.splitlines())
        if state != {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}:
            raise ValueError('Client transport must be externally stopped with no live process')
    validate_review(review_raw, role, reviewed_sha)
    files.write_new(directory/'apply-intent.json', json.dumps({'schema': 1, 'role': role,
                    'plan_sha256': reviewed_sha, 'maintenance_review_sha256': sha(review_raw)}).encode('ascii'))
    try:
        if baseline(role, old) != plan['state']:
            raise ValueError('Host changed before replacement')
        for path, content in candidates.items():
            if public_file(path)[1] != plan['state']['files'][str(path)]:
                raise ValueError('Original file changed before replacement')
            temporary = path.with_name(path.name+'.portal-upgrade-next')
            validate_review(review_raw, role, reviewed_sha)
            files.write_new(temporary, content)
            info = plan['state']['files'][str(path)]
            validate_review(review_raw, role, reviewed_sha)
            os.chown(temporary, info['uid'], info['gid'])
            validate_review(review_raw, role, reviewed_sha)
            os.chmod(temporary, info['mode'])
            validate_review(review_raw, role, reviewed_sha)
            os.replace(temporary, path)
            files.fsync_directory(path.parent)
        actual = baseline(role, new)
        for path, info in plan['state']['files'].items():
            if path not in plan['files'] and actual['files'][path] != info:
                raise ValueError('Unchanged transport binding changed during replacement')
        if role == 'server':
            if validate_server(SSHD, new, plan['admin_user']) != plan['admin_effective_sha256']:
                raise ValueError('Installed administrative policy differs')
        validate_review(review_raw, role, reviewed_sha)
        files.json_new(directory/'result.json', {'schema': 1, 'phase': 'installed', 'role': role,
                       'activated': False, 'plan_sha256': reviewed_sha,
                       'files': {str(path): sha(raw) for path, raw in candidates.items()}})
    except Exception as error:
        # Failure evidence must remain writable after expiry; no installed-file
        # mutation or success claim is allowed on an expired review.
        files.json_new(directory/'result.json', {'schema': 1, 'phase': 'failed', 'role': role,
                       'error_type': type(error).__name__, 'activated': False})
        raise


def main(role='server'):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'apply'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--old-config', type=Path)
    parser.add_argument('--new-config', type=Path)
    parser.add_argument('--admin-user')
    parser.add_argument('--reviewed-plan-sha256')
    parser.add_argument('--maintenance-review', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    def expired(*unused):
        raise TimeoutError('Upgrade exceeded60seconds')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(60)
    # Serialize this product's upgrade wrappers. The file is never unlinked.
    lock = os.open('/run/portal-transport-upgrade.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError('Protected transport upgrade lock required')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    directory = files.literal(args.directory)
    if args.operation == 'prepare':
        if not args.old_config or not args.new_config or args.reviewed_plan_sha256 or args.maintenance_review:
            raise ValueError('Prepare requires only original/new config and server administrative user')
        prepare(role, directory, args.old_config, args.new_config, args.admin_user)
    else:
        if not args.reviewed_plan_sha256 or not args.maintenance_review or args.old_config or args.new_config or args.admin_user:
            raise ValueError('Apply requires exact reviewed plan SHA and maintenance review only')
        apply(role, directory, args.reviewed_plan_sha256, args.maintenance_review)
    signal.alarm(0)
    print(json.dumps({'role': role, 'operation': args.operation, 'activated': False}))


if __name__ == '__main__':
    main()
