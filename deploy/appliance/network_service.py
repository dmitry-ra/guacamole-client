#!/usr/bin/env python3
"""Explicit dedicated-network preparation and conservative boot reconciliation."""
import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time

import catalog
import host
import network
import network_upgrade

STATE = host.PERSIST / 'network-bootstrap'
RECEIPT = STATE / 'state.json'
IP = '/usr/sbin/ip'
BIND_LABEL = 'guacamole.portal.bootstrap'
RELEASE_KEYS = {'schema', 'podman_network', 'config_sha256', 'network_sha256'}


def selection():
    """Accept the four-key provisional release or the strict final release."""
    release = host.read_json(host.RELEASE)
    if isinstance(release, dict) and set(release) == RELEASE_KEYS:
        # Reuse the final release validator without opening any admission files.
        host.parse_release(dict(release, image_id='sha256:' + '0' * 64,
            acceptance_evidence_path='/var/lib/portal-acceptance/pending.json',
            acceptance_evidence_sha256='0' * 64, backend_loopback_port=10080,
            apparmor_profile='portal-pending',
            apparmor_profile_path='/etc/apparmor.d/portal-pending',
            apparmor_profile_sha256='0' * 64))
    else:
        host.parse_release(release)
    config_raw = network.protected_read(host.CONFIG)
    network_raw = network.protected_read(host.NETWORK)
    if (host.sha(config_raw) != release['config_sha256']
            or host.sha(network_raw) != release['network_sha256']):
        raise RuntimeError('Pinned network/catalog input changed')
    cfg = network.parse_config(json.loads(network_raw, object_pairs_hook=catalog.unique_object))
    targets = catalog.parse(json.loads(config_raw, object_pairs_hook=catalog.unique_object))
    p = network.policy(cfg, targets)
    binding = {key: release[key] for key in RELEASE_KEYS}
    binding['policy_hash'] = network.digest(p)
    return release['podman_network'], cfg, p, binding


def engine(*args):
    if args[:2] != ('network', 'create'):
        return host.engine(*args, timeout=10)
    result = host.engine(*args, timeout=10, check=False)
    if result.returncode:
        # Network-only argv contains no credentials. Never print raw diagnostics.
        host.write(STATE / ('engine-failure-' + str(time.time_ns()) + '.json'),
                   dict(schema=1, argv=list(args), returncode=result.returncode,
                        stderr=result.stderr[:8192].decode('utf-8', errors='replace'),
                        stderr_sha256=host.sha(result.stderr),
                        stderr_truncated=len(result.stderr) > 8192))
        raise RuntimeError('Network creation failed; private diagnostic retained')
    return result


def ip(*args):
    return host.command([IP, *args], timeout=10)


def network_create_args(name, cfg, binding):
    return ['network', 'create', '--driver=bridge', '--disable-dns',
            '--interface-name=' + cfg.bridge, '--subnet=' + cfg.subnet_ipv4,
            '--gateway=' + cfg.gateway_ipv4, '--label=guacamole.portal=1',
            '--label=' + BIND_LABEL + '=' + network.digest(binding), name]


def inventory():
    rows = json.loads(engine('network', 'ls', '--format=json').stdout)
    if not isinstance(rows, list):
        raise RuntimeError('Network inventory unavailable')
    values = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError('Invalid network inventory')
        identity = host.identifier(row.get('id'))
        value = host.one(engine('network', 'inspect', identity).stdout)
        if value.get('id') != identity:
            raise RuntimeError('Network inventory identity changed')
        values.append(value)
    if len({v['id'] for v in values}) != len(values):
        raise RuntimeError('Duplicate network identity')
    return values


def inspect_network(name, cfg, binding, previous):
    """No adoption: an existing matching name still needs its root receipt."""
    definition = network_upgrade.definition_binding(previous, binding)
    matches = []
    for value in inventory():
        if value.get('name') == name:
            matches.append(value)
            continue
        if value.get('network_interface') == cfg.bridge:
            raise RuntimeError('Declared bridge belongs to another network')
        for subnet in value.get('subnets', []):
            foreign = ipaddress.ip_network(subnet['subnet'], strict=True)
            if foreign.version == 4 and foreign.overlaps(ipaddress.ip_network(cfg.subnet_ipv4)):
                raise RuntimeError('Declared subnet overlaps another network')
    if not matches:
        if previous is not None:
            raise RuntimeError('Previously owned network definition disappeared')
        return None
    if len(matches) != 1 or previous is None:
        raise RuntimeError('Existing network is not owned by a ready bootstrap receipt')
    value = matches[0]
    if (value.get('id') != previous.get('network_id')
            or value.get('driver') != 'bridge'
            or value.get('network_interface') != cfg.bridge
            or value.get('subnets') != [{'subnet': cfg.subnet_ipv4, 'gateway': cfg.gateway_ipv4}]
            or value.get('labels', {}).get(host.LABEL) != '1'
            or value.get('labels', {}).get(BIND_LABEL) != network.digest(definition)
            or value.get('ipv6_enabled') is not False
            or value.get('internal') is not False
            or value.get('dns_enabled') is not False
            or value.get('options', {}) not in ({}, None)):
        raise RuntimeError('Owned network definition changed')
    return value['id']


def empty(name, cfg):
    members = engine('ps', '--all', '--no-trunc', '--filter=network=' + name,
                     '--format={{.ID}}').stdout.decode().splitlines()
    if members:
        raise RuntimeError('Dedicated network already has consumers')
    # Check all links rather than relying on Podman membership alone.
    links = json.loads(ip('-j', 'link', 'show').stdout)
    bridge = next((link for link in links if link.get('ifname') == cfg.bridge), None)
    if bridge and any(link.get('master') in (cfg.bridge, bridge.get('ifindex')) for link in links):
        raise RuntimeError('Dedicated bridge already has attached links')


def inspect_bridge(cfg, binding, previous):
    definition = network_upgrade.definition_binding(previous, binding)
    links = json.loads(ip('-j', '-d', 'link', 'show').stdout)
    values = [link for link in links if link.get('ifname') == cfg.bridge]
    if not values:
        return False
    if len(values) != 1 or previous is None:
        raise RuntimeError('Pre-existing kernel bridge collision')
    value = values[0]
    if (value.get('linkinfo', {}).get('info_kind') != 'bridge'
            or value.get('ifalias') != 'guacamole.portal=' + network.digest(definition)
            or 'UP' not in value.get('flags', [])):
        raise RuntimeError('Owned kernel bridge changed')
    addresses = json.loads(ip('-j', '-4', 'address', 'show', 'dev', cfg.bridge).stdout)
    actual = {(a['local'], a['prefixlen']) for link in addresses
              for a in link.get('addr_info', []) if a.get('family') == 'inet'}
    if actual != {(cfg.gateway_ipv4, ipaddress.ip_network(cfg.subnet_ipv4).prefixlen)}:
        raise RuntimeError('Owned bridge address changed')
    if Path('/proc/sys/net/ipv4/conf', cfg.bridge, 'route_localnet').read_text().strip() != '1':
        raise RuntimeError('Owned bridge loopback routing prerequisite changed')
    return True


def firewall_prerequisite(p, previous, current_boot):
    """Inspect only: network.py remains the firewall transaction owner."""
    if network.STATE.exists():
        network.secure_directory(network.STATE)
        fd = os.open(network.STATE / 'lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise RuntimeError('Unsafe firewall lock')
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            saved = network.saved_state()
            raw = network.protected_read(network.STATE / 'state.json') if saved is not None else None
            if raw is not None and json.loads(raw, object_pairs_hook=catalog.unique_object) != saved:
                raise RuntimeError('Firewall receipt changed during inspection')
            proof = validate_firewall_absence(p, previous, current_boot, saved)
            return {**proof, 'receipt_sha256': host.sha(raw) if raw is not None else None}
    else:
        proof = validate_firewall_absence(p, previous, current_boot, None)
        return {**proof, 'receipt_sha256': None}


def validate_firewall_absence(p, previous, current_boot, saved):
    if previous is not None and previous.get('boot_id') == current_boot:
        if (not saved or saved.get('phase') != 'ready' or saved.get('policy') != p
                or saved.get('policy_hash') != network.digest(p)
                or saved.get('boot_id') != current_boot):
            raise RuntimeError('Same-boot bridge recreation requires exact ready firewall receipt')
        host.identifier(saved.get('guard_hash'))
        # Last-container teardown may remove only the kernel bridge. Verify the
        # complete existing policy without requiring that absent bridge yet.
        network.verify(p, saved['guard_hash'])
        return dict(mode='same_boot_verified', boot_id=current_boot,
                    policy_hash=network.digest(p), guard_hash=saved['guard_hash'])
    if previous is None:
        if saved is not None:
            raise RuntimeError('Unowned pre-existing firewall receipt')
    elif (previous.get('boot_id') == current_boot
          or not saved or saved.get('phase') != 'ready' or saved.get('policy') != p
          or saved.get('policy_hash') != network.digest(p)
          or saved.get('boot_id') != previous.get('boot_id')):
        raise RuntimeError('Missing bridge requires matching prior-boot ready firewall receipt')
    if not network.all_owned_absent(p):
        raise RuntimeError('Missing bridge requires all owned firewall objects absent')
    return dict(mode='initial_absent' if previous is None else 'cold_boot_absent',
                boot_id=current_boot, policy_hash=network.digest(p))


def bridge_create(cfg, binding):
    ip('link', 'add', 'name', cfg.bridge, 'type', 'bridge')
    ip('link', 'set', 'dev', cfg.bridge, 'alias', 'guacamole.portal=' + network.digest(binding))
    ip('address', 'add', str(ipaddress.ip_interface(
        cfg.gateway_ipv4 + '/' + str(ipaddress.ip_network(cfg.subnet_ipv4).prefixlen))),
        'dev', cfg.bridge)
    host.command(['/usr/sbin/sysctl', '-w',
                  'net.ipv4.conf.' + cfg.bridge + '.route_localnet=1'], timeout=10)
    ip('link', 'set', 'dev', cfg.bridge, 'up')


def policy_command(action):
    host.command(['/usr/bin/python3', '-B', host.ROOT / 'network.py', action,
                  '--config', host.NETWORK, '--catalog', host.CONFIG], timeout=90)


def saved():
    return host.private_json(RECEIPT) if os.path.lexists(RECEIPT) else None


def archive_failed(previous, expected_hash):
    """Preserve exact failed receipt bytes, exclusively and durably."""
    return archive_receipt(previous, expected_hash, 'failed-before-recovery-' + expected_hash)


def archive_ready(previous):
    raw = network.protected_read(RECEIPT)
    return archive_receipt(previous, host.sha(raw), 'ready-before-' + str(time.time_ns()))


def archive_receipt(previous, expected_hash, name):
    raw = network.protected_read(RECEIPT)
    if (host.sha(raw) != expected_hash
            or json.loads(raw, object_pairs_hook=catalog.unique_object) != previous):
        raise RuntimeError('Reviewed failed receipt changed')
    path = STATE / (name + '.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    host.sync_directory(STATE)
    return dict(filename=path.name, sha256=expected_hash)


def recover_failed_prepare(name, cfg, p, binding, expected_hash):
    """Explicit one-shot recovery of the original definite create failure only."""
    host.identifier(expected_hash)
    previous = saved()
    current_boot = network.boot_id()
    if (not previous or set(previous) != {'schema', 'phase', 'binding', 'boot_id',
            'network_id', 'started_at', 'error_type'} or previous.get('schema') != 1
            or previous.get('phase') != 'failed' or previous.get('binding') != binding
            or previous.get('network_id') is not None
            or previous.get('error_type') != 'RuntimeError'
            or previous.get('boot_id') != current_boot):
        raise RuntimeError('Only the reviewed same-boot original create failure is recoverable')
    if host.sha(network.protected_read(RECEIPT)) != expected_hash:
        raise RuntimeError('Explicit failed receipt hash does not match')
    if inspect_network(name, cfg, binding, None) is not None:
        raise RuntimeError('Network definition must be absent before recovery')
    if not inspect_bridge(cfg, binding, previous):
        raise RuntimeError('Exact owned empty bridge required for recovery')
    empty(name, cfg)
    firewall_prerequisite(p, None, current_boot)
    archived = archive_failed(previous, expected_hash)
    receipt = dict(schema=1, phase='intent', binding=binding, boot_id=current_boot,
                   network_id=None, started_at=time.time(), recovered_from=archived)
    host.write(RECEIPT, receipt)
    install(receipt, name, cfg, p, binding, None, True, remove_bridge=True)


def reconcile(action, name, cfg, p, binding):
    previous = saved()
    current_boot = network.boot_id()
    if previous is not None:
        if (previous.get('schema') != 1 or previous.get('phase') != 'ready'
                or previous.get('binding') != binding):
            raise RuntimeError('Unresolved or changed bootstrap receipt; operator review required')
        # Validate identity syntax even if the bridge is present.
        host.identifier(previous.get('network_id'))
        if not isinstance(previous.get('boot_id'), str) or not re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', previous['boot_id']):
            raise RuntimeError('Valid recorded boot identity required')
    elif action != 'prepare':
        raise RuntimeError('Explicit prepare is required before ordinary boot')
    identity = inspect_network(name, cfg, binding, previous)
    bridge_exists = inspect_bridge(cfg, binding, previous)
    empty(name, cfg)
    if action == 'check':
        if not bridge_exists:
            raise RuntimeError('Owned bridge missing')
        policy_command('check')
        return
    recreation_proof = firewall_prerequisite(p, previous, current_boot) if not bridge_exists else None
    # Preserve prior success before recording durable intent. No partial replay.
    archived = archive_ready(previous) if previous is not None else None
    receipt = dict(schema=1, phase='intent', binding=binding, boot_id=current_boot,
                   network_id=identity, started_at=time.time())
    if archived is not None:
        receipt['previous_ready_archive'] = archived
    if previous is not None and not bridge_exists:
        receipt['bridge_recreation'] = recreation_proof
    if previous is not None and 'upgrade_proof' in previous:
        # Resource labels retain their original creation identity. Every use
        # revalidates the complete protected additive upgrade proof.
        network_upgrade.definition_binding(previous, binding)
        receipt['definition_binding'] = previous['definition_binding']
        receipt['upgrade_proof'] = previous['upgrade_proof']
    host.write(RECEIPT, receipt)
    install(receipt, name, cfg, p, binding, identity, bridge_exists,
            recreate_from=previous if not bridge_exists else None)


def install(receipt, name, cfg, p, binding, identity, bridge_exists, *, remove_bridge=False,
            recreate_from=None):
    try:
        if remove_bridge:
            # Recheck immediately before deleting only this exact working artifact.
            if inspect_network(name, cfg, binding, None) is not None:
                raise RuntimeError('Network definition appeared before recovery')
            firewall_prerequisite(p, None, receipt['boot_id'])
            empty(name, cfg)
            if not inspect_bridge(cfg, binding, receipt):
                raise RuntimeError('Owned recovery bridge disappeared')
            ip('link', 'delete', 'dev', cfg.bridge, 'type', 'bridge')
            bridge_exists = False
            if inspect_bridge(cfg, binding, None):
                raise RuntimeError('Recovery bridge deletion is unresolved')
        if identity is None:
            empty(name, cfg)
            if inspect_bridge(cfg, binding, None):
                raise RuntimeError('Network definition creation requires absent kernel bridge')
            # Managed Netavark validates subnets against all live host interfaces.
            # Create its definition before adding this bridge's gateway address.
            engine(*network_create_args(name, cfg, binding))
            # A create is issued once. Failure/unknown result never authorizes replay.
            rows = [v for v in inventory() if v.get('name') == name]
            if len(rows) != 1:
                raise RuntimeError('Created network identity is unresolved')
            receipt['network_id'] = host.identifier(rows[0].get('id'))
            host.write(RECEIPT, receipt)
            inspect_network(name, cfg, binding, receipt)
        if not bridge_exists:
            empty(name, cfg)
            if inspect_bridge(cfg, binding, None):
                raise RuntimeError('Unexpected kernel bridge before creation')
            if recreate_from is not None:
                inspect_network(name, cfg, binding, receipt)
                proof = firewall_prerequisite(p, recreate_from, receipt['boot_id'])
                if proof != receipt['bridge_recreation']:
                    raise RuntimeError('Verified firewall receipt changed before bridge recreation')
            bridge_create(cfg, network_upgrade.definition_binding(receipt, binding))
        inspect_bridge(cfg, binding, receipt)
        empty(name, cfg)
        policy_command('apply')
        policy_command('check')
        inspect_network(name, cfg, binding, receipt)
        inspect_bridge(cfg, binding, receipt)
        empty(name, cfg)
    except Exception as error:
        receipt.update(phase='failed', error_type=type(error).__name__)
        host.write(RECEIPT, receipt)
        raise
    receipt.update(phase='ready', finished_at=time.time())
    host.write(RECEIPT, receipt)


@contextlib.contextmanager
def locked(action):
    create = action != 'check'
    if create:
        host.directory(host.PERSIST, mode=0o700, create=True)
    host.directory(STATE, mode=0o700, create=create)
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY)
    fd = os.open(STATE / 'lock', flags, 0o600)
    with os.fdopen(fd, 'r+' if create else 'r') as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise RuntimeError('Private root bootstrap lock required')
        fcntl.flock(lock, (fcntl.LOCK_EX if create else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'boot', 'check', 'recover-failed-prepare'))
    parser.add_argument('--failed-receipt-sha256')
    args = parser.parse_args()
    if (args.action == 'recover-failed-prepare') != (args.failed_receipt_sha256 is not None):
        parser.error('Recovery requires --failed-receipt-sha256; other actions forbid it')
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    selected = selection()
    with locked(args.action):
        if args.action == 'recover-failed-prepare':
            recover_failed_prepare(*selected, args.failed_receipt_sha256)
        else:
            reconcile(args.action, *selected)
    print(json.dumps({'success': True, 'policy_hash': selected[3]['policy_hash']}))


if __name__ == '__main__':
    main()
