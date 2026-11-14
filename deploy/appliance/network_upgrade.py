"""Narrow additive SSH network proof contract; never changes host resources."""
import hashlib
import json
import math
from pathlib import Path
import re
import os
import stat

import catalog
import network

BINDING_KEYS = {'schema', 'podman_network', 'config_sha256', 'network_sha256', 'policy_hash'}
PROOF_KEYS = {'schema', 'operation', 'plan_sha256', 'files', 'old_binding', 'new_binding',
              'network_id', 'creation_boot_id', 'upgrade_boot_id', 'review', 'finished_at', 'evidence'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(raw):
    return json.loads(raw, object_pairs_hook=catalog.unique_object)


def hash_value(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('Exact SHA256 required')
    return value


def boot(value):
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is None:
        raise ValueError('Exact boot identity required')
    return value


def private_read(path, limit=128*1024):
    """Historical proofs and archives remain private single-link files."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute protected proof path without traversal required')
    network.secure_directory(path.parent)
    raw = network.protected_read(path, limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit
                or stream.read(limit+1) != raw):
            raise ValueError('Unchanged bounded private proof archive required')
    return raw


def extension(old_network, new_network, old_catalog, new_catalog):
    """Only append SSH targets at new gateway-local tuples; retain old records."""
    before, after = network.parse_config(old_network), network.parse_config(new_network)
    old, new = catalog.parse(old_catalog), catalog.parse(new_catalog)
    if (new_catalog['schema_version'] != 2 or any(target.protocol != 'rdp' for target in old.targets)
            or old_catalog['portal'] != new_catalog['portal']
            or set(old_catalog['targets']) - set(new_catalog['targets'])
            or any(new_catalog['targets'][key] != value for key, value in old_catalog['targets'].items())):
        raise ValueError('Existing portal and every exact target record must be retained')
    added = [target for target in new.targets if target.alias not in old_catalog['targets']]
    additions = set(after.local_endpoints) - set(before.local_endpoints)
    if (not added or not additions or set(before.local_endpoints) - set(after.local_endpoints)
            or {key: value for key, value in old_network.items() if key != 'local_endpoints'} !=
               {key: value for key, value in new_network.items() if key != 'local_endpoints'}
            or any(target.protocol != 'ssh' or target.hostname != before.gateway_ipv4 for target in added)
            or {(target.hostname, target.port) for target in added} != additions
            or set(old.endpoints()) & additions):
        raise ValueError('Strict new gateway-local SSH tuples on the unchanged network required')
    p, q = network.policy(before, old), network.policy(after, new)
    if p['forwarded'] != q['forwarded']:
        raise ValueError('Forwarded destinations must remain unchanged')
    return p, q


def binding(value, catalog_raw, network_raw, policy):
    if (not isinstance(value, dict) or set(value) != BINDING_KEYS
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['podman_network'], str)
            or re.fullmatch('[a-z][a-z0-9_.-]{0,95}', value['podman_network']) is None
            or value['podman_network'] in ('host', 'none', 'bridge', 'unconfined')
            or value['config_sha256'] != sha(catalog_raw)
            or value['network_sha256'] != sha(network_raw)
            or value['policy_hash'] != network.digest(policy)):
        raise ValueError('Exact selected catalog/network/policy binding required')
    return value


def review(value, plan_sha, now, *, check_files=True):
    keys = {'schema', 'operation', 'plan_sha256', 'portal_closed', 'sessions_cleared',
            'closed_route', 'session_census', 'reviewed_at', 'expires_at'}
    if (not isinstance(value, dict) or set(value) != keys or type(value['schema']) is not int
            or value['schema'] != 1 or value['operation'] != 'add-local-ssh'
            or value['plan_sha256'] != hash_value(plan_sha)
            or value['portal_closed'] is not True or value['sessions_cleared'] is not True
            or any(type(value[key]) not in (int, float) or not math.isfinite(value[key])
                   for key in ('reviewed_at', 'expires_at'))
            or not value['reviewed_at'] <= now < value['expires_at']
            or not 0 < value['expires_at'] - value['reviewed_at'] <= 300):
        raise ValueError('Fresh exact closed-route/session maintenance review required')
    for key in ('closed_route', 'session_census'):
        entry = value[key]
        if (not isinstance(entry, dict) or set(entry) != {'path', 'sha256'}
                or not isinstance(entry['path'], str) or not Path(entry['path']).is_absolute()
                or '..' in Path(entry['path']).parts):
            raise ValueError('Exact protected maintenance evidence required')
        hash_value(entry['sha256'])
        if check_files and sha(network.protected_read(entry['path'])) != entry['sha256']:
            raise ValueError('Exact protected maintenance evidence required')
    return value


def definition_binding(receipt, selected):
    """Resolve old resource labels only through one complete immutable proof."""
    if receipt is None:
        return selected
    present = {'definition_binding', 'upgrade_proof'} & set(receipt)
    if not present:
        return selected
    if present != {'definition_binding', 'upgrade_proof'}:
        raise ValueError('Complete reviewed network upgrade proof required')
    ref = receipt['upgrade_proof']
    if not isinstance(ref, dict) or set(ref) != {'path', 'sha256'}:
        raise ValueError('Exact upgrade proof reference required')
    raw = private_read(ref['path'])
    if sha(raw) != hash_value(ref['sha256']):
        raise ValueError('Upgrade proof changed')
    proof = load(raw)
    if (not isinstance(proof, dict) or set(proof) != PROOF_KEYS or type(proof['schema']) is not int
            or proof['schema'] != 1 or proof['operation'] != 'add-local-ssh'
            or proof['new_binding'] != selected or receipt.get('binding') != selected
            or proof['old_binding'] != receipt['definition_binding']
            or proof['network_id'] != hash_value(receipt.get('network_id'))
            or type(proof['finished_at']) not in (int, float) or not math.isfinite(proof['finished_at'])):
        raise ValueError('Upgrade proof is not bound to this selected owned network')
    boot(proof['creation_boot_id']); boot(proof['upgrade_boot_id']); hash_value(proof['plan_sha256'])
    names = {'old-network.json', 'new-network.json', 'old-catalog.json', 'new-catalog.json',
             'old-bootstrap.json', 'old-firewall.json'}
    if not isinstance(proof['files'], dict) or set(proof['files']) != names:
        raise ValueError('Complete original network archives required')
    directory = Path(ref['path']).parent
    if sha(private_read(directory/'plan.json', 256*1024)) != proof['plan_sha256']:
        raise ValueError('Reviewed network plan changed')
    archived = {}
    for name in names:
        raw = private_read(directory / name)
        if sha(raw) != hash_value(proof['files'][name]):
            raise ValueError('Network upgrade archive changed')
        archived[name] = raw
    p, q = extension(*(load(archived[name]) for name in
        ('old-network.json', 'new-network.json', 'old-catalog.json', 'new-catalog.json')))
    before = binding(proof['old_binding'], archived['old-catalog.json'], archived['old-network.json'], p)
    after = binding(proof['new_binding'], archived['new-catalog.json'], archived['new-network.json'], q)
    original, firewall = load(archived['old-bootstrap.json']), load(archived['old-firewall.json'])
    if (before['podman_network'] != after['podman_network']
            or original.get('schema') != 1 or original.get('phase') != 'ready'
            or original.get('binding') != before or original.get('network_id') != proof['network_id']
            or original.get('boot_id') != proof['creation_boot_id']
            or {'definition_binding', 'upgrade_proof'} & set(original)
            or firewall.get('phase') != 'ready' or firewall.get('policy') != p
            or firewall.get('policy_hash') != network.digest(p)
            or firewall.get('boot_id') != proof['upgrade_boot_id']):
        raise ValueError('Original ready ownership and firewall archives required')
    hash_value(firewall.get('guard_hash'))
    # Historical approval remains valid on later boots. Its freshness is tested
    # at completion time, independently of the current ready receipt boot ID.
    review(proof['review'], proof['plan_sha256'], proof['finished_at'], check_files=False)
    if not isinstance(proof['evidence'], dict) or set(proof['evidence']) != {'closed_route', 'session_census'}:
        raise ValueError('Archived maintenance evidence required')
    for key in ('closed_route', 'session_census'):
        checksum = hash_value(proof['evidence'][key])
        if (checksum != proof['review'][key]['sha256']
                or sha(private_read(directory/(key+'-evidence'))) != checksum):
            raise ValueError('Historical maintenance evidence changed')
    return before
