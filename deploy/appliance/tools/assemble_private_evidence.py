#!/usr/bin/env python3
"""Bind reviewed primary receipts for private rehearsal, never public admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Root operator review required')
    image = host.image_id(args.image)
    host.directory(args.directory, mode=0o700)
    names = ('build', 'auth', 'synthetic-rdp', 'kernel', 'cold-backup',
             'rehearsal-restore', 'rehearsal-migration', 'promotion-restore',
             'promotion-migration', 'network-normal', 'transport')
    values, hashes = {}, {}
    for name in names:
        raw = host.network.protected_read(args.directory/(name+'.json'))
        hashes[name+'.json'] = hashlib.sha256(raw).hexdigest()
        values[name] = json.loads(raw, object_pairs_hook=host.catalog.unique_object)
    def require(value):
        if not value:
            raise RuntimeError('Primary private-rehearsal evidence does not match')
    require(values['build']['image_id'] == image)
    for name in ('auth', 'synthetic-rdp'):
        require(values[name]['image'] == image[7:] and values[name]['passed'] is True
                and values[name]['cleanup_verified'] is True)
    require(values['kernel']['passed'] is True and values['kernel']['cleanup_verified'] is True)
    require(values['cold-backup']['phase'] == 'ready' and values['cold-backup']['operation'] == 'backup')
    for name in ('rehearsal-restore', 'promotion-restore'):
        require(values[name]['phase'] == 'ready' and values[name]['operation'] == 'restore'
                and values[name]['legacy_receipt_archived'] is True
                and values[name]['manifest_sha256'] == values['cold-backup']['manifest_sha256'])
    for name in ('rehearsal-migration', 'promotion-migration'):
        value = values[name]
        require(value['image'] == image and value['passed'] is True and value['cleanup_verified'] is True
                and value['migration']['identity_unchanged'] is True and value['migration']['enrolled'] is True)
    require(values['rehearsal-migration']['migration']['identity_sha256']
            == values['promotion-migration']['migration']['identity_sha256'])
    require(values['network-normal']['passed'] is True and values['network-normal']['http_reply'] is True
            and values['network-normal']['cleanup_verified'] is True)
    require(values['transport']['passed'] is True and values['transport']['authenticated_publickey'] is True
            and values['transport']['shell_denied'] is True)
    result = {'schema': 1, 'scope': 'private restored rehearsal only',
              'public_admitted': False, 'image_id': image, 'primary_receipts': hashes,
              'windows_NLA_acceptance': 'pending', 'SSH_tmux_acceptance': 'pending',
              'host_sources': {name: hashlib.sha256(host.network.protected_read(host.ROOT/name)).hexdigest()
                               for name in ('host.py', 'network.py', 'network_service.py', 'catalog.py')}}
    path = args.directory/'review.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(result, out, sort_keys=True); out.write('\n'); out.flush(); os.fsync(out.fileno())
    print(json.dumps({'scope': result['scope'], 'review_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
