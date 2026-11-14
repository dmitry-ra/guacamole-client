#!/usr/bin/env python3
"""Render a restricted host-side SSH transport; never install or connect."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re


def address(value):
    if not isinstance(value, str):
        raise ValueError('Literal IPv4 text required')
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_multicast or int(ip) == 0xffffffff:
        raise ValueError('Unicast IPv4 required')
    return str(ip)


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('TCP port required')
    return value


def normalize(config):
    keys = {'schema', 'client_address', 'server_address', 'server_port', 'public_key', 'host_key'}
    forward_keys = {'listen_address', 'listen_port', 'target_address', 'target_port'}
    if not isinstance(config, dict) or type(config.get('schema')) is not int:
        raise ValueError('Exact transport schema required')
    schema = config['schema']
    expected = keys | (forward_keys if schema == 1 else {'forwards'})
    if schema not in (1, 2) or set(config) != expected:
        raise ValueError('Exact transport schema required')
    c = dict(config)
    for field in ('client_address', 'server_address'):
        c[field] = address(c[field])
    c['server_port'] = port(c['server_port'])
    for field in ('public_key', 'host_key'):
        if not isinstance(c[field], str) or re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', c[field]) is None:
            raise ValueError('Bare Ed25519 public key required')
    forwards = [{key: c[key] for key in forward_keys}] if schema == 1 else c['forwards']
    if not isinstance(forwards, list) or not 1 <= len(forwards) <= 8:
        raise ValueError('One to eight explicit forwards required')
    c['forwards'] = []
    listeners, endpoints, interfaces = set(), set(), set()
    for item in forwards:
        if not isinstance(item, dict) or set(item) != forward_keys:
            raise ValueError('Exact forward fields required')
        forward = {key: address(item[key]) if key.endswith('address') else port(item[key])
                   for key in forward_keys}
        if not ipaddress.ip_address(forward['listen_address']).is_private:
            raise ValueError('Private bridge listener required')
        listener = (forward['listen_address'], forward['listen_port'])
        endpoint = (forward['target_address'], forward['target_port'])
        interfaces.add(forward['listen_address'])
        if listener in listeners or endpoint in endpoints or len(interfaces) != 1:
            raise ValueError('Distinct listeners/endpoints on one bridge required')
        listeners.add(listener)
        endpoints.add(endpoint)
        c['forwards'].append(forward)
    return c


def render(config):
    c = normalize(config)
    user = 'portal-rdp-tunnel'
    root = '/etc/portal-rdp-transport'
    endpoints = [f"{f['target_address']}:{f['target_port']}" for f in c['forwards']]
    permit_open = ' '.join(endpoints)
    # Match all closes the included block so following global sshd settings
    # do not accidentally apply only to the tunnel account.
    server = f'''Match User {user}
    AuthorizedKeysFile {root}/authorized_keys
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    AuthorizedKeysCommand none
    TrustedUserCAKeys none
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    PermitOpen {permit_open}
    PermitListen none
    MaxSessions 0
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTunnel no
Match all
'''
    authorized = (f'from="{c["client_address"]}",restrict,port-forwarding,'
                  + ','.join(f'permitopen="{endpoint}"' for endpoint in endpoints)
                  + f' {c["public_key"]}\n')
    forwards = '\n'.join(f"    LocalForward {f['listen_address']}:{f['listen_port']} {endpoint}"
                         for f, endpoint in zip(c['forwards'], endpoints))
    client = f'''Host portal-rdp-peer
    HostName {c['server_address']}
    Port {c['server_port']}
    User {user}
    IdentityFile {root}/identity
    IdentitiesOnly yes
    IdentityAgent none
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    StrictHostKeyChecking yes
    UserKnownHostsFile {root}/known_hosts
    GlobalKnownHostsFile /dev/null
    HostKeyAlias portal-rdp-peer
    HostKeyAlgorithms ssh-ed25519
    ExitOnForwardFailure yes
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ConnectTimeout 10
{forwards}
'''
    unit = f'''[Unit]
Description=Restricted private RDP peer transport
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -N -F {root}/client.conf portal-rdp-peer
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_UNIX
UMask=0077

[Install]
WantedBy=multi-user.target
'''
    return {'sshd.conf': server, 'authorized_keys': authorized,
            'client.conf': client, 'known_hosts': 'portal-rdp-peer '+c['host_key']+'\n',
            'portal-rdp-transport.service': unit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    raw = args.config.read_bytes()
    if len(raw) > 16384:
        raise ValueError('Bounded configuration required')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate JSON key')
            value[key] = item
        return value
    outputs = render(json.loads(raw, object_pairs_hook=unique))
    args.out.mkdir(mode=0o700)
    hashes = {}
    for name, value in outputs.items():
        with (args.out/name).open('x') as out:
            out.write(value)
        hashes[name] = hashlib.sha256(value.encode()).hexdigest()
    receipt = {'schema': 1, 'config_sha256': hashlib.sha256(raw).hexdigest(),
               'files': hashes, 'scope': 'render only; no host changes'}
    with (args.out/'receipt.json').open('x') as out:
        json.dump(receipt, out, indent=2)
    print(json.dumps({'rendered': len(outputs), 'installed': False}))


if __name__ == '__main__':
    main()
