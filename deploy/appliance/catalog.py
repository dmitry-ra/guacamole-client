"""Strict, deployment-independent protocol target catalog. No network or secret reads."""

from dataclasses import dataclass
import ipaddress
import base64
import struct
import json
import os
from pathlib import Path
import re
import stat


def fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - (set(required) | set(optional)):
        raise ValueError("Unknown configuration field or invalid object")
    if not set(required) <= set(value):
        raise ValueError("Required configuration field missing")


def text(value, limit=128):
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Invalid configuration text")
    return value


def alias(value):
    if (not isinstance(value, str) or len(value) > 48
            or re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", value) is None):
        raise ValueError("Invalid target alias")
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError("Boolean configuration value required")
    return value


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Invalid target port")
    return value


@dataclass(frozen=True)
class Target:
    alias: str
    label: str
    hostname: str
    port: int
    username: str
    domain: str
    security: str
    certificate: str
    secret_file: str
    protocol: str = 'rdp'
    host_key: str = ''
    command: str = ''

    @property
    def secret_parameter(self):
        return 'password' if self.protocol == 'rdp' else 'private-key'

    @property
    def secret_limit(self):
        return 512 if self.protocol == 'rdp' else 16384

    @property
    def secret_token(self):
        suffix = '_PASSWORD' if self.protocol == 'rdp' else '_PRIVATE_KEY'
        return 'PORTAL_TARGET_' + self.alias.replace('-', '_').upper() + suffix

    @property
    def password_file(self):
        if self.protocol != 'rdp':
            raise ValueError('RDP password compatibility property requires RDP')
        return self.secret_file

    @property
    def password_token(self):
        if self.protocol != 'rdp':
            raise ValueError('RDP password compatibility property requires RDP')
        return self.secret_token

    def parameters(self):
        if self.protocol == 'ssh':
            return {'hostname': self.hostname, 'port': str(self.port), 'username': self.username,
                    'host-key': self.host_key, 'private-key': '${' + self.secret_token + '}',
                    'command': self.command, 'enable-sftp': 'false'}
        return {
            "hostname": self.hostname, "port": str(self.port),
            "username": self.username, "domain": self.domain,
            "security": self.security, "cert-fingerprints": self.certificate,
            "password": "${" + self.password_token + "}",
            "enable-drive": "false", "enable-printing": "false",
            "resize-method": "display-update", "enable-font-smoothing": "true",
            "client-name": "WEB-RDP",
        }


@dataclass(frozen=True)
class Catalog:
    username: str
    default_target: str | None
    publish_target_labels: bool
    targets: tuple[Target, ...]
    trusted_proxy_ipv4: str | None = None

    def target(self, selected):
        alias(selected)
        for target in self.targets:
            if target.alias == selected:
                return target
        raise ValueError("Unknown target")

    def parameters(self, mapping):
        if set(mapping) != {target.alias for target in self.targets}:
            raise ValueError("Connection mapping does not match catalog")
        if (any(type(v) is not int or v <= 0 for v in mapping.values())
                or len(set(mapping.values())) != len(mapping)):
            raise ValueError("Invalid or duplicate connection ID")
        return {mapping[target.alias]: target.parameters() for target in self.targets}

    def endpoints(self):
        return sorted({(target.hostname, target.port) for target in self.targets})


def known_host(value, hostname, number):
    value = text(value, 4096)
    parts = value.split(' ')
    endpoints = {f'[{hostname}]:{number}'}
    if number == 22:
        endpoints.add(hostname)
    if len(parts) != 3 or parts[0] not in endpoints or parts[1] not in ('ssh-ed25519', 'ecdsa-sha2-nistp256'):
        raise ValueError('Exact single endpoint known-host entry required')
    try:
        key = base64.b64decode(parts[2], validate=True)
        def field(offset):
            if offset+4 > len(key):
                raise ValueError()
            size = struct.unpack_from('>I', key, offset)[0]
            end = offset+4+size
            if end > len(key):
                raise ValueError()
            return key[offset+4:end], end
        kind, offset = field(0)
        if kind.decode('ascii') != parts[1]:
            raise ValueError()
        if parts[1] == 'ssh-ed25519':
            public, offset = field(offset)
            if len(public) != 32:
                raise ValueError()
        else:
            curve, offset = field(offset)
            public, offset = field(offset)
            if curve != b'nistp256' or len(public) != 65 or public[0] != 4:
                raise ValueError()
        if offset != len(key) or base64.b64encode(key).decode() != parts[2]:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError, struct.error):
        raise ValueError('Invalid supported host public key') from None
    return value


def parse(value):
    fields(value, {"schema_version", "portal", "targets"})
    if type(value["schema_version"]) is not int or value["schema_version"] not in (1, 2):
        raise ValueError("Unsupported configuration schema")
    portal = value["portal"]
    fields(portal, {"username"}, {"default_target", "publish_target_labels", "trusted_proxy_ipv4"})
    username = text(portal["username"], 32)
    if re.fullmatch(r"[a-z][a-z0-9_-]*", username) is None or username == "guacadmin":
        raise ValueError("Invalid portal username")
    records = value["targets"]
    if not isinstance(records, dict) or not 1 <= len(records) <= 32:
        raise ValueError("A catalog requires between one and 32 targets")
    for name in records:
        alias(name)
    targets = []
    for name, obj in sorted(records.items()):
        alias(name)
        if not isinstance(obj, dict):
            raise ValueError('Target object required')
        protocol = obj.get('protocol')
        if protocol == 'rdp':
            fields(obj, {'protocol', 'hostname', 'port', 'username', 'certificate_fingerprint',
                         'password_file'}, {'label', 'domain', 'security'})
        elif protocol == 'ssh' and value['schema_version'] == 2:
            fields(obj, {'protocol', 'hostname', 'port', 'username', 'host_key', 'private_key_file',
                         'command'}, {'label'})
        else:
            raise ValueError('Unsupported target protocol or schema')
        address = ipaddress.IPv4Address(text(obj['hostname']))
        if address.is_unspecified or address.is_multicast or str(address) == '255.255.255.255':
            raise ValueError('Unicast target address required')
        number = port(obj['port'])
        reference = text(obj['password_file' if protocol == 'rdp' else 'private_key_file'], 96)
        if re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]*', reference) is None:
            raise ValueError('Secret reference must be a literal filename')
        if protocol == 'rdp':
            security = text(obj.get('security', 'nla'))
            if security not in {'nla', 'tls'}:
                raise ValueError('Explicit TLS or NLA security required')
            certificate = text(obj['certificate_fingerprint'], 110)
            if re.fullmatch(r'sha256:(?:[0-9a-f]{2}:){31}[0-9a-f]{2}', certificate) is None:
                raise ValueError('Exact SHA256 certificate fingerprint required')
            domain = obj.get('domain', '')
            if domain != '':
                text(domain)
            targets.append(Target(name, text(obj.get('label', name), 100), str(address), number,
                                  text(obj['username']), domain, security, certificate, reference))
        else:
            ssh_username = text(obj['username'], 32)
            if re.fullmatch('[a-z_][a-z0-9_-]{0,31}', ssh_username) is None:
                raise ValueError('Literal SSH username required')
            key = known_host(obj['host_key'], str(address), number)
            command = text(obj['command'], 256)
            path = Path(command)
            if (not path.is_absolute() or '..' in path.parts or str(path) != command
                    or re.fullmatch('/[A-Za-z0-9_./-]+', command) is None or command.startswith('//') or command == '/'):
                raise ValueError('Fixed absolute launcher pathname required')
            targets.append(Target(name, text(obj.get('label', name), 100), str(address), number,
                                  ssh_username, '', '', '', reference, 'ssh', key, command))
    if value['schema_version'] == 2 and len({t.secret_file for t in targets}) != len(targets):
        raise ValueError('Connection-specific secret files required')
    proxy = portal.get("trusted_proxy_ipv4")
    if proxy is not None:
        address = ipaddress.IPv4Address(text(proxy))
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError("Exact unicast trusted proxy required")
        proxy = str(address)
    result = Catalog(username, portal.get("default_target"),
                     boolean(portal.get("publish_target_labels", False)), tuple(targets), proxy)
    if result.default_target is not None:
        result.target(result.default_target)
    return result


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON configuration key")
        result[key] = value
    return result


def load(path):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > 128 * 1024:
            raise ValueError("Bounded regular, non-writable configuration file required")
        data = stream.read(128 * 1024 + 1)
    if len(data) > 128 * 1024:
        raise ValueError("Configuration exceeds size limit")
    return parse(json.loads(data, object_pairs_hook=unique_object))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=Path)
    arguments = parser.parse_args()
    parsed = load(arguments.configuration)
    print(json.dumps({"valid": True, "targets": [t.alias for t in parsed.targets],
                      "default_target": parsed.default_target}))
