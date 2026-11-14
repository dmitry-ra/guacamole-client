#!/usr/bin/env python3
"""One operator-authorized in-container RDP login with only domain overridden."""
import argparse
import codecs
import json
import os
import re
import signal
import socket
import sys
import time

MAX_ELEMENT = 1024 * 1024
MAX_WIRE = 16 * 1024 * 1024
MAX_INSTRUCTIONS = 10000
PAINT = {'img', 'png', 'jpeg', 'rect', 'copy', 'video'}


class ProtocolError(ValueError):
    pass


def encode(values):
    # Guacamole lengths count Unicode characters, not UTF-8 wire bytes.
    return (','.join(str(len(str(v))) + '.' + str(v) for v in values) + ';').encode('utf-8')


class Protocol:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline
        self.buffer = ''
        self.position = 0
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.wire = 0

    def char(self):
        while self.position >= len(self.buffer):
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError()
            self.sock.settimeout(left)
            block = self.sock.recv(16384)
            if not block:
                raise EOFError()
            self.wire += len(block)
            if self.wire > MAX_WIRE:
                raise ProtocolError()
            self.buffer = self.decoder.decode(block)
            self.position = 0
        value = self.buffer[self.position]
        self.position += 1
        return value

    def read(self):
        result, total = [], 0
        for _ in range(256):
            digits = ''
            while True:
                c = self.char()
                if c == '.':
                    break
                if c not in '0123456789' or len(digits) >= 7:
                    raise ProtocolError()
                digits += c
            if not digits:
                raise ProtocolError()
            length = int(digits)
            total += length
            if length > MAX_ELEMENT or total > MAX_ELEMENT:
                raise ProtocolError()
            result.append(''.join(self.char() for _ in range(length)))
            separator = self.char()
            if separator == ';':
                return result
            if separator != ',':
                raise ProtocolError()
        raise ProtocolError()

    def send(self, *values):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        self.sock.settimeout(left)
        self.sock.sendall(encode(values))


def parameters(target, expected_username, secret):
    if target.username != expected_username or target.security != 'nla':
        raise ValueError('Target identity/NLA mismatch')
    result = dict(target.parameters())
    result['password'] = secret(target.password_file)
    result['domain'] = ''
    return result


def exchange(sock, params, deadline, report, geometry=(1024, 768, 96), return_protocol=False, media=None):
    if (not isinstance(geometry, tuple) or len(geometry) != 3
            or any(type(value) is not int for value in geometry)
            or not 64 <= geometry[0] <= 8192 or not 64 <= geometry[1] <= 8192
            or not 48 <= geometry[2] <= 384):
        raise ValueError('Invalid diagnostic geometry')
    if media is None:
        media = {'audio': [], 'video': [], 'image': ['image/png', 'image/jpeg'],
                 'timezone': 'Etc/UTC'}
    if (not isinstance(media, dict) or set(media) != {'audio','video','image','timezone'}
            or not isinstance(media['timezone'], str)
            or not re.fullmatch(r'[A-Za-z0-9_+./-]{1,64}',media['timezone'])):
        raise ValueError('Invalid diagnostic client information')
    for kind in ('audio','video','image'):
        values = media[kind]
        if (not isinstance(values,list) or len(values)>32
                or any(not isinstance(value,str) or len(value)>128
                       or not value.startswith(kind+'/')
                       or not re.fullmatch(r'[A-Za-z0-9/+.;=,_ -]+',value) for value in values)):
            raise ValueError('Invalid diagnostic MIME list')
    protocol = Protocol(sock, deadline)
    report['stage'] = 'select'
    protocol.send('select', 'rdp')
    args = protocol.read()
    required = {'hostname', 'port', 'username', 'domain', 'password', 'security', 'cert-fingerprints'}
    if (not args or args[0] != 'args' or not required.issubset(args[1:])
            or len(set(args[1:])) != len(args[1:])):
        raise ProtocolError()
    protocol.send('size', *map(str, geometry))
    protocol.send('audio', *media['audio'])
    protocol.send('video', *media['video'])
    protocol.send('image', *media['image'])
    protocol.send('timezone', media['timezone'])
    values = []
    for name in args[1:]:
        if name.startswith('VERSION_'):
            if not re.fullmatch(r'VERSION_[0-9]+_[0-9]+_[0-9]+', name):
                raise ProtocolError()
            values.append(name)
        else:
            values.append(params.get(name, ''))
    # The caller's durable intent must already exist before reaching this line.
    report['stage'] = 'credential_connect'
    protocol.send('connect', *values)
    values.clear()
    report['stage'] = 'observe'
    for _ in range(MAX_INSTRUCTIONS):
        message = protocol.read()
        if not message:
            raise ProtocolError()
        op = message[0]
        report['instructions'] += 1
        if op == 'error':
            if len(message) != 3 or not re.fullmatch('[0-9]{1,5}', message[2]) or int(message[2]) > 65535:
                raise ProtocolError()
            report['status'] = int(message[2])
            report['outcome'] = 'guacd_error'
            return
        if op in PAINT:
            report['display_instructions'] += 1
        if op == 'blob':
            if len(message) != 3 or not re.fullmatch('[0-9]{1,10}', message[1]):
                raise ProtocolError()
            report['display_payload_characters'] += len(message[2])
            protocol.send('ack', message[1], 'OK', '0')
        if op == 'sync':
            if len(message) < 2 or not re.fullmatch('[0-9]{1,20}', message[1]):
                raise ProtocolError()
            protocol.send('sync', message[1])
            if report['display_instructions']:
                report['outcome'] = 'display_activity'
                return protocol if return_protocol else None
    raise ProtocolError()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alias', required=True)
    parser.add_argument('--expected-username', required=True)
    args = parser.parse_args()
    report = dict(schema=1, uid=os.geteuid(), domain_empty=True, single_connection=True,
                  full_browser_acceptance=False, stage='validate', outcome='probe_failure',
                  status=None, instructions=0, display_instructions=0, display_payload_characters=0)
    sock = None
    def expired(signum, frame):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(30)
    deadline = time.monotonic() + 29
    try:
        if os.geteuid() != 0 or os.environ.get('WEB_RDP_PRODUCTION') != '1':
            raise ValueError('Exact running production image required')
        sys.path.insert(0, '/opt/homelab-web-rdp')
        import runtime
        runtime.integrity()
        registry, _ = runtime.configuration()
        target = registry.target(args.alias)
        params = parameters(target, args.expected_username, runtime.target_secret)
        report['stage'] = 'guacd_socket'
        sock = socket.create_connection(('127.0.0.1', 4822), timeout=min(5, max(.01, deadline-time.monotonic())))
        exchange(sock, params, deadline, report)
    except (TimeoutError, socket.timeout):
        report['outcome'] = 'timeout'
    except EOFError:
        report['outcome'] = 'eof'
    except Exception as error:
        # Fixed type only; never error messages, parameters or protocol values.
        report['error_type'] = type(error).__name__
    finally:
        if sock is not None:
            sock.close()
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['outcome'] == 'display_activity' else 1


if __name__ == '__main__':
    raise SystemExit(main())
