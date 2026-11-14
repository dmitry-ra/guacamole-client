#!/usr/bin/env python3
"""Credential-free bounded TCP, X224 NLA negotiation and pinned TLS probe.

Run inside the exact operator-selected container as the guacd service UID2002.
This script never sends CredSSP, credentials or desktop authentication messages.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import struct
import time

REQUEST = bytes.fromhex('030000130ee000000000000100080003000000')


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    if (address.is_unspecified or address.is_multicast or address.is_loopback
            or address.is_link_local or str(address) == '255.255.255.255'):
        raise ValueError('Unicast nonlocal IPv4 required')
    return str(address)


def endpoint(values):
    name, address, port, fingerprint = values
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', name):
        raise ValueError('Literal endpoint label required')
    if not re.fullmatch(r'[a-f0-9]{64}', fingerprint):
        raise ValueError('Exact lowercase SHA256 certificate pin required')
    if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
        raise ValueError('TCP port required')
    return name, ipv4(address), int(port), fingerprint


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('Probe deadline exceeded')
    return value


def receive(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        connection.settimeout(remaining(deadline))
        part = connection.recv(count - len(result))
        if not part:
            raise EOFError('Peer closed during negotiation')
        result.extend(part)
    return bytes(result)


def probe(selected, source, timeout):
    name, address, port, fingerprint = selected
    started = time.monotonic()
    deadline = started + timeout
    result = dict(name=name, target=[address, port], passed=False,
                  tcp_connected=False, nla_negotiated=False, tls_pinned=False,
                  phase='tcp_connect')
    try:
        with socket.create_connection((address, port), timeout=remaining(deadline),
                                      source_address=(source, 0)) as raw:
            result['source'] = raw.getsockname()[0]
            if result['source'] != source:
                raise RuntimeError('Unexpected service source address')
            result.update(tcp_connected=True, tcp_seconds=round(time.monotonic() - started, 4),
                          phase='x224_nla')
            raw.settimeout(remaining(deadline))
            raw.sendall(REQUEST)
            header = receive(raw, 4, deadline)
            if header[:2] != b'\x03\x00':
                raise ValueError('Invalid TPKT header')
            size = struct.unpack('!H', header[2:])[0]
            if not 12 <= size <= 4096:
                raise ValueError('Invalid bounded TPKT length')
            body = receive(raw, size - 4, deadline)
            kind, flags, length, protocol = struct.unpack('<BBHI', body[-8:])
            result.update(negotiation_kind=kind, protocol=protocol)
            if kind != 2 or length != 8 or protocol not in (2, 8):
                raise ValueError('Endpoint did not negotiate NLA')
            result.update(nla_negotiated=True, phase='tls_handshake')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw.settimeout(remaining(deadline))
            with context.wrap_socket(raw, server_hostname=address) as secure:
                actual = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
                result.update(certificate_sha256=actual, tls=secure.version(), phase='tls_pin')
                if actual != fingerprint:
                    raise ValueError('Pinned certificate differs')
                result.update(tls_pinned=True, passed=True, phase='complete')
    except Exception as error:
        result['error_type'] = type(error).__name__
        if isinstance(error, OSError) and error.errno is not None:
            result['errno'] = error.errno
    result['seconds'] = round(time.monotonic() - started, 4)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--endpoint', action='append', nargs=4,
                        metavar=('LABEL', 'IPV4', 'PORT', 'SHA256'), required=True)
    parser.add_argument('--timeout', type=int, default=8, choices=range(1, 16))
    args = parser.parse_args()
    source = ipv4(args.source)
    endpoints = [endpoint(value) for value in args.endpoint]
    if not 1 <= len(endpoints) <= 8 or len({value[0] for value in endpoints}) != len(endpoints):
        raise ValueError('One through eight uniquely labeled endpoints required')
    if os.geteuid() != 2002:
        raise RuntimeError('Actual guacd service UID2002 required')
    def expired(signum, frame):
        raise TimeoutError('Whole-probe deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(args.timeout * len(endpoints) + 2)
    try:
        results = [probe(value, source, args.timeout) for value in endpoints]
    finally:
        signal.alarm(0)
    passed = all(value['passed'] for value in results)
    print(json.dumps(dict(schema=1, passed=passed, uid=os.geteuid(),
                         credentials_used=False, desktop_authenticated=False,
                         results=results), sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
