#!/usr/bin/env python3
"""Conditional passive synthetic-only guacd handshake audit. No lifecycle actions.

Operator contract and admission schema: GUACD-HANDSHAKE-AUDIT.md.
Never invoke against an already completed trial. Tests do not open sockets.
"""
import codecs
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

IMAGE = '55f55e7abbc8ececed4f9f5ce69ca956469b584f0003bd59c8f4a0e713e63991'
LIMIT = 256 * 1024
KNOWN = frozenset(('hostname', 'port', 'username', 'domain', 'security',
    'cert-fingerprints', 'password', 'enable-drive', 'enable-printing',
    'resize-method', 'enable-font-smoothing', 'client-name'))


def require(condition):
    if not condition:
        raise ValueError('Rejected audit input or stream')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


class Parser:
    """Incremental UTF-8 decoder; protocol lengths count Unicode codepoints."""
    def __init__(self):
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.text = ''

    def feed(self, data):
        self.text += self.decoder.decode(data)
        require(len(self.text) <= LIMIT)

    def pop(self):
        offset, values = 0, []
        while True:
            dot = self.text.find('.', offset)
            if dot < 0:
                require(len(self.text) - offset <= 6)
                return None
            size = self.text[offset:dot]
            require(re.fullmatch(r'0|[1-9][0-9]{0,5}', size) is not None)
            end = dot + 1 + int(size)
            require(end <= LIMIT)
            if end >= len(self.text):
                return None
            values.append(self.text[dot + 1:end])
            require(len(values) <= 512 and self.text[end] in ',;')
            if self.text[end] == ';':
                self.text = self.text[end + 1:]
                return values
            offset = end + 1


class Stream:
    """SYN-bound sequence reassembly, including consistent overlapping repeats."""
    def __init__(self, syn):
        self.base = (syn + 1) & 0xffffffff
        self.history = bytearray()
        self.pending = {}

    def feed(self, seq, payload):
        offset = ((seq - self.base + 0x80000000) & 0xffffffff) - 0x80000000
        require(offset >= 0 and offset + len(payload) <= LIMIT // 2)
        for n, value in enumerate(payload, offset):
            if n < len(self.history):
                require(self.history[n] == value)
            elif n in self.pending:
                require(self.pending[n] == value)
            else:
                self.pending[n] = value
        start = len(self.history)
        while len(self.history) in self.pending:
            self.history.append(self.pending.pop(len(self.history)))
        return bytes(self.history[start:])

    def clear(self):
        self.history.clear()
        self.pending.clear()


class Flow:
    def __init__(self, ordinal, expected, epoch):
        self.expected = expected
        self.parsers = [Parser(), Parser()]
        self.streams = [None, None]
        self.args = None
        self.done = False
        self.result = {'flow': ordinal, 'alias': None, 'phases': {'syn': epoch},
                       'equality': {}, 'unknown_parameter_count': 0,
                       'comparison_observed': False,
                       'status': None, 'ready': False, 'complete': False}

    def finish(self, phase, epoch):
        self.result['phases'][phase] = epoch
        self.done = True
        for stream in self.streams:
            if stream:
                stream.clear()
        self.parsers = []
        self.args = None
        return self.result

    def instruction(self, direction, fields, epoch):
        require(bool(fields))
        opcode, values = fields[0], fields[1:]
        if direction == 1 and opcode == 'args':
            require(self.args is None and len(values) <= 256)
            # The first args field is the negotiated protocol version.
            require(values and re.fullmatch(r'VERSION_[0-9]+_[0-9]+_[0-9]+', values[0]))
            self.args = values[1:]
            require(len(set(self.args)) == len(self.args))
            self.result['unknown_parameter_count'] = sum(k not in KNOWN for k in self.args)
            self.result['phases']['args'] = epoch
        elif direction == 0 and opcode == 'connect':
            require(self.args is not None and len(values) == len(self.args) + 1)
            require(re.fullmatch(r'VERSION_[0-9]+_[0-9]+_[0-9]+', values[0]))
            actual = dict(zip(self.args, values[1:]))
            self.result['password_placeholder'] = actual.get('password', '').startswith('${')
            match = [alias for alias, params in self.expected.items()
                     if actual.get('port') == params['port']]
            if len(match) == 1:
                alias = match[0]
                self.result['alias'] = alias
                self.result['equality'] = {key: actual.get(key) == self.expected[alias][key]
                                           for key in sorted(KNOWN)}
                self.result['comparison_observed'] = True
            self.result['phases']['connect'] = epoch
        elif direction == 1 and opcode == 'ready':
            require(len(values) == 1)
            self.result['ready'] = True
            self.result['complete'] = self.result['comparison_observed']
            self.finish('ready', epoch)
        elif direction == 1 and opcode == 'error':
            require(len(values) == 2 and re.fullmatch(r'[0-9]{1,5}', values[1])
                    and int(values[1]) <= 65535)
            self.result['status'] = int(values[1])
            self.result['complete'] = True
            self.finish('error', epoch)
        elif opcode in {'select', 'size', 'audio', 'video', 'image', 'timezone', 'name'}:
            self.result['phases'].setdefault(opcode, epoch)
        else:
            # Do not process any display instruction, including an unexpected one.
            self.finish('unexpected_instruction', epoch)

    def feed(self, direction, seq, payload, epoch):
        require(self.streams[direction] is not None)
        self.parsers[direction].feed(self.streams[direction].feed(seq, payload))
        while not self.done:
            fields = self.parsers[direction].pop()
            if fields is None:
                break
            self.instruction(direction, fields, epoch)


def packet(data):
    """Return only loopback unfragmented IPv4 TCP4822 headers/payload."""
    if len(data) < 54 or data[12:14] != b'\x08\x00':
        return None
    ip = data[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    if (ip[0] >> 4 != 4 or ihl < 20 or len(ip) < total or total < ihl + 20
            or ip[9] != 6 or int.from_bytes(ip[6:8], 'big') & 0x3fff
            or ip[12:20] != b'\x7f\x00\x00\x01' * 2):
        return None
    tcp = ip[ihl:total]
    source, dest, seq = struct.unpack('!HHI', tcp[:8])
    if 4822 not in (source, dest) or source == dest:
        return None
    size = (tcp[12] >> 4) * 4
    if size < 20 or size > len(tcp):
        return None
    direction = int(source == 4822)
    return (dest if direction else source), direction, seq, tcp[13], tcp[size:]


def filter_instructions():
    # Ethernet IPv4, TCP, no fragments, source OR destination TCP port4822.
    # No HTTP packet is delivered to userspace, including on loopback.
    return [(0x28, 0, 0, 12), (0x15, 0, 14, 0x800),
        (0x30, 0, 0, 23), (0x15, 0, 12, 6),
        (0x28, 0, 0, 20), (0x45, 10, 0, 0x3fff),
        (0x20, 0, 0, 26), (0x15, 0, 8, 0x7f000001),
        (0x20, 0, 0, 30), (0x15, 0, 6, 0x7f000001),
        (0xb1, 0, 0, 14), (0x48, 0, 0, 14), (0x15, 2, 0, 4822),
        (0x48, 0, 0, 16), (0x15, 0, 1, 4822),
        (0x06, 0, 0, 65535), (0x06, 0, 0, 0)]


def attach_filter(sock):
    instructions = filter_instructions()
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filters', ctypes.POINTER(Filter))]
    filters = (Filter * len(instructions))(*(Filter(*row) for row in instructions))
    program = Program(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.setsockopt(sock.fileno(), socket.SOL_SOCKET, 26,
                           ctypes.byref(program), ctypes.sizeof(program)) == 0)


def private_json(path, digest, pid, container_path):
    require(re.fullmatch('[0-9a-f]{64}', digest) is not None)
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    proc_path = Path('/proc') / str(pid) / 'root' / container_path.lstrip('/')
    # Read only the exact admitted container mount, never a host-side substitute.
    require(path == proc_path)
    root_fd = os.open(Path('/proc') / str(pid) / 'root', os.O_PATH | os.O_DIRECTORY)
    parent_fd = root_fd
    try:
        if container_path == '/config/config.json':
            parent_fd = os.open('config', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=root_fd)
        fd = os.open(Path(container_path).name,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        if parent_fd != root_fd:
            os.close(parent_fd)
        os.close(root_fd)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 128 * 1024)
        if container_path == '/config/config.json':
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o644)
        else:
            require(info.st_uid in {0, 1000} and stat.S_IMODE(info.st_mode) == 0o600)
        raw = stream.read(128 * 1024 + 1)
    require(hashlib.sha256(raw).hexdigest() == digest)
    return json.loads(raw, object_pairs_hook=unique)


def expected_parameters(config, credentials):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import catalog
    parsed = catalog.parse(config)
    require({t.alias for t in parsed.targets} == {'desktop-a', 'desktop-b'})
    require(set(credentials) == {'targets'} and len(credentials['targets']) == 2)
    result = {}
    for target, item, alias, port in zip(parsed.targets, credentials['targets'],
            ('desktop-a', 'desktop-b'), (33389, 33390)):
        require(target.alias == alias and target.protocol == 'rdp'
                and target.hostname == '127.0.0.1' and target.port == port
                and target.security == 'tls' and target.domain == ''
                and re.fullmatch('p[ab][0-9a-f]{10}', target.username) is not None)
        require(set(item) == {'alias', 'address', 'port', 'username', 'password', 'certificate_sha256'})
        require(item['alias'] == ('alpha' if port == 33389 else 'beta')
                and item['port'] == port - 30000 and item['username'] == target.username
                and isinstance(item['password'], str) and 32 <= len(item['password']) <= 128
                and re.fullmatch('[0-9a-f]{64}', item['certificate_sha256']) is not None
                and target.certificate == 'sha256:' + ':'.join(
                    item['certificate_sha256'][n:n+2] for n in range(0, 64, 2)))
        require(re.fullmatch('pa[0-9a-f]{10}' if port == 33389 else 'pb[0-9a-f]{10}',
                             target.username) is not None)
        require(target.secret_file == alias + '-password')
        result[alias] = dict(target.parameters(), password=item['password'])
    return result


def identity(admission):
    require(os.geteuid() == 0 and admission['image'] == IMAGE)
    require(re.fullmatch('[0-9a-f]{64}', admission['cid']) is not None)
    require(re.fullmatch('[0-9a-f]{32}', admission['token']) is not None)
    info = json.loads(subprocess.check_output(['podman', 'inspect', admission['cid']],
                       timeout=5, stderr=subprocess.DEVNULL))[0]
    pid = admission['pid']
    require(type(pid) is int and pid > 1)
    require(info['Id'] == admission['cid'] and info['State']['Running']
            and info['State']['Pid'] == pid and info['Image'].removeprefix('sha256:') == IMAGE
            and info['Config']['Labels']['org.dmitryra.portal.rdp-fixture'] == admission['token'])
    proc = Path('/proc') / str(pid)
    require(int((proc/'stat').read_text().rsplit(')', 1)[1].split()[19]) == admission['start_ticks'])
    require((proc/'ns/net').stat().st_ino == admission['netns_inode']
            and admission['netns_inode'] != Path('/proc/self/ns/net').stat().st_ino)
    rows = (proc/'cgroup').read_text().splitlines()
    require(any(row.startswith('0::') and admission['cid'] in row for row in rows))


def run(admission):
    require(set(admission) == {'cid', 'image', 'token', 'pid', 'start_ticks',
        'netns_inode', 'config_path', 'config_sha256', 'targets_path', 'targets_sha256', 'seconds'})
    require(type(admission['seconds']) is int and 1 <= admission['seconds'] <= 180)
    identity(admission)
    pid = admission['pid']
    expected = expected_parameters(
        private_json(admission['config_path'], admission['config_sha256'], pid, '/config/config.json'),
        private_json(admission['targets_path'], admission['targets_sha256'], pid, '/targets.json'))
    ns = os.open('/proc/' + str(pid) + '/ns/net', os.O_RDONLY)
    try:
        identity(admission)
        os.setns(ns, 0)
    finally:
        os.close(ns)
    flows = {}
    deadline = time.monotonic() + admission['seconds']
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sock:
        attach_filter(sock)
        sock.bind(('lo', 0x800))
        print(json.dumps({'capture_ready': True, 'epoch': time.time()}), flush=True)
        terminal = 'deadline'
        while time.monotonic() < deadline:
            readable, _, _ = select.select([sock, sys.stdin.buffer], [], [],
                                           min(0.25, max(0, deadline - time.monotonic())))
            if sys.stdin.buffer in readable:
                require(sys.stdin.buffer.read(1) == b'')
                terminal = 'parent_closed'
                break
            if sock not in readable:
                continue
            raw = sock.recv(65535)
            row = packet(raw)
            if row is None:
                raw = b''
                continue
            port, direction, seq, flags, payload = row
            epoch = time.time()
            if port not in flows:
                if direction or not flags & 2 or flags & 16:
                    raw, row, payload = b'', None, b''
                    continue
                require(len(flows) < 8)
                flows[port] = Flow(len(flows) + 1, expected, epoch)
            flow = flows[port]
            if flow.done:
                raw, row, payload = b'', None, b''
                continue
            try:
                if flags & 2:
                    if flow.streams[direction] is None:
                        flow.streams[direction] = Stream(seq)
                    else:
                        require(flow.streams[direction].base == (seq + 1) & 0xffffffff)
                if payload:
                    flow.feed(direction, (seq + int(bool(flags & 2))) & 0xffffffff, payload, epoch)
                if flags & 5 and not flow.done:
                    flow.finish('closed', epoch)
            except (ValueError, UnicodeError):
                flow.finish('rejected_stream', epoch)
            if flow.done:
                print(json.dumps(flow.result, sort_keys=True), flush=True)
            raw, row, payload = b'', None, b''
        for flow in flows.values():
            if not flow.done:
                print(json.dumps(flow.finish(terminal, time.time()), sort_keys=True), flush=True)
    print(json.dumps({'finished': True, 'epoch': time.time(), 'flows': len(flows)}), flush=True)


def main():
    # No exception text/tracebacks: failures can contain credentials or raw data.
    try:
        signal.alarm(195)
        require(len(sys.argv) == 1)
        raw = sys.stdin.buffer.readline(16385)
        require(len(raw) <= 16384 and raw.endswith(b'\n'))
        run(json.loads(raw, object_pairs_hook=unique))
        return 0
    except Exception:
        print('{"rejected":true}', flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
