"""Pure inert checks. No raw sockets, setns, inspect or fixture operations."""
import json
import struct
import unittest
from unittest.mock import patch

import audit_guacd_handshake as audit


def encode(*fields):
    return (','.join(str(len(v)) + '.' + v for v in fields) + ';').encode()


def frame(source=41000, dest=4822, address=b'\x7f\x00\x00\x01', fragment=0):
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 6
    ip[2:4], ip[6:8] = struct.pack('!H', 40), struct.pack('!H', fragment)
    ip[12:16] = ip[16:20] = address
    tcp = bytearray(20)
    tcp[:8] = struct.pack('!HHI', source, dest, 123)
    tcp[12], tcp[13] = 0x50, 2
    return b'\0' * 12 + b'\x08\x00' + ip + tcp


def bpf(data):
    """Tiny independent interpreter for the exact used classic BPF subset."""
    a, x, pc = 0, 0, 0
    program = audit.filter_instructions()
    while pc < len(program):
        code, jt, jf, k = program[pc]
        if code in (0x20, 0x28, 0x30, 0x48):
            size = {0x20: 4, 0x28: 2, 0x30: 1, 0x48: 2}[code]
            offset = k + (x if code == 0x48 else 0)
            if offset + size > len(data):
                return 0
            a = int.from_bytes(data[offset:offset + size], 'big')
        elif code == 0xb1:
            if k >= len(data):
                return 0
            x = (data[k] & 15) * 4
        elif code in (0x15, 0x45):
            pc += jt if (a == k if code == 0x15 else bool(a & k)) else jf
        elif code == 6:
            return k
        else:
            raise AssertionError('Unknown BPF instruction')
        pc += 1
    raise AssertionError('No return')


class AuditTests(unittest.TestCase):
    def test_exact_synthetic_catalog_credentials(self):
        config = {'schema_version': 1, 'portal': {'username': 'operator'}, 'targets': {}}
        targets = {'targets': []}
        for name, alias, user, port in (('desktop-a', 'alpha', 'pa', 33389),
                                         ('desktop-b', 'beta', 'pb', 33390)):
            username = user + '0123456789'
            config['targets'][name] = {'protocol': 'rdp', 'hostname': '127.0.0.1',
                'port': port, 'username': username, 'security': 'tls',
                'certificate_fingerprint': 'sha256:' + ':'.join(['ab'] * 32),
                'password_file': name + '-password'}
            targets['targets'].append({'alias': alias, 'username': username,
                'port': port - 30000, 'password': 'SYNTHETIC_PASSWORD_' + 'x' * 32,
                'address': '192.0.2.1', 'certificate_sha256': 'ab' * 32})
        params = audit.expected_parameters(config, targets)
        self.assertEqual(params['desktop-a']['password'], targets['targets'][0]['password'])
        self.assertEqual(set(params['desktop-a']), audit.KNOWN)
        config['targets']['desktop-b']['hostname'] = '192.0.2.1'
        with self.assertRaises(ValueError):
            audit.expected_parameters(config, targets)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"password":"first","password":"second"}', object_pairs_hook=audit.unique)

    def test_unicode_split_every_byte(self):
        parser = audit.Parser()
        for byte in encode('connect', 'synthetic-\U0001f600-\u00e9'):
            parser.feed(bytes([byte]))
        self.assertEqual(parser.pop(), ['connect', 'synthetic-\U0001f600-\u00e9'])
        self.assertIsNone(parser.pop())

    def test_multiple_partial_and_invalid(self):
        parser = audit.Parser()
        parser.feed(encode('audio') + b'4.size,4.1100,3.800;')
        self.assertEqual(parser.pop(), ['audio'])
        self.assertEqual(parser.pop(), ['size', '1100', '800'])
        for raw in (b'1234567', b'01.x;', b'1.x!', b'999999.x;'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parser = audit.Parser()
                parser.feed(raw)
                parser.pop()

    def test_reassembly_duplicates_out_of_order_and_overlap(self):
        stream = audit.Stream(99)
        self.assertEqual(stream.feed(103, b'def'), b'')
        self.assertEqual(stream.feed(100, b'abcd'), b'abcdef')
        self.assertEqual(stream.feed(101, b'bcde'), b'')
        with self.assertRaises(ValueError):
            stream.feed(102, b'X')
        with self.assertRaises(ValueError):
            stream.feed(99, b'x')
        with self.assertRaises(ValueError):
            stream.feed(100 + audit.LIMIT, b'x')

    def test_sequence_wrap(self):
        stream = audit.Stream(0xfffffffd)
        self.assertEqual(stream.feed(0, b'cd'), b'')
        self.assertEqual(stream.feed(0xfffffffe, b'ab'), b'abcd')

    def test_filter_and_packet_scope(self):
        for source, dest, address, fragment, allowed in (
            (41000, 4822, b'\x7f\0\0\1', 0, True),
            (4822, 41000, b'\x7f\0\0\1', 0, True),
            (41000, 8080, b'\x7f\0\0\1', 0, False),
            (4822, 41000, b'\x0a\0\0\1', 0, False),
            (4822, 41000, b'\x7f\0\0\1', 0x2000, False)):
            raw = frame(source, dest, address, fragment)
            self.assertEqual(bool(bpf(raw)), allowed)
            self.assertEqual(audit.packet(raw) is not None, allowed)
        self.assertEqual(bpf(b'\0'), 0)

    def test_safe_comparison_ready_and_stop(self):
        params = {k: 'SYNTHETIC_SECRET_VALUE' for k in audit.KNOWN}
        params['port'] = '33389'
        flow = audit.Flow(1, {'desktop-a': params}, 1.0)
        flow.streams = [audit.Stream(99), audit.Stream(199)]
        keys = sorted(params)
        flow.feed(1, 200, encode('args', 'VERSION_1_5_0', *keys, 'UNTRUSTED_KEY_SECRET'), 2.0)
        flow.feed(0, 100, encode('connect', 'VERSION_1_5_0',
            *(params[k] for k in keys), 'UNTRUSTED_VALUE_SECRET'), 3.0)
        flow.feed(1, 200 + len(encode('args', 'VERSION_1_5_0', *keys, 'UNTRUSTED_KEY_SECRET')),
                  encode('ready', 'SECRET_CONNECTION_ID') + encode('img', 'SECRET_DISPLAY'), 4.0)
        self.assertTrue(flow.done)
        self.assertTrue(flow.result['ready'])
        self.assertTrue(all(flow.result['equality'].values()))
        self.assertEqual(flow.result['unknown_parameter_count'], 1)
        self.assertEqual(flow.result['alias'], 'desktop-a')
        self.assertEqual(flow.result['phases']['ready'], 4.0)
        self.assertNotIn('SECRET', json.dumps(flow.result))
        self.assertEqual(flow.parsers, [])
        self.assertTrue(all(not s.history and not s.pending for s in flow.streams))

    def test_error_payload_never_exported(self):
        flow = audit.Flow(1, {}, 1.0)
        flow.instruction(1, ['error', 'SECRET_ERROR_MESSAGE', '514'], 2.0)
        self.assertEqual(flow.result['status'], 514)
        self.assertNotIn('SECRET', json.dumps(flow.result))
        with self.assertRaises(ValueError):
            audit.Flow(2, {}, 1.0).instruction(1, ['error', 'SECRET', '65536'], 2.0)

    def test_ready_without_connect_is_not_complete_comparison(self):
        flow = audit.Flow(1, {}, 1.0)
        flow.instruction(1, ['ready', 'SECRET_CONNECTION_ID'], 2.0)
        self.assertTrue(flow.result['ready'])
        self.assertFalse(flow.result['complete'])
        self.assertFalse(flow.result['comparison_observed'])
        self.assertEqual(flow.result['equality'], {})

    def test_no_network_on_import_or_input_rejection(self):
        with patch.object(audit.socket, 'socket', side_effect=AssertionError('socket forbidden')):
            with self.assertRaises(ValueError):
                audit.run({})


if __name__ == '__main__':
    unittest.main()
