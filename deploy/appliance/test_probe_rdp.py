"""Credential-free negotiation tests; no real network connection is opened."""
import hashlib
import struct
import unittest
from unittest.mock import patch

from tools import probe_rdp as probe

SOURCE = '192.0.2.2'
CERT = b'synthetic certificate'
PIN = hashlib.sha256(CERT).hexdigest()
ENDPOINT = ('first', '198.51.100.2', 3389, PIN)


class Connection:
    def __init__(self, *, protocol=2, kind=2):
        body = b'\x0e\xd0\x00\x00\x00\x00\x00' + struct.pack('<BBHI', kind, 0, 8, protocol)
        self.data = b'\x03\x00' + struct.pack('!H', len(body) + 4) + body
        self.sent = []
        self.timeouts = []

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getsockname(self): return SOURCE, 40000
    def settimeout(self, value): self.timeouts.append(value)
    def sendall(self, value): self.sent.append(value)
    def recv(self, count):
        result, self.data = self.data[:count], self.data[count:]
        return result
    def getpeercert(self, binary_form=False): return CERT
    def version(self): return 'TLSv1.3'


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.raw = Connection()
        self.connect = patch.object(probe.socket, 'create_connection', return_value=self.raw).start()
        self.context = patch.object(probe.ssl, 'SSLContext').start().return_value
        self.context.wrap_socket.return_value = self.raw
        self.addCleanup(patch.stopall)

    def test_complete_probe_sends_only_x224_and_checks_source_and_pin(self):
        result = probe.probe(ENDPOINT, SOURCE, 8)
        self.assertTrue(result['passed'])
        self.assertTrue(result['tcp_connected'])
        self.assertTrue(result['nla_negotiated'])
        self.assertTrue(result['tls_pinned'])
        self.assertEqual(result['certificate_sha256'], PIN)
        self.assertEqual(self.raw.sent, [probe.REQUEST])
        self.assertEqual(self.connect.call_args.kwargs['source_address'], (SOURCE, 0))
        self.assertTrue(all(0 < value <= 8 for value in self.raw.timeouts))

    def test_tcp_timeout_is_distinct_from_negotiation_failure(self):
        self.connect.side_effect = TimeoutError('synthetic')
        result = probe.probe(ENDPOINT, SOURCE, 8)
        self.assertFalse(result['passed'])
        self.assertFalse(result['tcp_connected'])
        self.assertEqual(result['phase'], 'tcp_connect')
        self.assertEqual(result['error_type'], 'TimeoutError')
        self.context.wrap_socket.assert_not_called()

    def test_eof_after_tcp_records_last_completed_phase(self):
        self.raw.data = b''
        result = probe.probe(ENDPOINT, SOURCE, 8)
        self.assertTrue(result['tcp_connected'])
        self.assertFalse(result['nla_negotiated'])
        self.assertEqual(result['phase'], 'x224_nla')
        self.assertEqual(result['error_type'], 'EOFError')

    def test_non_nla_and_protocol_failure_never_start_tls(self):
        for protocol, kind in ((1, 2), (0, 2), (5, 3)):
            self.raw = Connection(protocol=protocol, kind=kind)
            self.connect.return_value = self.raw
            result = probe.probe(ENDPOINT, SOURCE, 8)
            self.assertFalse(result['passed'])
            self.assertFalse(result['nla_negotiated'])
            self.assertEqual(result['protocol'], protocol)
        self.context.wrap_socket.assert_not_called()

    def test_pin_mismatch_retains_tls_and_actual_fingerprint_without_auth(self):
        selected = (*ENDPOINT[:3], '0' * 64)
        result = probe.probe(selected, SOURCE, 8)
        self.assertFalse(result['passed'])
        self.assertTrue(result['nla_negotiated'])
        self.assertEqual(result['phase'], 'tls_pin')
        self.assertEqual(result['certificate_sha256'], PIN)
        self.assertFalse(result['tls_pinned'])
        self.assertEqual(self.raw.sent, [probe.REQUEST])

    def test_tpdu_length_is_bounded_before_body_read(self):
        self.raw.data = b'\x03\x00\xff\xff'
        result = probe.probe(ENDPOINT, SOURCE, 8)
        self.assertFalse(result['passed'])
        self.assertEqual(result['error_type'], 'ValueError')
        self.context.wrap_socket.assert_not_called()

    def test_absolute_deadline_prevents_indefinite_byte_drip(self):
        with patch.object(probe.time, 'monotonic', side_effect=[1, 3]):
            self.raw.recv = lambda count: b'x'
            with self.assertRaises(TimeoutError):
                probe.receive(self.raw, 2, deadline=2)

    def test_actual_service_uid_required_before_opening_socket(self):
        argv = ['probe', '--source', SOURCE, '--endpoint', 'first', ENDPOINT[1], '3389', PIN]
        with patch('sys.argv', argv), patch.object(probe.os, 'geteuid', return_value=0), self.assertRaises(RuntimeError):
            probe.main()
        self.connect.assert_not_called()

    def test_invalid_literal_arguments_refused(self):
        for values in (('bad;echo', ENDPOINT[1], '3389', PIN),
                       ('first', 'localhost', '3389', PIN),
                       ('first', ENDPOINT[1], '0', PIN),
                       ('first', ENDPOINT[1], '3389', 'A' * 64)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                probe.endpoint(values)


if __name__ == '__main__':
    unittest.main()
